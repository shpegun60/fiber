param(
    [string]$ArmGcc=$env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore=$env:CMSIS_CORE_INCLUDE,
    [Parameter(Mandatory=$true)][string]$QemuRoot,
    [string]$WslDistro='Ubuntu-24.04',
    [string]$BuildRoot,
    [string]$FreeRtosRoot=$env:FREERTOS_KERNEL_REFERENCE,
    [ValidateSet(0)][int]$ExpectedRuntimeSelectable=0,
    [string]$Python='python',
    [switch]$DevelopmentAdmissionOnly,
    [switch]$DevelopmentDefaultOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$admissionLiveRepo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if(!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)){throw 'Supply existing -ArmGcc'}
if(!$QemuRoot.StartsWith('/')){throw 'Explicit existing absolute WSL -QemuRoot required; no provisioning'}
if(!$CmsisCore){$CmsisCore=Join-Path $admissionLiveRepo '../../../Drivers/CMSIS/Include'}
if(!$FreeRtosRoot){$FreeRtosRoot=Join-Path $admissionLiveRepo '../../../../_reference/FreeRTOS-Kernel'}
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot=(Resolve-Path -LiteralPath $FreeRtosRoot).Path
$admissionLiveReference=$FreeRtosRoot
$admissionPython=(Get-Command $Python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
if(!$BuildRoot){$BuildRoot=[IO.Path]::GetTempPath()}
$admissionBuildBase=$BuildRoot
$admissionRoot=Join-Path $BuildRoot ('c55sa-'+[guid]::NewGuid().ToString('N').Substring(0,16))
$null=New-Item -ItemType Directory -Path $admissionRoot -Force
$admissionRoot=(Resolve-Path $admissionRoot).Path
$admissionCommands=Join-Path $admissionRoot 'commands.jsonl'
Write-Host "C55S admission evidence: $admissionRoot"
function AdmissionCommand([string]$Program,[string[]]$Arguments,[string]$Name){
    $old=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$lines=@(& $Program @Arguments 2>&1|ForEach-Object {"$_"});$exit=$LASTEXITCODE}
    finally{$ErrorActionPreference=$old}
    $log=Join-Path $admissionRoot ($Name+'.log')
    [IO.File]::WriteAllLines($log,[string[]]$lines)
    [pscustomobject]@{Program=$Program;Arguments=$Arguments;Exit=$exit;Log=$log}|ConvertTo-Json -Depth 6 -Compress|Add-Content $admissionCommands -Encoding ASCII
    if($exit -ne 0){throw "Admission command failed ($exit): $log`n$($lines -join "`n")"}
    return ($lines -join "`n")
}
function AdmissionLinux([string]$Path){return (AdmissionCommand 'wsl.exe' @('-d',$WslDistro,'--exec','wslpath','-u',$Path) ('wslpath-'+[guid]::NewGuid().ToString('N'))).Trim()}
function AdmissionHashes([string[]]$Paths){return @($Paths|Sort-Object -Unique|ForEach-Object {
    if(Test-Path -LiteralPath $_ -PathType Leaf){Get-FileHash -LiteralPath $_ -Algorithm SHA256|Select-Object Path,Hash}
    else{[pscustomobject]@{Path=$_;Hash=$null}}
})}
function AdmissionPlugin([string]$Trace,[string]$Query){
    $found=[regex]::Matches($Trace,'(?:^|\s)-plugin\s+(?:"([^"\r\n]+)"|([^\s"]+))(?=\s|$)')
    if($found.Count -ne 1){throw 'LTO plugin provenance: expected exactly one driver -plugin argument'}
    $path=$(if($found[0].Groups[1].Success){$found[0].Groups[1].Value}else{$found[0].Groups[2].Value})
    if(!(Test-Path -LiteralPath $path -PathType Leaf) -or !(Test-Path -LiteralPath $Query -PathType Leaf)){throw 'LTO plugin provenance: discovered plugin/query does not exist'}
    $resolved=(Resolve-Path -LiteralPath $path).Path
    if((Split-Path $resolved -Leaf) -ine 'liblto_plugin.dll' -or $resolved -ine (Resolve-Path -LiteralPath $Query).Path){throw 'LTO plugin provenance: driver/query plugin mismatch'}
    return $resolved
}
function AdmissionPluginManifest([object[]]$Rows,[string]$Plugin){
    $found=@($Rows|Where-Object {$_.Path -ieq $Plugin})
    if($found.Count -ne 1 -or !$found[0].Hash){throw 'LTO plugin provenance: plugin missing from required hash manifest'}
}
function AdmissionReference([string]$Root,[string]$Name){
    $head=(AdmissionCommand 'git' @('-C',$Root,'rev-parse','HEAD') ($Name+'-head')).Trim()
    $status=(AdmissionCommand 'git' @('-C',$Root,'status','--porcelain','--untracked-files=all') ($Name+'-status')).Trim()
    if($head -cne 'a50edad08b29052631aa469d4df6e6ec7ff68878' -or $status){throw "Reference not exact tracked/untracked-clean pin: $Root"}
}
$admissionVerdict='FAIL'
$admissionSources=@();$admissionTools=@();$admissionBefore=@();$admissionRuntime=$null;$admissionRuntimeResult=$null;$admissionDefaults=0
$admissionPlugin=$null
$admissionPluginControls=New-Object System.Collections.Generic.List[object]
$admissionRepo=Join-Path $admissionRoot 'source/repo'
$admissionCmsis=Join-Path $admissionRoot 'source/cmsis'
$admissionReference=Join-Path $admissionRoot 'source/reference'
$admissionCopied=New-Object System.Collections.Generic.List[object]
$admissionComplete=!($DevelopmentAdmissionOnly -or $DevelopmentDefaultOnly)
try{
    AdmissionReference $FreeRtosRoot 'live-reference-before'
    $admissionRepoInputs=@((Join-Path $admissionLiveRepo 'mcu_core.h'),(Join-Path $admissionLiveRepo 'basic_types.h'),
        $PSCommandPath,(Join-Path $admissionLiveRepo 'tools/test_m55_secure_runtime.ps1'),
        (Join-Path $admissionLiveRepo 'tools/fixtures/portable_application.c'),
        (Join-Path $admissionLiveRepo 'tools/fixtures/cm33_secure_guards/aircr_rsp.py'),
        (Join-Path $admissionLiveRepo 'tools/fixtures/arm_control/qemu.sh'),
        (Join-Path $admissionLiveRepo 'fiber/port/fiber_port_context_cohort_expectation.c'))+
        @(Get-ChildItem (Join-Path $admissionLiveRepo 'fiber') -File|Where-Object {$_.Extension -in @('.h','.c')}|Select-Object -ExpandProperty FullName)+
        @(Get-ChildItem (Join-Path $admissionLiveRepo 'fiber/port') -File -Filter '*.h'|Select-Object -ExpandProperty FullName)+
        @(Get-ChildItem (Join-Path $admissionLiveRepo 'tools/fixtures/m55_secure_runtime') -Recurse -File|Select-Object -ExpandProperty FullName)
    foreach($admissionRelative in @('fiber/port/ARM_CM55/non_secure','fiber/port/ARM_CM55/secure','fiber/port/ARM_CM33/secure')){
        $admissionRepoInputs+=@(Get-ChildItem (Join-Path $admissionLiveRepo $admissionRelative) -File|Where-Object {$_.Extension -in @('.h','.c','.ld','.md')}|Select-Object -ExpandProperty FullName)
    }
    foreach($admissionFile in @($admissionRepoInputs|Sort-Object -Unique)){
        $admissionRelative=$admissionFile.Substring($admissionLiveRepo.Length+1)
        $admissionTarget=Join-Path $admissionRepo $admissionRelative
        $null=New-Item -ItemType Directory -Path (Split-Path $admissionTarget) -Force
        $admissionHash=(Get-FileHash -LiteralPath $admissionFile -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $admissionFile -Destination $admissionTarget
        if((Get-FileHash -LiteralPath $admissionTarget -Algorithm SHA256).Hash -cne $admissionHash){throw "Source copy race: $admissionFile"}
        $admissionCopied.Add([pscustomobject]@{Source=$admissionFile;Snapshot=$admissionTarget;Hash=$admissionHash})
        $admissionSources+=@($admissionTarget)
    }
    foreach($admissionFile in @(Get-ChildItem $CmsisCore -Recurse -File)){
        $admissionTarget=Join-Path $admissionCmsis $admissionFile.FullName.Substring($CmsisCore.Length+1)
        $null=New-Item -ItemType Directory -Path (Split-Path $admissionTarget) -Force
        $admissionHash=(Get-FileHash -LiteralPath $admissionFile.FullName -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $admissionFile.FullName -Destination $admissionTarget
        if((Get-FileHash -LiteralPath $admissionTarget -Algorithm SHA256).Hash -cne $admissionHash){throw 'CMSIS source copy race'}
        $admissionCopied.Add([pscustomobject]@{Source=$admissionFile.FullName;Snapshot=$admissionTarget;Hash=$admissionHash})
        $admissionSources+=@($admissionTarget)
    }
    $null=AdmissionCommand 'git' @('-c','core.longpaths=true','clone','--quiet','--no-checkout',
        '--no-hardlinks','--config','core.longpaths=true','--',$FreeRtosRoot,$admissionReference) 'local-reference-snapshot'
    $null=AdmissionCommand 'git' @('-C',$admissionReference,'sparse-checkout','set','--cone','include','portable/GCC/ARM_CM55') 'reference-sparse-inputs'
    $null=AdmissionCommand 'git' @('-C',$admissionReference,'checkout','--quiet','--detach','a50edad08b29052631aa469d4df6e6ec7ff68878') 'reference-pinned-checkout'
    AdmissionReference $admissionReference 'snapshot-reference-before'
    $admissionSources+=@(Get-ChildItem (Join-Path $admissionReference 'include'),
        (Join-Path $admissionReference 'portable/GCC/ARM_CM55/non_secure'),
        (Join-Path $admissionReference 'portable/GCC/ARM_CM55/secure') -File|Where-Object {$_.Extension -in @('.h','.c')}|Select-Object -ExpandProperty FullName)
    foreach($admissionFile in $admissionSources){(Get-Item -LiteralPath $admissionFile).IsReadOnly=$true}
    $admissionCopied.ToArray()|ConvertTo-Json -Depth 5|Set-Content (Join-Path $admissionRoot 'snapshot-manifest.json') -Encoding ASCII
    $admissionBin=Split-Path $ArmGcc
    $admissionTools=@($ArmGcc,(Get-Command git.exe).Source,(Get-Command wsl.exe).Source)
    foreach($admissionName in @('g++','gcc-ar','gcc-nm','objdump','objcopy','readelf')){$admissionTools+=@(Join-Path $admissionBin ('arm-none-eabi-'+$admissionName+'.exe'))}
    foreach($admissionName in @('cc1','cc1plus','lto1','lto-wrapper','as','ld','collect2')){
        $admissionTool=(AdmissionCommand $ArmGcc @('-print-prog-name='+$admissionName) ('tool-'+$admissionName)).Trim()
        if(!(Test-Path -LiteralPath $admissionTool)){$admissionTool=(Get-Command $admissionTool -CommandType Application).Source}
        $admissionTools+=@($admissionTool)
    }
    $admissionPluginQuery=(AdmissionCommand $ArmGcc @('-print-file-name=liblto_plugin.dll') 'lto-plugin-query').Trim()
    $admissionPluginTrace=AdmissionCommand $ArmGcc @('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-flto','-###','-nostdlib','-x','c',
        (Join-Path $admissionRepo 'tools/fixtures/m55_secure_runtime/admission/constructor.c'),'-o',(Join-Path $admissionRoot 'driver-plan-only.elf')) 'lto-driver-plan'
    $admissionPlugin=AdmissionPlugin $admissionPluginTrace $admissionPluginQuery
    $admissionTools+=@($admissionPlugin)
    foreach($admissionControl in @(
        @{Name='missing-driver-plugin';Action={AdmissionPlugin 'collect2.exe -o fixture.elf' $admissionPluginQuery}},
        @{Name='duplicate-driver-plugin';Action={AdmissionPlugin ($admissionPluginTrace+' -plugin "'+$admissionPlugin+'"') $admissionPluginQuery}},
        @{Name='missing-plugin-file';Action={AdmissionPlugin ('collect2.exe -plugin "'+(Join-Path $admissionRoot 'absent/liblto_plugin.dll')+'"') (Join-Path $admissionRoot 'absent/liblto_plugin.dll')}})){
        $admissionRejected=$false
        try{$null=& $admissionControl.Action}catch{
            if(!$_.Exception.Message.StartsWith('LTO plugin provenance: ')){throw}
            $admissionRejected=$true
            $admissionPluginControls.Add([pscustomobject]@{Name=$admissionControl.Name;Result='EXPECTED-REJECTION';Error=$_.Exception.Message})
        }
        if(!$admissionRejected){throw "LTO plugin provenance control accepted: $($admissionControl.Name)"}
    }
    $admissionIncludes=(AdmissionCommand $ArmGcc @('-print-file-name=include') 'compiler-include').Trim()
    $admissionTools+=@(Get-ChildItem $admissionIncludes -Recurse -File|Select-Object -ExpandProperty FullName)
    $admissionTools+=@(Get-ChildItem (Join-Path (Split-Path $admissionBin) 'arm-none-eabi/include') -Recurse -File|Select-Object -ExpandProperty FullName)
    $admissionPythonBinary=(AdmissionCommand $admissionPython @('-B','-c',"import sys,pathlib; p=pathlib.Path(sys.executable); print(p if p.is_file() and 'windowsapps' not in str(p).lower() else pathlib.Path(sys.base_prefix)/p.name)") 'python-binary').Trim()
    $admissionTools+=@($admissionPythonBinary)
    $admissionBefore=AdmissionHashes @($admissionSources+$admissionTools)
    if(@($admissionBefore|Where-Object {!$_.Hash}).Count){throw 'A required source/tool input is missing'}
    AdmissionPluginManifest $admissionBefore $admissionPlugin
    $admissionRejected=$false
    try{AdmissionPluginManifest @($admissionBefore|Where-Object {$_.Path -ine $admissionPlugin}) $admissionPlugin}catch{
        if(!$_.Exception.Message.StartsWith('LTO plugin provenance: ')){throw}
        $admissionRejected=$true
        $admissionPluginControls.Add([pscustomobject]@{Name='omitted-plugin-manifest-row';Result='EXPECTED-REJECTION';Error=$_.Exception.Message})
    }
    if(!$admissionRejected){throw 'LTO plugin manifest omission control accepted'}
    $admissionPluginControls.ToArray()|ConvertTo-Json -Depth 4|Set-Content (Join-Path $admissionRoot 'lto-plugin-controls.json') -Encoding ASCII
    $admissionBefore|ConvertTo-Json -Depth 4|Set-Content (Join-Path $admissionRoot 'inputs-before.json') -Encoding ASCII
    $admissionStatic=Join-Path $admissionRoot 'admission';$null=New-Item -ItemType Directory -Path $admissionStatic
    $admissionScript=Join-Path $admissionRepo 'tools/fixtures/m55_secure_runtime/admission/run.py'
    $admissionStaticResult=AdmissionCommand $admissionPython @('-B',$admissionScript,'--repo',$admissionRepo,'--build',$admissionStatic,'--arm-gcc',$ArmGcc,'--cmsis',$admissionCmsis) 'static-admission'
    Write-Host $admissionStaticResult
    if(!$DevelopmentAdmissionOnly){
        $admissionInventory=Join-Path $admissionRepo 'tools/fixtures/m55_secure_runtime/admission/runtime_dependencies.sh'
        $admissionQemuBefore=Join-Path $admissionRoot 'qemu-before';$null=New-Item -ItemType Directory -Path $admissionQemuBefore
        $null=AdmissionCommand 'wsl.exe' @('-d',$WslDistro,'--exec','bash',(AdmissionLinux $admissionInventory),$QemuRoot,(AdmissionLinux $admissionQemuBefore)) 'qemu-before'
        # Dot-source the unchanged maintained suite, with no Development argument.
        # Its helpers remain available to build separate no-policy-override images.
        $admissionRuntimeArguments=@{ArmGcc=$ArmGcc;CmsisCore=$admissionCmsis;QemuRoot=$QemuRoot;WslDistro=$WslDistro;FreeRtosRoot=$admissionReference;BuildRoot=$admissionBuildBase}
        if($DevelopmentDefaultOnly){$admissionRuntimeArguments.DevelopmentModelOnly=$true}
        . (Join-Path $admissionRepo 'tools/test_m55_secure_runtime.ps1') @admissionRuntimeArguments
        $admissionRuntime=$out
        $admissionRuntimeResult=Get-Content (Join-Path $admissionRuntime 'results.json') -Raw|ConvertFrom-Json
        if($admissionRuntimeResult.Verdict -cne 'PASS'){throw 'Runtime/model stage failed'}
        if(!$DevelopmentDefaultOnly -and (!$admissionRuntimeResult.CompleteSuite -or $admissionRuntimeResult.Launches -ne 2490 -or $admissionRuntimeResult.TotalLaunches -ne 2491)){throw 'Unchanged full runtime inventory was not qualified'}
        if($DevelopmentDefaultOnly -and ($admissionRuntimeResult.CompleteSuite -or $admissionRuntimeResult.Launches -ne 0)){throw 'Development model-only receipt must not claim full qualification'}
        # Do not append default-case commands/logs to the already closed full
        # runtime evidence or invalidate its contemporaneous sha256.csv.
        $out=$admissionRoot
        $commands=Join-Path $admissionRoot 'default-commands.jsonl'
        $admissionDefaultPlan=New-Object System.Collections.Generic.List[object]
        foreach($admissionOpt in @('o2','os')){foreach($admissionLto in @($false,$true)){foreach($admissionArchive in @($false,$true)){foreach($admissionReserved in @($false,$true)){
            $admissionMode=@{Name=('default-'+$admissionOpt+$(if($admissionLto){'-lto'})+$(if($admissionArchive){'-archive'})+$(if($admissionReserved){'-reserved'}else{'-ordinary'}));
                Hash=1;Map=0;R9=$(if($admissionReserved){'reserved'}else{'ordinary'});R9Flags=$(if($admissionReserved){@('-ffixed-r9')}else{@()});
                Flags=@($(if($admissionOpt -eq 'o2'){'-O2'}else{'-Os'}),"-DRUNTIME_NVIC_PRIO_BITS=$modelBits")}
            if($admissionLto){$admissionMode.Flags+=@('-flto')}
            if($admissionArchive){$admissionMode.Archive=$true}
            $admissionDir=Join-Path $admissionRoot $admissionMode.Name;$null=New-Item -ItemType Directory -Path $admissionDir
            $admissionModel=BuildFiber $admissionMode $admissionDir
            $admissionPolicy=Compile 'default-observer' (Join-Path $fixture 'admission/default_policy.c') $admissionModel.NFlags $admissionDir
            $admissionModel.AppObjects+=@($admissionPolicy)
            $admissionModel.NLink+=@('-Wl,--undefined=c55s_default_policy')
            $admissionN=Link 'default-nonsecure' $admissionModel.NLink (NonsecureMembers $admissionModel) $admissionDir
            InspectRuntime $admissionN $admissionMode $admissionDir
            $admissionModel.Nonsecure=$admissionN
            $admissionManifest=FiberManifest $admissionModel.Secure $admissionN
            foreach($admissionKey in @('hash','map','r9_mode','priority_bits','basepri','priority_mask')){$admissionManifest[$admissionKey]=$admissionModel.Manifest[$admissionKey]}
            $admissionModel.Manifest=$admissionManifest
            $null=AdmissionCommand $admissionPython @('-B',$admissionScript,'--observe-policy',$admissionN.Elf,'--priority-bits',"$modelBits") ('observe-'+$admissionMode.Name)
            foreach($admissionCase in 0..4){$admissionDefaultPlan.Add([pscustomobject]@{Mode=$admissionMode.Name;Kind='fiber';Case=$admissionCase})}
            $admissionDefaultPlan.ToArray()|ConvertTo-Json -Depth 5|Set-Content (Join-Path $admissionRoot 'default-execution-plan.json') -Encoding ASCII
            ExecuteCases $admissionModel $admissionMode @(0..4)
            @($runs.ToArray()|Where-Object {$_.Mode -like 'default-*'})|ConvertTo-Json -Depth 5|Set-Content (Join-Path $admissionRoot 'default-runs.json') -Encoding ASCII
            $admissionDefaults+=5
            Write-Host "Completed unoverridden $($admissionMode.Name)"
        }}}}
        if($admissionDefaults -ne 80){throw 'Default execution inventory incomplete'}
        $admissionDefaultRuns=@($runs.ToArray()|Where-Object {$_.Mode -like 'default-*'})
        if($admissionDefaultRuns.Count -ne 80 -or (Compare-Object $admissionDefaultPlan.ToArray() $admissionDefaultRuns -Property Mode,Kind,Case)){throw 'Exact default execution inventory mismatch'}
        $admissionDefaultPlan.ToArray()|ConvertTo-Json -Depth 5|Set-Content (Join-Path $admissionRoot 'default-execution-plan.json') -Encoding ASCII
        $admissionDefaultRuns|ConvertTo-Json -Depth 5|Set-Content (Join-Path $admissionRoot 'default-runs.json') -Encoding ASCII
        $admissionQemuAfter=Join-Path $admissionRoot 'qemu-after';$null=New-Item -ItemType Directory -Path $admissionQemuAfter
        $null=AdmissionCommand 'wsl.exe' @('-d',$WslDistro,'--exec','bash',(AdmissionLinux $admissionInventory),$QemuRoot,(AdmissionLinux $admissionQemuAfter)) 'qemu-after'
        if((Get-FileHash (Join-Path $admissionQemuBefore 'runtime-dependencies.sha256')).Hash -cne (Get-FileHash (Join-Path $admissionQemuAfter 'runtime-dependencies.sha256')).Hash){throw 'QEMU/runtime dependency drift'}
    }
    AdmissionReference $admissionReference 'snapshot-reference-after'
    AdmissionReference $admissionLiveReference 'live-reference-after'
    $admissionVerdict='PASS'
}finally{
    $admissionAfter=AdmissionHashes @($admissionSources+$admissionTools)
    $admissionAfter|ConvertTo-Json -Depth 4|Set-Content (Join-Path $admissionRoot 'inputs-after.json') -Encoding ASCII
    $admissionDrift=@()
    if($admissionBefore.Count -gt 0 -and $admissionAfter.Count -gt 0){$admissionDrift=@(Compare-Object $admissionBefore $admissionAfter -Property Path,Hash)}
    elseif($admissionBefore.Count -ne $admissionAfter.Count){$admissionDrift=@([pscustomobject]@{Path='incomplete-before-manifest';Hash=$null})}
    if($admissionDrift.Count){$admissionVerdict='FAIL'}
    if($admissionPlugin){
        $admissionPluginBefore=@($admissionBefore|Where-Object {$_.Path -ieq $admissionPlugin})
        $admissionPluginAfter=@($admissionAfter|Where-Object {$_.Path -ieq $admissionPlugin})
        $admissionPluginValid=$admissionPluginBefore.Count -eq 1 -and $admissionPluginAfter.Count -eq 1 -and
            $admissionPluginBefore[0].Hash -and $admissionPluginBefore[0].Hash -ceq $admissionPluginAfter[0].Hash
        if(!$admissionPluginValid){$admissionVerdict='FAIL'}
        [pscustomobject]@{Path=$admissionPlugin;Before=$admissionPluginBefore;After=$admissionPluginAfter;Valid=[bool]$admissionPluginValid;
            Discovery='actual gcc -### -flto -plugin argument agrees with -print-file-name; plan is not executed';Controls=$admissionPluginControls.ToArray()}|
            ConvertTo-Json -Depth 6|Set-Content (Join-Path $admissionRoot 'lto-plugin-provenance.json') -Encoding ASCII
    }
    [pscustomobject]@{Verdict=$admissionVerdict;CompleteSuite=($admissionComplete -and $admissionVerdict -ceq 'PASS');
        SourceSnapshot=$admissionRepo;RuntimeRoot=$admissionRuntime;OriginalRuntimeLaunches=$(if($admissionRuntimeResult){$admissionRuntimeResult.Launches}else{0});
        DefaultLaunches=$admissionDefaults;InputCount=$admissionBefore.Count;InputDrift=$admissionDrift.Count;RuntimeSelectable=$ExpectedRuntimeSelectable;
        Limit='Immutable source-copy C55S paired Secure/common proof; Secure bootstrap is not TF-M. No physical-no-FP, hardware, stack-minimum or activation claim.'}|
        ConvertTo-Json -Depth 7|Set-Content (Join-Path $admissionRoot 'results.json') -Encoding ASCII
    $admissionArtifactRoots=@($admissionRoot)
    if($admissionRuntime){$admissionArtifactRoots+=@($admissionRuntime)}
    Get-ChildItem $admissionArtifactRoots -Recurse -File|Where-Object {$_.Name -ne 'artifacts.sha256.csv' -and $_.FullName -notmatch '[\\/]\.git[\\/]'}|
        ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256}|Select-Object Path,Hash|
        Export-Csv (Join-Path $admissionRoot 'artifacts.sha256.csv') -NoTypeInformation -Encoding ASCII
}
if($admissionVerdict -cne 'PASS'){throw "C55S admission failed; preserved $admissionRoot"}
Write-Host "PASS C55S admission (complete=$admissionComplete): $admissionRoot"
