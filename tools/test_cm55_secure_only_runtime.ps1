param(
    [string]$ArmGcc=$env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore=$env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot=$env:FREERTOS_KERNEL_REFERENCE,
    [string]$QemuRoot,
    [string]$WslDistro='Ubuntu-24.04',
    [string]$BuildRoot,
    [ValidateSet(0,1)][int]$ExpectedRuntimeSelectable=0,
    [ValidateSet('AttributesOnly')][string]$AdversarialAdmission='AttributesOnly',
    [switch]$CompilerAdversarialOnly,
    [switch]$AdmissionOnly,
    [ValidateRange(1,60)][int]$TimeoutSeconds=10
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$sourceIdentityScript=Join-Path $PSScriptRoot 'fixtures/source_export_identity/identity.ps1'
. $sourceIdentityScript
$fixture=Join-Path $PSScriptRoot 'fixtures/cm55_secure_only_runtime'
$port=Join-Path $repo 'fiber/port/ARM_CM55_SECURE_ONLY/secure'
if($AdmissionOnly -and $CompilerAdversarialOnly){throw 'Choose only one focused phase'}
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {throw 'Supply existing -ArmGcc'}
if (!$QemuRoot -or !$QemuRoot.StartsWith('/')) {throw 'Supply explicit existing absolute WSL -QemuRoot; no provisioning'}
if (!$CmsisCore) {$CmsisCore=Join-Path $repo '../../../Drivers/CMSIS/Include'}
if (!$FreeRtosRoot) {$FreeRtosRoot=Join-Path $repo '../../../../_reference/FreeRTOS-Kernel'}
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot=(Resolve-Path -LiteralPath $FreeRtosRoot).Path
$referenceRelative='portable/GCC/ARM_CM55_NTZ/non_secure'
$reference=Join-Path $FreeRtosRoot $referenceRelative
$pin='a50edad08b29052631aa469d4df6e6ec7ff68878'
$bin=Split-Path $ArmGcc
$nm=Join-Path $bin 'arm-none-eabi-nm.exe'
$objdump=Join-Path $bin 'arm-none-eabi-objdump.exe'
$readelf=Join-Path $bin 'arm-none-eabi-readelf.exe'
$ar=Join-Path $bin 'arm-none-eabi-gcc-ar.exe'
$gccnm=Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
foreach($file in @($nm,$objdump,$readelf,$ar,$gccnm,(Join-Path $CmsisCore 'core_cm55.h'))) {
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) {throw "Missing dependency: $file"}
}
if (!$BuildRoot) {$BuildRoot=[IO.Path]::GetTempPath()}
$out=Join-Path $BuildRoot ('cm55-secure-only-runtime-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out -Force
$commands=Join-Path $out 'commands.jsonl'
$checks=New-Object System.Collections.Generic.List[object]
$runs=New-Object System.Collections.Generic.List[object]
$compilerCases=New-Object System.Collections.Generic.List[object]
$verdict='FAIL';$failure='';$referenceChecked=$false
$repositoryMetadataBefore=$null;$repositoryMetadataAfter=$null
$inputs=@($PSCommandPath,$sourceIdentityScript,$ArmGcc,$nm,$objdump,$readelf,$ar,$gccnm,
    (Join-Path $repo 'tools/fixtures/portable_application.c'),
    (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h'))+
    @(Get-ChildItem -LiteralPath $fixture -File -Recurse | Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem -LiteralPath $port -File | Where-Object {$_.Extension -in @('.c','.h','.S','.ld')} | Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem (Join-Path $repo 'fiber') -File | Where-Object {$_.Extension -in @('.c','.h')} | Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem (Join-Path $repo 'fiber/port') -File | Where-Object {$_.Extension -in @('.c','.h')} | Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem -LiteralPath $CmsisCore -Filter '*.h' -File -Recurse | Select-Object -ExpandProperty FullName)+
    @('port.c','portasm.c','portasm.h','portmacro.h' | ForEach-Object {Join-Path $reference $_})
function Recorded([string]$File,[string[]]$Arguments,[string]$Log) {
    $old=$ErrorActionPreference
    try {$ErrorActionPreference='Continue';$lines=@(& $File @Arguments 2>&1);$code=$LASTEXITCODE}
    finally {$ErrorActionPreference=$old}
    $text=($lines | ForEach-Object {"$_"}) -join "`n"
    [IO.File]::WriteAllText($Log,$text)
    @{File=$File;Arguments=$Arguments;ExitCode=$code;Log=$Log} | ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath $commands -Encoding ASCII
    [pscustomobject]@{Code=$code;Text=$text}
}
function Need([string]$File,[string[]]$Arguments,[string]$Log) {
    $result=Recorded $File $Arguments $Log
    if($result.Code -ne 0) {throw "Command failed ($($result.Code)): $Log`n$($result.Text)"}
    $result.Text
}
function Check([string]$Name,[bool]$Condition,[object]$Evidence) {
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$Condition;Evidence=$Evidence})
    if(!$Condition) {throw "C5SO proof failed: $Name"}
}
function HashInputs {@($inputs | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)}
function WslPath([string]$Path) {(Need 'wsl.exe' @('-d',$WslDistro,'--exec','wslpath','-u',$Path) (Join-Path $out 'last-wslpath.log')).Trim()}
function Compile([string]$Source,[string]$Object,[string[]]$Flags) {
    $null=Need $ArmGcc ($Flags+@('-save-temps=obj','-MD','-c',$Source,'-o',$Object)) ($Object+'.log')
}
function Archive([string]$Path,[string[]]$Objects) {$null=Need $ar (@('rcs',$Path)+$Objects) ($Path+'.log')}
function Link([string]$Elf,[string[]]$Members,[string[]]$Flags,[string]$LinkerScript=(Join-Path $fixture 'image.ld')) {
    Recorded $ArmGcc ($Flags+@('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined',
        '-T',$LinkerScript,"-Wl,-Map,$Elf.map")+$Members+@('-o',$Elf)) ($Elf+'.link.log')
}
function Defined([string]$Object) {Need $gccnm @('--defined-only','-g',$Object) ($Object+'.defined.txt')}
function UndefinedFailure([string]$Name,[object]$Result,[string]$Symbol) {
    Check $Name ($Result.Code -ne 0 -and $Result.Text -match
        ('undefined reference to [^\r\n]*\b'+[regex]::Escape($Symbol)+'\b') -and
        $Result.Text -notmatch '(cannot find|file format not recognized|syntax error)') $Result.Text
}
function Scalar([string]$Text,[string]$Name) {
    $m=[regex]::Matches($Text,'(?m)^'+[regex]::Escape($Name)+'=0x([0-9a-f]{8})\r?$')
    if($m.Count -ne 1) {throw "Missing/duplicate observation: $Name"}
    [Convert]::ToUInt32($m[0].Groups[1].Value,16)
}
function Execute([string]$Name,[string]$Elf,[string]$Marker,[string]$Kind='Production') {
    $log=Join-Path (Split-Path $Elf) 'qemu.log'
    $result=Recorded 'wsl.exe' @('-d',$WslDistro,'--exec','bash',$qemuScript,'run',$QemuRoot,$wslOut,
        (WslPath $Elf),[string]$TimeoutSeconds) $log
    $runs.Add([pscustomobject]@{Name=$Name;Executed=$true;Kind=$Kind;ExitCode=$result.Code;ELF=$Elf;Log=$log;Marker=$Marker})
    $nonempty=@($result.Text -split "`n" | Where-Object {!([string]::IsNullOrWhiteSpace($_))})
    Check "$Name/strict-exit-sole-terminal" ($result.Code -eq 0 -and
        @($result.Text -split "`n" | Where-Object {$_.TrimEnd("`r") -ceq $Marker}).Count -eq 1 -and
        $nonempty.Count -gt 0 -and $nonempty[-1].TrimEnd("`r") -ceq $Marker -and
        $result.Text -cnotmatch '(FAIL:|FAILED_CHECK|Traceback|fatal:|Lockup|timed out)') $result.Text
    $result.Text
}
$generic=@('fiber_port_context_init','fiber_port_runtime_memory_barrier','fiber_port_panic_wait',
    'fiber_port_require_scheduler_configuration_environment','fiber_port_runtime_prepare_start',
    'fiber_port_runtime_select_first','fiber_port_runtime_start_first','fiber_port_runtime_schedule')
function Inspect([string]$Name,[string]$Elf,[switch]$InitOnly,[switch]$Partial,[switch]$Portable) {
    $dump=Need $objdump @('-drwC',$Elf) ($Elf+'.disassembly.txt')
    $symbols=Need $nm @('-n','-S',$Elf) ($Elf+'.symbols.txt')
    $u=Need $nm @('-u',$Elf) ($Elf+'.undefined.txt')
    $attr=Need $readelf @('-hASsW',$Elf) ($Elf+'.attributes.txt')
    Check "$Name/no-undefined" ([string]::IsNullOrWhiteSpace($u)) $Elf
    Check "$Name/scalar-v8M-image" ($attr -match 'Tag_CPU_arch:\s+v8\.1-M.mainline' -and
        $attr -notmatch '(Tag_ABI_VFP_args:|Tag_MVE_arch:)' -and $dump -notmatch '(?m)^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+v(?:ldr|str|stm|ldm|mov|push|pop|msr|mrs)\b') $Elf
    $addresses=@{}
    foreach($m in [regex]::Matches($symbols,'(?m)^([0-9a-f]+)\s+[0-9a-f]+\s+([A-Za-z])\s+(\S+)\r?$')) {
        $addresses[$m.Groups[3].Value]=[Convert]::ToUInt32($m.Groups[1].Value,16)
    }
    # A deliberate application panic override makes panic_wait unreachable;
    # its real extraction is checked separately with the weak common panic.
    $required=if($InitOnly){@('fiber_init','fiber_port_context_init')}else{@($generic | Where-Object {$_ -ne 'fiber_port_panic_wait'})+@('SVC_Handler','PendSV_Handler','fiber_internal_task_return','fiber_current','fiber_schedule','fiber_init','fiber_start')}
    # Registration has no noIPA requirement and may be inlined by LTO. Its
    # exact common-object owner is checked below; execution checks its effects.
    if(!$lto -and !$InitOnly){$required+='fiber_scheduler_set_pick_next'}
    if($Portable -and $lto){$required=@($required | Where-Object {$_ -ne 'fiber_init'})}
    if($Partial){$required=@('fiber_port_context_init','SVC_Handler','PendSV_Handler')}
    foreach($symbol in $required) {
        Check "$Name/exact-live-$symbol" ([regex]::Matches($symbols,
            '(?m)^[0-9a-f]+\s+[0-9a-f]+\s+T\s+'+[regex]::Escape($symbol)+'\r?$').Count -eq 1) $Elf
    }
    Check "$Name/exact-live-v1-object" ([regex]::Matches($attr,
        '(?m)^\s*\d+:\s+[0-9a-f]+\s+1\s+OBJECT\s+(?:LOCAL|GLOBAL)\s+\S+\s+\d+\s+fiber_internal_runtime_port_abi_v1_anchor\r?$').Count -eq 1) $Elf
    foreach($symbol in @($cohort,$storageCohort)) {
        $m=[regex]::Matches($attr,'(?m)^\s*\d+:\s+([0-9a-f]+)\s+1\s+OBJECT\s+GLOBAL\s+\S+\s+(\d+)\s+'+[regex]::Escape($symbol)+'\r?$')
        Check "$Name/exact-provider-$symbol" ($m.Count -eq 1) $Elf
        $section=[regex]::Matches($attr,'(?m)^\s*\[\s*'+$m[0].Groups[2].Value+'\]\s+\S+\s+PROGBITS\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+([A-Z]+)\s')
        $value=[Convert]::ToUInt32($m[0].Groups[1].Value,16)
        Check "$Name/readonly-secure-provider-$symbol" ($section.Count -eq 1 -and
            $section[0].Groups[1].Value.Contains('A') -and !$section[0].Groups[1].Value.Contains('W') -and
            $value -ge 0x00000800 -and $value -lt 0x00020000) $Elf
    }
    $v=[regex]::Matches($attr,'(?m)^\s*\[\s*\d+\]\s+\.vectors\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\s')
    Check "$Name/exact-vector-section" ($v.Count -eq 1) $Elf
    $offset=[Convert]::ToInt32($v[0].Groups[1].Value,16);$length=[Convert]::ToInt32($v[0].Groups[2].Value,16)
    $bytes=[IO.File]::ReadAllBytes($Elf)
    Check "$Name/bounded-vector-file-span" ($length -eq 2048 -and $offset+$length -le $bytes.Length) $Elf
    [byte[]]$vectors=$bytes[$offset..($offset+$length-1)]
    [IO.File]::WriteAllBytes(($Elf+'.vectors.bin'),$vectors)
    Check "$Name/secure-reset-memory-map" ([BitConverter]::ToUInt32($vectors,0) -eq 0x20004000 -and
        ([BitConverter]::ToUInt32($vectors,4) -band 0xfffffffeL) -eq $addresses['Reset_Handler']) $Elf
    if(!$InitOnly) {
        Check "$Name/strong-vector-binding" (([BitConverter]::ToUInt32($vectors,44) -band 0xfffffffeL) -eq $addresses['SVC_Handler'] -and
            ([BitConverter]::ToUInt32($vectors,56) -band 0xfffffffeL) -eq $addresses['PendSV_Handler'] -and
            $addresses['SVC_Handler'] -ne $addresses['fixture_fault_handler'] -and $addresses['PendSV_Handler'] -ne $addresses['fixture_fault_handler']) $Elf
        $portBodies=[regex]::Matches($dump,'(?ms)^[0-9a-f]+ <(fiber_port_[^>]+)>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
        Check "$Name/nonempty-generated-production-bodies" ($portBodies.Count -ge 8) $Elf
        foreach($body in $portBodies) {
            Check "$Name/ordinary-Secure-bank-$($body.Groups[1].Value)" ($body.Groups[2].Value -notmatch '\b(?:psp_ns|psplim_ns|control_ns|basepri_ns|primask_ns|faultmask_ns)\b') $Elf
        }
    }
}
function FullTrace([string]$Name,[string]$Elf,[string]$Log,[int]$Reserved) {
    Check "$Name/actual-first-six-switches" ($Log.Contains('PASS:C5SO-REAL-FIRST-SELECTION') -and (Scalar $Log 'VERIFIED_SWITCHES') -eq 6 -and
        $Log.Contains('PASS:C5SO-PUBLIC-R9-CALLEE-SAVE') -and
        $Log.Contains($(if($Reserved){'PASS:C5SO-RESERVED-R9-SEED'}else{'PASS:C5SO-ORDINARY-AAPCS-FRAME'}))) $Log
    $tracePath=Join-Path (Split-Path $Elf) 'qemu-exceptions.log'
    $trace=[IO.File]::ReadAllText($tracePath)
    Check "$Name/real-secure-first-exception-return" ([regex]::Matches($trace,'(?m)^Exception return: magic PC fffffffd previous exception 11\r?$').Count -eq 1) $tracePath
    Check "$Name/six-real-secure-pendsv-returns" ([regex]::Matches($trace,'(?m)^Exception return: magic PC fffffffd previous exception 14\r?$').Count -eq 6 -and
        $trace -notmatch 'taking pending nonsecure exception') $tracePath
}
. (Join-Path $fixture 'compiler_audit.ps1')
. (Join-Path $fixture 'admission.ps1')
function AuditDependencies {
    $known=@{};foreach($row in $before){$known[[IO.Path]::GetFullPath($row.Path).ToLowerInvariant()]=$true}
    $consumed=@{}
    foreach($dep in Get-ChildItem -LiteralPath $out -Filter '*.d' -File -Recurse) {
        $text=[IO.File]::ReadAllText($dep.FullName) -replace '\\\r?\n',' '
        $colon=$text.IndexOf('.o:');if($colon -lt 0){throw "Unknown dependency target: $($dep.FullName)"}
        $text=$text.Substring($colon+3);$token=New-Object Text.StringBuilder;$tokens=New-Object System.Collections.Generic.List[string]
        # GCC make dependencies escape whitespace/backslashes. Preserve a
        # Windows drive colon; only the explicit object-target suffix splits.
        for($i=0;$i -lt $text.Length;++$i) {
            $c=$text[$i]
            if($c -eq '\' -and $i+1 -lt $text.Length -and ($text[$i+1] -eq '\' -or [char]::IsWhiteSpace($text[$i+1]) -or $text[$i+1] -eq '#')) {
                ++$i;$null=$token.Append($text[$i])
            } elseif([char]::IsWhiteSpace($c)) {
                if($token.Length){$tokens.Add($token.ToString());$null=$token.Clear()}
            } else {$null=$token.Append($c)}
        }
        if($token.Length){$tokens.Add($token.ToString())}
        foreach($path in $tokens) {
            if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw "Unresolved actual compiler input: $path"}
            $resolved=(Resolve-Path -LiteralPath $path).Path;$key=$resolved.ToLowerInvariant()
            if($resolved.StartsWith($out+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){continue}
            Check 'provenance/actual-external-dependency-admitted' ($known.ContainsKey($key)) $resolved
            $consumed[$key]=$resolved
        }
    }
    Check 'provenance/nonempty-actual-dependency-census' ($consumed.Count -ge 20) $consumed.Count
    @($consumed.Values | Sort-Object) | ConvertTo-Json | Set-Content (Join-Path $out 'compiler-external-dependencies.json') -Encoding ASCII
}
function LinkControls {
    # These controls use the current source and natural common calls. No -u,
    # whole-archive, synthetic providers, or opaque precompiled inputs.
    $controlDir=Join-Path $dir 'controls';$null=New-Item -ItemType Directory -Path $controlDir
    $name="$mode/controls"
    $strong=Join-Path $controlDir 'strong-startup.o'
    Compile (Join-Path $fixture 'startup.S') $strong (@($caseFlags | Where-Object {$_ -ne '-DEXEC_WEAK_STARTUP=1'})+@('-DEXEC_WEAK_STARTUP=0'))
    $directDir=Join-Path $controlDir 'direct';$null=New-Item -ItemType Directory -Path $directDir
    $direct=Join-Path $directDir 'secure.elf'
    $result=Link $direct (@($strong)+@($fixtureObjects | Select-Object -Skip 1)+@($expectation)+$commonObjects+$portObjects) $flags
    Check "$name/direct-strong-link" ($result.Code -eq 0) $result.Text;Inspect "$name/direct" $direct
    $log=Execute "$name/direct" $direct 'PASS:C5SO-FULL-RUNTIME';FullTrace "$name/direct" $direct $log 1
    foreach($svc in @(0,1)) {
        $duplicate=Join-Path $controlDir "duplicate-$svc.o"
        Compile (Join-Path $fixture 'duplicate.c') $duplicate ($flags+@("-DDUPLICATE_SVC=$svc"))
        $symbol=if($svc){'SVC_Handler'}else{'PendSV_Handler'}
        $bad=Link (Join-Path $controlDir "duplicate-$svc.elf") ($members+@($duplicate)) $flags
        Check "$name/duplicate-$symbol" ($bad.Code -ne 0 -and $bad.Text -match ('multiple definition of [^\r\n]*\b'+$symbol+'\b')) $bad.Text
    }
    $stateText=[IO.File]::ReadAllText((Join-Path $repo 'fiber/fiber_runtime_state.c'))
    Check "$name/single-v1-source-mutation" ([regex]::Matches($stateText,'fiber_internal_runtime_port_abi_v1_anchor').Count -eq 1) 'Current-source definition rename only'
    $badStateSource=Join-Path $controlDir 'v2-state.c'
    [IO.File]::WriteAllText($badStateSource,$stateText.Replace('fiber_internal_runtime_port_abi_v1_anchor','fiber_internal_runtime_port_abi_v2_anchor'))
    $badState=Join-Path $controlDir 'v2-state.o';Compile $badStateSource $badState $commonFlags
    $badCommon=@($commonObjects[0],$badState,$commonObjects[2])
    $bad=Link (Join-Path $controlDir 'missing-v1.elf') (@($fixtureObjects)+@($expectation)+$badCommon+$portObjects) $flags
    UndefinedFailure "$name/missing-v1" $bad 'fiber_internal_runtime_port_abi_v1_anchor'
    $runtimeText=[IO.File]::ReadAllText((Join-Path $port 'fiber_port.c'))
    Check "$name/single-cohort-source-mutation" ([regex]::Matches($runtimeText,'FIBER_PORT_CONTEXT_COHORT_DEFINE\(\);').Count -eq 1) $cohort
    $badRuntimeSource=Join-Path $controlDir 'no-cohort.c'
    [IO.File]::WriteAllText($badRuntimeSource,$runtimeText.Replace('FIBER_PORT_CONTEXT_COHORT_DEFINE();','/* Deliberate negative: real provider removed. */'))
    $badRuntime=Join-Path $controlDir 'no-cohort.o';Compile $badRuntimeSource $badRuntime $flags
    $bad=Link (Join-Path $controlDir 'missing-cohort.elf') (@($fixtureObjects)+@($expectation)+$commonObjects+@($portObjects[0],$badRuntime)) $flags
    UndefinedFailure "$name/missing-cohort" $bad $cohort
    $otherFlags=@($flags | Where-Object {$_ -ne '-DFIBER_SCHEDULER_BASEPRI=128'})+@('-DFIBER_SCHEDULER_BASEPRI=64')
    $otherExpectation=Join-Path $controlDir 'other-expectation.o'
    Compile (Join-Path $repo 'fiber/port/fiber_port_context_cohort_expectation.c') $otherExpectation $otherFlags
    $u=Need $gccnm @('-u',$otherExpectation) ($otherExpectation+'.undefined.txt')
    $other=[regex]::Matches($u,'\bU\s+(fiber_port_context_cohort_\S+)')
    Check "$name/nonempty-different-expectation" ($other.Count -eq 1 -and $other[0].Groups[1].Value -cne $cohort) $u
    $otherCohort=$other[0].Groups[1].Value
    $bad=Link (Join-Path $controlDir 'wrong-build-expectation.elf') (@($fixtureObjects)+@($otherExpectation,'-Wl,--start-group',$commonArchive,$portArchive,'-Wl,--end-group')) $flags
    UndefinedFailure "$name/coherent-archive-wrong-explicit-expectation" $bad $otherCohort
    $otherBoot=Join-Path $controlDir 'other-boot.o';Compile (Join-Path $port 'fiber_port_boot.c') $otherBoot $otherFlags
    $bad=Link (Join-Path $controlDir 'mixed-boot.elf') (@($fixtureObjects)+@($expectation)+$commonObjects+@($otherBoot,$portObjects[1])) $flags
    UndefinedFailure "$name/mixed-private-config" $bad $otherCohort
    $storage=Join-Path $controlDir 'stale-storage.o';Compile (Join-Path $fixture 'storage.c') $storage $flags
    $bad=Link (Join-Path $controlDir 'stale-storage.elf') ($members+@($storage)) $flags
    UndefinedFailure "$name/synthetic-stale-public-storage" $bad 'fiber_port_storage_cohort_arm_cm55_secure_only_v0_r0'
    $foreignStorage=Join-Path $controlDir 'foreign-storage.o';Compile (Join-Path $fixture 'foreign_storage.c') $foreignStorage $flags
    $bad=Link (Join-Path $controlDir 'foreign-storage.elf') ($members+@($foreignStorage)) $flags
    UndefinedFailure "$name/actual-C3SO-public-storage-is-foreign" $bad 'fiber_port_storage_cohort_arm_cm33_secure_only_v1_r0'
    foreach($missing in @('boot','runtime')) {
        $remainingPort=if($missing -eq 'boot'){@($portObjects[1])}else{@($portObjects[0])}
        $smallArchive=Join-Path $controlDir "no-$missing.a";Archive $smallArchive $remainingPort
        $bad=Link (Join-Path $controlDir "missing-$missing.elf") (@($fixtureObjects)+@($expectation,'-Wl,--start-group',$commonArchive,$smallArchive,'-Wl,--end-group')) $flags
        $required=if($missing -eq 'boot'){'fiber_port_context_init'}else{'fiber_port_runtime_prepare_start'}
        UndefinedFailure "$name/weak-startup-cannot-hide-missing-$missing" $bad $required
    }
    $defaultDir=Join-Path $controlDir 'default-panic';$null=New-Item -ItemType Directory -Path $defaultDir
    $oracle=Join-Path $defaultDir 'oracle.o'
    Compile (Join-Path $fixture 'oracle.c') $oracle ($caseFlags+@('-DEXEC_DEFAULT_PANIC=1'))
    $elf=Join-Path $defaultDir 'secure.elf'
    $result=Link $elf (@($fixtureObjects | Select-Object -First 5)+@($oracle,$expectation,'-Wl,--start-group',$commonArchive,$portArchive,'-Wl,--end-group')) $flags
    Check "$name/default-weak-panic-link" ($result.Code -eq 0) $result.Text;Inspect "$name/default-weak-panic" $elf
    $weak=Defined $commonObjects[2];$oracleSymbols=Defined $oracle
    Check "$name/real-weak-common-panic-input" ($weak -match '(?m)^[0-9a-f]+\s+W\s+fiber_panic\r?$' -and $oracleSymbols -notmatch '\bfiber_panic\b') $weak
    $dump=[IO.File]::ReadAllText($elf+'.disassembly.txt')
    $body=[regex]::Matches($dump,'(?ms)^[0-9a-f]+ <fiber_panic>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
    Check "$name/exact-default-panic-body" ($body.Count -eq 1) $elf
    $barrier=[regex]::Match($body[0].Groups[1].Value,'\b(?:bl|b\.w)\s+[0-9a-f]+ <fiber_port_runtime_memory_barrier>')
    $wait=[regex]::Match($body[0].Groups[1].Value,'\b(?:bl|b\.w)\s+[0-9a-f]+ <fiber_port_panic_wait>')
    Check "$name/default-panic-real-operations" ($barrier.Success -and $wait.Success -and $barrier.Index -lt $wait.Index) $elf
    $runs.Add([pscustomobject]@{Name="$name/default-panic";Executed=$false;Kind='DefaultPanicLinkOnly';ELF=$elf;Reason='Actual terminal wait not executed'})
    # Constructor-only reachability: vector entries deliberately do not root
    # either production handler and the application never calls fiber_start.
    $initDir=Join-Path $controlDir 'init-only';$null=New-Item -ItemType Directory -Path $initDir
    $initObjects=@();$initFlags=$flags+@('-DEXEC_CASE=0','-DEXEC_WEAK_STARTUP=1','-DEXEC_INIT_ONLY=1')
    foreach($unit in @('startup.S','construct.S','init_only.c','environment.c')) {
        $o=Join-Path $initDir ($unit.Replace('.','-')+'.o');Compile (Join-Path $fixture $unit) $o $initFlags;$initObjects+=$o
    }
    $elf=Join-Path $initDir 'secure.elf'
    $result=Link $elf (@($initObjects)+@($expectation,'-Wl,--start-group',$commonArchive,$portArchive,'-Wl,--end-group')) $flags
    Check "$name/init-only-natural-archive-link" ($result.Code -eq 0) $result.Text;Inspect "$name/init-only" $elf -InitOnly
    $s=[IO.File]::ReadAllText($elf+'.symbols.txt')
    Check "$name/init-only-no-start-or-handler-roots" ($s -notmatch '(?m)\b(fiber_start|fiber_port_runtime_start_first|fiber_port_start_first_context)\r?$' -and
        $s -notmatch '(?m)^[0-9a-f]+\s+[0-9a-f]+\s+T\s+(SVC_Handler|PendSV_Handler)\r?$') $elf
    $null=Execute "$name/init-only" $elf 'PASS:C5SO-INIT-ONLY'
    $bad=Link (Join-Path $initDir 'missing-v1.elf') (@($initObjects)+@($expectation)+$badCommon+$portObjects) $flags
    UndefinedFailure "$name/init-only-missing-v1" $bad 'fiber_internal_runtime_port_abi_v1_anchor'
    $bootText=[IO.File]::ReadAllText((Join-Path $port 'fiber_port_boot.c'))
    Check "$name/one-constructor-v1-read-control" ([regex]::Matches($bootText,'FIBER_RUNTIME_PORT_ABI_RETAIN_V1\(\);').Count -eq 1) 'Remove only constructor cold ABI read'
    $unretainedSource=Join-Path $initDir 'unretained-boot.c'
    [IO.File]::WriteAllText($unretainedSource,$bootText.Replace('FIBER_RUNTIME_PORT_ABI_RETAIN_V1();','/* Compiled sensitivity control: remove constructor v1 read only. */'))
    $unretained=Join-Path $initDir 'unretained-boot.o';Compile $unretainedSource $unretained $flags
    $controlElf=Join-Path $initDir 'unretained-v2-only.elf'
    $control=Link $controlElf (@($initObjects)+@($expectation)+$badCommon+@($unretained,$portObjects[1])) $flags
    Check "$name/removed-constructor-read-admits-v2-control" ($control.Code -eq 0) $control.Text
    $controlSymbols=Need $nm @('-n','-S',$controlElf) ($controlElf+'.symbols.txt')
    Check "$name/control-no-v1-object" ($controlSymbols -notmatch '\bfiber_internal_runtime_port_abi_v1_anchor\b') $controlElf
    $controlDir2=Join-Path $initDir 'removed-read-control';$null=New-Item -ItemType Directory -Path $controlDir2
    $copiedElf=Join-Path $controlDir2 'secure.elf';[IO.File]::Copy($controlElf,$copiedElf)
    $null=Execute "$name/removed-constructor-read-control" $copiedElf 'PASS:C5SO-INIT-ONLY' 'CompiledControl'
    ConstructorArchiveAdmission 'PASS:C5SO-INIT-ONLY'
    PortableDefaultAdmission
    $bad=Link (Join-Path $initDir 'missing-cohort.elf') (@($initObjects)+@($expectation)+$commonObjects+@($portObjects[0],$badRuntime)) $flags
    UndefinedFailure "$name/init-only-missing-cohort" $bad $cohort
    # Reserved-ABI seed corruption is compiled from the current real builder.
    # The sole changed store must be rejected by the constructor's one-shot.
    $needle='frame[fiber_portFRAME_R9] = initial_r9;'
    Check "$name/single-r9-store-mutation" ([regex]::Matches($runtimeText,[regex]::Escape($needle)).Count -eq 1) $needle
    $mutantDir=Join-Path $controlDir 'corrupt-seed';$null=New-Item -ItemType Directory -Path $mutantDir
    $mutantSource=Join-Path $mutantDir 'fiber_port.c'
    [IO.File]::WriteAllText($mutantSource,$runtimeText.Replace($needle,'frame[fiber_portFRAME_R9] = initial_r9 ^ 1u;'))
    $mutant=Join-Path $mutantDir 'fiber_port.o';Compile $mutantSource $mutant $flags
    $mutantFlags=@($caseFlags | Where-Object {$_ -ne '-DEXEC_CASE=0'})+@('-DEXEC_CASE=16')
    $mutantObjects=@()
    foreach($unit in @('startup.S','construct.S','tasks.S','application.c','environment.c','oracle.c')) {
        $o=Join-Path $mutantDir ($unit.Replace('.','-')+'.o');Compile (Join-Path $fixture $unit) $o $mutantFlags;$mutantObjects+=$o
    }
    $elf=Join-Path $mutantDir 'secure.elf'
    $result=Link $elf (@($mutantObjects)+@($expectation)+$commonObjects+@($portObjects[0],$mutant)) $flags
    Check "$name/compiled-seed-mutant-link" ($result.Code -eq 0) $result.Text;Inspect "$name/compiled-seed-mutant" $elf -Partial
    $null=Execute "$name/compiled-seed-mutant" $elf 'PASS:C5SO-SEED-CORRUPTION-REJECTED' 'CompiledControl'
}
foreach($program in @('cc1','as','ld','collect2','lto1')) {
    $path=(Need $ArmGcc @("-print-prog-name=$program") (Join-Path $out ($program+'-path.txt'))).Trim()
    if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw "Missing compiler subprocess: $program"}
    $inputs+=(Resolve-Path -LiteralPath $path).Path
}
$systemInclude=(Need $ArmGcc @('-print-file-name=include') (Join-Path $out 'system-include-path.txt')).Trim()
$inputs+=@(Get-ChildItem -LiteralPath $systemInclude -File -Recurse | Select-Object -ExpandProperty FullName)
$libgcov=(Need $ArmGcc @('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-print-file-name=libgcov.a') (Join-Path $out 'libgcov-path.txt')).Trim()
if(!(Test-Path -LiteralPath $libgcov -PathType Leaf)){throw 'Missing raw coverage-control libgcov dependency'}
$inputs+=(Resolve-Path -LiteralPath $libgcov).Path
$before=HashInputs
$before | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII
$sourceIdentityBefore=Write-SourceExportManifest $repo $before $out before
$copyRoot=Join-Path $out 'input-copies';$null=New-Item -ItemType Directory -Path $copyRoot
$copyMap=@();$i=0
foreach($row in $before) {
    if([IO.Path]::GetExtension($row.Path) -in @('.exe','.dll')){continue}
    $copy=Join-Path $copyRoot ('{0:D3}-{1}' -f $i++,[IO.Path]::GetFileName($row.Path));[IO.File]::Copy($row.Path,$copy)
    if((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -cne $row.Hash){throw "Input copy drift: $($row.Path)"}
    $copyMap+=[pscustomobject]@{Original=$row.Path;Copy=$copy;SHA256=$row.Hash}
}
$copyMap | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'input-copy-map.json') -Encoding ASCII
try {
    Write-Host "C5SO runtime evidence: $out"
    $repositoryMetadataBefore=Get-SourceExportHeadMetadata $repo {
        param([string[]]$GitArguments)
        Recorded 'git' $GitArguments (Join-Path $out ('repository-metadata-before-'+[guid]::NewGuid().ToString('N')+'.log'))
    }
    $null=Need $ArmGcc @('--version') (Join-Path $out 'compiler.txt')
    $head=(Need 'git' @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.txt')).Trim()
    Check 'reference/exact-identity-pin' ($head -ceq $pin) $head
    $null=Need 'git' @('-C',$FreeRtosRoot,'diff','--exit-code','HEAD','--',"$referenceRelative/port.c","$referenceRelative/portasm.c","$referenceRelative/portasm.h","$referenceRelative/portmacro.h") (Join-Path $out 'reference-diff.txt')
    $referenceChecked=$true
    $base=@('-mcpu=cortex-m55','-mthumb','-mcmse','-mfloat-abi=soft','-mgeneral-regs-only','-std=gnu11',
        '-ffreestanding','-fno-builtin','-fno-common','-ffunction-sections','-fdata-sections','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-fno-instrument-functions','-fno-stack-protector','-fno-profile-arcs',
        '-fno-test-coverage','-fno-profile','-fno-stack-check','-fno-sanitize=all','-fno-sanitize-coverage=trace-pc',
        '-Wall','-Wextra','-Werror','-Wundef')
    $wslOut=WslPath $out;$qemuScript=WslPath (Join-Path $fixture 'qemu.sh')
    $null=Need 'wsl.exe' @('-d',$WslDistro,'--exec','bash',$qemuScript,'inspect',$QemuRoot,$wslOut) (Join-Path $out 'qemu-inspect.log')
    $probeDir=Join-Path $out 'model-probe';$null=New-Item -ItemType Directory -Path $probeDir
    $probeFlags=$base+@('-O2',"-I$fixture","-I$CmsisCore",'-DEXEC_WEAK_STARTUP=1')
    $probeObjects=@()
    foreach($unit in @('startup.S','probe.c')) {
        $o=Join-Path $probeDir ($unit.Replace('.','-')+'.o');Compile (Join-Path $fixture $unit) $o $probeFlags;$probeObjects+=$o
    }
    $probeElf=Join-Path $probeDir 'secure.elf';$result=Link $probeElf $probeObjects $probeFlags
    Check 'model/probe-link' ($result.Code -eq 0) $result.Text
    $probeLog=Execute 'model-probe' $probeElf 'PASS:C5SO-MODEL-PROBE' 'Probe'
    $priorityMask=Scalar $probeLog 'MODEL_PRIORITY_MASK';$priorityBits=0;$remaining=$priorityMask
    while($remaining -band 128){++$priorityBits;$remaining=($remaining -shl 1) -band 255}
    Check 'model/contiguous-priority-mask' ($priorityBits -ge 1 -and $priorityBits -le 8 -and $remaining -eq 0) $priorityMask
    Check 'model/secure-privileged-scalar-reset' ((Scalar $probeLog 'MODEL_CONTROL') -eq 0 -and
        (Scalar $probeLog 'MODEL_CPACR') -eq 0 -and (Scalar $probeLog 'MODEL_SAU_CTRL') -eq 0 -and (Scalar $probeLog 'COMPILER_CMSE') -eq 3) $probeLog
    Check 'model/actual-M55-part-number' (((Scalar $probeLog 'MODEL_CPUID') -shr 4 -band 0xfff) -eq 0xd22) $probeLog
    @{MPUType=(Scalar $probeLog 'MODEL_MPU_TYPE');PriorityMask=$priorityMask;CmsisPriorityBits=$priorityBits;SecureOnly=$true;MPUEnabled=$false;FloatingPointEnabled=$false} |
        ConvertTo-Json | Set-Content (Join-Path $out 'model.json') -Encoding ASCII
    if(!$AdmissionOnly){CompilerAdversarial}
    if(!$CompilerAdversarialOnly) {
    foreach($optimization in @('-O2','-Os')) {
        foreach($lto in @(0,1)) {
            foreach($r9Mode in @('reserved','ordinary','reserved-hostile')) {
                if($AdmissionOnly -and $r9Mode -ne 'reserved'){continue}
                $reserved=if($r9Mode -eq 'ordinary'){0}else{1}
                $hostile=$r9Mode -ne 'reserved'
                foreach($policy in @('default','map','no-rewind')) {
                    if($AdmissionOnly -and $policy -ne 'default'){continue}
                    if($hostile -and $policy -ne 'default'){continue}
                    $mode="$($optimization.Substring(1))-lto$lto-$r9Mode-$policy"
                    Write-Host "C5SO $mode"
                    $dir=Join-Path $out $mode;$null=New-Item -ItemType Directory -Path $dir
                    $rewind=if($policy -eq 'no-rewind'){0}else{1};$map=if($policy -eq 'map'){1}else{0}
                    $flags=$base+@($optimization,'-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV81M_MAINLINE=1',
                        '-DFIBER_SCHEDULER_BASEPRI=128',"-DFIBER_REWIND_MSP=$rewind","-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=$map",
                        "-DEXEC_NVIC_PRIO_BITS=$priorityBits","-DEXEC_EXPECT_RUNTIME_SELECTABLE=$ExpectedRuntimeSelectable","-DEXEC_RESERVED_R9=$reserved",
                        "-I$fixture","-I$port","-I$repo","-I$repo/fiber","-I$repo/fiber/port","-I$CmsisCore")
                    if($reserved){$flags+='-ffixed-r9'}
                    if($hostile){$flags+=@('-frename-registers','-fno-omit-frame-pointer')}
                    if($lto){$flags+=@('-flto','-ffat-lto-objects')}
                    @{Mode=$mode;Optimization=$optimization;LTO=[bool]$lto;ReservedR9=[bool]$reserved;HostileCompiler=[bool]$hostile;
                        RewindMSP=$rewind;MapOnSwitch=$map;BootHashOnSwitch=1;StackCanary=1;PermissiveHooks=0;SchedulerBasepri=128;Flags=$flags} |
                        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $dir 'mode.json') -Encoding ASCII
                    $portObjects=@()
                    foreach($unit in @('fiber_port_boot.c','fiber_port.c')) {
                        $o=Join-Path $dir ($unit.Replace('.c','.o'));Compile (Join-Path $port $unit) $o $flags;$portObjects+=$o
                    }
                    $commonObjects=@();$commonFlags=@($flags | Where-Object {$_ -notin @("-I$fixture","-I$port","-I$CmsisCore")})
                    foreach($unit in @('fiber_core.c','fiber_runtime_state.c','fiber_panic.c')) {
                        $o=Join-Path $dir ($unit.Replace('.c','.o'));Compile (Join-Path $repo ('fiber/'+$unit)) $o $commonFlags
                        $deps=[IO.File]::ReadAllText([IO.Path]::ChangeExtension($o,'.d'))
                        Check "$mode/common-not-CMSIS-or-private-$unit" ($deps -notmatch '(fiber_port_(private|types|selected|context_cohort)\.h|core_cm[0-9]+\.h)') $deps
                        $commonObjects+=$o
                    }
                    $coreDefinitions=Defined $commonObjects[0]
                    foreach($public in @('fiber_init','fiber_current','fiber_schedule','fiber_start','fiber_scheduler_set_pick_next')) {
                        Check "$mode/exact-common-public-owner-$public" ([regex]::Matches($coreDefinitions,
                            '(?m)^[0-9a-f]+\s+T\s+'+[regex]::Escape($public)+'\r?$').Count -eq 1) $commonObjects[0]
                    }
                    $commonArchive=Join-Path $dir 'libcommon.a';$portArchive=Join-Path $dir 'libport.a'
                    Archive $commonArchive $commonObjects;Archive $portArchive $portObjects
                    $owned=@{}
                    for($j=0;$j -lt $portObjects.Count;++$j) {
                        $definitions=Defined $portObjects[$j]
                        $ops=@([regex]::Matches($definitions,'(?m)^[0-9a-f]+\s+[A-Z]\s+(fiber_port_runtime_\S+)\r?$') | ForEach-Object {$_.Groups[1].Value})
                        Check "$mode/no-new-generic-operation-$j" (@($ops | Where-Object {$_ -notin ($generic+@('fiber_port_runtime_prepare'))}).Count -eq 0) $ops
                        foreach($symbol in $generic) {
                            if($definitions -match ('(?m)^[0-9a-f]+\s+[A-Z]\s+'+[regex]::Escape($symbol)+'\r?$')) {
                                Check "$mode/unique-operation-$symbol" (!$owned.ContainsKey($symbol)) $definitions;$owned[$symbol]=$j
                            }
                        }
                    }
                    Check "$mode/exact-eight-operations" ($owned.Count -eq 8 -and $owned['fiber_port_context_init'] -eq 0 -and
                        @($generic | Where-Object {$_ -ne 'fiber_port_context_init' -and $owned[$_] -ne 1}).Count -eq 0) $owned
                    $definitions=Defined $portObjects[1]
                    $m=[regex]::Matches($definitions,'(?m)^[0-9a-f]+\s+[RD]\s+(fiber_port_context_cohort_\S+)\r?$')
                    Check "$mode/sole-real-private-cohort" ($m.Count -eq 1) $definitions;$cohort=$m[0].Groups[1].Value
                    $m=[regex]::Matches($definitions,'(?m)^[0-9a-f]+\s+[RD]\s+(fiber_port_storage_cohort_\S+)\r?$')
                    Check "$mode/sole-real-public-storage-provider" ($m.Count -eq 1) $definitions;$storageCohort=$m[0].Groups[1].Value
                    $expectation=Join-Path $dir 'expectation.o';Compile (Join-Path $repo 'fiber/port/fiber_port_context_cohort_expectation.c') $expectation $flags
                    $cases=if($AdmissionOnly){@(0)}elseif($policy -eq 'default'){@(0)+@(1..15)+@(18,19)}elseif($policy -eq 'map'){@(0,17)}else{@(0)}
                    foreach($case in $cases) {
                        $name="$mode-case$case";$caseDir=Join-Path $dir "case$case";$null=New-Item -ItemType Directory -Path $caseDir
                        $caseFlags=$flags+@("-DEXEC_CASE=$case",'-DEXEC_WEAK_STARTUP=1');$fixtureObjects=@()
                        foreach($unit in @('startup.S','construct.S','tasks.S','application.c','environment.c','oracle.c')) {
                            $o=Join-Path $caseDir ($unit.Replace('.','-')+'.o');Compile (Join-Path $fixture $unit) $o $caseFlags;$fixtureObjects+=$o
                        }
                        $members=@($fixtureObjects)+@($expectation,'-Wl,--start-group',$commonArchive,$portArchive,'-Wl,--end-group')
                        $elf=Join-Path $caseDir 'secure.elf';$result=Link $elf $members $flags
                        Check "$name/archive-weak-startup-link" ($result.Code -eq 0) $result.Text;Inspect $name $elf -Partial:($case -ne 0)
                        $marker=if($case -eq 0){'PASS:C5SO-FULL-RUNTIME'}else{'PASS:C5SO-RUNTIME-NEGATIVE'}
                        $log=Execute $name $elf $marker
                        if($case -eq 0){FullTrace $name $elf $log $reserved}
                        if($case -eq 0 -and $policy -eq 'default' -and $r9Mode -eq 'reserved'){LinkControls}
                    }
                }
            }
        }
    }
    }
    $executed=@($runs | Where-Object {$_.Executed})
    Check 'receipt/unique-execution-logs' (@($executed.Log | Sort-Object -Unique).Count -eq $executed.Count) $executed.Count
    AuditDependencies
    $null=Need 'wsl.exe' @('-d',$WslDistro,'--exec','bash',$qemuScript,'verify',$QemuRoot,$wslOut) (Join-Path $out 'qemu-inputs-verify.log')
    $finalHead=(Need 'git' @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head-after.txt')).Trim()
    Check 'reference/pin-stable-through-qualification' ($finalHead -ceq $pin) $finalHead
    $repositoryMetadataAfter=Get-SourceExportHeadMetadata $repo {
        param([string[]]$GitArguments)
        Recorded 'git' $GitArguments (Join-Path $out ('repository-metadata-after-'+[guid]::NewGuid().ToString('N')+'.log'))
    }
    $verdict='PASS'
} catch {
    $failure=$_.Exception.Message;[IO.File]::WriteAllText((Join-Path $out 'failure.txt'),$failure);throw
} finally {
    $after=HashInputs;$after | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $sourceIdentityAfter=Write-SourceExportManifest $repo $after $out after
    $drift=@(Compare-Object @($before | ForEach-Object {$_.Path+'='+$_.Hash}) @($after | ForEach-Object {$_.Path+'='+$_.Hash}))
    if($drift.Count){$verdict='FAIL'}
    $checks.ToArray() | ConvertTo-Json -Depth 7 | Set-Content (Join-Path $out 'checks.json') -Encoding ASCII
    $runs.ToArray() | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $out 'runs.json') -Encoding ASCII
    @{Verdict=$verdict;CompleteSuite=($verdict -eq 'PASS' -and !$CompilerAdversarialOnly -and !$AdmissionOnly);CompilerAdversarialOnly=[bool]$CompilerAdversarialOnly;AdmissionOnly=[bool]$AdmissionOnly;
        AdversarialAdmission=$AdversarialAdmission;CompilerAdversarialCases=$compilerCases.Count;Evidence=$out;Checks=$checks.Count;Drift=$drift;Failure=$failure;
        Executed=@($runs | Where-Object {$_.Executed}).Count;CompileOnly=@($runs | Where-Object {!$_.Executed}).Count;
        ReferencePin=$pin;ReferenceIdentityChecked=$referenceChecked;ReferenceAssemblyCompared=$false;ReferenceExecuted=$false;
        ExpectedRuntimeSelectable=$ExpectedRuntimeSelectable;QemuRoot=$QemuRoot;
        RepositoryHEADBefore=$(if($null -ne $repositoryMetadataBefore){$repositoryMetadataBefore.Head});
        RepositoryHEADAfter=$(if($null -ne $repositoryMetadataAfter){$repositoryMetadataAfter.Head});
        RepositoryMetadataBefore=$repositoryMetadataBefore;RepositoryMetadataAfter=$repositoryMetadataAfter;
        RepositoryInputMode='Explicit hashed source bytes; optional exact-root HEAD is not a clean-tree claim or source identity';
        SourceIdentitySchema=$sourceIdentityBefore.Schema;
        SourceIdentityKind=$sourceIdentityBefore.IdentityKind;
        SourceManifestSHA256Before=$sourceIdentityBefore.ManifestSHA256;SourceManifestSHA256After=$sourceIdentityAfter.ManifestSHA256;
        SourceManifestStable=($sourceIdentityBefore.ManifestSHA256 -ceq $sourceIdentityAfter.ManifestSHA256);
        CompilerAdversarialBoundary='All port/common objects raw-compiled; whole-port and common-sensitive bodies checked; executions use raw port and real neutral common objects';
        CompilerCounterflagsAccepted=$false;CommonColdExports=@('fiber_init','fiber_scheduler_set_pick_next');
        ColdOnlyCommonHelper='fiber_internal_scheduler_store_pick_next';
        CompiledAttributeRemovalControls=@($checks | Where-Object {$_.Name -match 'attribute-removal-rejected-(fiber_port_|in-hot-helper-body$)'}).Count;
        CompiledColdEdgeControls=@($checks | Where-Object {$_.Name -match '/compiled-sensitive-cold-edge-control-rejected$'}).Count;
        PortableDefaultLinks=@($runs | Where-Object {$_.Kind -eq 'PortableDefaultLinkOnly'}).Count;
        ConstructorArchiveMismatches=@($checks | Where-Object {$_.Name -match '/init-only-archive-exact-missing-v1$'}).Count;
        ProductionSourceHashes=@($before | Where-Object {$_.Path.StartsWith($port+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)});
        Boundary='Actual five-operation common / eight-operation C5SO provider; single-image Secure M55, basic frames only; no NS bootstrap, FP/MPU, FreeRTOS parity/execution, or hardware claim'} |
        ConvertTo-Json -Depth 7 | Set-Content (Join-Path $out 'receipt.json') -Encoding ASCII
    Get-ChildItem -LiteralPath $out -File -Recurse | Where-Object {$_.Name -ne 'artifact-hashes.json'} |
        ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256} | Select-Object Path,Hash |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'artifact-hashes.json') -Encoding ASCII
    if($drift.Count){throw "C5SO inputs changed during run: $out"}
}
$scope=if($AdmissionOnly){'selected-group admission only; CompleteSuite=false'}elseif($CompilerAdversarialOnly){'raw protected-port compiler phase only; CompleteSuite=false'}else{'full runtime'}
Write-Host "PASS: C5SO $scope ($($checks.Count) checks); evidence $out"
