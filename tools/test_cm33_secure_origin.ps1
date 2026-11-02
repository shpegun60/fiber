param(
    [string]$ArmGcc=$env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore=$env:CMSIS_CORE_INCLUDE,
    [Parameter(Mandatory=$true)][string]$QemuRoot,
    [string]$WslDistro='Ubuntu-24.04',
    [string]$BuildRoot,
    [string]$FreeRtosRoot=$env:FREERTOS_KERNEL_REFERENCE,
    [ValidateRange(2,120)][int]$TimeoutSeconds=30,
    [string[]]$DevelopmentModes,
    [int[]]$DevelopmentCases,
    [switch]$DevelopmentNoMutants
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $repo 'tools/runtime_sources.ps1')
$runtimeRoles=@('engine','state','legacy_compat','optional_configuration')
$runtimeSources=@(Get-RuntimeSourcePaths -RepositoryRoot $repo -Roles $runtimeRoles)
$fixture=Join-Path $PSScriptRoot 'fixtures\cm33_secure_origin'
$rsp=Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards\aircr_rsp.py'
$inventory=Join-Path $PSScriptRoot 'fixtures\arm_control\qemu.sh'
if(!$ArmGcc){$found=Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue;if($found){$ArmGcc=$found.Source}}
if(!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)){throw 'Supply -ArmGcc'}
if(!$QemuRoot.StartsWith('/')){throw 'Explicit absolute WSL -QemuRoot required'}
if(!$CmsisCore){$CmsisCore=Join-Path $repo '..\..\..\Drivers\CMSIS\Include'}
if(!$FreeRtosRoot){$FreeRtosRoot=Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel'}
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot=(Resolve-Path -LiteralPath $FreeRtosRoot).Path
$ns=Join-Path $repo 'fiber\port\ARM_CM33\non_secure'
$secure=Join-Path $repo 'fiber\port\ARM_CM33\secure'
$reference=Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM33\non_secure'
$bin=Split-Path $ArmGcc
$nm=Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$objdump=Join-Path $bin 'arm-none-eabi-objdump.exe'
$objcopy=Join-Path $bin 'arm-none-eabi-objcopy.exe'
$wsl=(Get-Command wsl.exe -ErrorAction Stop).Source
foreach($file in @($nm,$objdump,$objcopy,$rsp,$inventory)){if(!(Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing $file"}}
if(!$BuildRoot){$BuildRoot=[IO.Path]::GetTempPath()}
$out=Join-Path $BuildRoot ('fiber-cm33-secure-origin-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out -Force
$out=(Resolve-Path -LiteralPath $out).Path
Write-Host "C33 A30 evidence: $out"
$runs=New-Object System.Collections.Generic.List[object]
$checks=New-Object System.Collections.Generic.List[object]
$verdict='FAIL'
function Command([string]$Program,[string[]]$Arguments,[string]$Log,[switch]$AllowFailure){
    [pscustomobject]@{Program=$Program;Arguments=$Arguments;Log=$Log}|ConvertTo-Json -Depth 5 -Compress|
        Add-Content (Join-Path $out 'commands.jsonl') -Encoding ASCII
    $previous=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$lines=@(& $Program @Arguments 2>&1|ForEach-Object {"$_"});$code=$LASTEXITCODE}
    finally{$ErrorActionPreference=$previous}
    [IO.File]::WriteAllLines($Log,[string[]]$lines)
    if($code -ne 0 -and !$AllowFailure){throw "Command failed ($code): $Log`n$($lines -join "`n")"}
    if($AllowFailure){return [pscustomobject]@{ExitCode=$code;Text=($lines -join "`n")}}
    return ($lines -join "`n")
}
function Check([string]$Name,[bool]$Condition){if(!$Condition){throw "C33 origin: $Name"};$checks.Add([pscustomobject]@{Name=$Name;Passed=$true})}
function LinuxPath([string]$Path){return (Command $wsl @('-d',$WslDistro,'--exec','wslpath','-u',$Path) (Join-Path $out ('path-'+[guid]::NewGuid().ToString('N')+'.log'))).Trim()}
function Symbol([string]$Text,[string]$Name){
    $m=[regex]::Matches($Text,'(?m)^([0-9a-f]+)\s+(?:[0-9a-f]+\s+)?[a-zA-Z]\s+'+[regex]::Escape($Name)+'\r?$')
    Check "unique actual symbol $Name" ($m.Count -eq 1)
    return [Convert]::ToUInt32($m[0].Groups[1].Value,16)
}
function Compile([string]$Name,[string]$Source,[string[]]$Flags,[string]$Dir){
    $obj=Join-Path $Dir ($Name+'.o')
    $null=Command $ArmGcc ($Flags+@('-save-temps=obj','-MMD','-c',$Source,'-o',$obj)) (Join-Path $Dir ($Name+'-compile.log'))
    return $obj
}
function Link([string]$Name,[string[]]$Flags,[string[]]$Objects,[string]$Dir){
    $elf=Join-Path $Dir ($Name+'.elf')
    $null=Command $ArmGcc ($Flags+$Objects+@("-Wl,-Map,$Dir/$Name.map",'-o',$elf)) (Join-Path $Dir ($Name+'-link.log'))
    $symbols=Command $nm @('-a','-S',$elf) (Join-Path $Dir ($Name+'.nm'))
    $dis=Command $objdump @('-drwC','-Mreg-names-std',$elf) (Join-Path $Dir ($Name+'.dis'))
    Check "$Name empty actual undefined set" ((Command $nm @('-u',$elf) (Join-Path $Dir ($Name+'-undefined.log'))).Trim().Length -eq 0)
    return @{Elf=$elf;Symbols=$symbols;Dis=$dis}
}
$base=@('-mcpu=cortex-m33','-mthumb','-mfloat-abi=soft','-mgeneral-regs-only','-std=c11',
    '-ffreestanding','-fno-builtin','-fno-common','-ffunction-sections','-fdata-sections',
    '-fstrict-aliasing','-Wstrict-aliasing=3','-Wall','-Wextra','-Werror','-g3',
    "-I$fixture","-I$repo","-I$CmsisCore")
$link=@('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none')
$entries=@('fiber_secure_gateway_v1_abi_version','fiber_secure_gateway_v1_context_port_id',
    'fiber_secure_gateway_v1_context_layout_version','fiber_secure_gateway_v1_context_feature_mask',
    'fiber_secure_context_gateway_v1_abi_version','fiber_secure_context_gateway_v1_stack_alignment',
    'fiber_secure_context_gateway_v1_max_contexts','fiber_secure_context_gateway_v1_max_stack_bytes',
    'fiber_secure_context_gateway_v1_initialize','fiber_secure_context_gateway_v1_allocate',
    'fiber_secure_context_gateway_v1_save','fiber_secure_context_gateway_v1_load')
function Manifest([hashtable]$S,[hashtable]$N){
    $m=@{gateways=@();exits=@()}
    for($i=0;$i -lt $entries.Count;$i++){
        $name='__acle_se_'+$entries[$i]
        $operation=if($i -lt 8){"query-$i"}else{@('initialize','allocate','save','load')[$i-8]}
        $address=Symbol $S.Symbols $name
        $m.gateways+=@{address=$address;operation=$operation}
        $body=[regex]::Matches($S.Dis,'(?ms)^[0-9a-f]+ <'+[regex]::Escape($name)+'>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
        Check "$name actual body" ($body.Count -eq 1)
        $returns=[regex]::Matches($body[0].Groups[1].Value,'(?m)^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+bxns\s+lr\s*\r?$')
        Check "$name real BXNS" ($returns.Count -gt 0)
        foreach($site in $returns){$m.exits+=@{address=[Convert]::ToUInt32($site.Groups[1].Value,16);operation=$operation}}
    }
    foreach($row in @(@('secure_ready','origin_secure_ready'),@('s_checkpoint','origin_secure_checkpoint'),@('s_resumed','origin_secure_resumed'),
        @('records','fiber_secure_context_pool_records'),@('stacks_s','fiber_secure_context_pool_stacks'),
        @('pool_state','fiber_secure_context_pool_initialized'),@('gateway_state','fiber_secure_context_gateway_state'),
        @('pool_start','__pool_start'),@('pool_end','__pool_end'))){$m[$row[0]]=Symbol $S.Symbols $row[1]}
    foreach($row in @(@('prepared','origin_prepared'),@('task_entry','origin_task'),@('task_return','fiber_internal_task_return'),
        @('pendsv','PendSV_Handler'),@('selector','origin_pick'),@('ns_checkpoint','origin_ns_checkpoint'),@('ns_resumed','origin_ns_resumed'),
        @('contexts','origin_contexts'),@('selected','origin_selected'),@('stacks_ns','origin_stacks'),
        @('current_slot','fiber_internal_runtime_current_context_slot'),@('live_handle','fiber_port_current_secure_context_handle'),@('panic','fiber_panic'))){$m[$row[0]]=Symbol $N.Symbols $row[1]}
    $body=[regex]::Matches($N.Dis,'(?ms)^[0-9a-f]+ <PendSV_Handler>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
    Check 'actual PendSV body' ($body.Count -eq 1)
    $returns=[regex]::Matches($body[0].Groups[1].Value,'(?m)^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+bx\s+lr\s*\r?$')
    Check 'one final PendSV BX LR' ($returns.Count -eq 1)
    $m.pd_return=[Convert]::ToUInt32($returns[0].Groups[1].Value,16)
    $validator=[regex]::Matches($N.Symbols,'(?m)^([0-9a-f]+)\s+([0-9a-f]+)\s+[tT]\s+fiber_port_context_validate_restore\r?$')
    Check 'bounded actual restore-validator symbol extent' ($validator.Count -eq 1)
    $m.validator_start=[Convert]::ToUInt32($validator[0].Groups[1].Value,16)
    $m.validator_end=$m.validator_start+[Convert]::ToUInt32($validator[0].Groups[2].Value,16)
    return $m
}
function Build([hashtable]$Mode,[string]$Dir,[switch]$Stale){
    $null=New-Item -ItemType Directory -Path $Dir -Force
    Check 'exact four-source active C33 NS provider' (!(Compare-Object @('fiber_port.c','fiber_port_boot.c','fiber_port_secure_context.c','fiber_port_svc.c') @(Get-ChildItem $ns -File -Filter '*.c'|Select-Object -ExpandProperty Name)))
    Check 'exact three-source C33 Secure provider' (!(Compare-Object @('fiber_secure_gateway.c','fiber_secure_context_gateway.c','fiber_secure_context_pool.c') @(Get-ChildItem $secure -File -Filter '*.c'|Select-Object -ExpandProperty Name)))
    $selected=$secure
    if($Stale){
        $selected=Join-Path $Dir 'mirror\fiber\port\ARM_CM33\secure'
        $null=New-Item -ItemType Directory -Path $selected -Force
        Get-ChildItem $secure -File|Where-Object {$_.Extension -in @('.h','.c')}|ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $selected $_.Name)}
        Copy-Item -LiteralPath (Join-Path $repo 'fiber\fiber_api_attributes.h') -Destination (Join-Path $Dir 'mirror\fiber\fiber_api_attributes.h')
        $contextMirror=Join-Path $Dir 'mirror\context'
        $null=New-Item -ItemType Directory -Path $contextMirror -Force
        Get-ChildItem (Join-Path $repo 'context') -File -Filter '*.h' | ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $contextMirror $_.Name)}
        $contract=Join-Path $selected 'fiber_secure_gateway_contract.h'
        $text=Get-Content $contract -Raw
        Check 'one exact stale layout substitution' ([regex]::Matches($text,'0x00020001u').Count -eq 1)
        [IO.File]::WriteAllText($contract,$text.Replace('0x00020001u','0x00010001u'))
    }
    $sf=$base+$Mode.Flags+@('-mcmse','-DORIGIN_SECURE=1',"-I$selected",'-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3u','-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=1024u')
    $nf=$base+$Mode.Flags+@('-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV8M_MAINLINE=1',"-I$ns")
    $sobjects=@()
    foreach($name in @('secure.c','startup.S','windows.S','support.c')){$sobjects+=Compile ('s-'+$name) (Join-Path $fixture $name) $sf $Dir}
    foreach($name in @('fiber_secure_gateway.c','fiber_secure_context_gateway.c','fiber_secure_context_pool.c')){$sobjects+=Compile $name (Join-Path $selected $name) $sf $Dir}
    $roots=@($entries|ForEach-Object {"-Wl,--undefined=$_"})
    $import=Join-Path $Dir 'secure-import.o'
    $sflags=$sf+$link+$roots+@('-T',(Join-Path $fixture 'secure.ld'),'-T',(Join-Path $secure 'fiber_secure_context_cohort_contract.ld'),'-Wl,--section-start=.gnu.sgstubs=0x10008000',"-Wl,--cmse-implib,--out-implib=$import")
    $s=Link 'secure' $sflags $sobjects $Dir
    $nfixture=@()
    foreach($name in @('nonsecure.c','startup.S','windows.S','support.c')){$nfixture+=Compile ('n-'+$name) (Join-Path $fixture $name) $nf $Dir}
    foreach($source in $runtimeSources){
        $name=$source.Substring($repo.Length+1).Replace('\','_').Replace('/','_')
        $nfixture+=Compile $name $source $nf $Dir
    }
    $nobjects=@()
    foreach($name in @('fiber_port.c','fiber_port_boot.c','fiber_port_secure_context.c','fiber_port_svc.c')){$nobjects+=Compile $name (Join-Path $ns $name) $nf $Dir}
    $nflags=$nf+$link+@('-T',(Join-Path $fixture 'nonsecure.ld'))
    $n=Link 'nonsecure' $nflags ($nfixture+$nobjects+@($import)) $Dir
    return @{Secure=$s;Nonsecure=$n;Manifest=(Manifest $s $n);Directory=$Dir;NFixture=$nfixture;NObjects=$nobjects;NFlags=$nf;NLink=$nflags;Import=$import}
}
function Execute([hashtable]$Model,[string]$Label,[int]$Case,[string]$ExpectedError='',[hashtable]$Extra=@{}){
    $dir=Join-Path $Model.Directory $Label;$null=New-Item -ItemType Directory -Path $dir -Force
    $scenario=if($Case -lt 10){$Case}else{1}
    if($Case -eq 20){$scenario=0}
    $word=Join-Path $dir 'case.bin';[IO.File]::WriteAllBytes($word,[BitConverter]::GetBytes([uint32]$scenario))
    $elf=Join-Path $dir 'case.elf'
    $null=Command $objcopy @('--update-section',".fixture_case=$word",$Model.Nonsecure.Elf,$elf) (Join-Path $dir 'case-patch.log')
    $m=@{};foreach($key in $Model.Manifest.Keys){$m[$key]=$Model.Manifest[$key]}
    $m.case=$Case;$m.scenario=$scenario
    foreach($key in $Extra.Keys){$m[$key]=$Extra[$key]}
    $m.secure=LinuxPath $Model.Secure.Elf;$m.nonsecure=LinuxPath $elf
    $m.secure_sha256=(Get-FileHash $Model.Secure.Elf -Algorithm SHA256).Hash
    $m.nonsecure_sha256=(Get-FileHash $elf -Algorithm SHA256).Hash
    $manifest=Join-Path $dir 'manifest.json';$m|ConvertTo-Json -Depth 8|Set-Content $manifest -Encoding ASCII
    $result=Command $wsl @('-d',$WslDistro,'--exec','python3','-B',"$linuxFixture/run.py",$QemuRoot,"$TimeoutSeconds",(LinuxPath $manifest),$linuxRsp) (Join-Path $dir 'run.log') -AllowFailure
    $receipt=Get-Content (Join-Path $dir 'receipt.json') -Raw|ConvertFrom-Json
    if($ExpectedError){
        Check "$Label exact compiled counterexample" ($result.ExitCode -eq 1 -and $receipt.result -ceq 'FAIL' -and $receipt.error_type -ceq 'RuntimeError' -and $receipt.error -ceq $ExpectedError)
        Check "$Label observed real FC entry" (@($receipt.trace|Where-Object {($_.event -eq 'pendsv') -and ($_.cpu.lr -eq [uint32]::Parse('FFFFFFFC',[Globalization.NumberStyles]::HexNumber))}).Count -gt 0)
    }else{Check "$Label actual execution PASS" ($result.ExitCode -eq 0 -and $receipt.result -ceq 'PASS')}
    $runs.Add([pscustomobject]@{Label=$Label;Case=$Case;ExpectedError=$ExpectedError;Receipt=(Join-Path $dir 'receipt.json')})
    return $receipt
}
function Controls([hashtable]$Model){
    $controls=@(
        @{Name='reject-S-origin';File='fiber_port_svc.c';Pattern='"bic\s+r3, r3, #0x40\s+\\n"';Replacement='"nop\n"';Case=1;Error='unexpected-panic-106';Panic=106},
        @{Name='store-NS-GPRs-for-S';File='fiber_port_svc.c';Pattern='"bne\s+84f\s+\\n"';Replacement='"nop\n"';Case=1;Error='saved-size'},
        @{Name='load-NS-GPRs-for-S';File='fiber_port_svc.c';Pattern='"bne\s+85f\s+\\n"';Replacement='"nop\n"';Case=1;Error='restore-NS-PSP'},
        @{Name='decode-NS-HW-for-S';File='fiber_port_boot.c';Pattern=[regex]::Escape('if (exc_return == fiber_portSECURE_ORIGIN_EXC_RETURN) {');Replacement='if (0u) {';Case=10;Error='unexpected-panic-88';Panic=88},
        @{Name='omit-header-extent';File='fiber_port_boot.c';Pattern='FIBER_REQUIRE\(available >= \(uintptr_t\)fiber_portSECURE_HEADER_BYTES,\s*''X''\);';Replacement='';Case=11;Error='header-read-before-extent-rejection';ReadWatch=$true})
    foreach($control in $controls){
        $dir=Join-Path $Model.Directory $control.Name;$null=New-Item -ItemType Directory -Path $dir
        $text=Get-Content (Join-Path $ns $control.File) -Raw
        Check "$($control.Name) one actual source mutation" ([regex]::Matches($text,$control.Pattern).Count -eq 1)
        $copy=Join-Path $dir 'actual-mutant.c'
        [IO.File]::WriteAllText($copy,[regex]::Replace($text,$control.Pattern,$control.Replacement))
        $object=Compile 'mutant' $copy $Model.NFlags $dir
        $objects=@($Model.NObjects|ForEach-Object {if((Split-Path $_ -Leaf) -ceq ($control.File+'.o')){$object}else{$_}})
        Check "$($control.Name) selected actual object replaced" ($object -cin $objects)
        $n=Link 'nonsecure' $Model.NLink ($Model.NFixture+$objects+@($Model.Import)) $dir
        $modelCopy=@{Secure=$Model.Secure;Nonsecure=$n;Manifest=(Manifest $Model.Secure $n);Directory=$dir}
        $receipt=Execute $modelCopy 'compiled-control' $control.Case $control.Error
        if($control.ContainsKey('Panic')){
            $observed=@($receipt.trace|Where-Object event -eq panic)
            Check "$($control.Name) exact panic and real PendSV origin" ($observed.Count -eq 1 -and $observed[0].code -eq $control.Panic -and ($observed[0].cpu.xpsr -band 511) -eq 14)
        }elseif($control.ContainsKey('ReadWatch')){
            $observed=@($receipt.trace|Where-Object event -eq header-read-before-extent-rejection)
            Check 'actual out-of-extent header read watchpoint counterexample' ($observed.Count -eq 1 -and $observed[0].address -eq $observed[0].expected_address -and ($observed[0].cpu.xpsr -band 511) -eq 14)
        }elseif($control.Name -eq 'store-NS-GPRs-for-S'){
            $observed=@($receipt.trace|Where-Object event -eq selector-observed|Select-Object -Last 1)
            Check 'extra 32-byte Secure-origin NS save counterexample' ($observed.Count -eq 1 -and ($observed[0].expected_saved-$observed[0].saved) -eq 32)
        }elseif($control.Name -eq 'load-NS-GPRs-for-S'){
            $observed=@($receipt.trace|Where-Object event -eq Secure-restore-before-BX|Select-Object -Last 1)
            Check 'extra 32-byte Secure-origin NS restore counterexample before BX' ($observed.Count -eq 1 -and ($observed[0].cpu.psp_ns-$observed[0].expected_psp) -eq 32)
        }
    }
}
$modes=@(@{Name='o0';Flags=@('-O0')},@{Name='o2';Flags=@('-O2')},@{Name='os';Flags=@('-Os')},@{Name='o2-lto';Flags=@('-O2','-flto')},@{Name='os-lto';Flags=@('-Os','-flto')})
if($DevelopmentModes){foreach($name in $DevelopmentModes){if($name -notin $modes.Name){throw "Unknown mode $name"}};$modes=@($modes|Where-Object {$_.Name -in $DevelopmentModes})}
$cases=@(0..4)+@(10..13)
if($PSBoundParameters.ContainsKey('DevelopmentCases')){foreach($n in $DevelopmentCases){if($n -notin $cases){throw "Unknown case $n"}};$cases=@($DevelopmentCases|Sort-Object -Unique)}
$inputs=@($PSCommandPath,$ArmGcc,$nm,$objdump,$objcopy,$rsp,$inventory,(Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h'))+
    @(Get-RuntimeSourceInputs -RepositoryRoot $repo -Roles $runtimeRoles)+
    @(Get-ChildItem (Join-Path $repo 'context') -File | Where-Object {$_.Extension -in @('.c','.h')} | Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $fixture -Recurse -File|Where-Object FullName -notmatch '__pycache__'|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $CmsisCore -Recurse -File -Filter '*.h'|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem (Join-Path $repo 'fiber') -File|Where-Object {$_.Extension -in @('.c','.h')}|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem (Join-Path $repo 'fiber/port') -File -Filter '*.h'|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $ns,$secure -File|Where-Object {$_.Extension -in @('.c','.h','.ld')}|Select-Object -ExpandProperty FullName)+
    @((Join-Path $reference 'portasm.c'),(Join-Path $reference 'port.c'))
$inputs=@($inputs|Sort-Object -Unique)
$before=@($inputs|ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256}|Select-Object Path,Hash)
$before|ConvertTo-Json -Depth 4|Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII
try{
    Check 'exact FreeRTOS pin' ((Command git @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.log')).Trim() -ceq 'a50edad08b29052631aa469d4df6e6ec7ff68878')
    $null=Command git @('-C',$FreeRtosRoot,'diff','--exit-code','HEAD','--') (Join-Path $out 'reference-clean.log')
    $null=Command $ArmGcc @('--version') (Join-Path $out 'compiler-version.log')
    $linuxFixture=LinuxPath $fixture;$linuxRsp=LinuxPath $rsp
    $null=Command $wsl @('-d',$WslDistro,'--exec','bash',(LinuxPath $inventory),'inspect',$QemuRoot,(LinuxPath $out)) (Join-Path $out 'qemu-inspect.log')
    Check 'exact direct/extraction/import optimized guards and counterfeit control' ((Command $wsl @('-d',$WslDistro,'--exec','python3','-B',"$linuxFixture/run.py",'--preflight') (Join-Path $out 'python-preflight.log')).Trim() -ceq 'PASS:C33-ORIGIN:Python-guards:7')
    foreach($mode in $modes){
        $dir=Join-Path $out $mode.Name
        $model=Build $mode $dir
        foreach($case in $cases){$null=Execute $model "case-$case" $case}
        if(!$DevelopmentNoMutants){Controls $model}
        $stale=Build $mode (Join-Path $dir 'stale-layout1') -Stale
        $null=Execute $stale 'stale-companion' 20
    }
    $verdict='PASS'
}finally{
    $after=@($inputs|ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256}|Select-Object Path,Hash)
    $after|ConvertTo-Json -Depth 4|Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $drift=@(Compare-Object $before $after -Property Path,Hash);if($drift.Count){$verdict='FAIL'}
    [pscustomobject]@{Verdict=$verdict;CompleteSuite=!($DevelopmentModes -or $PSBoundParameters.ContainsKey('DevelopmentCases') -or $DevelopmentNoMutants);Launches=$runs.Count;Checks=$checks.Count;InputCount=$before.Count;InputDrift=$drift.Count;
        Runs=@($runs.ToArray());Assertions=@($checks.ToArray());Limit='AN505 actual M33 two-image runtime and separately labelled stopped representation probes; no hardware claim or M55 runtime qualification. FreeRTOS comparison is pinned source, not executed in this runner.'}|
        ConvertTo-Json -Depth 8|Set-Content (Join-Path $out 'results.json') -Encoding ASCII
    Get-ChildItem $out -Recurse -File|Where-Object Name -ne sha256.csv|ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256}|
        Select-Object Path,Hash|Export-Csv (Join-Path $out 'sha256.csv') -NoTypeInformation -Encoding ASCII
    if($drift.Count){throw "Input drift: $out"}
}
if($verdict -ne 'PASS'){throw "C33 origin proof failed: $out"}
Write-Host "PASS C33 Secure-origin: $($runs.Count) launches; $out"
