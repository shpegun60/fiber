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
    [string[]]$DevelopmentPolicies,
    [string[]]$DevelopmentR9Modes,
    [switch]$DevelopmentModelOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture=Join-Path $PSScriptRoot 'fixtures\m55_secure_runtime'
if(!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)){throw 'Supply existing -ArmGcc'}
if(!$QemuRoot.StartsWith('/')){throw 'Explicit existing absolute WSL -QemuRoot required'}
if(!$CmsisCore){$CmsisCore=Join-Path $repo '..\..\..\Drivers\CMSIS\Include'}
if(!$FreeRtosRoot){$FreeRtosRoot=Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel'}
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot=(Resolve-Path -LiteralPath $FreeRtosRoot).Path
$refns=Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM55\non_secure'
$refs=Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM55\secure'
$ns=Join-Path $repo 'fiber\port\ARM_CM55\non_secure'
$secure=Join-Path $repo 'fiber\port\ARM_CM55\secure'
$foreign=Join-Path $repo 'fiber\port\ARM_CM33\secure'
$bin=Split-Path $ArmGcc
$nm=Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$objdump=Join-Path $bin 'arm-none-eabi-objdump.exe'
$objcopy=Join-Path $bin 'arm-none-eabi-objcopy.exe'
$readelf=Join-Path $bin 'arm-none-eabi-readelf.exe'
$ar=Join-Path $bin 'arm-none-eabi-gcc-ar.exe'
$wsl=(Get-Command wsl.exe -ErrorAction Stop).Source
$rsp=Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards\aircr_rsp.py'
$inventory=Join-Path $PSScriptRoot 'fixtures\arm_control\qemu.sh'
foreach($file in @($nm,$objdump,$objcopy,$readelf,$ar,$rsp,$inventory)){if(!(Test-Path -LiteralPath $file)){throw "Missing $file"}}
if(!$BuildRoot){$BuildRoot=[IO.Path]::GetTempPath()}
$out=Join-Path $BuildRoot ('fiber-m55-secure-runtime-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out -Force
$out=(Resolve-Path -LiteralPath $out).Path
Write-Host "C55S runtime evidence: $out"
$commands=Join-Path $out 'commands.jsonl'
$runs=New-Object System.Collections.Generic.List[object]
$checks=New-Object System.Collections.Generic.List[object]
$verdict='FAIL'
function Command([string]$Program,[string[]]$Arguments,[string]$Log,[switch]$AllowFailure){
    [pscustomobject]@{Program=$Program;Arguments=$Arguments;Log=$Log}|ConvertTo-Json -Depth 5 -Compress|Add-Content $commands -Encoding ASCII
    $old=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$lines=@(& $Program @Arguments 2>&1|ForEach-Object {"$_"});$code=$LASTEXITCODE}
    finally{$ErrorActionPreference=$old}
    [IO.File]::WriteAllLines($Log,[string[]]$lines)
    if($code -ne 0 -and !$AllowFailure){throw "Command failed ($code): $Log`n$($lines -join "`n")"}
    if($AllowFailure){return [pscustomobject]@{ExitCode=$code;Text=($lines -join "`n")}}
    return ($lines -join "`n")
}
function Check([string]$Name,[bool]$Value){if(!$Value){throw "Running proof: $Name"};$checks.Add([pscustomobject]@{Name=$Name;Passed=$true})}
function LinuxPath([string]$Path){return (Command $wsl @('-d',$WslDistro,'--exec','wslpath','-u',$Path) (Join-Path $out ('wslpath-'+[guid]::NewGuid().ToString('N')+'.log'))).Trim()}
function Symbol([string]$Symbols,[string]$Name){
    $found=[regex]::Matches($Symbols,'(?m)^([0-9a-f]+)\s+(?:[0-9a-f]+\s+)?[a-zA-Z]\s+'+[regex]::Escape($Name)+'\r?$')
    if($found.Count -ne 1){throw "Missing unique symbol $Name"}
    return [Convert]::ToUInt32($found[0].Groups[1].Value,16)
}
function PublicTrigger([hashtable]$N){
    $body=[regex]::Matches($N.Dis,'(?ms)^[0-9a-f]+ <fiber_port_runtime_schedule>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
    Check 'unique actual public-schedule body' ($body.Count -eq 1)
    $stores=@([regex]::Matches($body[0].Groups[1].Value,'(?m)^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?: [0-9a-f]{4})?)\s+str(?:\.w)?\s+(r\d+|ip|lr),\s*\[(r\d+|ip|lr)(?:,\s*#(\d+))?\]\s*(?:@[^\r\n]*)?\r?$'))
    Check 'exactly one generated non-stack schedule store' ($stores.Count -eq 1)
    $row=$stores[0]
    return @{address=[Convert]::ToUInt32($row.Groups[1].Value,16);size=[int]($row.Groups[2].Value.Replace(' ','').Length/2);
        value=$row.Groups[3].Value;base=$row.Groups[4].Value;offset=$(if($row.Groups[5].Success){[int]$row.Groups[5].Value}else{0})}
}
function Compile([string]$Name,[string]$Source,[string[]]$Flags,[string]$Dir){
    $object=Join-Path $Dir ($Name+'.o')
    $null=Command $ArmGcc ($Flags+@('-save-temps=obj','-MMD','-c',$Source,'-o',$object)) (Join-Path $Dir ($Name+'-compile.log'))
    return $object
}
function Link([string]$Name,[string[]]$Flags,[string[]]$Objects,[string]$Dir){
    $elf=Join-Path $Dir ($Name+'.elf')
    $null=Command $ArmGcc ($Flags+$Objects+@("-Wl,-Map,$Dir/$Name.map",'-o',$elf)) (Join-Path $Dir ($Name+'-link.log'))
    $symbols=Command $nm @('-a','-S',$elf) (Join-Path $Dir ($Name+'.nm'))
    $dis=Command $objdump @('-drwC',$elf) (Join-Path $Dir ($Name+'.dis'))
    Check "$Name empty final undefined set" ((Command $nm @('-u',$elf) (Join-Path $Dir ($Name+'-undefined.log'))).Trim().Length -eq 0)
    Check "$Name no instrumentation dependency/counter" ($symbols -notmatch '(?i)(__cyg_profile|__gcov|__ubsan|__asan|__tsan|__sanitizer|__stack_chk|__morestack|__mcount|__chkstk)')
    return @{Elf=$elf;Symbols=$symbols;Dis=$dis}
}
$queries=@('fiber_secure_gateway_c55s_v1_abi_version','fiber_secure_gateway_c55s_v1_context_port_id',
    'fiber_secure_gateway_c55s_v1_context_layout_version','fiber_secure_gateway_c55s_v1_context_feature_mask',
    'fiber_secure_context_gateway_c55s_v1_abi_version','fiber_secure_context_gateway_c55s_v1_stack_alignment',
    'fiber_secure_context_gateway_c55s_v1_max_contexts','fiber_secure_context_gateway_c55s_v1_max_stack_bytes')
$gateways=$queries+@('fiber_secure_context_gateway_c55s_v1_initialize','fiber_secure_context_gateway_c55s_v1_allocate',
    'fiber_secure_context_gateway_c55s_v1_save','fiber_secure_context_gateway_c55s_v1_load')
function GatewayManifest([hashtable]$S,[hashtable]$N,[bool]$Reference){
    $functions=@()
    if($Reference){
        foreach($row in @(@('priority','SecureInit_DePrioritizeNSExceptions'),@('initialize','SecureContext_Init'),
            @('allocate','SecureContext_AllocateContext'),@('save','SecureContext_SaveContext'),@('load','SecureContext_LoadContext'))){
            $functions+=@{operation=$row[0];name=$row[1]}
        }
    }else{
        $queries=@('fiber_secure_gateway_c55s_v1_abi_version','fiber_secure_gateway_c55s_v1_context_port_id',
            'fiber_secure_gateway_c55s_v1_context_layout_version','fiber_secure_gateway_c55s_v1_context_feature_mask',
            'fiber_secure_context_gateway_c55s_v1_abi_version','fiber_secure_context_gateway_c55s_v1_stack_alignment',
            'fiber_secure_context_gateway_c55s_v1_max_contexts','fiber_secure_context_gateway_c55s_v1_max_stack_bytes')
        for($i=0;$i -lt 8;$i++){$functions+=@{operation="query-$i";name=$queries[$i]}}
        foreach($op in @('initialize','allocate','save','load')){
            $functions+=@{operation=$op;name=('fiber_secure_context_gateway_c55s_v1_'+$op)}
        }
    }
    $entries=@();$exits=@()
    foreach($function in $functions){
        $name='__acle_se_'+$function.name
        $address=Symbol $S.Symbols $name
        $body=[regex]::Matches($S.Dis,'(?ms)^[0-9a-f]+ <'+[regex]::Escape($name)+'>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
        Check "$name has unique actual entry body" ($body.Count -eq 1)
        $returns=@([regex]::Matches($body[0].Groups[1].Value,'(?m)^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+bxns\s+lr\s*\r?$'))
        Check "$name has actual BXNS epilogue" ($returns.Count -gt 0)
        $entries+=@{address=$address;operation=$function.operation}
        foreach($site in $returns){$exits+=@{address=[Convert]::ToUInt32($site.Groups[1].Value,16);operation=$function.operation}}
    }
    return @{entries=$entries;exits=$exits;reference_tail_load=($Reference -and $N.Dis -match '\bb\.w\s+[0-9a-f]+ <__SecureContext_LoadContext_veneer>')}
}
$base=@('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-mgeneral-regs-only','-ffreestanding','-fno-builtin',
    '-fno-common','-ffunction-sections','-fdata-sections','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
    '-fstrict-aliasing','-Wstrict-aliasing=3','-Wall','-Wextra','-Werror','-g3')
$link=@('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none')
$modes=@(@{Name='o2';Flags=@('-O2')},@{Name='os';Flags=@('-Os')},
    @{Name='o2-lto';Flags=@('-O2','-flto')},@{Name='os-lto';Flags=@('-Os','-flto')},
    @{Name='o2-archive';Flags=@('-O2');Archive=$true},@{Name='os-archive';Flags=@('-Os');Archive=$true},
    @{Name='o2-archive-lto';Flags=@('-O2','-flto');Archive=$true},@{Name='os-archive-lto';Flags=@('-Os','-flto');Archive=$true},
    @{Name='o2-hostile';Flags=@('-O2');Hostile=$true},@{Name='os-hostile';Flags=@('-Os');Hostile=$true})
$complete=@($PSBoundParameters.Keys|Where-Object {$_ -like 'Development*'}).Count -eq 0
$policies=@(@{Name='00';Hash=0;Map=0},@{Name='01';Hash=0;Map=1},@{Name='10';Hash=1;Map=0},@{Name='11';Hash=1;Map=1})
$r9Modes=@(@{Name='ordinary';Flags=@()},@{Name='reserved';Flags=@('-ffixed-r9')})
if($DevelopmentPolicies){foreach($name in $DevelopmentPolicies){if($name -notin $policies.Name){throw "Unknown policy $name"}};$policies=@($policies|Where-Object {$_.Name -in $DevelopmentPolicies})}
if($DevelopmentR9Modes){foreach($name in $DevelopmentR9Modes){if($name -notin $r9Modes.Name){throw "Unknown r9 mode $name"}};$r9Modes=@($r9Modes|Where-Object {$_.Name -in $DevelopmentR9Modes})}
if($DevelopmentModes){foreach($name in $DevelopmentModes){if($name -notin $modes.Name){throw "Unknown mode $name"}};$modes=@($modes|Where-Object {$_.Name -in $DevelopmentModes})}
$attacks=@{
    400='entry:exc-dcrs:x:0:0';401='entry:exc-es:x:0:0';402='entry:exc-mode:x:0:0';403='entry:exc-fp:x:0:0';404='entry:exc-stack:x:0:0';405='entry:exc-fake-secure:D:0:0';
    410='entry:control:l:0:0';411='entry:primask:l:0:0';412='entry:basepri:l:0:0';413='entry:faultmask:l:0:0';414='entry:psplim:L:0:0';
    420='entry:current-zero:D:0:0';421='entry:current-unaligned:C:0:0';422='entry:current-foreign:C:0:0';423='entry:current-msp:C:0:0';424='entry:current-overflow:O:0:0';
    430='entry:psp-unaligned:x:0:0';431='entry:psp-zero:P:0:0';432='entry:psp-underflow:P:0:0';433='entry:psp-overflow:P:0:0';434='prepare:psp-argument:P:0:0';
    440='entry:hw-t:X:0:0';441='entry:hw-ipsr:X:0:0';442='entry:hw-pc-odd:x:0:0';443='entry:hw-pc-zero:x:0:0';444='entry:hw-pc-foreign:c:0:0';
    450='entry:current-hash:h:0:0';451='entry:current-canary:c:0:0';
    461='selector:next-sp-unaligned:A:2:0';462='selector:next-sp-foreign:P:2:0';463='selector:next-sp-short:X:2:0';
    464='selector:next-hash:h:2:0';465='selector:next-canary:c:2:0';466='selector:next-psplim:L:2:0';467='selector:next-exc:x:2:0';
    468='selector:next-hw-t:X:2:0';469='selector:next-hw-pc:x:2:0';470='selector:next-cold-r0:0:2:1';471='selector:next-cold-pc:x:2:1';472='selector:next-cold-r4:4:2:1';
    480='selector:primask:p:2:0';481='selector:control:l:2:0';482='selector:basepri:b:2:0';483='selector:faultmask:f:2:0';484='selector:psplim:L:2:0';485='selector:psp:P:2:0';
    510='save:secure-control:Q:1:1';511='save:secure-psplim:Q:1:1';512='save:secure-psp:Q:1:1';
    513='save:gateway-owner:Q:1:1';514='load:gateway-handle:Q:4:1';515='load:gateway-owner:Q:4:1';516='save:record-owner:Q:1:1';
    520='save:seal-first:!:1:1';521='save:seal-second:!:1:1';522='save:record-pointer:!:1:1';523='save:record-limit:!:1:1';
    530='save-exit:return-zero:Q:1:1';531='allocate-exit:return-zero:D:3:1';532='load-exit:return-zero:Q:4:1'
}
for($i=0;$i -lt 8;$i++){
    $attacks[540+$i]="query-$i-exit`:return-zero:Q:3:1"
    $attacks[550+$i]="query-$i`:primask:p:3:1"
}
$attacks[560]='query-7:control:l:3:1';$attacks[561]='query-7:basepri:b:3:1'
$attacks[562]='query-7:faultmask:f:3:1';$attacks[563]='query-7:psplim:L:3:1'
$life=@{
    100=@{Fault=20;Code=75;Origin=0};101=@{Fault=21;Code=71;Origin=0};102=@{Fault=22;Code=75;Origin=0};
    103=@{Fault=1;Code=78;Origin=0};104=@{Fault=2;Code=78;Origin=14};
    105=@{Fault=3;Code=107;Origin=0};106=@{Fault=4;Code=69;Origin=0};107=@{Fault=5;Code=107;Origin=0};108=@{Fault=6;Code=107;Origin=0};
    110=@{Fault=10;Code=107;Origin=0};111=@{Fault=11;Code=107;Origin=0};112=@{Fault=12;Code=69;Origin=0};113=@{Fault=13;Code=107;Origin=0};114=@{Fault=14;Code=82;Origin=0};
    116=@{Fault=16;Code=105;Origin=14};117=@{Fault=17;Code=105;Origin=14};118=@{Fault=18;Code=107;Origin=14}
}
$policyFaults=@{200=30;201=31;202=32;203=33;204=34;205=35;206=36;207=37;208=38;209=39}
$policyCodes=@{30=104;31=67;32=99;33=112;34=108;35=98;36=102;37=76;38=80;39=112}
$cpuProbes=@{}
$number=300
foreach($site in @('prestart','public-api','first-callback','running-callback')){
    $fields=@('control','primask','basepri','faultmask')
    if($site -like '*callback'){$fields+=@('psplim','psp')}
    foreach($field in $fields){
        $cpuProbes[$number]=@{site=$site;field=$field;code=@{control=108;primask=112;basepri=98;faultmask=102;psplim=76;psp=80}[$field];origin=$(if($site -eq 'running-callback'){14}else{0})}
        $number++
    }
}
$cases=@(0..4)+@($life.Keys|Sort-Object)+@($policyFaults.Keys|Sort-Object)+@($cpuProbes.Keys|Sort-Object)+@($attacks.Keys|Sort-Object)
$explicitCases=$PSBoundParameters.ContainsKey('DevelopmentCases')
if($explicitCases){foreach($n in $DevelopmentCases){if($n -notin $cases){throw "Unknown case $n"}};$cases=@($DevelopmentCases|Sort-Object -Unique)}
function VariantCases([hashtable]$Mode){
    if($explicitCases){return @($cases)}
    $selected=@(0..4)+@($policyFaults.Keys|Sort-Object)
    if($Mode.Hash -eq 0 -and $Mode.Map -eq 0 -and $Mode.R9 -ceq 'ordinary'){
        $selected+=@($life.Keys|Sort-Object)+@($cpuProbes.Keys|Sort-Object)
    }
    if($Mode.Hash -eq 1 -and $Mode.Map -eq 1 -and $Mode.R9 -ceq 'ordinary'){$selected+=@($attacks.Keys|Sort-Object)}
    return @($selected|Sort-Object -Unique)
}
$inputs=@($PSCommandPath,$ArmGcc,$nm,$objdump,$objcopy,$readelf,$ar,$rsp,$inventory,
    (Join-Path $repo 'fiber/port/fiber_port_context_cohort_expectation.c'))+
    @(Get-ChildItem $fixture -Recurse -File|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $CmsisCore -File -Filter '*.h'|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem (Join-Path $FreeRtosRoot 'include'),$refns,$refs -File|Where-Object {$_.Extension -in @('.h','.c')}|Select-Object -ExpandProperty FullName)
if($true){
    if(!(Test-Path (Join-Path $ns 'fiber_port_pendsv.c'))){throw 'Actual selected PendSV source required; no substitute is supplied'}
    $inputs+=@((Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h'))+
        @(Get-ChildItem (Join-Path $repo 'fiber') -File|Where-Object {$_.Extension -in @('.h','.c')}|Select-Object -ExpandProperty FullName)+
        @(Get-ChildItem (Join-Path $repo 'fiber/port') -File -Filter '*.h'|Select-Object -ExpandProperty FullName)+
        @(Get-ChildItem $ns,$secure -File|Where-Object {$_.Extension -in @('.h','.c','.ld')}|Select-Object -ExpandProperty FullName)
    $inputs+=@(Get-ChildItem $foreign -File|Where-Object {$_.Extension -in @('.h','.c','.ld')}|Select-Object -ExpandProperty FullName)
}
$inputs=@($inputs|Sort-Object -Unique)
$before=@($inputs|ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256}|Select-Object Path,Hash)
$before|ConvertTo-Json -Depth 4|Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII
$own=@($before|Where-Object {$_.Path -eq $PSCommandPath -or $_.Path.StartsWith($fixture+[IO.Path]::DirectorySeparatorChar)}|ForEach-Object {
    [pscustomobject]@{Path=$_.Path.Substring($repo.Length+1).Replace('\','/');Hash=$_.Hash}
}|Sort-Object Path)
$own|ConvertTo-Json -Depth 4|Set-Content (Join-Path $out 'fixture-inputs.json') -Encoding ASCII
function ExecuteCases([hashtable]$Model,[hashtable]$Mode,[int[]]$Cases){
    $dir=$Model.Directory
    $manifest=$Model.Manifest
    foreach($number in $cases){
        $manifest=@{}
        foreach($key in $Model.Manifest.Keys){$manifest[$key]=$Model.Manifest[$key]}
        $scenario=$number
        if($life.ContainsKey($number)){
            $manifest.life_fault=$life[$number].Fault;$manifest.panic_code=$life[$number].Code;$manifest.panic_origin=$life[$number].Origin
            $scenario=0
        }
        if($policyFaults.ContainsKey($number)){
            $faultId=$policyFaults[$number]
            $manifest.policy_fault=$faultId
            $scenario=0
            if(($faultId -eq 30 -and $Mode.Hash) -or ($faultId -ne 30 -and $Mode.Map)){
                $manifest.panic_code=$policyCodes[$faultId];$manifest.panic_origin=14
            }
        }
        if($cpuProbes.ContainsKey($number)){
            $manifest.cpu_probe=$cpuProbes[$number];$manifest.panic_code=$cpuProbes[$number].code;$manifest.panic_origin=$cpuProbes[$number].origin
            $scenario=0
        }
        if($attacks.ContainsKey($number)){
            $parts=$attacks[$number].Split(':')
            $manifest.attack=@{when=$parts[0];action=$parts[1]}
            $manifest.panic_code=[int][char]$parts[2]
            if($parts[2] -ceq '!'){$manifest.pool_fault=$true}
            $manifest.plan_state=[int]$parts[3]
            $scenario=[int]$parts[4]
        }
        $caseDir=Join-Path $dir ('case-'+$number);$null=New-Item -ItemType Directory -Path $caseDir
        $word=Join-Path $caseDir 'case.bin';[IO.File]::WriteAllBytes($word,[BitConverter]::GetBytes([uint32]$scenario))
        $elf=Join-Path $caseDir 'nonsecure.elf'
        $null=Command $objcopy @('--update-section',".fixture_case=$word",$Model.Nonsecure.Elf,$elf) (Join-Path $caseDir 'case-patch.log')
        if($life.ContainsKey($number) -or $policyFaults.ContainsKey($number)){
            $faultId=if($life.ContainsKey($number)){$life[$number].Fault}else{$policyFaults[$number]}
            $fault=Join-Path $caseDir 'fault.bin';[IO.File]::WriteAllBytes($fault,[BitConverter]::GetBytes([uint32]$faultId))
            $null=Command $objcopy @('--update-section',".fixture_fault=$fault",$elf) (Join-Path $caseDir 'callback-fault-patch.log')
        }
        $manifest.scenario=$scenario
        $manifest.case=$number;$manifest.secure=LinuxPath $Model.Secure.Elf;$manifest.nonsecure=LinuxPath $elf
        $manifest.secure_sha256=(Get-FileHash $Model.Secure.Elf -Algorithm SHA256).Hash;$manifest.nonsecure_sha256=(Get-FileHash $elf -Algorithm SHA256).Hash
        $file=Join-Path $caseDir 'manifest.json';$manifest|ConvertTo-Json -Depth 8|Set-Content $file -Encoding ASCII
        $null=Command $wsl @('-d',$WslDistro,'--exec','python3','-B',"$wslFixture/run.py",$QemuRoot,"$TimeoutSeconds",(LinuxPath $file),$wslRsp) (Join-Path $caseDir 'run.log')
        $r=Get-Content (Join-Path $caseDir 'receipt.json') -Raw|ConvertFrom-Json
        Check "$($mode.Name) $($manifest.kind) case $number" ($r.result -eq 'PASS')
        $runs.Add([pscustomobject]@{Mode=$mode.Name;Kind=$manifest.kind;Case=$number;Receipt=(Join-Path $caseDir 'receipt.json')})
    }
}
function MakeArchive([string]$Name,[string[]]$Objects,[string]$Dir){
    $archive=Join-Path $Dir ($Name+'.a')
    $null=Command $ar (@('rcs',$archive)+$Objects) (Join-Path $Dir ($Name+'-archive.log'))
    return $archive
}
function NonsecureMembers([hashtable]$Model,[hashtable]$Overrides=@{}){
    $app=$Model.AppObjects;$common=$Model.CommonList;$port=$Model.NList;$import=$Model.Import
    foreach($key in @('App','Common','Port','Import')){
        if($Overrides.ContainsKey($key)){
            switch($key){'App'{$app=$Overrides[$key]};'Common'{$common=$Overrides[$key]};'Port'{$port=$Overrides[$key]};'Import'{$import=$Overrides[$key]}}
        }
    }
    $members=@($app)
    if(!$Overrides.ContainsKey('NoExpectation')){$members+=@($Model.Expectation)}
    return @($members+@('-Wl,--start-group')+@($common)+@($port)+@('-Wl,--end-group')+@($import))
}
$generic=@('fiber_port_context_init','fiber_port_runtime_memory_barrier','fiber_port_panic_wait',
    'fiber_port_require_scheduler_configuration_environment','fiber_port_runtime_prepare_start',
    'fiber_port_runtime_select_first','fiber_port_runtime_start_first','fiber_port_runtime_schedule')
$public=@('fiber_init','fiber_current','fiber_start','fiber_scheduler_set_pick_next','fiber_schedule')
$reverse=@('fiber_internal_runtime_select_scheduler_candidate','fiber_internal_runtime_publish_current_context',
    'fiber_internal_runtime_require_current_context')
function Definitions([string]$Object){
    $text=Command $nm @('-g','--defined-only',$Object) ($Object+'.defined.nm')
    return @([regex]::Matches($text,'(?m)^[0-9a-f]+\s+[A-Z]\s+(\S+)\r?$')|ForEach-Object {$_.Groups[1].Value})
}
function VerifyRoles([string[]]$PortObjects,[string[]]$CommonObjects,[string[]]$FixtureObjects){
    $owners=@{}
    foreach($object in $PortObjects){
        $names=@(Definitions $object)
        Check "$object no private common/reverse provider" (@($names|Where-Object {$_ -in ($public+$reverse) -or $_ -ceq 'fiber_internal_runtime_port_abi_v1_anchor' -or $_ -ceq 'fiber_internal_runtime_current_context_slot'}).Count -eq 0)
        Check "$object no ninth generic runtime operation" (@($names|Where-Object {$_ -like 'fiber_port_runtime_*' -and $_ -notin $generic}).Count -eq 0)
        foreach($name in $generic){if($name -cin $names){Check "unique actual selected owner $name" (!$owners.ContainsKey($name));$owners[$name]=(Split-Path $object -Leaf)}}
    }
    Check 'exactly eight actual selected operation providers' ($owners.Count -eq 8 -and $owners['fiber_port_context_init'] -ceq 'fiber_port_boot.c.o' -and @($generic|Where-Object {$_ -cne 'fiber_port_context_init' -and $owners[$_] -cne 'fiber_port.c.o'}).Count -eq 0)
    $commonOwners=@{}
    foreach($object in $CommonObjects){
        $names=@(Definitions $object)
        foreach($name in ($public+$reverse+@('fiber_internal_runtime_current_context_slot','fiber_internal_runtime_port_abi_v1_anchor'))){
            if($name -cin $names){Check "unique actual common owner $name" (!$commonOwners.ContainsKey($name));$commonOwners[$name]=(Split-Path $object -Leaf)}
        }
        Check "$object no generic provider in common" (@($names|Where-Object {$_ -in $generic}).Count -eq 0)
        $deps=Get-Content ([IO.Path]::ChangeExtension($object,'.d')) -Raw
        Check "$object common remains independent of selected/CMSIS headers" ($deps -notmatch '(fiber_port_(private|types|traits|selected|context_cohort)\.h|[/\\]ARM_CM[0-9]|core_cm[0-9]+\.h)')
    }
    foreach($name in $public){Check "real public common-core owner $name" ($commonOwners[$name] -ceq 'fiber_core.c.o')}
    foreach($name in ($reverse+@('fiber_internal_runtime_current_context_slot','fiber_internal_runtime_port_abi_v1_anchor'))){Check "real common-state owner $name" ($commonOwners[$name] -ceq 'fiber_runtime_state.c.o')}
    foreach($object in $FixtureObjects){
        $names=@(Definitions $object)
        Check "$object fixture owns no generic/public/reverse/cohort provider" (@($names|Where-Object {$_ -in ($generic+$public+$reverse) -or $_ -like 'fiber_port_*cohort*' -or $_ -like 'fiber_internal_runtime_*'}).Count -eq 0)
    }
}
function InspectRuntime([hashtable]$N,[hashtable]$Mode,[string]$Dir){
    foreach($name in @('SVC_Handler','PendSV_Handler')){
        Check "$($Mode.Name) unique strong final $name despite weak startup alias" ([regex]::Matches($N.Symbols,'(?m)^[0-9a-f]+\s+[0-9a-f]+\s+T\s+'+$name+'\r?$').Count -eq 1)
        Check "$($Mode.Name) $name is not fallback" ((Symbol $N.Symbols $name) -ne (Symbol $N.Symbols 'runtime_fault_handler'))
    }
    $vectors=Join-Path $Dir 'vectors.bin'
    $null=Command $objcopy @('--dump-section',".vectors=$vectors",$N.Elf) (Join-Path $Dir 'vectors-extract.log')
    $bytes=[IO.File]::ReadAllBytes($vectors)
    Check "$($Mode.Name) exact strong actual vector words" ($bytes.Length -eq 64 -and [BitConverter]::ToUInt32($bytes,0) -eq 0x20020000 -and
        [BitConverter]::ToUInt32($bytes,44) -eq ((Symbol $N.Symbols 'SVC_Handler') -bor 1) -and
        [BitConverter]::ToUInt32($bytes,56) -eq ((Symbol $N.Symbols 'PendSV_Handler') -bor 1))
    $attributes=Command $readelf @('-hASsW',$N.Elf) (Join-Path $Dir 'nonsecure.attributes.txt')
    $keys=@([regex]::Matches($attributes,'(?m)^\s*\d+:\s+([0-9a-f]+)\s+1\s+OBJECT\s+GLOBAL\s+\S+\s+(\d+)\s+(fiber_port_(?:context|storage)_cohort_\S+)\r?$'))
    Check "$($Mode.Name) exactly one one-byte context and one storage key" ($keys.Count -eq 2 -and @($keys|Where-Object {$_.Groups[3].Value -like 'fiber_port_context_cohort_*'}).Count -eq 1)
    foreach($key in $keys){
        $section=[regex]::Matches($attributes,'(?m)^\s*\[\s*'+$key.Groups[2].Value+'\]\s+\S+\s+PROGBITS\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+([A-Z]+)\s')
        $address=[Convert]::ToUInt32($key.Groups[1].Value,16)
        Check "$($Mode.Name) actual exact key allocated readonly in NS flash" ($section.Count -eq 1 -and $section[0].Groups[1].Value.Contains('A') -and !$section[0].Groups[1].Value.Contains('W') -and $address -ge 0x10000 -and $address -lt 0x20000)
    }
}
function NormalHostile([string]$Name,[string]$Source,[string[]]$Flags,[string]$Hostile,[string]$Dir){
    $normal=Compile ($Name+'-normal') $Source $Flags $Dir
    $sets=@()
    foreach($object in @($normal,$Hostile)){
        $text=Command $nm @('-u',$object) ($object+'-undefined.log')
        $sets+=,@($text -split "`n"|ForEach-Object {if($_ -match '^\s*U\s+(\S+)\s*$'){$Matches[1]}}|Sort-Object -Unique)
    }
    Check "$Name exact normal/hostile undefined set" (!(Compare-Object $sets[0] $sets[1]))
    $symbols=Command $nm @('-a',$Hostile) ($Hostile+'-symbols.nm')
    Check "$Name no uncollected instrumentation escape" ($symbols -notmatch '(?i)(__cyg_profile|__gcov|__ubsan|__asan|__sanitizer|__stack_chk|__morestack|__mcount|__chkstk)')
}
function ProbeModel {
    $dir=Join-Path $out 'model';$null=New-Item -ItemType Directory -Path $dir
    $flags=$base+@('-O2','-std=c11','-mcmse','-DRUNTIME_SECURE=1',"-I$fixture","-I$CmsisCore")
    $objects=@()
    foreach($name in @('model.c','startup.S','support.c')){$objects+=Compile $name (Join-Path $fixture $name) $flags $dir}
    $image=Link 'probe' ($flags+$link+@('-T',(Join-Path $fixture 'model.ld'))) $objects $dir
    $log=Command $wsl @('-d',$WslDistro,'--exec','bash',(LinuxPath $inventory),'run',$QemuRoot,(LinuxPath $dir),
        'mps3-an547',(LinuxPath $image.Elf),"$TimeoutSeconds") (Join-Path $dir 'qemu.log')
    $match=[regex]::Matches($log,'(?m)^MODEL:NS-IRQ0-MASK=0x([0-9a-f]{8})\r?$')
    Check 'actual isolated AN547 model probe terminated exactly once' ($match.Count -eq 1 -and ([regex]::Matches($log,'(?m)^PASS:C55S-RUNTIME:MODEL\r?$')).Count -eq 1 -and $log -notmatch '(FAIL|FAULT|Lockup)')
    $mask=[Convert]::ToUInt32($match[0].Groups[1].Value,16)
    $matches=@(1..8|Where-Object {([uint32]255 -shl (8-$_) -band 255) -eq $mask})
    Check 'actual implemented NS priority mask is an exact 1..8-bit architecture mask' ($matches.Count -eq 1)
    [pscustomobject]@{Machine='mps3-an547';PriorityMask=$mask;PriorityBits=$matches[0]}|ConvertTo-Json|Set-Content (Join-Path $out 'model.json') -Encoding ASCII
    return [int]$matches[0]
}
function FiberManifest([hashtable]$S,[hashtable]$N){
    $manifest=@{kind='fiber';stride=80;secure_ready=(Symbol $s.Symbols 'runtime_secure_ready');
        pendsv=(Symbol $n.Symbols 'PendSV_Handler');selector=(Symbol $n.Symbols 'runtime_pick');
        ns_checkpoint=(Symbol $n.Symbols 'runtime_ns_window_checkpoint');ns_resumed=(Symbol $n.Symbols 'runtime_ns_window_resumed');
        s_checkpoint=(Symbol $s.Symbols 'runtime_secure_window_checkpoint');s_resumed=(Symbol $s.Symbols 'runtime_secure_window_resumed');
        records=(Symbol $s.Symbols 'fiber_secure_context_pool_image');heap=((Symbol $s.Symbols 'fiber_secure_context_pool_image')+72);
        pool_state=(Symbol $s.Symbols 'fiber_secure_context_pool_state');gateway_state=(Symbol $s.Symbols 'fiber_secure_context_gateway_state');
        tcbs=(Symbol $n.Symbols 'runtime_contexts');selected=((Symbol $n.Symbols 'runtime_scheduler')+8);
        current_slot=(Symbol $n.Symbols 'fiber_internal_runtime_current_context_slot');live_handle=(Symbol $n.Symbols 'fiber_port_live_secure_context_handle');
        save=(Symbol $s.Symbols '__acle_se_fiber_secure_context_gateway_c55s_v1_save');
        load=(Symbol $s.Symbols '__acle_se_fiber_secure_context_gateway_c55s_v1_load')}
    $manifest.gateways=GatewayManifest $s $n $false
    $manifest.prepared=Symbol $n.Symbols 'runtime_constructed'
    $manifest.prestart=Symbol $n.Symbols 'runtime_prestart'
    $manifest.init_entry=Symbol $n.Symbols 'fiber_port_context_init'
    $manifest.attach_entry=Symbol $n.Symbols 'fiber_port_secure_context_attach'
    $manifest.public_checkpoint=Symbol $n.Symbols 'runtime_public_window_checkpoint'
    $manifest.public_resumed=Symbol $n.Symbols 'runtime_public_window_resumed'
    $manifest.public_trigger=PublicTrigger $n
    $manifest.public_api=Symbol $n.Symbols 'fiber_port_runtime_schedule'
    $manifest.phase=Symbol $n.Symbols 'runtime_phase'
    $manifest.hooks=Symbol $n.Symbols 'runtime_hooks'
    $manifest.policy=Symbol $n.Symbols 'runtime_policy'
    $manifest.scheduler=Symbol $n.Symbols 'runtime_scheduler'
    $manifest.callback_inside=Symbol $n.Symbols 'runtime_callback_inside'
    $manifest.steady=Symbol $n.Symbols 'runtime_steady_checkpoint'
    $manifest.success=Symbol $n.Symbols 'runtime_success_terminal'
    $manifest.warm_before=Symbol $n.Symbols 'runtime_warm_before'
    $manifest.warm_after=Symbol $n.Symbols 'runtime_warm_after'
    $manifest.task_entry=Symbol $n.Symbols 'runtime_task'
    $manifest.task_return=Symbol $n.Symbols 'fiber_internal_task_return'
    $manifest.stacks=Symbol $n.Symbols 'runtime_stacks'
    $manifest.panic=Symbol $n.Symbols 'fiber_panic'
    $manifest.plan=Symbol $n.Symbols 'fiber_port_pendsv_plan'
    $manifest.prepare_save=Symbol $n.Symbols 'fiber_port_pendsv_prepare_save'
    $manifest.ram_hook=Symbol $n.Symbols 'fiber_addr_plausible_ram'
    $manifest.code_hook=Symbol $n.Symbols 'fiber_addr_plausible_code'
    $manifest.control_injection=Symbol $n.Symbols 'runtime_control_injection'
    $manifest.control_done=Symbol $n.Symbols 'runtime_control_done'
    $manifest.control_return=Symbol $n.Symbols 'runtime_control_return'
    $manifest.control_value=Symbol $n.Symbols 'runtime_control_value'
    $manifest.control_register=Symbol $n.Symbols 'runtime_control_register'
    foreach($field in @('injection','done','return','value','register')){
        $manifest[('s_control_'+$field)]=Symbol $s.Symbols ('runtime_control_'+$field)
    }
    $manifest.pool_fail=Symbol $s.Symbols 'fiber_secure_context_pool_fail_closed'
    $manifest.fault_entry=Symbol $s.Symbols 'runtime_fault_handler'
    $manifest.fault_terminal=Symbol $s.Symbols 'runtime_fault_terminal'
    return $manifest
}
function BuildFiber([hashtable]$Mode,[string]$Parent){
    $pendsv=Join-Path $ns 'fiber_port_pendsv.c'
    if(!(Test-Path -LiteralPath $pendsv)){throw 'Actual staged PendSV source has not landed; no substitute provider is supplied'}
    $dir=Join-Path $Parent 'fiber';$null=New-Item -ItemType Directory -Path $dir
    $flags=$base+$Mode.Flags+@('-std=c11','-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV81M_MAINLINE=1',
        "-I$fixture","-I$repo","-I$CmsisCore")
    $nf=$flags+$Mode.R9Flags+@("-I$ns")
    $sf=$flags+@('-mcmse','-DRUNTIME_SECURE=1',"-I$secure",'-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3u',
        '-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=1024u')
    $hostile=@()
    if($Mode.ContainsKey('Hostile')){$hostile=@('-finstrument-functions','-fstack-protector-all','-fprofile-arcs',
        '-ftest-coverage','-fsanitize=undefined','-fsanitize-coverage=trace-pc','-fstack-check=generic')}
    $sfixture=@()
    foreach($name in @('secure.c','startup.S','windows.S','support.c','secure_roots.c','control_injection.S')){
        $sfixture+=Compile ('s-'+$name) (Join-Path $fixture $name) $sf $dir
    }
    $sobjects=@()
    foreach($name in @('fiber_secure_gateway.c','fiber_secure_context_gateway.c','fiber_secure_context_pool.c')){
        $source=Join-Path $secure $name
        $object=Compile $name $source ($sf+$hostile) $dir
        if($hostile.Count){NormalHostile $name $source $sf $object $dir}
        $sobjects+=$object
    }
    $sraw=@($sobjects)
    if($Mode.ContainsKey('Archive')){$sobjects=@(MakeArchive 'secure-provider' $sobjects $dir)}
    $import=Join-Path $dir 'secure-import.o'
    $slink=$sf+$link+@('-T',(Join-Path $fixture 'secure.ld'),'-T',(Join-Path $secure 'fiber_secure_context_cohort_contract.ld'),
        '-Wl,--section-start=.gnu.sgstubs=0x10008000',"-Wl,--cmse-implib,--out-implib=$import")
    $s=Link 'secure' $slink ($sfixture+$sobjects) $dir
    $importSymbols=Command $nm @('-g','--defined-only',$import) (Join-Path $dir 'secure-import.nm')
    $importNames=@($importSymbols -split "`n"|ForEach-Object {if($_ -match '^\S+\s+[a-zA-Z]\s+(\S+)\s*$'){$Matches[1]}}|Sort-Object -Unique)
    Check "$($Mode.Name) exactly twelve production gateways plus one fixture SG" (!(Compare-Object @($gateways+@('runtime_secure_work')|Sort-Object) $importNames))
    $nfixture=@()
    foreach($name in @('application.c','scheduler.c','startup.S','windows.S','support.c','control_injection.S')){
        $nfixture+=Compile ('n-'+$name) (Join-Path $fixture $name) $nf $dir
    }
    $applicationObjects=@($nfixture)
    $commonObjects=@()
    foreach($name in @('fiber_core.c','fiber_runtime_state.c','fiber_runtime_context_configuration.c','fiber_panic.c')){
        $cf=@($nf|Where-Object {$_ -notin @("-I$fixture","-I$ns","-I$CmsisCore")})
        $commonObjects+=Compile $name (Join-Path $repo ('fiber/'+$name)) $cf $dir
    }
    $expectation=Compile 'selected-build-expectation' (Join-Path $repo 'fiber/port/fiber_port_context_cohort_expectation.c') $nf $dir
    $nobjects=@()
    foreach($name in @('fiber_port.c','fiber_port_boot.c','fiber_port_runtime.c','fiber_port_secure_context.c','fiber_port_svc.c','fiber_port_pendsv.c')){
        $source=Join-Path $ns $name
        $object=Compile $name $source ($nf+$hostile) $dir
        if($hostile.Count){NormalHostile $name $source $nf $object $dir}
        $nobjects+=$object
    }
    $nraw=@($nobjects)
    VerifyRoles $nraw $commonObjects $applicationObjects
    if($Mode.ContainsKey('Archive')){$nobjects=@(MakeArchive 'ns-staged-components' $nobjects $dir)}
    $commonList=@($commonObjects)
    if($Mode.ContainsKey('Archive')){$commonList=@(MakeArchive 'actual-common' $commonObjects $dir)}
    $nlink=$nf+$link+@('-T',(Join-Path $fixture 'nonsecure.ld'),'-T',(Join-Path $ns 'fiber_port_first_start_contract.ld'))
    $model=@{Secure=$s;Directory=$dir;SFlags=$sf;NFlags=$nf;Hostile=$hostile;
        SRaw=$sraw;NRaw=$nraw;NList=$nobjects;SFixture=$sfixture;AppObjects=$applicationObjects;
        CommonRaw=$commonObjects;CommonList=$commonList;Expectation=$expectation;SLink=$slink;NLink=$nlink;Import=$import}
    $n=Link 'nonsecure' $nlink (NonsecureMembers $model) $dir
    InspectRuntime $n $Mode $dir
    $pd=[regex]::Match($n.Dis,'(?ms)^[0-9a-f]+ <PendSV_Handler>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)').Groups[1].Value
    Check "$($Mode.Name) generated successful final GPR restore has only barriers and BX LR" ($pd -match '(?s)ldmia\.w\s+r2!,\s*\{r4, r5, r6, r7, r8, r9, sl, fp\}\s*\r?\n\s*[0-9a-f]+:\s+[0-9a-f ]+\s+dsb\s+sy\s*\r?\n\s*[0-9a-f]+:\s+[0-9a-f ]+\s+isb\s+sy\s*\r?\n\s*[0-9a-f]+:\s+[0-9a-f ]+\s+bx\s+lr')
    $manifest=FiberManifest $s $n
    $manifest.hash=$Mode.Hash;$manifest.map=$Mode.Map;$manifest.r9_mode=$Mode.R9
    $manifest.priority_bits=$modelBits;$manifest.basepri=[Math]::Max(2,(1 -shl (8-$modelBits)));$manifest.priority_mask=(255 -shl (8-$modelBits) -band 255)
    $model.Nonsecure=$n;$model.Manifest=$manifest
    return $model
}
function RejectUndefined([string]$Name,[string[]]$Flags,[string[]]$Objects,[string[]]$Expected,[string]$Dir){
    $result=Command $ArmGcc ($Flags+$Objects+@('-o',(Join-Path $Dir ($Name+'.elf')))) (Join-Path $Dir ($Name+'-rejected.log')) -AllowFailure
    Check "$Name failed actual link" ($result.ExitCode -ne 0)
    $actual=@([regex]::Matches($result.Text,"undefined reference to ``([^']+)'")|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique)
    Check "$Name exact missing symbol set expected=$($Expected -join ',') observed=$($actual -join ',')" (!(Compare-Object @($Expected|Sort-Object) $actual))
}
function CohortNegatives([hashtable]$Model,[hashtable]$Mode){
    $dir=Join-Path $Model.Directory 'cohort';$null=New-Item -ItemType Directory -Path $dir
    $provider=@($Model.NRaw|Where-Object {(Split-Path $_ -Leaf) -ceq 'fiber_port.c.o'})
    Check 'one actual context/storage cohort provider object' ($provider.Count -eq 1)
    $names=@(Definitions $provider[0])
    $current=@($names|Where-Object {$_ -like 'fiber_port_context_cohort_*'})
    $storage=@($names|Where-Object {$_ -like 'fiber_port_storage_cohort_*'})
    Check 'one actual private key and one public storage key' ($current.Count -eq 1 -and $storage.Count -eq 1)
    $stale=@()
    foreach($object in $Model.NRaw){
        $name=(Split-Path $object -Leaf) -replace '\.o$',''
        $stale+=Compile ('basepri4-'+$name) (Join-Path $ns $name) ($Model.NFlags+$Model.Hostile+@('-DFIBER_SCHEDULER_BASEPRI=4u')) $dir
    }
    $otherNames=@(Definitions $stale[0])
    $other=@($otherNames|Where-Object {$_ -like 'fiber_port_context_cohort_*'})
    $otherStorage=@($otherNames|Where-Object {$_ -like 'fiber_port_storage_cohort_*'})
    Check 'actual supported BASEPRI alternative changes private key only' ($other.Count -eq 1 -and $other[0] -cne $current[0] -and !(Compare-Object $storage $otherStorage))
    $staleArchive=MakeArchive 'actual-basepri4-port' $stale $dir
    RejectUndefined 'stale-complete-archive' $Model.NLink (NonsecureMembers $Model @{Port=@($staleArchive)}) $current $dir
    $null=Link 'stale-no-build-expectation-CONTROL-NOT-EXECUTED' $Model.NLink (NonsecureMembers $Model @{Port=@($staleArchive);NoExpectation=$true}) $dir
    foreach($index in 0..($Model.NRaw.Count-1)){
        $objects=@($Model.NRaw)
        $objects[$index]=$stale[$index]
        $name='stale-single-'+((Split-Path $Model.NRaw[$index] -Leaf) -replace '\.c\.o$','')
        $archive=MakeArchive $name $objects $dir
        $expected=if($index -eq 0){$current}else{$other}
        RejectUndefined $name $Model.NLink (NonsecureMembers $Model @{Port=@($archive)}) $expected $dir
    }
    $text=Get-Content (Join-Path $ns 'fiber_port.c') -Raw
    $pattern=[regex]::Escape('FIBER_PORT_CONTEXT_COHORT_DEFINE();')
    Check 'unique real selected cohort definition' ([regex]::Matches($text,$pattern).Count -eq 1)
    $source=Join-Path $dir 'actual-provider-without-cohort.c'
    [IO.File]::WriteAllText($source,[regex]::Replace($text,$pattern,''))
    $absent=Compile 'absent-cohort' $source ($Model.NFlags+$Model.Hostile) $dir
    $without=@(Definitions $absent)
    Check 'cohort-only removal preserves all real provider operations' (!(Compare-Object @($names|Where-Object {$_ -notin ($current+$storage)}) $without))
    $objects=@($Model.NRaw);$objects[0]=$absent
    $archive=MakeArchive 'actual-port-no-cohort' $objects $dir
    RejectUndefined 'absent-cohort-provider-only' $Model.NLink (NonsecureMembers $Model @{Port=@($archive)}) ($current+$storage) $dir
}
function RemoveFunction([string]$Text,[string]$Name){
    $pattern='(?m)^[A-Za-z_][^;{}\r\n]*\b'+[regex]::Escape($Name)+'\s*\([^;{}]*\)\s*\{'
    $found=[regex]::Matches($Text,$pattern)
    Check "$Name unique actual function definition" ($found.Count -eq 1)
    $match=$found[0];$open=$match.Index+$match.Length-1;$depth=1;$end=$open+1
    while($end -lt $Text.Length -and $depth){
        if($Text[$end] -eq '{'){$depth++};if($Text[$end] -eq '}'){$depth--};$end++
    }
    Check "$Name complete actual function body" ($depth -eq 0)
    return $Text.Substring(0,$match.Index)+$Text.Substring($end)
}
function ReverseNegatives([hashtable]$Model,[hashtable]$Mode){
    $dir=Join-Path $Model.Directory 'reverse';$null=New-Item -ItemType Directory -Path $dir
    $original=@($Model.CommonRaw|Where-Object {(Split-Path $_ -Leaf) -ceq 'fiber_runtime_state.c.o'})
    $names=@(Definitions $original[0])
    foreach($missing in @('fiber_internal_runtime_port_abi_v1_anchor')+$reverse){
        $text=Get-Content (Join-Path $repo 'fiber/fiber_runtime_state.c') -Raw
        if($missing -ceq 'fiber_internal_runtime_port_abi_v1_anchor'){
            $pattern='const unsigned char fiber_internal_runtime_port_abi_v1_anchor\s*=\s*\(unsigned char\)FIBER_RUNTIME_PORT_ABI_VERSION;'
            Check 'unique actual reverse ABI anchor definition' ([regex]::Matches($text,$pattern).Count -eq 1)
            $text=[regex]::Replace($text,$pattern,'')
        }else{$text=RemoveFunction $text $missing}
        $source=Join-Path $dir ($missing+'.c');[IO.File]::WriteAllText($source,$text)
        $flags=@($Model.NFlags|Where-Object {$_ -notin @("-I$fixture","-I$ns","-I$CmsisCore")})+@("-I$repo/fiber")
        $object=Compile $missing $source $flags $dir
        $actual=@(Definitions $object)
        Check "$missing removal preserves every other real common definition" (!(Compare-Object @($names|Where-Object {$_ -cne $missing}) $actual))
        $objects=@($Model.CommonRaw|ForEach-Object {if($_ -ceq $original[0]){$object}else{$_}})
        $archive=MakeArchive ('missing-'+$missing) $objects $dir
        RejectUndefined ('missing-'+$missing) $Model.NLink (NonsecureMembers $Model @{Common=@($archive)}) @($missing) $dir
    }
    $expected=@('fiber_internal_runtime_port_abi_v1_anchor','fiber_internal_runtime_current_context_slot',
        'fiber_internal_runtime_load_current_context','fiber_internal_scheduler_store_pick_next',
        'fiber_internal_scheduler_is_configured','fiber_internal_runtime_close_context_configuration',
        'fiber_internal_runtime_context_configuration_is_open')+$reverse
    $objects=@($Model.CommonRaw|Where-Object {$_ -cne $original[0]})
    $archive=MakeArchive 'absent-real-common-state' $objects $dir
    RejectUndefined 'absent-real-common-state' $Model.NLink (NonsecureMembers $Model @{Common=@($archive)}) $expected $dir
}
function ComponentNegatives([hashtable]$Model,[hashtable]$Mode){
    $dir=Join-Path $Model.Directory 'components';$null=New-Item -ItemType Directory -Path $dir
    foreach($item in @(
        @{File='fiber_port_pendsv.c.o';Missing=@('fiber_port_arm_cm55_secure_context_pendsv_component_v1_anchor','fiber_port_running_cpu_capture','fiber_port_running_cpu_check')},
        @{File='fiber_port_svc.c.o';Missing=@('fiber_port_arm_cm55_secure_context_first_start_component_v1_anchor','fiber_port_start_first_context','fiber_port_restore_first_context_from_svc','fiber_port_c55s_first_start_svc_return')})){
        $objects=@($Model.NRaw|Where-Object {(Split-Path $_ -Leaf) -cne $item.File})
        Check "$($item.File) removes exactly one real handler component" ($objects.Count -eq 5)
        $archive=MakeArchive ('without-'+$item.File) $objects $dir
        $members=NonsecureMembers $Model @{Port=@($archive)}
        $flags=$Model.NLink
        if($item.File -ceq 'fiber_port_svc.c.o'){
            $result=Command $ArmGcc ($flags+$members+@('-o',(Join-Path $dir 'without-SVC-contract.elf'))) (Join-Path $dir 'without-SVC-contract-rejected.log') -AllowFailure
            Check 'missing SVC fails the actual owned-handler linker contract' ($result.ExitCode -ne 0 -and $result.Text.Contains('C55S first start requires its strong owned SVC component'))
            $expressions=@([regex]::Matches($result.Text,"undefined symbol ``([^']+)' referenced in expression")|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique)
            Check 'missing SVC exact undefined linker-expression symbol' ($expressions.Count -eq 1 -and $expressions[0] -ceq 'fiber_port_c55s_first_start_svc_return')
            $flags=@()
            for($i=0;$i -lt $Model.NLink.Count;$i++){
                if($Model.NLink[$i] -ceq '-T' -and $Model.NLink[$i+1] -ceq (Join-Path $ns 'fiber_port_first_start_contract.ld')){$i++;continue}
                $flags+=@($Model.NLink[$i])
            }
        }
        RejectUndefined ('without-'+$item.File) $flags $members $item.Missing $dir
    }
    foreach($item in @(
        @{File='fiber_runtime_context_configuration.c.o';Missing=@('fiber_internal_runtime_context_configuration_abi_v1_anchor','fiber_internal_runtime_require_context_configuration_open')},
        @{File='fiber_core.c.o';Missing=($public+@('fiber_internal_task_return'))})){
        $objects=@($Model.CommonRaw|Where-Object {(Split-Path $_ -Leaf) -cne $item.File})
        Check "$($item.File) removes exactly one real common module" ($objects.Count -eq 3)
        $archive=MakeArchive ('without-'+$item.File) $objects $dir
        RejectUndefined ('without-'+$item.File) $Model.NLink (NonsecureMembers $Model @{Common=@($archive)}) $item.Missing $dir
    }
}
function ProviderNegatives([hashtable]$Model,[hashtable]$Mode){
    $dir=Join-Path $Model.Directory 'providers';$null=New-Item -ItemType Directory -Path $dir
    $original=Command $nm @('-g','--defined-only',$Model.Import) (Join-Path $dir 'actual-import.nm')
    $address=Symbol $original 'runtime_secure_work'
    $work=Compile 'work-only-import' (Join-Path $fixture 'work_only_import.S') ($Model.NFlags+@("-DRUNTIME_SG_ADDRESS=$address")) $dir
    $symbols=Command $nm @('-g','--defined-only',$work) (Join-Path $dir 'work-only-import.nm')
    $public=@($symbols -split "`n"|Where-Object {$_ -match '^\S+\s+[a-zA-Z]\s+\S+\s*$'})
    Check "$($Mode.Name) fixture work-only import has exactly one actual same-address global" ($public.Count -eq 1 -and (Symbol $symbols 'runtime_secure_work') -eq $address)
    RejectUndefined 'missing-Secure-provider' $Model.NLink (NonsecureMembers $Model @{Import=@($work)}) $gateways $dir
    $flags=@('-mcpu=cortex-m33')+@($base|Where-Object {$_ -notlike '-mcpu=*'})+$Mode.Flags+@('-std=c11','-mcmse',
        '-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV8M_MAINLINE=1',
        '-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3u','-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=128u',
        "-I$fixture/foreign_cm33","-I$foreign","-I$repo","-I$CmsisCore")
    $objects=@()
    foreach($name in @('fiber_secure_gateway.c','fiber_secure_context_gateway.c','fiber_secure_context_pool.c')){
        $objects+=Compile ('cm33-'+$name) (Join-Path $foreign $name) $flags $dir
    }
    $actualNames=@($gateways|ForEach-Object {$_.Replace('_c55s_v1_','_v1_')})
    $import=Join-Path $dir 'cm33-import.o'
    $roots=@($actualNames|ForEach-Object {"-Wl,-u,$_"})
    $image=Link 'actual-cm33-provider' ($flags+$link+$roots+@('-Wl,--entry=0','-T',(Join-Path $fixture 'foreign_cm33/import.ld'),
        '-T',(Join-Path $foreign 'fiber_secure_context_cohort_contract.ld'),'-Wl,--section-start=.gnu.sgstubs=0x10008000',
        "-Wl,--cmse-implib,--out-implib=$import")) $objects $dir
    $symbols=Command $nm @('-g','--defined-only',$import) (Join-Path $dir 'cm33-import.nm')
    Check "$($Mode.Name) actual foreign provider is C33S not C55S" ($symbols -notmatch '_c55s_' -and $image.Symbols -match 'fiber_secure_context_cohort_c33s_g1_')
    RejectUndefined 'foreign-C33S-provider' $Model.NLink (NonsecureMembers $Model @{Import=@($work,$import)}) $gateways $dir
}
function CompiledControls([hashtable]$Model,[hashtable]$Mode){
    $allocate=[regex]::Escape('fiber_secure_context_gateway_c55s_v1_allocate(requested, (uintptr_t)next)')
    $controls=@(
        @{Name='omit-NS-GPR-restore';File='fiber_port_pendsv.c';Pattern=[regex]::Escape('ldmia r2!, {r4-r11}');
            Replacement='add r2, r2, #32';Scene=0;Error='initial-all-GPRs-including-inherited-r9'},
        @{Name='wrong-next-allocation-size';File='fiber_port_secure_context.c';Pattern=$allocate;
            Replacement='fiber_secure_context_gateway_c55s_v1_allocate(requested + 8u, (uintptr_t)next)';Scene=1;Error='independent-allocation-arguments'},
        @{Name='wrong-next-allocation-owner';File='fiber_port_secure_context.c';Pattern=$allocate;
            Replacement='fiber_secure_context_gateway_c55s_v1_allocate(requested, (uintptr_t)next + 4u)';Scene=1;Error='independent-allocation-arguments'},
        @{Name='omit-Secure-save';File='fiber_port_secure_context.c';Pattern='fiber_secure_context_gateway_c55s_v1_save\(\s*handle,\s*\(uintptr_t\)current\)';
            Replacement='1u';Scene=1;Error='missing-actual-Secure-save-before-NS-save'},
        @{Name='decode-NS-hardware-frame-for-Secure-origin';File='fiber_port_boot.c';Scope=$true;
            Pattern=[regex]::Escape('if ((exc_return & 0x40u) != 0u) {');
            Replacement='if ((exc_return & 0x40u) != 0u) { fiber_port_running_hardware_frame_check(psp, ctx->boot.stack_top, &cpu);';
            Scene=1;Error='unexpected-panic';Panic='raw-NS-frame';State=0},
        @{Name='store-NS-GPRs-for-Secure-origin';File='fiber_port_pendsv.c';Pattern=[regex]::Escape('"bne 1f\n"');
            Replacement='"nop\n"';Scene=1;Error='unexpected-panic';Panic=83;State=2},
        @{Name='force-hot-map-despite-opt-out';File='fiber_port_boot.c';Begin='void fiber_port_running_context_check(';End='void fiber_port_running_exc_return_check(';
            Pattern='(?m)^#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH\r?$';Replacement='#if 1';Count=3;
            Scene=0;PolicyFault=31;Error='unexpected-policy-panic';ObservedPanic=67},
        @{Name='force-hot-hash-despite-opt-out';File='fiber_port_boot.c';Begin='void fiber_port_running_context_check(';End='void fiber_port_running_exc_return_check(';
            Pattern='(?m)^#if FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH\r?$';Replacement='#if 1';Count=1;
            Scene=0;PolicyFault=30;Error='unexpected-policy-panic';ObservedPanic=104})
    foreach($control in $controls){
        $dir=Join-Path $Model.Directory $control.Name;$null=New-Item -ItemType Directory -Path $dir
        $text=Get-Content -LiteralPath (Join-Path $ns $control.File) -Raw
        $begin=0;$end=$text.Length
        if($control.ContainsKey('Scope')){
            $begin=$text.IndexOf('void fiber_port_context_live_frame_check(')
            $end=$text.IndexOf('uint32_t fiber_port_context_saved_frame_check(',$begin)
            Check "$($control.Name) exact actual helper scope" ($begin -ge 0 -and $end -gt $begin)
        }
        if($control.ContainsKey('Begin')){$begin=$text.IndexOf($control.Begin);$end=$text.IndexOf($control.End,$begin);Check "$($control.Name) exact running helper scope" ($begin -ge 0 -and $end -gt $begin)}
        $part=$text.Substring($begin,$end-$begin)
        $count=if($control.ContainsKey('Count')){$control.Count}else{1}
        Check "$($Mode.Name) $($control.Name) exact actual source mutation count" ([regex]::Matches($part,$control.Pattern).Count -eq $count)
        $source=Join-Path $dir 'actual-NS-mutant.c'
        [IO.File]::WriteAllText($source,$text.Substring(0,$begin)+[regex]::Replace($part,$control.Pattern,$control.Replacement)+$text.Substring($end))
        $object=Compile 'mutant' $source ($Model.NFlags+$Model.Hostile) $dir
        $objects=@($Model.NRaw|ForEach-Object {if((Split-Path $_ -Leaf) -ceq ($control.File+'.o')){$object}else{$_}})
        Check "$($control.Name) actual object replaced" ($object -cin $objects)
        if($Mode.ContainsKey('Archive')){$objects=@(MakeArchive 'mutated-staged-components' $objects $dir)}
        $n=Link 'nonsecure' $Model.NLink (NonsecureMembers $Model @{Port=$objects}) $dir
        $manifest=FiberManifest $Model.Secure $n
        foreach($key in @('hash','map','r9_mode','priority_bits','basepri','priority_mask')){$manifest[$key]=$Model.Manifest[$key]}
        $manifest.case=$control.Scene;$manifest.scenario=$control.Scene
        $word=Join-Path $dir 'case.bin';[IO.File]::WriteAllBytes($word,[BitConverter]::GetBytes([uint32]$control.Scene))
        $elf=Join-Path $dir 'case.elf'
        $null=Command $objcopy @('--update-section',".fixture_case=$word",$n.Elf,$elf) (Join-Path $dir 'case-patch.log')
        if($control.ContainsKey('PolicyFault')){
            $manifest.policy_fault=$control.PolicyFault
            $word=Join-Path $dir 'fault.bin';[IO.File]::WriteAllBytes($word,[BitConverter]::GetBytes([uint32]$control.PolicyFault))
            $null=Command $objcopy @('--update-section',".fixture_fault=$word",$elf) (Join-Path $dir 'fault-patch.log')
        }
        $manifest.secure=LinuxPath $Model.Secure.Elf;$manifest.nonsecure=LinuxPath $elf
        $manifest.secure_sha256=(Get-FileHash $Model.Secure.Elf -Algorithm SHA256).Hash
        $manifest.nonsecure_sha256=(Get-FileHash $elf -Algorithm SHA256).Hash
        $file=Join-Path $dir 'manifest.json';$manifest|ConvertTo-Json -Depth 8|Set-Content $file -Encoding ASCII
        $result=Command $wsl @('-d',$WslDistro,'--exec','python3','-B',"$wslFixture/run.py",$QemuRoot,"$TimeoutSeconds",(LinuxPath $file),$wslRsp) (Join-Path $dir 'run.log') -AllowFailure
        $receipt=Get-Content (Join-Path $dir 'receipt.json') -Raw|ConvertFrom-Json
        Check "$($Mode.Name) $($control.Name) compiled mutation rejected at exact oracle" ($result.ExitCode -ne 0 -and $receipt.result -eq 'FAIL' -and $receipt.error -ceq $control.Error)
        if($control.ContainsKey('Panic')){
            $observed=@($receipt.trace|Where-Object event -eq panic-observed)
            $origin=@($receipt.trace|Where-Object {($_.event -eq 'pendsv') -and ($_.cpu.lr -eq [uint32]::Parse('FFFFFFFC',[Globalization.NumberStyles]::HexNumber))})
            $expected=$control.Panic
            if($expected -ceq 'raw-NS-frame'){
                Check 'one actual Secure-origin raw NS-stack observation' ($origin.Count -eq 1)
                $hex=$origin[0].ns.bytes;$raw=New-Object byte[] ($hex.Length/2)
                for($i=0;$i -lt $raw.Length;$i++){$raw[$i]=[Convert]::ToByte($hex.Substring(2*$i,2),16)}
                $pc=[BitConverter]::ToUInt32($raw,40);$xpsr=[BitConverter]::ToUInt32($raw,44)
                $expected=if(($xpsr -band 0x01000000) -eq 0 -or ($xpsr -band 511) -ne 0){88}elseif($pc -lt 2 -or ($pc -band 1) -ne 0){120}else{0}
                Check 'real inactive NS stack is independently not a valid basic frame' ($expected -ne 0)
            }
            Check "$($control.Name) exact real Secure-origin terminal diagnostic" ($observed.Count -eq 1 -and $observed[0].code -eq $expected -and ($observed[0].cpu.xpsr -band 511) -eq 14 -and $origin.Count -eq 1)
            Check "$($control.Name) exact sticky plan phase" ($observed[0].plan_words[7] -eq $control.State)
        }
        if($control.ContainsKey('ObservedPanic')){
            $observed=@($receipt.trace|Where-Object event -eq panic-observed)
            Check "$($control.Name) fails due to actual forbidden hot-path operation" ($observed.Count -eq 1 -and $observed[0].code -eq $control.ObservedPanic -and ($observed[0].cpu.xpsr -band 511) -eq 14 -and $observed[0].plan_words[7] -eq 0)
        }
        $runs.Add([pscustomobject]@{Mode=$Mode.Name;Kind='compiled-control';Case=$control.Scene;Label=$control.Name;Result='EXPECTED-REJECTION';Receipt=(Join-Path $dir 'receipt.json')})
    }
    if($Mode.ContainsKey('Hostile')){
        $text=Get-Content (Join-Path $ns 'fiber_port_pendsv.c') -Raw
        $pattern='static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY\r?\nvoid fiber_port_pendsv_cpu_capture'
        Check "$($Mode.Name) unique actual PendSV capture annotation" ([regex]::Matches($text,$pattern).Count -eq 1)
        $source=Join-Path $Model.Directory 'annotation-removal.c'
        [IO.File]::WriteAllText($source,[regex]::Replace($text,$pattern,"static FIBER_GENERAL_REGS_ONLY`nvoid fiber_port_pendsv_cpu_capture"))
        $object=Compile 'annotation-removal' $source ($Model.NFlags+$Model.Hostile) $Model.Directory
        $undefined=Command $nm @('-u',$object) (Join-Path $Model.Directory 'annotation-removal-undefined.log')
        $symbols=Command $nm @('-a',$object) (Join-Path $Model.Directory 'annotation-removal.nm')
        Check "$($Mode.Name) compiled annotation removal exposes instrumentation and counters" ($undefined -match '__cyg_profile_func_enter' -and $symbols -match '__gcov')
    }
}
function FaultControls([hashtable]$Model,[hashtable]$Mode){
    foreach($control in @(
        @{Name='wrong-Handler-stack-selection';File='startup.S';Pattern=[regex]::Escape('tst lr,#8');Replacement='tst lr,#4'},
        @{Name='counterfeit-Thread-fault-record';File='support.c';Pattern=[regex]::Escape('runtime_fault_terminal(frame,ret);');Replacement='runtime_fault_terminal(frame,ret | 8u);'})){
        $dir=Join-Path $Model.Directory $control.Name;$null=New-Item -ItemType Directory -Path $dir
        $text=Get-Content (Join-Path $fixture $control.File) -Raw
        Check "$($Mode.Name) $($control.Name) unique fixture mutation" ([regex]::Matches($text,$control.Pattern).Count -eq 1)
        $source=Join-Path $dir ('compiled-fault-control'+[IO.Path]::GetExtension($control.File))
        [IO.File]::WriteAllText($source,[regex]::Replace($text,$control.Pattern,$control.Replacement))
        $object=Compile 'fault-control' $source $Model.SFlags $dir
        $fixtures=@($Model.SFixture|ForEach-Object {if((Split-Path $_ -Leaf) -ceq ('s-'+$control.File+'.o')){$object}else{$_}})
        Check "$($control.Name) actual fixture object replaced" ($object -cin $fixtures)
        $objects=$Model.SRaw
        if($Mode.ContainsKey('Archive')){$objects=@(MakeArchive 'secure-provider' $objects $dir)}
        $import=Join-Path $dir 'secure-import.o'
        $flags=@($Model.SLink|Where-Object {$_ -notlike '-Wl,--cmse-implib,*'})+@("-Wl,--cmse-implib,--out-implib=$import")
        $s=Link 'secure' $flags ($fixtures+$objects) $dir
        $n=Link 'nonsecure' $Model.NLink (NonsecureMembers $Model @{Import=@($import)}) $dir
        $manifest=FiberManifest $s $n
        foreach($key in @('hash','map','r9_mode','priority_bits','basepri','priority_mask')){$manifest[$key]=$Model.Manifest[$key]}
        $manifest.case=220;$manifest.scenario=1;$manifest.pool_fault=$true;$manifest.panic_code=33;$manifest.plan_state=1
        $manifest.attack=@{when='save';action='seal-first'}
        $word=Join-Path $dir 'case.bin';[IO.File]::WriteAllBytes($word,[BitConverter]::GetBytes([uint32]1))
        $elf=Join-Path $dir 'case.elf'
        $null=Command $objcopy @('--update-section',".fixture_case=$word",$n.Elf,$elf) (Join-Path $dir 'case-patch.log')
        $manifest.secure=LinuxPath $s.Elf;$manifest.nonsecure=LinuxPath $elf
        $manifest.secure_sha256=(Get-FileHash $s.Elf -Algorithm SHA256).Hash;$manifest.nonsecure_sha256=(Get-FileHash $elf -Algorithm SHA256).Hash
        $file=Join-Path $dir 'manifest.json';$manifest|ConvertTo-Json -Depth 8|Set-Content $file -Encoding ASCII
        $result=Command $wsl @('-d',$WslDistro,'--exec','python3','-B',"$wslFixture/run.py",$QemuRoot,"$TimeoutSeconds",(LinuxPath $file),$wslRsp) (Join-Path $dir 'run.log') -AllowFailure
        $receipt=Get-Content (Join-Path $dir 'receipt.json') -Raw|ConvertFrom-Json
        Check "$($Mode.Name) $($control.Name) compiled fault record rejected" ($result.ExitCode -ne 0 -and $receipt.result -ceq 'FAIL' -and $receipt.error -ceq 'exact-terminal-Secure-Handler-fault-record')
        $observed=@($receipt.trace|Where-Object event -eq fault-entry-observed)
        Check "$($control.Name) actual real UsageFault precedes rejected report" ($observed.Count -eq 1 -and ($observed[0].cpu.xpsr -band 511) -eq 6 -and $observed[0].cpu.lr -eq [uint32]::Parse('FFFFFFF5',[Globalization.NumberStyles]::HexNumber))
        $runs.Add([pscustomobject]@{Mode=$Mode.Name;Kind='compiled-control';Case=220;Label=$control.Name;Result='EXPECTED-REJECTION';Receipt=(Join-Path $dir 'receipt.json')})
    }
}
function WeakPanicProof([hashtable]$Model,[hashtable]$Mode){
    $dir=Join-Path $Model.Directory 'actual-weak-panic';$null=New-Item -ItemType Directory -Path $dir
    $object=Compile 'application-weak-panic' (Join-Path $fixture 'application.c') ($Model.NFlags+@('-DRUNTIME_USE_WEAK_PANIC=1')) $dir
    $app=@($Model.AppObjects|ForEach-Object {if((Split-Path $_ -Leaf) -ceq 'n-application.c.o'){$object}else{$_}})
    Check 'real weak-panic fixture application replaced' ($object -cin $app)
    $n=Link 'nonsecure' $Model.NLink (NonsecureMembers $Model @{App=$app}) $dir
    foreach($name in $generic){Check "$($Mode.Name) all eight actual operations live with real common weak fallback: $name" ([regex]::Matches($n.Symbols,'(?m)^[0-9a-f]+\s+[0-9a-f]+\s+T\s+'+$name+'\r?$').Count -eq 1)}
    $fallback=[regex]::Matches($n.Symbols,'(?m)^([0-9a-f]+)\s+00000001\s+[bB]\s+fiber_internal_fallback_panic_code(?:\.lto_priv\.\d+)?\r?$')
    Check 'one actual common-owned one-byte fallback code' ($fallback.Count -eq 1)
    $body=[regex]::Matches($n.Dis,'(?ms)^[0-9a-f]+ <fiber_port_panic_wait>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
    Check 'actual panic-wait has DSB ISB WFE and backwards wait loop' ($body.Count -eq 1 -and $body[0].Groups[1].Value -match '(?s)dsb\s+sy.*isb\s+sy.*wfe.*b(?:\.n|\.w)?\s+[0-9a-f]+ <fiber_port_panic_wait\+')
    $manifest=FiberManifest $Model.Secure $n
    foreach($key in @('hash','map','r9_mode','priority_bits','basepri','priority_mask')){$manifest[$key]=$Model.Manifest[$key]}
    $manifest.case=100;$manifest.scenario=0;$manifest.life_fault=20;$manifest.panic_code=75;$manifest.panic_origin=0
    $manifest.weak_panic=@{wait=(Symbol $n.Symbols 'fiber_port_panic_wait');code=[Convert]::ToUInt32($fallback[0].Groups[1].Value,16)}
    $word=Join-Path $dir 'fault.bin';[IO.File]::WriteAllBytes($word,[BitConverter]::GetBytes([uint32]20))
    $elf=Join-Path $dir 'case.elf'
    $null=Command $objcopy @('--update-section',".fixture_fault=$word",$n.Elf,$elf) (Join-Path $dir 'case-patch.log')
    $manifest.secure=LinuxPath $Model.Secure.Elf;$manifest.nonsecure=LinuxPath $elf
    $manifest.secure_sha256=(Get-FileHash $Model.Secure.Elf -Algorithm SHA256).Hash;$manifest.nonsecure_sha256=(Get-FileHash $elf -Algorithm SHA256).Hash
    $file=Join-Path $dir 'manifest.json';$manifest|ConvertTo-Json -Depth 8|Set-Content $file -Encoding ASCII
    $null=Command $wsl @('-d',$WslDistro,'--exec','python3','-B',"$wslFixture/run.py",$QemuRoot,"$TimeoutSeconds",(LinuxPath $file),$wslRsp) (Join-Path $dir 'run.log')
    $receipt=Get-Content (Join-Path $dir 'receipt.json') -Raw|ConvertFrom-Json
    Check "$($Mode.Name) actual common weak panic reaches actual terminal wait" ($receipt.result -ceq 'PASS' -and $receipt.stop -ceq 'actual-common-fallback-and-port-wait')
    $runs.Add([pscustomobject]@{Mode=$Mode.Name;Kind='weak-panic';Case=100;Receipt=(Join-Path $dir 'receipt.json')})
}
try{
    Check 'clean exact FreeRTOS pin' ((Command git @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.log')).Trim() -eq 'a50edad08b29052631aa469d4df6e6ec7ff68878')
    $null=Command git @('-C',$FreeRtosRoot,'diff','--exit-code','HEAD','--') (Join-Path $out 'reference-clean.log')
    $null=Command $ArmGcc @('--version') (Join-Path $out 'compiler-version.log')
    $wslFixture=LinuxPath $fixture;$wslRsp=LinuxPath $rsp
    $null=Command $wsl @('-d',$WslDistro,'--exec','bash',(LinuxPath $inventory),'inspect',$QemuRoot,(LinuxPath $out)) (Join-Path $out 'qemu-inspect.log')
    $modelBits=ProbeModel
    $planned=New-Object System.Collections.Generic.List[object]
    if(!$DevelopmentModelOnly){foreach($mode in $modes){
        foreach($policy in $policies){foreach($r9 in $r9Modes){
            $variant=@{Name=($mode.Name+'-h'+$policy.Hash+'m'+$policy.Map+'-'+$r9.Name);Hash=$policy.Hash;Map=$policy.Map;R9=$r9.Name;R9Flags=$r9.Flags;
                Flags=($mode.Flags+@("-DRUNTIME_NVIC_PRIO_BITS=$modelBits","-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=$($policy.Hash)","-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=$($policy.Map)"))}
            foreach($key in @('Archive','Hostile')){if($mode.ContainsKey($key)){$variant[$key]=$true}}
            $selected=@(VariantCases $variant)
            foreach($case in $selected){$planned.Add([pscustomobject]@{Mode=$variant.Name;Kind='fiber';Case=$case;Label=''})}
            if($policy.Name -eq '00'){$planned.Add([pscustomobject]@{Mode=$variant.Name;Kind='weak-panic';Case=100;Label=''})}
            if($policy.Name -eq '00' -and $r9.Name -eq 'ordinary'){
                foreach($row in @(
                    @('omit-NS-GPR-restore',0),@('wrong-next-allocation-size',1),@('wrong-next-allocation-owner',1),@('omit-Secure-save',1),
                    @('decode-NS-hardware-frame-for-Secure-origin',1),@('store-NS-GPRs-for-Secure-origin',1),
                    @('force-hot-map-despite-opt-out',0),@('force-hot-hash-despite-opt-out',0),
                    @('wrong-Handler-stack-selection',220),@('counterfeit-Thread-fault-record',220))){
                    $planned.Add([pscustomobject]@{Mode=$variant.Name;Kind='compiled-control';Case=$row[1];Label=$row[0]})
                }
            }
            $planned.ToArray()|ConvertTo-Json -Depth 5|Set-Content (Join-Path $out 'execution-plan.json') -Encoding ASCII
            $dir=Join-Path $out $variant.Name;$null=New-Item -ItemType Directory -Path $dir
            $model=BuildFiber $variant $dir
            ExecuteCases $model $variant $selected
            if($policy.Name -eq '00'){WeakPanicProof $model $variant}
            if($policy.Name -eq '00' -and $r9.Name -eq 'ordinary'){
                CohortNegatives $model $variant
                ProviderNegatives $model $variant
                ReverseNegatives $model $variant
                ComponentNegatives $model $variant
                CompiledControls $model $variant
                FaultControls $model $variant
            }
            Write-Host "Completed $($variant.Name): $($selected.Count) runtime cases"
        }}
    }}
    $actual=@($runs.ToArray()|ForEach-Object {[pscustomobject]@{Mode=$_.Mode;Kind=$_.Kind;Case=$_.Case;Label=$(if($_.PSObject.Properties['Label']){$_.Label}else{''})}})
    $expected=@($planned.ToArray())
    Check 'exact finite execution inventory (no omitted or duplicate runtime/mutant proof)' ($actual.Count -eq $expected.Count -and ($actual.Count -eq 0 -or !(Compare-Object $expected $actual -Property Mode,Kind,Case,Label)))
    $verdict='PASS'
}finally{
    $after=@($inputs|ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256}|Select-Object Path,Hash)
    $after|ConvertTo-Json -Depth 4|Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $drift=@(Compare-Object $before $after -Property Path,Hash);if($drift.Count){$verdict='FAIL'}
    [pscustomobject]@{Verdict=$verdict;CompleteSuite=($complete -and $verdict -ceq 'PASS');Launches=$runs.Count;ModelLaunches=1;TotalLaunches=($runs.Count+1);Checks=$checks.Count;InputCount=$before.Count;InputDrift=$drift.Count;
        Runs=@($runs.ToArray());Assertions=@($checks.ToArray());Limit='AN547 two-image actual common plus selected C55S runtime; explicit policies, 8 KiB NS task stacks; hostile flags on selected NS/S units, neutral common/application. Not physical-no-FP, board, minimum-stack or public RuntimeSelectable promotion evidence.'}|
        ConvertTo-Json -Depth 8|Set-Content (Join-Path $out 'results.json') -Encoding ASCII
    Get-ChildItem $out -Recurse -File|Where-Object Name -ne sha256.csv|ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256}|
        Select-Object Path,Hash|Export-Csv (Join-Path $out 'sha256.csv') -NoTypeInformation -Encoding ASCII
    if($drift.Count){throw "Input drift: $out"}
}
if($verdict -ne 'PASS'){throw "Running proof failed: $out"}
Write-Host "PASS C55S runtime (complete=$complete): $($runs.Count) launches; $out"
