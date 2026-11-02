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
    [switch]$DevelopmentReferenceOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $repo 'tools/runtime_sources.ps1')
$runtimeRoles=@('state','optional_configuration')
$runtimeSources=@(Get-RuntimeSourcePaths -RepositoryRoot $repo -Roles $runtimeRoles)
$fixture=Join-Path $PSScriptRoot 'fixtures\m55_secure_running'
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
$ar=Join-Path $bin 'arm-none-eabi-gcc-ar.exe'
$wsl=(Get-Command wsl.exe -ErrorAction Stop).Source
$rsp=Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards\aircr_rsp.py'
$inventory=Join-Path $PSScriptRoot 'fixtures\arm_control\qemu.sh'
foreach($file in @($nm,$objdump,$objcopy,$ar,$rsp,$inventory)){if(!(Test-Path -LiteralPath $file)){throw "Missing $file"}}
if(!$BuildRoot){$BuildRoot=[IO.Path]::GetTempPath()}
$out=Join-Path $BuildRoot ('fiber-m55-secure-running-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out -Force
$out=(Resolve-Path -LiteralPath $out).Path
Write-Host "C55S running evidence: $out"
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
$referenceModes=@('o2','os','o2-lto','os-lto')
$complete=!$DevelopmentReferenceOnly -and !$PSBoundParameters.ContainsKey('DevelopmentModes') -and !$PSBoundParameters.ContainsKey('DevelopmentCases')
if($DevelopmentReferenceOnly){$modes=@($modes|Where-Object {$_.Name -in $referenceModes})}
if($DevelopmentModes){foreach($name in $DevelopmentModes){if($name -notin $modes.Name){throw "Unknown mode $name"}};$modes=@($modes|Where-Object {$_.Name -in $DevelopmentModes})}
$attacks=@{
    100='entry:exc-dcrs:x:0:0';101='entry:exc-es:x:0:0';102='entry:exc-mode:x:0:0';103='entry:exc-fp:x:0:0';104='entry:exc-stack:x:0:0';105='entry:exc-fake-secure:D:0:0';
    110='entry:control:l:0:0';111='entry:primask:l:0:0';112='entry:basepri:l:0:0';113='entry:faultmask:l:0:0';114='entry:psplim:L:0:0';
    120='entry:current-zero:D:0:0';121='entry:current-unaligned:C:0:0';122='entry:current-foreign:C:0:0';123='entry:current-msp:C:0:0';124='entry:current-overflow:O:0:0';
    130='entry:psp-unaligned:x:0:0';131='entry:psp-zero:P:0:0';132='entry:psp-underflow:P:0:0';133='entry:psp-overflow:P:0:0';134='prepare:psp-argument:P:0:0';
    140='entry:hw-t:X:0:0';141='entry:hw-ipsr:X:0:0';142='entry:hw-pc-odd:x:0:0';143='entry:hw-pc-zero:x:0:0';144='entry:hw-pc-foreign:c:0:0';
    150='entry:current-hash:h:0:0';151='entry:current-canary:c:0:0';
    160='selector:next-null:N:2:0';161='selector:next-sp-unaligned:A:2:0';162='selector:next-sp-foreign:P:2:0';163='selector:next-sp-short:X:2:0';
    164='selector:next-hash:h:2:0';165='selector:next-canary:c:2:0';166='selector:next-psplim:L:2:0';167='selector:next-exc:x:2:0';
    168='selector:next-hw-t:X:2:0';169='selector:next-hw-pc:x:2:0';170='selector:next-cold-r0:0:2:1';171='selector:next-cold-pc:x:2:1';172='selector:next-cold-r4:4:2:1';
    180='selector:primask:p:2:0';181='selector:control:l:2:0';182='selector:basepri:b:2:0';183='selector:faultmask:f:2:0';184='selector:psplim:L:2:0';185='selector:psp:P:2:0';
    190='ram:primask:p:0:0';191='ram:control:l:0:0';192='ram:basepri:b:0:0';193='code:psplim:L:0:0';
    210='save:secure-control:Q:1:1';211='save:secure-psplim:Q:1:1';212='save:secure-psp:Q:1:1';
    213='save:gateway-owner:Q:1:1';214='load:gateway-handle:Q:4:1';215='load:gateway-owner:Q:4:1';216='save:record-owner:Q:1:1';
    220='save:seal-first:!:1:1';221='save:seal-second:!:1:1';222='save:record-pointer:!:1:1';223='save:record-limit:!:1:1';
    230='save-exit:return-zero:Q:1:1';231='allocate-exit:return-zero:D:3:1';232='load-exit:return-zero:Q:4:1'
}
for($i=0;$i -lt 8;$i++){
    $attacks[240+$i]="query-$i-exit`:return-zero:Q:3:1"
    $attacks[250+$i]="query-$i`:primask:p:3:1"
}
$attacks[260]='query-7:control:l:3:1'
$attacks[261]='query-7:basepri:b:3:1'
$attacks[262]='query-7:faultmask:f:3:1'
$attacks[263]='query-7:psplim:L:3:1'
$cases=@(0..4)+@($attacks.Keys|Sort-Object)
if($PSBoundParameters.ContainsKey('DevelopmentCases')){foreach($n in $DevelopmentCases){if($n -notin $cases){throw "Unknown case $n"}};$cases=@($DevelopmentCases|Sort-Object -Unique)}
$inputs=@($PSCommandPath,$ArmGcc,$nm,$objdump,$objcopy,$ar,$rsp,$inventory)+
    @(Get-RuntimeSourceInputs -RepositoryRoot $repo -Roles $runtimeRoles)+
    @(Get-ChildItem $fixture -Recurse -File|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $CmsisCore -File -Filter '*.h'|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem (Join-Path $FreeRtosRoot 'include'),$refns,$refs -File|Where-Object {$_.Extension -in @('.h','.c')}|Select-Object -ExpandProperty FullName)
if(!$DevelopmentReferenceOnly){
    if(!(Test-Path (Join-Path $ns 'fiber_port_pendsv.c'))){throw 'Actual staged PendSV has not landed; use -DevelopmentReferenceOnly for the established reference probe'}
    $inputs+=@((Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h'))+
        @(Get-ChildItem (Join-Path $repo 'context') -File | Where-Object {$_.Extension -in @('.c','.h')} | Select-Object -ExpandProperty FullName)+
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
function BuildReference([hashtable]$Mode,[string]$Parent){
    $dir=Join-Path $Parent 'reference';$null=New-Item -ItemType Directory -Path $dir
    $flags=$base+$mode.Flags+@('-std=c11','-DRUNNING_REFERENCE=1',"-I$fixture/reference","-I$fixture","-I$CmsisCore")
    $sf=$flags+@('-mcmse','-DRUNNING_SECURE=1',"-I$refs")
    $nf=$flags+@("-I$FreeRtosRoot/include","-I$refns","-I$refs")
    $objects=@()
    foreach($u in @(@('init',(Join-Path $refs 'secure_init.c')),@('context',(Join-Path $refs 'secure_context.c')),
        @('context-port',(Join-Path $refs 'secure_context_port.c')),@('secure',(Join-Path $fixture 'secure.c')),
        @('startup',(Join-Path $fixture 'startup.S')),@('windows',(Join-Path $fixture 'windows.S')),
        @('support',(Join-Path $fixture 'support.c')),@('heap',(Join-Path $fixture 'reference/heap.c')),
        @('roots',(Join-Path $fixture 'reference/secure_roots.c')))){
        $extra=if($u[0] -eq 'context-port'){@('-Wno-unused-parameter')}else{@()}
        $objects+=Compile $u[0] $u[1] ($sf+$extra) $dir
    }
    $import=Join-Path $dir 'secure-import.o'
    $s=Link 'secure' ($sf+$link+@('-T',(Join-Path $fixture 'reference/secure.ld'),'-Wl,--section-start=.gnu.sgstubs=0x10008000',"-Wl,--cmse-implib,--out-implib=$import")) $objects $dir
    $objects=@()
    foreach($u in @(@('port',(Join-Path $refns 'port.c')),@('portasm',(Join-Path $refns 'portasm.c')),
        @('nonsecure',(Join-Path $fixture 'reference/nonsecure.c')),@('ns-startup',(Join-Path $fixture 'startup.S')),
        @('ns-windows',(Join-Path $fixture 'windows.S')),@('ns-support',(Join-Path $fixture 'support.c')))){
        $extra=if($u[0] -eq 'portasm'){@('-Wno-unused-parameter')}else{@()}
        $objects+=Compile $u[0] $u[1] ($nf+$extra) $dir
    }
    $n=Link 'nonsecure' ($nf+$link+@('-T',(Join-Path $fixture 'reference/nonsecure.ld'))) ($objects+@($import)) $dir
    $manifest=@{kind='reference';stride=4;secure_ready=(Symbol $s.Symbols 'running_secure_ready');pendsv=(Symbol $n.Symbols 'PendSV_Handler');selector=(Symbol $n.Symbols 'vTaskSwitchContext');
        ns_checkpoint=(Symbol $n.Symbols 'running_ns_window_checkpoint');ns_resumed=(Symbol $n.Symbols 'running_ns_window_resumed');
        s_checkpoint=(Symbol $s.Symbols 'running_secure_window_checkpoint');s_resumed=(Symbol $s.Symbols 'running_secure_window_resumed');
        records=(Symbol $s.Symbols 'xSecureContexts');heap=(Symbol $s.Symbols 'running_reference_heap');
        tcbs=(Symbol $n.Symbols 'running_tcbs');selected=(Symbol $n.Symbols 'running_selected');
        current_slot=(Symbol $n.Symbols 'pxCurrentTCB');live_handle=(Symbol $n.Symbols 'xSecureContext');
        save=(Symbol $s.Symbols '__acle_se_SecureContext_SaveContext');load=(Symbol $s.Symbols '__acle_se_SecureContext_LoadContext')}
    $manifest.gateways=GatewayManifest $s $n $true
    $manifest.prepared=Symbol $n.Symbols 'running_prepared'
    $manifest.task_entry=Symbol $n.Symbols 'running_task'
    $manifest.task_return=Symbol $n.Symbols 'running_task_return'
    $manifest.stacks=Symbol $n.Symbols 'running_stacks'
    return @{Secure=$s;Nonsecure=$n;Manifest=$manifest;Directory=$dir}
}
function ExecuteCases([hashtable]$Model,[hashtable]$Mode,[int[]]$Cases){
    $dir=$Model.Directory
    $manifest=$Model.Manifest
    foreach($number in $cases){
        $manifest=@{}
        foreach($key in $Model.Manifest.Keys){$manifest[$key]=$Model.Manifest[$key]}
        $scenario=$number
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
        if($number -eq 160){
            $fault=Join-Path $caseDir 'fault.bin';[IO.File]::WriteAllBytes($fault,[BitConverter]::GetBytes([uint32]1))
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
function FiberManifest([hashtable]$S,[hashtable]$N){
    $manifest=@{kind='fiber';stride=80;secure_ready=(Symbol $s.Symbols 'running_secure_ready');
        pendsv=(Symbol $n.Symbols 'PendSV_Handler');selector=(Symbol $n.Symbols 'running_pick');
        ns_checkpoint=(Symbol $n.Symbols 'running_ns_window_checkpoint');ns_resumed=(Symbol $n.Symbols 'running_ns_window_resumed');
        s_checkpoint=(Symbol $s.Symbols 'running_secure_window_checkpoint');s_resumed=(Symbol $s.Symbols 'running_secure_window_resumed');
        records=(Symbol $s.Symbols 'fiber_secure_context_pool_image');heap=((Symbol $s.Symbols 'fiber_secure_context_pool_image')+72);
        pool_state=(Symbol $s.Symbols 'fiber_secure_context_pool_state');gateway_state=(Symbol $s.Symbols 'fiber_secure_context_gateway_state');
        tcbs=(Symbol $n.Symbols 'running_contexts');selected=(Symbol $n.Symbols 'running_selected');
        current_slot=(Symbol $n.Symbols 'fiber_internal_runtime_current_context_slot');live_handle=(Symbol $n.Symbols 'fiber_port_live_secure_context_handle');
        save=(Symbol $s.Symbols '__acle_se_fiber_secure_context_gateway_c55s_v1_save');
        load=(Symbol $s.Symbols '__acle_se_fiber_secure_context_gateway_c55s_v1_load')}
    $manifest.gateways=GatewayManifest $s $n $false
    $manifest.prepared=Symbol $n.Symbols 'running_prepared'
    $manifest.task_entry=Symbol $n.Symbols 'running_task'
    $manifest.task_return=Symbol $n.Symbols 'fiber_internal_task_return'
    $manifest.stacks=Symbol $n.Symbols 'running_stacks'
    $manifest.panic=Symbol $n.Symbols 'fiber_panic'
    $manifest.plan=Symbol $n.Symbols 'fiber_port_pendsv_plan'
    $manifest.prepare_save=Symbol $n.Symbols 'fiber_port_pendsv_prepare_save'
    $manifest.ram_hook=Symbol $n.Symbols 'fiber_addr_plausible_ram'
    $manifest.code_hook=Symbol $n.Symbols 'fiber_addr_plausible_code'
    $manifest.control_injection=Symbol $n.Symbols 'running_control_injection'
    $manifest.control_done=Symbol $n.Symbols 'running_control_done'
    $manifest.control_return=Symbol $n.Symbols 'running_control_return'
    $manifest.control_value=Symbol $n.Symbols 'running_control_value'
    $manifest.control_register=Symbol $n.Symbols 'running_control_register'
    foreach($field in @('injection','done','return','value','register')){
        $manifest[('s_control_'+$field)]=Symbol $s.Symbols ('running_control_'+$field)
    }
    $manifest.pool_fail=Symbol $s.Symbols 'fiber_secure_context_pool_fail_closed'
    $manifest.fault_entry=Symbol $s.Symbols 'running_fault_handler'
    $manifest.fault_terminal=Symbol $s.Symbols 'running_fault_terminal'
    return $manifest
}
function BuildFiber([hashtable]$Mode,[string]$Parent){
    $pendsv=Join-Path $ns 'fiber_port_pendsv.c'
    if(!(Test-Path -LiteralPath $pendsv)){throw 'Actual staged PendSV source has not landed; no substitute provider is supplied'}
    $dir=Join-Path $Parent 'fiber';$null=New-Item -ItemType Directory -Path $dir
    $flags=$base+$Mode.Flags+@('-std=c11','-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV81M_MAINLINE=1',
        "-I$fixture","-I$repo","-I$CmsisCore")
    $nf=$flags+@("-I$ns")
    $sf=$flags+@('-mcmse','-DRUNNING_SECURE=1',"-I$secure",'-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3u',
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
    Check "$($Mode.Name) exactly twelve production gateways plus one fixture SG" (!(Compare-Object @($gateways+@('running_secure_work')|Sort-Object) $importNames))
    $nfixture=@()
    foreach($name in @('nonsecure.c','startup.S','windows.S','support.c','control_injection.S')){
        $nfixture+=Compile ('n-'+$name) (Join-Path $fixture $name) $nf $dir
    }
    foreach($source in $runtimeSources){
        $name=$source.Substring($repo.Length+1).Replace('\','_').Replace('/','_')
        $nfixture+=Compile $name $source $nf $dir
    }
    $nobjects=@()
    foreach($name in @('fiber_port_boot.c','fiber_port_runtime.c','fiber_port_secure_context.c','fiber_port_svc.c','fiber_port_pendsv.c')){
        $source=Join-Path $ns $name
        $object=Compile $name $source ($nf+$hostile) $dir
        if($hostile.Count){NormalHostile $name $source $nf $object $dir}
        $nobjects+=$object
    }
    $nraw=@($nobjects)
    if($Mode.ContainsKey('Archive')){$nobjects=@(MakeArchive 'ns-staged-components' $nobjects $dir)}
    $nlink=$nf+$link+@('-T',(Join-Path $fixture 'nonsecure.ld'),'-T',(Join-Path $ns 'fiber_port_first_start_contract.ld'))
    $n=Link 'nonsecure' $nlink ($nfixture+$nobjects+@($import)) $dir
    $pd=[regex]::Match($n.Dis,'(?ms)^[0-9a-f]+ <PendSV_Handler>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)').Groups[1].Value
    Check "$($Mode.Name) generated successful final GPR restore has only barriers and BX LR" ($pd -match '(?s)ldmia\.w\s+r2!,\s*\{r4, r5, r6, r7, r8, r9, sl, fp\}\s*\r?\n\s*[0-9a-f]+:\s+[0-9a-f ]+\s+dsb\s+sy\s*\r?\n\s*[0-9a-f]+:\s+[0-9a-f ]+\s+isb\s+sy\s*\r?\n\s*[0-9a-f]+:\s+[0-9a-f ]+\s+bx\s+lr')
    $names=@($n.Symbols -split "`n"|ForEach-Object {if($_ -match '^\S+\s+(?:\S+\s+)?[a-zA-Z]\s+(\S+)\s*$'){$Matches[1]}})
    foreach($name in @('fiber_init','fiber_start','fiber_yield','fiber_set_scheduler','fiber_request_stop',
        'fiber_port_panic_wait','fiber_port_runtime_prepare_start','fiber_port_runtime_select_first',
        'fiber_port_runtime_start_first','fiber_port_runtime_schedule','fiber_port_require_scheduler_configuration_environment')){
        Check "$($Mode.Name) no fake full provider/public operation $name" ($name -cnotin $names)
    }
    $manifest=FiberManifest $s $n
    return @{Secure=$s;Nonsecure=$n;Manifest=$manifest;Directory=$dir;SFlags=$sf;NFlags=$nf;Hostile=$hostile;
        SRaw=$sraw;NRaw=$nraw;NList=$nobjects;SFixture=$sfixture;NFixture=$nfixture;SLink=$slink;NLink=$nlink;Import=$import}
}
function RejectUndefined([string]$Name,[string[]]$Flags,[string[]]$Objects,[string[]]$Expected,[string]$Dir){
    $result=Command $ArmGcc ($Flags+$Objects+@('-o',(Join-Path $Dir ($Name+'.elf')))) (Join-Path $Dir ($Name+'-rejected.log')) -AllowFailure
    Check "$Name failed actual link" ($result.ExitCode -ne 0)
    $actual=@([regex]::Matches($result.Text,"undefined reference to ``([^']+)'")|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique)
    Check "$Name exact missing gateway set" (!(Compare-Object @($Expected|Sort-Object) $actual))
}
function ProviderNegatives([hashtable]$Model,[hashtable]$Mode){
    $dir=Join-Path $Model.Directory 'providers';$null=New-Item -ItemType Directory -Path $dir
    $original=Command $nm @('-g','--defined-only',$Model.Import) (Join-Path $dir 'actual-import.nm')
    $address=Symbol $original 'running_secure_work'
    $work=Compile 'work-only-import' (Join-Path $fixture 'work_only_import.S') ($Model.NFlags+@("-DRUNNING_SG_ADDRESS=$address")) $dir
    $symbols=Command $nm @('-g','--defined-only',$work) (Join-Path $dir 'work-only-import.nm')
    $public=@($symbols -split "`n"|Where-Object {$_ -match '^\S+\s+[a-zA-Z]\s+\S+\s*$'})
    Check "$($Mode.Name) fixture work-only import has exactly one actual same-address global" ($public.Count -eq 1 -and (Symbol $symbols 'running_secure_work') -eq $address)
    RejectUndefined 'missing-Secure-provider' $Model.NLink ($Model.NFixture+$Model.NList+@($work)) $gateways $dir
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
    RejectUndefined 'foreign-C33S-provider' $Model.NLink ($Model.NFixture+$Model.NList+@($work,$import)) $gateways $dir
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
            Scene=1;Error='unexpected-panic';Panic=88;State=0},
        @{Name='store-NS-GPRs-for-Secure-origin';File='fiber_port_pendsv.c';Pattern=[regex]::Escape('"bne 1f\n"');
            Replacement='"beq 1f\n"';Scene=1;Error='unexpected-panic';Panic=83;State=2})
    foreach($control in $controls){
        $dir=Join-Path $Model.Directory $control.Name;$null=New-Item -ItemType Directory -Path $dir
        $text=Get-Content -LiteralPath (Join-Path $ns $control.File) -Raw
        $begin=0;$end=$text.Length
        if($control.ContainsKey('Scope')){
            $begin=$text.IndexOf('void fiber_port_context_live_frame_check(')
            $end=$text.IndexOf('uint32_t fiber_port_context_saved_frame_check(',$begin)
            Check "$($control.Name) exact actual helper scope" ($begin -ge 0 -and $end -gt $begin)
        }
        $part=$text.Substring($begin,$end-$begin)
        Check "$($Mode.Name) $($control.Name) unique actual source mutation" ([regex]::Matches($part,$control.Pattern).Count -eq 1)
        $source=Join-Path $dir 'actual-NS-mutant.c'
        [IO.File]::WriteAllText($source,$text.Substring(0,$begin)+[regex]::Replace($part,$control.Pattern,$control.Replacement)+$text.Substring($end))
        $object=Compile 'mutant' $source ($Model.NFlags+$Model.Hostile) $dir
        $objects=@($Model.NRaw|ForEach-Object {if((Split-Path $_ -Leaf) -ceq ($control.File+'.o')){$object}else{$_}})
        Check "$($control.Name) actual object replaced" ($object -cin $objects)
        if($Mode.ContainsKey('Archive')){$objects=@(MakeArchive 'mutated-staged-components' $objects $dir)}
        $n=Link 'nonsecure' $Model.NLink ($Model.NFixture+$objects+@($Model.Import)) $dir
        $manifest=FiberManifest $Model.Secure $n
        $manifest.case=$control.Scene;$manifest.scenario=$control.Scene
        $word=Join-Path $dir 'case.bin';[IO.File]::WriteAllBytes($word,[BitConverter]::GetBytes([uint32]$control.Scene))
        $elf=Join-Path $dir 'case.elf'
        $null=Command $objcopy @('--update-section',".fixture_case=$word",$n.Elf,$elf) (Join-Path $dir 'case-patch.log')
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
            Check "$($control.Name) exact real Secure-origin terminal diagnostic" ($observed.Count -eq 1 -and $observed[0].code -eq $control.Panic -and ($observed[0].cpu.xpsr -band 511) -eq 14 -and $origin.Count -eq 1)
            Check "$($control.Name) exact sticky plan phase" ($observed[0].plan_words[7] -eq $control.State)
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
        @{Name='counterfeit-Thread-fault-record';File='support.c';Pattern=[regex]::Escape('running_fault_terminal(frame,ret);');Replacement='running_fault_terminal(frame,ret | 8u);'})){
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
        $n=Link 'nonsecure' $Model.NLink ($Model.NFixture+$Model.NList+@($import)) $dir
        $manifest=FiberManifest $s $n
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
try{
    Check 'clean exact FreeRTOS pin' ((Command git @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.log')).Trim() -eq 'a50edad08b29052631aa469d4df6e6ec7ff68878')
    $null=Command git @('-C',$FreeRtosRoot,'diff','--exit-code','HEAD','--') (Join-Path $out 'reference-clean.log')
    $null=Command $ArmGcc @('--version') (Join-Path $out 'compiler-version.log')
    $wslFixture=LinuxPath $fixture;$wslRsp=LinuxPath $rsp
    $null=Command $wsl @('-d',$WslDistro,'--exec','bash',(LinuxPath $inventory),'inspect',$QemuRoot,(LinuxPath $out)) (Join-Path $out 'qemu-inspect.log')
    foreach($mode in $modes){
        $dir=Join-Path $out $mode.Name;$null=New-Item -ItemType Directory -Path $dir
        $referenceCases=@($cases|Where-Object {$_ -lt 5})
        if($mode.Name -in $referenceModes -and $referenceCases.Count){$model=BuildReference $mode $dir;ExecuteCases $model $mode $referenceCases}
        if(!$DevelopmentReferenceOnly){$model=BuildFiber $mode $dir;ProviderNegatives $model $mode;ExecuteCases $model $mode $cases;CompiledControls $model $mode;FaultControls $model $mode}
    }
    if($complete){
        Check 'complete maintained inventory: ten modes, ninety Fiber cases, eight compiled controls, twenty reference executions' ($modes.Count -eq 10 -and $cases.Count -eq 90 -and $runs.Count -eq 1000)
        foreach($mode in $modes){
            $rows=@($runs|Where-Object Mode -ceq $mode.Name)
            $fiberRows=@($rows|Where-Object Kind -ceq fiber)
            Check "$($mode.Name) exact ninety distinct Fiber case receipts" ($fiberRows.Count -eq 90 -and !(Compare-Object @($cases|Sort-Object) @($fiberRows.Case|Sort-Object)))
            $controls=@($rows|Where-Object Kind -ceq compiled-control)
            Check "$($mode.Name) eight distinct compiled rejection controls" ($controls.Count -eq 8 -and @($controls.Label|Sort-Object -Unique).Count -eq 8 -and @($controls|Where-Object Result -cne EXPECTED-REJECTION).Count -eq 0)
            $refs=@($rows|Where-Object Kind -ceq reference)
            Check "$($mode.Name) exact reference applicability" ($refs.Count -eq $(if($mode.Name -in $referenceModes){5}else{0}))
        }
    }
    $verdict='PASS'
}finally{
    $after=@($inputs|ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256}|Select-Object Path,Hash)
    $after|ConvertTo-Json -Depth 4|Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $drift=@(Compare-Object $before $after -Property Path,Hash);if($drift.Count){$verdict='FAIL'}
    [pscustomobject]@{Verdict=$verdict;CompleteSuite=($complete -and $verdict -ceq 'PASS');Launches=$runs.Count;Checks=$checks.Count;InputCount=$before.Count;InputDrift=$drift.Count;
        Runs=@($runs.ToArray());Assertions=@($checks.ToArray());Limit='Actual staged C55S first/PendSV components only; not all eight provider operations, public-runtime activation, four-setting hash/map switch policy, full kernel, asynchronous stress, silicon, or board qualification'}|
        ConvertTo-Json -Depth 8|Set-Content (Join-Path $out 'results.json') -Encoding ASCII
    Get-ChildItem $out -Recurse -File|Where-Object Name -ne sha256.csv|ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256}|
        Select-Object Path,Hash|Export-Csv (Join-Path $out 'sha256.csv') -NoTypeInformation -Encoding ASCII
    if($drift.Count){throw "Input drift: $out"}
}
if($verdict -ne 'PASS'){throw "Running proof failed: $out"}
Write-Host "PASS C55S running (complete=$complete): $($runs.Count) launches; $out"
