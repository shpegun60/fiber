param(
    [string]$ArmGcc=$env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore=$env:CMSIS_CORE_INCLUDE,
    [string]$QemuRoot,
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
$fixture=Join-Path $PSScriptRoot 'fixtures\m55_secure_first_start'
$ns=Join-Path $repo 'fiber\port\ARM_CM55\non_secure'
$secure=Join-Path $repo 'fiber\port\ARM_CM55\secure'
if(!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)){throw 'Supply existing -ArmGcc'}
if(!$QemuRoot -or !$QemuRoot.StartsWith('/')){throw 'Explicit existing absolute WSL -QemuRoot required; no installation or silent skip'}
if(!$CmsisCore){$CmsisCore=Join-Path $repo '..\..\..\Drivers\CMSIS\Include'}
if(!$FreeRtosRoot){$FreeRtosRoot=Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel'}
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot=(Resolve-Path -LiteralPath $FreeRtosRoot).Path
$refns=Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM55\non_secure'
$refs=Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM55\secure'
$bin=Split-Path $ArmGcc
$nm=Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$ar=Join-Path $bin 'arm-none-eabi-gcc-ar.exe'
$objdump=Join-Path $bin 'arm-none-eabi-objdump.exe'
$objcopy=Join-Path $bin 'arm-none-eabi-objcopy.exe'
$wsl=(Get-Command wsl.exe -ErrorAction Stop).Source
$rsp=Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards\aircr_rsp.py'
$inspect=Join-Path $PSScriptRoot 'fixtures\arm_control\qemu.sh'
foreach($path in @($nm,$ar,$objdump,$objcopy,$rsp,$inspect,(Join-Path $ns 'fiber_port_private.h'),
        (Join-Path $ns 'fiber_port_runtime.c'),(Join-Path $ns 'fiber_port_svc.c'),(Join-Path $refs 'secure_context.c'))){
    if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw "Missing actual source/tool: $path"}
}
if(!$BuildRoot){$BuildRoot=[IO.Path]::GetTempPath()}
$out=Join-Path $BuildRoot ('fiber-m55-secure-first-start-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out -Force
$out=(Resolve-Path -LiteralPath $out).Path
$commands=Join-Path $out 'commands.jsonl'
$checks=New-Object System.Collections.Generic.List[object]
$runs=New-Object System.Collections.Generic.List[object]
$verdict='FAIL'
Write-Host "C55S first-start evidence: $out"
function Recorded([string]$Program,[string[]]$Arguments,[string]$Log,[switch]$AllowFailure){
    [pscustomobject]@{Program=$Program;Arguments=$Arguments;Log=$Log}|ConvertTo-Json -Depth 6 -Compress|
        Add-Content -LiteralPath $commands -Encoding ASCII
    $previous=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$lines=@(& $Program @Arguments 2>&1|ForEach-Object {"$_"});$code=$LASTEXITCODE}
    finally{$ErrorActionPreference=$previous}
    [IO.File]::WriteAllLines($Log,[string[]]$lines)
    if($code -ne 0 -and !$AllowFailure){throw "Command failed ($code): $Log`n$($lines -join "`n")"}
    return [pscustomobject]@{ExitCode=$code;Text=($lines -join "`n")}
}
function Check([string]$Name,[bool]$Value){
    if(!$Value){throw "Failed first-start check: $Name"}
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$true})
}
function WslPath([string]$Path){
    return (Recorded $wsl @('-d',$WslDistro,'--exec','wslpath','-u',$Path) (Join-Path $out ('wslpath-'+[guid]::NewGuid().ToString('N')+'.log'))).Text.Trim()
}
function Symbol([string]$Symbols,[string]$Name){
    $found=[regex]::Matches($Symbols,'(?m)^([0-9a-f]+)\s+(?:([0-9a-f]+)\s+)?([a-zA-Z])\s+'+[regex]::Escape($Name)+'\r?$')
    if($found.Count -ne 1){throw "Missing unique ELF symbol $Name"}
    return [Convert]::ToUInt32($found[0].Groups[1].Value,16)
}
function FunctionBody([string]$Dis,[string]$Name){
    $found=[regex]::Matches($Dis,'(?ms)^[0-9a-f]+ <'+[regex]::Escape($Name)+'>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
    if($found.Count -ne 1){throw "Missing unique disassembly body $Name"}
    return $found[0].Groups[1].Value
}
function Bx([string]$Dis,[string]$Name){
    $body=FunctionBody $Dis $Name
    $found=[regex]::Matches($body,'(?m)^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+bx\s+r3\s*\r?$')
    if($found.Count -ne 1){throw "Missing unique EXC_RETURN BX in $Name"}
    return [Convert]::ToUInt32($found[0].Groups[1].Value,16)
}
function SecureExits([string]$Dis,[string]$Name,[string]$Operation){
    $body=FunctionBody $Dis $Name
    $sites=@([regex]::Matches($body,'(?m)^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+bxns\s+lr\s*\r?$'))
    if(!$sites.Count){throw "Missing actual BXNS return in $Name"}
    return @($sites|ForEach-Object {@{operation=$Operation;address=[Convert]::ToUInt32($_.Groups[1].Value,16)}})
}
function SvcReturn([string]$Dis,[string]$Name,[int]$Immediate){
    $body=FunctionBody $Dis $Name
    $sites=@([regex]::Matches($body,'(?m)^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+svc\s+'+$Immediate+'(?:\s+[^\r\n]*)?\r?$'))
    if($sites.Count -ne 1){throw "Missing exact SVC$Immediate in $Name"}
    return [Convert]::ToUInt32($sites[0].Groups[1].Value,16)+2
}
function Compile([string]$Name,[string]$Source,[string[]]$Flags,[string]$Directory){
    $object=Join-Path $Directory ($Name+'.o')
    $null=Recorded $ArmGcc ($Flags+@('-save-temps=obj','-MMD','-c',$Source,'-o',$object)) (Join-Path $Directory ($Name+'-compile.log'))
    return $object
}
function LinkImage([string]$Name,[string[]]$Flags,[string[]]$Objects,[string]$Directory){
    $elf=Join-Path $Directory ($Name+'.elf')
    $null=Recorded $ArmGcc ($Flags+$Objects+@("-Wl,-Map,$Directory/$Name.map",'-o',$elf)) (Join-Path $Directory ($Name+'-link.log'))
    $symbols=(Recorded $nm @('-a','-S',$elf) (Join-Path $Directory ($Name+'.nm'))).Text
    $dis=(Recorded $objdump @('-drwC',$elf) (Join-Path $Directory ($Name+'.dis'))).Text
    $undefined=(Recorded $nm @('-u',$elf) (Join-Path $Directory ($Name+'-undefined.log'))).Text.Trim()
    Check "$Name empty final undefined set" ($undefined.Length -eq 0)
    Check "$Name no instrumentation dependency/counter" ($symbols -notmatch '(?i)(__cyg_profile|__gcov|__ubsan|__asan|__tsan|__sanitizer|__stack_chk|__morestack|__mcount|__chkstk)')
    return @{Elf=$elf;Symbols=$symbols;Dis=$dis}
}
function Archive([string]$Name,[string[]]$Objects,[string]$Directory){
    $path=Join-Path $Directory ($Name+'.a')
    $null=Recorded $ar (@('rcs',$path)+$Objects) (Join-Path $Directory ($Name+'-archive.log'))
    return $path
}
function UndefinedSet([string]$Object,[string]$Log){
    $text=(Recorded $nm @('-u',$Object) $Log).Text
    return @($text -split "`n"|ForEach-Object {if($_ -match '^\s*U\s+(\S+)\s*$'){$Matches[1]}}|Sort-Object -Unique)
}
function RejectUndefined([string]$Name,[string[]]$Flags,[string[]]$Objects,[string[]]$Expected,[string]$Directory){
    $r=Recorded $ArmGcc ($Flags+$Objects+@('-o',(Join-Path $Directory ($Name+'.elf')))) (Join-Path $Directory ($Name+'-rejected.log')) -AllowFailure
    Check "$Name actual failed link" ($r.ExitCode -ne 0)
    $actual=@([regex]::Matches($r.Text,"undefined reference to ``([^']+)'")|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique)
    Check "$Name exact missing gateway symbol set" (!(Compare-Object @($Expected|Sort-Object) $actual))
}
function HostileContract([string]$Name,[string]$Source,[string[]]$Flags,[string]$Object,[string]$Directory){
    $normal=Compile ($Name+'-normal') $Source $Flags $Directory
    $normalDeps=@(UndefinedSet $normal (Join-Path $Directory ($Name+'-normal-undefined.log')))
    $hostileDeps=@(UndefinedSet $Object (Join-Path $Directory ($Name+'-hostile-undefined.log')))
    Check "$($mode.Name) $Name exact normal/hostile undefined contract" (!(Compare-Object $normalDeps $hostileDeps))
    $symbols=(Recorded $nm @('-a',$Object) (Join-Path $Directory ($Name+'-hostile-symbols.nm'))).Text
    Check "$($mode.Name) $Name no hidden uncollected counters" ($symbols -notmatch '(?i)(__cyg_profile|__gcov|__ubsan|__asan|__tsan|__sanitizer|__stack_chk|__morestack|__mcount|__chkstk)')
}
function RunCase([string]$Label,[int]$Number,[hashtable]$Model,[hashtable]$Extra,[string]$Directory,[string]$RejectError=''){
    $dir=Join-Path $Directory $Label
    $null=New-Item -ItemType Directory -Path $dir
    $word=Join-Path $dir 'case.bin'
    [IO.File]::WriteAllBytes($word,[BitConverter]::GetBytes([uint32]$Number))
    $elf=Join-Path $dir 'nonsecure.elf'
    $null=Recorded $objcopy @('--update-section',".fixture_case=$word",$Model.Nonsecure.Elf,$elf) (Join-Path $dir 'case-patch.log')
    if($Number -eq 2 -or $Number -eq 3){
        $vectors=Join-Path $dir 'vectors.bin'
        $null=Recorded $objcopy @('--dump-section',".vectors=$vectors",$elf) (Join-Path $dir 'vector-dump.log')
        $bytes=[IO.File]::ReadAllBytes($vectors)
        $top=if($Number -eq 2){0x20020008}else{0x200187f8}
        [BitConverter]::GetBytes([uint32]$top).CopyTo($bytes,0)
        [IO.File]::WriteAllBytes($vectors,$bytes)
        $null=Recorded $objcopy @('--update-section',".vectors=$vectors",$elf) (Join-Path $dir 'vector-patch.log')
    }
    $manifest=@{}
    foreach($key in $Model.Manifest.Keys){$manifest[$key]=$Model.Manifest[$key]}
    foreach($key in $Extra.Keys){$manifest[$key]=$Extra[$key]}
    $manifest.case=$Number
    $manifest.secure=WslPath $Model.Secure.Elf
    $manifest.nonsecure=WslPath $elf
    $manifest.secure_sha256=(Get-FileHash -LiteralPath $Model.Secure.Elf -Algorithm SHA256).Hash
    $manifest.nonsecure_sha256=(Get-FileHash -LiteralPath $elf -Algorithm SHA256).Hash
    $file=Join-Path $dir 'manifest.json'
    $manifest|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $file -Encoding ASCII
    $r=Recorded $wsl @('-d',$WslDistro,'--exec','python3','-B',"$wslFixture/run.py",$QemuRoot,"$TimeoutSeconds",(WslPath $file),$wslRsp) (Join-Path $dir 'run.log') -AllowFailure
    $receipt=Get-Content -LiteralPath (Join-Path $dir 'receipt.json') -Raw|ConvertFrom-Json
    if($RejectError){
        Check "$($mode.Name) $Label compiled control rejected at exact oracle" ($r.ExitCode -ne 0 -and $receipt.result -eq 'FAIL' -and $receipt.error -ceq $RejectError)
    }else{Check "$($mode.Name) $Label execution" ($r.ExitCode -eq 0 -and $receipt.result -eq 'PASS')}
    $runs.Add([pscustomobject]@{Mode=$mode.Name;Label=$Label;Case=$Number;Kind=$manifest.kind;Receipt=(Join-Path $dir 'receipt.json');
        Result=$(if($RejectError){'EXPECTED-REJECTION'}else{$receipt.result})})
}
$queries=@('fiber_secure_gateway_c55s_v1_abi_version','fiber_secure_gateway_c55s_v1_context_port_id',
    'fiber_secure_gateway_c55s_v1_context_layout_version','fiber_secure_gateway_c55s_v1_context_feature_mask',
    'fiber_secure_context_gateway_c55s_v1_abi_version','fiber_secure_context_gateway_c55s_v1_stack_alignment',
    'fiber_secure_context_gateway_c55s_v1_max_contexts','fiber_secure_context_gateway_c55s_v1_max_stack_bytes')
$base=@('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-mgeneral-regs-only','-ffreestanding','-fno-builtin','-fno-common',
    '-ffunction-sections','-fdata-sections','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
    '-fstrict-aliasing','-Wstrict-aliasing=3','-Wall','-Wextra','-Werror','-g3')
$selected=@('-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV81M_MAINLINE=1')
$link=@('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none')
$allModes=@(@{Name='o2';Flags=@('-O2')},@{Name='os';Flags=@('-Os')},
    @{Name='o2-lto';Flags=@('-O2','-flto')},@{Name='os-lto';Flags=@('-Os','-flto')},
    @{Name='o2-archive';Flags=@('-O2');Archive=$true},@{Name='os-archive';Flags=@('-Os');Archive=$true},
    @{Name='o2-archive-lto';Flags=@('-O2','-flto');Archive=$true},@{Name='os-archive-lto';Flags=@('-Os','-flto');Archive=$true},
    @{Name='o2-hostile';Flags=@('-O2');Hostile=$true},@{Name='os-hostile';Flags=@('-Os');Hostile=$true})
$modes=$allModes
if($DevelopmentModes){
    foreach($name in $DevelopmentModes){if($name -notin $allModes.Name){throw "Unknown development mode $name"}}
    $modes=@($allModes|Where-Object {$_.Name -in $DevelopmentModes})
}
$allCases=@(0..27)+@(100..107)+@(200..207)+@(210..213)+@(300..302)+@(400,401)
$cases=$allCases
if($PSBoundParameters.ContainsKey('DevelopmentCases')){
    foreach($n in $DevelopmentCases){if($n -notin $allCases){throw "Unknown development case $n"}}
    $cases=@($DevelopmentCases|Sort-Object -Unique)
}
$inputPaths=@($PSCommandPath,$ArmGcc,$nm,$ar,$objdump,$objcopy,$rsp,$inspect,
    (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h'))+
    @(Get-ChildItem (Join-Path $repo 'fiber') -File|Where-Object {$_.Extension -in @('.h','.c')}|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem (Join-Path $repo 'fiber\port') -File|Where-Object {$_.Extension -eq '.h'}|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $ns,$secure -File|Where-Object {$_.Extension -in @('.h','.c','.ld')}|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem (Join-Path $repo 'fiber\port\ARM_CM33\secure') -File|Where-Object {$_.Extension -in @('.h','.c','.ld')}|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $CmsisCore -File -Filter '*.h'|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem (Join-Path $FreeRtosRoot 'include'),$refns,$refs -File|Where-Object {$_.Extension -in @('.h','.c')}|Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $fixture -File -Recurse|Where-Object {$_.Extension -ne '.pyc'}|Select-Object -ExpandProperty FullName)
$inputPaths=@($inputPaths|Sort-Object -Unique)
$before=@($inputPaths|ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256}|Select-Object Path,Hash)
$before|ConvertTo-Json -Depth 4|Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII

function BuildReference([hashtable]$Mode,[string]$Parent){
    $dir=Join-Path $Parent 'reference'
    $null=New-Item -ItemType Directory -Path $dir
    $flags=$base+$Mode.Flags+@('-std=c11','-DFIRST_REFERENCE=1',"-I$fixture/reference","-I$fixture","-I$CmsisCore")
    $sflags=$flags+@('-mcmse','-DFIRST_SECURE=1',"-I$refs")
    $nflags=$flags+@("-I$FreeRtosRoot/include","-I$refns","-I$refs")
    $objects=@()
    foreach($u in @(@{Name='init';Source=(Join-Path $refs 'secure_init.c')},
            @{Name='context';Source=(Join-Path $refs 'secure_context.c')},
            @{Name='context-port';Source=(Join-Path $refs 'secure_context_port.c');Extra=@('-Wno-unused-parameter')},
            @{Name='heap';Source=(Join-Path $fixture 'reference\heap.c')},
            @{Name='secure-boot';Source=(Join-Path $fixture 'secure.c')},
            @{Name='secure-startup';Source=(Join-Path $fixture 'startup.S')},
            @{Name='secure-support';Source=(Join-Path $fixture 'support.c')},
            @{Name='secure-roots';Source=(Join-Path $fixture 'secure_roots.c')})){
        $extra=if($u.ContainsKey('Extra')){$u.Extra}else{@()}
        $objects+=Compile $u.Name $u.Source ($sflags+$extra) $dir
    }
    $import=Join-Path $dir 'secure-import.o'
    $s=LinkImage 'secure' ($sflags+$link+@('-T',(Join-Path $fixture 'reference\secure.ld'),
        '-Wl,--section-start=.gnu.sgstubs=0x10008000',"-Wl,--cmse-implib,--out-implib=$import")) $objects $dir
    $objects=@()
    foreach($u in @(@{Name='ns-port';Source=(Join-Path $refns 'port.c')},
            @{Name='ns-portasm';Source=(Join-Path $refns 'portasm.c');Extra=@('-Wno-unused-parameter')},
            @{Name='ns-fixture';Source=(Join-Path $fixture 'reference\nonsecure.c')},
            @{Name='ns-startup';Source=(Join-Path $fixture 'startup.S')},
            @{Name='ns-support';Source=(Join-Path $fixture 'support.c')})){
        $extra=if($u.ContainsKey('Extra')){$u.Extra}else{@()}
        $objects+=Compile $u.Name $u.Source ($nflags+$extra) $dir
    }
    $n=LinkImage 'nonsecure' ($nflags+$link+@('-T',(Join-Path $fixture 'reference\nonsecure.ld'))) ($objects+@($import)) $dir
    $body=FunctionBody $n.Dis 'vRestoreContextOfFirstTask'
    Check "$($Mode.Name) actual pin discards 32 GPR bytes" ($body -match '\badds\s+r0,\s*#32' -and $body -notmatch '\bldm[^\r\n]*\{r4')
    foreach($pattern in @('\bmsr\s+PSPLIM','\bmsr\s+CONTROL','\bmsr\s+PSP','\bmsr\s+BASEPRI')){
        Check "$($Mode.Name) actual pin special transfer $pattern" ($body -match $pattern)
    }
    $entries=@(@{operation='priority';address=(Symbol $s.Symbols '__acle_se_SecureInit_DePrioritizeNSExceptions')},
        @{operation='initialize';address=(Symbol $s.Symbols '__acle_se_SecureContext_Init')},
        @{operation='allocate';address=(Symbol $s.Symbols '__acle_se_SecureContext_AllocateContext')},
        @{operation='load';address=(Symbol $s.Symbols '__acle_se_SecureContext_LoadContext')})
    $exits=@()
    foreach($item in @(@{Name='SecureInit_DePrioritizeNSExceptions';Op='priority'},@{Name='SecureContext_Init';Op='initialize'},
            @{Name='SecureContext_AllocateContext';Op='allocate'},@{Name='SecureContext_LoadContext';Op='load'})){
        $exits+=SecureExits $s.Dis ('__acle_se_'+$item.Name) $item.Op
    }
    $manifest=@{kind='reference';secure_ready=(Symbol $s.Symbols 'first_secure_ready');prepared=(Symbol $n.Symbols 'first_prepared');entry=(Symbol $n.Symbols 'first_task_entry');
        restore_bx=(Bx $n.Dis 'vRestoreContextOfFirstTask');current_slot=(Symbol $n.Symbols 'pxCurrentTCB');
        live_handle=(Symbol $n.Symbols 'xSecureContext');reference_records=(Symbol $s.Symbols 'xSecureContexts');
        reference_heap=(Symbol $s.Symbols 'first_reference_heap');reference_heap_used=(Symbol $s.Symbols 'first_reference_heap_used');
        secure_entries=$entries;secure_exits=$exits;
        reference_tail_load=((FunctionBody $n.Dis 'vPortSVCHandler_C') -match '\bb\.w\s+[0-9a-f]+ <__SecureContext_LoadContext_veneer>')}
    return @{Secure=$s;Nonsecure=$n;Manifest=$manifest}
}

function FiberManifest([hashtable]$S,[hashtable]$N,[switch]$GprMutationControl){
    $entries=@();$exits=@()
    for($i=0;$i -lt $queries.Count;$i++){
        $name='__acle_se_'+$queries[$i]
        $entries+=@{operation="query-$i";address=(Symbol $S.Symbols $name)}
        $exits+=SecureExits $S.Dis $name "query-$i"
    }
    foreach($operation in @('initialize','allocate','load')){
        $name='__acle_se_fiber_secure_context_gateway_c55s_v1_'+$operation
        $entries+=@{operation=$operation;address=(Symbol $S.Symbols $name)}
        $exits+=SecureExits $S.Dis $name $operation
    }
    $restore=FunctionBody $N.Dis 'fiber_port_restore_first_context_from_svc'
    $gpr=[regex]::Matches($restore,'(?m)^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+ldmia[^\r\n]*\{r4[^\r\n]*(?:fp|r11)\}\r?$')
    if(!$GprMutationControl){
        Check "$($mode.Name) actual full r4-r11 restore" ($gpr.Count -eq 1)
        $tail=$restore.Substring($gpr[0].Index)
        $tail=$tail.Substring(0,$tail.IndexOf('bx')+2)
        Check "$($mode.Name) no C call after final GPR transfer" ($tail -notmatch '\bblx?\b')
    }else{Check "$($mode.Name) compiled mutation actually omits r4-r11 load" ($gpr.Count -eq 0)}
    $names=@($N.Symbols -split "`n"|ForEach-Object {if($_ -match '\s+[A-Za-z]\s+(\S+)\r?$'){$Matches[1]}})
    foreach($forbidden in @('PendSV_Handler','fiber_port_runtime_prepare_start','fiber_port_runtime_select_first',
            'fiber_port_runtime_start_first','fiber_port_runtime_schedule','fiber_port_require_scheduler_configuration_environment',
            'fiber_init','fiber_start','fiber_yield','fiber_set_scheduler','fiber_request_stop')){
        Check "$($mode.Name) staged image omits $forbidden" ($forbidden -cnotin $names)
    }
    return @{kind='fiber';secure_ready=(Symbol $S.Symbols 'first_secure_ready');prepared=(Symbol $N.Symbols 'first_prepared');
        entry=(Symbol $N.Symbols 'first_task_entry');restore_bx=(Bx $N.Dis 'fiber_port_restore_first_context_from_svc');
        panic=(Symbol $N.Symbols 'fiber_panic');svc=(Symbol $N.Symbols 'SVC_Handler');fault_handler=(Symbol $N.Symbols 'first_fault_handler');
        dispatch=(Symbol $N.Symbols 'fiber_port_svc_dispatch');prepare=(Symbol $N.Symbols 'fiber_port_prepare_first_start');
        context=(Symbol $N.Symbols 'first_context');original_frame=(Symbol $N.Symbols 'first_original_frame');
        current_slot=(Symbol $N.Symbols 'fiber_internal_runtime_current_context_slot');
        pool=(Symbol $S.Symbols 'fiber_secure_context_pool_image');pool_state=(Symbol $S.Symbols 'fiber_secure_context_pool_state');
        gateway_state=(Symbol $S.Symbols 'fiber_secure_context_gateway_state');
        plan=(Symbol $N.Symbols 'fiber_port_first_start_plan');live_handle=(Symbol $N.Symbols 'fiber_port_live_secure_context_handle');
        owned_return=(Symbol $N.Symbols 'fiber_port_c55s_first_start_svc_return');
        foreign_return=(SvcReturn $N.Dis 'first_foreign_70' 70);
        secure_entries=$entries;secure_exits=$exits}
}
function BuildFiber([hashtable]$Mode,[string]$Parent){
    $dir=Join-Path $Parent 'fiber'
    $null=New-Item -ItemType Directory -Path $dir
    $flags=$base+$Mode.Flags+$selected+@('-std=c11',"-I$fixture","-I$repo","-I$CmsisCore")
    $nflags=$flags+@("-I$ns")
    $sflags=$flags+@('-mcmse','-DFIRST_SECURE=1',"-I$secure",
        '-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3u','-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=128u')
    $hostile=@()
    if($Mode.ContainsKey('Hostile')){
        $hostile=@('-finstrument-functions','-fstack-protector-all','-fprofile-arcs','-ftest-coverage',
            '-fsanitize=undefined','-fsanitize-coverage=trace-pc','-fstack-check=generic')
    }
    $sfixture=@()
    foreach($u in @(@{Name='secure-fixture';Source=(Join-Path $fixture 'secure.c')},
            @{Name='secure-startup';Source=(Join-Path $fixture 'startup.S')},
            @{Name='secure-support';Source=(Join-Path $fixture 'support.c')},
            @{Name='secure-roots';Source=(Join-Path $fixture 'secure_roots.c')})){
        $sfixture+=Compile $u.Name $u.Source $sflags $dir
    }
    $sobjects=@{}
    foreach($u in @(@{Name='identity';Source=(Join-Path $secure 'fiber_secure_gateway.c')},
            @{Name='gateway';Source=(Join-Path $secure 'fiber_secure_context_gateway.c')},
            @{Name='pool';Source=(Join-Path $secure 'fiber_secure_context_pool.c')})){
        $sobjects[$u.Name]=Compile ('secure-'+$u.Name) $u.Source ($sflags+$hostile) $dir
        if($hostile.Count){HostileContract ('secure-'+$u.Name) $u.Source $sflags $sobjects[$u.Name] $dir}
    }
    $slist=@($sobjects.identity,$sobjects.gateway,$sobjects.pool)
    if($Mode.ContainsKey('Archive')){$slist=@(Archive 'secure-provider' $slist $dir)}
    $import=Join-Path $dir 'secure-import.o'
    $slink=$sflags+$link+@('-T',(Join-Path $fixture 'secure.ld'),'-T',(Join-Path $secure 'fiber_secure_context_cohort_contract.ld'),
        '-Wl,--section-start=.gnu.sgstubs=0x10008000',"-Wl,--cmse-implib,--out-implib=$import")
    $s=LinkImage 'secure' $slink ($sfixture+$slist) $dir
    $imports=(Recorded $nm @('-g','--defined-only',$import) (Join-Path $dir 'imports.nm')).Text
    $actual=@($imports -split "`n"|ForEach-Object {if($_ -match '^\s*[0-9a-f]+\s+[A-Za-z]\s+(\S+)\s*$'){$Matches[1]}}|Sort-Object)
    $expected=$queries+@('fiber_secure_context_gateway_c55s_v1_initialize','fiber_secure_context_gateway_c55s_v1_allocate',
        'fiber_secure_context_gateway_c55s_v1_load','fiber_secure_context_gateway_c55s_v1_save')
    Check "$($Mode.Name) exact genuine C55S twelve-import surface" (!(Compare-Object @($expected|Sort-Object) $actual))
    $nfixture=@()
    foreach($u in @(@{Name='ns-fixture';Source=(Join-Path $fixture 'nonsecure.c')},
            @{Name='ns-startup';Source=(Join-Path $fixture 'startup.S')},
            @{Name='ns-support';Source=(Join-Path $fixture 'support.c')},
            @{Name='common-state';Source=(Join-Path $repo 'fiber\fiber_runtime_state.c')},
            @{Name='common-configuration';Source=(Join-Path $repo 'fiber\fiber_runtime_context_configuration.c')})){
        $nfixture+=Compile $u.Name $u.Source $nflags $dir
    }
    $nobjects=@{}
    foreach($u in @(@{Name='boot';Source=(Join-Path $ns 'fiber_port_boot.c')},
            @{Name='runtime';Source=(Join-Path $ns 'fiber_port_runtime.c')},
            @{Name='context';Source=(Join-Path $ns 'fiber_port_secure_context.c')},
            @{Name='svc';Source=(Join-Path $ns 'fiber_port_svc.c')})){
        $nobjects[$u.Name]=Compile ('ns-'+$u.Name) $u.Source ($nflags+$hostile) $dir
        if($hostile.Count){HostileContract ('ns-'+$u.Name) $u.Source $nflags $nobjects[$u.Name] $dir}
    }
    $nlist=@($nobjects.boot,$nobjects.runtime,$nobjects.context,$nobjects.svc)
    if($Mode.ContainsKey('Archive')){$nlist=@(Archive 'ns-first-component' $nlist $dir)}
    $nlink=$nflags+$link+@('-T',(Join-Path $fixture 'nonsecure.ld'),'-T',(Join-Path $ns 'fiber_port_first_start_contract.ld'))
    $n=LinkImage 'nonsecure' $nlink ($nfixture+$nlist+@($import)) $dir
    $manifest=FiberManifest $s $n
    return @{Secure=$s;Nonsecure=$n;Manifest=$manifest;SFlags=$sflags;NFlags=$nflags;Hostile=$hostile;
        SObjects=$sobjects;SFixture=$sfixture;SLink=$slink;NObjects=$nobjects;NFixture=$nfixture;NList=$nlist;
        NLink=$nlink;Import=$import;Directory=$dir}
}
function Failure([int]$Number){
    $zero=@{priority=0;initialize=0;allocate=0;load=0}
    if($Number -le 1){return @{}}
    $codes=@{2='M';3='M';4='V';5='S';6='c';7='x';8='h';9='u';10='u';11='C';12='l';
        13='M';14='M';15='X';16='X';17='X';18='u';19='u';20='u';21='u';22='T';23='C';24='M';25='M';26='u';27='D'}
    if($Number -lt 100){
        $thread=@(2,3,4,5,6,7,8,12,22,23,24)
        return @{panic_code=[int][char]$codes[$Number];panic_ipsr=$(if($Number -in $thread){0}else{11});expected_counts=$zero}
    }
    if($Number -ge 100 -and $Number -le 107){return @{panic_code=81;panic_ipsr=11;expected_counts=$zero;query_index=($Number-100)}}
    if($Number -ge 200 -and $Number -le 207){return @{panic_code=112;panic_ipsr=11;expected_counts=$zero;query_index=($Number-200);disturb='primask'}}
    if($Number -ge 210 -and $Number -le 213){
        $fields=@('control','basepri','faultmask','psplim');$errors=@('l','b','f','L');$i=$Number-210
        return @{panic_code=[int][char]$errors[$i];panic_ipsr=11;expected_counts=$zero;query_index=7;disturb=$fields[$i]}
    }
    if($Number -ge 400){return @{panic_code=86;panic_ipsr=11;expected_counts=@{priority=0;initialize=1;allocate=1;load=1}}}
    $op=@('initialize','allocate','load')[$Number-300]
    return @{panic_code=$(if($Number -eq 301){68}else{81});panic_ipsr=11;bad_primitive=$op;
        expected_counts=@{priority=0;initialize=1;allocate=[int]($Number -ge 301);load=[int]($Number -ge 302)}}
}
function MutatedSecure([hashtable]$Model,[int]$Number,[hashtable]$Failure,[hashtable]$Mode){
    $dir=Join-Path $Model.Directory ('mutant-'+$Number)
    $null=New-Item -ItemType Directory -Path $dir
    $unit='gateway'
    if($Number -lt 300){
        $index=$Failure.query_index
        $function=$queries[$index]
        if($index -lt 4){$unit='identity'}
    }else{$function='fiber_secure_context_gateway_c55s_v1_'+$Failure.bad_primitive}
    $source=Join-Path $secure $(if($unit -eq 'identity'){'fiber_secure_gateway.c'}else{'fiber_secure_context_gateway.c'})
    $text=Get-Content -LiteralPath $source -Raw
    $pattern='(?ms)(uint32_t '+[regex]::Escape($function)+'\s*\([^)]*\)\s*\{)(.*?)(\r?\n\})'
    $found=[regex]::Matches($text,$pattern)
    Check "$($Mode.Name) $Number exact actual mutation function" ($found.Count -eq 1)
    $body=$found[0].Groups[2].Value
    $returns=[regex]::Matches($body,'return\s+([^;]+);')
    Check "$($Mode.Name) $Number actual return exists" ($returns.Count -gt 0)
    $last=$returns[$returns.Count-1]
    if($Number -ge 300){
        $replacement='const uint32_t test_real_result = '+$last.Groups[1].Value+'; (void)test_real_result; return 0u;'
    }else{
        $test='uint32_t test_origin; __asm volatile("mrs %0, ipsr" : "=r"(test_origin)); '+
            'if (test_origin == 11u) { '
        if($Number -lt 200){$test+='return 0u;'}
        else{
            $register=$Failure.disturb+'_ns'
            $mask=@{primask=1;control=2;basepri=128;faultmask=1;psplim=8}[$Failure.disturb]
            $test+='__asm volatile("mrs r3, '+$register+'\n\teor r3, r3, #'+$mask+'\n\tmsr '+$register+', r3" ::: "r3", "memory");'
        }
        $replacement=$test+' } '+$last.Value
    }
    $body=$body.Substring(0,$last.Index)+$replacement+$body.Substring($last.Index+$last.Length)
    $new=$found[0].Groups[1].Value+$body+$found[0].Groups[3].Value
    $path=Join-Path $dir 'actual-gateway-mutant.c'
    [IO.File]::WriteAllText($path,$text.Substring(0,$found[0].Index)+$new+$text.Substring($found[0].Index+$found[0].Length))
    $object=Compile 'mutated' $path ($Model.SFlags+$Model.Hostile) $dir
    $objects=@($Model.SObjects.identity,$Model.SObjects.gateway,$Model.SObjects.pool)|ForEach-Object {
        if($_ -eq $Model.SObjects[$unit]){$object}else{$_}}
    if($Mode.ContainsKey('Archive')){$objects=@(Archive 'mutated-secure-provider' $objects $dir)}
    $import=Join-Path $dir 'mutant-import.o'
    $flags=@($Model.SLink|Where-Object {$_ -notlike '-Wl,--cmse-implib,*'})+@("-Wl,--cmse-implib,--out-implib=$import")
    $s=LinkImage 'secure' $flags ($Model.SFixture+$objects) $dir
    $n=LinkImage 'nonsecure' $Model.NLink ($Model.NFixture+$Model.NList+@($import)) $dir
    return @{Secure=$s;Nonsecure=$n;Manifest=(FiberManifest $s $n)}
}
function ProviderNegatives([hashtable]$Model,[hashtable]$Mode){
    $dir=Join-Path $Model.Directory 'providers'
    $null=New-Item -ItemType Directory -Path $dir
    $missing=$queries+@('fiber_secure_context_gateway_c55s_v1_initialize',
        'fiber_secure_context_gateway_c55s_v1_allocate','fiber_secure_context_gateway_c55s_v1_load')
    RejectUndefined ($Mode.Name+'-missing-Secure-provider') $Model.NLink ($Model.NFixture+$Model.NList) $missing $dir
    $foreign=Join-Path $repo 'fiber\port\ARM_CM33\secure'
    $flags=@('-mcpu=cortex-m33')+@($base|Where-Object {$_ -notlike '-mcpu=*'})+$Mode.Flags+@('-std=c11','-mcmse',
        '-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV8M_MAINLINE=1',
        '-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3u','-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=128u',
        "-I$fixture/foreign_cm33","-I$foreign","-I$repo","-I$CmsisCore")
    $objects=@()
    foreach($name in @('fiber_secure_gateway.c','fiber_secure_context_gateway.c','fiber_secure_context_pool.c')){
        $objects+=Compile ('actual-cm33-'+$name) (Join-Path $foreign $name) $flags $dir
    }
    $actualNames=@($queries|ForEach-Object {$_.Replace('_c55s_v1_','_v1_')})+
        @('fiber_secure_context_gateway_v1_initialize','fiber_secure_context_gateway_v1_allocate',
          'fiber_secure_context_gateway_v1_load','fiber_secure_context_gateway_v1_save')
    $import=Join-Path $dir 'actual-cm33-import.o'
    $roots=@($actualNames|ForEach-Object {"-Wl,-u,$_"})
    $foreignImage=LinkImage 'actual-cm33-provider' ($flags+$link+$roots+@('-Wl,--entry=0','-T',(Join-Path $fixture 'foreign_cm33\import.ld'),
        '-T',(Join-Path $foreign 'fiber_secure_context_cohort_contract.ld'),
        '-Wl,--section-start=.gnu.sgstubs=0x10008000',"-Wl,--cmse-implib,--out-implib=$import")) $objects $dir
    $symbols=(Recorded $nm @('-g','--defined-only',$import) (Join-Path $dir 'foreign-import.nm')).Text
    Check "$($Mode.Name) actual CM33 import has no C55 namespace" ($symbols -notmatch '_c55s_')
    Check "$($Mode.Name) actual foreign provider carries C33S key" ($foreignImage.Symbols -match 'fiber_secure_context_cohort_c33s_g1_')
    RejectUndefined ($Mode.Name+'-foreign-C33S-provider') $Model.NLink ($Model.NFixture+$Model.NList+@($import)) $missing $dir
}
function CompiledControls([hashtable]$Model,[hashtable]$Mode){
    $controls=@(@{Name='omitted-GPR-restore';Unit='svc';Source=(Join-Path $ns 'fiber_port_svc.c');
            Pattern='ldmia r0!, \{r4-r11\}';Replacement='add r0, r0, #32';Oracle='first-restored-r4-r11'},
        @{Name='wrong-allocation-size';Unit='context';Source=(Join-Path $ns 'fiber_port_secure_context.c');
            Pattern='fiber_secure_context_gateway_c55s_v1_allocate\(requested, begin\)';
            Replacement='fiber_secure_context_gateway_c55s_v1_allocate(requested + 8u, begin)';Oracle='independent-allocation-arguments'},
        @{Name='wrong-allocation-owner';Unit='context';Source=(Join-Path $ns 'fiber_port_secure_context.c');
            Pattern='fiber_secure_context_gateway_c55s_v1_allocate\(requested, begin\)';
            Replacement='fiber_secure_context_gateway_c55s_v1_allocate(requested, begin + 4u)';Oracle='independent-allocation-arguments'})
    foreach($control in $controls){
        $dir=Join-Path $Model.Directory $control.Name
        $null=New-Item -ItemType Directory -Path $dir
        $text=Get-Content -LiteralPath $control.Source -Raw
        Check "$($Mode.Name) $($control.Name) exact source mutation" ([regex]::Matches($text,$control.Pattern).Count -eq 1)
        $source=Join-Path $dir 'actual-ns-mutant.c'
        [IO.File]::WriteAllText($source,[regex]::Replace($text,$control.Pattern,$control.Replacement))
        $object=Compile 'mutant' $source ($Model.NFlags+$Model.Hostile) $dir
        $objects=@($Model.NObjects.boot,$Model.NObjects.runtime,$Model.NObjects.context,$Model.NObjects.svc)|ForEach-Object {
            if($_ -eq $Model.NObjects[$control.Unit]){$object}else{$_}}
        if($Mode.ContainsKey('Archive')){$objects=@(Archive 'mutant-first-component' $objects $dir)}
        $n=LinkImage 'nonsecure' $Model.NLink ($Model.NFixture+$objects+@($Model.Import)) $dir
        $variant=@{Secure=$Model.Secure;Nonsecure=$n;Manifest=(FiberManifest $Model.Secure $n -GprMutationControl:($control.Unit -eq 'svc'))}
        RunCase ('control-'+$control.Name) 1 $variant @{} $dir $control.Oracle
    }
    if($Mode.ContainsKey('Hostile')){
        $text=Get-Content -LiteralPath (Join-Path $ns 'fiber_port_runtime.c') -Raw
        $pattern='static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY\r?\nvoid fiber_port_first_start_cpu_capture'
        Check "$($Mode.Name) annotation-removal exact helper" ([regex]::Matches($text,$pattern).Count -eq 1)
        $source=Join-Path $Model.Directory 'annotation-removal.c'
        [IO.File]::WriteAllText($source,[regex]::Replace($text,$pattern,"static FIBER_GENERAL_REGS_ONLY`nvoid fiber_port_first_start_cpu_capture"))
        $object=Compile 'annotation-removal' $source ($Model.NFlags+$Model.Hostile) $Model.Directory
        $deps=@(UndefinedSet $object (Join-Path $Model.Directory 'annotation-removal-undefined.log'))
        $symbols=(Recorded $nm @('-a',$object) (Join-Path $Model.Directory 'annotation-removal.nm'))
        Check "$($Mode.Name) compiled annotation removal escapes instrumentation" (($deps -match '__cyg_profile_func_enter').Count -gt 0 -and $symbols.Text -match '__gcov')
    }
}

try{
    $pin=Recorded 'git' @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.log')
    Check 'exact actual FreeRTOS pin' ($pin.Text.Trim() -eq 'a50edad08b29052631aa469d4df6e6ec7ff68878')
    $null=Recorded 'git' @('-C',$FreeRtosRoot,'diff','--exit-code','HEAD','--') (Join-Path $out 'reference-clean.log')
    $null=Recorded $ArmGcc @('--version') (Join-Path $out 'compiler-version.log')
    $wslFixture=WslPath $fixture
    $wslRsp=WslPath $rsp
    $null=Recorded $wsl @('-d',$WslDistro,'--exec','bash',(WslPath $inspect),'inspect',$QemuRoot,(WslPath $out)) (Join-Path $out 'qemu-inspect.log')
    Check 'existing QEMU AN547 model' ((Get-Content (Join-Path $out 'qemu-machines.txt') -Raw) -match '(?m)^mps3-an547\s')
    foreach($mode in $modes){
        $dir=Join-Path $out $mode.Name
        $null=New-Item -ItemType Directory -Path $dir
        if($mode.Name -in @('o2','os','o2-lto','os-lto')){
            $model=BuildReference $mode $dir
            RunCase 'reference-zero' 0 $model @{} $dir
            RunCase 'reference-later-allocate' 1 $model @{} $dir
        }
        if(!$DevelopmentReferenceOnly){
            $model=BuildFiber $mode $dir
            ProviderNegatives $model $mode
            foreach($number in $cases){
                $extra=Failure $number
                $variant=if($number -ge 100 -and $number -lt 400){MutatedSecure $model $number $extra $mode}else{$model}
                RunCase ('fiber-case-'+$number) $number $variant $extra $dir
            }
            CompiledControls $model $mode
        }
    }
    Check 'nonempty execution inventory' ($runs.Count -gt 0)
    $expectedReference=2*@($modes|Where-Object {$_.Name -in @('o2','os','o2-lto','os-lto')}).Count
    $expected=$expectedReference+$(if($DevelopmentReferenceOnly){0}else{$modes.Count*($cases.Count+3)})
    Check 'exact complete selected launch inventory' ($runs.Count -eq $expected)
    $verdict='PASS'
}finally{
    $after=@($inputPaths|ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256}|Select-Object Path,Hash)
    $after|ConvertTo-Json -Depth 4|Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $drift=@(Compare-Object $before $after -Property Path,Hash)
    if($drift.Count){$verdict='FAIL'}
    [pscustomobject]@{Verdict=$verdict;CompleteSuite=(!$DevelopmentModes -and !$PSBoundParameters.ContainsKey('DevelopmentCases') -and !$DevelopmentReferenceOnly);
        Modes=@($modes.Name);Launches=$runs.Count;Checks=$checks.Count;InputCount=$before.Count;InputDrift=$drift.Count;
        Runs=@($runs.ToArray());Assertions=@($checks.ToArray());Limits=@('staged first component only; no generic runtime or PendSV qualification',
            'actual reference skips saved r4-r11; Fiber deliberately restores them',
            'reference later SVC100 allocation differs from Fiber pre-start request in owned SVC70',
            'QEMU TCG AN547, not hardware')}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $out 'results.json') -Encoding ASCII
    $files=@(Get-ChildItem $out -Recurse -File|Where-Object {$_.Name -ne 'sha256.csv'})
    $files|ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256}|Select-Object Path,Hash|
        Export-Csv (Join-Path $out 'sha256.csv') -NoTypeInformation -Encoding ASCII
    if($drift.Count){throw "First-start inputs changed during run: $out"}
}
if($verdict -ne 'PASS'){throw "C55S first-start failed: $out"}
Write-Host "PASS C55S first start: $($runs.Count) launches; evidence $out"
