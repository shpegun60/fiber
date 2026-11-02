param(
    [string]$ArmGcc=$env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore=$env:CMSIS_CORE_INCLUDE,
    [string]$QemuRoot,
    [string]$WslDistro='Ubuntu-24.04',
    [string]$BuildRoot,
    [string]$FreeRtosRoot=$env:FREERTOS_KERNEL_REFERENCE,
    [ValidateRange(10,300)][int]$TimeoutSeconds=90
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture=Join-Path $PSScriptRoot 'fixtures\m55_secure_lifecycle'
$initFixture=Join-Path $PSScriptRoot 'fixtures\m55_secure_initialize'
$secure=Join-Path $repo 'fiber\port\ARM_CM55\secure'
$nonsecure=Join-Path $repo 'fiber\port\ARM_CM55\non_secure'
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply existing -ArmGcc' }
if (!$QemuRoot -or !$QemuRoot.StartsWith('/')) { throw 'Supply explicit existing absolute WSL -QemuRoot; no provisioning/skip' }
if (!$CmsisCore) { $CmsisCore=Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
if (!$FreeRtosRoot) { $FreeRtosRoot=Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel' }
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot=(Resolve-Path -LiteralPath $FreeRtosRoot).Path
$reference=Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM55\secure'
$bin=Split-Path $ArmGcc
$gxx=Join-Path $bin 'arm-none-eabi-g++.exe'
$nm=Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$objdump=Join-Path $bin 'arm-none-eabi-objdump.exe'
$wsl=(Get-Command wsl.exe -ErrorAction Stop).Source
$initializer=Join-Path $PSScriptRoot 'test_m55_secure_initialize.ps1'
$a26=Join-Path $PSScriptRoot 'test_cm33_secure_guards.ps1'
$inspect=Join-Path $PSScriptRoot 'fixtures\arm_control\qemu.sh'
foreach($dependency in @($gxx,$nm,$objdump,$initializer,$a26,$inspect,(Join-Path $fixture 'run.py'),
        (Join-Path $secure 'fiber_secure_context_gateway.c'),(Join-Path $reference 'secure_context.c'))) {
    if(!(Test-Path -LiteralPath $dependency -PathType Leaf)) { throw "Missing maintained dependency: $dependency" }
}
function ImportFunction([string]$Path,[string[]]$Names) {
    $tokens=$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if($errors.Count) { throw "Parser dependency failed: $Path" }
    foreach($name in $Names) {
        $defs=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object {$_.Name -eq $name})
        if($defs.Count -ne 1) { throw "Missing exact shared helper $name" }
        # Install at script scope; only definitions, never the runner body.
        $parameters=(@($defs[0].Parameters | ForEach-Object {$_.Extent.Text}) -join ',')
        $body='param('+$parameters+")`n"+$defs[0].Body.Extent.Text.Trim('{}')
        Set-Item -Path ('function:script:'+ $name) -Value ([scriptblock]::Create($body))
    }
}
ImportFunction $a26 @('Get-ExactDisassemblyFunction','Get-Instructions','Get-ExactSymbolAddress','Assert-EntryCallerProof')
ImportFunction $initializer @('Recorded','WslPath','Symbol','FunctionRange','AssertImports','AssertM55CallerProof')
. (Join-Path $initFixture 'hostile_codegen.ps1')
if(!$BuildRoot) { $BuildRoot=[IO.Path]::GetTempPath() }
$out=Join-Path $BuildRoot ('fiber-m55-secure-lifecycle-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out -Force
$out=(Resolve-Path -LiteralPath $out).Path
$commands=Join-Path $out 'commands.jsonl'
$verdict='FAIL'
$runs=New-Object System.Collections.Generic.List[object]
Write-Host "C55S lifecycle evidence: $out"
$identity=@('fiber_secure_gateway_c55s_v1_abi_version','fiber_secure_gateway_c55s_v1_context_port_id',
    'fiber_secure_gateway_c55s_v1_context_layout_version','fiber_secure_gateway_c55s_v1_context_feature_mask')
$capacity=@('fiber_secure_context_gateway_c55s_v1_abi_version','fiber_secure_context_gateway_c55s_v1_stack_alignment',
    'fiber_secure_context_gateway_c55s_v1_max_stack_bytes','fiber_secure_context_gateway_c55s_v1_max_contexts')
$prefix='fiber_secure_context_gateway_c55s_v1_'
$old9=$identity+$capacity+@($prefix+'initialize')
$new3=@('allocate','load','save' | ForEach-Object {$prefix+$_})
$expected12=$old9+$new3
$inputPaths=@($PSCommandPath,$ArmGcc,$gxx,$nm,$objdump,$initializer,$a26,$inspect,
    (Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards\aircr_rsp.py'),
    (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h'),(Join-Path $repo 'fiber\fiber_api_attributes.h'),
    (Join-Path $nonsecure 'fiber_port_secure_context_gateway_abi.h'))+
    @(Get-ChildItem $fixture,$initFixture,$secure,$reference -File -Recurse | Where-Object {$_.Extension -ne '.pyc'} | Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $CmsisCore -Filter '*.h' -File | Select-Object -ExpandProperty FullName)
$hashesBefore=@($inputPaths | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
$hashesBefore | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII

function MutatedGateway([string]$Source,[hashtable]$Case,[string]$Path) {
    $name=$prefix+$Case.Operation
    $start=$Source.IndexOf('uint32_t '+$name+'(')
    if($start -lt 0) { throw "Mutation function missing $name" }
    $end=$Source.IndexOf("`nuint32_t ",$start+1)
    if($end -lt 0) { $end=$Source.Length }
    $body=$Source.Substring($start,$end-$start)
    $pattern=$Case.Pattern
    if([regex]::Matches($body,$pattern).Count -ne 1) { throw "Mutation must have one exact site: $($Case.Name)" }
    $changed=[regex]::Replace($body,$pattern,$Case.Replace)
    ($Source.Substring(0,$start)+$changed+$Source.Substring($end)) | Set-Content -LiteralPath $Path -Encoding ASCII
}
function AssertLifecycleCallerProof([string]$Disassembly,[string]$Name,[string]$Receipt) {
    $body=Get-ExactDisassemblyFunction $Disassembly ('__acle_se_'+$Name)
    foreach($instruction in @(Get-Instructions $body)) {
        if($instruction.Opcode -in @('stmdb','stmdb.w') -and
                $instruction.Operands -match '^sp!, \{(?:r\d+, )*lr\}$') {
            # Exact flag/LR-preserving PUSH alias; keep original bytes in evidence.
            Add-Content -LiteralPath $Receipt -Encoding ASCII -Value ('Qualified STMDB SP! alias: '+$instruction.Text)
            $alias=$instruction.Text -replace '\bstmdb(?:\.w)?\s+sp!,\s*',"push.w`t"
            $Disassembly=$Disassembly.Replace($instruction.Text,$alias)
        }
    }
    AssertM55CallerProof $Disassembly $Name $Receipt
}

try {
    $pin=(Recorded 'git' @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.txt')).Text.Trim()
    if($pin -ne 'a50edad08b29052631aa469d4df6e6ec7ff68878') { throw 'Pinned FreeRTOS revision mismatch' }
    $null=Recorded 'git' @('-C',$FreeRtosRoot,'diff','--exit-code','HEAD','--') (Join-Path $out 'reference-clean.txt')
    $referenceStatus=Recorded 'git' @('-C',$FreeRtosRoot,'status','--porcelain=v1','--untracked-files=all') (Join-Path $out 'reference-status.txt')
    if($referenceStatus.Text.Trim()) { throw 'Reference has modified or untracked files' }
    $null=Recorded $ArmGcc @('--version') (Join-Path $out 'compiler-version.txt')
    $wslFixture=WslPath $fixture
    $wslOut=WslPath $out
    $null=Recorded $wsl @('-d',$WslDistro,'--exec','bash',(WslPath $inspect),'inspect',$QemuRoot,$wslOut) (Join-Path $out 'inspect.log')
    if((Get-Content (Join-Path $out 'qemu-machines.txt') -Raw) -notmatch '(?m)^mps3-an547\s') { throw 'Installed QEMU lacks actual M55 machine' }
    $null=Recorded $wsl @('-d',$WslDistro,'--exec','python3','-B',"$wslFixture/scenario.py","$wslOut/scenario.h","$wslOut/scenario.json") (Join-Path $out 'scenario-generation.log')
    $base=@('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-mgeneral-regs-only','-ffreestanding','-fno-builtin',
        '-fno-common','-fstrict-aliasing','-Wstrict-aliasing=3','-ffunction-sections','-fdata-sections',
        '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-instrument-functions','-fno-stack-protector',
        '-fno-profile-arcs','-fno-test-coverage','-fno-sanitize=all','-fno-profile','-fno-stack-check',
        '-fno-sanitize-coverage=trace-pc','-Wall','-Wextra','-Werror','-Wundef','-g3')
    $modes=@(@{Name='o2';Flags=@('-O2')},@{Name='os';Flags=@('-Os')},
        @{Name='o2-lto';Flags=@('-O2','-flto')},@{Name='os-lto';Flags=@('-Os','-flto')})
    $gatewayPath=Join-Path $secure 'fiber_secure_context_gateway.c'
    $gatewayText=Get-Content -LiteralPath $gatewayPath -Raw
    foreach($name in $new3) { if($gatewayText -notmatch ([regex]::Escape($name)+'\(')) { throw "Production not ready: $name" } }
    foreach($mode in $modes) {
        $dir=Join-Path $out $mode.Name
        $null=New-Item -ItemType Directory -Path $dir
        $flags=$base+$mode.Flags
        $sflags=$flags+@('-std=c11','-mcmse','-DLIFE_SECURE=1','-DFIBER_PORT_BUILD_SELECTED=1',
            '-DFIBER_PORT_ARMV81M_MAINLINE=1','-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3',
            '-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=128',"-I$fixture","-I$secure","-I$repo","-I$CmsisCore")
        $nflags=$flags+@('-std=c11',"-I$out","-I$fixture","-I$nonsecure","-I$CmsisCore")
        $storeObject=Join-Path $dir 'store-controls.o'
        $null=Recorded $ArmGcc ($flags+@('-c',(Join-Path $fixture 'store_controls.S'),'-o',$storeObject)) (Join-Path $dir 'store-controls.log')
        $null=Recorded $objdump @('-drwC',$storeObject) (Join-Path $dir 'store-controls-m55.dis')
        # Only this never-executed classifier counterexample uses a generic
        # Thumb decoder: M55's decoder correctly marks the STC word undefined.
        $storeDis=(Recorded $objdump @('-drwC','-m','arm','-M','force-thumb',$storeObject) (Join-Path $dir 'store-controls.dis')).Text
        $storeCases=foreach($opcode in @('stl','stlex','stc')) {
            $instructions=@(Get-Instructions (Get-ExactDisassemblyFunction $storeDis ('lifecycle_unknown_'+$opcode)))
            if(!$instructions.Count) {throw "Missing compiled store control: $opcode"}
            @{name=$opcode;instruction=$instructions[0]}
        }
        $storeManifest=Join-Path $dir 'store-controls.json'
        $storeCases | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $storeManifest -Encoding ASCII
        $null=Recorded $wsl @('-d',$WslDistro,'--exec','python3','-B',"$wslFixture/classify_stores.py",(WslPath $storeManifest),
            (WslPath (Join-Path $dir 'store-control-receipt.json'))) (Join-Path $dir 'store-classifier.log')
        $link=@('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none')
        $slink=$link+@('-Wl,--section-start=.gnu.sgstubs=0x10008000')
        $objects=@()
        foreach($unit in @(@{Name='identity';Path=(Join-Path $secure 'fiber_secure_gateway.c')},
                @{Name='pool';Path=(Join-Path $secure 'fiber_secure_context_pool.c')},
                @{Name='fixture';Path=(Join-Path $fixture 'secure.c')},@{Name='startup';Path=(Join-Path $fixture 'startup.S')})) {
            $object=Join-Path $dir ($unit.Name+'.o')
            $null=Recorded $ArmGcc ($sflags+@('-save-temps=obj','-MMD','-c',$unit.Path,'-o',$object)) (Join-Path $dir ($unit.Name+'-compile.log'))
            $objects+=$object
        }
        $rflags=$flags+@('-std=c11','-mcmse',"-I$(Join-Path $initFixture 'reference')","-I$reference")
        $refObjects=@()
        foreach($unit in @('secure_init.c','secure_context.c','secure_context_port.c')) {
            $object=Join-Path $dir ('reference-'+$unit+'.o')
            $null=Recorded $ArmGcc ($rflags+@('-Wno-unused-parameter','-save-temps=obj','-c',(Join-Path $reference $unit),'-o',$object)) (Join-Path $dir ($unit+'-compile.log'))
            $refObjects+=$object
        }
        $heap=Join-Path $dir 'reference-heap.o'
        $null=Recorded $ArmGcc ($rflags+@('-c',(Join-Path $initFixture 'reference\link_only_heap.c'),'-o',$heap)) (Join-Path $dir 'reference-heap.log')
        $refElf=Join-Path $dir 'reference.elf'
        $null=Recorded $ArmGcc ($rflags+$slink+@('-Wl,--entry=0','-Wl,-u,SecureContext_Init',
            '-T',(Join-Path $initFixture 'import.ld'),"-Wl,-Map,$dir/reference.map")+$refObjects+@($heap,'-o',$refElf)) (Join-Path $dir 'reference-link.log')
        $refDis=(Recorded $objdump @('-drwC',$refElf) (Join-Path $dir 'reference.dis')).Text
        @('Actual pinned SecureContext_LoadContextAsm:',(Get-ExactDisassemblyFunction $refDis 'SecureContext_LoadContextAsm'),
            'Actual pinned SecureContext_SaveContextAsm:',(Get-ExactDisassemblyFunction $refDis 'SecureContext_SaveContextAsm'),
            'Fiber retains scalar limit-before-pointer load; save publishes PSP before clearing limit then pointer.',
            'Differences: immediate NS origin/exact exception/READY/CONTROL2 admission; static owned pool and seals;',
            'explicit barriers, actual register readbacks, repeated owned lookup and exact volatile saved-PSP readback.',
            'No FP stacking trigger/CONTROL slot, no NS runtime provider or Secure Thread execution qualification.') |
            Set-Content (Join-Path $dir 'reference-transfer-comparison.txt') -Encoding ASCII
        $savedFixture=$fixture
        try { $fixture=$initFixture;TestC55SHostile -Flags $sflags -Directory (Join-Path $dir 'hostile') -ReferenceDisassembly $refDis -Exports $expected12 }
        finally { $fixture=$savedFixture }
        $oldObject=Join-Path $dir 'old9.o'
        $oldImport=Join-Path $dir 'old9-import.o'
        $null=Recorded $ArmGcc ($sflags+@('-c',(Join-Path $fixture 'old9.c'),'-o',$oldObject)) (Join-Path $dir 'old9-compile.log')
        $roots=@($old9 | ForEach-Object {"-Wl,-u,$_"})
        $null=Recorded $ArmGcc ($sflags+$slink+$roots+@('-Wl,--entry=0','-T',(Join-Path $initFixture 'import.ld'),
            "-Wl,--cmse-implib,--out-implib=$oldImport",$oldObject,'-o',(Join-Path $dir 'old9.elf'))) (Join-Path $dir 'old9-link.log')
        AssertImports $oldImport $old9 (Join-Path $dir 'old9.nm')
        $nsObject=Join-Path $dir 'nonsecure.o'
        $nsStartup=Join-Path $dir 'ns-startup.o'
        $null=Recorded $ArmGcc ($nflags+@('-c',(Join-Path $fixture 'startup.S'),'-o',$nsStartup)) (Join-Path $dir 'ns-startup.log')
        $null=Recorded $ArmGcc ($nflags+@('-save-temps=obj','-MMD','-c',(Join-Path $fixture 'nonsecure.c'),'-o',$nsObject)) (Join-Path $dir 'nonsecure.log')
        $cases=@(@{Name='success';kind='success'})
        foreach($op in @('load','save')) {
            foreach($r in @(@{Name='limit';Register='psplim';Read=2},@{Name='pointer';Register='psp';Read=2},@{Name='final-limit';Register='psplim';Read=3})) {
                $cases+=@{Name="$op-$($r.Name)-readback";kind='readback';target=if($op -eq 'load') {'load-a-first'} else {'save-a-first'};register=$r.Register;read=$r.Read}
            }
        }
        $cases+=@{Name='save-publish-readback';kind='readback';target='save-a-first';register='published'}
        $cases+=@{Name='terminal-thread-resume';kind='readback';target='save-a-first';register='published';
            ThreadResume=$true;kill='terminal-thread-resume';kill_step='save-a-first';kill_op=3;kill_direct=$false}
        foreach($r in @(@{Name='record-pointer';Offset=0},@{Name='record-limit';Offset=4},@{Name='record-top';Offset=8},
                @{Name='record-owner';Offset=12},@{Name='record-size';Offset=16},@{Name='record-state';Offset=20})) {
            $corruption=@{Name=$r.Name;kind='corruption';target='load-a-first';offset=$r.Offset}
            if($r.Name -eq 'record-owner') { $corruption.value=0 }
            $cases+=$corruption
        }
        foreach($offset in @(0,4)) { $cases+=@{Name="seal-$offset";kind='corruption';target='load-a-first';seal=$true;offset=$offset} }
        $cases+=@{Name='save-seal';kind='corruption';target='save-a-first';seal=$true;offset=0}
        $cases+=@{Name='dirty-free-record';kind='corruption';target='allocate-a';offset=64;value=8}
        $cases+=@{Name='duplicate-stored-owner';kind='corruption';target='allocate-c';offset=36;value=0xA101}
        . (Join-Path $fixture 'mutants.ps1')
        $cases+=GetLifecycleMutants
        foreach($case in $cases) {
            $caseDir=Join-Path $dir $case.Name
            $null=New-Item -ItemType Directory -Path $caseDir
            if($case.Name -eq 'success' -or $case.ContainsKey('Operation') -or $case.ContainsKey('ThreadResume')) {
                $source=$gatewayPath
                if($case.ContainsKey('Operation')) { $source=Join-Path $caseDir 'gateway-mutant.c';MutatedGateway $gatewayText $case $source }
                $gateway=Join-Path $caseDir 'gateway.o'
                $null=Recorded $ArmGcc ($sflags+@('-save-temps=obj','-MMD','-c',$source,'-o',$gateway)) (Join-Path $caseDir 'gateway.log')
                $sElf=Join-Path $caseDir 'secure.elf'
                $import=Join-Path $caseDir 'secure-import.o'
                $helpers=@('lifecycle_set_stacks','lifecycle_set_masks','lifecycle_set_control','lifecycle_direct_probe','lifecycle_direct_done') | ForEach-Object {"-Wl,-u,$_"}
                $null=Recorded $ArmGcc ($sflags+$slink+$helpers+@('-T',(Join-Path $initFixture 'secure.ld'),"-Wl,-Map,$caseDir/secure.map",
                    "-Wl,--cmse-implib,--out-implib=$import")+$objects+@($gateway,'-o',$sElf)) (Join-Path $caseDir 'secure-link.log')
                AssertImports $import $expected12 (Join-Path $caseDir 'secure-import.nm')
                $sDis=(Recorded $objdump @('-drwC',$sElf) (Join-Path $caseDir 'secure.dis')).Text
                $sNm=(Recorded $nm @('-a','-S','-n',$sElf) (Join-Path $caseDir 'secure.nm')).Text
                $nElf=Join-Path $caseDir 'nonsecure.elf'
                $caseNsObject=$nsObject
                if($case.ContainsKey('ThreadResume')) {
                    $caseNsObject=Join-Path $caseDir 'nonsecure-thread-resume.o'
                    $null=Recorded $ArmGcc ($nflags+@('-DLIFE_COUNTERFEIT_THREAD_RESUME=1','-save-temps=obj','-MMD',
                        '-c',(Join-Path $fixture 'nonsecure.c'),'-o',$caseNsObject)) (Join-Path $caseDir 'thread-resume-compile.log')
                }
                $null=Recorded $ArmGcc ($nflags+$link+@('-Wl,-u,lifecycle_terminal_stop','-T',(Join-Path $initFixture 'nonsecure.ld'),"-Wl,-Map,$caseDir/nonsecure.map",
                    $nsStartup,$caseNsObject,$import,'-o',$nElf)) (Join-Path $caseDir 'nonsecure-link.log')
                $nNm=(Recorded $nm @('-a','-S','-n',$nElf) (Join-Path $caseDir 'nonsecure.nm')).Text
                $null=Recorded $objdump @('-drwC',$nElf) (Join-Path $caseDir 'nonsecure.dis')
                $functions=@{}
                $operation=1
                foreach($name in $new3) {
                    $instructions=@(Get-Instructions (Get-ExactDisassemblyFunction $sDis ('__acle_se_'+$name)))
                    for($i=0;$i -lt $instructions.Count;++$i) {
                        $next=if($i+1 -lt $instructions.Count) {[Convert]::ToUInt32($instructions[$i+1].Address,16)} else {0}
                        $instructions[$i] | Add-Member -NotePropertyName Next -NotePropertyValue $next
                    }
                    $functions["$operation"]=@{entry=(Get-ExactSymbolAddress $sNm ('__acle_se_'+$name));instructions=$instructions}
                    if(!$case.ContainsKey('Operation')) { AssertLifecycleCallerProof $sDis $name (Join-Path $caseDir 'caller-proof.txt') }
                    ++$operation
                }
                $sites=@{}
                foreach($pair in @(@('index','lifecycle_index'),@('result','lifecycle_result'),@('terminal','lifecycle_terminal'),
                        @('checkpoint','lifecycle_ns_checkpoint'),@('thread_checkpoint','lifecycle_thread_checkpoint'),@('terminal_stop','lifecycle_terminal_stop'))) {
                    $sites[$pair[0]]=Get-ExactSymbolAddress $nNm $pair[1]
                }
                foreach($pair in @(@('pool','__pool_start'),@('gate','fiber_secure_context_gateway_state'),@('set_stacks','lifecycle_set_stacks'),
                        @('set_masks','lifecycle_set_masks'),@('direct_probe','lifecycle_direct_probe'),@('direct_done','lifecycle_direct_done'),
                        @('fault_handler','lifecycle_fault_handler'),@('backend_allocate','fiber_secure_context_pool_allocate'),@('backend_lookup','fiber_secure_context_pool_lookup_owned'))) {
                    $sites[$pair[0]]=Get-ExactSymbolAddress $sNm $pair[1]
                }
                $traps=@{gateway=(FunctionRange $sNm $sDis 'fiber_secure_context_gateway_fail_closed');pool=(FunctionRange $sNm $sDis 'fiber_secure_context_pool_fail_closed')}
                if($case.Name -eq 'success') {
                    foreach($language in @('c','c++')) {
                        $compiler=if($language -eq 'c') {$ArmGcc} else {$gxx}
                        $cflags=@($nflags | Where-Object {$_ -ne '-std=c11'})
                        $consumer=$nsObject
                        if($language -eq 'c++') {
                            $consumer=Join-Path $caseDir 'consumer-cpp.o'
                            $null=Recorded $compiler ($cflags+@('-x','c++','-std=c++17','-fno-exceptions','-fno-rtti','-c',(Join-Path $fixture 'nonsecure.c'),'-o',$consumer)) (Join-Path $caseDir 'cpp-compile.log')
                        }
                        $bad=Recorded $compiler ($cflags+$link+@('-T',(Join-Path $initFixture 'nonsecure.ld'),$nsStartup,$consumer,$oldImport,
                            '-o',(Join-Path $caseDir ("stale9-$language.elf")))) (Join-Path $caseDir ("stale9-$language.log")) -AllowFailure
                        $missing=@([regex]::Matches($bad.Text,"undefined reference to [``']([^']+)'") | ForEach-Object {$_.Groups[1].Value} | Sort-Object -Unique)
                        if($bad.ExitCode -eq 0 -or (Compare-Object @($new3 | Sort-Object) $missing)) { throw 'Stale nine provider must fail solely on the new three symbols' }
                        if($language -eq 'c++') {
                            $null=Recorded $compiler ($cflags+$link+@('-T',(Join-Path $initFixture 'nonsecure.ld'),$nsStartup,$consumer,$import,
                                '-o',(Join-Path $caseDir 'matching-cpp.elf'))) (Join-Path $caseDir 'matching-cpp.log')
                        }
                    }
                    $normal=@{Secure=$sElf;Nonsecure=$nElf;Functions=$functions;Sites=$sites;Traps=$traps}
                }
            } else { $sElf=$normal.Secure;$nElf=$normal.Nonsecure;$functions=$normal.Functions;$sites=$normal.Sites;$traps=$normal.Traps }
            $manifest=Join-Path $caseDir 'manifest.json'
            @{case=$case;scenario="$wslOut/scenario.json";scenario_sha256=(Get-FileHash (Join-Path $out 'scenario.json') -Algorithm SHA256).Hash;
                functions=$functions;sites=$sites;traps=$traps;
                secure_sha256=(Get-FileHash $sElf -Algorithm SHA256).Hash;nonsecure_sha256=(Get-FileHash $nElf -Algorithm SHA256).Hash} |
                ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifest -Encoding ASCII
            $null=Recorded $wsl @('-d',$WslDistro,'--exec','bash',"$wslFixture/qemu.sh",$QemuRoot,(WslPath $sElf),(WslPath $nElf),
                "$TimeoutSeconds",(WslPath $manifest)) (Join-Path $caseDir 'runner.log')
            $receipt=Get-Content (Join-Path $caseDir 'execution-receipt.json') -Raw | ConvertFrom-Json
            if($receipt.result -ne 'PASS') { throw "Non-PASS receipt: $caseDir" }
            $runs.Add([pscustomobject]@{Mode=$mode.Name;Case=$case.Name;Directory=$caseDir;Receipt=$receipt})
            $runs.ToArray() | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $out 'receipts.json') -Encoding ASCII
            Write-Host "PASS lifecycle $($mode.Name)/$($case.Name): $($receipt.classification)"
        }
    }
    $hashesAfter=@($inputPaths | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
    $hashesAfter | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    if(Compare-Object $hashesBefore $hashesAfter -Property Path,Hash) { throw 'Qualification inputs changed; rerun required' }
    $verdict='PASS'
} finally {
    @{Verdict=$verdict;Machine='mps3-an547';QemuRoot=$QemuRoot;WslDistro=$WslDistro;PhysicalNoFPProof=$false;
        NonsecureRuntimeProvider=$false;Runs=$runs.ToArray()} | ConvertTo-Json -Depth 14 | Set-Content (Join-Path $out 'results.json') -Encoding ASCII
    Get-ChildItem -LiteralPath $out -Recurse -File | Where-Object {$_.Name -ne 'sha256.csv'} | Get-FileHash -Algorithm SHA256 |
        Select-Object Path,Hash | Export-Csv (Join-Path $out 'sha256.csv') -NoTypeInformation -Encoding ASCII
}
Write-Host "PASS C55S lifecycle; evidence: $out"
