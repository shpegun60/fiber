param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$QemuRoot,
    [string]$WslDistro = 'Ubuntu-24.04',
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [ValidateRange(2,120)][int]$TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture = Join-Path $PSScriptRoot 'fixtures\m55_secure_initialize'
$secure = Join-Path $repo 'fiber\port\ARM_CM55\secure'
$nonsecure = Join-Path $repo 'fiber\port\ARM_CM55\non_secure'
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply an existing -ArmGcc' }
if (!$QemuRoot -or !$QemuRoot.StartsWith('/')) { throw 'Explicit existing absolute WSL -QemuRoot required; no provisioning or silent skip' }
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
if (!$FreeRtosRoot) { $FreeRtosRoot = Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
$reference = Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM55\secure'
$bin = Split-Path $ArmGcc
$gxx = Join-Path $bin 'arm-none-eabi-g++.exe'
$nm = Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$objdump = Join-Path $bin 'arm-none-eabi-objdump.exe'
$wsl = (Get-Command wsl.exe -ErrorAction Stop).Source
$a26 = Join-Path $PSScriptRoot 'test_cm33_secure_guards.ps1'
$a26Rsp = Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards\aircr_rsp.py'
$inspect = Join-Path $PSScriptRoot 'fixtures\arm_control\qemu.sh'
foreach ($path in @($gxx,$nm,$objdump,$a26,$a26Rsp,$inspect,
        (Join-Path $CmsisCore 'core_cm55.h'), (Join-Path $secure 'fiber_secure_context_gateway.c'),
        (Join-Path $reference 'secure_init.c'), (Join-Path $reference 'secure_context.c'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing maintained dependency: $path" }
}

# Reuse the maintained A26 generated-instruction/caller parser without running
# or editing its old runner. Only these four function definitions are loaded.
$tokens = $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($a26,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'A26 parser source has syntax errors' }
foreach ($name in @('Get-ExactDisassemblyFunction','Get-Instructions','Get-ExactSymbolAddress','Assert-EntryCallerProof')) {
    $definitions = @($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true) |
        Where-Object { $_.Name -eq $name })
    if ($definitions.Count -ne 1) { throw "Missing unique A26 parser function $name" }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ('fiber-m55-secure-initialize-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out -Force
$out = (Resolve-Path -LiteralPath $out).Path
$commands = Join-Path $out 'commands.jsonl'
$runs = New-Object System.Collections.Generic.List[object]
$verdict = 'FAIL'
Write-Host "C55S initializer evidence: $out"

function Recorded([string]$Program,[string[]]$Arguments,[string]$Log,[switch]$AllowFailure) {
    [pscustomobject]@{Program=$Program; Arguments=$Arguments; Log=$Log} |
        ConvertTo-Json -Depth 5 -Compress | Add-Content -LiteralPath $commands -Encoding ASCII
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $Program @Arguments 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    [IO.File]::WriteAllLines($Log,[string[]]$lines)
    if ($code -ne 0 -and !$AllowFailure) { throw "Command failed ($code): $Log`n$($lines -join "`n")" }
    return [pscustomobject]@{ExitCode=$code; Text=($lines -join "`n")}
}
function WslPath([string]$Path) {
    $r = Recorded $wsl @('-d',$WslDistro,'--exec','wslpath','-u',$Path) (Join-Path $out ('wslpath-'+[guid]::NewGuid().ToString('N')+'.txt'))
    return $r.Text.Trim()
}
function Symbol([string]$Text,[string]$Name) {
    $m = [regex]::Matches($Text,'(?m)^([0-9a-f]+) ([0-9a-f]+) ([a-zA-Z]) '+[regex]::Escape($Name)+'\r?$')
    if ($m.Count -ne 1) { throw "Missing unique sized ELF symbol: $Name" }
    return [pscustomobject]@{Address=[Convert]::ToUInt32($m[0].Groups[1].Value,16);
        Size=[Convert]::ToUInt32($m[0].Groups[2].Value,16); Type=$m[0].Groups[3].Value}
}
function FunctionRange([string]$Symbols,[string]$Disassembly,[string]$Name,[switch]$Optional) {
    if ($Optional -and $Symbols -notmatch ('(?m) '+[regex]::Escape($Name)+'\r?$')) { return @{start=0;end=0;udf=@()} }
    $s = Symbol $Symbols $Name
    $body = Get-ExactDisassemblyFunction $Disassembly $Name
    $udf = @(Get-Instructions $body | Where-Object {$_.Opcode -match '^udf'} |
        ForEach-Object {[Convert]::ToUInt32($_.Address,16)})
    if (!$udf.Count) { throw "No exact UDF in $Name" }
    return @{start=$s.Address; end=($s.Address+$s.Size); udf=$udf}
}
function AssertImports([string]$Path,[string[]]$Expected,[string]$Log) {
    $r = Recorded $nm @('-g','--defined-only',$Path) $Log
    $actual = @($r.Text -split "`n" | ForEach-Object {
        if ($_ -match '^\s*[0-9a-f]+\s+[A-Za-z]\s+(\S+)\s*$') { $Matches[1] }
    } | Sort-Object -Unique)
    if (Compare-Object @($Expected | Sort-Object) $actual) { throw "Non-exact CMSE import surface: $($actual -join ', ')" }
    foreach ($line in ($r.Text -split "`n")) {
        if ($line -match '^\s*([0-9a-f]+)\s+[A-Za-z]\s+(fiber_\S+)\s*$') {
            $address=[Convert]::ToUInt32($Matches[1],16)
            if ($address -lt 0x10008000 -or $address -ge 0x10009000) { throw 'Import escaped exact NSC range' }
        }
    }
}
function AssertM55CallerProof([string]$Disassembly,[string]$Name,[string]$Receipt) {
    $body=Get-ExactDisassemblyFunction $Disassembly ('__acle_se_'+$Name)
    $first=@(Get-Instructions $body)[0]
    if ($first.Opcode -eq 'vstr' -and $first.Operands -eq 'FPCXTNS, [sp, #-4]!') {
        # M55 -Os puts this LR/flags-preserving CMSE stack save before TST.
        # Qualify that one exact prefix, then reuse A26's unchanged LR parser.
        Add-Content -LiteralPath $Receipt -Encoding ASCII -Value ("Qualified M55 prefix: "+$first.Text)
        $Disassembly=$Disassembly.Replace($first.Text,'')
    }
    Assert-EntryCallerProof $Disassembly $Name $Receipt
}

$identity = @('fiber_secure_gateway_c55s_v1_abi_version','fiber_secure_gateway_c55s_v1_context_port_id',
    'fiber_secure_gateway_c55s_v1_context_layout_version','fiber_secure_gateway_c55s_v1_context_feature_mask')
$capacity = @('fiber_secure_context_gateway_c55s_v1_abi_version','fiber_secure_context_gateway_c55s_v1_stack_alignment',
    'fiber_secure_context_gateway_c55s_v1_max_stack_bytes','fiber_secure_context_gateway_c55s_v1_max_contexts')
$entryName = 'fiber_secure_context_gateway_c55s_v1_initialize'
$old8 = $identity + $capacity
$expected12 = $old8 + @($entryName) + @('fiber_secure_context_gateway_c55s_v1_allocate',
    'fiber_secure_context_gateway_c55s_v1_load','fiber_secure_context_gateway_c55s_v1_save')
$inputPaths = @($PSCommandPath,$ArmGcc,$a26,$a26Rsp,$inspect,
    (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h'),
    (Join-Path $repo 'fiber\fiber_api_attributes.h'),
    (Join-Path $CmsisCore 'core_cm55.h'),(Join-Path $CmsisCore 'cmsis_gcc.h'),
    (Join-Path $nonsecure 'fiber_port_secure_context_gateway_abi.h')) +
    @(Get-ChildItem -LiteralPath $secure -File | Where-Object {$_.Extension -in @('.h','.c')} | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath $reference -File | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath $fixture -File -Recurse | Where-Object {$_.Extension -ne '.pyc'} | Select-Object -ExpandProperty FullName)
$hashesBefore = @($inputPaths | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
$hashesBefore | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII

try {
    $pin = Recorded 'git' @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.txt')
    if ($pin.Text.Trim() -ne 'a50edad08b29052631aa469d4df6e6ec7ff68878') { throw 'Reference pin mismatch' }
    $null = Recorded 'git' @('-C',$FreeRtosRoot,'diff','--exit-code','HEAD','--') (Join-Path $out 'reference-status.txt')
    $null = Recorded $ArmGcc @('--version') (Join-Path $out 'compiler-version.txt')
    $wslOut = WslPath $out
    $null = Recorded $wsl @('-d',$WslDistro,'--exec','bash',(WslPath $inspect),'inspect',$QemuRoot,$wslOut) (Join-Path $out 'inspect.log')
    if ((Get-Content (Join-Path $out 'qemu-machines.txt') -Raw) -notmatch '(?m)^mps3-an547\s') { throw 'Existing QEMU lacks M55 mps3-an547' }
    $base = @('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-mgeneral-regs-only',
        '-ffreestanding','-fno-builtin','-fno-common','-fstrict-aliasing','-Wstrict-aliasing=3',
        '-ffunction-sections','-fdata-sections','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
        '-fno-instrument-functions','-fno-stack-protector','-fno-profile-arcs','-fno-test-coverage',
        '-fno-sanitize=all','-fno-profile','-fno-stack-check','-fno-sanitize-coverage=trace-pc',
        '-Wall','-Wextra','-Werror','-Wundef','-g3')
    $selected = @('-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV81M_MAINLINE=1')
    $modes = @(@{Name='o2';Flags=@('-O2')},@{Name='os';Flags=@('-Os')},
        @{Name='o2-lto';Flags=@('-O2','-flto')},@{Name='os-lto';Flags=@('-Os','-flto')})
    $gatewayPath = Join-Path $secure 'fiber_secure_context_gateway.c'
    $gatewayText = Get-Content -LiteralPath $gatewayPath -Raw
    if ($gatewayText -notmatch ('uint32_t '+$entryName+'\(void\)')) { throw 'Production initializer not present yet' }
    foreach ($mode in $modes) {
        $dir=Join-Path $out $mode.Name
        $null=New-Item -ItemType Directory -Path $dir
        $flags=$base+$mode.Flags
        $sflags=$flags+@('-std=c11','-mcmse','-DINIT_SECURE=1',
            '-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3','-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=128',
            "-I$fixture","-I$secure","-I$repo","-I$CmsisCore")+$selected
        $nflags=$flags+@('-std=c11',"-I$fixture","-I$nonsecure","-I$CmsisCore")
        $link=@('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none')
        $slink=$link+@('-Wl,--section-start=.gnu.sgstubs=0x10008000')
        $objects=@()
        foreach ($unit in @(@{Name='identity';Path=(Join-Path $secure 'fiber_secure_gateway.c')},
                @{Name='pool';Path=(Join-Path $secure 'fiber_secure_context_pool.c')},
                @{Name='fixture';Path=(Join-Path $fixture 'secure.c')},
                @{Name='startup';Path=(Join-Path $fixture 'startup.S')})) {
            $object=Join-Path $dir ($unit.Name+'.o')
            $null=Recorded $ArmGcc ($sflags+@('-save-temps=obj','-MMD','-c',$unit.Path,'-o',$object)) (Join-Path $dir ($unit.Name+'-compile.log'))
            $objects+=$object
        }
        $oldObject=Join-Path $dir 'old8.o'
        $oldImport=Join-Path $dir 'old8-import.o'
        $null=Recorded $ArmGcc ($sflags+@('-c',(Join-Path $fixture 'old8.c'),'-o',$oldObject)) (Join-Path $dir 'old8-compile.log')
        $roots=@($old8 | ForEach-Object {"-Wl,-u,$_"})
        $null=Recorded $ArmGcc ($sflags+$slink+$roots+@('-Wl,--entry=0','-T',(Join-Path $fixture 'import.ld'),
            "-Wl,--cmse-implib,--out-implib=$oldImport",$oldObject,'-o',(Join-Path $dir 'old8.elf'))) (Join-Path $dir 'old8-link.log')
        AssertImports $oldImport $old8 (Join-Path $dir 'old8-import.nm')

        # Actual pinned sources, final linked code (including LTO), no copied body.
        $refObjects=@()
        $rflags=$flags+@('-std=c11','-mcmse',"-I$(Join-Path $fixture 'reference')","-I$reference")
        foreach ($unit in @('secure_init.c','secure_context.c','secure_context_port.c')) {
            $object=Join-Path $dir ('reference-'+$unit+'.o')
            $refWarnings=if ($unit -eq 'secure_context_port.c') {@('-Wno-unused-parameter')} else {@()}
            $null=Recorded $ArmGcc ($rflags+$refWarnings+@('-save-temps=obj','-c',(Join-Path $reference $unit),'-o',$object)) (Join-Path $dir ($unit+'-compile.log'))
            $refObjects+=$object
        }
        $heapObject=Join-Path $dir 'reference-link-only-heap.o'
        $null=Recorded $ArmGcc ($rflags+@('-c',(Join-Path $fixture 'reference\link_only_heap.c'),'-o',$heapObject)) (Join-Path $dir 'reference-link-only-heap.log')
        $refObjects+=$heapObject
        $refElf=Join-Path $dir 'reference.elf'
        $null=Recorded $ArmGcc ($rflags+$slink+@('-Wl,--entry=0','-Wl,-u,SecureInit_DePrioritizeNSExceptions','-Wl,-u,SecureContext_Init',
            '-T',(Join-Path $fixture 'import.ld'),"-Wl,-Map,$dir/reference.map")+$refObjects+@('-o',$refElf)) (Join-Path $dir 'reference-link.log')
        $refDis=(Recorded $objdump @('-drwC',$refElf) (Join-Path $dir 'reference.dis')).Text
        $refContext=Get-ExactDisassemblyFunction $refDis '__acle_se_SecureContext_Init'
        $refPriority=Get-ExactDisassemblyFunction $refDis '__acle_se_SecureInit_DePrioritizeNSExceptions'
        foreach ($pattern in @('(?i)msr\s+PSPLIM','(?i)msr\s+PSP','(?i)msr\s+CONTROL')) {
            if ($refContext -notmatch $pattern) { throw "Pinned initialization lost actual instruction $pattern" }
        }
        if ($refPriority -notmatch '\bstr(?:\.w)?\b') { throw 'Pinned deprioritization lost AIRCR store' }
        @('Actual pinned SecureInit_DePrioritizeNSExceptions:', $refPriority,
            'Actual pinned SecureContext_Init:', $refContext,
            'Other retained CMSE exports use unexecuted trapping heap stubs only to complete this comparison link.',
            'Fiber differences: direct NS caller + exact SVC; BFHFNMINS precondition before commitment; irreversible BSS latch;',
            'keyed PRIS preservation/readback and barriers; zero-stack readback; bounded scrub/readback pool; exact CONTROL=2;',
            'return failure with sticky INITIALIZING, or exact fail-closed UDF for latch readback failures.') |
            Set-Content (Join-Path $dir 'reference-comparison.txt') -Encoding ASCII

        . (Join-Path $fixture 'hostile_codegen.ps1')
        TestC55SHostile -Flags $sflags -Directory (Join-Path $dir 'hostile') -ReferenceDisassembly $refDis -Exports $expected12

        $cases=@(@{Name='success';Control='';Mutant=$false})
        foreach ($name in @('aircr-readback','psplim-readback','psp-readback','pool-return','control-readback',
                'control-6','control-10','control-14','latch-initial','latch-ready')) {
            $cases+=@{Name=$name;Control='';Mutant=$false}
        }
        $cases+=@{Name='bfhfnmins-mutant';Control='';Mutant=$true}
        if ($mode.Name -eq 'o2') {
            foreach ($name in @('unrelated-fault','missing-report','timeout','register-offset-store','unrecognized-store')) {
                $cases+=@{Name='success';Control=$name;Mutant=$false}
            }
        }
        foreach ($case in $cases) {
            $caseLabel=if ($case.Control) {$case.Control} else {$case.Name}
            $caseDir=Join-Path $dir $caseLabel
            $null=New-Item -ItemType Directory -Path $caseDir
            $source=$gatewayPath
            if ($case.Mutant) {
                $predicate='\(\(aircr_before & fiber_secure_contextAIRCR_BFHFNMINS_MASK\) != 0u\)'
                if ([regex]::Matches($gatewayText,$predicate).Count -ne 1) { throw 'Missing exact A26 BFHFNMINS mutation site' }
                $source=Join-Path $caseDir 'gateway-mutant.c'
                [regex]::Replace($gatewayText,$predicate,'(0)') | Set-Content -LiteralPath $source -Encoding ASCII
            }
            $gateway=Join-Path $caseDir 'gateway.o'
            $null=Recorded $ArmGcc ($sflags+@('-save-temps=obj','-MMD','-c',$source,'-o',$gateway)) (Join-Path $caseDir 'gateway-compile.log')
            $sElf=Join-Path $caseDir 'secure.elf'
            $import=Join-Path $caseDir 'secure-import.o'
            $null=Recorded $ArmGcc ($sflags+$slink+@('-Wl,-u,init_fixture_policy_store','-Wl,-u,init_fixture_mask_store',
                '-Wl,-u,init_fixture_register_offset_store','-Wl,-u,init_fixture_unrecognized_store',
                '-T',(Join-Path $fixture 'secure.ld'),"-Wl,-Map,$caseDir/secure.map",
                "-Wl,--cmse-implib,--out-implib=$import")+$objects+@($gateway,'-o',$sElf)) (Join-Path $caseDir 'secure-link.log')
            AssertImports $import $expected12 (Join-Path $caseDir 'secure-import.nm')
            $sDis=(Recorded $objdump @('-drwC',$sElf) (Join-Path $caseDir 'secure.dis')).Text
            $sNm=(Recorded $nm @('-a','-S','-n',$sElf) (Join-Path $caseDir 'secure.nm')).Text
            AssertM55CallerProof $sDis $entryName (Join-Path $caseDir 'entry-caller-proof.txt')
            $body=Get-ExactDisassemblyFunction $sDis ('__acle_se_'+$entryName)
            $instructions=@(Get-Instructions $body)
            for ($i=0;$i -lt $instructions.Count;$i++) {
                $next=if ($i+1 -lt $instructions.Count) {[Convert]::ToUInt32($instructions[$i+1].Address,16)} else {0}
                $instructions[$i] | Add-Member -NotePropertyName Next -NotePropertyValue $next
            }
            $storeControl=@()
            if ($case.Control -in @('register-offset-store','unrecognized-store')) {
                $controlName='init_fixture_'+$case.Control.Replace('-','_')
                $storeControl=@(Get-Instructions (Get-ExactDisassemblyFunction $sDis $controlName))
                $expectedOp=if ($case.Control -eq 'register-offset-store') {'str'} else {'strt'}
                if ($storeControl[0].Opcode -ne $expectedOp) { throw 'Store control lost its actual first instruction' }
            }
            $controlId=if ($case.Control -eq 'unrelated-fault') {1} elseif ($case.Control -eq 'missing-report') {2} elseif ($case.Control -eq 'timeout') {3} else {0}
            $isFault=if ($case.Name -eq 'success' -or $case.Mutant) {0} else {1}
            $nObject=Join-Path $caseDir 'nonsecure.o'
            $nsStartup=Join-Path $caseDir 'ns-startup.o'
            $null=Recorded $ArmGcc ($nflags+@('-c',(Join-Path $fixture 'startup.S'),'-o',$nsStartup)) (Join-Path $caseDir 'ns-startup.log')
            $null=Recorded $ArmGcc ($nflags+@("-DINIT_FAULT_CASE=$isFault","-DINIT_CONTROL=$controlId",'-save-temps=obj',
                '-c',(Join-Path $fixture 'nonsecure.c'),'-o',$nObject)) (Join-Path $caseDir 'nonsecure-compile.log')
            $nElf=Join-Path $caseDir 'nonsecure.elf'
            $null=Recorded $ArmGcc ($nflags+$link+@('-T',(Join-Path $fixture 'nonsecure.ld'),"-Wl,-Map,$caseDir/nonsecure.map",
                $nsStartup,$nObject,$import,'-o',$nElf)) (Join-Path $caseDir 'nonsecure-link.log')
            $nDis=(Recorded $objdump @('-drwC',$nElf) (Join-Path $caseDir 'nonsecure.dis')).Text
            $nNm=(Recorded $nm @('-a','-S','-n',$nElf) (Join-Path $caseDir 'nonsecure.nm')).Text
            if ($case.Name -eq 'success' -and !$case.Control) {
                foreach ($language in @('c','c++')) {
                    $compiler=if ($language -eq 'c') {$ArmGcc} else {$gxx}
                    $consumerFlags=if ($language -eq 'c') {$nflags} else {@($nflags | Where-Object {$_ -ne '-std=c11'})}
                    $consumer=$nObject
                    if ($language -eq 'c++') {
                        $consumer=Join-Path $caseDir 'nonsecure-cpp.o'
                        $null=Recorded $compiler ($consumerFlags+@('-x','c++','-std=c++17','-fno-exceptions','-fno-rtti',
                            '-c',(Join-Path $fixture 'nonsecure.c'),'-o',$consumer)) (Join-Path $caseDir 'cpp-compile.log')
                        # Link fixture C++ functions with C names to the assembly vectors.
                    }
                    $bad=Recorded $compiler ($consumerFlags+$link+@('-T',(Join-Path $fixture 'nonsecure.ld'),
                        $nsStartup,$consumer,$oldImport,'-o',(Join-Path $caseDir ("old8-$language.elf")))) (Join-Path $caseDir ("old8-$language.log")) -AllowFailure
                    $missing=@([regex]::Matches($bad.Text,"undefined reference to [``']([^']+)'") |
                        ForEach-Object {$_.Groups[1].Value} | Sort-Object -Unique)
                    if ($bad.ExitCode -eq 0 -or $missing.Count -ne 1 -or $missing[0] -ne $entryName) {
                        throw 'Old eight-entry provider must fail solely on missing initializer'
                    }
                    if ($language -eq 'c++') {
                        $null=Recorded $compiler ($consumerFlags+$link+@('-T',(Join-Path $fixture 'nonsecure.ld'),
                            $nsStartup,$consumer,$import,'-o',(Join-Path $caseDir 'matching-cpp.elf'))) (Join-Path $caseDir 'cpp-link.log')
                    }
                }
            }
            $checkpoints=@{}
            $checkpoints.secure_rejected=Get-ExactSymbolAddress $sNm 'init_fixture_secure_rejected'
            foreach ($name in @('wrong_done','rejected','first_result','repeat_result')) {
                if (!$case.Control) { $checkpoints[$name]=Get-ExactSymbolAddress $nNm ('init_fixture_'+$name) }
            }
            $manifest=Join-Path $caseDir 'manifest.json'
            @{case=$case.Name;control=$case.Control;mutant=$case.Mutant;instructions=$instructions;checkpoints=$checkpoints;
                entry=(Get-ExactSymbolAddress $sNm ('__acle_se_'+$entryName));
                pool_entry=(Get-ExactSymbolAddress $sNm 'fiber_secure_context_pool_boot_initialize');
                gate=(Get-ExactSymbolAddress $sNm 'fiber_secure_context_gateway_state');
                pool_state=(Get-ExactSymbolAddress $sNm 'fiber_secure_context_pool_state');
                pool=(Get-ExactSymbolAddress $sNm '__pool_start');pool_size=480;
                policy_store=(Get-ExactSymbolAddress $sNm 'init_fixture_policy_store');
                mask_store=(Get-ExactSymbolAddress $sNm 'init_fixture_mask_store');store_control=$storeControl;
                fault_handler=(Get-ExactSymbolAddress $sNm 'init_fault_handler');
                fail_closed=(FunctionRange $sNm $sDis 'fiber_secure_context_gateway_fail_closed');
                unrelated=(FunctionRange $nNm $nDis 'init_fixture_unrelated_udf' -Optional);
                secure_sha256=(Get-FileHash $sElf -Algorithm SHA256).Hash;
                nonsecure_sha256=(Get-FileHash $nElf -Algorithm SHA256).Hash} |
                ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $manifest -Encoding ASCII
            $seconds=if ($case.Control -eq 'timeout') {2} else {$TimeoutSeconds}
            $null=Recorded $wsl @('-d',$WslDistro,'--exec','bash',(WslPath (Join-Path $fixture 'qemu.sh')),
                $QemuRoot,(WslPath $sElf),(WslPath $nElf),"$seconds",(WslPath $manifest)) (Join-Path $caseDir 'runner.log')
            $receipt=Get-Content (Join-Path $caseDir 'execution-receipt.json') -Raw | ConvertFrom-Json
            if ($receipt.result -ne 'PASS') { throw "Non-PASS execution receipt: $caseDir" }
            $runs.Add([pscustomobject]@{Mode=$mode.Name;Case=$caseLabel;Receipt=$receipt;Directory=$caseDir})
            $runs.ToArray() | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $out 'receipts.json') -Encoding ASCII
            Write-Host "PASS M55 SG $($mode.Name)/$caseLabel`: $($receipt.classification)"
        }
    }
    $hashesAfter=@($inputPaths | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
    $hashesAfter | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    if (Compare-Object $hashesBefore $hashesAfter -Property Path,Hash) { throw 'Qualification inputs changed during execution' }
    $verdict='PASS'
} finally {
    [pscustomobject]@{Verdict=$verdict;Machine='mps3-an547';QemuRoot=$QemuRoot;WslDistro=$WslDistro;
        DefaultM55Codegen=$true;NonSecureFiberRuntime=$false;HardwareQualification=$false;Runs=$runs.ToArray()} |
        ConvertTo-Json -Depth 14 | Set-Content (Join-Path $out 'results.json') -Encoding ASCII
    Get-ChildItem -LiteralPath $out -Recurse -File | Where-Object {$_.Name -ne 'sha256.csv'} |
        Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash |
        Export-Csv -LiteralPath (Join-Path $out 'sha256.csv') -NoTypeInformation -Encoding ASCII
}
Write-Host "PASS C55S stateful initializer; evidence: $out"
