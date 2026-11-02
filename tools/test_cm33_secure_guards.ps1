param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$QemuRoot,
    [string]$WslDistro = "Ubuntu-24.04",
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 10
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
if (-not $ArmGcc -or -not (Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {
    throw "An existing -ArmGcc is required"
}
if (-not $CmsisCore -or -not (Test-Path -LiteralPath (Join-Path $CmsisCore 'core_cm33.h'))) {
    throw "-CmsisCore must contain core_cm33.h"
}
if (-not $QemuRoot -or -not $QemuRoot.StartsWith('/')) {
    throw "An existing absolute WSL -QemuRoot is required; this runner never provisions packages"
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture = Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards'
$secure = Join-Path $repo 'fiber\port\ARM_CM33\secure'
$nonsecure = Join-Path $repo 'fiber\port\ARM_CM33\non_secure'
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$bin = Split-Path $ArmGcc
$objdump = Join-Path $bin 'arm-none-eabi-objdump.exe'
$nm = Join-Path $bin 'arm-none-eabi-nm.exe'
if (-not (Test-Path $objdump) -or -not (Test-Path $nm)) { throw 'Missing ARM binutils' }
if (-not $BuildRoot) { $BuildRoot = $env:TEMP }
$out = Join-Path $BuildRoot ('cm33-secure-guards-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out -Force | Out-Null
$out = (Resolve-Path -LiteralPath $out).Path
$script:commands = Join-Path $out 'commands.txt'
Write-Host "CM33 Secure guard evidence: $out"

function Get-GuardInputHashes {
    $paths = @($PSCommandPath, $ArmGcc, $objdump, $nm,
        (Join-Path $repo 'mcu_core.h'), (Join-Path $repo 'basic_types.h'),
        (Join-Path $repo 'fiber\fiber_api_attributes.h'),
        (Join-Path $PSScriptRoot 'fixtures\arm_control\report.h'),
        (Join-Path $PSScriptRoot 'fixtures\arm_control\qemu.sh')) +
        @(Get-ChildItem $fixture, $secure, $nonsecure -File -Recurse |
            Where-Object { $_.Extension -ne '.pyc' } |
            Select-Object -ExpandProperty FullName) +
        @(Get-ChildItem $CmsisCore -Filter '*.h' -File -Recurse |
            Select-Object -ExpandProperty FullName)
    @($paths | Sort-Object -Unique | ForEach-Object {
        Get-FileHash -LiteralPath $_ -Algorithm SHA256
    } | Select-Object Path, Hash)
}
$inputBefore = Get-GuardInputHashes
$inputBefore | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $out 'inputs-before.json') -Encoding ASCII

function Invoke-Recorded([string]$Executable, [string[]]$Arguments, [string]$Log) {
    Add-Content -LiteralPath $script:commands -Encoding ASCII -Value (
        '& "' + $Executable + '" ' + (($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '))
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = & $Executable @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $saved }
    $lines | Out-File -LiteralPath $Log -Encoding utf8
    return $code
}
function Require-Command([string]$Executable, [string[]]$Arguments, [string]$Log) {
    if ((Invoke-Recorded $Executable $Arguments $Log) -ne 0) { throw "Command failed: $Log" }
}
function Wsl-Path([string]$Path) {
    $value = & wsl.exe -d $WslDistro --exec wslpath -u $Path
    if ($LASTEXITCODE -ne 0 -or -not $value) { throw "WSL path conversion failed: $Path" }
    return ($value -join '').Trim()
}
function Get-ExactDisassemblyFunction([string]$Disassembly, [string]$Name) {
    $match = [regex]::Match($Disassembly,
        '(?ms)^[0-9a-f]+ <' + [regex]::Escape($Name) + '>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
    if (-not $match.Success) { throw "Missing exact ELF function: $Name" }
    return $match.Groups[1].Value
}
function Get-Instructions([string]$Body) {
    return @([regex]::Matches($Body,
        '(?m)^[ \t]*([0-9a-f]+):[ \t]+(?:[0-9a-f]{4}(?:[0-9a-f]{4})?[ \t]+)+([a-z][a-z0-9.]*)(?:[ \t]+([^\r\n]*))?') |
        ForEach-Object {
            [pscustomobject]@{ Address=$_.Groups[1].Value; Opcode=$_.Groups[2].Value;
                Operands=$_.Groups[3].Value; Text=$_.Value.Trim() }
        })
}
function Get-ExactSymbolAddress([string]$Symbols, [string]$Name) {
    $found = [regex]::Matches($Symbols, '(?m)^([0-9a-f]+) (?:[0-9a-f]+ )?[a-zA-Z] ' +
        [regex]::Escape($Name) + '\r?$')
    if ($found.Count -ne 1) { throw "Missing unique ELF symbol: $Name" }
    return [Convert]::ToUInt32($found[0].Groups[1].Value, 16)
}
function Assert-EntryCallerProof([string]$Disassembly, [string]$Name, [string]$Receipt) {
    $body = Get-ExactDisassemblyFunction $Disassembly ('__acle_se_' + $Name)
    $instructions = @(Get-Instructions $body)
    $branchIndex = -1
    if ($instructions.Count -gt 1 -and $instructions[0].Opcode -match '^tst(?:\.w)?$' -and
        $instructions[0].Operands -match '^lr,\s*#1\s*$') {
        # The pinned optimized shapes test untouched incoming LR first. Only
        # flag-preserving prologue/argument moves may precede its branch.
        for ($i = 1; $i -lt [Math]::Min(9, $instructions.Count); ++$i) {
            $instruction = $instructions[$i]
            if ($instruction.Opcode -match '^b(?:eq|ne)(?:\.[nw])?$') { $branchIndex=$i; break }
            if ($instruction.Opcode -notmatch '^(?:push(?:\.w)?|mov(?:\.w)?|sub(?:\.w)?)$' -or
                ($instruction.Opcode -match '^mov' -and $instruction.Operands -match '^lr,') -or
                ($instruction.Opcode -match '^sub' -and $instruction.Operands -notmatch '^sp,')) {
                throw "Unqualified instruction between incoming-LR test and branch: $Name / $($instruction.Text)"
            }
        }
    } else {
        # GCC -O0 preserves incoming LR in r3 before any BL. Qualify the exact
        # bounded prologue/dataflow, rather than accepting an arbitrary later
        # 'and #1' that could be testing a helper's return address.
        if ($instructions.Count -lt 12 -or
            $instructions[0].Opcode -ne 'push' -or $instructions[0].Operands -ne '{r7, lr}' -or
            $instructions[1].Opcode -ne 'sub' -or $instructions[1].Operands -notmatch '^sp, #' -or
            $instructions[2].Opcode -ne 'add' -or $instructions[2].Operands -ne 'r7, sp, #0' -or
            $instructions[3].Opcode -ne 'mov' -or $instructions[3].Operands -ne 'r3, lr') {
            throw "Unqualified incoming-LR capture in exact NSC entry: $Name"
        }
        $i = 4
        while ($i -lt $instructions.Count -and $instructions[$i].Opcode -eq 'str' -and
            $instructions[$i].Operands -match '^r[01], \[r7, #\d+\]$') { ++$i }
        $expected = @(
            @('and.w', '^r3, r3, #1$'), @('cmp', '^r3, #0$'), @('ite', '^eq$'),
            @('moveq', '^r3, #1$'), @('movne', '^r3, #0$'), @('cmp', '^r3, #0$'),
            @('beq.n', '^[0-9a-f]+ <'))
        foreach ($item in $expected) {
            if ($i -ge $instructions.Count -or $instructions[$i].Opcode -ne $item[0] -or
                $instructions[$i].Operands -notmatch $item[1]) {
                throw "Unqualified -O0 incoming-LR dataflow: $Name instruction $i"
            }
            ++$i
        }
        $branchIndex = $i - 1
    }
    if ($branchIndex -lt 0) { throw "Missing branch on incoming caller state: $Name" }
    $veneer = @(Get-Instructions (Get-ExactDisassemblyFunction $Disassembly $Name))
    if ($veneer.Count -lt 2 -or $veneer[0].Opcode -ne 'sg' -or
        $veneer[1].Opcode -notmatch '^b(?:\.w)?$' -or
        $veneer[1].Operands -notmatch ('^[0-9a-f]+ <__acle_se_' + [regex]::Escape($Name) + '>$')) {
        throw "Generated SG veneer is not bound to the exact tested entry: $Name"
    }
    Add-Content -LiteralPath $Receipt -Encoding ASCII -Value ("$Name`n" +
        (($instructions[0..$branchIndex] | ForEach-Object { $_.Text }) -join "`n") + "`n" +
        (($veneer[0..1] | ForEach-Object { $_.Text }) -join "`n") + "`n")
}

$gatewayPath = Join-Path $secure 'fiber_secure_context_gateway.c'
$gatewaySource = Get-Content -LiteralPath $gatewayPath -Raw
$poolSource = Get-Content -LiteralPath (Join-Path $secure 'fiber_secure_context_pool.c') -Raw
$operations = @('initialize', 'allocate', 'load', 'save')
foreach ($operation in $operations) {
    $name = 'fiber_secure_context_gateway_v1_' + $operation
    $body = [regex]::Match($gatewaySource, '(?ms)^uint32_t ' + $name + '\(.*?^\}').Value
    if (-not $body -or ([regex]::Matches($body, 'cmse_nonsecure_caller\(\)')).Count -ne 1) {
        throw "Stateful NSC entry must directly check the CMSE caller: $name"
    }
}
if (([regex]::Matches($gatewaySource, 'cmse_nonsecure_caller\(\)')).Count -ne 4) {
    throw 'Origin checks must be exactly in the four stateful entries, not helpers or pure queries'
}
foreach ($helper in @('write_stack_seal', 'stack_seal_is_valid')) {
    $body = [regex]::Match($poolSource,
        '(?ms)^(?:void|uint32_t) fiber_secure_context_pool_' + $helper + '\(.*?^\}').Value
    if (-not $body -or $body -match '\buint32_t\s*\*' -or
        $body -notmatch '\bunsigned char\s*\*') {
        throw "Seal helper must use character object access, not a uint32_t pointer: $helper"
    }
}
Get-ChildItem -LiteralPath $fixture -File | Get-FileHash -Algorithm SHA256 |
    Format-Table -AutoSize | Out-File (Join-Path $out 'fixture-sha256.txt') -Width 350
$sourcePaths = @($PSCommandPath, $gatewayPath, (Join-Path $secure 'fiber_secure_context_gateway_abi.h'),
    (Join-Path $secure 'fiber_secure_context_pool.c'), (Join-Path $secure 'fiber_secure_context_pool.h'),
    (Join-Path $secure 'fiber_secure_context_cohort.h'),
    (Join-Path $secure 'fiber_secure_context_cohort_contract.ld'),
    (Join-Path $secure 'fiber_secure_gateway_contract.h'),
    (Join-Path $secure 'fiber_secure_context_gateway_contract.h'),
    (Join-Path $PSScriptRoot 'fixtures\arm_control\report.h'))
Get-FileHash -LiteralPath $sourcePaths -Algorithm SHA256 |
    Format-Table -AutoSize | Out-File (Join-Path $out 'source-sha256.txt') -Width 350
Require-Command $ArmGcc @('--version') (Join-Path $out 'compiler-version.txt')
$wslOut = Wsl-Path $out
$inspect = Wsl-Path (Join-Path $PSScriptRoot 'fixtures\arm_control\qemu.sh')
Require-Command 'wsl.exe' @('-d', $WslDistro, '--exec', 'bash', $inspect, 'inspect', $QemuRoot, $wslOut) `
    (Join-Path $out 'qemu-inspect.log')
$run = Wsl-Path (Join-Path $fixture 'qemu.sh')

$cases = @(
    @{Name='o0'; Flags=@('-O0'); Mutant=''; Exit=0; Marker='PASS:CM33-SECURE-GUARDS'},
    @{Name='o2'; Flags=@('-O2'); Mutant=''; Exit=0; Marker='PASS:CM33-SECURE-GUARDS'},
    @{Name='os'; Flags=@('-Os'); Mutant=''; Exit=0; Marker='PASS:CM33-SECURE-GUARDS'},
    @{Name='o2-lto'; Flags=@('-O2', '-flto'); Mutant=''; Exit=0; Marker='PASS:CM33-SECURE-GUARDS'},
    @{Name='os-lto'; Flags=@('-Os', '-flto'); Mutant=''; Exit=0; Marker='PASS:CM33-SECURE-GUARDS'}
)
foreach ($operation in $operations) {
    $status = @{initialize=40; allocate=41; load=42; save=43}[$operation]
    $cases += @{Name="mutant-$operation"; Flags=@('-O2'); Mutant=$operation; Exit=$status;
        Marker="FAIL:GUARDS:secure-$operation-accepted"}
}
foreach ($mode in @($cases | Where-Object { -not $_.Mutant })) {
    $cases += @{Name=("mutant-bfhfnmins-" + $mode.Name); Flags=$mode.Flags; Mutant='bfhfnmins'; Exit=0;
        Marker='PASS:GUARDS:BFHFNMINS-mutant-stopped-before-AIRCR-STR'}
}
foreach ($case in $cases) {
    $dir = Join-Path $out $case.Name
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $source = $gatewayPath
    if ($case.Mutant) {
        $operation = $case.Mutant
        if ($operation -eq 'bfhfnmins') { $operation = 'initialize' }
        $name = 'fiber_secure_context_gateway_v1_' + $operation
        $match = [regex]::Match($gatewaySource, '(?ms)^uint32_t ' + $name + '\(.*?^\}')
        if ($case.Mutant -eq 'bfhfnmins') {
            $predicate = '\(\(aircr_before & fiber_secure_contextAIRCR_BFHFNMINS_MASK\) != 0u\)'
            if (([regex]::Matches($match.Value, $predicate)).Count -ne 1) {
                throw 'Missing exact BFHFNMINS precondition mutation site'
            }
            $body = [regex]::Replace($match.Value, $predicate, '(0)')
        } else {
            $body = $match.Value.Replace('(cmse_nonsecure_caller() == 0)', '(0)')
        }
        if ($body -eq $match.Value) { throw "Missing exact mutation site: $name" }
        $source = Join-Path $dir 'gateway-mutant.c'
        ($gatewaySource.Substring(0, $match.Index) + $body +
            $gatewaySource.Substring($match.Index + $match.Length)) |
            Set-Content -LiteralPath $source -Encoding ASCII
    }
    $common = @('-mcpu=cortex-m33', '-mthumb', '-mfloat-abi=soft', '-mgeneral-regs-only',
        '-std=c11', '-g3', '-ffreestanding', '-fno-builtin', '-fstrict-aliasing',
        '-Wstrict-aliasing=3', '-Wall', '-Wextra', '-Werror',
        '-fno-instrument-functions', '-fno-stack-protector', '-fno-profile-arcs',
        '-fno-test-coverage', '-fno-sanitize=all', '-fno-profile', '-fno-stack-check',
        '-fno-sanitize-coverage=trace-pc') + $case.Flags
    $sflags = $common + @('-mcmse', '-DGUARD_SECURE=1',
        '-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3',
        '-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=64',
        "-I$fixture", "-I$secure", "-I$repo", "-I$CmsisCore")
    $objects = @()
    foreach ($unit in @(@{Name='gateway'; Source=$source},
        @{Name='secure'; Source=(Join-Path $fixture 'secure.c')},
        @{Name='secure-start'; Source=(Join-Path $fixture 'startup.S')})) {
        $object = Join-Path $dir ($unit.Name + '.o')
        Require-Command $ArmGcc ($sflags + @('-save-temps=obj', '-c', $unit.Source, '-o', $object)) `
            (Join-Path $dir ($unit.Name + '-compile.log'))
        $objects += $object
    }
    $sElf = Join-Path $dir 'secure.elf'
    $import = Join-Path $dir 'secure-import.o'
    $link = @('-nostdlib', '-nostartfiles', '-Wl,--build-id=none')
    Require-Command $ArmGcc ($sflags + $link + @('-T', (Join-Path $fixture 'secure.ld'),
        '-T', (Join-Path $secure 'fiber_secure_context_cohort_contract.ld'),
        '-Wl,--section-start=.gnu.sgstubs=0x10008000',
        "-Wl,-Map,$dir/secure.map", "-Wl,--cmse-implib,--out-implib=$import") + $objects + @('-o', $sElf)) `
        (Join-Path $dir 'secure-link.log')
    $nflags = $common + @("-I$fixture", "-I$nonsecure")
    $nElf = Join-Path $dir 'nonsecure.elf'
    Require-Command $ArmGcc ($nflags + $link + @('-T', (Join-Path $fixture 'nonsecure.ld'),
        "-Wl,-Map,$dir/nonsecure.map", (Join-Path $fixture 'startup.S'),
        (Join-Path $fixture 'nonsecure.c'), $import, '-o', $nElf)) (Join-Path $dir 'nonsecure-build.log')
    Require-Command $objdump @('-drwC', $sElf) (Join-Path $dir 'secure.dis')
    Require-Command $objdump @('-drwC', $nElf) (Join-Path $dir 'nonsecure.dis')
    Require-Command $nm @('-S', '-n', $sElf) (Join-Path $dir 'secure.nm')
    $symbols = Get-Content -LiteralPath (Join-Path $dir 'secure.nm') -Raw
    foreach ($storage in @(@{Name='records'; Size=72; Alignment=8},
        @{Name='stacks'; Size=216; Alignment=8}, @{Name='initialized'; Size=4; Alignment=4})) {
        $symbolMatches = [regex]::Matches($symbols,
            '(?m)^([0-9a-f]+) ([0-9a-f]+) [bBdDrR] fiber_secure_context_pool_' +
            $storage.Name + '\r?$')
        if ($symbolMatches.Count -ne 1 -or [Convert]::ToUInt32($symbolMatches[0].Groups[2].Value, 16) -ne $storage.Size -or
            ([Convert]::ToUInt32($symbolMatches[0].Groups[1].Value, 16) % $storage.Alignment) -ne 0) {
            throw "Secure pool storage symbol geometry changed: $($storage.Name)"
        }
    }
    $disassembly = Get-Content -LiteralPath (Join-Path $dir 'secure.dis') -Raw
    foreach ($operation in $operations) {
        if ($case.Mutant -eq $operation) {
            $rejected = $false
            try {
                Assert-EntryCallerProof $disassembly ('fiber_secure_context_gateway_v1_' + $operation) `
                    (Join-Path $dir 'unexpected-lr-proof.txt')
            } catch {
                $rejected = $true
                $_.Exception.Message | Out-File (Join-Path $dir 'nsc-entry-lr-rejection.txt') -Encoding utf8
            }
            if (-not $rejected) { throw "Entry-LR proof accepted missing origin guard: $operation" }
        } else {
            Assert-EntryCallerProof $disassembly ('fiber_secure_context_gateway_v1_' + $operation) `
                (Join-Path $dir 'nsc-entry-lr-proof.txt')
        }
    }
    $log = Join-Path $dir 'qemu.log'
    $arguments = @('-d', $WslDistro, '--exec', 'bash', $run, $QemuRoot,
        (Wsl-Path $sElf), (Wsl-Path $nElf), "$TimeoutSeconds")
    $rspProof = (-not $case.Mutant -or $case.Mutant -eq 'bfhfnmins')
    if ($rspProof) {
        $entryName = '__acle_se_fiber_secure_context_gateway_v1_initialize'
        $stores = @(Get-Instructions (Get-ExactDisassemblyFunction $disassembly $entryName) |
            Where-Object { $_.Opcode -match '^(?:str|stm)' })
        if (-not $stores.Count) { throw 'Missing initializer stores for exact AIRCR execution proof' }
        $poison = @()
        foreach ($region in @(@{Name='records'; Size=72}, @{Name='stacks'; Size=216},
            @{Name='initialized'; Size=4})) {
            $poison += @{address=(Get-ExactSymbolAddress $symbols ('fiber_secure_context_pool_' + $region.Name));
                size=$region.Size}
        }
        $manifest = Join-Path $dir 'aircr-rsp-manifest.json'
        @{entry=(Get-ExactSymbolAddress $symbols $entryName);
            gate=(Get-ExactSymbolAddress $symbols 'fiber_secure_context_gateway_state');
            prepared=(Get-ExactSymbolAddress $symbols 'guard_fixture_bfhfnmins_prepared');
            checkpoint=(Get-ExactSymbolAddress $symbols 'guard_fixture_bfhfnmins_checkpoint');
            mutant=($case.Mutant -eq 'bfhfnmins'); stores=$stores; poison=$poison;
            secure_sha256=(Get-FileHash -LiteralPath $sElf -Algorithm SHA256).Hash;
            nonsecure_sha256=(Get-FileHash -LiteralPath $nElf -Algorithm SHA256).Hash} |
            ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifest -Encoding ASCII
        $arguments += (Wsl-Path $manifest)
    }
    $code = Invoke-Recorded 'wsl.exe' $arguments $log
    $trace = Get-Content -LiteralPath $log -Raw
    if ($code -ne $case.Exit -or $trace -notmatch ([regex]::Escape($case.Marker) + '(?:\r?\n|$)')) {
        throw "QEMU $($case.Name) exit=$code expected=$($case.Exit) marker=$($case.Marker); see $log"
    }
    if ($rspProof -and -not $case.Mutant -and $trace -notmatch
        'PASS:GUARDS:BFHFNMINS-two-rejections-gate0-before-positive-AIRCR-STR(?:\r?\n|$)') {
        throw "Missing exact pre-commit rejection / positive AIRCR proof: $log"
    }
    Add-Content -LiteralPath (Join-Path $out 'results.txt') -Encoding ASCII -Value (
        "$($case.Name): exit=$code marker=$($case.Marker)")
    $outcome = "actual QEMU exit $code"
    if ($case.Mutant -eq 'bfhfnmins') { $outcome = 'inferior safely stopped before forbidden AIRCR STR' }
    Write-Host "PASS: $($case.Name) ($outcome)"
}
Get-ChildItem -LiteralPath $out -Filter *.elf -Recurse | Get-FileHash -Algorithm SHA256 |
    Format-Table -AutoSize | Out-File (Join-Path $out 'elf-sha256.txt') -Width 350
$inputAfter = Get-GuardInputHashes
$inputAfter | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $out 'inputs-after.json') -Encoding ASCII
$drift = @(Compare-Object $inputBefore $inputAfter -Property Path, Hash)
$verdict = if ($drift.Count) { 'FAIL' } else { 'PASS' }
@{Verdict=$verdict; Cases=$cases.Count; Inputs=$inputBefore.Count; Drift=$drift;
    Evidence=$out; HardwareExecuted=$false; Model='QEMU mps2-an505 Cortex-M33'} |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $out 'receipt.json') -Encoding ASCII
if ($drift.Count) { throw 'CM33 guard inputs changed during qualification' }
Get-ChildItem -LiteralPath $out -File -Recurse |
    Where-Object { $_.Name -ne 'artifact-sha256.json' } |
    Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash |
    ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $out 'artifact-sha256.json') -Encoding ASCII
Write-Host "PASS: CM33 Secure caller/AIRCR guards and strict-aliasing pool; evidence $out"
