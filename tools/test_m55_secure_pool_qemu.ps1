param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$BuildRoot,
    [string]$WslDistro = "Ubuntu-24.04",
    [string]$QemuRoot,
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 10
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixtures = Join-Path $PSScriptRoot "fixtures/m55_secure_pool_qemu"
$port = Join-Path $repo "fiber/port/ARM_CM55/secure"
if ([string]::IsNullOrWhiteSpace($ArmGcc) -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {
    throw "Supply an existing -ArmGcc (or ARM_NONE_EABI_GCC); this runner never installs tools."
}
if ([string]::IsNullOrWhiteSpace($QemuRoot) -or !$QemuRoot.StartsWith("/")) {
    throw "Supply an explicit existing absolute WSL -QemuRoot; no provisioning or silent skip is supported."
}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin "arm-none-eabi-gcc-nm.exe"
$objdump = Join-Path $bin "arm-none-eabi-objdump.exe"
$qemuScript = Join-Path $PSScriptRoot "fixtures/arm_control/qemu.sh"
$wsl = (Get-Command wsl.exe -ErrorAction Stop).Source
foreach ($required in @($nm, $objdump, $qemuScript, (Join-Path $fixtures "cases.c"),
        (Join-Path $fixtures "startup.S"), (Join-Path $fixtures "pool.ld"),
        (Join-Path $port "fiber_secure_context_pool.c"))) {
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing dependency: $required" }
}
if ([string]::IsNullOrWhiteSpace($BuildRoot)) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ("fiber-m55-secure-pool-qemu-" + [guid]::NewGuid().ToString("N"))
$null = New-Item -ItemType Directory -Path $out -Force
$out = (Resolve-Path -LiteralPath $out).Path
$commands = Join-Path $out "commands.jsonl"
$receipts = New-Object System.Collections.Generic.List[object]
$modesReceipt = New-Object System.Collections.Generic.List[object]
$verdict = "FAIL"

function Invoke-Recorded {
    param([string]$Program, [string[]]$Arguments, [string]$Log)
    [pscustomobject]@{ Program = $Program; Arguments = $Arguments; Log = $Log } |
        ConvertTo-Json -Depth 4 -Compress | Add-Content -LiteralPath $commands -Encoding ASCII
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $lines = @(& $Program @Arguments 2>&1 | ForEach-Object { "$_" })
        $status = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }
    [IO.File]::WriteAllLines($Log, [string[]]$lines)
    return [pscustomobject]@{ ExitCode = $status; Text = ($lines -join "`n"); Log = $Log }
}

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments, [string]$Log)
    $result = Invoke-Recorded $Program $Arguments $Log
    if ($result.ExitCode -ne 0) {
        throw "$Program failed ($($result.ExitCode)): $($result.Text)`nEvidence: $out"
    }
    return $result
}

function Convert-ToWsl {
    param([string]$Path)
    $result = Invoke-Checked $wsl @("-d", $WslDistro, "--exec", "wslpath", "-u", $Path) `
        (Join-Path $out ("wslpath-" + [guid]::NewGuid().ToString("N") + ".log"))
    if (!$result.Text.Trim()) { throw "Empty WSL translation for $Path" }
    return $result.Text.Trim()
}

function Read-Symbols {
    param([string]$Text)
    return @($Text -split "`n" | ForEach-Object {
        $match = [regex]::Match($_, '^\s*([0-9a-fA-F]+)(?:\s+([0-9a-fA-F]+))?\s+([A-Za-z])\s+(\S+)\s*$')
        if ($match.Success) {
            $size = if ($match.Groups[2].Success) {
                [Convert]::ToUInt64($match.Groups[2].Value, 16)
            } else { [uint64]0 }
            [pscustomobject]@{ Name = $match.Groups[4].Value;
                Address = [Convert]::ToUInt64($match.Groups[1].Value, 16);
                Size = $size; Type = $match.Groups[3].Value }
        }
    })
}

function Get-ExactSymbol {
    param([object[]]$Symbols, [string]$Name)
    $found = @($Symbols | Where-Object { $_.Name -ceq $Name })
    if ($found.Count -ne 1) { throw "Expected exactly one retained ELF symbol $Name" }
    return $found[0]
}

function Classify-Run {
    param([object]$Run, [object]$Case, [object]$Target)
    $classification = [pscustomobject]@{ Pass = $false; Reason = "";
        PC = $null; CFSR = $null; HFSR = $null; IPSR = $null;
        ExcReturn = $null; XPSR = $null }
    if ($Run.ExitCode -ne $Case.Exit) {
        $classification.Reason = "exit-status"
        return $classification
    }
    $name = [regex]::Escape($Case.Name)
    if ([regex]::Matches($Run.Text,
            "(?m)^START:C55S-POOL:$name THREAD=MSP SECURE=1\r?$").Count -ne 1) {
        $classification.Reason = "start-marker"
        return $classification
    }
    if ($Run.Text -match '(?m)^FAIL:C55S-POOL:') {
        $classification.Reason = "fixture-assertion"
        return $classification
    }
    $marker = if ($Case.Id -eq 0) { "PASS" } else { "FAULT-EXIT" }
    if ([regex]::Matches($Run.Text, "(?m)^${marker}:C55S-POOL:$name\r?$").Count -ne 1) {
        $classification.Reason = "exit-marker"
        return $classification
    }
    $reports = @([regex]::Matches($Run.Text,
        ("(?m)^FAULT:C55S-POOL:$name PC=0x([0-9a-f]{8}) CFSR=0x([0-9a-f]{8}) " +
         'HFSR=0x([0-9a-f]{8}) IPSR=0x([0-9a-f]{8}) EXC_RETURN=0x([0-9a-f]{8}) XPSR=0x([0-9a-f]{8})\r?$')))
    if ($Case.Id -eq 0) {
        if ($reports.Count -ne 0 -or $Run.Text -match '(?m)^FAULT:') {
            $classification.Reason = "unexpected-fault"
            return $classification
        }
    }
    else {
        if ($reports.Count -ne 1) {
            $classification.Reason = "fault-report-count"
            return $classification
        }
        $report = $reports[0]
        $classification.PC = [Convert]::ToUInt32($report.Groups[1].Value, 16)
        $classification.CFSR = [Convert]::ToUInt32($report.Groups[2].Value, 16)
        $classification.HFSR = [Convert]::ToUInt32($report.Groups[3].Value, 16)
        $classification.IPSR = [Convert]::ToUInt32($report.Groups[4].Value, 16)
        $classification.ExcReturn = [Convert]::ToUInt32($report.Groups[5].Value, 16)
        $classification.XPSR = [Convert]::ToUInt32($report.Groups[6].Value, 16)
        if ($classification.CFSR -ne 0x00010000) {
            $classification.Reason = "cfsr-not-undefinstr"
            return $classification
        }
        if ($classification.HFSR -ne 0 -or $classification.IPSR -ne 6 -or
                ($classification.XPSR -band 0x010001ff) -ne 0x01000000 -or
                ($classification.ExcReturn -band 0x5c) -ne 0x58) {
            $classification.Reason = "fault-context"
            return $classification
        }
        if ($classification.PC -lt $Target.Start -or $classification.PC -ge $Target.End) {
            $classification.Reason = "pc-not-fail-closed"
            return $classification
        }
        if ($Target.UdfAddresses -notcontains [uint64]$classification.PC) {
            $classification.Reason = "pc-not-udf-instruction"
            return $classification
        }
    }
    $classification.Pass = $true
    $classification.Reason = "verified"
    return $classification
}

Write-Host "C55S M55 QEMU evidence: $out"
$inputPaths = @(
    $PSCommandPath, $qemuScript, $ArmGcc,
    (Join-Path $port "fiber_secure_context_pool.c"),
    (Join-Path $port "fiber_secure_context_pool.h"),
    (Join-Path $port "fiber_secure_context_gateway_contract.h"),
    (Join-Path $repo "fiber/fiber_api_attributes.h")
) + @(Get-ChildItem -LiteralPath $fixtures -File | Select-Object -ExpandProperty FullName)
$sourcesBefore = @($inputPaths | ForEach-Object { Get-FileHash -LiteralPath $_ -Algorithm SHA256 } |
    Select-Object Path, Hash)
$sourcesBefore | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $out "inputs-before.json") -Encoding ASCII
$snapshot = Join-Path $out "inputs"
$null = New-Item -ItemType Directory -Path $snapshot
foreach ($path in $inputPaths) {
    if ($path -ne $ArmGcc) { Copy-Item -LiteralPath $path -Destination $snapshot }
}

try {
    $null = Invoke-Checked $ArmGcc @("--version") (Join-Path $out "compiler-version.txt")
    $wslOut = Convert-ToWsl $out
    $wslScript = Convert-ToWsl $qemuScript
    $null = Invoke-Checked $wsl @("-d", $WslDistro, "--exec", "bash", $wslScript,
        "inspect", $QemuRoot, $wslOut) (Join-Path $out "qemu-inspect.log")
    $machines = Get-Content (Join-Path $out "qemu-machines.txt") -Raw
    if ($machines -notmatch '(?m)^mps3-an547\s') { throw "Existing QEMU lacks mps3-an547" }

    $base = @("-mcpu=cortex-m55", "-mthumb", "-mcmse", "-mfloat-abi=soft",
        "-mgeneral-regs-only", "-ffreestanding", "-fno-builtin", "-fno-common",
        "-fstrict-aliasing", "-Wstrict-aliasing=2", "-Wcast-align=strict",
        "-ffunction-sections", "-fdata-sections", "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables", "-fno-instrument-functions",
        "-fno-stack-protector", "-fno-profile-arcs", "-fno-test-coverage",
        "-fno-sanitize=all", "-Wall", "-Wextra", "-Wundef", "-Werror", "-g3",
        "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3",
        "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=128", "-I$port", "-I$repo")
    $modes = @(
        @{ Name = "o2"; Flags = @("-O2") },
        @{ Name = "os"; Flags = @("-Os") },
        @{ Name = "o2-lto"; Flags = @("-O2", "-flto") },
        @{ Name = "os-lto"; Flags = @("-Os", "-flto") }
    )
    $coreCases = @(
        @{ Id = 0; Name = "success"; Exit = 0 },
        @{ Id = 1; Name = "unready-allocate"; Exit = 42 },
        @{ Id = 2; Name = "corrupt-seal"; Exit = 42 },
        @{ Id = 3; Name = "corrupt-metadata"; Exit = 42 }
    )
    $controls = @(
        @{ Id = 4; Name = "outside-udf"; Exit = 42; Reject = "pc-not-fail-closed" },
        @{ Id = 5; Name = "other-fault"; Exit = 42; Reject = "cfsr-not-undefinstr" },
        @{ Id = 6; Name = "missing-fault"; Exit = 42; Reject = "fault-report-count" },
        @{ Id = 7; Name = "timeout"; Exit = 42; Reject = "exit-status" }
    )
    foreach ($mode in $modes) {
        $dir = Join-Path $out $mode.Name
        $null = New-Item -ItemType Directory -Path $dir
        $flags = $base + $mode.Flags
        $poolObject = Join-Path $dir "pool.o"
        $null = Invoke-Checked $ArmGcc ($flags + @("-std=c11", "-save-temps=obj", "-MMD",
            "-MF", (Join-Path $dir "pool.d"), "-c", (Join-Path $port "fiber_secure_context_pool.c"),
            "-o", $poolObject)) (Join-Path $dir "pool-compile.log")
        $undefined = Invoke-Checked $nm @("-u", $poolObject) (Join-Path $dir "pool-undefined.txt")
        if ($undefined.Text.Trim()) { throw "Production pool gained helper/runtime dependencies: $($undefined.Text)" }
        $startupObject = Join-Path $dir "startup.o"
        $null = Invoke-Checked $ArmGcc ($flags + @("-c", (Join-Path $fixtures "startup.S"),
            "-o", $startupObject)) (Join-Path $dir "startup-compile.log")
        $cases = @($coreCases)
        if ($mode.Name -eq "o2") { $cases += $controls }
        foreach ($case in $cases) {
            $caseDir = Join-Path $dir $case.Name
            $null = New-Item -ItemType Directory -Path $caseDir
            $fixtureObject = Join-Path $caseDir "fixture.o"
            $null = Invoke-Checked $ArmGcc ($flags + @("-std=c11", "-DPOOL_QEMU_CASE=$($case.Id)",
                "-save-temps=obj", "-c", (Join-Path $fixtures "cases.c"), "-o", $fixtureObject)) `
                (Join-Path $caseDir "fixture-compile.log")
            $elf = Join-Path $caseDir "pool.elf"
            $null = Invoke-Checked $ArmGcc ($flags + @("-nostdlib", "-nostartfiles",
                "-save-temps=obj", "-Wl,--gc-sections", "-Wl,--no-undefined", "-Wl,--build-id=none",
                "-Wl,-Map,$(Join-Path $caseDir 'pool.map')", "-T", (Join-Path $fixtures "pool.ld"),
                $startupObject, $fixtureObject, $poolObject, "-o", $elf)) (Join-Path $caseDir "link.log")
            $undefined = Invoke-Checked $nm @("-u", $elf) (Join-Path $caseDir "undefined.txt")
            if ($undefined.Text.Trim()) { throw "Final ELF has undefined symbols: $($undefined.Text)" }
            $symbolText = Invoke-Checked $nm @("-a", "-S", $elf) (Join-Path $caseDir "symbols.txt")
            $symbols = @(Read-Symbols $symbolText.Text)
            $trap = Get-ExactSymbol $symbols "fiber_secure_context_pool_fail_closed"
            if ($trap.Size -eq 0 -or $trap.Type -cnotmatch '^[tT]$') { throw "Missing real fail-closed code range" }
            $disassembly = Invoke-Checked $objdump @("-drwC", $elf) (Join-Path $caseDir "pool.dis")
            $trapDis = Invoke-Checked $objdump @("-d", "--disassemble=fiber_secure_context_pool_fail_closed", $elf) `
                (Join-Path $caseDir "fail-closed.dis")
            $udf = @([regex]::Matches($trapDis.Text,
                '(?im)^\s*([0-9a-f]+):\s+(?:[0-9a-f]{4,8}\s+)+udf(?:\.w)?\s') |
                ForEach-Object { [Convert]::ToUInt64($_.Groups[1].Value, 16) })
            if ($udf.Count -eq 0) { throw "Production fail-closed symbol contains no decoded UDF" }
            $target = [pscustomobject]@{ Start = ($trap.Address -band [uint64]4294967294);
                End = (($trap.Address -band [uint64]4294967294) + $trap.Size); UdfAddresses = $udf }
            $poolStart = Get-ExactSymbol $symbols "__pool_start"
            $poolEnd = Get-ExactSymbol $symbols "__pool_end"
            $bssStart = Get-ExactSymbol $symbols "__bss_start"
            $bssEnd = Get-ExactSymbol $symbols "__bss_end"
            $state = Get-ExactSymbol $symbols "fiber_secure_context_pool_state"
            if ($poolStart.Address -ne 0x20000000 -or $poolEnd.Address - $poolStart.Address -ne 480 -or
                    $state.Size -ne 4 -or $state.Type -cnotmatch '^[bB]$' -or
                    $state.Address -lt $bssStart.Address -or $state.Address + 4 -gt $bssEnd.Address) {
                throw "Pool NOLOAD geometry or independent zero-initialized readiness marker changed"
            }
            $sections = Invoke-Checked $objdump @("-h", $elf) (Join-Path $caseDir "sections.txt")
            if ($sections.Text -notmatch '(?m)^\s*\d+\s+\.fiber_secure_context_pool\s+000001e0\s+20000000[^\r\n]*2\*\*3\r?\n\s+ALLOC\s*$') {
                throw "Pool section must remain an aligned 480-byte NOLOAD allocation"
            }
            if ($symbols.Name -match '^fiber_(?:secure_gateway|secure_context_gateway|port_)' -or
                    $symbols.Name -match '^(?:SVC_Handler|PendSV_Handler|fiber_init|fiber_start)$' -or
                    $sections.Text -match '\.gnu\.sgstubs') {
                throw "Memory-only fixture acquired NSC or fiber runtime activation"
            }
            $initDis = Invoke-Checked $objdump @("-d", "--disassemble=fiber_secure_context_pool_boot_initialize", $elf) `
                (Join-Path $caseDir "initialize.dis")
            $lowLoops = @([regex]::Matches($initDis.Text,
                '(?im)^\s*[0-9a-f]+:\s+(?:[0-9a-f]{4,8}\s+)+(dls|wls|le|dlstp|wlstp|letp)\b') |
                ForEach-Object { $_.Groups[1].Value })
            $wslElf = Convert-ToWsl $elf
            $seconds = if ($case.Id -eq 7) { 1 } else { $TimeoutSeconds }
            $run = Invoke-Recorded $wsl @("-d", $WslDistro, "--exec", "bash", $wslScript,
                "run", $QemuRoot, $wslOut, "mps3-an547", $wslElf, "$seconds") (Join-Path $caseDir "qemu.log")
            $classification = Classify-Run $run $case $target
            $isControl = $case.ContainsKey("Reject")
            $receipts.Add([pscustomobject]@{ Mode = $mode.Name; Case = $case.Name;
                ClassifierControl = $isControl; ExitCode = $run.ExitCode;
                Classification = $classification; FailClosed = $target;
                InitializeLowOverheadInstructions = $lowLoops;
                Elf = $elf; ElfSha256 = (Get-FileHash $elf -Algorithm SHA256).Hash })
            $receipts | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $out "receipts.json") -Encoding ASCII
            if ($isControl) {
                if ($classification.Pass -or $classification.Reason -ne $case.Reject -or
                        ($case.Id -eq 7 -and $run.ExitCode -ne 124)) {
                    throw "Harness control $($case.Name) did not reject for $($case.Reject): $($run.Text)"
                }
                Write-Host "PASS classifier rejection: $($case.Name) ($($classification.Reason))"
            }
            else {
                if (!$classification.Pass) {
                    throw "QEMU $($mode.Name)/$($case.Name) rejected: $($classification.Reason)`n$($run.Text)`nEvidence: $out"
                }
                Write-Host "PASS actual M55 $($mode.Name)/$($case.Name) (exit $($run.ExitCode))"
            }
        }
        $modesReceipt.Add([pscustomobject]@{ Name = $mode.Name; Flags = $flags;
            ProductionObject = $poolObject; ProductionObjectSha256 = (Get-FileHash $poolObject -Algorithm SHA256).Hash })
    }
    $withLoops = @($receipts | Where-Object { !$_.ClassifierControl -and $_.InitializeLowOverheadInstructions.Count -gt 0 })
    if ($withLoops.Count -eq 0) { throw "No production initializer retained default M55 low-overhead loops; qualification changed" }
    $sourcesAfter = @($inputPaths | ForEach-Object { Get-FileHash -LiteralPath $_ -Algorithm SHA256 } |
        Select-Object Path, Hash)
    $sourcesAfter | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $out "inputs-after.json") -Encoding ASCII
    if (Compare-Object $sourcesBefore $sourcesAfter -Property Path, Hash) {
        throw "An input changed during qualification; do not attribute mixed-source receipts to one snapshot"
    }
    $verdict = "PASS"
}
finally {
    [pscustomobject]@{ Verdict = $verdict; Machine = "mps3-an547"; WslDistro = $WslDistro;
        QemuRoot = $QemuRoot; SecureBoot = $true; NonSecureRuntime = $false;
        WholeTrustZoneQualification = $false; BranchCountCounterflag = $false;
        Modes = @($modesReceipt.ToArray()); Runs = @($receipts.ToArray()) } |
        ConvertTo-Json -Depth 10 | Set-Content (Join-Path $out "results.json") -Encoding ASCII
    Get-ChildItem -LiteralPath $out -Recurse -File | Where-Object { $_.Name -ne "sha256.csv" } |
        Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash |
        Export-Csv -LiteralPath (Join-Path $out "sha256.csv") -NoTypeInformation -Encoding ASCII
}
Write-Host "PASS C55S private pool: 16 actual M55 runs, 4 rejected harness controls; evidence: $out"
