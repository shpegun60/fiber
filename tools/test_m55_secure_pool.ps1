param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$BuildRoot,
    [string]$Python = "python",
    [string]$PythonModules = $env:FIBER_CLASSIC_AUDIT_PYTHONPATH,
    [string]$FreeRtosRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixtures = Join-Path $PSScriptRoot "fixtures\m55_secure_pool"
$port = Join-Path $repo "fiber\port\ARM_CM55\secure"
if (-not $ArmGcc) {
    $command = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($command) { $ArmGcc = $command.Source }
    else {
        $found = Get-ChildItem -Path C:\ST -Recurse -Filter arm-none-eabi-gcc.exe `
            -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $ArmGcc = $found.FullName }
    }
}
if (-not $ArmGcc -or -not (Test-Path -LiteralPath $ArmGcc)) {
    throw "Set -ArmGcc to arm-none-eabi-gcc.exe"
}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin "arm-none-eabi-gcc-nm.exe"
$objdump = Join-Path $bin "arm-none-eabi-objdump.exe"
foreach ($required in @($nm, $objdump, (Join-Path $port "fiber_secure_context_pool.c"),
        (Join-Path $fixtures "linkage.cpp"), (Join-Path $fixtures "run_pool.py"))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Missing dependency: $required" }
}
if (-not $FreeRtosRoot) {
    $FreeRtosRoot = Join-Path $repo "..\..\..\..\_reference\FreeRTOS-Kernel"
}
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
if (-not $BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ("fiber-m55-secure-pool-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $build -Force | Out-Null
$transcript = Join-Path $build "commands.log"

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    Add-Content -LiteralPath $transcript -Value `
        ((@($Program) + $Arguments | ConvertTo-Json -Compress)) -Encoding ASCII
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = @(& $Program @Arguments 2>&1)
    $status = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($output.Count) {
        Add-Content -LiteralPath $transcript -Value ($output -join "`n") -Encoding ASCII
    }
    if ($status -ne 0) { throw "$Program failed ($status): $($output -join "`n")" }
}

$oldPythonPath = $env:PYTHONPATH
try {
    if (-not $PythonModules) {
        $cached = Join-Path ([IO.Path]::GetTempPath()) "fiber-classic-audit-python"
        if (Test-Path -LiteralPath $cached) { $PythonModules = $cached }
    }
    if ($PythonModules) {
        $env:PYTHONPATH = $PythonModules + [IO.Path]::PathSeparator + $oldPythonPath
    }
    try {
        Invoke-Checked $Python @("-c", `
            "import sys, importlib.metadata as m; sys.flags.optimize == 0 or sys.exit('Disable PYTHONOPTIMIZE for maintained assertions'); assert m.version('unicorn') == '2.1.4'; assert m.version('pyelftools') == '0.33'; print(sys.executable); print(sys.version)")
    }
    catch {
        throw "Required pinned packages are unavailable. Install tools/fixtures/classic_audit/requirements.txt as described in tools/fixtures/m55_secure_pool/README.md. $($_.Exception.Message)"
    }
    $pin = "a50edad08b29052631aa469d4df6e6ec7ff68878"
    $actual = (& git -C $FreeRtosRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actual -ne $pin) {
        throw "FreeRTOS HEAD differs from the audited pin: $actual"
    }
    Invoke-Checked "git" @("-C", $FreeRtosRoot, "diff", "--exit-code", "HEAD", "--")
    $referenceFiles = @("secure_context.c", "secure_context.h", "secure_context_port.c",
        "secure_init.c", "secure_port_macros.h", "secure_heap.c")
    $evidence = foreach ($relative in $referenceFiles) {
        $path = Join-Path $FreeRtosRoot ("portable/GCC/ARM_CM55/secure/" + $relative)
        [pscustomobject]@{ Path = $relative; Sha256 = (Get-FileHash $path -Algorithm SHA256).Hash }
    }
    [pscustomobject]@{ Pin = $pin; Files = @($evidence); Comparison = @(
        "Reference no-MPU/no-FP SecureContext uses index-plus-one handles, opaque owners, PSP at requested top, and two seal words above that top.",
        "Fiber uses bounded static lifetime instead of secure_heap; no free operation, register setup, or NSC gateway is exercised here.",
        "Fresh BSS gates the retained NOLOAD image; interruptions are real instruction-hook stops, not an allocator model."
    ) } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $build "reference.json") -Encoding ASCII
    $sourcePaths = @((Join-Path $port "fiber_secure_context_pool.c"),
        (Join-Path $port "fiber_secure_context_pool.h"),
        (Join-Path $port "fiber_secure_context_gateway_contract.h"),
        (Join-Path $repo "fiber\fiber_api_attributes.h"))
    $sourcePaths += @(Get-ChildItem -LiteralPath $fixtures -File | Select-Object -ExpandProperty FullName)
    $sources = $sourcePaths | ForEach-Object {
        $path = $_
        [pscustomobject]@{ Path = $path; Sha256 = (Get-FileHash $path -Algorithm SHA256).Hash }
    }
    ConvertTo-Json -InputObject @($sources) | Set-Content (Join-Path $build "sources.json") -Encoding ASCII
    # Mechanical mutations of the compiled production source live only in the
    # evidence directory. Fail if source edits make either mutation ambiguous.
    $originalPool = [IO.File]::ReadAllText((Join-Path $port "fiber_secure_context_pool.c"))
    $mutationDir = Join-Path $build "mutant-sources"
    New-Item -ItemType Directory -Path $mutationDir | Out-Null
    $mutations = @(
        @{Name="ready-readback";
          Function='(?ms)^uint32_t\s+fiber_secure_context_pool_boot_initialize\(void\)\s*\{.*?^\}';
          Guard='(?s)if\s*\(fiber_secure_context_pool_state\s*!=\s*fiber_secure_contextPOOL_READY\)\s*\{\s*fiber_secure_context_pool_fail_closed\(\);\s*\}';
          Replacement='/* Deliberate mutant: final READY readback removed. */'},
        @{Name="early-free-break";
          Function='(?ms)^FiberSecureContextHandle\s+fiber_secure_context_pool_allocate\([^)]*\)\s*\{.*?^\}';
          Guard='first_free\s*=\s*index;';
          Replacement="first_free = index;`n`t`t`t`tbreak; /* Deliberate mutant: skip later records. */"})
    foreach ($mutation in $mutations) {
        $functions = [regex]::Matches($originalPool, $mutation.Function)
        if ($functions.Count -ne 1) { throw "Mutant function anchor changed: $($mutation.Name)" }
        $function = $functions[0]
        $guards = [regex]::Matches($function.Value, $mutation.Guard)
        if ($guards.Count -ne 1) { throw "Mutant guard anchor changed: $($mutation.Name)" }
        $guard = $guards[0]
        $body = $function.Value.Substring(0, $guard.Index) + $mutation.Replacement +
            $function.Value.Substring($guard.Index + $guard.Length)
        $changed = $originalPool.Substring(0, $function.Index) + $body +
            $originalPool.Substring($function.Index + $function.Length)
        $mutation.Source = Join-Path $mutationDir ($mutation.Name + ".c")
        Set-Content -LiteralPath $mutation.Source -Value $changed -Encoding ASCII -NoNewline
        $mutation.Sha256 = (Get-FileHash -LiteralPath $mutation.Source -Algorithm SHA256).Hash
    }
    Invoke-Checked $ArmGcc @("--version")

    $base = @("-mcpu=cortex-m55", "-mthumb", "-mcmse", "-mfloat-abi=soft",
        "-mgeneral-regs-only", "-ffreestanding", "-fno-builtin", "-fno-common",
        "-fstrict-aliasing", "-Wstrict-aliasing=2", "-Wcast-align=strict",
        "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Werror",
        "-I$port", "-I$repo")
    $cohorts = @(@{Count=1; Capacity=8}, @{Count=3; Capacity=128}, @{Count=5; Capacity=256})
    $runs = @()
    $mutantRuns = @()
    $attributeProbes = 0
    foreach ($cohort in $cohorts) {
        foreach ($optimization in @("-O2", "-Os")) {
            foreach ($lto in @($false, $true)) {
                $name = "n$($cohort.Count)-s$($cohort.Capacity)-" + $optimization.Substring(1)
                if ($lto) { $name += "-lto" }
                $baselineElf = $null
                $attributeElf = $null
                foreach ($variant in @("baseline", "execute")) {
                    $dir = Join-Path $build (Join-Path $name $variant)
                    New-Item -ItemType Directory -Path $dir | Out-Null
                    $flags = $base + @($optimization,
                        "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=$($cohort.Count)",
                        "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=$($cohort.Capacity)")
                    if ($lto) { $flags += "-flto" }
                    # Unicorn has no M55 low-overhead-loop implementation. Preserve
                    # untouched baseline codegen too; never model DLS/LE in Python.
                    if ($variant -eq "execute") { $flags += "-fno-branch-count-reg" }
                    $pool = Join-Path $dir "pool.o"
                    $cpp = Join-Path $dir "linkage.o"
                    Invoke-Checked $ArmGcc ($flags + @("-std=c11", "-save-temps=obj", "-c",
                        (Join-Path $port "fiber_secure_context_pool.c"), "-o", $pool))
                    Invoke-Checked $ArmGcc ($flags + @("-x", "c++", "-std=c++17",
                        "-fno-exceptions", "-fno-rtti", "-fno-threadsafe-statics", "-save-temps=obj",
                        "-c", (Join-Path $fixtures "linkage.cpp"), "-o", $cpp))
                    $poolUndefined = @(& $nm -u $pool)
                    if ($LASTEXITCODE -ne 0 -or $poolUndefined.Count -ne 0) {
                        throw "Pool gained runtime/helper dependencies ($name): $poolUndefined"
                    }
                    $cppUndefined = @(& $nm -u $cpp | ForEach-Object {
                        if ($_ -match '\bU\s+(\S+)$') { $Matches[1] }
                    } | Sort-Object -Unique)
                    $expected = @("fiber_secure_context_pool_allocate",
                        "fiber_secure_context_pool_boot_initialize",
                        "fiber_secure_context_pool_lookup_owned") | Sort-Object
                    if ($LASTEXITCODE -ne 0 -or $cppUndefined.Count -ne 3 -or
                            (Compare-Object -ReferenceObject $expected -DifferenceObject $cppUndefined)) {
                        throw "C++ header linkage changed ($name): $cppUndefined"
                    }
                    $elf = Join-Path $dir "pool.elf"
                    $keep = @("m55_pool_cpp_initialize", "m55_pool_cpp_allocate",
                        "m55_pool_cpp_lookup", "m55_pool_geometry") | ForEach-Object { "-Wl,-u,$_" }
                    Invoke-Checked $ArmGcc ($flags + @("-nostdlib", "-Wl,--gc-sections",
                        "-Wl,--no-undefined", "-Wl,-T,$(Join-Path $fixtures 'probe.ld')",
                        "-Wl,-Map,$(Join-Path $dir 'pool.map')") + $keep + @($pool, $cpp, "-o", $elf))
                    $undefined = @(& $nm -u $elf)
                    if ($LASTEXITCODE -ne 0 -or $undefined.Count -ne 0) {
                        throw "ELF has undefined dependencies ($name): $undefined"
                    }
                    $disassembly = (& $objdump -dr $elf) -join "`n"
                    if ($LASTEXITCODE -ne 0) { throw "objdump failed ($name)" }
                    Set-Content (Join-Path $dir "pool.dis") $disassembly -Encoding ASCII
                    if ($disassembly -match '(?im)^\s*[0-9a-f]+:\s+(?:[0-9a-f]+\s+)+(?:mrs|msr|cpsid|cpsie|sg|bxns|blxns|v[a-z][a-z0-9.]*|wfe|wfi)\b') {
                        throw "CPU/FP/gateway instruction appeared in the pure pool ($name)"
                    }
                    if ($variant -eq "baseline") {
                        $baselineElf = $elf
                        if ($cohort.Count -eq 3) {
                            $attributeObject = Join-Path $dir "sensitive.o"
                            $attributeElf = Join-Path $dir "sensitive.elf"
                            $hostile = @("-finstrument-functions", "-fstack-protector-all",
                                "-fsanitize=undefined", "-fprofile-arcs", "-ftest-coverage")
                            Invoke-Checked $ArmGcc ($flags + $hostile + @("-std=c11", "-c",
                                (Join-Path $port "fiber_secure_context_pool.c"), "-o", $attributeObject))
                            Invoke-Checked $ArmGcc ($flags + @("-nostdlib", "-Wl,--gc-sections",
                                "-Wl,--no-undefined", "-Wl,-T,$(Join-Path $fixtures 'probe.ld')") +
                                $keep + @($attributeObject, $cpp, "-o", $attributeElf))
                            $attributeUndefined = @(& $nm -u $attributeElf)
                            if ($LASTEXITCODE -ne 0 -or $attributeUndefined.Count -ne 0) {
                                throw "Sensitive attributes allowed implicit runtime dependencies ($name): $attributeUndefined"
                            }
                            $attributeProbes++
                        }
                    }
                    else {
                        if ($disassembly -match '(?im)^\s*[0-9a-f]+:\s+(?:[0-9a-f]+\s+)+(?:dls|wls|le|dlstp|wlstp|letp)\b') {
                            throw "Unicorn execution build still contains unsupported low-overhead loops ($name)"
                        }
                        $runs += [pscustomobject]@{ Name=$name; Elf=$elf; Count=$cohort.Count;
                            Capacity=$cohort.Capacity; Lto=$lto; Optimization=$optimization;
                            BaselineElf=$baselineElf; AttributeElf=$attributeElf;
                            ExecutionCounterflag="-fno-branch-count-reg" }
                        if ($cohort.Count -eq 3) {
                            foreach ($mutation in $mutations) {
                                $mutantDir = Join-Path $dir $mutation.Name
                                New-Item -ItemType Directory -Path $mutantDir | Out-Null
                                $mutantObject = Join-Path $mutantDir "pool.o"
                                $mutantElf = Join-Path $mutantDir "pool.elf"
                                Invoke-Checked $ArmGcc ($flags + @("-std=c11", "-save-temps=obj",
                                    "-c", $mutation.Source, "-o", $mutantObject))
                                Invoke-Checked $ArmGcc ($flags + @("-nostdlib", "-Wl,--gc-sections",
                                    "-Wl,--no-undefined", "-Wl,-T,$(Join-Path $fixtures 'probe.ld')") +
                                    $keep + @($mutantObject, $cpp, "-o", $mutantElf))
                                $mutantDisassembly = (& $objdump -dr $mutantElf) -join "`n"
                                if ($LASTEXITCODE -ne 0) { throw "Mutant objdump failed ($name)" }
                                Set-Content (Join-Path $mutantDir "pool.dis") $mutantDisassembly -Encoding ASCII
                                $mutantRuns += [pscustomobject]@{ Name=($name + "/" + $mutation.Name);
                                    Elf=$mutantElf; Count=$cohort.Count; Capacity=$cohort.Capacity;
                                    Scenario=$mutation.Name; Source=$mutation.Source;
                                    SourceSha256=$mutation.Sha256 }
                            }
                        }
                    }
                    Write-Host "Built $name/$variant"
                }
            }
        }
    }

    $badManifests = @(
        @{Name="zero-count"; Count="0"; Capacity="128"; Error="count must be non-zero"},
        @{Name="handle-overflow"; Count="0xFFFFFFFFu"; Capacity="128"; Error="count exceeds handle range"},
        @{Name="zero-size"; Count="3"; Capacity="0"; Error="capacity is too small"},
        @{Name="small-size"; Count="3"; Capacity="7"; Error="capacity is too small"},
        @{Name="unaligned-size"; Count="3"; Capacity="9"; Error="eight-byte aligned"},
        @{Name="seal-overflow"; Count="3"; Capacity="0xFFFFFFF8u"; Error="overflows the seal allocation"})
    foreach ($case in $badManifests) {
        $args = $base + @("-std=c11", "-fsyntax-only",
            "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=$($case.Count)",
            "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=$($case.Capacity)",
            (Join-Path $fixtures "manifest.c"))
        $previous = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = @(& $ArmGcc @args 2>&1)
        $status = $LASTEXITCODE
        $ErrorActionPreference = $previous
        Add-Content -LiteralPath $transcript -Value `
            ((@($ArmGcc) + $args | ConvertTo-Json -Compress)) -Encoding ASCII
        Add-Content -LiteralPath $transcript -Value ($output -join "`n") -Encoding ASCII
        if ($status -eq 0 -or ($output -join "`n") -notmatch [regex]::Escape($case.Error)) {
            throw "Invalid manifest $($case.Name) failed for the wrong reason: $output"
        }
    }
    $manifest = Join-Path $build "runs.json"
    ConvertTo-Json -InputObject @($runs) -Depth 5 | Set-Content $manifest -Encoding ASCII
    Invoke-Checked $Python @((Join-Path $fixtures "run_pool.py"), $manifest)
    $mutantManifest = Join-Path $build "mutants.json"
    ConvertTo-Json -InputObject @($mutantRuns) -Depth 5 | Set-Content $mutantManifest -Encoding ASCII
    Invoke-Checked $Python @((Join-Path $fixtures "run_pool.py"), "--mutants", $mutantManifest)
    foreach ($source in $sources) {
        if ((Get-FileHash $source.Path -Algorithm SHA256).Hash -ne $source.Sha256) {
            throw "Pool source changed during qualification; rerun for coherent evidence: $($source.Path)"
        }
    }
    $result = Get-Content (Join-Path $build "results.json") -Raw | ConvertFrom-Json
    $mutantResult = Get-Content (Join-Path $build "mutant_results.json") -Raw | ConvertFrom-Json
    Write-Host "Executed $($result.checks) generated ARM calls, $($badManifests.Count) invalid manifests, $attributeProbes sensitive-attribute ELF probes"
    Write-Host "Killed $($mutantResult.killed) guard-removal mutants in $($mutantResult.checks) additional generated ARM calls"
    Write-Host "PASS C55S pool: $($runs.Count) Unicorn scalar ELFs (-fno-branch-count-reg); $($runs.Count) untouched default-M55 codegen-only ELFs"
    Write-Host "Evidence: $build"
}
finally {
    $env:PYTHONPATH = $oldPythonPath
}
