param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$Python = "python",
    [string]$ExpectedSvcSha256
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixture = Join-Path $PSScriptRoot "fixtures\cm33f_mpu_first_start_codegen"
$port = Join-Path $repo "fiber\port\ARM_CM33F_MPU\non_secure"
$svc = Join-Path $port "fiber_port_svc.c"
$boot = Join-Path $port "fiber_port_boot.c"
$pendsv = Join-Path $port "fiber_port_pendsv.c"
$contract = Join-Path $port "fiber_port_linker_contract.ld"
if (-not $ArmGcc) {
    $found = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $ArmGcc = $found.Source }
    else {
        $found = Get-ChildItem C:\ST -Recurse -Filter arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found) { $ArmGcc = $found.FullName }
    }
}
if (-not $ArmGcc) { throw "Set -ArmGcc to an existing ARM GCC executable" }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin "arm-none-eabi-nm.exe"
$gccNm = Join-Path $bin "arm-none-eabi-gcc-nm.exe"
$objdump = Join-Path $bin "arm-none-eabi-objdump.exe"
$readelf = Join-Path $bin "arm-none-eabi-readelf.exe"
if (-not $CmsisCore) { $CmsisCore = Join-Path $repo "..\..\..\Drivers\CMSIS\Include" }
if (-not $FreeRtosRoot) { $FreeRtosRoot = Join-Path $repo "..\..\..\..\_reference\FreeRTOS-Kernel" }
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
$reference = Join-Path $FreeRtosRoot "portable\GCC\ARM_CM33_NTZ\non_secure"
foreach ($path in @($nm, $gccNm, $objdump, $readelf, $svc, $boot, $pendsv, $contract,
        (Join-Path $reference "portasm.c"), (Join-Path $reference "port.c"),
        (Join-Path $CmsisCore "core_cm33.h"))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing codegen-proof dependency: $path" }
}
if ($ExpectedSvcSha256 -and (Get-FileHash -LiteralPath $svc -Algorithm SHA256).Hash -ne $ExpectedSvcSha256) {
    throw "C3FP SVC source does not match -ExpectedSvcSha256"
}
if (-not $BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ("cm33f-mpu-first-start-codegen-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $build -Force | Out-Null
$commands = Join-Path $build "commands.log"
Write-Host "C3FP first-start codegen artifacts: $build"

function Invoke-Proof {
    param([string]$Program, [string[]]$Arguments, [string]$Log, [switch]$AllowFailure)
    Add-Content -LiteralPath $commands -Encoding ASCII -Value `
        (ConvertTo-Json -Compress -InputObject (@($Program) + $Arguments))
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $lines = @(& $Program @Arguments 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $saved }
    $output = $lines -join "`n"
    if ($Log) { Set-Content -LiteralPath $Log -Value $output -Encoding ASCII }
    if ($output) { Add-Content -LiteralPath $commands -Value $output -Encoding ASCII }
    if ($code -ne 0 -and -not $AllowFailure) {
        $tail = ($lines | Select-Object -Last 12) -join "`n"
        throw "Codegen proof command failed ($code): $Program; full evidence $commands`n$tail"
    }
    return [pscustomobject]@{ExitCode=$code; Output=$output}
}

function Write-Json {
    param([string]$Path, [object]$Value)
    ConvertTo-Json -Depth 12 -InputObject $Value | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Save-ElfEvidence {
    param([string]$Elf)
    Invoke-Proof $objdump @("-d", $Elf) -Log ($Elf + ".dis") | Out-Null
    Invoke-Proof $nm @("-S", $Elf) -Log ($Elf + ".symbols") | Out-Null
    Invoke-Proof $readelf @("-A", "-S", "-s", "-W", $Elf) -Log ($Elf + ".readelf") | Out-Null
}

function Test-SensitiveDefinitions {
    param([string]$Preprocessed, [string[]]$Names)
    $text = Get-Content -LiteralPath $Preprocessed -Raw
    foreach ($name in $Names) {
        $definitions = [regex]::Matches($text, '(?s)\b' + [regex]::Escape($name) + '\s*\([^;{}]*\)\s*\{')
        if ($definitions.Count -ne 1) { throw "Missing/ambiguous preprocessed production definition: $name" }
        $definition = $definitions[0]
        $boundary = [Math]::Max($text.LastIndexOf(';', $definition.Index),
            [Math]::Max($text.LastIndexOf('{', $definition.Index), $text.LastIndexOf('}', $definition.Index)))
        $head = $text.Substring($boundary + 1, $definition.Index + $definition.Length - $boundary - 1)
        foreach ($attribute in @('noinline', 'noipa', 'noclone', 'no_icf', 'used', 'no_instrument_function',
                'no_stack_protector', 'no_sanitize', 'no_profile_instrument_function', 'no_sanitize_coverage')) {
            if ($head -notmatch ('\b' + $attribute + '\b')) { throw "Production sensitive attribute missing: $name/$attribute" }
        }
        if ($head -notmatch 'target\s*\(\s*"general-regs-only"\s*\)') {
            throw "Production general-register target attribute missing: $name"
        }
    }
}

function Test-Oracle {
    param([string]$Elf, [int]$Regions, [string]$ReferenceElf, [string]$ExpectedRejection)
    $manifest = @{Elf=$Elf; Disassembly=($Elf + ".dis"); Regions=$Regions}
    if ($ReferenceElf) {
        $manifest.ReferenceElf = $ReferenceElf
        $manifest.ReferenceDisassembly = $ReferenceElf + ".dis"
    }
    $manifestPath = $Elf + ".json"
    Write-Json $manifestPath $manifest
    $result = Invoke-Proof $Python @("-B", (Join-Path $fixture "check.py"), $manifestPath) `
        -Log ($Elf + ".check.log") -AllowFailure
    if ($ExpectedRejection) {
        if ($result.ExitCode -ne 1 -or $result.Output -cnotmatch ("^REJECT:" + $ExpectedRejection + ":") -or
                $result.Output -match "Traceback") {
            throw "Mutant did not hit exact oracle rejection $ExpectedRejection : $Elf`n$($result.Output)"
        }
    }
    elseif ($result.ExitCode -ne 0) { throw "Final-ELF codegen oracle failed: $Elf`n$($result.Output)" }
    return $result.Output
}

$pin = "a50edad08b29052631aa469d4df6e6ec7ff68878"
$inputPaths = @($PSCommandPath, $ArmGcc, $nm, $gccNm, $objdump, $readelf,
    (Join-Path $port "FREERTOS_PARITY.md"),
    (Join-Path $reference "port.c"), (Join-Path $reference "portasm.c"),
    (Join-Path $PSScriptRoot "fixtures\freertos_asm_parity\FreeRTOSConfig.h"),
    (Join-Path $PSScriptRoot "fixtures\cm33f_mpu_constructor\main.h"))
foreach ($tool in @("cc1", "lto1", "as", "ld", "collect2")) {
    $query = Invoke-Proof $ArmGcc @("-print-prog-name=$tool")
    $inputPaths += (Resolve-Path -LiteralPath $query.Output.Trim()).Path
}
$includeQuery = Invoke-Proof $ArmGcc @("-print-file-name=include")
$compilerInclude = (Resolve-Path -LiteralPath $includeQuery.Output.Trim()).Path
foreach ($directory in @($compilerInclude, (Join-Path (Split-Path $bin) "arm-none-eabi\include"))) {
    $inputPaths += @(Get-ChildItem -LiteralPath $directory -Recurse -File -Filter *.h |
        Select-Object -ExpandProperty FullName)
}
foreach ($directory in @($repo, (Join-Path $repo "fiber"), (Join-Path $repo "fiber\port"),
        $port, $reference, (Join-Path $FreeRtosRoot "include"), $CmsisCore)) {
    $inputPaths += @(Get-ChildItem -LiteralPath $directory -File |
        Where-Object { $_.Extension -in @(".h", ".c", ".ld") } | Select-Object -ExpandProperty FullName)
}
$inputPaths += @(Get-ChildItem -LiteralPath $fixture -File -Recurse |
    Where-Object { $_.FullName -notmatch '[\\/]__pycache__[\\/]' } | Select-Object -ExpandProperty FullName)
$hashes = @($inputPaths | Sort-Object -Unique | ForEach-Object {
    [pscustomobject]@{Path=$_; Sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
})
Write-Json (Join-Path $build "inputs.before.json") $hashes
$runs = @()
$negatives = @()
$success = $false
try {
    $head = Invoke-Proof "git" @("-C", $FreeRtosRoot, "rev-parse", "HEAD") -Log (Join-Path $build "reference-head.txt")
    if ($head.Output.Trim() -ne $pin) { throw "FreeRTOS reference must be pinned at $pin" }
    $clean = Invoke-Proof "git" @("-C", $FreeRtosRoot, "status", "--porcelain", "--untracked-files=all") `
        -Log (Join-Path $build "reference-status.before.txt")
    if ($clean.Output.Trim()) { throw "Pinned reference has tracked/untracked changes" }
    Invoke-Proof $ArmGcc @("--version") -Log (Join-Path $build "compiler.txt") | Out-Null
    Invoke-Proof $Python @("-B", "-c", "import sys; print(sys.executable); print(sys.version)") `
        -Log (Join-Path $build "python.txt") | Out-Null
    $common = @("-mcpu=cortex-m33", "-mthumb", "-mfpu=fpv5-sp-d16", "-std=gnu11",
        "-ffreestanding", "-fno-builtin", "-fno-common", "-ffunction-sections", "-fdata-sections",
        "-fno-unwind-tables", "-fno-asynchronous-unwind-tables")
    $warnings = @("-Wall", "-Wextra", "-Werror", "-Wundef", "-Werror=implicit-function-declaration")
    $includes = @("-I$(Join-Path $PSScriptRoot 'fixtures\cm33f_mpu_constructor')", "-I$port",
        "-I$(Join-Path $repo 'fiber\port')", "-I$(Join-Path $repo 'fiber')", "-I$repo", "-I$CmsisCore")
    $hostile = @("-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs", "-ftest-coverage",
        "-fsanitize=undefined", "-fsanitize-coverage=trace-pc")
    # CMSIS always-inline definitions do not inherit the caller's attributes.
    # These are the documented integration counter-options, not an attribute-
    # only hostile qualification of the complete call graph.
    $counters = @("-fno-instrument-functions", "-fno-stack-protector", "-fno-profile-arcs",
        "-fno-test-coverage", "-fno-sanitize=all", "-fno-sanitize-coverage=trace-pc", "-mgeneral-regs-only")
    $linker = Join-Path $fixture "production.ld"
    foreach ($regions in @(8, 16)) {
        foreach ($abi in @("hard", "softfp")) {
            foreach ($optimization in @("-O2", "-Os")) {
                foreach ($lto in @($false, $true)) {
                    $name = "r$regions-$abi-$($optimization.Substring(1))" + $(if ($lto) {"-lto"} else {""})
                    $dir = Join-Path $build $name
                    New-Item -ItemType Directory -Path $dir | Out-Null
                    $base = $common + @("-mfloat-abi=$abi", $optimization) + $(if ($lto) {@("-flto")} else {@()})
                    $flags = $base + $warnings + $includes + @("-DFIBER_PORT_BUILD_SELECTED=1",
                        "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$regions")
                    $provider = Join-Path $dir "test-only-providers.o"
                    Invoke-Proof $ArmGcc ($flags + @("-MMD", "-c", (Join-Path $fixture "providers.c"), "-o", $provider)) | Out-Null
                    $providerSymbols = Invoke-Proof $gccNm @("-g", "--defined-only", $provider) -Log ($provider + ".exports")
                    # LTO IR reports this initialized object as D; the final
                    # ELF oracle separately verifies readonly size/value/load.
                    if ([regex]::Matches($providerSymbols.Output,
                            '(?m)^\S+\s+[DR]\s+fiber_internal_runtime_port_abi_v1_anchor\s*$').Count -ne 1) {
                        throw "Test provider must define the strong external reverse-v1 marker: $name"
                    }
                    if ($providerSymbols.Output -match '\bfiber_port_(?:context|storage)_cohort_|\bfiber_port_(?:runtime_\w+|panic_wait|require_scheduler_configuration_environment|handler_bundle_v1_anchor)\b') {
                        throw "Fixture must not supply production forward operations, bundle, or cohort providers: $name"
                    }
                    $controlObject = Join-Path $dir "unprotected-hostile-control.o"
                    Invoke-Proof $ArmGcc ($flags + $hostile + @("-c", (Join-Path $fixture "instrumentation_control.c"),
                        "-o", $controlObject)) | Out-Null
                    $controlSymbols = Invoke-Proof $gccNm @("-a", $controlObject) -Log ($controlObject + ".symbols")
                    # In LTO, inspect the same effective options in a concrete
                    # control object as well; its symbols are otherwise IR-only.
                    if ($lto) {
                        Invoke-Proof $ArmGcc ($flags + $hostile + @("-fno-lto", "-c",
                            (Join-Path $fixture "instrumentation_control.c"), "-o", ($controlObject + ".native.o"))) | Out-Null
                        $controlSymbols = Invoke-Proof $nm @("-a", ($controlObject + ".native.o")) `
                            -Log ($controlObject + ".native.symbols")
                    }
                    foreach ($family in @("__cyg_profile", "__stack_chk", "__gcov", "__ubsan", "__sanitizer_cov")) {
                        if ($controlSymbols.Output -notmatch [regex]::Escape($family)) {
                            throw "Hostile compiler option is not effective in unprotected control: $family/$name"
                        }
                    }
                    $refFlags = $base + @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1",
                        "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=$regions", "-I$(Join-Path $fixture 'reference')",
                        "-I$(Join-Path $FreeRtosRoot 'include')", "-I$reference")
                    $refObjects = @()
                    foreach ($unit in @("port.c", "portasm.c", "providers.c")) {
                        $source = if ($unit -eq "providers.c") { Join-Path $fixture "reference\providers.c" } else { Join-Path $reference $unit }
                        $object = Join-Path $dir ("reference-" + $unit.Replace(".c", ".o"))
                        Invoke-Proof $ArmGcc ($refFlags + @("-save-temps=obj", "-MMD", "-c", $source, "-o", $object)) | Out-Null
                        $refObjects += $object
                    }
                    $refElf = Join-Path $dir "actual-freertos.elf"
                    Invoke-Proof $ArmGcc ($base + @("-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings",
                        "-Wl,-T,$(Join-Path $fixture 'reference.ld')", "-Wl,-Map,$refElf.map") + $refObjects + @("-o", $refElf)) | Out-Null
                    Save-ElfEvidence $refElf
                    foreach ($policy in @("normal", "countered-hostile")) {
                        $objects = @()
                        $effective = $flags + $(if ($policy -eq "countered-hostile") {$hostile + $counters} else {@()})
                        foreach ($unit in @(@{Name="boot"; Path=$boot}, @{Name="svc"; Path=$svc},
                                @{Name="pendsv"; Path=$pendsv})) {
                            $object = Join-Path $dir ($policy + "-" + $unit.Name + ".o")
                            Invoke-Proof $ArmGcc ($effective + @("-save-temps=obj", "-MMD", "-c", $unit.Path, "-o", $object)) | Out-Null
                            if ($unit.Name -in @("svc", "pendsv")) {
                                $surface = Invoke-Proof $gccNm @("-g", "--defined-only", $object) -Log ($object + ".exports")
                                $actual = @([regex]::Matches($surface.Output, '(?m)^\S+\s+T\s+(\w+)\s*$') |
                                    ForEach-Object {$_.Groups[1].Value} | Sort-Object)
                                $expected = if ($unit.Name -eq "svc") {
                                    @("fiber_port_prepare_first_start", "fiber_port_svc_dispatch", "fiber_port_start_first_context",
                                      "fiber_port_restore_first_context_from_svc", "SVC_Handler",
                                      "fiber_port_yield_from_thread", "fiber_port_unprivileged_task_return",
                                      "fiber_port_runtime_memory_barrier", "fiber_port_panic_wait",
                                      "fiber_port_require_scheduler_configuration_environment", "fiber_port_runtime_prepare_start",
                                      "fiber_port_runtime_select_first", "fiber_port_runtime_start_first", "fiber_port_runtime_schedule",
                                      "fiber_port_handler_bundle_v1_anchor", "fiber_port_primask_save_disable", "fiber_port_primask_restore")
                                } else {
                                    @("fiber_port_context_validate_restore", "fiber_port_pendsv_validate_save_current",
                                      "fiber_port_scheduler_pick_next_from_pendsv", "fiber_port_mpu_switch_to_context",
                                      "fiber_port_mpu_validate_active_context", "PendSV_Handler",
                                      "fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor",
                                      "fiber_port_scheduler_pick_first_from_start")
                                }
                                # gcc-nm sees IR declarations, not an inline-asm
                                # global label. The final-ELF oracle proves that
                                # label in every mode, including full LTO.
                                if (-not $lto -and $unit.Name -eq "svc") {
                                    $expected += @("fiber_port_svc_start_return_site", "fiber_port_svc_yield_return_site",
                                        "fiber_port_svc_return_return_site")
                                }
                                $expected = @($expected | Sort-Object)
                                if (($actual.Count -ne $expected.Count) -or (Compare-Object $expected $actual)) {
                                    throw "Exact production $($unit.Name) function/return-site surface changed: $name/$policy"
                                }
                                $cohorts = @([regex]::Matches($surface.Output,
                                    '(?m)^\S+\s+[DR]\s+(fiber_port_(?:context|storage)_cohort_\w+)\s*$') |
                                    ForEach-Object {$_.Groups[1].Value})
                                if ($unit.Name -eq 'svc') {
                                    if ($cohorts.Count -ne 2 -or
                                            @($cohorts | Where-Object {$_ -cmatch '^fiber_port_context_cohort_armv8m_mainline_p0x43334650u_l0x000100(?:08|10)u_'}).Count -ne 1 -or
                                            @($cohorts | Where-Object {$_ -ceq "fiber_port_storage_cohort_arm_cm33f_mpu_v1_r$regions"}).Count -ne 1) {
                                        throw "Production SVC must own exactly the C3FP context/storage provider pair: $name/$policy"
                                    }
                                    Test-SensitiveDefinitions ([IO.Path]::ChangeExtension($object, '.i')) @(
                                        'fiber_port_runtime_memory_barrier', 'fiber_port_panic_wait',
                                        'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_prepare_start',
                                        'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first', 'fiber_port_runtime_schedule',
                                        'fiber_port_handler_bundle_v1_anchor', 'fiber_port_primask_save_disable', 'fiber_port_primask_restore')
                                } else {
                                    if ($cohorts.Count) { throw "PendSV must retain, not define, cohort providers: $name/$policy" }
                                    Test-SensitiveDefinitions ([IO.Path]::ChangeExtension($object, '.i')) @(
                                        'fiber_port_scheduler_pick_first_from_start', 'fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor')
                                }
                            }
                            if (-not $lto) {
                                Invoke-Proof $objdump @("-dr", $object) -Log ($object + ".dis") | Out-Null
                            }
                            $objects += $object
                        }
                        $elf = Join-Path $dir ($policy + ".elf")
                        Invoke-Proof $ArmGcc ($flags + @("-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings",
                            "-Wl,-T,$linker", "-Wl,-T,$contract", "-Wl,-Map,$elf.map") + $objects + @($provider, "-o", $elf)) | Out-Null
                        Save-ElfEvidence $elf
                        $observation = Test-Oracle $elf $regions $refElf
                        $runs += [pscustomobject]@{Name=$name; Policy=$policy; Elf=$elf; Reference=$refElf; Observation=($observation | ConvertFrom-Json)}
                        if ($policy -eq "normal" -and $abi -eq "hard" -and $optimization -eq "-O2") {
                            # Real separately compiled broken SVC components; the
                            # production files are never rewritten by this runner.
                            . (Join-Path $fixture "mutants.ps1")
                            $negatives += @(Test-CodegenMutants -Directory $dir -Flags $flags -Objects $objects `
                                -Provider $provider -Regions $regions -Source $svc -SvcObject $objects[1] `
                                -Linker $linker -Contract $contract)
                        }
                    }
                    Write-Host "C3FP first-start codegen checked: $name / normal + countered-hostile"
                }
            }
        }
    }
    if ($runs.Count -ne 32 -or $negatives.Count -ne 60) {
        throw "Incomplete 16-configuration first-start/service-surface grid"
    }
    Write-Json (Join-Path $build "runs.json") $runs
    Write-Json (Join-Path $build "negatives.json") $negatives
    $clean = Invoke-Proof "git" @("-C", $FreeRtosRoot, "status", "--porcelain", "--untracked-files=all") `
        -Log (Join-Path $build "reference-status.after.txt")
    if ($clean.Output.Trim()) { throw "Pinned reference changed during qualification" }
    $success = $true
}
finally {
    $after = @($hashes | ForEach-Object {
        [pscustomobject]@{Path=$_.Path; Sha256=(Get-FileHash -LiteralPath $_.Path -Algorithm SHA256).Hash}
    })
    Write-Json (Join-Path $build "inputs.after.json") $after
    $beforeByPath = @{}
    foreach ($hash in $hashes) { $beforeByPath[$hash.Path] = $hash.Sha256 }
    $drift = @($after | Where-Object { $_.Sha256 -ne $beforeByPath[$_.Path] })
    $artifacts = @(Get-ChildItem -LiteralPath $build -Recurse -File | ForEach-Object {
        [pscustomobject]@{Path=$_.FullName.Substring($build.Length + 1); Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    Write-Json (Join-Path $build "artifacts.json") $artifacts
    if ($drift.Count) { throw "Source/tool input drift; no qualification: $($drift.Path -join ', '); evidence $build" }
}
if ($success) {
    Write-Host "PASS C3FP first-start codegen: 16 configurations, $($runs.Count) production ELF checks, $($negatives.Count) compiled/link negatives; no execution; artifacts $build"
}
