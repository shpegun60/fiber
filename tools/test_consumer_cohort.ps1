param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($ArmGcc)) {
    $command = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($command) { $ArmGcc = $command.Source }
    elseif (Test-Path "C:\ST") {
        $candidate = Get-ChildItem "C:\ST" -Recurse -Filter arm-none-eabi-gcc.exe |
            Select-Object -First 1
        if ($candidate) { $ArmGcc = $candidate.FullName }
    }
}
if ([string]::IsNullOrWhiteSpace($ArmGcc) -or !(Test-Path $ArmGcc)) {
    throw "Set -ArmGcc or ARM_NONE_EABI_GCC to arm-none-eabi-gcc.exe."
}
$ArmGcc = (Resolve-Path $ArmGcc).Path
$Bin = Split-Path $ArmGcc
$Cxx = Join-Path $Bin "arm-none-eabi-g++.exe"
$Ar = Join-Path $Bin "arm-none-eabi-gcc-ar.exe"
$Nm = Join-Path $Bin "arm-none-eabi-gcc-nm.exe"
$Dump = Join-Path $Bin "arm-none-eabi-objdump.exe"
foreach ($tool in @($Cxx, $Ar, $Nm, $Dump)) {
    if (!(Test-Path $tool)) { throw "Missing required tool: $tool" }
}
if ([string]::IsNullOrWhiteSpace($CmsisCore)) {
    $CmsisCore = Join-Path $Repo "../../../Drivers/CMSIS/Include"
}
if (!(Test-Path (Join-Path $CmsisCore "core_cm33.h"))) {
    throw "Set -CmsisCore or CMSIS_CORE_INCLUDE to the real CMSIS core include directory."
}
$CmsisCore = (Resolve-Path $CmsisCore).Path
if ([string]::IsNullOrWhiteSpace($BuildRoot)) { $BuildRoot = [IO.Path]::GetTempPath() }
$Build = Join-Path $BuildRoot ("consumer-cohort-" + [Guid]::NewGuid().ToString("N"))
$null = New-Item -ItemType Directory -Path $Build -Force
$Commands = Join-Path $Build "commands.log"
$Results = New-Object System.Collections.Generic.List[object]
$script:CommandIndex = 0

function Invoke-Tool {
    param([string]$Tool, [string[]]$Arguments, [switch]$AllowFailure)
    ++$script:CommandIndex
    $log = Join-Path $Build ("command-{0:D4}.log" -f $script:CommandIndex)
    Add-Content -LiteralPath $Commands -Encoding ASCII -Value (
        '"' + $Tool + '" ' + (($Arguments | ForEach-Object { '"' + $_ + '"' }) -join " "))
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = @(& $Tool @Arguments 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    [IO.File]::WriteAllLines($log, [string[]]$output)
    Add-Content -LiteralPath $Commands -Encoding ASCII -Value "exit=$code log=$log"
    if (($code -ne 0) -and !$AllowFailure) {
        throw "Tool failed ($code): $Tool`n$($output -join "`n")`nArtifacts: $Build"
    }
    return [pscustomobject]@{ Code = $code; Text = ($output -join "`n"); Log = $log }
}

$PublicBase = @("-mthumb", "-mfloat-abi=soft", "-O2", "-ffreestanding",
    "-fno-common", "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra",
    "-Wundef", "-Werror", "-I$Repo", "-I$(Join-Path $Repo 'fiber')",
    "-I$(Join-Path $Repo 'fiber/port')", "-DFIBER_PORT_BUILD_SELECTED=1")
$Storage = Join-Path $PSScriptRoot "fixtures/consumer_cohort_storage.c"
$Driver = Join-Path $PSScriptRoot "fixtures/consumer_cohort_driver.c"
$Linker = Join-Path $PSScriptRoot "fixtures/consumer_cohort_runtime.ld"
$Profile = Join-Path $Repo "fiber/port/ARM_CM33_MPU/non_secure"

function Get-StorageIdentity {
    param([string[]]$Flags)
    $preprocessed = Invoke-Tool $ArmGcc ($Flags + @("-std=gnu11", "-E", "-P", $Storage))
    $identities = @([regex]::Matches($preprocessed.Text,
        'extern const unsigned char (fiber_port_storage_cohort_[A-Za-z0-9_]+);'))
    if ($identities.Count -ne 1) { throw "Expected exactly one expanded storage declaration." }
    return $identities[0].Groups[1].Value
}

# Compile all public complete types with no CMSIS include directory, in C/C++.
# Only the selected public type directory and compiler architecture are supplied.
$PublicProfiles = @(
    @("ARM_CM0", "cortex-m0", "ARMV6M", ""),
    @("ARM_CM3", "cortex-m3", "ARMV7M", ""),
    @("ARM_CM4", "cortex-m4", "ARMV7EM", ""),
    @("ARM_CM7/r0p1", "cortex-m7", "ARMV7EM", ""),
    @("ARM_CM0_MPU", "cortex-m0plus", "ARMV6M", ""),
    @("ARM_CM3_MPU", "cortex-m3", "ARMV7M", ""),
    @("ARM_CM4_MPU", "cortex-m4", "ARMV7EM", "FIBER_PORT_CM4_MPU_TOTAL_REGIONS"),
    @("ARM_CM23_NTZ/non_secure", "cortex-m23", "ARMV8M_BASELINE", ""),
    @("ARM_CM33_NTZ/non_secure", "cortex-m33", "ARMV8M_MAINLINE", ""),
    @("ARM_CM33F_NTZ/non_secure", "cortex-m33", "ARMV8M_MAINLINE", ""),
    @("ARM_CM33/non_secure", "cortex-m33", "ARMV8M_MAINLINE", ""),
    @("ARM_CM33_TFM/non_secure", "cortex-m33", "ARMV8M_MAINLINE", ""),
    @("ARM_CM33_MPU/non_secure", "cortex-m33", "ARMV8M_MAINLINE", "FIBER_PORT_CM33_MPU_TOTAL_REGIONS"),
    @("ARM_CM55_NTZ/non_secure", "cortex-m55+nomve+nofp", "ARMV81M_MAINLINE", ""),
    @("ARM_CM55F_NTZ/non_secure", "cortex-m55+nomve+nofp", "ARMV81M_MAINLINE", ""),
    @("ARM_CM55_MVEF_NTZ/non_secure", "cortex-m55+nomve+nofp", "ARMV81M_MAINLINE", ""),
    @("ARM_CM55/non_secure", "cortex-m55+nomve+nofp", "ARMV81M_MAINLINE", ""),
    @("ARM_CM55_MPU/non_secure", "cortex-m55+nomve+nofp", "ARMV81M_MAINLINE", "FIBER_PORT_CM55_MPU_TOTAL_REGIONS"),
    @("ARM_CM55F_MPU/non_secure", "cortex-m55+nomve+nofp", "ARMV81M_MAINLINE", "FIBER_PORT_CM55F_MPU_TOTAL_REGIONS"),
    @("ARM_CM55_MVEF_MPU/non_secure", "cortex-m55+nomve+nofp", "ARMV81M_MAINLINE", "FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS"),
    @("transitional_v8m", "cortex-m33", "ARMV8M_MAINLINE", "")
)
$invalidManifests = 0
foreach ($profileInfo in $PublicProfiles) {
    if (!$profileInfo[3]) { continue }
    foreach ($invalidRegions in @(0, 12)) {
        $flags = $PublicBase + @("-mcpu=$($profileInfo[1])", "-std=gnu11",
            "-DFIBER_PORT_$($profileInfo[2])=1", "-I$(Join-Path $Repo ('fiber/port/' + $profileInfo[0]))")
        if ($invalidRegions) { $flags += "-D$($profileInfo[3])=$invalidRegions" }
        $compile = Invoke-Tool $ArmGcc ($flags + @("-c", $Storage, "-o",
            (Join-Path $Build "invalid-manifest.o"))) -AllowFailure
        $diagnostic = if ($invalidRegions) { "supports exactly 8 or 16" } else { "requires an explicit" }
        if (($compile.Code -eq 0) -or ($compile.Text -notmatch $diagnostic)) {
            throw "Public storage guard bypassed raw manifest validation for $($profileInfo[0])."
        }
        ++$invalidManifests
    }
}
$publicCompiles = 0
foreach ($profileInfo in $PublicProfiles) {
    $regionVariants = if ($profileInfo[3]) { @(8, 16) } else { @(0) }
    foreach ($regions in $regionVariants) {
        $flags = $PublicBase + @("-mcpu=$($profileInfo[1])",
            "-DFIBER_PORT_$($profileInfo[2])=1", "-I$(Join-Path $Repo ('fiber/port/' + $profileInfo[0]))")
        if ($regions) { $flags += "-D$($profileInfo[3])=$regions" }
        $identity = Get-StorageIdentity $flags
        foreach ($language in @("c", "c++")) {
            $compiler = if ($language -eq "c") { $ArmGcc } else { $Cxx }
            $standard = if ($language -eq "c") { "-std=gnu11" } else { "-std=gnu++17" }
            foreach ($direct in @(0, 1, 2)) {
                $object = Join-Path $Build ("public-{0:D3}.o" -f $publicCompiles)
                $compileFlags = $flags + @($standard, "-x", $language)
                if ($direct) { $compileFlags += "-DFIBER_CONSUMER_DIRECT_TYPES=1" }
                if ($direct -eq 2) { $compileFlags += "-DFIBER_CONSUMER_DIRECT_EXPECTATION=1" }
                $null = Invoke-Tool $compiler ($compileFlags + @("-c", $Storage, "-o", $object))
                $undefined = Invoke-Tool $Nm @("-u", $object)
                $expectedCount = if ($direct -eq 1) { 0 } else { 1 }
                $actual = @([regex]::Matches($undefined.Text, '(?m)\bU\s+(\S+)\s*$') |
                    ForEach-Object { $_.Groups[1].Value })
                if (($actual.Count -ne $expectedCount) -or
                        (($expectedCount -ne 0) -and ($actual[0] -ne $identity))) {
                    throw "Public include dependency surface changed for $($profileInfo[0])/$language/$direct."
                }
                ++$publicCompiles
            }
        }
    }
}

$NoCmsisFlags = $PublicBase + @("-mcpu=cortex-m33", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
foreach ($source in @("fiber_core.c", "fiber_runtime_state.c", "fiber_panic.c",
        "fiber_runtime_context_configuration.c")) {
    $path = Join-Path $Repo ("fiber/" + $source)
    $null = Invoke-Tool $ArmGcc ($NoCmsisFlags + @("-std=gnu11", "-c", $path,
        "-o", (Join-Path $Build ("common-" + $source + ".o"))))
    $dependencies = Invoke-Tool $ArmGcc ($NoCmsisFlags + @("-std=gnu11", "-MM", $path))
    if ($dependencies.Text -match 'fiber_port_(storage_cohort|types|private|context_cohort|selected)\.h|[\\/]core_cm[0-9]+\.h') {
        throw "Common runtime gained a selected-port/storage/CMSIS dependency: $source"
    }
}

# Fresh runtime/boot/expectation are real library sources, not identity stubs.
$RuntimeBase = $NoCmsisFlags + @("-I$Profile", "-I$CmsisCore",
    "-I$(Join-Path $PSScriptRoot 'fixtures/consumer_cohort')", "-fno-builtin",
    "-fno-instrument-functions", "-fno-stack-protector", "-fno-profile-arcs",
    "-fno-test-coverage", "-fno-sanitize=all", "-mgeneral-regs-only",
    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables")
$modes = @(
    @{ Name = "o2"; Flags = @("-O2") },
    @{ Name = "os"; Flags = @("-Os") },
    @{ Name = "o2-lto"; Flags = @("-O2", "-flto") },
    @{ Name = "os-lto"; Flags = @("-Os", "-flto") }
)

foreach ($mode in $modes) {
    $dir = Join-Path $Build $mode.Name
    $null = New-Item -ItemType Directory -Path $dir
    $base = $RuntimeBase + $mode.Flags
    $commonObjects = @()
    foreach ($source in @("fiber_core.c", "fiber_runtime_state.c", "fiber_panic.c")) {
        $object = Join-Path $dir ($source + ".o")
        $null = Invoke-Tool $ArmGcc ($base + @("-std=gnu11", "-c",
            (Join-Path $Repo ("fiber/" + $source)), "-o", $object))
        $commonObjects += $object
    }
    $driverObject = Join-Path $dir "driver.o"
    $null = Invoke-Tool $ArmGcc ($base + @("-std=gnu11", "-c", $Driver, "-o", $driverObject))
    $ports = @{}
    $consumers = @{}
    foreach ($regions in @(8, 16)) {
        $flags = $base + @("-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=$regions")
        $members = @()
        foreach ($source in @("fiber_port.c", "fiber_port_boot.c")) {
            $object = Join-Path $dir ("port-$regions-" + $source + ".o")
            $null = Invoke-Tool $ArmGcc ($flags + @("-std=gnu11", "-c",
                (Join-Path $Profile $source), "-o", $object))
            $members += $object
        }
        $archive = Join-Path $dir ("libport$regions.a")
        $null = Invoke-Tool $Ar (@("rcs", $archive) + $members)
        $expectation = Join-Path $dir ("expectation$regions.o")
        $null = Invoke-Tool $ArmGcc ($flags + @("-std=gnu11", "-c",
            (Join-Path $Repo "fiber/port/fiber_port_context_cohort_expectation.c"),
            "-o", $expectation))
        $ports[$regions] = @{ Archive = $archive; Expectation = $expectation }
        foreach ($revision in @("fresh", "v1")) {
            $consumerFlags = $flags
            if ($revision -eq "v1") {
                $consumerFlags = @("-I$(Join-Path $PSScriptRoot 'fixtures/consumer_cohort_v1')") + $flags
            }
            $identity = Get-StorageIdentity $consumerFlags
            foreach ($language in @("c", "c++")) {
                $compiler = if ($language -eq "c") { $ArmGcc } else { $Cxx }
                $standard = if ($language -eq "c") { "-std=gnu11" } else { "-std=gnu++17" }
                foreach ($includeMode in @("facade", "direct")) {
                    $key = "$regions-$language-$revision-$includeMode"
                    $object = Join-Path $dir ("consumer-$key.o")
                    $includeFlags = if ($includeMode -eq "direct") {
                        @("-DFIBER_CONSUMER_DIRECT_TYPES=1", "-DFIBER_CONSUMER_DIRECT_EXPECTATION=1")
                    } else { @() }
                    $null = Invoke-Tool $compiler ($consumerFlags + $includeFlags + @($standard, "-x", $language,
                        "-c", $Storage, "-o", $object))
                    $undefined = Invoke-Tool $Nm @("-u", $object)
                    if ($undefined.Text -notmatch ("(?m)\bU\s+" + [regex]::Escape($identity) + "\s*$")) {
                        throw "Allocating-only consumer lost exact identity $identity"
                    }
                    $consumerArchive = Join-Path $dir ("libconsumer-$key.a")
                    $null = Invoke-Tool $Ar @("rcs", $consumerArchive, $object)
                    $consumers[$key] = @{ Object = $object; Archive = $consumerArchive; Identity = $identity }
                }
            }
        }
    }
    foreach ($freshRegions in @(8, 16)) {
        foreach ($consumerRegions in @(8, 16)) {
            foreach ($language in @("c", "c++")) {
                foreach ($revision in @("fresh", "v1")) {
                    foreach ($includeMode in @("facade", "direct")) {
                        $consumer = $consumers["$consumerRegions-$language-$revision-$includeMode"]
                        foreach ($packaging in @("Object", "Archive")) {
                            $name = "port$freshRegions-consumer$consumerRegions-$language-$revision-$includeMode-$packaging"
                            $elf = Join-Path $dir ($name + ".elf")
                            $inputs = @($driverObject) + $commonObjects +
                                @($consumer[$packaging], $ports[$freshRegions].Expectation, $ports[$freshRegions].Archive)
                            $link = Invoke-Tool $ArmGcc ($base + @("-nostdlib", "-Wl,--gc-sections",
                                "-Wl,-T,$Linker", "-Wl,-Map,$elf.map") + $inputs + @("-o", $elf)) -AllowFailure
                            $shouldPass = ($freshRegions -eq $consumerRegions) -and ($revision -eq "fresh")
                            if (($link.Code -eq 0) -ne $shouldPass) {
                                throw "Unexpected link result for $($mode.Name)/$name`n$($link.Text)"
                            }
                            if (!$shouldPass) {
                                $missing = @([regex]::Matches($link.Text,
                                    ("undefined reference to ['" + [char]96 + "]([^']+)'")) |
                                    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
                                if (($missing.Count -ne 1) -or ($missing[0] -ne $consumer.Identity)) {
                                    throw "Negative link must fail only on exact consumer identity $($consumer.Identity): $($link.Text)"
                                }
                            }
                            else {
                                $symbols = Invoke-Tool $Nm @("-S", $elf)
                                $undefined = Invoke-Tool $Nm @("-u", $elf)
                                if ($undefined.Text.Trim()) { throw "Positive ELF has undefined symbols." }
                                $expectedSize = if ($freshRegions -eq 8) { "000000d8" } else { "00000118" }
                                if ($symbols.Text -notmatch ("(?m)^\w+\s+" + $expectedSize +
                                        "\s+[Bb]\s+fiber_consumer_storage\s*$")) {
                                    throw "Positive ELF did not retain the expected $freshRegions-region allocation."
                                }
                                if ($symbols.Text -notmatch ("(?m)^\w+\s+00000001\s+[RT]\s+" +
                                        [regex]::Escape($consumer.Identity) + "\s*$")) {
                                    throw "Positive ELF lost link-visible storage identity."
                                }
                                $disassembly = Invoke-Tool $Dump @("-dr", $elf)
                                [IO.File]::WriteAllText(($elf + ".dis"), $disassembly.Text)
                            }
                            $Results.Add([pscustomobject]@{ Mode = $mode.Name; Case = $name;
                                ExpectedPass = $shouldPass; ExitCode = $link.Code; Identity = $consumer.Identity })
                        }
                    }
                }
            }
        }
    }
    Write-Host "consumer cohort $($mode.Name): matching and stale C/C++ links checked"
}
$Results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Build "results.json") -Encoding ASCII
Get-ChildItem $Build -Recurse -File | Where-Object { $_.Name -ne "sha256.csv" } |
    Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash |
    Export-Csv -LiteralPath (Join-Path $Build "sha256.csv") -NoTypeInformation -Encoding ASCII
Write-Host "PASS consumer cohort: $publicCompiles no-CMSIS public compiles, $invalidManifests invalid manifests, $($Results.Count) GC links; artifacts: $Build"
