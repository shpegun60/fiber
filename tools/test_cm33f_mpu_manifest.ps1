param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixtures = Join-Path $PSScriptRoot "fixtures\cm33f_mpu_manifest"
$port = Join-Path $repo "fiber\port\ARM_CM33F_MPU\non_secure"
if (-not $ArmGcc) {
    $command = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($command) { $ArmGcc = $command.Source }
    else {
        $found = Get-ChildItem C:\ST -Recurse -Filter arm-none-eabi-gcc.exe `
            -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $ArmGcc = $found.FullName }
    }
}
if (-not $ArmGcc -or -not (Test-Path -LiteralPath $ArmGcc)) {
    throw "Set -ArmGcc to the existing ARM GCC executable"
}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$bin = Split-Path $ArmGcc
$gxx = Join-Path $bin "arm-none-eabi-g++.exe"
$nm = Join-Path $bin "arm-none-eabi-nm.exe"
$objdump = Join-Path $bin "arm-none-eabi-objdump.exe"
$objcopy = Join-Path $bin "arm-none-eabi-objcopy.exe"
if (-not $CmsisCore) { $CmsisCore = Join-Path $repo "..\..\..\Drivers\CMSIS\Include" }
if (-not $FreeRtosRoot) { $FreeRtosRoot = Join-Path $repo "..\..\..\..\_reference\FreeRTOS-Kernel" }
foreach ($required in @($gxx, $nm, $objdump, $objcopy,
        (Join-Path $CmsisCore "core_cm33.h"), (Join-Path $CmsisCore "mpu_armv8.h"),
        (Join-Path $port "fiber_port_types.h"), (Join-Path $port "fiber_port_boot_types.h"),
        (Join-Path $port "fiber_portmacro.h"))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Missing type-proof dependency: $required" }
}
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
$reference = Join-Path $FreeRtosRoot "portable\GCC\ARM_CM33_NTZ\non_secure"
if (-not $BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ("cm33f-mpu-manifest-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $build -Force | Out-Null
$commands = Join-Path $build "commands.log"

function Invoke-Proof {
    param([string]$Program, [string[]]$Arguments, [string]$Log, [switch]$AllowFailure)
    Add-Content -LiteralPath $commands -Encoding ASCII -Value `
        ((@($Program) + $Arguments | ConvertTo-Json -Compress))
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
    if (-not $AllowFailure -and $code -ne 0) { throw "Proof command failed ($code): $Program`n$output" }
    return [pscustomobject]@{ ExitCode=$code; Output=$output }
}

function Assert-Ordered {
    param([string]$Text, [string[]]$Patterns, [string]$Label)
    $cursor = 0
    foreach ($pattern in $Patterns) {
        $match = [regex]::Match($Text.Substring($cursor), $pattern, "IgnoreCase")
        if (-not $match.Success) { throw "$Label lost generated reference geometry: $pattern" }
        $cursor += $match.Index + $match.Length
    }
}

$pin = "a50edad08b29052631aa469d4df6e6ec7ff68878"
$head = (& git -C $FreeRtosRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -ne $pin) { throw "FreeRTOS reference pin mismatch: $head" }
Invoke-Proof "git" @("-C", $FreeRtosRoot, "diff", "--exit-code", "HEAD", "--") | Out-Null
Invoke-Proof $ArmGcc @("--version") -Log (Join-Path $build "gcc-version.txt") | Out-Null
Invoke-Proof $gxx @("--version") -Log (Join-Path $build "gxx-version.txt") | Out-Null
$referenceHashes = @("port.c", "portasm.c", "portasm.h", "portmacro.h", "portmacrocommon.h") |
    ForEach-Object {
        $path = Join-Path $reference $_
        [pscustomobject]@{ Path=$path; Sha256=(Get-FileHash $path -Algorithm SHA256).Hash }
    }
$sourcePaths = @($PSCommandPath, $ArmGcc, $gxx, $nm, $objdump, $objcopy,
    (Join-Path $repo "basic_types.h"), (Join-Path $repo "mcu_core.h"),
    (Join-Path $port "fiber_port_types.h"),
    (Join-Path $port "fiber_port_boot_types.h"), (Join-Path $port "fiber_portmacro.h"),
    (Join-Path $CmsisCore "core_cm33.h"), (Join-Path $CmsisCore "mpu_armv8.h"),
    (Join-Path $CmsisCore "cmsis_gcc.h"),
    (Join-Path $repo "tools\fixtures\freertos_asm_parity\FreeRTOSConfig.h"))
$sourcePaths += @(Get-ChildItem -LiteralPath (Join-Path $repo 'fiber'),
    (Join-Path $repo 'fiber\port'), $port, $CmsisCore, (Join-Path $FreeRtosRoot 'include') -File -Filter '*.h' |
    Select-Object -ExpandProperty FullName)
$sourcePaths += @(Get-ChildItem -LiteralPath $fixtures -Recurse -File | Select-Object -ExpandProperty FullName)
$sourcePaths += @(Get-ChildItem -LiteralPath (Join-Path $repo 'context') -File -Filter '*.h' |
    Select-Object -ExpandProperty FullName)
$sourceHashes = @($sourcePaths | Sort-Object -Unique | ForEach-Object {
    [pscustomobject]@{ Path=$_; Sha256=(Get-FileHash $_ -Algorithm SHA256).Hash }
})
ConvertTo-Json -InputObject $sourceHashes -Depth 4 | Set-Content (Join-Path $build "sources.json") -Encoding ASCII
[pscustomobject]@{ Pin=$pin; Files=@($referenceHashes);
    Comparison="Actual pinned M33_NTZ port.c/portasm.c with MPU=1, FPU=1, MVE/TrustZone/PAC/BTI=0, wrappers v2, syscall stack 128, ACL=0.";
    Shareability="Independent numeric oracle NON=0 OUTER=2 INNER=3; reserved SH=1 in the pinned reference is not parity.";
    ConstructorAssemblyParity="NOT_TESTED_BY_THIS_RUNNER: use test_cm33f_mpu_constructor.ps1 for the separate construction slice."
} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $build "reference.json") -Encoding ASCII

$common = @("-mthumb", "-ffreestanding", "-fno-builtin", "-fno-common",
    "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Werror", "-Wundef")
$selected = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
$privateIncludes = @("-I$(Join-Path $fixtures 'device')", "-I$port", "-I$fixtures",
    "-I$repo", "-I$(Join-Path $repo 'fiber')", "-I$(Join-Path $repo 'fiber\port')", "-I$CmsisCore")
$publicIncludes = @("-I$(Join-Path $fixtures 'types_only')", "-I$port", "-I$fixtures")
$configs = @()
foreach ($regions in @(8, 16)) {
    foreach ($abi in @("hard", "softfp")) {
        foreach ($optimization in @("-O2", "-Os")) {
            $configs += [pscustomobject]@{ Regions=$regions; Abi=$abi; Optimization=$optimization;
                Name="r$regions-$abi-$($optimization.Substring(1))" }
        }
    }
}
$publicCount = 0
$referenceCount = 0
$manifestCount = 0
$negativeResults = @()

# Public C/C++ compilation deliberately has no CMSIS, root MCU, or CPU header
# include directory, expectation anchor, provider definition, or final link.
foreach ($config in $configs) {
    $dir = Join-Path $build $config.Name
    New-Item -ItemType Directory -Path $dir | Out-Null
    $cpu = @("-mcpu=cortex-m33", "-mfpu=fpv5-sp-d16", "-mfloat-abi=$($config.Abi)")
    $region = "-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$($config.Regions)"
    foreach ($language in @("c", "c++")) {
        $compiler = if ($language -eq "c") { $ArmGcc } else { $gxx }
        $standard = if ($language -eq "c") { "-std=c11" } else { "-std=c++17" }
        $object = Join-Path $dir ("public-" + $language.Replace("+", "p") + ".o")
        $dependency = [IO.Path]::ChangeExtension($object, ".d")
        Invoke-Proof $compiler ($cpu + $common + @($config.Optimization, "-x", $language,
            $standard, $region, "-MMD", "-MF", $dependency, "-save-temps=obj") + $publicIncludes +
            @("-c", (Join-Path $fixtures "public.c"), "-o", $object)) | Out-Null
        $deps = Get-Content -LiteralPath $dependency -Raw
        if ($deps -match '(?i)(?:mcu_core|core_cm\d+|cmsis\w*|fiber_compiler|fiber_portmacro)\.h') {
            throw "Public storage acquired a private/CMSIS dependency: $dependency"
        }
        $storage = [IO.Path]::ChangeExtension($object, ".storage")
        Invoke-Proof $objcopy @("--dump-section", ".manifest_storage=$storage", $object) | Out-Null
        $storageName = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($storage)).TrimEnd([char]0)
        $expectedStorage = "fiber_port_storage_cohort_arm_cm33f_mpu_v1_r$($config.Regions)"
        if ($storageName -ne $expectedStorage) { throw "Public storage identity drift: $storageName" }
        $undefined = Invoke-Proof $nm @("-u", $object)
        if ($undefined.Output.Trim()) { throw "Public type proof acquired a link dependency: $($undefined.Output)" }
        $publicCount++
    }
    Write-Host "Public C/C++ PASS $($config.Name) (no CMSIS)"
}

# Independently compile the actual reference, never a hand-written substitute.
foreach ($config in $configs) {
    $dir = Join-Path $build (Join-Path $config.Name "reference")
    New-Item -ItemType Directory -Path $dir | Out-Null
    $flags = @("-mcpu=cortex-m33", "-mthumb", "-mfpu=fpv5-sp-d16", "-mfloat-abi=$($config.Abi)",
        "-std=gnu11", $config.Optimization, "-ffreestanding", "-fno-builtin", "-fno-common",
        "-ffunction-sections", "-fdata-sections", "-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1",
        "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=$($config.Regions)",
        "-I$(Join-Path $fixtures 'reference')", "-I$(Join-Path $FreeRtosRoot 'include')", "-I$reference")
    foreach ($unit in @("port.c", "portasm.c", "geometry.c")) {
        $source = if ($unit -eq "geometry.c") { Join-Path $fixtures "reference\geometry.c" } else { Join-Path $reference $unit }
        $object = Join-Path $dir ($unit.Replace(".c", ".o"))
        Invoke-Proof $ArmGcc ($flags + @("-save-temps=obj", "-c", $source, "-o", $object)) | Out-Null
        $assembly = Invoke-Proof $objdump @("-dr", $object) -Log ([IO.Path]::ChangeExtension($object, ".dis"))
        if ($unit -eq "port.c" -and $assembly.Output -notmatch '<pxPortInitialiseStack>:') {
            throw "Pinned reference constructor was not compiled: $object"
        }
        if ($unit -eq "portasm.c") {
            Assert-Ordered $assembly.Output @(
                '\bvstmiaeq\s+r1!,\s*\{s16-s31\}',
                '\bvldmiaeq\s+r2,\s*\{s0-s16\}',
                '\bvstmiaeq\s+r1!,\s*\{s0-s16\}',
                '\bstmia(?:\.w)?\s+r1!,\s*\{r2,\s*r3,\s*r4,\s*lr\}',
                '\bvldmdbeq\s+r1!,\s*\{s0-s16\}',
                '\bvstmiaeq\s+r2!,\s*\{s0-s16\}',
                '\bvldmdbeq\s+r1!,\s*\{s16-s31\}'
            ) "pinned M33 MPU/SP-FP save/restore"
        }
        $referenceCount++
    }
    Invoke-Proof $ArmGcc ($flags + @("-E", "-dM", (Join-Path $fixtures "reference\geometry.c"))) `
        -Log (Join-Path $dir "macros.txt") | Out-Null
    Write-Host "Pinned M33 MPU+FP reference PASS $($config.Name)"
}

foreach ($config in $configs) {
    $dir = Join-Path $build $config.Name
    $flags = @("-mcpu=cortex-m33", "-mfpu=fpv5-sp-d16", "-mfloat-abi=$($config.Abi)") +
        $common + @($config.Optimization, "-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$($config.Regions)") +
        $selected + $privateIncludes
    foreach ($language in @("c", "c++")) {
        $compiler = if ($language -eq "c") { $ArmGcc } else { $gxx }
        $standard = if ($language -eq "c") { "-std=c11" } else { "-std=c++17" }
        $object = Join-Path $dir ("manifest-" + $language.Replace("+", "p") + ".o")
        Invoke-Proof $compiler ($flags + @("-x", $language, $standard, "-MMD", "-save-temps=obj",
            "-c", (Join-Path $fixtures "manifest.c"), "-o", $object)) | Out-Null
        Invoke-Proof $objdump @("-dr", $object) -Log ([IO.Path]::ChangeExtension($object, ".dis")) | Out-Null
        $defined = Invoke-Proof $nm @("-g", "--defined-only", $object)
        if ($defined.Output -match '\b(?:SVC_Handler|PendSV_Handler|fiber_port_(?:context_init|runtime_\w+|start_first_context))\b') {
            throw "Header-only manifest probe emitted runtime definitions: $object"
        }
        if ($defined.Output -match '\bfiber_port_(?:context|storage)_cohort_') {
            throw "Header-only manifest probe must not define a cohort provider: $object"
        }
        $manifestCount++
    }
    Invoke-Proof $ArmGcc ($flags + @("-std=c11", "-E", "-dM", (Join-Path $fixtures "manifest.c"))) `
        -Log (Join-Path $dir "manifest-macros.txt") | Out-Null
    Write-Host "Strict real-CMSIS manifest PASS $($config.Name)"
}

$cases = @()
foreach ($fact in @(
        @{Name="core"; Key="CORE"; Diagnostic="CMSIS __CORTEX_M == 33"; Bad=@(0,55)},
        @{Name="mpu"; Key="MPU"; Diagnostic="__MPU_PRESENT == 1"; Bad=@(0,2)},
        @{Name="vtor"; Key="VTOR"; Diagnostic="__VTOR_PRESENT == 1"; Bad=@(0,2)},
        @{Name="fpu-present"; Key="FPU_PRESENT"; Diagnostic="CMSIS __FPU_PRESENT == 1"; Bad=@(0,2)},
        @{Name="fpu-used"; Key="FPU_USED"; Diagnostic="CMSIS __FPU_USED == 1"; Bad=@(0,2)},
        @{Name="nvic"; Key="NVIC"; Diagnostic="1..8 implemented NVIC priority bits"; Bad=@(0,9)},
        @{Name="arm-fp"; Key="ARM_FP"; Diagnostic="__ARM_FP == 4"; Bad=@(0,6,14)})) {
    $cases += @{Name="missing-$($fact.Name)"; Defines=@("-DPROOF_OMIT_$($fact.Key)=1"); Diagnostic=$fact.Diagnostic}
    foreach ($bad in $fact.Bad) {
        $cases += @{Name="$($fact.Name)-$bad"; Defines=@("-DPROOF_$($fact.Key)=$bad"); Diagnostic=$fact.Diagnostic}
    }
}
$cases += @(
    @{Name="missing-regions"; OmitRegions=$true; Diagnostic="FIBER_PORT_CM33F_MPU_TOTAL_REGIONS=8 or 16"},
    @{Name="regions-12"; Regions=12; Diagnostic="supports exactly 8 or 16 MPU regions"},
    @{Name="regions-0"; Regions=0; Diagnostic="supports exactly 8 or 16 MPU regions"},
    @{Name="secure"; ExtraCpu=@("-mcmse"); Diagnostic="excludes Secure CMSE builds"},
    @{Name="mve"; Defines=@("-DPROOF_MVE=1"); Diagnostic="does not permit MVE"},
    @{Name="soft-abi"; Abi="soft"; Defines=@("-DPROOF_FPU_USED=1", "-DPROOF_ARM_FP=4"); Diagnostic="__ARM_FP == 4"},
    @{Name="double-precision"; Fpu="fpv5-d16"; Diagnostic="__ARM_FP == 4"},
    @{Name="wrong-cpu-m4"; Cpu="cortex-m4"; Diagnostic="requires an ARMv8.0-M Mainline compiler target"},
    @{Name="declared-armv81"; Defines=@("-D__ARM_ARCH_8_1M_MAIN__=1"); Diagnostic="requires an ARMv8.0-M Mainline compiler target"},
    @{Name="runtime-selectable"; Defines=@("-DFIBER_PORT_RUNTIME_SELECTABLE=1"); Diagnostic="runtime-selectable state must not be predefined"},
    @{Name="owned-fpu-fact"; Defines=@("-DFIBER_PORT_TOOLCHAIN_HAS_FP=1"); Diagnostic="FPU facts are selected-port-owned"},
    @{Name="owned-feature"; Defines=@("-DFIBER_PORT_HAS_FPU=1"); Diagnostic="selected-port traits must not be predefined"})
foreach ($foreign in @("CM33_MPU", "CM55_MPU", "CM55F_MPU", "CM55_MVEF_MPU", "CM4_MPU", "MPU")) {
    $cases += @{Name="foreign-$foreign"; Defines=@("-DFIBER_PORT_${foreign}_TOTAL_REGIONS=8"); Diagnostic="requires its own MPU-region manifest macro"}
}
foreach ($feature in @("PAC_DEFAULT", "PAUTH", "PAUTH_DEFAULT", "BTI_DEFAULT", "BTI")) {
    $category = if ($feature.StartsWith("BTI")) { "BTI" } else { "PAC" }
    $cases += @{Name="feature-$feature-zero"; Defines=@("-D__ARM_FEATURE_${feature}=0"); Diagnostic="does not permit $category"}
}
foreach ($case in $cases) {
    $dir = Join-Path $build ("negative-" + $case.Name)
    New-Item -ItemType Directory -Path $dir | Out-Null
    $cpu = if ($case.ContainsKey("Cpu")) { $case.Cpu } else { "cortex-m33" }
    $fpu = if ($case.ContainsKey("Fpu")) { $case.Fpu } else { "fpv5-sp-d16" }
    $abi = if ($case.ContainsKey("Abi")) { $case.Abi } else { "hard" }
    $arguments = @("-mcpu=$cpu", "-mfpu=$fpu", "-mfloat-abi=$abi", "-std=c11") +
        $common + $selected + $privateIncludes
    if (-not $case.ContainsKey("OmitRegions")) {
        $regions = if ($case.ContainsKey("Regions")) { $case.Regions } else { 8 }
        $arguments += "-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$regions"
    }
    if ($case.ContainsKey("Defines")) { $arguments += $case.Defines }
    if ($case.ContainsKey("ExtraCpu")) { $arguments += $case.ExtraCpu }
    $arguments += @("-c", (Join-Path $fixtures "manifest.c"), "-o", (Join-Path $dir "rejected.o"))
    $result = Invoke-Proof $ArmGcc $arguments -Log (Join-Path $dir "diagnostics.txt") -AllowFailure
    if ($result.ExitCode -eq 0 -or $result.Output.IndexOf($case.Diagnostic, [StringComparison]::Ordinal) -lt 0) {
        throw "Negative $($case.Name) failed for the wrong reason (expected $($case.Diagnostic)):`n$($result.Output)"
    }
    $negativeResults += [pscustomobject]@{ Name=$case.Name; ExitCode=$result.ExitCode; Diagnostic=$case.Diagnostic }
}

# Public manifest validation is also exercised in C++ without CMSIS.
foreach ($language in @("c", "c++")) {
    foreach ($invalid in @("missing", "12", "foreign")) {
        $compiler = if ($language -eq "c") { $ArmGcc } else { $gxx }
        $standard = if ($language -eq "c") { "-std=c11" } else { "-std=c++17" }
        $arguments = @("-mcpu=cortex-m33", "-mfloat-abi=soft", "-x", $language, $standard) +
            $common + $publicIncludes
        $diagnostic = "explicit 8- or 16-region MPU manifest"
        if ($invalid -eq "12") {
            $arguments += "-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=12"
            $diagnostic = "supports exactly 8 or 16 MPU regions"
        }
        elseif ($invalid -eq "foreign") {
            $arguments += @("-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=8", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8")
            $diagnostic = "requires its own MPU-region manifest macro"
        }
        $name = "public-$($language.Replace('+','p'))-$invalid"
        $arguments += @("-fsyntax-only", (Join-Path $fixtures "public.c"))
        $result = Invoke-Proof $compiler $arguments -Log (Join-Path $build "$name.log") -AllowFailure
        if ($result.ExitCode -eq 0 -or $result.Output.IndexOf($diagnostic, [StringComparison]::Ordinal) -lt 0) {
            throw "Public negative $name failed for the wrong reason: $($result.Output)"
        }
        $negativeResults += [pscustomobject]@{ Name=$name; ExitCode=$result.ExitCode; Diagnostic=$diagnostic }
    }
}
foreach ($source in $sourceHashes) {
    if ((Get-FileHash $source.Path -Algorithm SHA256).Hash -ne $source.Sha256) {
        throw "Source/header changed during type qualification; rerun: $($source.Path)"
    }
}
[pscustomobject]@{ Status="PASS"; PublicObjects=$publicCount; ManifestObjects=$manifestCount;
    ActualPinnedReferenceObjects=$referenceCount; NegativeCases=$negativeResults.Count;
    Negatives=@($negativeResults); ConstructorAssemblyParity="NOT_TESTED_BY_THIS_RUNNER";
    ManifestObjectsDefineRuntimeOrHandlers=$false; HardwareQualified=$false
} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $build "results.json") -Encoding ASCII
Write-Host "PASS C3FP type/manifest: $publicCount public C/C++ objects, $manifestCount real-CMSIS objects, $referenceCount actual pinned M33 reference objects, $($negativeResults.Count) strict negatives"
Write-Host "Type-only proof; constructor parity belongs to the separate runner; no runtime provider or handlers fabricated"
Write-Host "Evidence: $build"
