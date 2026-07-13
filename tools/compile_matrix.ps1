param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [switch]$SettingsOnly,
    [switch]$KeepBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Test-CmsisCorePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    return (Test-Path (Join-Path $Path "cmsis_compiler.h")) `
        -and (Test-Path (Join-Path $Path "core_cm0.h")) `
        -and (Test-Path (Join-Path $Path "core_cm0plus.h")) `
        -and (Test-Path (Join-Path $Path "core_cm23.h")) `
        -and (Test-Path (Join-Path $Path "core_cm3.h")) `
        -and (Test-Path (Join-Path $Path "core_cm4.h")) `
        -and (Test-Path (Join-Path $Path "core_cm7.h")) `
        -and (Test-Path (Join-Path $Path "core_cm33.h")) `
        -and (Test-Path (Join-Path $Path "core_cm55.h"))
}

function Find-ArmGcc {
    if (-not [string]::IsNullOrWhiteSpace($ArmGcc)) {
        if (Test-Path $ArmGcc) {
            return (Resolve-Path $ArmGcc).Path
        }
        throw "ARM_NONE_EABI_GCC points to a missing file: $ArmGcc"
    }

    $cmd = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $candidates = @(
        "C:\ST",
        "C:\Program Files",
        "C:\Program Files (x86)"
    )

    foreach ($root in $candidates) {
        if (-not (Test-Path $root)) {
            continue
        }

        $found = Get-ChildItem -Path $root -Recurse -Filter "arm-none-eabi-gcc.exe" `
            -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }

    throw "arm-none-eabi-gcc.exe not found. Set ARM_NONE_EABI_GCC to the compiler path."
}

function Find-CmsisCore {
    if (Test-CmsisCorePath $CmsisCore) {
        return (Resolve-Path $CmsisCore).Path
    }

    $workspace = Join-Path $env:USERPROFILE "Documents\my_workspace"
    $candidates = @(
        (Join-Path $RepoRoot "..\..\..\Drivers\CMSIS\Include"),
        (Join-Path $workspace "gnu\gnu-tools-for-stm32\linkdb\tests\tmp_external\STM32_Embedded_CPP\Targets\Nucleo_F446RE\Drivers\CMSIS\Include"),
        (Join-Path $workspace "gnu\gnu-tools-for-stm32\linkdb\tests\tmp_external\STM32_FreeRTOS-Kernel\Drivers\CMSIS\Core\Include"),
        (Join-Path $workspace "gnu\gnu-tools-for-stm32\linkdb\tests\tmp_external\STM32_FreeRTOS-Kernel\Drivers\CMSIS\Include")
    )

    foreach ($candidate in $candidates) {
        if (Test-CmsisCorePath $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "CMSIS core headers not found. Set CMSIS_CORE_INCLUDE to a folder containing cmsis_compiler.h and core_cm*.h."
}

function Get-CFunctionBody {
    param(
        [string]$Source,
        [string]$Signature,
        [string]$Path
    )

    $signatureIndex = $Source.IndexOf($Signature, [System.StringComparison]::Ordinal)
    if ($signatureIndex -lt 0) {
        throw "Missing function signature in ${Path}: $Signature"
    }

    $openBraceIndex = $Source.IndexOf('{', $signatureIndex)
    if ($openBraceIndex -lt 0) {
        throw "Missing function body in ${Path}: $Signature"
    }

    $depth = 0
    for ($index = $openBraceIndex; $index -lt $Source.Length; ++$index) {
        if ($Source[$index] -eq '{') {
            ++$depth
        }
        elseif ($Source[$index] -eq '}') {
            --$depth
            if ($depth -eq 0) {
                return $Source.Substring($openBraceIndex, $index - $openBraceIndex + 1)
            }
        }
    }

    throw "Unterminated function body in ${Path}: $Signature"
}

function Test-SchedulePortBoundary {
    param([string]$RepositoryRoot)

    $corePath = Join-Path $RepositoryRoot "fiber\fiber_core.c"
    $coreSource = Get-Content -LiteralPath $corePath -Raw
    $scheduleBody = Get-CFunctionBody -Source $coreSource `
        -Signature "void fiber_schedule(void)" -Path $corePath

    $requiredCalls = @(
        "fiber_port_require_schedule_environment();",
        "fiber_port_request_schedule();"
    )
    foreach ($requiredCall in $requiredCalls) {
        if ($scheduleBody.IndexOf($requiredCall, [System.StringComparison]::Ordinal) -lt 0) {
            throw "fiber_schedule must delegate through selected-port ABI: missing $requiredCall"
        }
    }

    $forbiddenCpuAccess = @(
        "__get_IPSR",
        "__get_PRIMASK",
        "__get_BASEPRI",
        "__get_FAULTMASK",
        "fiber_port_basepri_read",
        "SCB->ICSR",
        "fiber_port_pend_switch"
    )
    foreach ($forbidden in $forbiddenCpuAccess) {
        if ($scheduleBody.IndexOf($forbidden, [System.StringComparison]::Ordinal) -ge 0) {
            throw "fiber_schedule must not contain CPU-specific schedule access: $forbidden"
        }
    }
}

function Test-ContextPortBoundary {
    param([string]$RepositoryRoot)

    $corePath = Join-Path $RepositoryRoot "fiber\fiber_core.c"
    $runtimePath = Join-Path $RepositoryRoot "fiber\fiber_runtime_state.c"
    $sources = @{
        $corePath = Get-Content -LiteralPath $corePath -Raw
        $runtimePath = Get-Content -LiteralPath $runtimePath -Raw
    }

    $forbiddenLayoutKnowledge = @(
        "->boot",
        "->sp",
        "FiberPortBoot",
        "offsetof(FiberContext",
        "sizeof(FiberContext",
        "_Alignof(FiberContext"
    )
    foreach ($path in $sources.Keys) {
        foreach ($forbidden in $forbiddenLayoutKnowledge) {
            if ($sources[$path].IndexOf($forbidden, [System.StringComparison]::Ordinal) -ge 0) {
                throw "Common runtime must not inspect selected context layout: $forbidden in $path"
            }
        }
    }

    $requiredCoreCalls = @(
        "fiber_port_context_init(",
        "fiber_port_require_start_environment();",
        "fiber_port_require_start_interrupt_state();",
        "fiber_port_runtime_prepare();",
        "fiber_port_context_prepare_first_start("
    )
    foreach ($requiredCall in $requiredCoreCalls) {
        if ($sources[$corePath].IndexOf($requiredCall, [System.StringComparison]::Ordinal) -lt 0) {
            throw "fiber_core.c must use selected-port context ABI: missing $requiredCall"
        }
    }

    if ($sources[$runtimePath].IndexOf("fiber_port_context_validate_restore(",
            [System.StringComparison]::Ordinal) -lt 0) {
        throw "fiber_runtime_state.c must validate contexts through selected-port ABI"
    }
}

function Invoke-CompilerProbe {
    param(
        [string]$Compiler,
        [string[]]$Arguments,
        [string]$LogPath
    )

    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $Compiler @Arguments *> $LogPath
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    $output = ""
    if (Test-Path $LogPath) {
        $output = Get-Content -LiteralPath $LogPath -Raw
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = $output
    }
}

$gcc = Find-ArmGcc
$cmsis = Find-CmsisCore
$nm = Join-Path (Split-Path -Parent $gcc) "arm-none-eabi-nm.exe"
if (-not (Test-Path $nm)) {
    throw "arm-none-eabi-nm.exe not found next to compiler: $gcc"
}

Test-SchedulePortBoundary -RepositoryRoot $RepoRoot
Test-ContextPortBoundary -RepositoryRoot $RepoRoot

$commonSources = @(
    "fiber\fiber_core.c",
    "fiber\fiber_runtime_state.c",
    "fiber\fiber_stack.c",
    "fiber\fiber_panic.c"
)

$selectorPortSources = @(
    "fiber\port\ARM_CM7\r0p1\fiber_port.c",
    "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c",
    "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c",
    "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c",
    "fiber\port\transitional_v8m\fiber_port_boot.c",
    "fiber\port\transitional_v8m\fiber_port_exception.c",
    "fiber\port\ARM_CM0\fiber_port.c",
    "fiber\port\ARM_CM0\fiber_port_boot.c",
    "fiber\port\ARM_CM0\fiber_port_exception.c",
    "fiber\port\ARM_CM3\fiber_port.c",
    "fiber\port\ARM_CM3\fiber_port_boot.c",
    "fiber\port\ARM_CM3\fiber_port_exception.c",
    "fiber\port\ARM_CM4\fiber_port.c",
    "fiber\port\ARM_CM4\fiber_port_boot.c",
    "fiber\port\ARM_CM4\fiber_port_exception.c"
)

$configs = @(
    [pscustomobject]@{ Name = "cortex-m0";          CpuArgs = @("-mcpu=cortex-m0");              Core = "core_cm0.h";     PriorityBits = 4; VtorPresent = 0; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m0plus";      CpuArgs = @("-mcpu=cortex-m0plus");          Core = "core_cm0plus.h"; PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m3";          CpuArgs = @("-mcpu=cortex-m3");              Core = "core_cm3.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m4";          CpuArgs = @("-mcpu=cortex-m4");              Core = "core_cm4.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m4f";         CpuArgs = @("-mcpu=cortex-m4");              Core = "core_cm4.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv4-sp-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m7";          CpuArgs = @("-mcpu=cortex-m7");              Core = "core_cm7.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m7f";         CpuArgs = @("-mcpu=cortex-m7");              Core = "core_cm7.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv5-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m7f-prio8";   CpuArgs = @("-mcpu=cortex-m7");              Core = "core_cm7.h";     PriorityBits = 8; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv5-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m23";         CpuArgs = @("-mcpu=cortex-m23");             Core = "core_cm23.h";    PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m33";         CpuArgs = @("-mcpu=cortex-m33");             Core = "core_cm33.h";    PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m33f";        CpuArgs = @("-mcpu=cortex-m33");             Core = "core_cm33.h";    PriorityBits = 4; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv5-sp-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m55";         CpuArgs = @("-mcpu=cortex-m55");             Core = "core_cm55.h";    PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m55f";        CpuArgs = @("-mcpu=cortex-m55");             Core = "core_cm55.h";    PriorityBits = 4; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv5-sp-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m55-mve-fp";  CpuArgs = @("-march=armv8.1-m.main+mve.fp"); Core = "core_cm55.h";    PriorityBits = 4; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfloat-abi=hard") }
)

$portProfiles = @{
    "cortex-m0"         = "FIBER_PORT_PROFILE_ARMV6M"
    "cortex-m0plus"     = "FIBER_PORT_PROFILE_ARMV6M"
    "cortex-m3"         = "FIBER_PORT_PROFILE_ARMV7M"
    "cortex-m4"         = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m4f"        = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m7"         = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m7f"        = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m7f-prio8"  = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m23"        = "FIBER_PORT_PROFILE_ARMV8M_BASELINE"
    "cortex-m33"        = "FIBER_PORT_PROFILE_ARMV8M_MAINLINE"
    "cortex-m33f"       = "FIBER_PORT_PROFILE_ARMV8M_MAINLINE"
    # GCC 14 reports plain -mcpu=cortex-m55 as ARMv8-M Mainline until an
    # ARMv8.1-M feature is explicitly enabled. Its M55 FP configuration also
    # defines __ARM_FEATURE_MVE, so that mode must select the v8.1-M profile.
    "cortex-m55"        = "FIBER_PORT_PROFILE_ARMV8M_MAINLINE"
    "cortex-m55f"       = "FIBER_PORT_PROFILE_ARMV81M_MAINLINE"
    "cortex-m55-mve-fp" = "FIBER_PORT_PROFILE_ARMV81M_MAINLINE"
}

$portResultMacros = @{
    "FIBER_PORT_PROFILE_ARMV6M"           = "FIBER_PORT_ARMV6M"
    "FIBER_PORT_PROFILE_ARMV7M"           = "FIBER_PORT_ARMV7M"
    "FIBER_PORT_PROFILE_ARMV7EM"          = "FIBER_PORT_ARMV7EM"
    "FIBER_PORT_PROFILE_ARMV8M_BASELINE"  = "FIBER_PORT_ARMV8M_BASELINE"
    "FIBER_PORT_PROFILE_ARMV8M_MAINLINE"  = "FIBER_PORT_ARMV8M_MAINLINE"
    "FIBER_PORT_PROFILE_ARMV81M_MAINLINE" = "FIBER_PORT_ARMV81M_MAINLINE"
}

$portIncludeDirs = @{
    "FIBER_PORT_PROFILE_ARMV6M"           = "fiber\port\ARM_CM0"
    "FIBER_PORT_PROFILE_ARMV7M"           = "fiber\port\ARM_CM3"
    "FIBER_PORT_PROFILE_ARMV7EM"          = "fiber\port\ARM_CM4"
    "FIBER_PORT_PROFILE_ARMV8M_BASELINE"  = "fiber\port\transitional_v8m"
    "FIBER_PORT_PROFILE_ARMV8M_MAINLINE"  = "fiber\port\transitional_v8m"
    "FIBER_PORT_PROFILE_ARMV81M_MAINLINE" = "fiber\port\transitional_v8m"
}

$buildSelectedPortSourcesByProfile = @{
    "FIBER_PORT_PROFILE_ARMV6M"           = @("fiber\port\ARM_CM0\fiber_port.c", "fiber\port\ARM_CM0\fiber_port_boot.c", "fiber\port\ARM_CM0\fiber_port_exception.c")
    "FIBER_PORT_PROFILE_ARMV7M"           = @("fiber\port\ARM_CM3\fiber_port.c", "fiber\port\ARM_CM3\fiber_port_boot.c", "fiber\port\ARM_CM3\fiber_port_exception.c")
    "FIBER_PORT_PROFILE_ARMV7EM"          = @("fiber\port\ARM_CM4\fiber_port.c", "fiber\port\ARM_CM4\fiber_port_boot.c", "fiber\port\ARM_CM4\fiber_port_exception.c")
    "FIBER_PORT_PROFILE_ARMV8M_BASELINE"  = @("fiber\port\transitional_v8m\fiber_port_transitional_v8m.c", "fiber\port\transitional_v8m\fiber_port_boot.c", "fiber\port\transitional_v8m\fiber_port_exception.c")
    "FIBER_PORT_PROFILE_ARMV8M_MAINLINE"  = @("fiber\port\transitional_v8m\fiber_port_transitional_v8m.c", "fiber\port\transitional_v8m\fiber_port_boot.c", "fiber\port\transitional_v8m\fiber_port_exception.c")
    "FIBER_PORT_PROFILE_ARMV81M_MAINLINE" = @("fiber\port\transitional_v8m\fiber_port_transitional_v8m.c", "fiber\port\transitional_v8m\fiber_port_boot.c", "fiber\port\transitional_v8m\fiber_port_exception.c")
}

$buildSelectedPortIncludeDirsByConfig = @{
    "cortex-m7"  = "fiber\port\ARM_CM7\r0p1"
    "cortex-m7f" = "fiber\port\ARM_CM7\r0p1"
    "cortex-m7f-prio8" = "fiber\port\ARM_CM7\r0p1"
}

$buildSelectedPortSourcesByConfig = @{
    "cortex-m7"  = @("fiber\port\ARM_CM7\r0p1\fiber_port.c", "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c", "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c")
    "cortex-m7f" = @("fiber\port\ARM_CM7\r0p1\fiber_port.c", "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c", "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c")
    "cortex-m7f-prio8" = @("fiber\port\ARM_CM7\r0p1\fiber_port.c", "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c", "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c")
}

$buildRoot = Join-Path ([IO.Path]::GetTempPath()) ("fiber-compile-matrix-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $buildRoot | Out-Null

$requiredPortSymbols = @(
    "fiber_port_init_context_frame",
    "fiber_port_context_init",
    "fiber_port_context_validate_restore",
    "fiber_port_context_prepare_first_start",
    "fiber_port_require_start_environment",
    "fiber_port_require_start_interrupt_state",
    "fiber_port_boot_create",
    "fiber_port_boot_check",
    "fiber_port_boot_prepare_msp_for_start",
    "fiber_port_boot_record_compute_hash",
    "fiber_port_boot_record_fast_check",
    "fiber_port_boot_record_check",
    "fiber_port_runtime_prepare",
    "fiber_port_require_schedule_environment",
    "fiber_port_request_schedule",
    "fiber_port_start_first_context",
    "fiber_svc",
    "fiber_pendsv",
    "fiber_exception_runtime_check",
    "fiber_pendsv_init_lowest_priority"
)

try {
    Write-Host "Compiler: $gcc"
    Write-Host "CMSIS:    $cmsis"
    Write-Host "Build:    $buildRoot"

    if (-not $SettingsOnly) {
        foreach ($cfg in $configs) {
        $profile = $portProfiles[$cfg.Name]
        if ([string]::IsNullOrWhiteSpace($profile)) {
            throw "No explicit FIBER_PORT_PROFILE mapping for $($cfg.Name)"
        }
        $portMacro = $portResultMacros[$profile]
        if ([string]::IsNullOrWhiteSpace($portMacro)) {
            throw "No build-selected FIBER_PORT_* mapping for $profile"
        }
        $portIncludeDir = $portIncludeDirs[$profile]
        if ([string]::IsNullOrWhiteSpace($portIncludeDir)) {
            throw "No build-selected include directory mapping for $profile"
        }
        if ($buildSelectedPortIncludeDirsByConfig.ContainsKey($cfg.Name)) {
            $portIncludeDir = $buildSelectedPortIncludeDirsByConfig[$cfg.Name]
        }

        $buildSelectedPortSources = $buildSelectedPortSourcesByProfile[$profile]
        if (($null -eq $buildSelectedPortSources) -or ($buildSelectedPortSources.Count -eq 0)) {
            throw "No build-selected source group mapping for $profile"
        }
        if ($buildSelectedPortSourcesByConfig.ContainsKey($cfg.Name)) {
            $buildSelectedPortSources = $buildSelectedPortSourcesByConfig[$cfg.Name]
        }

        $wrapperDefines = @("-DFIBER_PENDSV_WIRED=1", "-DFIBER_SVC_WIRED=1")
        $directPendsvDefines = @("-DFIBER_PENDSV_VECTOR_DIRECT=1", "-DFIBER_SVC_WIRED=1")
        $buildSelectedDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-D$portMacro=1")
        $buildSelectedIncludeArgs = @("-I$(Join-Path $RepoRoot $portIncludeDir)")

        $selectionModes = @(
            [pscustomobject]@{ Name = "auto";                         Defines = $wrapperDefines; ExtraArgs = @(); PortSources = $selectorPortSources },
            [pscustomobject]@{ Name = "explicit";                     Defines = @("-DFIBER_PORT_PROFILE=$profile") + $wrapperDefines; ExtraArgs = @(); PortSources = $selectorPortSources },
            [pscustomobject]@{ Name = "build-selected";               Defines = $buildSelectedDefines + $wrapperDefines; ExtraArgs = $buildSelectedIncludeArgs; PortSources = $buildSelectedPortSources },
            [pscustomobject]@{ Name = "auto-direct-pendsv";           Defines = $directPendsvDefines; ExtraArgs = @(); PortSources = $selectorPortSources },
            [pscustomobject]@{ Name = "explicit-direct-pendsv";       Defines = @("-DFIBER_PORT_PROFILE=$profile") + $directPendsvDefines; ExtraArgs = @(); PortSources = $selectorPortSources },
            [pscustomobject]@{ Name = "build-selected-direct-pendsv"; Defines = $buildSelectedDefines + $directPendsvDefines; ExtraArgs = $buildSelectedIncludeArgs; PortSources = $buildSelectedPortSources }
        )

        $selectionModes += [pscustomobject]@{
            Name = "auto-direct-vectors"
            Defines = @(
                "-DFIBER_PENDSV_VECTOR_DIRECT=1",
                "-DFIBER_SVC_VECTOR_DIRECT=1"
            )
            ExtraArgs = @()
            PortSources = $selectorPortSources
        }
        $selectionModes += [pscustomobject]@{
            Name = "explicit-direct-vectors"
            Defines = @(
                "-DFIBER_PORT_PROFILE=$profile",
                "-DFIBER_PENDSV_VECTOR_DIRECT=1",
                "-DFIBER_SVC_VECTOR_DIRECT=1"
            )
            ExtraArgs = @()
            PortSources = $selectorPortSources
        }
        $selectionModes += [pscustomobject]@{
            Name = "build-selected-direct-vectors"
            Defines = $buildSelectedDefines + @(
                "-DFIBER_PENDSV_VECTOR_DIRECT=1",
                "-DFIBER_SVC_VECTOR_DIRECT=1"
            )
            ExtraArgs = $buildSelectedIncludeArgs
            PortSources = $buildSelectedPortSources
        }

        if (($cfg.Name -eq "cortex-m33") -or
            ($cfg.Name -eq "cortex-m33f") -or
            ($cfg.Name -eq "cortex-m55") -or
            ($cfg.Name -eq "cortex-m55f") -or
            ($cfg.Name -eq "cortex-m55-mve-fp")) {
            $selectionModes += [pscustomobject]@{
                Name = "explicit-nonsecure-exc-return"
                Defines = @(
                    "-DFIBER_PORT_PROFILE=$profile",
                    "-DFIBER_PENDSV_WIRED=1",
                    "-DFIBER_SVC_WIRED=1",
                    "-DFIBER_TRANSITIONAL_V8M_RUN_NONSECURE=1"
                )
                ExtraArgs = @()
                PortSources = $selectorPortSources
            }
            $selectionModes += [pscustomobject]@{
                Name = "explicit-secure-target-ns-bank"
                Defines = @(
                    "-DFIBER_PORT_PROFILE=$profile",
                    "-DFIBER_PENDSV_WIRED=1",
                    "-DFIBER_SVC_WIRED=1",
                    "-DFIBER_TRANSITIONAL_V8M_RUN_NONSECURE=1",
                    "-DFIBER_TRANSITIONAL_V8M_TARGET_NS_BANK=1",
                    "-DFIBER_TZ_NS=1"
                )
                ExtraArgs = @("-mcmse")
                PortSources = $selectorPortSources
            }
        }

        # Port selection is centralized in fiber_port_selected.h. Test the
        # exact type-only header owned by the same selected source group
        # without a generated device header or CMSIS include path. The public
        # selected facade itself is covered by the normal source builds below.
        $typeProbeDir = Join-Path (Join-Path $buildRoot $cfg.Name) "type-only"
        New-Item -ItemType Directory -Path $typeProbeDir | Out-Null
        $typeProbeSource = @"
#include <stddef.h>
#include <stdint.h>

#include "fiber_port_types.h"

_Static_assert(offsetof(FiberContext, sp) == 0u,
    "[fiber]: transitional FiberContext.sp must remain first");
_Static_assert(offsetof(FiberContext, boot) == sizeof(uint32_t *),
    "[fiber]: transitional FiberContext.boot offset changed");
_Static_assert(sizeof(FiberContext) ==
        (offsetof(FiberContext, boot) + sizeof(FiberPortBoot)),
    "[fiber]: transitional FiberContext has unexpected tail padding");
_Static_assert(_Alignof(FiberContext) == _Alignof(uint32_t *),
    "[fiber]: transitional FiberContext alignment changed");

int fiber_type_layout_probe(void)
{
    return 0;
}
"@
        $typeProbePath = Join-Path $typeProbeDir "fiber-type-layout-probe.c"
        $typeProbeObject = Join-Path $typeProbeDir "fiber-type-layout-probe.o"
        Set-Content -Path $typeProbePath -Value $typeProbeSource -Encoding ASCII

        $typeProbeArgs = $cfg.CpuArgs + @(
            "-mthumb"
        ) + $cfg.Extra + @(
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-Wall",
            "-Wextra",
            "-Wundef",
            "-Werror=undef",
            "-Werror=implicit-function-declaration",
            "-Werror=return-type",
            "-I$(Join-Path $RepoRoot $portIncludeDir)",
            "-I$RepoRoot",
            "-I$(Join-Path $RepoRoot 'fiber')",
            "-c",
            $typeProbePath,
            "-o",
            $typeProbeObject
        )

        & $gcc @typeProbeArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Type-only selected-port header compile failed for $($cfg.Name)"
        }

        foreach ($mode in $selectionModes) {
            $cfgDir = Join-Path (Join-Path $buildRoot $cfg.Name) $mode.Name
            New-Item -ItemType Directory -Path $cfgDir | Out-Null

            $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_

#define __MPU_PRESENT             0U
#define __VTOR_PRESENT            $($cfg.VtorPresent)U
#define __NVIC_PRIO_BITS          $($cfg.PriorityBits)U
#define __Vendor_SysTickConfig    0U
#define __FPU_PRESENT             $($cfg.FpuPresent)U
#define __FPU_USED                $($cfg.FpuUsed)U
#define __DSP_PRESENT             $($cfg.DspPresent)U
#define __SAUREGION_PRESENT       0U
#define __ICACHE_PRESENT          0U
#define __DCACHE_PRESENT          0U

typedef enum IRQn {
    NonMaskableInt_IRQn = -14,
    HardFault_IRQn      = -13,
    MemoryManagement_IRQn = -12,
    BusFault_IRQn       = -11,
    UsageFault_IRQn     = -10,
    SecureFault_IRQn    = -9,
    SVCall_IRQn         = -5,
    DebugMonitor_IRQn   = -4,
    PendSV_IRQn         = -2,
    SysTick_IRQn        = -1,
    DummyDevice_IRQn    = 0
} IRQn_Type;

void Error_Handler(void);

#include "$($cfg.Core)"

#endif
"@
            Set-Content -Path (Join-Path $cfgDir "main.h") -Value $mainHeader -Encoding ASCII

            Write-Host ""
            Write-Host "== $($cfg.Name) / $($mode.Name) =="

            $sources = $commonSources + $mode.PortSources
            $objects = @()

            foreach ($source in $sources) {
                $srcPath = Join-Path $RepoRoot $source
                $objName = ($source -replace '[\\/]', '_') + ".o"
                $objPath = Join-Path $cfgDir $objName

                $args = $cfg.CpuArgs + $mode.ExtraArgs + @(
                    "-mthumb"
                ) + $cfg.Extra + @(
                    "-std=gnu11",
                    "-ffreestanding",
                    "-fno-common",
                    "-Wall",
                    "-Wextra",
                    "-Wundef",
                    "-Wno-unused-parameter",
                    "-Werror=undef",
                    "-Werror=implicit-function-declaration",
                    "-Werror=return-type"
                ) + $mode.Defines + @(
                    "-I$cfgDir",
                    "-I$RepoRoot",
                    "-I$(Join-Path $RepoRoot 'fiber')",
                    "-I$cmsis",
                    "-c",
                    $srcPath,
                    "-o",
                    $objPath
                )

                & $gcc @args
                if ($LASTEXITCODE -ne 0) {
                    throw "Compile failed for $($cfg.Name) / $($mode.Name): $source"
                }

                $objects += $objPath
            }

            # A relocatable link catches duplicate port implementations while
            # allowing application-owned wrapper symbols to remain unresolved.
            $linkedObject = Join-Path $cfgDir "fiber-matrix-linked.o"
            $linkArgs = $cfg.CpuArgs + @("-mthumb") + $cfg.Extra + @(
                "-nostdlib",
                "-r",
                "-o",
                $linkedObject
            ) + $objects

            & $gcc @linkArgs
            if ($LASTEXITCODE -ne 0) {
                throw "Relocatable link failed for $($cfg.Name) / $($mode.Name)"
            }

            $definedSymbols = & $nm -g --defined-only $linkedObject
            if ($LASTEXITCODE -ne 0) {
                throw "Symbol scan failed for $($cfg.Name) / $($mode.Name)"
            }

            foreach ($symbol in $requiredPortSymbols) {
                $definitions = @($definedSymbols | Where-Object {
                    $_ -match "\s[TW]\s+$([regex]::Escape($symbol))$"
                })
                if ($definitions.Count -ne 1) {
                    throw "Expected exactly one $symbol definition for $($cfg.Name) / $($mode.Name); found $($definitions.Count)"
                }
            }
        }
        }

        # Transitional v8-M inputs are port-local bring-up policy. Prove that
        # malformed values and Non-secure-bank access without CMSE fail closed.
        $v8ProbeCfg = $configs | Where-Object { $_.Name -eq "cortex-m33" }
        $v8ProbeProfile = $portProfiles["cortex-m33"]
        $v8ProbeDir = Join-Path (Join-Path $buildRoot "cortex-m33") "explicit"
        $v8NegativeCases = @(
            [pscustomobject]@{ Name = "invalid-run-nonsecure"; Define = "-DFIBER_TRANSITIONAL_V8M_RUN_NONSECURE=2"; Diagnostic = "FIBER_TRANSITIONAL_V8M_RUN_NONSECURE must be 0 or 1" },
            [pscustomobject]@{ Name = "invalid-target-ns-bank"; Define = "-DFIBER_TRANSITIONAL_V8M_TARGET_NS_BANK=2"; Diagnostic = "FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK must be 0 or 1" },
            [pscustomobject]@{ Name = "target-ns-bank-without-cmse"; Define = "-DFIBER_TRANSITIONAL_V8M_TARGET_NS_BANK=1"; Diagnostic = "requires a Secure CMSE level 3 build" }
        )

        foreach ($case in $v8NegativeCases) {
            Write-Host "== cortex-m33 / transitional-contract-$($case.Name) =="
            $objectPath = Join-Path $v8ProbeDir ($case.Name + ".o")
            $args = $v8ProbeCfg.CpuArgs + @("-mthumb") + $v8ProbeCfg.Extra + @(
                "-std=gnu11",
                "-ffreestanding",
                "-fno-common",
                "-Wall",
                "-Wextra",
                "-Wundef",
                "-Werror=undef",
                "-Werror=implicit-function-declaration",
                "-Werror=return-type",
                "-DFIBER_PORT_PROFILE=$v8ProbeProfile",
                "-DFIBER_PENDSV_WIRED=1",
                "-DFIBER_SVC_WIRED=1",
                $case.Define,
                "-I$v8ProbeDir",
                "-I$RepoRoot",
                "-I$(Join-Path $RepoRoot 'fiber')",
                "-I$cmsis",
                "-c",
                (Join-Path $RepoRoot "fiber\fiber_core.c"),
                "-o",
                $objectPath
            )

            $result = Invoke-CompilerProbe -Compiler $gcc -Arguments $args `
                -LogPath (Join-Path $v8ProbeDir ($case.Name + ".log"))
            if ($result.ExitCode -eq 0) {
                throw "Invalid transitional v8-M setting unexpectedly compiled: $($case.Name)"
            }
            $normalizedOutput = $result.Output -replace '\s+', ' '
            $normalizedDiagnostic = $case.Diagnostic -replace '\s+', ' '
            if ($normalizedOutput -notmatch [regex]::Escape($normalizedDiagnostic)) {
                throw "Invalid transitional v8-M setting failed for the wrong reason: $($case.Name)`n$($result.Output)"
            }
        }
    }

    # Compile-time policy probes prove that the concrete CM7 port fails closed
    # for invalid settings. These compile one common source because the selected
    # port facade evaluates the complete settings and trait contract there.
    $probeCfg = $configs | Where-Object { $_.Name -eq "cortex-m7f" }
    if ($null -eq $probeCfg) {
        throw "cortex-m7f configuration is required for settings probes"
    }

    $probeRoot = Join-Path $buildRoot "cm7-settings-contract"
    $probe4Dir = Join-Path $probeRoot "prio4"
    $probe8Dir = Join-Path $probeRoot "prio8"
    New-Item -ItemType Directory -Path $probe4Dir | Out-Null
    New-Item -ItemType Directory -Path $probe8Dir | Out-Null

    $probeHeader = @"
#ifndef MAIN_H_
#define MAIN_H_

#define __MPU_PRESENT             0U
#define __VTOR_PRESENT            1U
#define __NVIC_PRIO_BITS          __PROBE_NVIC_PRIO_BITS
#define __Vendor_SysTickConfig    0U
#define __FPU_PRESENT             1U
#define __FPU_USED                1U
#define __DSP_PRESENT             1U
#define __SAUREGION_PRESENT       0U
#define __ICACHE_PRESENT          0U
#define __DCACHE_PRESENT          0U

typedef enum IRQn {
    NonMaskableInt_IRQn = -14,
    HardFault_IRQn      = -13,
    MemoryManagement_IRQn = -12,
    BusFault_IRQn       = -11,
    UsageFault_IRQn     = -10,
    SecureFault_IRQn    = -9,
    SVCall_IRQn         = -5,
    DebugMonitor_IRQn   = -4,
    PendSV_IRQn         = -2,
    SysTick_IRQn        = -1,
    DummyDevice_IRQn    = 0
} IRQn_Type;

void Error_Handler(void);

#include "core_cm7.h"

#endif
"@
    Set-Content -LiteralPath (Join-Path $probe4Dir "main.h") `
        -Value ($probeHeader.Replace("__PROBE_NVIC_PRIO_BITS", "4U")) -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $probe8Dir "main.h") `
        -Value ($probeHeader.Replace("__PROBE_NVIC_PRIO_BITS", "8U")) -Encoding ASCII

    $probeCommonArgs = $probeCfg.CpuArgs + @(
        "-I$(Join-Path $RepoRoot 'fiber\port\ARM_CM7\r0p1')",
        "-mthumb"
    ) + $probeCfg.Extra + @(
        "-std=gnu11",
        "-ffreestanding",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-Wundef",
        "-Werror=undef",
        "-Werror=implicit-function-declaration",
        "-Werror=return-type",
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV7EM=1",
        "-DFIBER_PENDSV_WIRED=1",
        "-DFIBER_SVC_WIRED=1"
    )
    $probeSource = Join-Path $RepoRoot "fiber\fiber_core.c"
    $probeBootSource = Join-Path $RepoRoot "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c"

    Write-Host ""
    Write-Host "== cortex-m7f / settings-contract-prio8-default =="
    $positiveArgs = $probeCommonArgs + @(
        "-I$probe8Dir",
        "-I$RepoRoot",
        "-I$(Join-Path $RepoRoot 'fiber')",
        "-I$cmsis",
        "-c",
        $probeSource,
        "-o",
        (Join-Path $probe8Dir "default-basepri.o")
    )
    $positiveResult = Invoke-CompilerProbe -Compiler $gcc -Arguments $positiveArgs `
        -LogPath (Join-Path $probe8Dir "default-basepri.log")
    if ($positiveResult.ExitCode -ne 0) {
        throw "8-bit NVIC default BASEPRI probe failed:`n$($positiveResult.Output)"
    }

    Write-Host "== cortex-m7f / settings-contract-alternate-fault-policy =="
    $alternateFaultPolicyArgs = $probeCommonArgs + @(
        "-DFIBER_CLEAR_STICKY_FAULT_STATUS_ON_START=1",
        "-DFIBER_ENABLE_CONFIGURABLE_FAULTS=0",
        "-I$probe4Dir",
        "-I$RepoRoot",
        "-I$(Join-Path $RepoRoot 'fiber')",
        "-I$cmsis",
        "-c",
        $probeBootSource,
        "-o",
        (Join-Path $probe4Dir "alternate-fault-policy.o")
    )
    $alternateFaultPolicyResult = Invoke-CompilerProbe -Compiler $gcc `
        -Arguments $alternateFaultPolicyArgs `
        -LogPath (Join-Path $probe4Dir "alternate-fault-policy.log")
    if ($alternateFaultPolicyResult.ExitCode -ne 0) {
        throw "Alternate startup fault-policy probe failed:`n$($alternateFaultPolicyResult.Output)"
    }

    $negativeCases = @(
        [pscustomobject]@{ Name = "invalid-fpu-lazy"; Define = "-DFIBER_FPU_LAZY=2"; Diagnostic = "FIBER_FPU_LAZY must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-rewind-msp"; Define = "-DFIBER_REWIND_MSP=2"; Diagnostic = "FIBER_REWIND_MSP must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-hash-on-switch"; Define = "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=2"; Diagnostic = "FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-canary-boolean"; Define = "-DFIBER_STACK_CANARY=2"; Diagnostic = "FIBER_STACK_CANARY must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-canary-zero-redzone"; Define = "-DFIBER_STACK_REDZONE_BYTES=0"; Diagnostic = "enabled stack canary requires at least 8 bytes of red zone"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-redzone-alignment"; Define = "-DFIBER_STACK_REDZONE_BYTES=7"; Diagnostic = "FIBER_STACK_REDZONE_BYTES must be a multiple of selected-port stack alignment"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-unaligned-trap"; Define = "-DFIBER_ENABLE_UNALIGNED_TRAP=2"; Diagnostic = "FIBER_ENABLE_UNALIGNED_TRAP must be 0 or 1"; Dir = $probe4Dir; Source = $probeBootSource },
        [pscustomobject]@{ Name = "invalid-div0-trap"; Define = "-DFIBER_ENABLE_DIV0_TRAP=2"; Diagnostic = "FIBER_ENABLE_DIV0_TRAP must be 0 or 1"; Dir = $probe4Dir; Source = $probeBootSource },
        [pscustomobject]@{ Name = "invalid-clear-sticky-faults"; Define = "-DFIBER_CLEAR_STICKY_FAULT_STATUS_ON_START=2"; Diagnostic = "FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START must be 0 or 1"; Dir = $probe4Dir; Source = $probeBootSource },
        [pscustomobject]@{ Name = "invalid-enable-configurable-faults"; Define = "-DFIBER_ENABLE_CONFIGURABLE_FAULTS=2"; Diagnostic = "FIBER_ENABLE_CONFIGURABLE_FAULTS must be 0 or 1"; Dir = $probe4Dir; Source = $probeBootSource },
        [pscustomobject]@{ Name = "invalid-pendsv-direct"; Define = "-DFIBER_PENDSV_VECTOR_DIRECT=2"; Diagnostic = "FIBER_PENDSV_VECTOR_DIRECT must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-svc-direct"; Define = "-DFIBER_SVC_VECTOR_DIRECT=2"; Diagnostic = "FIBER_SVC_VECTOR_DIRECT must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-svc-number"; Define = "-DFIBER_SVC_START_NUMBER=256"; Diagnostic = "FIBER_SVC_START_NUMBER must fit in an 8-bit SVC immediate"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "predefined-port-exc-return"; Define = "-DFIBER_PORT_INITIAL_EXC_RETURN=0xFFFFFFDDu"; Diagnostic = "selected-port traits must not be predefined"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "predefined-port-frame-size"; Define = "-DFIBER_PORT_MAX_SAVED_CONTEXT_BYTES=1u"; Diagnostic = "selected-port traits must not be predefined"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-validation-switch"; Define = "-DFIBER_VALIDATE_EXCEPTION_SETUP=0"; Diagnostic = "startup validation is mandatory"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-vector-validation"; Define = "-DFIBER_VALIDATE_VECTOR_WIRING=0"; Diagnostic = "startup validation is mandatory"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-pendsv-validation"; Define = "-DFIBER_VALIDATE_PENDSV_VECTOR=0"; Diagnostic = "startup validation is mandatory"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-svc-validation"; Define = "-DFIBER_VALIDATE_SVC_VECTOR=0"; Diagnostic = "startup validation is mandatory"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-basepri-validation"; Define = "-DFIBER_VALIDATE_BASEPRI_PRIORITY_MASK=0"; Diagnostic = "startup validation is mandatory"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-prigroup-validation"; Define = "-DFIBER_VALIDATE_PRIORITY_GROUPING=0"; Diagnostic = "startup validation is mandatory"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-errata-validation"; Define = "-DFIBER_VALIDATE_M7_R0P1_ERRATA_POLICY=0"; Diagnostic = "startup validation is mandatory"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-svc-priority-validation"; Define = "-DFIBER_VALIDATE_SVC_PRIORITY=0"; Diagnostic = "startup validation is mandatory"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-force-prigroup"; Define = "-DFIBER_FORCE_PRIGROUP=0"; Diagnostic = "owns neither PRIGROUP nor SysTick"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-tune-systick"; Define = "-DFIBER_TUNE_SYSTICK=0"; Diagnostic = "owns neither PRIGROUP nor SysTick"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-tune-svcall"; Define = "-DFIBER_TUNE_SVCALL=1"; Diagnostic = "owns neither PRIGROUP nor SysTick"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-scheduled-validation"; Define = "-DFIBER_VALIDATE_SCHEDULED_CONTEXT=0"; Diagnostic = "restore-context validation is mandatory"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-current-validation"; Define = "-DFIBER_VALIDATE_CURRENT=0"; Diagnostic = "runtime current-context ownership is always enforced"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-enable-cpacr"; Define = "-DFIBER_ENABLE_CPACR=0"; Diagnostic = "FIBER_ENABLE_CPACR was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-force-save-fpu"; Define = "-DFIBER_FORCE_SAVE_FPU=1"; Diagnostic = "FIBER_FORCE_SAVE_FPU was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-vtor-use-ns"; Define = "-DFIBER_VTOR_USE_NS=1"; Diagnostic = "FIBER_VTOR_USE_NS was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-run-nonsecure"; Define = "-DFIBER_RUN_NONSECURE=1"; Diagnostic = "FIBER_RUN_NONSECURE was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-exc-return"; Define = "-DFIBER_INITIAL_EXC_RETURN=0xFFFFFFFFu"; Diagnostic = "FIBER_INITIAL_EXC_RETURN was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-clear-fpca"; Define = "-DFIBER_BOOT_CLEAR_FPCA=0"; Diagnostic = "FIBER_BOOT_CLEAR_FPCA was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-stack-align"; Define = "-DFIBER_STACK_ALIGN=16"; Diagnostic = "FIBER_STACK_ALIGN was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-canary-value"; Define = "-DFIBER_CANARY_VALUE=0"; Diagnostic = "FIBER_CANARY_VALUE was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-context-area"; Define = "-DFIBER_BOOT_EXTRA_BYTES=4"; Diagnostic = "FIBER_BOOT_EXTRA_BYTES was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-switch-mask"; Define = "-DFIBER_SWITCH_MASK_IRQS=0"; Diagnostic = "FIBER_SWITCH_MASK_IRQS was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-switch-barriers"; Define = "-DFIBER_SWITCH_STRICT_BARRIERS=0"; Diagnostic = "FIBER_SWITCH_STRICT_BARRIERS was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-m7-r0p1-errata-switch"; Define = "-DFIBER_CORTEX_M7_R0P1_ERRATA_837070=1"; Diagnostic = "FIBER_CORTEX_M7_R0P1_ERRATA_837070 was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-legacy-trait-bridge"; Define = "-DFIBER_PORT_TRAITS_LEGACY_BRIDGE=1"; Diagnostic = "FIBER_PORT_TRAITS_LEGACY_BRIDGE was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-basepri-trait"; Define = "-DFIBER_HAS_BASEPRI=1"; Diagnostic = "FIBER_HAS_BASEPRI is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-faultmask-trait"; Define = "-DFIBER_HAS_FAULTMASK=1"; Diagnostic = "FIBER_HAS_FAULTMASK is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-vtor-trait"; Define = "-DFIBER_HAS_VTOR=1"; Diagnostic = "FIBER_HAS_VTOR is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-psplim-trait"; Define = "-DFIBER_HAS_PSPLIM=1"; Diagnostic = "FIBER_HAS_PSPLIM is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-fpu-trait"; Define = "-DFIBER_HAS_FPU=1"; Diagnostic = "FIBER_HAS_FPU is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-extended-fp-trait"; Define = "-DFIBER_HAS_EXTENDED_FP_CONTEXT=1"; Diagnostic = "FIBER_HAS_EXTENDED_FP_CONTEXT is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-psplim-use-trait"; Define = "-DFIBER_USE_PSPLIM_REGISTER=1"; Diagnostic = "FIBER_USE_PSPLIM_REGISTER is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-mve-trait"; Define = "-DFIBER_HAS_MVE=1"; Diagnostic = "FIBER_HAS_MVE is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-pac-trait"; Define = "-DFIBER_HAS_PAC=1"; Diagnostic = "FIBER_HAS_PAC is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-bti-trait"; Define = "-DFIBER_HAS_BTI=1"; Diagnostic = "FIBER_HAS_BTI is obsolete"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-psp-levels"; Define = "-DFIBER_EXC_LEVELS_ON_PSP=2"; Diagnostic = "FIBER_EXC_LEVELS_ON_PSP was removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "unimplemented-basepri-bits"; Define = "-DFIBER_SCHEDULER_BASEPRI=1"; Diagnostic = "uses unimplemented priority bits"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "eight-bit-basepri-subpriority"; Define = "-DFIBER_SCHEDULER_BASEPRI=1"; Diagnostic = "bit 0 is subpriority"; Dir = $probe8Dir; Source = $probeSource }
    )

    foreach ($case in $negativeCases) {
        Write-Host "== cortex-m7f / settings-contract-$($case.Name) =="
        $objectPath = Join-Path $case.Dir ($case.Name + ".o")
        $logPath = Join-Path $case.Dir ($case.Name + ".log")
        $negativeArgs = $probeCommonArgs + @(
            $case.Define,
            "-I$($case.Dir)",
            "-I$RepoRoot",
            "-I$(Join-Path $RepoRoot 'fiber')",
            "-I$cmsis",
            "-c",
            $case.Source,
            "-o",
            $objectPath
        )
        $negativeResult = Invoke-CompilerProbe -Compiler $gcc -Arguments $negativeArgs `
            -LogPath $logPath

        if ($negativeResult.ExitCode -eq 0) {
            throw "Invalid setting unexpectedly compiled: $($case.Name)"
        }
        $normalizedOutput = $negativeResult.Output -replace '\s+', ' '
        $normalizedDiagnostic = $case.Diagnostic -replace '\s+', ' '
        if ($normalizedOutput -notmatch [regex]::Escape($normalizedDiagnostic)) {
            throw "Invalid setting failed for the wrong reason: $($case.Name)`n$($negativeResult.Output)"
        }
    }

    Write-Host ""
    Write-Host "PASS: compile matrix completed."
}
finally {
    if ($KeepBuild) {
        Write-Host "Kept build directory: $buildRoot"
    }
    else {
        Remove-Item -LiteralPath $buildRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
