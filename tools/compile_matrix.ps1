param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
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

$gcc = Find-ArmGcc
$cmsis = Find-CmsisCore

$sources = @(
    "fiber\fiber_core.c",
    "fiber\fiber_boot.c",
    "fiber\fiber_stack.c",
    "fiber\port\fiber_port_state.c",
    "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c",
    "fiber\port\armv6m\fiber_port_armv6m.c",
    "fiber\port\armv7m\fiber_port_armv7m.c",
    "fiber\port\armv7em\fiber_port_armv7em.c",
    "fiber\target\fiber_fpu.c",
    "fiber\target\fiber_irq.c",
    "fiber\target\fiber_panic.c"
)

$configs = @(
    [pscustomobject]@{ Name = "cortex-m0";         CpuArgs = @("-mcpu=cortex-m0");              Core = "core_cm0.h";     VtorPresent = 0; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m0plus";     CpuArgs = @("-mcpu=cortex-m0plus");          Core = "core_cm0plus.h"; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m3";         CpuArgs = @("-mcpu=cortex-m3");              Core = "core_cm3.h";     VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m4";         CpuArgs = @("-mcpu=cortex-m4");              Core = "core_cm4.h";     VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m4f";        CpuArgs = @("-mcpu=cortex-m4");              Core = "core_cm4.h";     VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv4-sp-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m7";         CpuArgs = @("-mcpu=cortex-m7");              Core = "core_cm7.h";     VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m7f";        CpuArgs = @("-mcpu=cortex-m7");              Core = "core_cm7.h";     VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv5-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m23";        CpuArgs = @("-mcpu=cortex-m23");             Core = "core_cm23.h";    VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m33";        CpuArgs = @("-mcpu=cortex-m33");             Core = "core_cm33.h";    VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m33f";       CpuArgs = @("-mcpu=cortex-m33");             Core = "core_cm33.h";    VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv5-sp-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m55";        CpuArgs = @("-mcpu=cortex-m55");             Core = "core_cm55.h";    VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m55f";       CpuArgs = @("-mcpu=cortex-m55");             Core = "core_cm55.h";    VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv5-sp-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m55-mve-fp"; CpuArgs = @("-march=armv8.1-m.main+mve.fp"); Core = "core_cm55.h";    VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfloat-abi=hard") }
)

$portProfiles = @{
    "cortex-m0"         = "FIBER_PORT_PROFILE_ARMV6M"
    "cortex-m0plus"     = "FIBER_PORT_PROFILE_ARMV6M"
    "cortex-m3"         = "FIBER_PORT_PROFILE_ARMV7M"
    "cortex-m4"         = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m4f"        = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m7"         = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m7f"        = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m23"        = "FIBER_PORT_PROFILE_ARMV8M_BASELINE"
    "cortex-m33"        = "FIBER_PORT_PROFILE_ARMV8M_MAINLINE"
    "cortex-m33f"       = "FIBER_PORT_PROFILE_ARMV8M_MAINLINE"
    "cortex-m55"        = "FIBER_PORT_PROFILE_ARMV8M_MAINLINE"
    "cortex-m55f"       = "FIBER_PORT_PROFILE_ARMV81M_MAINLINE"
    "cortex-m55-mve-fp" = "FIBER_PORT_PROFILE_ARMV81M_MAINLINE"
}

$buildRoot = Join-Path ([IO.Path]::GetTempPath()) ("fiber-compile-matrix-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $buildRoot | Out-Null

try {
    Write-Host "Compiler: $gcc"
    Write-Host "CMSIS:    $cmsis"
    Write-Host "Build:    $buildRoot"

    foreach ($cfg in $configs) {
        $profile = $portProfiles[$cfg.Name]
        if ([string]::IsNullOrWhiteSpace($profile)) {
            throw "No explicit FIBER_PORT_PROFILE mapping for $($cfg.Name)"
        }

        $wrapperDefines = @("-DFIBER_PENDSV_WIRED=1")
        if ($profile -eq "FIBER_PORT_PROFILE_ARMV7EM") {
            $wrapperDefines += "-DFIBER_SVC_WIRED=1"
        }

        $directPendsvDefines = @("-DFIBER_PENDSV_VECTOR_DIRECT=1")
        if ($profile -eq "FIBER_PORT_PROFILE_ARMV7EM") {
            $directPendsvDefines += "-DFIBER_SVC_WIRED=1"
        }

        $selectionModes = @(
            [pscustomobject]@{ Name = "auto";                  Defines = $wrapperDefines; ExtraArgs = @() },
            [pscustomobject]@{ Name = "explicit";              Defines = @("-DFIBER_PORT_PROFILE=$profile") + $wrapperDefines; ExtraArgs = @() },
            [pscustomobject]@{ Name = "auto-direct-pendsv";    Defines = $directPendsvDefines; ExtraArgs = @() },
            [pscustomobject]@{ Name = "explicit-direct-pendsv"; Defines = @("-DFIBER_PORT_PROFILE=$profile") + $directPendsvDefines; ExtraArgs = @() }
        )

        if ($profile -eq "FIBER_PORT_PROFILE_ARMV7EM") {
            $selectionModes += [pscustomobject]@{
                Name = "auto-direct-vectors"
                Defines = @(
                    "-DFIBER_PENDSV_VECTOR_DIRECT=1",
                    "-DFIBER_SVC_VECTOR_DIRECT=1"
                )
                ExtraArgs = @()
            }
            $selectionModes += [pscustomobject]@{
                Name = "explicit-direct-vectors"
                Defines = @(
                    "-DFIBER_PORT_PROFILE=$profile",
                    "-DFIBER_PENDSV_VECTOR_DIRECT=1",
                    "-DFIBER_SVC_VECTOR_DIRECT=1"
                )
                ExtraArgs = @()
            }
        }

        if (($cfg.Name -eq "cortex-m7") -or ($cfg.Name -eq "cortex-m7f")) {
            $selectionModes += [pscustomobject]@{
                Name = "explicit-r0p1-errata"
                Defines = @(
                    "-DFIBER_PORT_PROFILE=$profile",
                    "-DFIBER_PENDSV_WIRED=1",
                    "-DFIBER_SVC_WIRED=1",
                    "-DFIBER_CORTEX_M7_R0P1_ERRATA_837070=1"
                )
                ExtraArgs = @()
            }
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
                    "-DFIBER_RUN_NONSECURE=1"
                )
                ExtraArgs = @()
            }
            $selectionModes += [pscustomobject]@{
                Name = "explicit-secure-target-ns-bank"
                Defines = @(
                    "-DFIBER_PORT_PROFILE=$profile",
                    "-DFIBER_PENDSV_WIRED=1",
                    "-DFIBER_RUN_NONSECURE=1",
                    "-DFIBER_TZ_NS=1"
                )
                ExtraArgs = @("-mcmse")
            }
        }

        foreach ($mode in $selectionModes) {
            $cfgDir = Join-Path (Join-Path $buildRoot $cfg.Name) $mode.Name
            New-Item -ItemType Directory -Path $cfgDir | Out-Null

            $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_

#define __MPU_PRESENT             0U
#define __VTOR_PRESENT            $($cfg.VtorPresent)U
#define __NVIC_PRIO_BITS          4U
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
                    "-Wno-unused-parameter",
                    "-Werror=implicit-function-declaration",
                    "-Werror=return-type"
                ) + $mode.Defines + @(
                    "-I$cfgDir",
                    "-I$RepoRoot",
                    "-I$(Join-Path $RepoRoot 'fiber')",
                    "-I$(Join-Path $RepoRoot 'fiber\target')",
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
            }
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
