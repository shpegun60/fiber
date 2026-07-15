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

    $searchIndex = 0
    $signatureIndex = -1
    $openBraceIndex = -1
    while ($true) {
        $candidate = $Source.IndexOf($Signature, $searchIndex,
            [System.StringComparison]::Ordinal)
        if ($candidate -lt 0) {
            break
        }

        $afterSignature = $candidate + $Signature.Length
        $candidateBrace = $Source.IndexOf('{', $afterSignature)
        $candidateSemicolon = $Source.IndexOf(';', $afterSignature)
        if (($candidateBrace -ge 0) -and
                (($candidateSemicolon -lt 0) -or
                 ($candidateBrace -lt $candidateSemicolon))) {
            $signatureIndex = $candidate
            $openBraceIndex = $candidateBrace
            break
        }

        $searchIndex = $afterSignature
    }

    if ($signatureIndex -lt 0) {
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

    foreach ($path in $sources.Keys) {
        if ($sources[$path].IndexOf("fiber_port_selected.h",
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "Common runtime must not include the selected complete type facade: $path"
        }
    }

    $forbiddenRuntimeCpuAccess = @(
        "__get_IPSR",
        "__get_PRIMASK",
        "__get_CONTROL",
        "__get_BASEPRI",
        "__get_FAULTMASK",
        "fiber_port_basepri_read",
        "fiber_port_scheduler_critical_",
        "FIBER_PORT_HAS_"
    )
    foreach ($forbidden in $forbiddenRuntimeCpuAccess) {
        if ($sources[$runtimePath].IndexOf($forbidden,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "Common scheduler state must not inspect selected CPU state: $forbidden in $runtimePath"
        }
    }

    $requiredCoreCalls = @(
        "fiber_port_context_init(",
        "fiber_port_require_start_environment();",
        "fiber_port_require_start_interrupt_state();",
        "fiber_port_runtime_prepare();",
        "fiber_port_context_prepare_first_start(",
        "fiber_port_scheduler_pick_first_from_start();",
        "fiber_port_scheduler_set_pick_next("
    )
    foreach ($requiredCall in $requiredCoreCalls) {
        if ($sources[$corePath].IndexOf($requiredCall, [System.StringComparison]::Ordinal) -lt 0) {
            throw "fiber_core.c must use selected-port context ABI: missing $requiredCall"
        }
    }

    $futureForwardAdapters = @(
        "fiber_port_require_scheduler_configuration_environment(",
        "fiber_port_runtime_prepare_start(",
        "fiber_port_runtime_select_first(",
        "fiber_port_runtime_start_first(",
        "fiber_port_runtime_schedule("
    )
    foreach ($adapter in $futureForwardAdapters) {
        if ($sources[$corePath].IndexOf($adapter,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "Adapter checkpoint must not change common runtime choreography: $adapter"
        }
    }

    $requiredRuntimeCalls = @(
        "fiber_internal_scheduler_invoke_pick_next(",
        "fiber_internal_scheduler_commit_current_context("
    )
    foreach ($requiredCall in $requiredRuntimeCalls) {
        if ($sources[$runtimePath].IndexOf($requiredCall,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "fiber_runtime_state.c must retain common scheduler ownership: missing $requiredCall"
        }
    }

    $portSources = @(
        "fiber\port\ARM_CM0\fiber_port.c",
        "fiber\port\ARM_CM3\fiber_port.c",
        "fiber\port\ARM_CM4\fiber_port.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port.c",
        "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c"
    )
    $requiredPortBridgeSymbols = @(
        "FiberPortSchedulerCpuState",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_runtime_schedule",
        "fiber_port_scheduler_set_pick_next",
        "fiber_port_scheduler_pick_first_from_start",
        "fiber_port_scheduler_pick_next_from_pendsv",
        "fiber_port_context_validate_restore",
        "fiber_internal_scheduler_commit_current_context"
    )
    foreach ($relativePath in $portSources) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw
        foreach ($requiredSymbol in $requiredPortBridgeSymbols) {
            if ($source.IndexOf($requiredSymbol,
                    [System.StringComparison]::Ordinal) -lt 0) {
                throw "Selected port must own scheduler CPU-state validation: missing $requiredSymbol in $path"
            }
        }

        $configurationBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_require_scheduler_configuration_environment(void)" `
            -Path $path
        if (($configurationBody.IndexOf("FIBER_REQUIRE(__get_IPSR() == 0u, 'i');",
                    [System.StringComparison]::Ordinal) -lt 0) -or
                ($configurationBody.IndexOf("fiber_internal_scheduler_",
                    [System.StringComparison]::Ordinal) -ge 0)) {
            throw "Scheduler-configuration adapter must validate only its CPU environment: $path"
        }

        $prepareBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_runtime_prepare_start(void)" -Path $path
        $prepareCalls = @(
            "fiber_port_require_start_environment();",
            "fiber_port_require_start_interrupt_state();",
            "fiber_pendsv_init_lowest_priority();",
            "fiber_port_runtime_prepare();"
        )
        $lastIndex = -1
        foreach ($call in $prepareCalls) {
            $callIndex = $prepareBody.IndexOf($call,
                [System.StringComparison]::Ordinal)
            if ($callIndex -le $lastIndex) {
                throw "Start-preparation adapter call order is incomplete: $call in $path"
            }
            $lastIndex = $callIndex
        }

        $selectBody = Get-CFunctionBody -Source $source `
            -Signature "FiberContext *fiber_port_runtime_select_first(void)" `
            -Path $path
        if ($selectBody.IndexOf(
                "return fiber_port_scheduler_pick_first_from_start();",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "First-selection adapter must delegate to the validated bridge: $path"
        }

        $startBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_runtime_start_first(FiberContext *first)" `
            -Path $path
        $startPrepare = $startBody.IndexOf(
            "fiber_port_context_prepare_first_start(first)",
            [System.StringComparison]::Ordinal)
        $startMasks = $startBody.IndexOf(
            "fiber_port_require_start_interrupt_state();",
            [System.StringComparison]::Ordinal)
        $startTransfer = $startBody.IndexOf(
            "fiber_port_start_first_context(msp_top);",
            [System.StringComparison]::Ordinal)
        if (($startPrepare -lt 0) -or ($startMasks -le $startPrepare) -or
                ($startTransfer -le $startMasks)) {
            throw "First-start adapter must preserve validation and transfer order: $path"
        }

        $scheduleBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_runtime_schedule(void)" -Path $path
        $scheduleRequire = $scheduleBody.IndexOf(
            "fiber_port_require_schedule_environment();",
            [System.StringComparison]::Ordinal)
        $scheduleRequest = $scheduleBody.IndexOf(
            "fiber_port_request_schedule();",
            [System.StringComparison]::Ordinal)
        if (($scheduleRequire -lt 0) -or ($scheduleRequest -le $scheduleRequire)) {
            throw "Schedule adapter must preserve environment-before-request order: $path"
        }
    }
}

function Test-SelectedPortPrivateDeclarations {
    param([string]$RepositoryRoot)

    $privateHeaders = @(
        "fiber\port\ARM_CM0\fiber_port_private.h",
        "fiber\port\ARM_CM3\fiber_port_private.h",
        "fiber\port\ARM_CM4\fiber_port_private.h",
        "fiber\port\ARM_CM7\r0p1\fiber_port_private.h",
        "fiber\port\transitional_v8m\fiber_port_private.h"
    )
    $requiredPrivateSymbols = @(
        "fiber_internal_task_return",
        "fiber_port_init_context_frame",
        "fiber_port_context_validate_restore",
        "fiber_port_context_validate_save_current",
        "fiber_port_context_prepare_first_start",
        "fiber_port_require_start_environment",
        "fiber_port_require_start_interrupt_state",
        "fiber_port_runtime_prepare",
        "fiber_port_require_schedule_environment",
        "fiber_port_request_schedule",
        "fiber_port_scheduler_set_pick_next",
        "fiber_port_scheduler_pick_first_from_start",
        "fiber_port_scheduler_pick_next_from_pendsv",
        "fiber_exception_runtime_check",
        "fiber_pendsv_init_lowest_priority",
        "fiber_port_start_first_context",
        "fiber_svc",
        "fiber_pendsv"
    )

    foreach ($relativePath in $privateHeaders) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw

        if ($source.IndexOf("fiber_port_runtime_abi.h",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "Selected-port private header must import the generic runtime ABI: $path"
        }
        foreach ($symbol in $requiredPrivateSymbols) {
            if (-not [regex]::IsMatch($source,
                    "\b$([regex]::Escape($symbol))\s*\(")) {
                throw "Selected-port private header is missing ${symbol}: $path"
            }
        }
    }

    $implementationSources = @(
        "fiber\port\ARM_CM0\fiber_port.c",
        "fiber\port\ARM_CM0\fiber_port_boot.c",
        "fiber\port\ARM_CM0\fiber_port_exception.c",
        "fiber\port\ARM_CM3\fiber_port.c",
        "fiber\port\ARM_CM3\fiber_port_boot.c",
        "fiber\port\ARM_CM3\fiber_port_exception.c",
        "fiber\port\ARM_CM4\fiber_port.c",
        "fiber\port\ARM_CM4\fiber_port_boot.c",
        "fiber\port\ARM_CM4\fiber_port_exception.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c",
        "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c",
        "fiber\port\transitional_v8m\fiber_port_boot.c",
        "fiber\port\transitional_v8m\fiber_port_exception.c"
    )
    foreach ($relativePath in $implementationSources) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw
        if ($source.IndexOf('#include "fiber_port_private.h"',
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "Selected-port implementation must include its private declarations: $path"
        }
    }

    $legacyDeclarationHeaders = @(
        "fiber\port\ARM_CM0\fiber_portmacro.h",
        "fiber\port\ARM_CM0\fiber_port_boot.h",
        "fiber\port\ARM_CM3\fiber_portmacro.h",
        "fiber\port\ARM_CM3\fiber_port_boot.h",
        "fiber\port\ARM_CM4\fiber_portmacro.h",
        "fiber\port\ARM_CM4\fiber_port_boot.h",
        "fiber\port\ARM_CM7\r0p1\fiber_portmacro.h",
        "fiber\port\ARM_CM7\r0p1\fiber_port_boot.h",
        "fiber\port\transitional_v8m\fiber_portmacro.h",
        "fiber\port\transitional_v8m\fiber_port_boot.h",
        "fiber\port\transitional_v8m\fiber_port_transitional_v8m.h"
    )
    foreach ($relativePath in $legacyDeclarationHeaders) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw
        if ($source.IndexOf("fiber_port_runtime_abi.h",
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "Port macro/boot headers must not expose the generic callable ABI: $path"
        }
        foreach ($symbol in $requiredPrivateSymbols) {
            if ([regex]::IsMatch($source,
                    "\b$([regex]::Escape($symbol))\s*\(")) {
                throw "Port-private declaration leaked into legacy header: $symbol in $path"
            }
        }
    }
}

function Test-SelectedPortIntegrityPreflight {
    param([string]$RepositoryRoot)

    $bootSources = @(
        "fiber\port\ARM_CM0\fiber_port_boot.c",
        "fiber\port\ARM_CM3\fiber_port_boot.c",
        "fiber\port\ARM_CM4\fiber_port_boot.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c",
        "fiber\port\transitional_v8m\fiber_port_boot.c"
    )

    foreach ($relativePath in $bootSources) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw
        $saveBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_context_validate_save_current(const FiberContext *ctx)" `
            -Path $path
        $restoreBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_context_validate_restore(FiberContext *ctx)" `
            -Path $path

        $savePointer = $saveBody.IndexOf("fiber_port_validate_context_pointer(ctx);",
            [System.StringComparison]::Ordinal)
        $saveStackMap = $saveBody.IndexOf(
            "fiber_port_validate_stack_address_map_on_switch(ctx);",
            [System.StringComparison]::Ordinal)
        $saveCanary = $saveBody.IndexOf("fiber_port_validate_stack_canary(ctx);",
            [System.StringComparison]::Ordinal)
        $saveMsp = $saveBody.IndexOf("fiber_port_validate_start_msp_for_boot(&ctx->boot);",
            [System.StringComparison]::Ordinal)
        $savePsp = $saveBody.IndexOf("const uintptr_t psp = (uintptr_t)__get_PSP();",
            [System.StringComparison]::Ordinal)
        $saveGuardedCapture = [regex]::IsMatch($saveBody,
            '(?s)#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH\s+FiberPortValidationCpuState cpu_state;\s+fiber_port_capture_validation_cpu_state\(&cpu_state\);\s*#endif')
        $saveGuardedStackMap = [regex]::IsMatch($saveBody,
            '(?s)#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH\s+fiber_port_validate_stack_address_map_on_switch\(ctx\);\s*#endif')
        $saveGuardedStateCheck = [regex]::IsMatch($saveBody,
            '(?s)#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH\s+fiber_port_validate_validation_cpu_state\(&cpu_state\);\s*#endif')

        if (($savePointer -lt 0) -or
                ($saveStackMap -lt 0) -or ($saveCanary -lt 0) -or ($saveMsp -ge 0) -or
                ($savePsp -lt 0) -or
                (-not $saveGuardedCapture) -or (-not $saveGuardedStackMap) -or
                (-not $saveGuardedStateCheck) -or
                ($savePointer -ge $saveStackMap) -or
                ($saveStackMap -ge $saveCanary) -or
                ($saveCanary -ge $savePsp)) {
            throw "Selected port save preflight must gate all CPU-state and address-map hooks before canary and live PSP access without revalidating the startup MSP plan: $path"
        }

        $restorePointer = $restoreBody.IndexOf("fiber_port_validate_context_pointer(ctx);",
            [System.StringComparison]::Ordinal)
        $restoreStackMap = $restoreBody.IndexOf(
            "fiber_port_validate_stack_address_map_on_switch(ctx);",
            [System.StringComparison]::Ordinal)
        $restoreCode = $restoreBody.IndexOf("fiber_addr_plausible_code(",
            [System.StringComparison]::Ordinal)
        $restoreStateCheck = $restoreBody.LastIndexOf(
            "fiber_port_validate_validation_cpu_state(&cpu_state);",
            [System.StringComparison]::Ordinal)
        $restoreMsp = $restoreBody.IndexOf(
            "fiber_port_validate_start_msp_for_boot(&ctx->boot);",
            [System.StringComparison]::Ordinal)
        $restoreGuardedCapture = [regex]::IsMatch($restoreBody,
            '(?s)#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH\s+FiberPortValidationCpuState cpu_state;\s+fiber_port_capture_validation_cpu_state\(&cpu_state\);\s*#endif')
        $restoreGuardedStackMap = [regex]::IsMatch($restoreBody,
            '(?s)#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH\s+fiber_port_validate_stack_address_map_on_switch\(ctx\);\s*#endif')
        $restoreGuardedCode = [regex]::IsMatch($restoreBody,
            '(?s)#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH\s+FIBER_REQUIRE\(fiber_addr_plausible_code\(\(uintptr_t\)stacked_pc\) != 0, .c.\);\s*#endif')
        $restoreGuardedStateCheck = [regex]::IsMatch($restoreBody,
            '(?s)#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH\s+fiber_port_validate_validation_cpu_state\(&cpu_state\);\s*#endif')

        if (($restorePointer -lt 0) -or
                ($restoreStackMap -lt 0) -or ($restoreCode -lt 0) -or
                ($restoreStateCheck -lt 0) -or
                ($restoreMsp -lt 0) -or
                (-not $restoreGuardedCapture) -or
                (-not $restoreGuardedStackMap) -or
                (-not $restoreGuardedCode) -or
                (-not $restoreGuardedStateCheck) -or
                ($restorePointer -ge $restoreStackMap) -or
                ($restoreStackMap -ge $restoreMsp) -or
                ($restoreMsp -ge $restoreCode) -or
                ($restoreStateCheck -le $restoreCode)) {
            throw "Selected port restore validation must retain the startup MSP plan and gate all CPU-state and address-map hooks: $path"
        }

        $pointerBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_validate_context_pointer(const FiberContext *const ctx)" `
            -Path $path
        $stackMapBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_validate_stack_address_map_on_switch(" `
            -Path $path
        $requiredAddressMapPolicy = @(
            "#if FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH",
            "const uintptr_t end = begin + sizeof(*ctx);",
            "fiber_addr_plausible_ram(begin, end)"
        )
        foreach ($required in $requiredAddressMapPolicy) {
            if ($pointerBody.IndexOf($required,
                    [System.StringComparison]::Ordinal) -lt 0) {
                throw "Selected port context address-map policy is incomplete in ${path}: $required"
            }
        }

        $requiredStackAddressMapPolicy = @(
            "fiber_addr_plausible_ram(ctx->boot.stack_base,",
            "ctx->boot.stack_top)"
        )
        foreach ($required in $requiredStackAddressMapPolicy) {
            if ($stackMapBody.IndexOf($required,
                    [System.StringComparison]::Ordinal) -lt 0) {
                throw "Selected port stack address-map policy is incomplete in ${path}: $required"
            }
        }

        $fallbackBody = Get-CFunctionBody -Source $source `
            -Signature "uintptr_t fiber_port_fallback_initial_msp_checked(void)" `
            -Path $path
        $prepareMspBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_prepare_start_msp_plan(void)" `
            -Path $path
        $validateMspBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_validate_start_msp_for_boot(const FiberPortBoot *const ctx)" `
            -Path $path
        $fallbackCapture = $fallbackBody.IndexOf(
            "fiber_port_capture_validation_cpu_state(&cpu_state);",
            [System.StringComparison]::Ordinal)
        $fallbackCall = $fallbackBody.IndexOf("fiber_fallback_initial_msp();",
            [System.StringComparison]::Ordinal)
        $fallbackStateCheck = $fallbackBody.IndexOf(
            "fiber_port_validate_validation_cpu_state(&cpu_state);",
            [System.StringComparison]::Ordinal)
        $fallbackWrapper = "fiber_port_fallback_initial_msp_checked();"

        if (($fallbackCapture -lt 0) -or ($fallbackCall -lt 0) -or
                ($fallbackStateCheck -lt 0) -or ($fallbackCapture -ge $fallbackCall) -or
                ($fallbackStateCheck -le $fallbackCall) -or
                ($prepareMspBody.IndexOf($fallbackWrapper,
                    [System.StringComparison]::Ordinal) -lt 0) -or
                ($validateMspBody.IndexOf($fallbackWrapper,
                    [System.StringComparison]::Ordinal) -lt 0) -or
                ($prepareMspBody.IndexOf("fiber_fallback_initial_msp();",
                    [System.StringComparison]::Ordinal) -ge 0) -or
                ($validateMspBody.IndexOf("fiber_fallback_initial_msp();",
                    [System.StringComparison]::Ordinal) -ge 0)) {
            throw "Selected port MSP fallback must preserve CPU state locally: $path"
        }
    }
}

function Test-PendSvSaveValidationOrdering {
    param([string]$RepositoryRoot)

    $portSources = @(
        "fiber\port\ARM_CM0\fiber_port.c",
        "fiber\port\ARM_CM3\fiber_port.c",
        "fiber\port\ARM_CM4\fiber_port.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port.c",
        "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c"
    )

    foreach ($relativePath in $portSources) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw
        $pendsvBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_pendsv(void)" -Path $path

        $validationCalls = [regex]::Matches($pendsvBody,
            "bl\s+fiber_port_context_validate_save_current\b")
        $currentContextLoads = [regex]::Matches($pendsvBody,
            '"ldr\s+r1,\s+\[r1\][^"]*\\n"')
        $stackBaseLoads = [regex]::Matches($pendsvBody,
            "ldr\s+r2,\s+\[r1,\s+%c\[offsb\]\]")

        if (($validationCalls.Count -eq 0) -or
                ($validationCalls.Count -ne $currentContextLoads.Count) -or
                ($validationCalls.Count -ne $stackBaseLoads.Count)) {
            throw "PendSV save validation/load count mismatch in $path"
        }

        for ($index = 0; $index -lt $validationCalls.Count; ++$index) {
            if ($validationCalls[$index].Index -ge $stackBaseLoads[$index].Index) {
                throw "PendSV reads current stack metadata before save validation in $path"
            }

            $currentLoadEnd = $currentContextLoads[$index].Index +
                    $currentContextLoads[$index].Length
            if ($currentLoadEnd -ge $validationCalls[$index].Index) {
                throw "PendSV current-context load does not precede save validation in $path"
            }

            $beforeValidation = $pendsvBody.Substring($currentLoadEnd,
                    $validationCalls[$index].Index - $currentLoadEnd)
            $currentFieldAccesses = [regex]::Matches($beforeValidation,
                '"\s*(?:ldr|str|ldmia|stmia|ldmdb|stmdb)\s+[^"\r\n]*\[\s*r1(?:\s*,|\s*\])')
            if ($currentFieldAccesses.Count -ne 0) {
                throw "PendSV reads or writes a current-context field before save validation in $path"
            }

            # Before the validator, r1 is the untrusted current-context pointer.
            # Keep the allowed sequence deliberately narrow: test it, preserve it
            # across the C call, then pass it as r0. This rejects pointer aliases
            # such as "mov r3, r1; ldr r2, [r3]" that a base-r1-only scan misses.
            $r1Instructions = [regex]::Matches($beforeValidation,
                '"(?<instruction>[^"\r\n]*\br1\b[^"\r\n]*)\\n"')
            foreach ($match in $r1Instructions) {
                $instruction = $match.Groups['instruction'].Value.Trim()
                if ($instruction -notmatch '^(?:cmp\s+r1,\s+#0|cbz\s+r1,\s+\S+|push\s+\{(?=[^}]*\br1\b)[^}]+\}|mov(?:s)?\s+r0,\s*r1)$') {
                    throw "PendSV uses r1 outside the save-validator preflight contract in ${path}: $instruction"
                }
            }

            $nullChecks = [regex]::Matches($beforeValidation,
                '"\s*(?:cmp\s+r1,\s+#0|cbz\s+r1,\s+\S+)\s*\\n"')
            $preserveCurrent = [regex]::Matches($beforeValidation,
                '"\s*push\s+\{(?=[^}]*\br0\b)(?=[^}]*\br1\b)(?=[^}]*\blr\b)[^}]+\}\s*\\n"')
            $passCurrent = [regex]::Matches($beforeValidation,
                '"\s*mov(?:s)?\s+r0,\s*r1\s*\\n"')
            if (($nullChecks.Count -ne 1) -or ($preserveCurrent.Count -ne 1) -or
                    ($passCurrent.Count -ne 1) -or
                    ($preserveCurrent[0].Index -ge $passCurrent[0].Index)) {
                throw "PendSV save-validator preflight must null-check, preserve, and pass current in $path"
            }
        }
    }
}

function Test-ScheduleValidationOwnership {
    param([string]$RepositoryRoot)

    $portSources = @(
        "fiber\port\ARM_CM0\fiber_port.c",
        "fiber\port\ARM_CM3\fiber_port.c",
        "fiber\port\ARM_CM4\fiber_port.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port.c",
        "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c"
    )

    foreach ($relativePath in $portSources) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw
        $scheduleBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_require_schedule_environment(void)" `
            -Path $path
        $bridgeBody = Get-CFunctionBody -Source $source `
            -Signature "FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current)" `
            -Path $path

        if ($scheduleBody.IndexOf("fiber_internal_require_schedule_current();",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "Thread schedule path must retain current-context ownership check: $path"
        }
        if ($scheduleBody.IndexOf("fiber_port_context_validate_save_current(",
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "Thread schedule path must not duplicate PendSV save preflight: $path"
        }

        $hook = $bridgeBody.IndexOf("fiber_internal_scheduler_invoke_pick_next(current);",
            [System.StringComparison]::Ordinal)
        $restoreCurrent = $bridgeBody.IndexOf("fiber_port_context_validate_restore(current);",
            [System.StringComparison]::Ordinal)
        $restoreNext = $bridgeBody.IndexOf("fiber_port_context_validate_restore(next);",
            [System.StringComparison]::Ordinal)
        $commit = $bridgeBody.IndexOf("fiber_internal_scheduler_commit_current_context(next);",
            [System.StringComparison]::Ordinal)

        if (($hook -lt 0) -or ($restoreCurrent -ge 0) -or
                ($restoreNext -lt 0) -or ($commit -lt 0) -or
                ($restoreNext -le $hook) -or ($commit -le $restoreNext)) {
            throw "PendSV scheduler bridge must validate only the selected next context after scheduling: $path"
        }
    }
}

function Test-CommonRuntimeWithoutCmsis {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$BuildRoot
    )

    # The common runtime must stay compilation-isolated from CMSIS and selected
    # port headers. It only needs opaque API types plus callable port ABI.
    $probeDir = Join-Path $BuildRoot "common-runtime-no-cmsis"
    New-Item -ItemType Directory -Path $probeDir | Out-Null

    $sources = @(
        "fiber\fiber_core.c",
        "fiber\fiber_runtime_state.c",
        "fiber\fiber_panic.c"
    )
    foreach ($source in $sources) {
        $sourcePath = Join-Path $RepositoryRoot $source
        $objectPath = Join-Path $probeDir ((Split-Path $source -Leaf) + ".o")
        $args = @(
            "-mcpu=cortex-m7",
            "-mthumb",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-Wall",
            "-Wextra",
            "-Wundef",
            "-Werror=undef",
            "-Werror=implicit-function-declaration",
            "-Werror=return-type",
            "-I$RepositoryRoot",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-c",
            $sourcePath,
            "-o",
            $objectPath
        )

        & $Compiler @args
        if ($LASTEXITCODE -ne 0) {
            throw "Common runtime unexpectedly requires CMSIS or selected-port headers: $source"
        }
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
Test-SelectedPortPrivateDeclarations -RepositoryRoot $RepoRoot
Test-SelectedPortIntegrityPreflight -RepositoryRoot $RepoRoot
Test-PendSvSaveValidationOrdering -RepositoryRoot $RepoRoot
Test-ScheduleValidationOwnership -RepositoryRoot $RepoRoot

$commonSources = @(
    "fiber\fiber_core.c",
    "fiber\fiber_runtime_state.c",
    "fiber\fiber_panic.c"
)

$portableApplicationFixture = "tools\fixtures\portable_application.c"
$portableApplicationApiSymbols = @(
    "fiber_current",
    "fiber_init",
    "fiber_schedule",
    "fiber_scheduler_set_pick_next",
    "fiber_start"
)
$forbiddenPortableApplicationHeaders = @(
    "fiber_port_mpu_abi.h",
    "fiber_port_secure_context_abi.h",
    "fiber_port_tfm_abi.h",
    "fiber_runtime_context_configuration_abi.h"
)

$portableApplicationSourcePath = Join-Path $RepoRoot $portableApplicationFixture
$portableApplicationSource = Get-Content -LiteralPath $portableApplicationSourcePath -Raw
$portableApplicationIncludes = [regex]::Matches(
    $portableApplicationSource,
    '(?m)^\s*#\s*include\s*([<"][^>"]+[>"])')

if (($portableApplicationIncludes.Count -ne 1) -or
        ($portableApplicationIncludes[0].Groups[1].Value -ne '"fiber/fiber_core.h"')) {
    throw "Portable application fixture must directly include only fiber/fiber_core.h"
}
if ([regex]::IsMatch($portableApplicationSource,
        '(?m)^\s*#\s*(if|ifdef|ifndef|elif)\b')) {
    throw "Portable application fixture must not contain profile conditionals"
}
if ([regex]::IsMatch($portableApplicationSource,
        '\b(FIBER_PORT_|fiber_port_)')) {
    throw "Portable application fixture must not reference selected-port names"
}

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
    "fiber_port_context_validate_save_current",
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
    "fiber_port_runtime_memory_barrier",
    "fiber_port_panic_wait",
    "fiber_port_require_scheduler_configuration_environment",
    "fiber_port_runtime_prepare_start",
    "fiber_port_runtime_select_first",
    "fiber_port_runtime_start_first",
    "fiber_port_runtime_schedule",
    "fiber_port_require_schedule_environment",
    "fiber_port_request_schedule",
    "fiber_port_scheduler_set_pick_next",
    "fiber_port_scheduler_pick_first_from_start",
    "fiber_port_scheduler_pick_next_from_pendsv",
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

    Write-Host "== common-runtime / no-cmsis =="
    Test-CommonRuntimeWithoutCmsis -RepositoryRoot $RepoRoot -Compiler $gcc `
        -BuildRoot $buildRoot

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
            if ($mode.Name -eq "build-selected") {
                $sources += $portableApplicationFixture
            }
            $objects = @()

            foreach ($source in $sources) {
                $srcPath = Join-Path $RepoRoot $source
                $objName = ($source -replace '[\\/]', '_') + ".o"
                $objPath = Join-Path $cfgDir $objName

                $dependencyPath = $null
                $dependencyArgs = @()
                if ($source -eq $portableApplicationFixture) {
                    $dependencyPath = Join-Path $cfgDir "portable-application.d"
                    $dependencyArgs = @("-MMD", "-MF", $dependencyPath)
                }

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
                ) + $mode.Defines + $dependencyArgs + @(
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

                if ($source -eq $portableApplicationFixture) {
                    if (-not (Test-Path $dependencyPath)) {
                        throw "Portable application dependency output missing for $($cfg.Name)"
                    }

                    $dependencies = Get-Content -LiteralPath $dependencyPath -Raw
                    foreach ($forbiddenHeader in $forbiddenPortableApplicationHeaders) {
                        if ($dependencies.IndexOf($forbiddenHeader,
                                [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            throw "Portable application depends on optional header for $($cfg.Name): $forbiddenHeader"
                        }
                    }

                    $undefinedOutput = & $nm -u $objPath
                    if ($LASTEXITCODE -ne 0) {
                        throw "Portable application symbol scan failed for $($cfg.Name)"
                    }

                    $undefinedSymbols = @($undefinedOutput | ForEach-Object {
                        if ($_ -match '\bU\s+(\S+)$') {
                            $Matches[1]
                        }
                    })
                    foreach ($symbol in $undefinedSymbols) {
                        if ($portableApplicationApiSymbols -notcontains $symbol) {
                            throw "Portable application references non-public symbol for $($cfg.Name): $symbol"
                        }
                    }
                    foreach ($symbol in $portableApplicationApiSymbols) {
                        if ($undefinedSymbols -notcontains $symbol) {
                            throw "Portable application does not exercise public API for $($cfg.Name): $symbol"
                        }
                    }
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
                (Join-Path $RepoRoot "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c"),
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
        "-Werror=unused-function",
        "-Werror=implicit-function-declaration",
        "-Werror=return-type",
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV7EM=1",
        "-DFIBER_PENDSV_WIRED=1",
        "-DFIBER_SVC_WIRED=1"
    )
    # Settings and trait checks are selected-port responsibilities. Probe the
    # concrete CM7 port rather than common fiber_core.c, which deliberately
    # sees only the opaque callable port ABI.
    $probeSource = Join-Path $RepoRoot "fiber\port\ARM_CM7\r0p1\fiber_port.c"
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

    Write-Host "== cortex-m7f / settings-contract-address-map-on-switch =="
    $addressMapOnArgs = $probeCommonArgs + @(
        "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1",
        "-I$probe4Dir",
        "-I$RepoRoot",
        "-I$(Join-Path $RepoRoot 'fiber')",
        "-I$cmsis",
        "-c",
        $probeBootSource,
        "-o",
        (Join-Path $probe4Dir "address-map-on-switch.o")
    )
    $addressMapOnResult = Invoke-CompilerProbe -Compiler $gcc `
        -Arguments $addressMapOnArgs `
        -LogPath (Join-Path $probe4Dir "address-map-on-switch.log")
    if ($addressMapOnResult.ExitCode -ne 0) {
        throw "Address-map-on-switch policy probe failed:`n$($addressMapOnResult.Output)"
    }

    Write-Host "== cortex-m7f / settings-contract-production-switch-policy =="
    $productionSwitchArgs = $probeCommonArgs + @(
        "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0",
        "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=0",
        "-DFIBER_REWIND_MSP=0",
        "-I$probe4Dir",
        "-I$RepoRoot",
        "-I$(Join-Path $RepoRoot 'fiber')",
        "-I$cmsis",
        "-c",
        $probeBootSource,
        "-o",
        (Join-Path $probe4Dir "production-switch-policy.o")
    )
    $productionSwitchResult = Invoke-CompilerProbe -Compiler $gcc `
        -Arguments $productionSwitchArgs `
        -LogPath (Join-Path $probe4Dir "production-switch-policy.log")
    if ($productionSwitchResult.ExitCode -ne 0) {
        throw "Production switch policy probe failed:`n$($productionSwitchResult.Output)"
    }

    $negativeCases = @(
        [pscustomobject]@{ Name = "invalid-fpu-lazy"; Define = "-DFIBER_FPU_LAZY=2"; Diagnostic = "FIBER_FPU_LAZY must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-rewind-msp"; Define = "-DFIBER_REWIND_MSP=2"; Diagnostic = "FIBER_REWIND_MSP must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-hash-on-switch"; Define = "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=2"; Diagnostic = "FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-address-map-on-switch"; Define = "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=2"; Diagnostic = "FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "invalid-permissive-address-map-hooks"; Define = "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=2"; Diagnostic = "FIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS must be 0 or 1"; Dir = $probe4Dir; Source = $probeSource },
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
        [pscustomobject]@{ Name = "predefined-port-faultmask"; Define = "-DFIBER_PORT_HAS_FAULTMASK=0"; Diagnostic = "selected-port traits must not be predefined"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "predefined-port-context-id"; Define = "-DFIBER_PORT_CONTEXT_ABI_PORT_ID=1u"; Diagnostic = "selected-port traits must not be predefined"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "predefined-port-context-layout"; Define = "-DFIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION=1u"; Diagnostic = "selected-port traits must not be predefined"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "predefined-port-context-features"; Define = "-DFIBER_PORT_CONTEXT_ABI_FEATURE_MASK=1u"; Diagnostic = "selected-port traits must not be predefined"; Dir = $probe4Dir; Source = $probeSource },
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
