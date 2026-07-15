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

    $requiredCalls = @("fiber_port_runtime_schedule();")
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

    $forbiddenTransitionalCalls = @(
        "fiber_port_require_schedule_environment();",
        "fiber_port_request_schedule();"
    )
    foreach ($forbidden in $forbiddenTransitionalCalls) {
        if ($scheduleBody.IndexOf($forbidden,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "fiber_schedule must use only the frozen schedule ABI: $forbidden"
        }
    }
}

function Test-FinalForwardPortAbi {
    param([string]$RepositoryRoot)

    $abiPath = Join-Path $RepositoryRoot "fiber\port\fiber_port_runtime_abi.h"
    $abiSource = Get-Content -LiteralPath $abiPath -Raw
    $expectedSymbols = @(
        "fiber_port_context_init",
        "fiber_port_runtime_memory_barrier",
        "fiber_port_panic_wait",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_runtime_schedule"
    ) | Sort-Object
    $actualSymbols = @([regex]::Matches(
        $abiSource,
        '\b(fiber_port_[A-Za-z0-9_]+)\s*\(') | ForEach-Object {
            $_.Groups[1].Value
        } | Sort-Object -Unique)

    if (($actualSymbols.Count -ne $expectedSymbols.Count) -or
            (Compare-Object -ReferenceObject $expectedSymbols `
                -DifferenceObject $actualSymbols)) {
        throw "Generic forward port ABI must expose exactly the frozen eight symbols; found: $($actualSymbols -join ', ')"
    }
}

function Test-FinalReversePortAbi {
    param([string]$RepositoryRoot)

    $abiPath = Join-Path $RepositoryRoot "fiber\fiber_runtime_port_abi.h"
    $abiSource = Get-Content -LiteralPath $abiPath -Raw
    $expectedFunctions = @(
        "fiber_internal_runtime_select_scheduler_candidate",
        "fiber_internal_runtime_publish_current_context",
        "fiber_internal_runtime_require_current_context",
        "fiber_internal_task_return"
    ) | Sort-Object
    $actualFunctions = @([regex]::Matches(
        $abiSource,
        '\b(fiber_internal_[A-Za-z0-9_]+)\s*\(') | ForEach-Object {
            $_.Groups[1].Value
        } | Sort-Object -Unique)

    if (($actualFunctions.Count -ne $expectedFunctions.Count) -or
            (Compare-Object -ReferenceObject $expectedFunctions `
                -DifferenceObject $actualFunctions)) {
        throw "Reverse port ABI must expose exactly the frozen callable symbols; found: $($actualFunctions -join ', ')"
    }

    foreach ($required in @(
            "#define FIBER_RUNTIME_PORT_ABI_VERSION 1u",
            "fiber_internal_runtime_port_abi_v1_anchor",
            '#include "fiber_panic.h"')) {
        if ($abiSource.IndexOf($required,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "Reverse port ABI is missing required contract text: $required"
        }
    }

    if ([regex]::IsMatch($abiSource,
            '(?s)\bextern\b[^;]*\bfiber_internal_runtime_current_context_slot\b[^;]*;')) {
        throw "Reverse port ABI must not expose the current-context slot as a C lvalue"
    }

    $panicHeaderPath = Join-Path $RepositoryRoot "fiber\fiber_panic.h"
    $panicHeader = Get-Content -LiteralPath $panicHeaderPath -Raw
    $panicDeclaration = [regex]::Match($panicHeader,
        '(?s)(?<declaration>[^;]*\bfiber_panic\s*\(\s*char\s+code\s*\)\s*;)')
    if (-not $panicDeclaration.Success) {
        throw "Canonical fiber_panic declaration is missing"
    }
    if ($panicDeclaration.Groups['declaration'].Value.IndexOf("FIBER_API_WEAK",
            [System.StringComparison]::Ordinal) -ge 0) {
        throw "Port-side fiber_panic declaration must be strong; only the fallback definition is weak"
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
        "fiber_port_require_scheduler_configuration_environment();",
        "fiber_internal_scheduler_store_pick_next(",
        "fiber_port_runtime_prepare_start();",
        "fiber_port_runtime_select_first();",
        "fiber_internal_runtime_publish_current_context(first);",
        "fiber_port_runtime_start_first(first);",
        "fiber_port_runtime_schedule();"
    )
    foreach ($requiredCall in $requiredCoreCalls) {
        if ($sources[$corePath].IndexOf($requiredCall, [System.StringComparison]::Ordinal) -lt 0) {
            throw "fiber_core.c must use selected-port context ABI: missing $requiredCall"
        }
    }

    $transitionalCoreCalls = @(
        "fiber_port_require_start_environment(",
        "fiber_port_require_start_interrupt_state(",
        "fiber_pendsv_init_lowest_priority(",
        "fiber_port_runtime_prepare(",
        "fiber_port_context_prepare_first_start(",
        "fiber_port_scheduler_pick_first_from_start(",
        "fiber_port_scheduler_set_pick_next(",
        "fiber_port_require_schedule_environment(",
        "fiber_port_request_schedule(",
        "fiber_port_start_first_context("
    )
    foreach ($call in $transitionalCoreCalls) {
        if ($sources[$corePath].IndexOf($call,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "fiber_core.c must not use displaced transitional port ABI: $call"
        }
    }

    $startBody = Get-CFunctionBody -Source $sources[$corePath] `
        -Signature "void fiber_start(void)" -Path $corePath
    $startSteps = @(
        "FIBER_REQUIRE(fiber_internal_scheduler_is_configured() != 0u, 'K');",
        "FIBER_REQUIRE(fiber_current() == 0, 'k');",
        "fiber_port_runtime_prepare_start();",
        "FiberContext *const first = fiber_port_runtime_select_first();",
        "fiber_internal_runtime_publish_current_context(first);",
        "fiber_port_runtime_start_first(first);"
    )
    $lastIndex = -1
    foreach ($step in $startSteps) {
        $stepIndex = $startBody.IndexOf($step,
            [System.StringComparison]::Ordinal)
        if ($stepIndex -le $lastIndex) {
            throw "fiber_start must preserve frozen lifecycle and panic order: $step"
        }
        $lastIndex = $stepIndex
    }

    $setBody = Get-CFunctionBody -Source $sources[$corePath] `
        -Signature "void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next, void *user)" `
        -Path $corePath
    $setEnvironment = $setBody.IndexOf(
        "fiber_port_require_scheduler_configuration_environment();",
        [System.StringComparison]::Ordinal)
    $setStore = $setBody.IndexOf(
        "fiber_internal_scheduler_store_pick_next(pick_next, user);",
        [System.StringComparison]::Ordinal)
    if (($setEnvironment -lt 0) -or ($setStore -le $setEnvironment)) {
        throw "Scheduler hook installation must validate the port environment before common-owned storage"
    }

    $requiredRuntimeCalls = @(
        "fiber_internal_runtime_select_scheduler_candidate(",
        "fiber_internal_runtime_publish_current_context(",
        "fiber_internal_runtime_require_current_context("
    )
    foreach ($requiredCall in $requiredRuntimeCalls) {
        if ($sources[$runtimePath].IndexOf($requiredCall,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "fiber_runtime_state.c must retain common scheduler ownership: missing $requiredCall"
        }
    }

    $candidateBody = Get-CFunctionBody -Source $sources[$runtimePath] `
        -Signature "FiberContext *fiber_internal_runtime_select_scheduler_candidate(" `
        -Path $runtimePath
    $candidateSteps = @(
        "fiber_internal_runtime_scheduler_first_selection_started = 1u;",
        "FiberContext *const next = pick_next(current, user);",
        "FIBER_REQUIRE(next != 0, 'N');",
        "return next;"
    )
    $lastCandidateIndex = -1
    foreach ($step in $candidateSteps) {
        $stepIndex = $candidateBody.IndexOf($step,
            [System.StringComparison]::Ordinal)
        if ($stepIndex -le $lastCandidateIndex) {
            throw "Reverse scheduler selector must preserve one-way lifecycle and NULL-result order: $step"
        }
        $lastCandidateIndex = $stepIndex
    }
    if ([regex]::IsMatch($candidateBody,
            'fiber_internal_runtime_scheduler_first_selection_started\s*=\s*0')) {
        throw "First-selection lifecycle marker must never reopen scheduler replacement"
    }

    $publishBody = Get-CFunctionBody -Source $sources[$runtimePath] `
        -Signature "void fiber_internal_runtime_publish_current_context(FiberContext *next)" `
        -Path $runtimePath
    $publishNull = $publishBody.IndexOf("FIBER_REQUIRE(next != 0, 'N');",
        [System.StringComparison]::Ordinal)
    $publishStore = $publishBody.IndexOf(
        "fiber_internal_runtime_current_context_slot = next;",
        [System.StringComparison]::Ordinal)
    if (($publishNull -lt 0) -or ($publishStore -le $publishNull)) {
        throw "Reverse publication must reject NULL before the only current-slot store"
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
        "fiber_port_scheduler_pick_first_from_start",
        "fiber_port_scheduler_pick_next_from_pendsv",
        "fiber_port_context_validate_restore",
        "fiber_internal_runtime_select_scheduler_candidate",
        "fiber_internal_runtime_publish_current_context",
        "fiber_internal_runtime_require_current_context"
    )
    foreach ($relativePath in $portSources) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw

        if ($source.IndexOf("fiber_runtime_port_abi.h",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "Selected port must include the frozen reverse ABI: $path"
        }
        if ($source.IndexOf("fiber_runtime_state.h",
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "Selected port must not include common-private runtime state: $path"
        }

        foreach ($forbiddenReverseName in @(
                "fiber_internal_port_current_context",
                "fiber_internal_scheduler_begin_first_selection",
                "fiber_internal_scheduler_end_first_selection",
                "fiber_internal_scheduler_invoke_pick_next",
                "fiber_internal_scheduler_commit_current_context",
                "fiber_internal_require_schedule_current")) {
            if ($source.IndexOf($forbiddenReverseName,
                    [System.StringComparison]::Ordinal) -ge 0) {
                throw "Selected port still uses transitional reverse ABI: $forbiddenReverseName in $path"
            }
        }

        $slotOccurrences = [regex]::Matches($source,
            '\bfiber_internal_runtime_current_context_slot\b')
        $slotLoads = [regex]::Matches($source,
            '"\s*ldr\s+r[01],\s*=fiber_internal_runtime_current_context_slot\s*\\n"')
        if (($slotOccurrences.Count -eq 0) -or
                ($slotOccurrences.Count -ne $slotLoads.Count)) {
            throw "Current-context slot may appear in selected-port C only as an assembly address/load sequence: $path"
        }
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
            "FIBER_RUNTIME_PORT_ABI_RETAIN_V1();",
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
        $scheduleSteps = @(
            "FIBER_REQUIRE(__get_IPSR() == 0u, 'i');",
            "fiber_internal_runtime_require_current_context();",
            "FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');"
        )
        $lastScheduleIndex = -1
        foreach ($step in $scheduleSteps) {
            $stepIndex = $scheduleBody.IndexOf($step,
                [System.StringComparison]::Ordinal)
            if ($stepIndex -le $lastScheduleIndex) {
                throw "Schedule adapter must preserve i/G/p validation order: $step in $path"
            }
            $lastScheduleIndex = $stepIndex
        }
        foreach ($optionalMask in @(
                "fiber_port_basepri_read() == 0u",
                "__get_FAULTMASK() == 0u")) {
            $maskIndex = $scheduleBody.IndexOf($optionalMask,
                [System.StringComparison]::Ordinal)
            if (($maskIndex -ge 0) -and ($maskIndex -le $lastScheduleIndex)) {
                throw "Optional schedule mask validation must follow i/G/p: $optionalMask in $path"
            }
            if ($maskIndex -ge 0) {
                $lastScheduleIndex = $maskIndex
            }
        }
        $requestIndexes = @(@(
            $scheduleBody.IndexOf("fiber_portNVIC_INT_CTRL_REG =",
                [System.StringComparison]::Ordinal),
            $scheduleBody.IndexOf("fiber_arm_cm7_r0p1_yield_request();",
                [System.StringComparison]::Ordinal),
            $scheduleBody.IndexOf("SCB->ICSR =",
                [System.StringComparison]::Ordinal)
        ) | Where-Object { $_ -ge 0 })
        if (($requestIndexes.Count -ne 1) -or
                ($requestIndexes[0] -le $lastScheduleIndex)) {
            throw "Schedule adapter must issue exactly one request after all validation: $path"
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
        "fiber_port_init_context_frame",
        "fiber_port_context_validate_restore",
        "fiber_port_context_validate_save_current",
        "fiber_port_context_prepare_first_start",
        "fiber_port_require_start_environment",
        "fiber_port_require_start_interrupt_state",
        "fiber_port_runtime_prepare",
        "fiber_port_scheduler_pick_first_from_start",
        "fiber_port_scheduler_pick_next_from_pendsv",
        "fiber_exception_runtime_check",
        "fiber_pendsv_init_lowest_priority",
        "fiber_port_start_first_context",
        "SVC_Handler",
        "PendSV_Handler"
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
            -Signature "void PendSV_Handler(void)" -Path $path

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
            -Signature "void fiber_port_runtime_schedule(void)" `
            -Path $path
        $bridgeBody = Get-CFunctionBody -Source $source `
            -Signature "FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current)" `
            -Path $path

        if ($scheduleBody.IndexOf("fiber_internal_runtime_require_current_context();",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "Thread schedule path must retain current-context ownership check: $path"
        }
        if ($scheduleBody.IndexOf("fiber_port_context_validate_save_current(",
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "Thread schedule path must not duplicate PendSV save preflight: $path"
        }

        $hook = $bridgeBody.IndexOf("fiber_internal_runtime_select_scheduler_candidate(current);",
            [System.StringComparison]::Ordinal)
        $restoreCurrent = $bridgeBody.IndexOf("fiber_port_context_validate_restore(current);",
            [System.StringComparison]::Ordinal)
        $restoreNext = $bridgeBody.IndexOf("fiber_port_context_validate_restore(next);",
            [System.StringComparison]::Ordinal)
        $commit = $bridgeBody.IndexOf("fiber_internal_runtime_publish_current_context(next);",
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

function Get-DisassemblyFunctionBody {
    param(
        [string]$Disassembly,
        [string]$Symbol,
        [string]$Path
    )

    $pattern = '(?ms)^[0-9a-fA-F]+\s+<' + [regex]::Escape($Symbol) +
            '>:\r?\n(?<body>.*?)(?=^[0-9a-fA-F]+\s+<[^>]+>:\r?\n|\z)'
    $match = [regex]::Match($Disassembly, $pattern)
    if (-not $match.Success) {
        throw "Generated-code audit cannot find ${Symbol} in $Path"
    }

    return $match.Groups['body'].Value
}

function Assert-SensitiveFunctionClean {
    param(
        [string]$Disassembly,
        [string]$Symbol,
        [string]$Path
    )

    $body = Get-DisassemblyFunctionBody -Disassembly $Disassembly `
        -Symbol $Symbol -Path $Path
    $forbidden = @(
        '__cyg_profile_func_',
        '__stack_chk_',
        '__gcov',
        '__ubsan_',
        '__asan_',
        '__tsan_',
        '__sanitizer_cov',
        '__gnu_mcount_nc',
        '\bmcount\b'
    )
    foreach ($pattern in $forbidden) {
        if ($body -match $pattern) {
            throw "Sensitive function ${Symbol} acquired forbidden generated code (${pattern}) in $Path"
        }
    }
}

function Test-SensitiveAttributeContract {
    param([string]$RepositoryRoot)

    $attributesPath = Join-Path $RepositoryRoot "fiber\fiber_api_attributes.h"
    $attributes = Get-Content -LiteralPath $attributesPath -Raw
    foreach ($token in @(
            "FIBER_API_NOIPA",
            "FIBER_API_NOCLONE",
            "FIBER_API_NOICF",
            "FIBER_API_NOINSTR",
            "FIBER_API_NOSSP",
            "FIBER_API_NOSAN",
            "FIBER_API_NOPROF",
            "FIBER_API_NOCOVERAGE")) {
        if ($attributes.IndexOf($token, [System.StringComparison]::Ordinal) -lt 0) {
            throw "Public sensitive attribute bundle is missing $token"
        }
    }
    if ($attributes -notmatch '(?s)#\s*define\s+FIBER_SCHEDULER_HOOK_ATTR\s+\\\s*FIBER_API_ATTR_SENSITIVE\s+FIBER_GENERAL_REGS_ONLY') {
        throw "FIBER_SCHEDULER_HOOK_ATTR must combine the canonical sensitive and general-registers-only bundles"
    }

    $compilerPath = Join-Path $RepositoryRoot "fiber\port\fiber_compiler.h"
    $compiler = Get-Content -LiteralPath $compilerPath -Raw
    if ($compiler -notmatch '#include\s+"\.\./fiber_api_attributes\.h"') {
        throw "Selected-port compiler mappings must import the canonical public attribute header"
    }
    if ([regex]::Matches($compiler,
            '(?m)^\s*#\s*define\s+FIBER_SCHEDULER_HOOK_ATTR\b').Count -ne 0) {
        throw "Selected-port compiler header must not redefine FIBER_SCHEDULER_HOOK_ATTR"
    }

    $publicPath = Join-Path $RepositoryRoot "fiber\fiber_api_decl.h"
    $public = Get-Content -LiteralPath $publicPath -Raw
    foreach ($pattern in @(
            'FIBER_API_ATTR_SENSITIVE\s+FIBER_GENERAL_REGS_ONLY\s+FiberContext\s*\*fiber_current\s*\(void\)',
            'FIBER_API_NORETURN\s+FIBER_API_ATTR_SENSITIVE\s+FIBER_GENERAL_REGS_ONLY\s+void\s+fiber_start\s*\(void\)',
            'FIBER_API_ATTR_SENSITIVE\s+FIBER_GENERAL_REGS_ONLY\s+void\s+fiber_schedule\s*\(void\)')) {
        if ($public -notmatch $pattern) {
            throw "Public API is missing a frozen sensitive attribute declaration: $pattern"
        }
    }

    $forwardPath = Join-Path $RepositoryRoot "fiber\port\fiber_port_runtime_abi.h"
    $forward = Get-Content -LiteralPath $forwardPath -Raw
    foreach ($symbol in @(
            "fiber_port_runtime_memory_barrier",
            "fiber_port_panic_wait",
            "fiber_port_runtime_prepare_start",
            "fiber_port_runtime_select_first",
            "fiber_port_runtime_start_first",
            "fiber_port_runtime_schedule")) {
        $prefix = $forward.Substring(0, $forward.IndexOf($symbol,
                [System.StringComparison]::Ordinal))
        $lineStart = $prefix.LastIndexOf("`n")
        $declarationWindowStart = [Math]::Max(0, $lineStart - 180)
        $declarationWindow = $forward.Substring($declarationWindowStart,
                $forward.IndexOf($symbol, [System.StringComparison]::Ordinal) -
                $declarationWindowStart)
        if (($declarationWindow.IndexOf("FIBER_API_ATTR_SENSITIVE",
                [System.StringComparison]::Ordinal) -lt 0) -or
                ($declarationWindow.IndexOf("FIBER_GENERAL_REGS_ONLY",
                [System.StringComparison]::Ordinal) -lt 0)) {
            throw "Forward ABI function lacks the sensitive/general-registers-only contract: $symbol"
        }
    }
}

function Test-StrongHandlerSourceOwnership {
    param([string]$RepositoryRoot)

    $ports = @(
        [pscustomobject]@{ Source = "fiber\port\ARM_CM0\fiber_port.c"; Private = "fiber\port\ARM_CM0\fiber_port_private.h"; Exception = "fiber\port\ARM_CM0\fiber_port_exception.c"; Macro = "fiber\port\ARM_CM0\fiber_portmacro.h" },
        [pscustomobject]@{ Source = "fiber\port\ARM_CM3\fiber_port.c"; Private = "fiber\port\ARM_CM3\fiber_port_private.h"; Exception = "fiber\port\ARM_CM3\fiber_port_exception.c"; Macro = "fiber\port\ARM_CM3\fiber_portmacro.h" },
        [pscustomobject]@{ Source = "fiber\port\ARM_CM4\fiber_port.c"; Private = "fiber\port\ARM_CM4\fiber_port_private.h"; Exception = "fiber\port\ARM_CM4\fiber_port_exception.c"; Macro = "fiber\port\ARM_CM4\fiber_portmacro.h" },
        [pscustomobject]@{ Source = "fiber\port\ARM_CM7\r0p1\fiber_port.c"; Private = "fiber\port\ARM_CM7\r0p1\fiber_port_private.h"; Exception = "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c"; Macro = "fiber\port\ARM_CM7\r0p1\fiber_portmacro.h" },
        [pscustomobject]@{ Source = "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c"; Private = "fiber\port\transitional_v8m\fiber_port_private.h"; Exception = "fiber\port\transitional_v8m\fiber_port_exception.c"; Macro = "fiber\port\transitional_v8m\fiber_portmacro.h" }
    )

    foreach ($port in $ports) {
        $sourcePath = Join-Path $RepositoryRoot $port.Source
        $source = Get-Content -LiteralPath $sourcePath -Raw
        foreach ($handler in @("SVC_Handler", "PendSV_Handler")) {
            if ($source -notmatch ('FIBER_ATTR_NAKED_ASM\s+void\s+' +
                    [regex]::Escape($handler) + '\s*\(void\)')) {
                throw "Selected port must define a naked strong ${handler}: $sourcePath"
            }
        }
        if ($source -match '\bvoid\s+fiber_(?:svc|pendsv)\s*\(void\)') {
            throw "Transitional handler body symbol remains in selected port: $sourcePath"
        }
        if ($source -notmatch '\bvoid\s+fiber_port_runtime_prepare_start\s*\(void\)') {
            throw "Strong handlers must be co-located with an always-linked mandatory ABI function: $sourcePath"
        }

        $privatePath = Join-Path $RepositoryRoot $port.Private
        $private = Get-Content -LiteralPath $privatePath -Raw
        foreach ($handler in @("SVC_Handler", "PendSV_Handler")) {
            if ($private -notmatch ('FIBER_ATTR_NAKED_ASM\s+void\s+' +
                    [regex]::Escape($handler) + '\s*\(void\)\s*;')) {
                throw "Selected-port private header is missing the naked handler declaration: $privatePath"
            }
        }

        $exceptionPath = Join-Path $RepositoryRoot $port.Exception
        $exception = Get-Content -LiteralPath $exceptionPath -Raw
        foreach ($expected in @(
                "fiber_validate_vector_entry(11u, SVC_Handler, 'y');",
                "fiber_validate_vector_entry(14u, PendSV_Handler, 'Y');")) {
            if ($exception.IndexOf($expected,
                    [System.StringComparison]::Ordinal) -lt 0) {
                throw "Runtime vector validation does not require selected strong handlers: $exceptionPath"
            }
        }

        $macroPath = Join-Path $RepositoryRoot $port.Macro
        $macro = Get-Content -LiteralPath $macroPath -Raw
        if ($macro.IndexOf("vector routing macros were removed",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "Selected port must reject obsolete wrapper/direct routing macros: $macroPath"
        }
    }
}

function Test-AdversarialSensitiveGeneratedCode {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Objdump,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $probeDir = Join-Path $BuildRoot "sensitive-generated-code"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    $adversarial = @(
        "-O2",
        "-finstrument-functions",
        "-fstack-protector-all",
        "-fprofile-arcs",
        "-ftest-coverage",
        "-fsanitize=undefined"
    )
    $commonArgs = @(
        "-mcpu=cortex-m7",
        "-mthumb",
        "-std=gnu11",
        "-ffreestanding",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-I$RepositoryRoot",
        "-I$(Join-Path $RepositoryRoot 'fiber')"
    ) + $adversarial
    $commonFunctions = @{
        "fiber\fiber_core.c" = @(
            "fiber_current",
            "fiber_start",
            "fiber_schedule",
            "fiber_internal_task_return"
        )
        "fiber\fiber_runtime_state.c" = @(
            "fiber_internal_runtime_load_current_context",
            "fiber_internal_scheduler_is_configured",
            "fiber_internal_runtime_select_scheduler_candidate",
            "fiber_internal_runtime_publish_current_context",
            "fiber_internal_runtime_require_current_context"
        )
        "fiber\fiber_panic.c" = @("fiber_panic")
    }

    foreach ($source in $commonFunctions.Keys) {
        $object = Join-Path $probeDir (($source -replace '[\\/]', '_') + ".o")
        $args = $commonArgs + @(
            "-c",
            (Join-Path $RepositoryRoot $source),
            "-o",
            $object
        )
        & $Compiler @args
        if ($LASTEXITCODE -ne 0) {
            throw "Adversarial common compile failed: $source"
        }
        $disassembly = (& $Objdump -dr $object) -join "`n"
        foreach ($symbol in $commonFunctions[$source]) {
            Assert-SensitiveFunctionClean -Disassembly $disassembly `
                -Symbol $symbol -Path $source
        }
    }

    $hookSource = @"
#include "fiber/fiber_api_attributes.h"
typedef struct FiberContext FiberContext;
static FIBER_SCHEDULER_HOOK_ATTR
FiberContext *fiber_sensitive_hook_probe(FiberContext *current, void *user)
{
    (void)user;
    return current;
}
"@
    $hookPath = Join-Path $probeDir "scheduler-hook.c"
    $hookObject = Join-Path $probeDir "scheduler-hook.o"
    Set-Content -LiteralPath $hookPath -Value $hookSource -Encoding ASCII
    & $Compiler @($commonArgs + @("-c", $hookPath, "-o", $hookObject))
    if ($LASTEXITCODE -ne 0) {
        throw "Adversarial scheduler-hook compile failed"
    }
    $hookDisassembly = (& $Objdump -dr $hookObject) -join "`n"
    Assert-SensitiveFunctionClean -Disassembly $hookDisassembly `
        -Symbol "fiber_sensitive_hook_probe" -Path $hookPath

    $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 0U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 1U
#define __FPU_USED 1U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 0U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SecureFault_IRQn = -9,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm7.h"
#endif
"@
    Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
        -Value $mainHeader -Encoding ASCII

    # CMSIS force-inline helpers do not inherit a caller's function attribute.
    # Selected-port translation units therefore have a mandatory build rule in
    # addition to source attributes. Place the counter-flags last and prove the
    # resulting objects contain no instrumentation/runtime support references.
    $portCounterFlags = @(
        "-fno-instrument-functions",
        "-fno-stack-protector",
        "-fno-profile-arcs",
        "-fno-test-coverage",
        "-fno-sanitize=all",
        "-mgeneral-regs-only"
    )
    $portSources = @(
        "fiber\port\ARM_CM7\r0p1\fiber_port.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c"
    )
    foreach ($source in $portSources) {
        $object = Join-Path $probeDir (($source -replace '[\\/]', '_') + ".o")
        $args = @(
            "-mcpu=cortex-m7",
            "-mthumb",
            "-mfpu=fpv5-d16",
            "-mfloat-abi=hard",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-Wall",
            "-Wextra",
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV7EM=1",
            "-I$probeDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port\ARM_CM7\r0p1')",
            "-I$RepositoryRoot",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$CmsisPath"
        ) + $adversarial + $portCounterFlags + @(
            "-c",
            (Join-Path $RepositoryRoot $source),
            "-o",
            $object
        )
        & $Compiler @args
        if ($LASTEXITCODE -ne 0) {
            throw "Sensitive selected-port compile contract failed: $source"
        }
        $undefined = (& $script:nm -u $object) -join "`n"
        if ($undefined -match '__cyg_profile_func_|__stack_chk_|__gcov|__ubsan_|__asan_|__tsan_|__sanitizer_cov|__gnu_mcount_nc|\bmcount\b') {
            throw "Selected-port object acquired forbidden compiler runtime dependencies: $source`n$undefined"
        }
    }
}

function Get-StrongTextSymbolAddress {
    param(
        [string[]]$NmOutput,
        [string]$Symbol,
        [string]$Path
    )

    $matches = @($NmOutput | Where-Object {
        $_ -match "^(?<address>[0-9a-fA-F]+)\s+T\s+$([regex]::Escape($Symbol))$"
    })
    if ($matches.Count -ne 1) {
        throw "Expected one strong text symbol ${Symbol} in $Path; found $($matches.Count)"
    }
    [void]($matches[0] -match '^(?<address>[0-9a-fA-F]+)')
    return [Convert]::ToUInt32($Matches['address'], 16)
}

function Test-Cm7StrongHandlerElfOwnership {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$Objcopy,
        [string]$Ar,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $fixtureSource = @"
#include <stdint.h>

extern void fiber_start(void) __attribute__((noreturn));

void Default_Handler(void)
{
    for (;;) {
        __asm volatile ("wfe");
    }
}

void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));

void Reset_Handler(void)
{
    fiber_start();
}

__attribute__((used, section(".isr_vector")))
const uintptr_t fiber_synthetic_vectors[16] = {
    [0] = UINT32_C(0x20010000),
    [1] = (uintptr_t)Reset_Handler,
    [11] = (uintptr_t)SVC_Handler,
    [14] = (uintptr_t)PendSV_Handler
};

int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end)
{
    return (start < end) ? 1 : 0;
}

int fiber_addr_plausible_code(uintptr_t address)
{
    return (address != 0u) ? 1 : 0;
}
"@
    $competingSource = @"
void SVC_Handler(void) { }
void PendSV_Handler(void) { }
"@
    $linkerSource = @"
ENTRY(Reset_Handler)
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 256K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}
SECTIONS
{
    .isr_vector : ALIGN(4) { KEEP(*(.isr_vector)) } > FLASH
    .text : ALIGN(4) { *(.text*) *(.rodata*) } > FLASH
    .ARM.extab : ALIGN(4) { *(.ARM.extab*) } > FLASH
    .ARM.exidx : ALIGN(4)
    {
        __exidx_start = .;
        *(.ARM.exidx*)
        __exidx_end = .;
    } > FLASH
    .data : ALIGN(4) { *(.data*) } > RAM AT > FLASH
    .bss (NOLOAD) : ALIGN(4) { *(.bss*) *(COMMON) } > RAM
}
"@
    $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 0U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 1U
#define __FPU_USED 1U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 0U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SecureFault_IRQn = -9,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm7.h"
#endif
"@
    $commonSources = @(
        "fiber\fiber_core.c",
        "fiber\fiber_runtime_state.c",
        "fiber\fiber_panic.c"
    )
    $portSources = @(
        "fiber\port\ARM_CM7\r0p1\fiber_port.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c"
    )
    $portCounterFlags = @(
        "-fno-instrument-functions",
        "-fno-stack-protector",
        "-fno-profile-arcs",
        "-fno-test-coverage",
        "-fno-sanitize=all",
        "-mgeneral-regs-only"
    )

    foreach ($useLto in @($false, $true)) {
        $mode = if ($useLto) { "lto" } else { "normal" }
        $probeDir = Join-Path $BuildRoot "cm7-handler-elf-$mode"
        New-Item -ItemType Directory -Path $probeDir | Out-Null
        $fixturePath = Join-Path $probeDir "startup.c"
        $competingPath = Join-Path $probeDir "competing.c"
        $linkerPath = Join-Path $probeDir "synthetic.ld"
        Set-Content -LiteralPath $fixturePath -Value $fixtureSource -Encoding ASCII
        Set-Content -LiteralPath $competingPath -Value $competingSource -Encoding ASCII
        Set-Content -LiteralPath $linkerPath -Value $linkerSource -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
            -Value $mainHeader -Encoding ASCII

        $ltoArgs = if ($useLto) { @("-flto") } else { @() }
        $baseArgs = @(
            "-mcpu=cortex-m7",
            "-mthumb",
            "-mfpu=fpv5-d16",
            "-mfloat-abi=hard",
            "-Os",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-fno-builtin",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV7EM=1",
            "-I$probeDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port\ARM_CM7\r0p1')",
            "-I$RepositoryRoot",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$CmsisPath"
        ) + $ltoArgs

        $archiveObjects = @()
        foreach ($source in ($commonSources + $portSources)) {
            $object = Join-Path $probeDir (($source -replace '[\\/]', '_') + ".o")
            $extraFlags = if ($portSources -contains $source) {
                $portCounterFlags
            }
            else {
                @()
            }
            & $Compiler @($baseArgs + $extraFlags + @(
                "-c", (Join-Path $RepositoryRoot $source), "-o", $object))
            if ($LASTEXITCODE -ne 0) {
                throw "CM7 handler archive compile failed ($mode): $source"
            }
            $archiveObjects += $object
        }

        $startupObject = Join-Path $probeDir "startup.o"
        $competingObject = Join-Path $probeDir "competing.o"
        & $Compiler @($baseArgs + @("-c", $fixturePath, "-o", $startupObject))
        if ($LASTEXITCODE -ne 0) {
            throw "CM7 synthetic startup compile failed ($mode)"
        }
        & $Compiler @($baseArgs + @("-c", $competingPath, "-o", $competingObject))
        if ($LASTEXITCODE -ne 0) {
            throw "CM7 competing-handler compile failed ($mode)"
        }

        $archivePath = Join-Path $probeDir "libfiber.a"
        & $Ar rcs $archivePath @archiveObjects
        if ($LASTEXITCODE -ne 0) {
            throw "CM7 handler archive creation failed ($mode)"
        }

        $elfPath = Join-Path $probeDir "fiber-handler-proof.elf"
        $linkArgs = @(
            "-mcpu=cortex-m7",
            "-mthumb",
            "-mfpu=fpv5-d16",
            "-mfloat-abi=hard"
        ) + $ltoArgs + @(
            "-nostdlib",
            "-Wl,--gc-sections",
            "-T", $linkerPath,
            $startupObject,
            $archivePath,
            "-o", $elfPath
        )
        & $Compiler @linkArgs
        if ($LASTEXITCODE -ne 0) {
            throw "CM7 static-archive/vector link failed ($mode)"
        }

        $defined = @(& $Nm -g --defined-only $elfPath)
        $svcAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
            -Symbol "SVC_Handler" -Path $elfPath
        $pendsvAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
            -Symbol "PendSV_Handler" -Path $elfPath
        foreach ($removed in @("fiber_svc", "fiber_pendsv")) {
            if ($defined -match "\s$([regex]::Escape($removed))$") {
                throw "Removed transitional handler symbol survived final ELF ($mode): $removed"
            }
        }

        $vectorPath = Join-Path $probeDir "vectors.bin"
        & $Objcopy -O binary --only-section=.isr_vector $elfPath $vectorPath
        if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $vectorPath))) {
            throw "CM7 vector extraction failed ($mode)"
        }
        $bytes = [IO.File]::ReadAllBytes($vectorPath)
        if ($bytes.Length -lt (16 * 4)) {
            throw "CM7 synthetic vector table is truncated ($mode)"
        }
        $svcVector = [BitConverter]::ToUInt32($bytes, 11 * 4)
        $pendsvVector = [BitConverter]::ToUInt32($bytes, 14 * 4)
        if ((($svcVector -band 1) -eq 0) -or
                (($svcVector -band [uint32]4294967294) -ne
                ($svcAddress -band [uint32]4294967294))) {
            throw "Synthetic vector slot 11 does not resolve to strong SVC_Handler ($mode)"
        }
        if ((($pendsvVector -band 1) -eq 0) -or
                (($pendsvVector -band [uint32]4294967294) -ne
                ($pendsvAddress -band [uint32]4294967294))) {
            throw "Synthetic vector slot 14 does not resolve to strong PendSV_Handler ($mode)"
        }

        $duplicateLog = Join-Path $probeDir "duplicate-handler.log"
        $duplicateResult = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments ($linkArgs[0..($linkArgs.Count - 3)] + @(
                $competingObject, "-o", (Join-Path $probeDir "duplicate.elf"))) `
            -LogPath $duplicateLog
        if (($duplicateResult.ExitCode -eq 0) -or
                ($duplicateResult.Output -notmatch 'multiple definition')) {
            throw "Competing strong handler must fail link with a multiple-definition diagnostic ($mode)`n$($duplicateResult.Output)"
        }
    }
}

$gcc = Find-ArmGcc
$cmsis = Find-CmsisCore
$nm = Join-Path (Split-Path -Parent $gcc) "arm-none-eabi-nm.exe"
if (-not (Test-Path $nm)) {
    throw "arm-none-eabi-nm.exe not found next to compiler: $gcc"
}
$objdump = Join-Path (Split-Path -Parent $gcc) "arm-none-eabi-objdump.exe"
if (-not (Test-Path $objdump)) {
    throw "arm-none-eabi-objdump.exe not found next to compiler: $gcc"
}
$objcopy = Join-Path (Split-Path -Parent $gcc) "arm-none-eabi-objcopy.exe"
if (-not (Test-Path $objcopy)) {
    throw "arm-none-eabi-objcopy.exe not found next to compiler: $gcc"
}
$ar = Join-Path (Split-Path -Parent $gcc) "arm-none-eabi-gcc-ar.exe"
if (-not (Test-Path $ar)) {
    throw "arm-none-eabi-gcc-ar.exe not found next to compiler: $gcc"
}

Test-SchedulePortBoundary -RepositoryRoot $RepoRoot
Test-FinalForwardPortAbi -RepositoryRoot $RepoRoot
Test-FinalReversePortAbi -RepositoryRoot $RepoRoot
Test-SensitiveAttributeContract -RepositoryRoot $RepoRoot
Test-StrongHandlerSourceOwnership -RepositoryRoot $RepoRoot
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

$mandatoryPortRuntimeSources = @(
    "fiber\port\ARM_CM0\fiber_port.c",
    "fiber\port\ARM_CM3\fiber_port.c",
    "fiber\port\ARM_CM4\fiber_port.c",
    "fiber\port\ARM_CM7\r0p1\fiber_port.c",
    "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c"
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
    "fiber_port_scheduler_pick_first_from_start",
    "fiber_port_scheduler_pick_next_from_pendsv",
    "fiber_port_start_first_context",
    "SVC_Handler",
    "PendSV_Handler",
    "fiber_exception_runtime_check",
    "fiber_pendsv_init_lowest_priority"
)

$requiredReverseSymbolTypes = @{
    "fiber_internal_runtime_port_abi_v1_anchor"       = "R"
    "fiber_internal_runtime_current_context_slot"     = "B"
    "fiber_internal_runtime_select_scheduler_candidate" = "T"
    "fiber_internal_runtime_publish_current_context"  = "T"
    "fiber_internal_runtime_require_current_context"  = "T"
    "fiber_internal_task_return"                      = "T"
}

$forbiddenTransitionalReverseSymbols = @(
    "fiber_internal_port_current_context",
    "fiber_internal_port_scheduler_pick_next",
    "fiber_internal_port_scheduler_user",
    "fiber_internal_scheduler_begin_first_selection",
    "fiber_internal_scheduler_end_first_selection",
    "fiber_internal_scheduler_invoke_pick_next",
    "fiber_internal_scheduler_commit_current_context",
    "fiber_internal_require_schedule_current"
)

try {
    Write-Host "Compiler: $gcc"
    Write-Host "CMSIS:    $cmsis"
    Write-Host "Build:    $buildRoot"

    Write-Host "== common-runtime / no-cmsis =="
    Test-CommonRuntimeWithoutCmsis -RepositoryRoot $RepoRoot -Compiler $gcc `
        -BuildRoot $buildRoot
    Write-Host "== sensitive generated-code contract =="
    Test-AdversarialSensitiveGeneratedCode -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Objdump $objdump -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== CM7 strong-handler archive/ELF contract =="
    Test-Cm7StrongHandlerElfOwnership -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -Objcopy $objcopy -Ar $ar `
        -CmsisPath $cmsis -BuildRoot $buildRoot

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

        $buildSelectedDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-D$portMacro=1")
        $buildSelectedIncludeArgs = @("-I$(Join-Path $RepoRoot $portIncludeDir)")

        $selectionModes = @(
            [pscustomobject]@{ Name = "auto";           Defines = @(); ExtraArgs = @(); PortSources = $selectorPortSources },
            [pscustomobject]@{ Name = "explicit";       Defines = @("-DFIBER_PORT_PROFILE=$profile"); ExtraArgs = @(); PortSources = $selectorPortSources },
            [pscustomobject]@{ Name = "build-selected"; Defines = $buildSelectedDefines; ExtraArgs = $buildSelectedIncludeArgs; PortSources = $buildSelectedPortSources }
        )

        if (($cfg.Name -eq "cortex-m33") -or
            ($cfg.Name -eq "cortex-m33f") -or
            ($cfg.Name -eq "cortex-m55") -or
            ($cfg.Name -eq "cortex-m55f") -or
            ($cfg.Name -eq "cortex-m55-mve-fp")) {
            $selectionModes += [pscustomobject]@{
                Name = "explicit-nonsecure-exc-return"
                Defines = @(
                    "-DFIBER_PORT_PROFILE=$profile",
                    "-DFIBER_TRANSITIONAL_V8M_RUN_NONSECURE=1"
                )
                ExtraArgs = @()
                PortSources = $selectorPortSources
            }
            $selectionModes += [pscustomobject]@{
                Name = "explicit-secure-target-ns-bank"
                Defines = @(
                    "-DFIBER_PORT_PROFILE=$profile",
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
            $runtimeAbiAnchorReferenceCount = 0
            $strongPortPanicReferenceCount = 0

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

                if ($mandatoryPortRuntimeSources -contains $source) {
                    $portUndefinedOutput = & $nm -u $objPath
                    if ($LASTEXITCODE -ne 0) {
                        throw "Selected-port undefined-symbol scan failed for $($cfg.Name) / $($mode.Name): $source"
                    }

                    $anchorReferences = @($portUndefinedOutput | Where-Object {
                        $_ -match '\bU\s+fiber_internal_runtime_port_abi_v1_anchor$'
                    })
                    $panicReferences = @($portUndefinedOutput | Where-Object {
                        $_ -match '\bU\s+fiber_panic$'
                    })
                    if (($anchorReferences.Count -gt 1) -or
                            ($panicReferences.Count -gt 1)) {
                        throw "Selected-port runtime object has duplicate ABI/panic relocations: $source"
                    }
                    $runtimeAbiAnchorReferenceCount += $anchorReferences.Count
                    $strongPortPanicReferenceCount += $panicReferences.Count
                }

                $objects += $objPath
            }

            if ($runtimeAbiAnchorReferenceCount -ne 1) {
                throw "Expected one active selected-port v1 anchor relocation for $($cfg.Name) / $($mode.Name); found $runtimeAbiAnchorReferenceCount"
            }
            if ($strongPortPanicReferenceCount -ne 1) {
                throw "Expected one active selected-port strong panic reference for $($cfg.Name) / $($mode.Name); found $strongPortPanicReferenceCount"
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

            foreach ($handler in @("SVC_Handler", "PendSV_Handler")) {
                $strongDefinitions = @($definedSymbols | Where-Object {
                    $_ -match "\sT\s+$([regex]::Escape($handler))$"
                })
                if ($strongDefinitions.Count -ne 1) {
                    throw "Expected exactly one strong selected-port $handler for $($cfg.Name) / $($mode.Name); found $($strongDefinitions.Count)"
                }
            }

            foreach ($symbol in $requiredReverseSymbolTypes.Keys) {
                $expectedType = $requiredReverseSymbolTypes[$symbol]
                $definitions = @($definedSymbols | Where-Object {
                    $_ -match "\s$expectedType\s+$([regex]::Escape($symbol))$"
                })
                if ($definitions.Count -ne 1) {
                    throw "Expected one strong reverse symbol $symbol of type $expectedType for $($cfg.Name) / $($mode.Name); found $($definitions.Count)"
                }
            }

            $panicDefinitions = @($definedSymbols | Where-Object {
                $_ -match '\sW\s+fiber_panic$'
            })
            if ($panicDefinitions.Count -ne 1) {
                throw "Expected exactly one weak common fiber_panic fallback for $($cfg.Name) / $($mode.Name); found $($panicDefinitions.Count)"
            }

            foreach ($symbol in $forbiddenTransitionalReverseSymbols) {
                $definitions = @($definedSymbols | Where-Object {
                    $_ -match "\s[A-Za-z]\s+$([regex]::Escape($symbol))$"
                })
                if ($definitions.Count -ne 0) {
                    throw "Transitional reverse symbol remains defined for $($cfg.Name) / $($mode.Name): $symbol"
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
        "-DFIBER_PORT_ARMV7EM=1"
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
        [pscustomobject]@{ Name = "obsolete-pendsv-direct"; Define = "-DFIBER_PENDSV_VECTOR_DIRECT=1"; Diagnostic = "vector routing macros were removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-svc-direct"; Define = "-DFIBER_SVC_VECTOR_DIRECT=1"; Diagnostic = "vector routing macros were removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-pendsv-wired"; Define = "-DFIBER_PENDSV_WIRED=1"; Diagnostic = "vector routing macros were removed"; Dir = $probe4Dir; Source = $probeSource },
        [pscustomobject]@{ Name = "obsolete-svc-wired"; Define = "-DFIBER_SVC_WIRED=1"; Diagnostic = "vector routing macros were removed"; Dir = $probe4Dir; Source = $probeSource },
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
