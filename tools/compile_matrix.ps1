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
    $slotOwnerSources = @($portSources) + @(
        "fiber\port\ARM_CM23_NTZ\non_secure\fiber_port.c",
        "fiber\port\ARM_CM33_NTZ\non_secure\fiber_port.c",
        "fiber\port\ARM_CM33F_NTZ\non_secure\fiber_port.c",
        "fiber\port\ARM_CM3_MPU\fiber_port.c",
		"fiber\port\ARM_CM4_MPU\fiber_port.c",
		"fiber\port\ARM_CM0_MPU\fiber_port.c",
		"fiber\port\ARM_CM33_MPU\non_secure\fiber_port.c"
    )
    $expectedSlotOwners = @($slotOwnerSources | ForEach-Object {
        (Join-Path $RepositoryRoot $_).ToLowerInvariant()
    } | Sort-Object)
    $actualSlotOwners = @(
        Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot "fiber\port") `
            -Recurse -File | Where-Object {
                $_.Extension -in @(".c", ".h", ".s", ".S")
            } | Where-Object {
                (Get-Content -LiteralPath $_.FullName -Raw).IndexOf(
                    "fiber_internal_runtime_current_context_slot",
                    [System.StringComparison]::Ordinal) -ge 0
            } | ForEach-Object {
                $_.FullName.ToLowerInvariant()
            } | Sort-Object
    )
    if (($expectedSlotOwners.Count -ne $actualSlotOwners.Count) -or
            (Compare-Object -ReferenceObject $expectedSlotOwners `
                -DifferenceObject $actualSlotOwners)) {
        throw "The assembly-only current slot must appear only in selected-port runtime sources.`nExpected: $($expectedSlotOwners -join ', ')`nActual: $($actualSlotOwners -join ', ')"
    }
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
            "fiber_internal_runtime_require_current_context();"
        )
        if ($relativePath -notmatch 'transitional_v8m') {
            $scheduleSteps +=
                "FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');"
        }
        $scheduleSteps += "FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');"
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

        if ($relativePath -notmatch 'transitional_v8m') {
            $exceptionPath = Join-Path (Split-Path -Parent $path) `
                "fiber_port_exception.c"
            $exceptionSource = Get-Content -LiteralPath $exceptionPath -Raw
            if ($exceptionSource -match '\(rd\s*&\s*lowest\)\s*==\s*lowest') {
                throw "Selected port still accepts a masked-only PendSV priority readback: $exceptionPath"
            }
            $exactPriorityChecks = [regex]::Matches($exceptionSource,
                "FIBER_REQUIRE\(rd == lowest, 'P'\);")
            if ($exactPriorityChecks.Count -ne 2) {
                throw "Selected port must verify exact PendSV priority during setup and runtime: $exceptionPath"
            }
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

function Test-SelectedPortExceptionFrameGeometry {
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
        $restoreBody = Get-CFunctionBody -Source $source `
            -Signature "void fiber_port_context_validate_restore(FiberContext *ctx)" `
            -Path $path

        $coreOffset = $restoreBody.IndexOf(
            "uintptr_t core_frame_offset = (uintptr_t)FIBER_PORT_SOFTWARE_FRAME_BYTES;",
            [System.StringComparison]::Ordinal)
        $pcOffset = $restoreBody.IndexOf(
            "stacked_pc_offset = core_frame_offset +",
            [System.StringComparison]::Ordinal)
        $xpsrOffset = $restoreBody.IndexOf(
            "stacked_xpsr_offset = core_frame_offset +",
            [System.StringComparison]::Ordinal)
        $requiredBytes = $restoreBody.IndexOf(
            "required_bytes = core_frame_offset +",
            [System.StringComparison]::Ordinal)
        $fpExtent = $restoreBody.IndexOf(
            "required_bytes += (uintptr_t)FIBER_EXC_FP_EXT_BYTES;",
            [System.StringComparison]::Ordinal)
        $extentCheck = $restoreBody.IndexOf(
            "FIBER_REQUIRE(available_bytes >= required_bytes, 'X');",
            [System.StringComparison]::Ordinal)

        if (($coreOffset -lt 0) -or ($pcOffset -le $coreOffset) -or
                ($xpsrOffset -le $pcOffset) -or
                ($requiredBytes -le $xpsrOffset) -or
                ($fpExtent -le $requiredBytes) -or
                ($extentCheck -le $fpExtent) -or
                $restoreBody.Contains("hardware_frame_offset") -or
                [regex]::IsMatch($restoreBody,
                    'core_frame_offset\s*\+=\s*\(uintptr_t\)FIBER_EXC_FP_EXT_BYTES')) {
            throw "Selected port must keep the hardware core frame at PSP and apply the FP extension only to total saved-frame extent: $path"
        }
    }

    $saveSources = @(
        "fiber\port\ARM_CM0\fiber_port.c",
        "fiber\port\ARM_CM3\fiber_port.c",
        "fiber\port\ARM_CM4\fiber_port.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port.c",
        "fiber\port\ARM_CM23_NTZ\non_secure\fiber_port.c"
    )

    foreach ($relativePath in $saveSources) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw
        $pendsvBody = Get-CFunctionBody -Source $source `
            -Signature "void PendSV_Handler(void)" -Path $path
        $xpsrLoads = [regex]::Matches($pendsvBody,
            'ldr\s+r3,\s*\[r0,\s*%c\[xpsr\]\]')

        if (($source.IndexOf("fiber_portOFFSET_STACKED_XPSR = 7u * 4u",
                    [System.StringComparison]::Ordinal) -lt 0) -or
                ($xpsrLoads.Count -ne 1) -or
                ($pendsvBody.IndexOf("[alignpad]", [System.StringComparison]::Ordinal) -lt 0) -or
                ($pendsvBody.IndexOf("FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES",
                    [System.StringComparison]::Ordinal) -lt 0) -or
                [regex]::IsMatch($source, 'xpsr(?:basic|ext)') -or
                $source.Contains("fiber_portOFFSET_EXTENDED_STACKED_XPSR")) {
            throw "PendSV must include xPSR.STACKALIGN in the hardware-frame upper bound: $path"
        }
    }

    $restorePcSources = @(
        "fiber\port\ARM_CM0\fiber_port_boot.c",
        "fiber\port\ARM_CM3\fiber_port_boot.c",
        "fiber\port\ARM_CM4\fiber_port_boot.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c",
        "fiber\port\ARM_CM23_NTZ\non_secure\fiber_port_boot.c",
        "fiber\port\ARM_CM3_MPU\fiber_port_boot.c"
    )
    foreach ($relativePath in $restorePcSources) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw
        if ($source.IndexOf("FIBER_REQUIRE(stacked_pc >= 2u, 'x');",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "Restore validation must reject null and underflowing stacked PC values: $path"
        }
    }

    $mpuRuntimePath = Join-Path $RepositoryRoot `
        "fiber\port\ARM_CM3_MPU\fiber_port.c"
    $mpuRuntimeSource = Get-Content -LiteralPath $mpuRuntimePath -Raw
    $mpuSvcFrameBody = Get-CFunctionBody -Source $mpuRuntimeSource `
        -Signature "void fiber_port_validate_svc_frame_shape(const uint32_t *hardware_frame)" `
        -Path $mpuRuntimePath
    if ($mpuSvcFrameBody.IndexOf("FIBER_REQUIRE(stacked_pc >= 2u, 'x');",
            [System.StringComparison]::Ordinal) -lt 0) {
        throw "ARM_CM3_MPU SVC frame validation must reject null stacked PC"
    }
}

function Test-SelectedPortHandlerHardening {
    param([string]$RepositoryRoot)

    $portSources = @(
        "fiber\port\ARM_CM0\fiber_port.c",
        "fiber\port\ARM_CM3\fiber_port.c",
        "fiber\port\ARM_CM4\fiber_port.c",
        "fiber\port\ARM_CM7\r0p1\fiber_port.c"
    )

    foreach ($relativePath in $portSources) {
        $path = Join-Path $RepositoryRoot $relativePath
        $source = Get-Content -LiteralPath $path -Raw
        $svcBody = Get-CFunctionBody -Source $source `
            -Signature "void SVC_Handler(void)" -Path $path
        $pendsvBody = Get-CFunctionBody -Source $source `
            -Signature "void PendSV_Handler(void)" -Path $path

        $svcIpsrMatch = [regex]::Match($svcBody, 'mrs\s+r[0-3],\s*ipsr')
        $svcNumberMatch = [regex]::Match($svcBody, 'cmp\s+r[0-3],\s*#11')
        $svcIpsr = $svcIpsrMatch.Index
        $svcNumber = $svcNumberMatch.Index
        $svcExcReturn = $svcBody.IndexOf("0xFFFFFFF9",
            [System.StringComparison]::Ordinal)
        $svcMsp = [regex]::Match($svcBody, 'mrs\s+r0,\s*msp').Index
        $svcXpsr = $svcBody.IndexOf("[r0, #28]",
            [System.StringComparison]::Ordinal)
        $svcPc = $svcBody.IndexOf("[r0, #24]",
            [System.StringComparison]::Ordinal)
        $svcPcFloorMatch = [regex]::Match($svcBody, 'cmp\s+r3,\s*#2')
        $svcPcFloor = $svcPcFloorMatch.Index
        $svcOpcode = $svcBody.IndexOf("#0xDF",
            [System.StringComparison]::Ordinal)
        if ((-not $svcIpsrMatch.Success) -or (-not $svcNumberMatch.Success) -or
                (-not $svcPcFloorMatch.Success) -or
                ($svcNumber -le $svcIpsr) -or
                ($svcExcReturn -le $svcNumber) -or ($svcMsp -le $svcExcReturn) -or
                ($svcXpsr -le $svcMsp) -or ($svcPc -le $svcXpsr) -or
                ($svcPcFloor -le $svcPc) -or ($svcOpcode -le $svcPcFloor) -or
                ($svcBody.IndexOf("stacked Thread state must be Thumb",
                    [System.StringComparison]::Ordinal) -lt 0) -or
                ($svcBody.IndexOf("stacked IPSR must describe Thread mode",
                    [System.StringComparison]::Ordinal) -lt 0) -or
                ($svcBody.IndexOf("cannot require padding",
                    [System.StringComparison]::Ordinal) -lt 0)) {
            throw "SVC first-start preflight is weaker than the frozen handler contract: $path"
        }

        $pendsvIpsrMatch = [regex]::Match($pendsvBody,
            'mrs\s+r[0-3],\s*ipsr')
        $pendsvNumberMatch = [regex]::Match($pendsvBody,
            'cmp\s+r[0-3],\s*#14')
        $pendsvPspMatch = [regex]::Match($pendsvBody,
            'mrs\s+r0,\s*psp')
        $pendsvIpsr = $pendsvIpsrMatch.Index
        $pendsvNumber = $pendsvNumberMatch.Index
        $pendsvExcReturn = $pendsvBody.IndexOf("0xFFFFFFFD",
            [System.StringComparison]::Ordinal)
        $pendsvPsp = $pendsvPspMatch.Index
        $pendsvAlignment = $pendsvBody.IndexOf("8-byte hardware-frame base",
            [System.StringComparison]::Ordinal)
        $pendsvValidator = $pendsvBody.IndexOf(
            "bl    fiber_port_context_validate_save_current",
            [System.StringComparison]::Ordinal)
        $pendsvXpsr = $pendsvBody.IndexOf("[r0, %c[xpsr]]",
            [System.StringComparison]::Ordinal)
        $pendsvAlignPad = $pendsvBody.IndexOf("%c[alignpad]",
            [System.StringComparison]::Ordinal)
        if ((-not $pendsvIpsrMatch.Success) -or
                (-not $pendsvNumberMatch.Success) -or
                (-not $pendsvPspMatch.Success) -or
                ($pendsvNumber -le $pendsvIpsr) -or
                ($pendsvExcReturn -le $pendsvNumber) -or
                ($pendsvPsp -le $pendsvExcReturn) -or
                ($pendsvAlignment -le $pendsvPsp) -or
                ($pendsvValidator -le $pendsvAlignment) -or
                ($pendsvXpsr -le $pendsvValidator) -or
                ($pendsvAlignPad -le $pendsvXpsr)) {
            throw "PendSV exception provenance or STACKALIGN preflight regressed: $path"
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
        "fiber\port\ARM_CM23_NTZ\non_secure\fiber_port.c",
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
        "fiber\port\ARM_CM23_NTZ\non_secure\fiber_port.c",
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
        [string]$Objdump,
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

    $runtimeStateObject = Join-Path $probeDir "fiber_runtime_state.c.o"
    $runtimeStateSections = (& $Objdump -h $runtimeStateObject) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed for common runtime current-slot storage proof"
    }
    if ($runtimeStateSections -notmatch
            '\.bss\.fiber_runtime_current_context_slot\s+00000004\s+') {
        throw "Common current slot must remain one 32-bit object in its isolated .bss subsection"
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

function Get-NmUndefinedSymbolNames {
    param(
        [string[]]$NmOutput,
        [string]$Path
    )

    $symbols = @()
    foreach ($line in $NmOutput) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line -notmatch '^\s*U\s+(?<symbol>\S+)\s*$') {
            throw "Unexpected nm -u output for ${Path}: $line"
        }
        $symbols += $Matches['symbol']
    }

    return @($symbols | Sort-Object -Unique)
}

function Assert-ExactSymbolSet {
    param(
        [string[]]$Expected,
        [string[]]$Actual,
        [string]$Description
    )

    $expectedSet = @($Expected | Sort-Object -Unique)
    $actualSet = @($Actual | Sort-Object -Unique)
    $difference = @(Compare-Object -ReferenceObject $expectedSet `
        -DifferenceObject $actualSet)
    if (($expectedSet.Count -ne $actualSet.Count) -or
            ($difference.Count -ne 0)) {
        throw "$Description does not match the frozen allowlist.`nExpected: $($expectedSet -join ', ')`nActual:   $($actualSet -join ', ')"
    }
}

function Test-ReverseAbiSlotCIsolation {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$BuildRoot
    )

    $probeDir = Join-Path $BuildRoot "reverse-slot-c-isolation"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    $cases = @(
        [pscustomobject]@{
            Name = "read"
            Body = "return fiber_internal_runtime_current_context_slot;"
            ReturnType = "FiberContext *"
            Argument = "void"
        },
        [pscustomobject]@{
            Name = "write"
            Body = "fiber_internal_runtime_current_context_slot = ctx;"
            ReturnType = "void"
            Argument = "FiberContext *ctx"
        },
        [pscustomobject]@{
            Name = "address"
            Body = "return &fiber_internal_runtime_current_context_slot;"
            ReturnType = "void *"
            Argument = "void"
        }
    )

    foreach ($case in $cases) {
        $source = @"
#include "fiber/fiber_runtime_port_abi.h"

$($case.ReturnType) fiber_reverse_slot_$($case.Name)($($case.Argument))
{
    $($case.Body)
}
"@
        $sourcePath = Join-Path $probeDir ($case.Name + ".c")
        $objectPath = Join-Path $probeDir ($case.Name + ".o")
        $logPath = Join-Path $probeDir ($case.Name + ".log")
        Set-Content -LiteralPath $sourcePath -Value $source -Encoding ASCII

        $args = @(
            "-mcpu=cortex-m3",
            "-mthumb",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-Wall",
            "-Wextra",
            "-Werror=implicit-function-declaration",
            "-I$RepositoryRoot",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-c",
            $sourcePath,
            "-o",
            $objectPath
        )
        $result = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $args -LogPath $logPath
        if (($result.ExitCode -eq 0) -or
                ($result.Output -notmatch 'fiber_internal_runtime_current_context_slot') -or
                ($result.Output -notmatch 'undeclared')) {
            throw "Reverse current slot must be unavailable as a C lvalue ($($case.Name)).`n$($result.Output)"
        }
    }
}

function Test-GeneratedCurrentSlotLoadOnly {
    param([string]$AssemblyPath)

    if (-not (Test-Path $AssemblyPath)) {
        throw "Selected-port generated assembly is missing: $AssemblyPath"
    }

    $assembly = Get-Content -LiteralPath $AssemblyPath -Raw
    $symbol = "fiber_internal_runtime_current_context_slot"
    $occurrences = [regex]::Matches($assembly, "\b$symbol\b")
    $pairPattern = '(?im)^[ \t]*ldr[ \t]+(?<register>r(?:1[0-2]|[0-9])),[ \t]*=' +
        [regex]::Escape($symbol) +
        '[ \t]*(?:@.*)?\r?\n[ \t]*ldr[ \t]+\k<register>,[ \t]*\[\k<register>\][ \t]*(?:@.*)?\r?$'
    $loadPairs = [regex]::Matches($assembly, $pairPattern)
    if (($occurrences.Count -eq 0) -or
            ($occurrences.Count -ne $loadPairs.Count)) {
        throw "Generated selected-port assembly may only load the current slot through an immediate address/load pair: $AssemblyPath"
    }
}

function Test-ReverseAbiVersionMismatch {
    param(
        [string]$Compiler,
        [string]$Ar,
        [string]$BuildRoot
    )

    $portTemplate = @"
extern const unsigned char fiber_internal_runtime_port_abi_vVERSION_anchor;

__attribute__((noinline, used))
void fiber_port_runtime_prepare_start(void)
{
    __asm volatile ("" : : "r"(&fiber_internal_runtime_port_abi_vVERSION_anchor) : "memory");
}
"@
    $commonTemplate = @"
__attribute__((used))
const unsigned char fiber_internal_runtime_port_abi_vVERSION_anchor = VERSION;
"@
    $startupSource = @"
extern void fiber_port_runtime_prepare_start(void);

void Reset_Handler(void)
{
    fiber_port_runtime_prepare_start();
    for (;;) {
        __asm volatile ("wfe");
    }
}
"@
    $linkerSource = @"
ENTRY(Reset_Handler)
SECTIONS
{
    . = 0x08000000;
    .text : { *(.text*) *(.rodata*) }
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
}
"@

    foreach ($useLto in @($false, $true)) {
        $mode = if ($useLto) { "lto" } else { "normal" }
        $probeDir = Join-Path $BuildRoot "reverse-abi-version-$mode"
        New-Item -ItemType Directory -Path $probeDir | Out-Null
        $startupPath = Join-Path $probeDir "startup.c"
        $linkerPath = Join-Path $probeDir "reverse-abi.ld"
        Set-Content -LiteralPath $startupPath -Value $startupSource -Encoding ASCII
        Set-Content -LiteralPath $linkerPath -Value $linkerSource -Encoding ASCII

        $ltoArgs = if ($useLto) { @("-flto") } else { @() }
        $baseArgs = @(
            "-mcpu=cortex-m3",
            "-mthumb",
            "-O2",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables"
        ) + $ltoArgs

        $startupObject = Join-Path $probeDir "startup.o"
        & $Compiler @($baseArgs + @("-c", $startupPath, "-o", $startupObject))
        if ($LASTEXITCODE -ne 0) {
            throw "Reverse ABI startup fixture compile failed ($mode)"
        }

        $commonObjects = @{}
        $portArchives = @{}
        foreach ($version in @(1, 2)) {
            $portPath = Join-Path $probeDir "port-v$version.c"
            $commonPath = Join-Path $probeDir "common-v$version.c"
            $portObject = Join-Path $probeDir "port-v$version.o"
            $commonObject = Join-Path $probeDir "common-v$version.o"
            $archivePath = Join-Path $probeDir "libport-v$version.a"
            Set-Content -LiteralPath $portPath `
                -Value ($portTemplate.Replace("VERSION", [string]$version)) `
                -Encoding ASCII
            Set-Content -LiteralPath $commonPath `
                -Value ($commonTemplate.Replace("VERSION", [string]$version)) `
                -Encoding ASCII

            foreach ($compile in @(
                    [pscustomobject]@{ Source = $portPath; Object = $portObject },
                    [pscustomobject]@{ Source = $commonPath; Object = $commonObject })) {
                & $Compiler @($baseArgs + @(
                    "-c", $compile.Source, "-o", $compile.Object))
                if ($LASTEXITCODE -ne 0) {
                    throw "Reverse ABI v$version fixture compile failed ($mode): $($compile.Source)"
                }
            }

            & $Ar rcs $archivePath $portObject
            if ($LASTEXITCODE -ne 0) {
                throw "Reverse ABI v$version archive creation failed ($mode)"
            }
            $commonObjects[$version] = $commonObject
            $portArchives[$version] = $archivePath
        }

        $linkBase = @(
            "-mcpu=cortex-m3",
            "-mthumb"
        ) + $ltoArgs + @(
            "-nostdlib",
            "-Wl,--gc-sections",
            "-T", $linkerPath,
            $startupObject
        )

        foreach ($version in @(1, 2)) {
            $positivePath = Join-Path $probeDir "positive-v$version.elf"
            & $Compiler @($linkBase + @(
                $commonObjects[$version], $portArchives[$version],
                "-o", $positivePath))
            if ($LASTEXITCODE -ne 0) {
                throw "Matching reverse ABI v$version cohort failed link ($mode)"
            }
        }

        foreach ($pair in @(
                [pscustomobject]@{ Port = 1; Common = 2 },
                [pscustomobject]@{ Port = 2; Common = 1 })) {
            $missingAnchor = "fiber_internal_runtime_port_abi_v$($pair.Port)_anchor"
            $logPath = Join-Path $probeDir `
                "mismatch-port-v$($pair.Port)-common-v$($pair.Common).log"
            $result = Invoke-CompilerProbe -Compiler $Compiler `
                -Arguments ($linkBase + @(
                    $commonObjects[$pair.Common], $portArchives[$pair.Port],
                    "-o", (Join-Path $probeDir "mismatch.elf"))) `
                -LogPath $logPath
            if (($result.ExitCode -eq 0) -or
                    ($result.Output -notmatch [regex]::Escape($missingAnchor))) {
                throw "Mismatched reverse ABI cohort must fail on $missingAnchor ($mode).`n$($result.Output)"
            }
        }
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
            "FIBER_API_NOCOVERAGE",
            "FIBER_API_THREAD_FUNCTION")) {
        if ($attributes.IndexOf($token, [System.StringComparison]::Ordinal) -lt 0) {
            throw "Public sensitive attribute bundle is missing $token"
        }
    }
    if ($attributes -notmatch '(?s)#\s*define\s+FIBER_SCHEDULER_HOOK_ATTR\s+\\\s*FIBER_API_ATTR_SENSITIVE\s+FIBER_GENERAL_REGS_ONLY') {
        throw "FIBER_SCHEDULER_HOOK_ATTR must combine the canonical sensitive and general-registers-only bundles"
    }
    if ($attributes -notmatch
            'section\("\.text\.fiber_runtime_thread_functions"\)') {
        throw "FIBER_API_THREAD_FUNCTION must retain its LTO-stable .text placement"
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
            'FIBER_API_ATTR_SENSITIVE\s+FIBER_GENERAL_REGS_ONLY\s+FIBER_API_THREAD_FUNCTION\s+FiberContext\s*\*fiber_current\s*\(void\)',
            'FIBER_API_NORETURN\s+FIBER_API_ATTR_SENSITIVE\s+FIBER_GENERAL_REGS_ONLY\s+void\s+fiber_start\s*\(void\)',
            'FIBER_API_ATTR_SENSITIVE\s+FIBER_GENERAL_REGS_ONLY\s+FIBER_API_THREAD_FUNCTION\s+void\s+fiber_schedule\s*\(void\)')) {
        if ($public -notmatch $pattern) {
            throw "Public API is missing a frozen sensitive attribute declaration: $pattern"
        }
    }

    $forwardPath = Join-Path $RepositoryRoot "fiber\port\fiber_port_runtime_abi.h"
    $forward = Get-Content -LiteralPath $forwardPath -Raw
    foreach ($symbol in @(
            "fiber_port_context_init",
            "fiber_port_runtime_memory_barrier",
            "fiber_port_panic_wait",
            "fiber_port_require_scheduler_configuration_environment",
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
#include <stddef.h>
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

function Test-SelectedPortContextCohortMismatch {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Ar,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $startupSource = @"
#include <stddef.h>
#include <stdint.h>

extern void fiber_portable_application_fixture(void)
    __attribute__((noreturn));

void Reset_Handler(void)
{
    fiber_portable_application_fixture();
}

int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end)
{
    return (start < end) ? 1 : 0;
}

int fiber_addr_plausible_code(uintptr_t address)
{
    return (address != 0u) ? 1 : 0;
}

void *memcpy(void *destination, const void *source, size_t count)
{
    unsigned char *dst = (unsigned char *)destination;
    const unsigned char *src = (const unsigned char *)source;
    while (count-- != 0u) {
        *dst++ = *src++;
    }
    return destination;
}

void *memset(void *destination, int value, size_t count)
{
    unsigned char *dst = (unsigned char *)destination;
    while (count-- != 0u) {
        *dst++ = (unsigned char)value;
    }
    return destination;
}
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
    .text : ALIGN(4)
    {
        *(.text*)
        KEEP(*(.fiber_port_context_cohort_expectation))
        *(.rodata*)
    } > FLASH
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
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
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
#include "core_cm33.h"
#endif
"@
    $commonSources = @(
        "fiber\fiber_core.c",
        "fiber\fiber_runtime_state.c",
        "fiber\fiber_panic.c"
    )
    $portSources = @{
        Runtime = "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c"
        Boot = "fiber\port\transitional_v8m\fiber_port_boot.c"
        Exception = "fiber\port\transitional_v8m\fiber_port_exception.c"
    }
    $portableSource = "tools\fixtures\portable_application.c"
    $expectationSource =
        "fiber\port\fiber_port_context_cohort_expectation.c"
    $portCounterFlags = @(
        "-fno-instrument-functions",
        "-fno-stack-protector",
        "-fno-profile-arcs",
        "-fno-test-coverage",
        "-fno-sanitize=all",
        "-mgeneral-regs-only"
    )
    $variants = @(
        [pscustomobject]@{ Name = "secure"; Nonsecure = 0 },
        [pscustomobject]@{ Name = "nonsecure"; Nonsecure = 1 }
    )

    foreach ($useLto in @($false, $true)) {
        $mode = if ($useLto) { "lto" } else { "normal" }
        $probeDir = Join-Path $BuildRoot "context-cohort-$mode"
        New-Item -ItemType Directory -Path $probeDir | Out-Null
        $startupPath = Join-Path $probeDir "startup.c"
        $linkerPath = Join-Path $probeDir "context-cohort.ld"
        Set-Content -LiteralPath $startupPath -Value $startupSource `
            -Encoding ASCII
        Set-Content -LiteralPath $linkerPath -Value $linkerSource `
            -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
            -Value $mainHeader -Encoding ASCII

        $ltoArgs = if ($useLto) { @("-flto") } else { @() }
        $objectNm = if ($useLto) { $GccNm } else { $Nm }
        $baseArgs = @(
            "-mcpu=cortex-m33",
            "-mthumb",
            "-Os",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-fno-builtin",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-I$probeDir",
            "-I$RepositoryRoot",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$CmsisPath"
        ) + $ltoArgs

        $startupObject = Join-Path $probeDir "startup.o"
        & $Compiler @($baseArgs + @(
            "-c", $startupPath, "-o", $startupObject))
        if ($LASTEXITCODE -ne 0) {
            throw "Context-cohort startup fixture compile failed ($mode)"
        }

        $commonObjects = @()
        foreach ($source in $commonSources) {
            $object = Join-Path $probeDir `
                (($source -replace '[\\/]', '_') + ".o")
            & $Compiler @($baseArgs + @(
                "-c", (Join-Path $RepositoryRoot $source),
                "-o", $object))
            if ($LASTEXITCODE -ne 0) {
                throw "Context-cohort common compile failed ($mode): $source"
            }
            $commonObjects += $object
        }

        $compiled = @{}
        foreach ($variant in $variants) {
            $variantDir = Join-Path $probeDir $variant.Name
            New-Item -ItemType Directory -Path $variantDir | Out-Null
            $variantArgs = $baseArgs + @(
                "-DFIBER_PORT_BUILD_SELECTED=1",
                "-DFIBER_PORT_ARMV8M_MAINLINE=1",
                "-DFIBER_TRANSITIONAL_V8M_RUN_NONSECURE=$($variant.Nonsecure)",
                "-DFIBER_ALLOW_UNVALIDATED_ARMV8M_MAINLINE_RUNTIME=1",
                "-DFIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME=1",
                "-I$(Join-Path $RepositoryRoot 'fiber\port\transitional_v8m')"
            )
            $objects = @{}
            foreach ($role in $portSources.Keys) {
                $source = $portSources[$role]
                $object = Join-Path $variantDir `
                    (($source -replace '[\\/]', '_') + ".o")
                & $Compiler @($variantArgs + $portCounterFlags + @(
                    "-c", (Join-Path $RepositoryRoot $source),
                    "-o", $object))
                if ($LASTEXITCODE -ne 0) {
                    throw "Context-cohort $($variant.Name) port compile failed ($mode): $source"
                }
                $objects[$role] = $object
            }

            $portableObject = Join-Path $variantDir "portable-application.o"
            & $Compiler @($variantArgs + @(
                "-c", (Join-Path $RepositoryRoot $portableSource),
                "-o", $portableObject))
            if ($LASTEXITCODE -ne 0) {
                throw "Context-cohort portable application compile failed ($mode / $($variant.Name))"
            }

            $expectationObject = Join-Path $variantDir "expectation.o"
            & $Compiler @($variantArgs + @(
                "-c", (Join-Path $RepositoryRoot $expectationSource),
                "-o", $expectationObject))
            if ($LASTEXITCODE -ne 0) {
                throw "Context-cohort expectation compile failed ($mode / $($variant.Name))"
            }

            $defined = @(& $objectNm -g --defined-only $objects.Runtime)
            $cohortDefinitions = @($defined | ForEach-Object {
                if ($_ -match
                        '\s[DR]\s+(fiber_port_context_cohort_\S+)$') {
                    $Matches[1]
                }
            })
            $undefined = @(& $objectNm -u $expectationObject)
            $cohortExpectations = @($undefined | ForEach-Object {
                if ($_ -match
                        '\bU\s+(fiber_port_context_cohort_\S+)$') {
                    $Matches[1]
                }
            })
            if (($cohortDefinitions.Count -ne 1) -or
                    ($cohortExpectations.Count -ne 1) -or
                    ($cohortDefinitions[0] -ne $cohortExpectations[0])) {
                throw "Context-cohort identity extraction failed ($mode / $($variant.Name))"
            }

            $objects.Portable = $portableObject
            $objects.Expectation = $expectationObject
            $objects.Cohort = $cohortDefinitions[0]
            $compiled[$variant.Name] = $objects
        }

        if ($compiled.secure.Cohort -eq $compiled.nonsecure.Cohort) {
            throw "Secure and Non-secure transitional profiles must have distinct exact cohort symbols ($mode)"
        }

        $linkBase = @(
            "-mcpu=cortex-m33",
            "-mthumb"
        ) + $ltoArgs + @(
            "-nostdlib",
            "-Wl,--gc-sections",
            "-T", $linkerPath,
            $startupObject
        )

        foreach ($variant in $variants) {
            $objects = $compiled[$variant.Name]
            $archivePath = Join-Path $probeDir `
                "positive-$($variant.Name).a"
            & $Ar rcs $archivePath @($commonObjects + @(
                $objects.Runtime, $objects.Boot, $objects.Exception))
            if ($LASTEXITCODE -ne 0) {
                throw "Context-cohort positive archive creation failed ($mode / $($variant.Name))"
            }
            & $Compiler @($linkBase + @(
                $objects.Portable,
                $objects.Expectation,
                $archivePath,
                "-o", (Join-Path $probeDir `
                    "positive-$($variant.Name).elf")))
            if ($LASTEXITCODE -ne 0) {
                throw "Matching real selected-port cohort failed link ($mode / $($variant.Name))"
            }
        }

        $negativeCases = @(
            [pscustomobject]@{ Name = "stale-runtime-secure"; Runtime = "secure"; Boot = "nonsecure"; Exception = "nonsecure"; Expected = "nonsecure"; Missing = "nonsecure" },
            [pscustomobject]@{ Name = "stale-boot-secure"; Runtime = "nonsecure"; Boot = "secure"; Exception = "nonsecure"; Expected = "nonsecure"; Missing = "secure" },
            [pscustomobject]@{ Name = "stale-exception-secure"; Runtime = "nonsecure"; Boot = "nonsecure"; Exception = "secure"; Expected = "nonsecure"; Missing = "secure" },
            [pscustomobject]@{ Name = "stale-complete-secure"; Runtime = "secure"; Boot = "secure"; Exception = "secure"; Expected = "nonsecure"; Missing = "nonsecure" },
            [pscustomobject]@{ Name = "stale-runtime-nonsecure"; Runtime = "nonsecure"; Boot = "secure"; Exception = "secure"; Expected = "secure"; Missing = "secure" },
            [pscustomobject]@{ Name = "stale-boot-nonsecure"; Runtime = "secure"; Boot = "nonsecure"; Exception = "secure"; Expected = "secure"; Missing = "nonsecure" },
            [pscustomobject]@{ Name = "stale-exception-nonsecure"; Runtime = "secure"; Boot = "secure"; Exception = "nonsecure"; Expected = "secure"; Missing = "nonsecure" },
            [pscustomobject]@{ Name = "stale-complete-nonsecure"; Runtime = "nonsecure"; Boot = "nonsecure"; Exception = "nonsecure"; Expected = "secure"; Missing = "secure" }
        )
        foreach ($case in $negativeCases) {
            $archivePath = Join-Path $probeDir ($case.Name + ".a")
            & $Ar rcs $archivePath @($commonObjects + @(
                $compiled[$case.Runtime].Runtime,
                $compiled[$case.Boot].Boot,
                $compiled[$case.Exception].Exception))
            if ($LASTEXITCODE -ne 0) {
                throw "Context-cohort stale archive creation failed ($mode / $($case.Name))"
            }

            $missingSymbol = $compiled[$case.Missing].Cohort
            $logPath = Join-Path $probeDir ($case.Name + ".log")
            $result = Invoke-CompilerProbe -Compiler $Compiler `
                -Arguments ($linkBase + @(
                    $compiled[$case.Expected].Portable,
                    $compiled[$case.Expected].Expectation,
                    $archivePath,
                    "-o", (Join-Path $probeDir ($case.Name + ".elf")))) `
                -LogPath $logPath
            $normalizedOutput = $result.Output -replace '\s+', ''
            if (($result.ExitCode -eq 0) -or
                    ($normalizedOutput -notmatch
                    [regex]::Escape($missingSymbol))) {
                throw "Stale selected-port object cohort must fail on $missingSymbol ($mode / $($case.Name)).`n$($result.Output)"
            }
        }
    }
}

function Test-BasepriContextCohortIdentity {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $probeRoot = Join-Path $BuildRoot "basepri-context-cohort"
    New-Item -ItemType Directory -Path $probeRoot | Out-Null
    $expectationSource = Join-Path $RepositoryRoot `
        "fiber\port\fiber_port_context_cohort_expectation.c"
    $variants = @(
        [pscustomobject]@{ Name = "prio4-basepri16"; PriorityBits = 4; Basepri = 16; Token = "_g4_u00010000_" },
        [pscustomobject]@{ Name = "prio4-basepri32"; PriorityBits = 4; Basepri = 32; Token = "_g4_u00100000_" },
        [pscustomobject]@{ Name = "prio5-basepri16"; PriorityBits = 5; Basepri = 16; Token = "_g5_u00010000_" }
    )
    $symbols = @{}

    foreach ($variant in $variants) {
        $probeDir = Join-Path $probeRoot $variant.Name
        New-Item -ItemType Directory -Path $probeDir | Out-Null
        $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 0U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS $($variant.PriorityBits)U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5,
    DebugMonitor_IRQn = -4, PendSV_IRQn = -2,
    SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm3.h"
#endif
"@
        Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
            -Value $mainHeader -Encoding ASCII
        $objectPath = Join-Path $probeDir "expectation.o"
        $compileArgs = @(
            "-mcpu=cortex-m3",
            "-mthumb",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-Wall",
            "-Wextra",
            "-Wundef",
            "-Werror=undef",
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV7M=1",
            "-DFIBER_SCHEDULER_BASEPRI=$($variant.Basepri)",
            "-I$probeDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port\ARM_CM3')",
            "-I$RepositoryRoot",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$CmsisPath",
            "-c", $expectationSource,
            "-o", $objectPath
        )
        & $Compiler @compileArgs
        if ($LASTEXITCODE -ne 0) {
            throw "BASEPRI context-cohort expectation failed compile: $($variant.Name)"
        }

        $undefined = @(& $Nm -u $objectPath)
        $cohortSymbols = @($undefined | ForEach-Object {
            if ($_ -match '\bU\s+(fiber_port_context_cohort_\S+)$') {
                $Matches[1]
            }
        })
        if (($cohortSymbols.Count -ne 1) -or
                ($cohortSymbols[0].IndexOf($variant.Token,
                    [System.StringComparison]::Ordinal) -lt 0)) {
            throw "Exact cohort omitted NVIC/BASEPRI policy: $($variant.Name)"
        }
        $symbols[$variant.Name] = $cohortSymbols[0]
    }

    if ((@($symbols.Values | Sort-Object -Unique)).Count -ne $variants.Count) {
        throw "Distinct NVIC/BASEPRI policies collapsed to one exact context cohort"
    }
}

function Test-ArmCm23NtzRuntimeContract {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Objdump,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot `
        "fiber\port\ARM_CM23_NTZ\non_secure"
    $fixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm23_ntz_layout_probe.c"
    foreach ($required in @(
            (Join-Path $profileDir "fiber_port_types.h"),
            (Join-Path $profileDir "fiber_port_boot_types.h"),
            (Join-Path $profileDir "fiber_portmacro.h"),
            (Join-Path $profileDir "fiber_port_boot.h"),
            (Join-Path $profileDir "fiber_port_private.h"),
            (Join-Path $profileDir "fiber_port.c"),
            (Join-Path $profileDir "fiber_port_boot.c"),
            (Join-Path $profileDir "FREERTOS_PARITY.md"),
            $fixture)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "ARM_CM23_NTZ runtime slice is missing: $required"
        }
    }

    foreach ($forbiddenRuntime in @(
            "fiber_port_exception.c",
            "fiber_portasm.c")) {
        if (Test-Path -LiteralPath (Join-Path $profileDir $forbiddenRuntime)) {
            throw "ARM_CM23_NTZ runtime slice must not expose an unowned runtime artifact: $forbiddenRuntime"
        }
    }

    $selectors = @(
        (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
        (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h")
    )
    foreach ($selector in $selectors) {
        if ((Get-Content -LiteralPath $selector -Raw).IndexOf(
                "ARM_CM23_NTZ", [System.StringComparison]::Ordinal) -ge 0) {
            throw "Build-selected ARM_CM23_NTZ profile entered global architecture selection: $selector"
        }
    }

    $typeText = Get-Content -LiteralPath `
        (Join-Path $profileDir "fiber_port_types.h") -Raw
    foreach ($forbiddenTypeDependency in @(
            "mcu_core.h",
            "fiber_compiler.h",
            "fiber_portmacro.h",
            "fiber_port_select.h")) {
        $includePattern = '(?m)^\s*#\s*include\s*["<][^">]*' +
            [regex]::Escape($forbiddenTypeDependency) + '[">]'
        if ([regex]::IsMatch($typeText, $includePattern)) {
            throw "ARM_CM23_NTZ public storage acquired CPU dependency: $forbiddenTypeDependency"
        }
    }

    $parity = Get-Content -LiteralPath `
        (Join-Path $profileDir "FREERTOS_PARITY.md") -Raw
    foreach ($requiredParity in @(
            "a50edad08b29052631aa469d4df6e6ec7ff68878",
            "23709D8EE3DE532A8394EAD05414FCF4FB4B37C94B5288ACF1FB1B829AA3F50E",
            "324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2",
            "BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A",
            "E15BDECFD24AB85165B69E3496E6FA644E5FF9C36EFBB3FFE6975FD5D7C9806C",
            "ignored PSPLIM slot, initially stack_base; zero after first save",
            "ten-word non-MPU NTZ frame",
            "mpu_wrappers_v2_asm.c")) {
        if ($parity.IndexOf($requiredParity,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM23_NTZ parity ledger lost reference evidence: $requiredParity"
        }
    }

    $probeDir = Join-Path $BuildRoot "arm-cm23-ntz-layout"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 0U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 3U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 0U
#define __SAUREGION_PRESENT 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    SVCall_IRQn = -5, PendSV_IRQn = -2, SysTick_IRQn = -1,
    DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm23.h"
#endif
"@
    Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
        -Value $mainHeader -Encoding ASCII

    $typeProbe = Join-Path $probeDir "type-only.c"
    Set-Content -LiteralPath $typeProbe -Encoding ASCII -Value @'
#include "fiber_port_types.h"
_Static_assert(sizeof(FiberPortBoot) == 72u, "boot size");
_Static_assert(sizeof(FiberContext) == 76u, "context size");
_Static_assert(_Alignof(FiberContext) == 4u, "context alignment");
FiberContext fiber_cm23_ntz_type_only_object;
'@
    $typeObject = Join-Path $probeDir "type-only.o"
    $typeArgs = @(
        "-mcpu=cortex-m23", "-mthumb", "-std=c11",
        "-ffreestanding", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
        "-I$profileDir", "-c", $typeProbe, "-o", $typeObject
    )
    & $Compiler @typeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM23_NTZ type-only C header failed without CMSIS"
    }

    $cppProbe = Join-Path $probeDir "type-only.cpp"
    Set-Content -LiteralPath $cppProbe -Encoding ASCII -Value @'
#include "fiber_port_types.h"
static_assert(sizeof(FiberPortBoot) == 72u, "boot size");
static_assert(sizeof(FiberContext) == 76u, "context size");
static_assert(alignof(FiberContext) == 4u, "context alignment");
FiberContext fiber_cm23_ntz_cpp_type_only_object;
'@
    $cppObject = Join-Path $probeDir "type-only-cpp.o"
    & $Compiler -x c++ -mcpu=cortex-m23 -mthumb -std=c++17 `
        -ffreestanding -fno-builtin -Wall -Wextra -Werror `
        "-I$profileDir" -c $cppProbe -o $cppObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM23_NTZ type-only C++ header failed without CMSIS"
    }

    $layoutObject = Join-Path $probeDir "layout.o"
    $manifestArgs = @(
        "-mcpu=cortex-m23", "-mthumb", "-std=c11",
        "-ffreestanding", "-fno-builtin", "-fno-common",
        "-Wall", "-Wextra", "-Wundef", "-Werror=undef",
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV8M_BASELINE=1",
        "-I$probeDir", "-I$profileDir",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot", "-I$CmsisPath"
    )
    & $Compiler @manifestArgs -c $fixture -o $layoutObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM23_NTZ exact layout manifest failed compile"
    }

    $defined = @(& $Nm -g --defined-only $layoutObject)
    if ($LASTEXITCODE -ne 0) {
        throw "nm failed for ARM_CM23_NTZ layout probe"
    }
    $cohorts = @($defined | ForEach-Object {
        if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
            $Matches[1]
        }
    })
    if ($cohorts.Count -ne 1) {
        throw "ARM_CM23_NTZ layout must define one exact cohort"
    }
    foreach ($token in @(
            "armv8m_baseline",
            "p0x4332334Eu",
            "l0x00010001u",
            "_o0xFFFFFFBCu_",
            "_c0_s1_x0_",
            "_t1_n1_k0_")) {
        if ($cohorts[0].IndexOf($token,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM23_NTZ exact cohort lost token ${token}: $($cohorts[0])"
        }
    }

    $runtimePath = Join-Path $profileDir "fiber_port.c"
    $bootPath = Join-Path $profileDir "fiber_port_boot.c"
    $runtimeSource = Get-Content -LiteralPath $runtimePath -Raw
    $bootSource = Get-Content -LiteralPath $bootPath -Raw
    $frameBody = Get-CFunctionBody -Source $runtimeSource `
        -Signature "void fiber_port_init_context_frame(FiberContext *const ctx)" `
        -Path $runtimePath
    $requiredAssignments = @(
        "frame[fiber_portFRAME_PSPLIM] = (uint32_t)ctx->boot.stack_base;",
        "frame[fiber_portFRAME_EXC_RETURN] = fiber_portINITIAL_EXC_RETURN;",
        "frame[fiber_portFRAME_R4] = 0u;",
        "frame[fiber_portFRAME_R5] = 0u;",
        "frame[fiber_portFRAME_R6] = 0u;",
        "frame[fiber_portFRAME_R7] = 0u;",
        "frame[fiber_portFRAME_R8] = 0u;",
        "frame[fiber_portFRAME_R9] = fiber_port_read_r9();",
        "frame[fiber_portFRAME_R10] = 0u;",
        "frame[fiber_portFRAME_R11] = 0u;",
        "frame[fiber_portFRAME_R0] = (uint32_t)(uintptr_t)ctx->boot.arg;",
        "frame[fiber_portFRAME_R1] = 0u;",
        "frame[fiber_portFRAME_R2] = 0u;",
        "frame[fiber_portFRAME_R3] = 0u;",
        "frame[fiber_portFRAME_R12] = 0u;",
        "frame[fiber_portFRAME_LR] =",
        "frame[fiber_portFRAME_PC] =",
        "frame[fiber_portFRAME_XPSR] = fiber_port_initial_xpsr();",
        "ctx->sp = frame;"
    )
    $lastAssignment = -1
    foreach ($assignment in $requiredAssignments) {
        $assignmentIndex = $frameBody.IndexOf($assignment,
            [System.StringComparison]::Ordinal)
        if ($assignmentIndex -le $lastAssignment) {
            throw "ARM_CM23_NTZ initial frame lost exact assignment order: $assignment"
        }
        $lastAssignment = $assignmentIndex
    }
    if (([regex]::Matches($frameBody, 'frame\[fiber_portFRAME_[A-Z0-9_]+\]\s*=')).Count -ne 18) {
        throw "ARM_CM23_NTZ constructor must assign exactly eighteen frame words"
    }
    foreach ($requiredFrameContract in @(
            "fiber_portFRAME_PSPLIM = 0",
            "fiber_portFRAME_EXC_RETURN = 1",
            "fiber_portFRAME_R0 = 10",
            "fiber_portFRAME_XPSR = 17",
            "fiber_portFRAME_WORD_COUNT = 18",
            "FIBER_PORT_CONTEXT_COHORT_DEFINE();",
            "FIBER_PORT_CONTEXT_COHORT_RETAIN();")) {
        if ($runtimeSource.IndexOf($requiredFrameContract,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM23_NTZ runtime lost exact construction contract: $requiredFrameContract"
        }
    }
    foreach ($requiredBootContract in @(
            "void fiber_port_context_init(FiberContext *const ctx,",
            "ctx->boot = fiber_port_boot_create(stack_begin, stack_end, entry, arg);",
            "fiber_port_init_context_frame(ctx);",
            "fiber_port_validate_initial_frame(ctx);",
            "FIBER_PORT_CONTEXT_COHORT_RETAIN();")) {
        if ($bootSource.IndexOf($requiredBootContract,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM23_NTZ boot source lost constructor contract: $requiredBootContract"
        }
    }

    $runtimeObject = Join-Path $probeDir "fiber-port.o"
    $bootObject = Join-Path $probeDir "fiber-port-boot.o"
    $groupObject = Join-Path $probeDir "runtime-group.o"
    & $Compiler @manifestArgs -O2 -c $runtimePath -o $runtimeObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM23_NTZ runtime source failed compile"
    }
    & $Compiler @manifestArgs -O2 -c $bootPath -o $bootObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM23_NTZ boot runtime support failed compile"
    }

    $configurationCohorts = @(
        [pscustomobject]@{
            Name = "paranoid"
            Defines = @(
                "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=1",
                "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1")
        },
        [pscustomobject]@{
            Name = "minimal"
            Defines = @(
                "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0",
                "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=0",
                "-DFIBER_STACK_CANARY=0",
                "-DFIBER_REWIND_MSP=0")
        }
    )
    foreach ($cohort in $configurationCohorts) {
        $cohortArgs = $manifestArgs + @($cohort.Defines)
        $cohortRuntime = Join-Path $probeDir `
            ("fiber-port-{0}.o" -f $cohort.Name)
        $cohortBoot = Join-Path $probeDir `
            ("fiber-port-boot-{0}.o" -f $cohort.Name)
        & $Compiler @cohortArgs -O2 -c `
            $runtimePath -o $cohortRuntime
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM23_NTZ $($cohort.Name) runtime configuration failed compile"
        }
        & $Compiler @cohortArgs -O2 -c `
            $bootPath -o $cohortBoot
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM23_NTZ $($cohort.Name) boot configuration failed compile"
        }
    }

    & $Compiler -r $runtimeObject $bootObject -o $groupObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM23_NTZ runtime object group failed relocatable link"
    }

    $groupDefined = @(& $Nm -g --defined-only $groupObject)
    if ($LASTEXITCODE -ne 0) {
        throw "nm failed for ARM_CM23_NTZ constructor group"
    }
    $definedForward = @($groupDefined | ForEach-Object {
        if ($_ -match '\b(fiber_port_(?:context_init|runtime_memory_barrier|panic_wait|require_scheduler_configuration_environment|runtime_prepare_start|runtime_select_first|runtime_start_first|runtime_schedule))$') {
            $Matches[1]
        }
    } | Sort-Object -Unique)
    $expectedForward = @(
        "fiber_port_context_init",
        "fiber_port_panic_wait",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_memory_barrier",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_runtime_schedule"
    ) | Sort-Object
    if (@(Compare-Object -ReferenceObject $expectedForward `
            -DifferenceObject $definedForward).Count -ne 0) {
        throw "ARM_CM23_NTZ runtime forward ABI surface changed: $($definedForward -join ', ')"
    }
    $strongSvc = @($groupDefined | Where-Object { $_ -match '\bT\s+SVC_Handler$' })
    if ($strongSvc.Count -ne 1) {
        throw "ARM_CM23_NTZ runtime must define one strong SVC_Handler"
    }
    $strongPendSv = @($groupDefined | Where-Object { $_ -match '\bT\s+PendSV_Handler$' })
    if ($strongPendSv.Count -ne 1) {
        throw "ARM_CM23_NTZ runtime must define one strong PendSV_Handler"
    }
    $groupCohorts = @($groupDefined | ForEach-Object {
        if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
            $Matches[1]
        }
    })
    if (($groupCohorts.Count -ne 1) -or ($groupCohorts[0] -ne $cohorts[0])) {
        throw "ARM_CM23_NTZ runtime group disagrees with its frozen layout cohort"
    }

    $undefined = @(& $Nm -u $groupObject | ForEach-Object {
        if ($_ -match '\bU\s+(\S+)$') {
            $Matches[1]
        }
    } | Sort-Object -Unique)
    $allowedUndefined = @(
        "fiber_addr_plausible_code",
        "fiber_addr_plausible_ram",
        "fiber_internal_runtime_current_context_slot",
        "fiber_internal_runtime_port_abi_v1_anchor",
        "fiber_internal_runtime_publish_current_context",
        "fiber_internal_runtime_require_current_context",
        "fiber_internal_runtime_select_scheduler_candidate",
        "fiber_internal_task_return",
        "fiber_panic",
        "memcpy",
        "memset"
    ) | Sort-Object
    $unexpectedUndefined = @(Compare-Object -ReferenceObject $allowedUndefined `
        -DifferenceObject $undefined | Where-Object SideIndicator -eq "=>")
    if ($unexpectedUndefined.Count -ne 0) {
        throw "ARM_CM23_NTZ runtime gained unexpected dependencies: $($undefined -join ', ')"
    }
    foreach ($requiredUndefined in @(
            "fiber_addr_plausible_code",
            "fiber_addr_plausible_ram",
            "fiber_internal_runtime_current_context_slot",
            "fiber_internal_runtime_port_abi_v1_anchor",
            "fiber_internal_runtime_publish_current_context",
            "fiber_internal_runtime_require_current_context",
            "fiber_internal_runtime_select_scheduler_candidate",
            "fiber_internal_task_return",
            "fiber_panic")) {
        if ($undefined -notcontains $requiredUndefined) {
            throw "ARM_CM23_NTZ runtime lost required integration dependency: $requiredUndefined"
        }
    }

    foreach ($requiredStartupContract in @(
            "fiber_portSVC_ORIGIN_EXC_RETURN 0xFFFFFFB8u",
            "void fiber_port_runtime_prepare_start(void)",
            "FiberContext *fiber_port_runtime_select_first(void)",
            "void fiber_port_runtime_start_first(FiberContext *const first)",
            "void fiber_port_runtime_schedule(void)",
            "FiberContext *fiber_port_scheduler_pick_next_from_pendsv(",
            "void fiber_port_validate_exception_start_configuration(void)",
            "void SVC_Handler(void)",
            "void PendSV_Handler(void)",
            "fiber_internal_runtime_current_context_slot",
            "adds  r0, #24",
            "subs  r0, #36")) {
        if ($runtimeSource.IndexOf($requiredStartupContract,
                [System.StringComparison]::Ordinal) -lt 0 -and
                (Get-Content -LiteralPath (Join-Path $profileDir "fiber_portmacro.h") -Raw).IndexOf(
                    $requiredStartupContract, [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM23_NTZ SVC startup contract lost: $requiredStartupContract"
        }
    }

    $startFirstBody = Get-CFunctionBody -Source $runtimeSource `
        -Signature "void fiber_port_runtime_start_first(FiberContext *const first)" `
        -Path $runtimePath
    $lastStartBoundary = -1
    foreach ($startBoundaryStep in @(
            "fiber_port_context_prepare_first_start(first)",
            "fiber_port_require_start_interrupt_state()",
            "fiber_port_primask_save_disable()",
            "__get_PRIMASK() == 1u",
            "fiber_port_validate_exception_start_configuration()",
            "fiber_port_start_first_context(msp_top)")) {
        $stepIndex = $startFirstBody.IndexOf($startBoundaryStep,
            [System.StringComparison]::Ordinal)
        if ($stepIndex -le $lastStartBoundary) {
            throw "ARM_CM23_NTZ final masked start ordering changed: $startBoundaryStep"
        }
        $lastStartBoundary = $stepIndex
    }

    $runtimeDisassembly = (& $Objdump -d $runtimeObject | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed for ARM_CM23_NTZ startup object"
    }
    $svcBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
        -Symbol "SVC_Handler" -Path $runtimeObject
    $pendSvBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
        -Symbol "PendSV_Handler" -Path $runtimeObject
    foreach ($requiredShape in @(
            '\bmovs\s+r2,\s*#71\b',
            '\bmvns\s+r2,\s*r2\b',
            '\bmsr\s+CONTROL,\s*r0\b',
            '\badds\s+r0,\s*#24\b',
            '\bsubs\s+r0,\s*#36\b',
            '\bmsr\s+PSP,\s*r0\b',
            '\bbx\s+lr\b')) {
        if ($svcBody -notmatch $requiredShape) {
            throw "ARM_CM23_NTZ generated SVC restore shape changed: $requiredShape"
        }
    }
    if ($svcBody -notmatch 'fiber_port_context_validate_restore') {
        throw "ARM_CM23_NTZ SVC must validate the selected context before restore"
    }
    $orderedSvcRestore = @(
        'fiber_port_context_validate_restore',
        '\bldr\s+r0,\s*\[r2(?:,\s*#0)?\]',
        '\badds\s+r0,\s*#24\b',
        '\bmsr\s+PSP,\s*r0\b',
        '\bsubs\s+r0,\s*#36\b',
        '\bbx\s+lr\b'
    )
    $lastSvcRestore = -1
    foreach ($pattern in $orderedSvcRestore) {
        $match = [regex]::Match($svcBody, $pattern)
        if ((-not $match.Success) -or ($match.Index -le $lastSvcRestore)) {
            throw "ARM_CM23_NTZ generated SVC restore ordering changed: $pattern"
        }
        $lastSvcRestore = $match.Index
    }
    if (([regex]::Matches($runtimeDisassembly, '\bsvc\s+70\b')).Count -ne 1) {
        throw "ARM_CM23_NTZ runtime slice must emit exactly one start SVC"
    }

    $scheduleBody = Get-CFunctionBody -Source $runtimeSource `
        -Signature "void fiber_port_runtime_schedule(void)" -Path $runtimePath
    $lastScheduleStep = -1
    foreach ($scheduleStep in @(
            "FIBER_REQUIRE(__get_IPSR() == 0u, 'i');",
            "fiber_internal_runtime_require_current_context();",
            "FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');",
            "FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');",
            "fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVSET_BIT;",
            "fiber_portDATA_SYNC_BARRIER();",
            "fiber_portINST_SYNC_BARRIER();")) {
        $stepIndex = $scheduleBody.IndexOf($scheduleStep,
            [System.StringComparison]::Ordinal)
        if ($stepIndex -le $lastScheduleStep) {
            throw "ARM_CM23_NTZ runtime_schedule ordering changed: $scheduleStep"
        }
        $lastScheduleStep = $stepIndex
    }
    if ($scheduleBody.IndexOf("fiber_port_context_validate_save_current(",
            [System.StringComparison]::Ordinal) -ge 0) {
        throw "ARM_CM23_NTZ Thread schedule path must not duplicate PendSV preflight"
    }

    $pendSvSource = Get-CFunctionBody -Source $runtimeSource `
        -Signature "void PendSV_Handler(void)" -Path $runtimePath
    $stackTopLoad = $pendSvSource.IndexOf("ldr   r2, [r1, %c[offtop]]",
        [System.StringComparison]::Ordinal)
    if ($stackTopLoad -lt 0) {
        throw "ARM_CM23_NTZ PendSV lost the stack-top hardware-frame preflight"
    }
    $basicFrameCheck = $pendSvSource.IndexOf("cmp   r0, r2", $stackTopLoad,
        [System.StringComparison]::Ordinal)
    $stackedXpsrLoad = $pendSvSource.IndexOf("ldr   r3, [r0, %c[xpsr]]",
        [System.StringComparison]::Ordinal)
    if (($basicFrameCheck -le $stackTopLoad) -or
            ($stackedXpsrLoad -le $basicFrameCheck)) {
        throw "ARM_CM23_NTZ must prove the basic hardware frame before reading stacked xPSR"
    }

    foreach ($requiredShape in @(
            '\bmovs\s+r2,\s*#67\b',
            '\bmvns\s+r2,\s*r2\b',
            '\bmrs\s+r0,\s*PSP\b',
            'fiber_port_context_validate_save_current',
            '\bsubs\s+r0,\s*#40\b',
            '\bstmia\s+r0!,\s*\{r2,\s*r3,\s*r4,\s*r5,\s*r6,\s*r7\}',
            '\bcpsid\s+i\b',
            'fiber_port_scheduler_pick_next_from_pendsv',
            '\bcpsie\s+i\b',
            '\badds\s+r0,\s*#24\b',
            '\bmsr\s+PSP,\s*r0\b',
            '\bsubs\s+r0,\s*#36\b',
            '\bbx\s+lr\b')) {
        if ($pendSvBody -notmatch $requiredShape) {
            throw "ARM_CM23_NTZ generated PendSV shape changed: $requiredShape"
        }
    }
    if ($pendSvBody -match '(?i)\bpsplim\b') {
        throw "ARM_CM23_NTZ Non-secure PendSV must not access PSPLIM"
    }
    $orderedPendSv = @(
        'fiber_port_context_validate_save_current',
        '\bldr\s+r2,\s*\[r1',
        '\bsubs\s+r0,\s*#40\b',
        '\bcpsid\s+i\b',
        'fiber_port_scheduler_pick_next_from_pendsv',
        '\bcpsie\s+i\b',
        '\badds\s+r0,\s*#24\b',
        '\bmsr\s+PSP,\s*r0\b',
        '\bsubs\s+r0,\s*#36\b',
        '\bbx\s+lr\b'
    )
    $lastPendSvStep = -1
    foreach ($pattern in $orderedPendSv) {
        $match = [regex]::Match($pendSvBody, $pattern)
        if ((-not $match.Success) -or ($match.Index -le $lastPendSvStep)) {
            throw "ARM_CM23_NTZ generated PendSV ordering changed: $pattern"
        }
        $lastPendSvStep = $match.Index
    }

    $negativeCases = @(
        [pscustomobject]@{
            Name = "selector-mode"
            CompilerArgs = @("-mcpu=cortex-m23", "-mthumb")
            Defines = @("-DFIBER_PORT_PROFILE=4")
            Diagnostic = "ARM_CM23_NTZ is build-selected only"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "secure-cmse"
            CompilerArgs = @("-mcpu=cortex-m23", "-mthumb", "-mcmse")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_BASELINE=1")
            Diagnostic = "does not accept a Secure CMSE build"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "no-vtor"
            CompilerArgs = @("-mcpu=cortex-m23", "-mthumb")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_BASELINE=1")
            Diagnostic = "requires __VTOR_PRESENT == 1"
            Main = ($mainHeader -replace '__VTOR_PRESENT 1U', '__VTOR_PRESENT 0U')
        },
        [pscustomobject]@{
            Name = "wrong-core"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb")
            Defines = @(
                "-DFIBER_PORT_BUILD_SELECTED=1",
                "-DFIBER_PORT_ARMV8M_BASELINE=1",
                "-DFIBER_PORT_SELECTION_ALLOW_MISMATCH=1")
            Diagnostic = "requires an ARMv8-M Baseline compiler target"
            Main = ($mainHeader -replace 'core_cm23.h', 'core_cm33.h')
        },
        [pscustomobject]@{
            Name = "fpu-present"
            CompilerArgs = @("-mcpu=cortex-m23", "-mthumb")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_BASELINE=1")
            Diagnostic = "Cortex-M23 has no FPU"
            Main = (($mainHeader -replace '__FPU_PRESENT 0U', '__FPU_PRESENT 1U') `
                -replace '__FPU_USED 0U', '__FPU_USED 1U')
        },
        [pscustomobject]@{
            Name = "invalid-svc-number"
            CompilerArgs = @("-mcpu=cortex-m23", "-mthumb")
            Defines = @(
                "-DFIBER_PORT_BUILD_SELECTED=1",
                "-DFIBER_PORT_ARMV8M_BASELINE=1",
                "-DFIBER_SVC_START_NUMBER=256")
            Diagnostic = "FIBER_SVC_START_NUMBER"
            Main = $mainHeader
        }
    )

    foreach ($case in $negativeCases) {
        $caseDir = Join-Path $probeDir $case.Name
        New-Item -ItemType Directory -Path $caseDir | Out-Null
        Set-Content -LiteralPath (Join-Path $caseDir "main.h") `
            -Value $case.Main -Encoding ASCII
        $log = Join-Path $caseDir "compile.log"
        $arguments = @($case.CompilerArgs + @(
            "-std=c11", "-ffreestanding", "-fno-builtin",
            "-Wall", "-Wextra", "-I$caseDir", "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot", "-I$CmsisPath") +
            $case.Defines + @(
            "-c", $fixture, "-o", (Join-Path $caseDir "invalid.o")))
        $result = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $arguments -LogPath $log
        if (($result.ExitCode -eq 0) -or
                ($result.Output.IndexOf($case.Diagnostic,
                [System.StringComparison]::Ordinal) -lt 0)) {
            throw "Invalid ARM_CM23_NTZ manifest failed for the wrong reason: $($case.Name)`n$($result.Output)"
        }
    }
}

function Test-ArmCm23NtzRuntimeIntegration {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Objdump,
        [string]$Objcopy,
        [string]$Ar,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot `
        "fiber\port\ARM_CM23_NTZ\non_secure"
    $startupSource = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm23_ntz_runtime_startup.c"
    $portableSource = Join-Path $RepositoryRoot `
        "tools\fixtures\portable_application.c"
    $expectationSource = Join-Path $RepositoryRoot `
        "fiber\port\fiber_port_context_cohort_expectation.c"
    $linkerScript = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm23_ntz_runtime.ld"
    foreach ($requiredPath in @($startupSource, $portableSource,
            $expectationSource, $linkerScript)) {
        if (-not (Test-Path -LiteralPath $requiredPath)) {
            throw "ARM_CM23_NTZ runtime integration fixture is missing: $requiredPath"
        }
    }

    $commonSources = @(
        "fiber\fiber_core.c",
        "fiber\fiber_runtime_state.c",
        "fiber\fiber_panic.c"
    )
    $portSources = @(
        "fiber\port\ARM_CM23_NTZ\non_secure\fiber_port.c",
        "fiber\port\ARM_CM23_NTZ\non_secure\fiber_port_boot.c"
    )
    $forwardAbiSymbols = @(
        "fiber_port_context_init",
        "fiber_port_runtime_memory_barrier",
        "fiber_port_panic_wait",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_runtime_schedule"
    )
    $manifestDefines = @(
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV8M_BASELINE=1"
    )
    $counterFlags = @(
        "-fno-instrument-functions",
        "-fno-stack-protector",
        "-fno-profile-arcs",
        "-fno-test-coverage",
        "-fno-sanitize=all",
        "-mgeneral-regs-only"
    )

    foreach ($useLto in @($false, $true)) {
        $mode = if ($useLto) { "lto" } else { "normal" }
        $probeDir = Join-Path $BuildRoot "arm-cm23-ntz-runtime-$mode"
        New-Item -ItemType Directory -Path $probeDir | Out-Null

        $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 0U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 0U
#define __SAUREGION_PRESENT 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    SVCall_IRQn = -5, PendSV_IRQn = -2, SysTick_IRQn = -1,
    DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm23.h"
#endif
"@
        Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
            -Value $mainHeader -Encoding ASCII

        $ltoArgs = if ($useLto) { @("-flto") } else { @() }
        $baseArgs = @(
            "-mcpu=cortex-m23",
            "-mthumb",
            "-mfloat-abi=soft",
            "-O2",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-fno-builtin",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wundef",
            "-Werror=undef",
            "-Werror=implicit-function-declaration",
            "-Werror=return-type",
            "-I$probeDir",
            "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot",
            "-I$CmsisPath"
        ) + $manifestDefines + $ltoArgs

        $archiveObjects = @()
        foreach ($source in ($commonSources + $portSources)) {
            $object = Join-Path $probeDir `
                (($source -replace '[\\/]', '_') + ".o")
            $sourcePath = Join-Path $RepositoryRoot $source
            $extraFlags = if ($portSources -contains $source) {
                $counterFlags
            }
            else {
                @()
            }
            & $Compiler @($baseArgs + $extraFlags + @(
                "-c", $sourcePath, "-o", $object))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM23_NTZ runtime archive compile failed ($mode): $source"
            }
            $archiveObjects += $object
        }

        $startupObject = Join-Path $probeDir "startup.o"
        $portableObject = Join-Path $probeDir "portable.o"
        $expectationObject = Join-Path $probeDir "expectation.o"
        foreach ($compile in @(
                [pscustomobject]@{ Source = $startupSource; Object = $startupObject; Name = "startup" },
                [pscustomobject]@{ Source = $portableSource; Object = $portableObject; Name = "portable application" },
                [pscustomobject]@{ Source = $expectationSource; Object = $expectationObject; Name = "cohort expectation" })) {
            $fixtureArgs = $baseArgs
            if ($useLto -and ($compile.Name -eq "portable application")) {
                $fixtureArgs = @($baseArgs | Where-Object { $_ -ne "-flto" })
                $fixtureArgs += "-fno-lto"
            }
            & $Compiler @($fixtureArgs + $counterFlags + @(
                "-c", $compile.Source, "-o", $compile.Object))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM23_NTZ $($compile.Name) compile failed ($mode)"
            }
        }

        $objectNm = if ($useLto) { $GccNm } else { $Nm }
        $expectationUndefined = @(& $objectNm --undefined-only $expectationObject)
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM23_NTZ expectation nm failed ($mode)"
        }
        $expectedCohorts = @($expectationUndefined | ForEach-Object {
            if ($_ -match '\bU\s+(fiber_port_context_cohort_armv8m_baseline_\S+)$') {
                $Matches[1]
            }
        })
        if ($expectedCohorts.Count -ne 1) {
            throw "ARM_CM23_NTZ expectation must retain one exact cohort relocation ($mode)"
        }

        $archivePath = Join-Path $probeDir "libfiber-arm-cm23-ntz.a"
        & $Ar rcs $archivePath @archiveObjects
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM23_NTZ runtime archive creation failed ($mode)"
        }

        $elfPath = Join-Path $probeDir "fiber-arm-cm23-ntz.elf"
        $mapPath = Join-Path $probeDir "fiber-arm-cm23-ntz.map"
        $linkArgs = @(
            "-mcpu=cortex-m23",
            "-mthumb",
            "-mfloat-abi=soft"
        ) + $ltoArgs + @(
            "-nostdlib",
            "-Wl,--gc-sections",
            "-Wl,-Map,$mapPath",
            "-Wl,-T,$linkerScript",
            $startupObject,
            $portableObject,
            $expectationObject,
            $archivePath,
            "-o", $elfPath
        )
        & $Compiler @linkArgs
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM23_NTZ portable archive/link integration failed ($mode)"
        }

        $defined = @(& $Nm -a --defined-only $elfPath)
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM23_NTZ final ELF nm failed ($mode)"
        }
        foreach ($symbol in $forwardAbiSymbols) {
            $definitions = @($defined | Where-Object {
                $_ -match ("\b[TW]\s+" + [regex]::Escape($symbol) + "$")
            })
            if ($definitions.Count -ne 1) {
                throw "ARM_CM23_NTZ final ELF must define one strong forward ABI symbol ($mode): $symbol"
            }
        }

        $cohortDefinitions = @($defined | ForEach-Object {
            if ($_ -match '\b[DRTdrt]\s+(fiber_port_context_cohort_armv8m_baseline_\S+)$') {
                $Matches[1]
            }
        })
        $cohortSymbols = @($defined | Where-Object {
            $_ -match '\bfiber_port_context_cohort_armv8m_baseline_\S+$'
        })
        if (($cohortDefinitions.Count -ne 1) -or
                ($cohortDefinitions[0] -ne $expectedCohorts[0])) {
            throw "ARM_CM23_NTZ final ELF must satisfy its exact cohort expectation ($mode): expected $($expectedCohorts -join ', '), found $($cohortDefinitions -join ', '); raw symbols $($cohortSymbols -join '; ')"
        }

        $svcAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
            -Symbol "SVC_Handler" -Path $elfPath
        $pendsvAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
            -Symbol "PendSV_Handler" -Path $elfPath

        $sections = (& $Objdump -h $elfPath) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM23_NTZ final ELF section audit failed ($mode)"
        }
        if ($sections -notmatch
                '\.fiber_port_context_cohort_expectation\s+00000004\s+[0-9a-fA-F]+\s+') {
            throw "ARM_CM23_NTZ final ELF lost its retained four-byte cohort expectation ($mode)"
        }
        $vectorPath = Join-Path $probeDir "vectors.bin"
        & $Objcopy -O binary --only-section=.isr_vector $elfPath $vectorPath
        if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $vectorPath))) {
            throw "ARM_CM23_NTZ runtime vector extraction failed ($mode)"
        }
        $vectorBytes = [IO.File]::ReadAllBytes($vectorPath)
        if ($vectorBytes.Length -ne 64) {
            throw "ARM_CM23_NTZ runtime vector fixture changed size ($mode)"
        }
        $svcVector = [BitConverter]::ToUInt32($vectorBytes, 11 * 4)
        $pendsvVector = [BitConverter]::ToUInt32($vectorBytes, 14 * 4)
        if ($svcVector -ne ($svcAddress -bor 1)) {
            throw "ARM_CM23_NTZ runtime vector slot 11 lost strong SVC handler ($mode)"
        }
        if ($pendsvVector -ne ($pendsvAddress -bor 1)) {
            throw "ARM_CM23_NTZ runtime vector slot 14 lost strong PendSV handler ($mode)"
        }

        $competingSource = Join-Path $probeDir "competing.c"
        $competingObject = Join-Path $probeDir "competing.o"
        Set-Content -LiteralPath $competingSource -Encoding ASCII -Value `
            "void SVC_Handler(void) { }`nvoid PendSV_Handler(void) { }`n"
        & $Compiler @($baseArgs + @(
            "-c", $competingSource, "-o", $competingObject))
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM23_NTZ competing-handler fixture compile failed ($mode)"
        }
        $duplicateLog = Join-Path $probeDir "duplicate.log"
        $duplicateArgs = @($linkArgs[0..($linkArgs.Count - 3)] + @(
            $competingObject, "-o", (Join-Path $probeDir "duplicate.elf")))
        $duplicate = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $duplicateArgs -LogPath $duplicateLog
        if (($duplicate.ExitCode -eq 0) -or
                ($duplicate.Output -notmatch 'multiple definition')) {
            throw "ARM_CM23_NTZ competing strong handlers must fail link ($mode)`n$($duplicate.Output)"
        }
    }
}

function Test-ArmCm33MpuLayoutContract {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot `
        "fiber\port\ARM_CM33_MPU\non_secure"
    $fixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm33_mpu_layout_probe.c"
    foreach ($required in @(
            "fiber_port_boot_types.h",
            "fiber_port_types.h",
            "fiber_portmacro.h",
			"fiber_port_boot.h",
			"fiber_port_boot.c",
			"fiber_port_linker_contract.ld",
            "FREERTOS_PARITY.md")) {
        $path = Join-Path $profileDir $required
        if (-not (Test-Path -LiteralPath $path)) {
            throw "ARM_CM33_MPU layout contract is missing required file: $path"
        }
    }
    if (-not (Test-Path -LiteralPath $fixture)) {
        throw "ARM_CM33_MPU layout contract is missing its layout fixture"
    }

    foreach ($forbiddenArtifact in @(
            "fiber_port_exception.c",
            "fiber_port_mpu_abi.h",
            "fiber_port_mpu_abi.c",
            "fiber_port_secure_context.c")) {
        if (Test-Path -LiteralPath (Join-Path $profileDir $forbiddenArtifact)) {
            throw "ARM_CM33_MPU staged profile exposed forbidden artifact: $forbiddenArtifact"
        }
    }

    foreach ($selector in @(
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h"))) {
        if ((Get-Content -LiteralPath $selector -Raw).IndexOf(
                "ARM_CM33_MPU", [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM33_MPU staged profile must not enter global selection: $selector"
        }
    }

    $typeText = Get-Content -LiteralPath `
        (Join-Path $profileDir "fiber_port_types.h") -Raw
    foreach ($forbiddenTypeDependency in @(
            "mcu_core.h",
            "fiber_compiler.h",
            "fiber_portmacro.h",
            "fiber_port_select.h")) {
        $includePattern = '(?m)^\s*#\s*include\s*["<][^">]*' +
            [regex]::Escape($forbiddenTypeDependency) + '[">]'
        if ([regex]::IsMatch($typeText, $includePattern)) {
            throw "ARM_CM33_MPU public storage acquired CPU dependency: $forbiddenTypeDependency"
        }
    }

    $parity = Get-Content -LiteralPath `
        (Join-Path $profileDir "FREERTOS_PARITY.md") -Raw
    foreach ($requiredParity in @(
            "a50edad08b29052631aa469d4df6e6ec7ff68878",
            "GCC_ARM_CM33_NTZ_NONSECURE",
            "F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B",
            "324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2",
            "BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A",
            "DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5",
            "00B42952962E48F8C9421F5EC66BBCE9E02465760560728FEE2D743CE1706F3E",
            "The first 20 context words are active",
            "cursor_limit",
            "There is no `xSecureContext` word",
            "the runtime has exactly one strong SVC handler, no PendSV handler, no forward",
            "protected first-start runtime compiles for 8 and 16 regions",
            "is passed explicitly from the C dispatcher into naked restore")) {
        if ($parity.IndexOf($requiredParity,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33_MPU parity ledger lost reference evidence: $requiredParity"
        }
    }

    $probeDir = Join-Path $BuildRoot "arm-cm33-mpu-layout"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
#ifndef FIBER_TEST_FPU_USED
#define FIBER_TEST_FPU_USED 0U
#endif
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    SVCall_IRQn = -5, PendSV_IRQn = -2, SysTick_IRQn = -1,
    DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm33.h"
#if FIBER_TEST_FPU_USED != 0U
#undef __FPU_USED
#define __FPU_USED FIBER_TEST_FPU_USED
#endif
#endif
"@
    Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
        -Value $mainHeader -Encoding ASCII

    $warningArgs = @(
        "-ffreestanding",
        "-fno-builtin",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wundef",
        "-Werror=undef",
        "-Werror=implicit-function-declaration",
        "-Werror=return-type"
    )
    $cppWarningArgs = @($warningArgs | Where-Object {
        ($_ -ne "-Werror=implicit-function-declaration")
    })
    $typeIncludeArgs = @("-I$profileDir")
    $manifestIncludeArgs = @(
        "-I$probeDir",
        "-I$profileDir",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot",
        "-I$CmsisPath"
    )

    $typeProbe = Join-Path $probeDir "type-only.c"
    Set-Content -LiteralPath $typeProbe -Encoding ASCII -Value @'
#include <stddef.h>
#include "fiber_port_types.h"

_Static_assert(sizeof(FiberPortBoot) == 88u, "boot size");
_Static_assert(sizeof(FiberPortProtectedContext) == 84u, "protected size");
_Static_assert(_Alignof(FiberContext) == 8u, "context alignment");
#if FIBER_PORT_CM33_MPU_TOTAL_REGIONS == 8
_Static_assert(sizeof(FiberContext) == 216u, "8-region context size");
_Static_assert(offsetof(FiberContext, protected_context) == 40u, "8-region protected offset");
#else
_Static_assert(sizeof(FiberContext) == 280u, "16-region context size");
_Static_assert(offsetof(FiberContext, protected_context) == 104u, "16-region protected offset");
#endif
FiberContext fiber_arm_cm33_mpu_type_only_object;
'@
    $cppProbe = Join-Path $probeDir "type-only.cpp"
    Set-Content -LiteralPath $cppProbe -Encoding ASCII -Value @'
#include <cstddef>
#include "fiber_port_types.h"

static_assert(sizeof(FiberPortBoot) == 88u, "boot size");
static_assert(sizeof(FiberPortProtectedContext) == 84u, "protected size");
static_assert(alignof(FiberContext) == 8u, "context alignment");
#if FIBER_PORT_CM33_MPU_TOTAL_REGIONS == 8
static_assert(sizeof(FiberContext) == 216u, "8-region context size");
#else
static_assert(sizeof(FiberContext) == 280u, "16-region context size");
#endif
FiberContext fiber_arm_cm33_mpu_cpp_type_only_object;
'@
    $facadeProbe = Join-Path $probeDir "selected-facade.c"
    Set-Content -LiteralPath $facadeProbe -Encoding ASCII -Value @'
#include <stddef.h>
#include "fiber/fiber_core.h"

#if FIBER_PORT_CM33_MPU_TOTAL_REGIONS == 8
_Static_assert(sizeof(FiberContext) == 216u, "8-region selected facade");
#else
_Static_assert(sizeof(FiberContext) == 280u, "16-region selected facade");
#endif
int fiber_arm_cm33_mpu_selected_facade_probe(void)
{
    return 0;
}
'@

    $variantCohorts = @{}
    foreach ($regions in @(8, 16)) {
        $layoutToken = if ($regions -eq 8) {
            "l0x00010008u"
        } else {
            "l0x00010010u"
        }
        $regionDefines = @("-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=$regions")
        $typeObject = Join-Path $probeDir "type-only-$regions.o"
        & $Compiler -mcpu=cortex-m33 -mthumb -mfloat-abi=soft -std=c11 `
            @warningArgs @typeIncludeArgs @regionDefines -c $typeProbe -o $typeObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_MPU type-only C header failed without CMSIS ($regions regions)"
        }
        $cppObject = Join-Path $probeDir "type-only-$regions-cpp.o"
        & $Compiler -x c++ -mcpu=cortex-m33 -mthumb -mfloat-abi=soft -std=c++17 `
            -fno-exceptions -fno-rtti @cppWarningArgs @typeIncludeArgs @regionDefines `
            -c $cppProbe -o $cppObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_MPU type-only C++ header failed without CMSIS ($regions regions)"
        }

        $selectedDefines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV8M_MAINLINE=1") + $regionDefines
        $facadeObject = Join-Path $probeDir "selected-facade-$regions.o"
        & $Compiler -mcpu=cortex-m33 -mthumb -mfloat-abi=soft -std=c11 `
            @warningArgs @selectedDefines @manifestIncludeArgs `
            -c $facadeProbe -o $facadeObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_MPU build-selected public facade failed compile ($regions regions)"
        }

        foreach ($optimization in @("-O2", "-Os")) {
            $mode = $optimization.Substring(1).ToLowerInvariant()
            $layoutObject = Join-Path $probeDir "layout-$regions-$mode.o"
            $manifestArgs = @(
                "-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft", "-std=c11",
                $optimization) + $warningArgs + $selectedDefines + $manifestIncludeArgs
            & $Compiler @manifestArgs -c $fixture -o $layoutObject
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU exact layout manifest failed compile ($regions regions/$mode)"
            }
            $defined = @(& $Nm -g --defined-only $layoutObject)
            if ($LASTEXITCODE -ne 0) {
                throw "nm failed for ARM_CM33_MPU layout probe ($regions regions/$mode)"
            }
            $cohorts = @($defined | ForEach-Object {
                if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
                    $Matches[1]
                }
            })
            if ($cohorts.Count -ne 1) {
                throw "ARM_CM33_MPU layout must define one exact cohort ($regions regions/$mode)"
            }
            foreach ($token in @(
                    "armv8m_mainline",
                    "p0x4333334Du",
                    $layoutToken,
                    "_h1_j1_v1_d1_r1_",
                    "_z8u_y0_w2_g4_",
                    "_i0_o0xFFFFFFBCu_c1_s1_x0_m0_a0_b0_t1_n1_k0_q0")) {
                if ($cohorts[0].IndexOf($token,
                        [System.StringComparison]::Ordinal) -lt 0) {
                    throw "ARM_CM33_MPU exact cohort lost token ${token} ($regions regions/$mode): $($cohorts[0])"
                }
            }
            $runtimeDefinitions = @($defined | Where-Object {
                $_ -match '\b(?:fiber_port_runtime_|SVC_Handler$|PendSV_Handler$)'
            })
            if ($runtimeDefinitions.Count -ne 0) {
                throw "ARM_CM33_MPU layout slice emitted runtime symbols ($regions regions/$mode): $($runtimeDefinitions -join ', ')"
            }
            $variantCohorts["$regions-$mode"] = $cohorts[0]
        }
    }
    foreach ($mode in @("o2", "os")) {
        if ($variantCohorts["8-$mode"] -eq $variantCohorts["16-$mode"]) {
            throw "ARM_CM33_MPU 8- and 16-region manifests collapsed one exact cohort ($mode)"
        }
    }

    $negativeCases = @(
        [pscustomobject]@{
            Name = "selector-mode"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_PROFILE=5", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8")
            Diagnostic = "ARM_CM33_MPU is build-selected only"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "missing-mpu"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8")
            Diagnostic = "manifest requires __MPU_PRESENT == 1"
            Main = ($mainHeader -replace '__MPU_PRESENT 1U', '__MPU_PRESENT 0U')
        },
        [pscustomobject]@{
            Name = "missing-vtor"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8")
            Diagnostic = "requires __VTOR_PRESENT == 1"
            Main = ($mainHeader -replace '__VTOR_PRESENT 1U', '__VTOR_PRESENT 0U')
        },
        [pscustomobject]@{
            Name = "wrong-cmsis-core"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8")
            Diagnostic = "manifest requires CMSIS __CORTEX_M == 33"
            Main = ($mainHeader -replace 'core_cm33.h', 'core_cm23.h')
        },
        [pscustomobject]@{
            Name = "wrong-architecture"
            CompilerArgs = @("-mcpu=cortex-m23", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8", "-DFIBER_PORT_SELECTION_ALLOW_MISMATCH=1")
            Diagnostic = "requires an ARMv8-M Mainline compiler target"
            Main = ($mainHeader -replace 'core_cm33.h', 'core_cm23.h')
        },
        [pscustomobject]@{
            Name = "secure-cmse"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft", "-mcmse")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8")
            Diagnostic = "selected profile excludes Secure CMSE builds"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "fpu-used"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8", "-DFIBER_TEST_FPU_USED=1")
            Diagnostic = "requires __FPU_USED == 0"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "mve"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8", "-D__ARM_FEATURE_MVE=1")
            Diagnostic = "does not permit MVE"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "pac-default"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8", "-D__ARM_FEATURE_PAC_DEFAULT=0")
            Diagnostic = "does not permit PAC"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "pac-auth"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8", "-D__ARM_FEATURE_PAUTH=1")
            Diagnostic = "does not permit PAC"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "pac-auth-default"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8", "-D__ARM_FEATURE_PAUTH_DEFAULT=0")
            Diagnostic = "does not permit PAC"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "bti-default"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8", "-D__ARM_FEATURE_BTI_DEFAULT=0")
            Diagnostic = "does not permit BTI"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "bti"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8", "-D__ARM_FEATURE_BTI=1")
            Diagnostic = "does not permit BTI"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "invalid-region-count"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=12")
            Diagnostic = "supports exactly 8 or 16 MPU regions"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "runtime-selectable-override"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8", "-DFIBER_PORT_RUNTIME_SELECTABLE=1")
            Diagnostic = "runtime-selectable state must not be predefined"
            Main = $mainHeader
        }
    )
    foreach ($case in $negativeCases) {
        $caseDir = Join-Path $probeDir $case.Name
        New-Item -ItemType Directory -Path $caseDir | Out-Null
        Set-Content -LiteralPath (Join-Path $caseDir "main.h") `
            -Value $case.Main -Encoding ASCII
        $log = Join-Path $caseDir "compile.log"
        $arguments = @($case.CompilerArgs + @(
            "-std=c11", "-ffreestanding", "-fno-builtin", "-fno-common",
            "-Wall", "-Wextra", "-Wundef", "-Werror=undef",
            "-I$caseDir", "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot", "-I$CmsisPath") +
            $case.Defines + @(
            "-c", $fixture, "-o", (Join-Path $caseDir "invalid.o")))
        $result = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $arguments -LogPath $log
        if (($result.ExitCode -eq 0) -or
                ($result.Output.IndexOf($case.Diagnostic,
                [System.StringComparison]::Ordinal) -lt 0)) {
            throw "Invalid ARM_CM33_MPU manifest failed for the wrong reason: $($case.Name)`n$($result.Output)"
        }
    }
}

function Test-ArmCm33MpuFirstStartContract {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Objdump,
        [string]$Objcopy,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot `
        "fiber\port\ARM_CM33_MPU\non_secure"
    $runtimeSource = Join-Path $profileDir "fiber_port.c"
    $bootSource = Join-Path $profileDir "fiber_port_boot.c"
    $privateHeader = Join-Path $profileDir "fiber_port_private.h"
    $linkerContract = Join-Path $profileDir "fiber_port_linker_contract.ld"
    $fixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm33_mpu_first_start_probe.c"
    $fixtureLinker = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm33_mpu_first_start.ld"
    $competing = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm33_mpu_competing_svc.c"

    foreach ($required in @($runtimeSource, $bootSource, $privateHeader,
            $linkerContract, $fixture, $fixtureLinker, $competing)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "ARM_CM33_MPU first-start slice is missing: $required"
        }
    }

    $runtimeText = Get-Content -LiteralPath $runtimeSource -Raw
    foreach ($requiredText in @(
            "FIBER_PORT_CONTEXT_COHORT_DEFINE();",
            "fiber_port_prepare_first_start",
            "fiber_port_svc_dispatch",
            "fiber_port_mpu_program_global_image_while_disabled",
            "fiber_port_mpu_validate_active_initial_context",
            "fiber_port_start_first_context",
            "fiber_port_restore_first_context_from_svc",
            "fiber_port_restore_first_context_from_svc(current, exc_return);",
            "fiber_port_unprivileged_task_return",
            "void SVC_Handler(void)",
            "fiber_portSVC_START",
            "fiber_portSVC_RETURN",
            "fiber_portMPU_MAIR0_REG",
            "fiber_portMPU_CTRL_REQUIRED")) {
        if ($runtimeText.IndexOf($requiredText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33_MPU first-start source lost required mechanism: $requiredText"
        }
    }
    foreach ($forbiddenText in @(
            "void PendSV_Handler(",
            "fiber_port_runtime_",
            "fiber_runtime_port_abi.h",
            "fiber_internal_runtime_select_scheduler_candidate",
            "fiber_internal_runtime_publish_current_context")) {
        if ($runtimeText.IndexOf($forbiddenText,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM33_MPU first-start slice acquired forbidden ownership: $forbiddenText"
        }
    }

    $privateText = Get-Content -LiteralPath $privateHeader -Raw
    foreach ($forbiddenInclude in @(
            "fiber_port_runtime_abi.h",
            "fiber_runtime_port_abi.h")) {
        if ($privateText.IndexOf($forbiddenInclude,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM33_MPU private first-start boundary acquired runtime ABI: $forbiddenInclude"
        }
    }

    foreach ($selector in @(
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h"))) {
        if ((Get-Content -LiteralPath $selector -Raw).IndexOf(
                "ARM_CM33_MPU", [System.StringComparison]::Ordinal) -ge 0) {
            throw "Staged ARM_CM33_MPU first-start profile entered global selection: $selector"
        }
    }

    $probeDir = Join-Path $BuildRoot "arm-cm33-mpu-first-start"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5,
    DebugMonitor_IRQn = -4, PendSV_IRQn = -2,
    SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm33.h"
#endif
"@
    $warningArgs = @(
        "-ffreestanding", "-fno-builtin", "-fno-common",
        "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra",
        "-Werror", "-Wundef", "-Werror=undef",
        "-Werror=implicit-function-declaration", "-Werror=return-type")
    $requiredRuntimeSymbols = @(
        "fiber_port_prepare_first_start",
        "fiber_port_svc_dispatch",
        "fiber_port_start_first_context",
        "fiber_port_restore_first_context_from_svc",
        "fiber_port_unprivileged_task_return",
        "SVC_Handler")

    foreach ($regions in @(8, 16)) {
        $variantDir = Join-Path $probeDir "regions-$regions"
        New-Item -ItemType Directory -Path $variantDir | Out-Null
        Set-Content -LiteralPath (Join-Path $variantDir "main.h") `
            -Value $mainHeader -Encoding ASCII
        $defines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV8M_MAINLINE=1",
            "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=$regions")
        $includes = @(
            "-I$variantDir", "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot", "-I$CmsisPath")

        foreach ($modeSpec in @(
                [pscustomobject]@{ Name = "o2"; Optimization = "-O2"; Lto = 0 },
                [pscustomobject]@{ Name = "os"; Optimization = "-Os"; Lto = 0 },
                [pscustomobject]@{ Name = "o2-lto"; Optimization = "-O2"; Lto = 1 })) {
            $mode = $modeSpec.Name
            $ltoArgs = if ($modeSpec.Lto -ne 0) { @("-flto") } else { @() }
            $baseArgs = @(
                "-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft",
                "-std=gnu11", $modeSpec.Optimization) + $ltoArgs +
                $warningArgs + $defines + $includes
            $runtimeObject = Join-Path $variantDir "fiber_port-$mode.o"
            $bootObject = Join-Path $variantDir "fiber_port_boot-$mode.o"
            $fixtureObject = Join-Path $variantDir "probe-$mode.o"
            & $Compiler @($baseArgs + @("-save-temps=obj", "-c",
                $runtimeSource, "-o", $runtimeObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU first-start source failed compile ($regions/$mode)"
            }
            & $Compiler @($baseArgs + @("-c", $bootSource, "-o", $bootObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU first-start boot source failed compile ($regions/$mode)"
            }
            & $Compiler @($baseArgs + @("-c", $fixture, "-o", $fixtureObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU first-start fixture failed compile ($regions/$mode)"
            }

            $objectNm = if ($modeSpec.Lto -ne 0) { $GccNm } else { $Nm }
            $runtimeDefined = @(& $objectNm -g --defined-only $runtimeObject)
            foreach ($symbol in $requiredRuntimeSymbols) {
                if (-not ($runtimeDefined -match
                        "\bT\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM33_MPU first-start object lost strong symbol: $symbol / $regions/$mode"
                }
            }
            if ($runtimeDefined -match '\bPendSV_Handler$|\bfiber_port_runtime_') {
                throw "ARM_CM33_MPU first-start object exposed unowned runtime symbol: $regions/$mode"
            }

            if ($modeSpec.Lto -eq 0) {
                $runtimeSymbols = (& $Objdump -t $runtimeObject) -join "`n"
                foreach ($symbol in @(
                        "fiber_port_prepare_first_start",
                        "fiber_port_svc_dispatch",
                        "fiber_port_start_first_context",
                        "fiber_port_restore_first_context_from_svc",
                        "SVC_Handler")) {
                    if ($runtimeSymbols -notmatch
                            "(?m)\bF\s+\.fiber_port_privileged_functions\s+[0-9a-fA-F]+\s+$([regex]::Escape($symbol))$") {
                        throw "ARM_CM33_MPU first-start escaped privileged section: $symbol / $regions/$mode"
                    }
                }
                if ($runtimeSymbols -notmatch
                        "(?m)\bF\s+\.fiber_port_syscalls\s+[0-9a-fA-F]+\s+fiber_port_unprivileged_task_return$") {
                    throw "ARM_CM33_MPU task-return veneer escaped syscall flash: $regions/$mode"
                }
                $runtimeDisassembly = (& $Objdump -dr $runtimeObject) -join "`n"
                foreach ($requiredPattern in @(
                        '(?im)\bsvc\s+70\b',
                        '(?im)\bsvc\s+72\b',
                        '(?im)0xe000ed08', '(?im)0xe000ed94',
                        '(?im)0xe000ed98', '(?im)0xe000ed9c',
                        '(?im)0xe000edc0', '(?im)\bmsr\s+psp',
                        '(?im)\bmsr\s+psplim', '(?im)\bmsr\s+control',
                        '(?im)\bmsr\s+basepri', '(?im)\bmov\s+lr,\s*r1',
                        '(?im)\bmvn(?:\.w)?\s+r5,\s*#71',
                        '(?im)\bcmp\s+lr,\s*r5',
                        '(?im)\bldmia(?:\.w)?\s+r0!',
                        '(?im)\bstmia(?:\.w)?\s+r2', '(?im)\bbx\s+lr')) {
                    if ($runtimeDisassembly -notmatch $requiredPattern) {
                        throw "ARM_CM33_MPU first-start generated assembly lost $requiredPattern / $regions/$mode"
                    }
                }
                if ($runtimeDisassembly -match '(?im)\bPendSV_Handler\b') {
                    throw "ARM_CM33_MPU first-start generated assembly acquired PendSV: $regions/$mode"
                }
            }

            $elf = Join-Path $variantDir "first-start-$mode.elf"
            & $Compiler @($baseArgs + @(
                "-nostdlib", "-Wl,--gc-sections",
                "-Wl,-T,$fixtureLinker", "-Wl,-T,$linkerContract",
                $runtimeObject, $bootObject, $fixtureObject, "-o", $elf))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU first-start synthetic ELF failed link ($regions/$mode)"
            }
            $elfDefined = @(& $objectNm -g --defined-only $elf)
            foreach ($symbol in @($requiredRuntimeSymbols + @(
                    "fiber_arm_cm33_mpu_first_start_probe"))) {
                if (-not ($elfDefined -match
                        "\bT\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM33_MPU first-start ELF lost symbol: $symbol / $regions/$mode"
                }
            }
            if ($elfDefined -match '\bPendSV_Handler$') {
                throw "ARM_CM33_MPU first-start ELF must not own PendSV: $regions/$mode"
            }
            $svcSymbols = @($elfDefined | Where-Object {
                $_ -match '^([0-9a-fA-F]+)\s+T\s+SVC_Handler$'
            })
            if ($svcSymbols.Count -ne 1) {
                throw "ARM_CM33_MPU first-start ELF must retain one strong SVC_Handler: $regions/$mode"
            }
            [void]($svcSymbols[0] -match '^([0-9a-fA-F]+)')
            $svcAddress = [Convert]::ToUInt32($Matches[1], 16)
            $vectorBinary = Join-Path $variantDir "vectors-$mode.bin"
            & $Objcopy -O binary --only-section=.fiber_test_vectors $elf $vectorBinary
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU first-start vector extraction failed: $regions/$mode"
            }
            $vectorBytes = [IO.File]::ReadAllBytes($vectorBinary)
            if ($vectorBytes.Length -lt (16 * 4)) {
                throw "ARM_CM33_MPU first-start vector fixture is truncated: $regions/$mode"
            }
            if ([BitConverter]::ToUInt32($vectorBytes, 11 * 4) -ne
                    ($svcAddress -bor [uint32]1)) {
                throw "ARM_CM33_MPU first-start vector slot 11 lost SVC_Handler: $regions/$mode"
            }

            $competingObject = Join-Path $variantDir "competing-$mode.o"
            & $Compiler @($baseArgs + @("-c", $competing, "-o", $competingObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU competing-SVC fixture failed compile ($regions/$mode)"
            }
            $duplicateLog = Join-Path $variantDir "duplicate-$mode.log"
            $duplicate = Invoke-CompilerProbe -Compiler $Compiler -Arguments `
                @($baseArgs + @(
                    "-nostdlib", "-Wl,--gc-sections",
                    "-Wl,-T,$fixtureLinker", "-Wl,-T,$linkerContract",
                    $runtimeObject, $bootObject, $fixtureObject, $competingObject,
                    "-o", (Join-Path $variantDir "duplicate-$mode.elf"))) `
                -LogPath $duplicateLog
            if (($duplicate.ExitCode -eq 0) -or
                    ($duplicate.Output -notmatch '(?s)multiple definition.*SVC_Handler')) {
                throw "ARM_CM33_MPU competing strong SVC handlers must fail link ($regions/$mode)`n$($duplicate.Output)"
            }
        }
    }
}

function Test-ArmCm33MpuConstructionContract {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Objdump,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot `
        "fiber\port\ARM_CM33_MPU\non_secure"
    $bootSource = Join-Path $profileDir "fiber_port_boot.c"
    $bootHeader = Join-Path $profileDir "fiber_port_boot.h"
    $linkerContract = Join-Path $profileDir "fiber_port_linker_contract.ld"
    $fixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm33_mpu_boot_probe.c"
    $fixtureLinker = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm33_mpu_boot.ld"

    foreach ($required in @($bootSource, $bootHeader, $linkerContract,
            $fixture, $fixtureLinker)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "ARM_CM33_MPU construction slice is missing: $required"
        }
    }
    foreach ($forbiddenArtifact in @(
            "fiber_port_exception.c",
            "fiber_port_mpu_abi.h",
            "fiber_port_mpu_abi.c",
            "fiber_port_secure_context.c")) {
        if (Test-Path -LiteralPath (Join-Path $profileDir $forbiddenArtifact)) {
            throw "ARM_CM33_MPU construction slice exposed runtime artifact: $forbiddenArtifact"
        }
    }

    $bootText = Get-Content -LiteralPath $bootSource -Raw
    foreach ($requiredText in @(
            "FIBER_PORT_CONTEXT_COHORT_RETAIN();",
            "fiber_portMPU_STACK_REGION_NUMBER",
            "fiber_portMPU_CONTEXT_STACK_INDEX",
            "fiber_portMPU_CONTEXT_FIRST_CONFIGURABLE_INDEX",
            "fiber_port_mpu_try_encode_exact_region",
            "fiber_port_mpu_build_global_regions",
            "fiber_port_context_compute_seal",
            "fiber_port_context_seal_check",
            "fiber_port_context_validate_initial_restore",
            "fiber_port_unprivileged_task_return",
            "end - 1u")) {
        if ($bootText.IndexOf($requiredText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33_MPU construction lost invariant: $requiredText"
        }
    }
    foreach ($forbiddenText in @(
            "void SVC_Handler(",
            "void PendSV_Handler(",
            "fiber_port_runtime_",
            "fiber_internal_runtime_")) {
        if ($bootText.IndexOf($forbiddenText,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM33_MPU construction acquired runtime ownership: $forbiddenText"
        }
    }

    $boundarySymbols = @(
        "__fiber_mpu_privileged_flash_start__",
        "__fiber_mpu_privileged_flash_end__",
        "__fiber_mpu_unprivileged_flash_start__",
        "__fiber_mpu_unprivileged_flash_end__",
        "__fiber_mpu_unprivileged_syscalls_start__",
        "__fiber_mpu_unprivileged_syscalls_end__",
        "__fiber_mpu_privileged_sram_start__",
        "__fiber_mpu_privileged_sram_end__",
        "__fiber_mpu_current_context_slot_start__",
        "__fiber_mpu_current_context_slot_end__",
        "__fiber_mpu_unprivileged_ram_start__",
        "__fiber_mpu_unprivileged_ram_end__"
    )
    $linkerText = Get-Content -LiteralPath $linkerContract -Raw
    foreach ($boundary in $boundarySymbols) {
        if ($linkerText.IndexOf($boundary,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33_MPU linker contract lost boundary: $boundary"
        }
    }
    foreach ($requiredLinkerText in @(
            "SIZEOF(.fiber_current_context_slot) == 4",
            "current slot must remain in privileged SRAM",
            "protected port code escaped privileged flash",
            "syscall veneer escaped syscall flash",
            "protected data escaped privileged SRAM",
            "privileged and unprivileged flash overlap",
            "syscall flash and privileged SRAM overlap")) {
        if ($linkerText.IndexOf($requiredLinkerText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33_MPU linker contract lost isolation check: $requiredLinkerText"
        }
    }

    $probeDir = Join-Path $BuildRoot "arm-cm33-mpu-construction"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5,
    DebugMonitor_IRQn = -4, PendSV_IRQn = -2,
    SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm33.h"
#endif
"@

    $warningArgs = @(
        "-ffreestanding",
        "-fno-builtin",
        "-fno-common",
        "-ffunction-sections",
        "-fdata-sections",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wundef",
        "-Werror=undef",
        "-Werror=implicit-function-declaration",
        "-Werror=return-type"
    )
    $requiredBootSymbols = @(
        "fiber_port_context_init",
        "fiber_port_mpu_load_linker_layout",
        "fiber_port_mpu_linker_layout_check",
        "fiber_port_mpu_try_encode_exact_region",
        "fiber_port_mpu_build_global_regions",
        "fiber_port_context_compute_seal",
        "fiber_port_context_seal_check",
        "fiber_port_context_validate_initial_restore"
    )

    foreach ($regions in @(8, 16)) {
        $variantDir = Join-Path $probeDir "regions-$regions"
        New-Item -ItemType Directory -Path $variantDir | Out-Null
        Set-Content -LiteralPath (Join-Path $variantDir "main.h") `
            -Value $mainHeader -Encoding ASCII
        $defines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV8M_MAINLINE=1",
            "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=$regions"
        )
        $includes = @(
            "-I$variantDir",
            "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot",
            "-I$CmsisPath"
        )

        foreach ($modeSpec in @(
                [pscustomobject]@{ Name = "o2"; Optimization = "-O2"; Lto = 0 },
                [pscustomobject]@{ Name = "os"; Optimization = "-Os"; Lto = 0 },
                [pscustomobject]@{ Name = "o2-lto"; Optimization = "-O2"; Lto = 1 })) {
            $optimization = $modeSpec.Optimization
            $mode = $modeSpec.Name
            $ltoArgs = if ($modeSpec.Lto -ne 0) { @("-flto") } else { @() }
            $baseArgs = @(
                "-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft",
                "-std=gnu11", $optimization) + $ltoArgs + $warningArgs + $defines +
                $includes
            $bootObject = Join-Path $variantDir "fiber_port_boot-$mode.o"
            $bootAssembly = [IO.Path]::ChangeExtension($bootObject, ".s")
            & $Compiler @($baseArgs + @("-save-temps=obj", "-c",
                $bootSource, "-o", $bootObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU construction source failed compile ($regions/$mode)"
            }

            # gcc-nm loads the GCC LTO plugin, unlike binutils nm. The
            # construction proof deliberately covers normal ELF objects and
            # LTO bytecode objects with the same ABI surface checks.
            $bootDefined = @(& $GccNm -g --defined-only $bootObject)
            foreach ($symbol in $requiredBootSymbols) {
                if (-not ($bootDefined -match
                        "\bT\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM33_MPU construction lost strong symbol: $symbol / $regions/$mode"
                }
            }
            foreach ($line in $bootDefined) {
                if ($line -match '\b(?:SVC_Handler|PendSV_Handler|fiber_port_runtime_)') {
                    throw "ARM_CM33_MPU construction object emitted runtime symbol: $line"
                }
            }
            $bootUndefined = @(& $GccNm -u $bootObject | ForEach-Object {
                if ($_ -match '\bU\s+(\S+)$') { $Matches[1] }
            })
            foreach ($boundary in $boundarySymbols) {
                if ($bootUndefined -notcontains $boundary) {
                    throw "ARM_CM33_MPU construction lost linker relocation: $boundary / $regions/$mode"
                }
            }
            foreach ($requiredUndefined in @(
                    "fiber_panic",
                    "fiber_port_unprivileged_task_return")) {
                if ($bootUndefined -notcontains $requiredUndefined) {
                    throw "ARM_CM33_MPU construction lost dependency: $requiredUndefined / $regions/$mode"
                }
            }
            $cohorts = @($bootUndefined | Where-Object {
                $_ -match '^fiber_port_context_cohort_'
            })
            if ($cohorts.Count -ne 1) {
                throw "ARM_CM33_MPU construction must retain one exact cohort: $regions/$mode"
            }
            $allowedUndefined = @($boundarySymbols + @(
                    "fiber_panic",
                    "fiber_port_unprivileged_task_return",
                    $cohorts[0])) | Sort-Object
            $actualUndefined = @($bootUndefined | Sort-Object)
            if (($allowedUndefined.Count -ne $actualUndefined.Count) -or
                    (Compare-Object -ReferenceObject $allowedUndefined `
                        -DifferenceObject $actualUndefined)) {
                throw "ARM_CM33_MPU construction dependency surface changed: $regions/$mode`nExpected: $($allowedUndefined -join ', ')`nActual: $($actualUndefined -join ', ')"
            }

            if ($modeSpec.Lto -eq 0) {
                $bootSymbolTable = @(& $Objdump -t $bootObject)
                foreach ($symbol in $requiredBootSymbols) {
                    $sectionMatch = @($bootSymbolTable | Where-Object {
                        $_ -match "\bF\s+\.fiber_port_privileged_functions\s+[0-9a-fA-F]+\s+$([regex]::Escape($symbol))$"
                    })
                    if ($sectionMatch.Count -ne 1) {
                        throw "ARM_CM33_MPU construction escaped privileged section: $symbol / $regions/$mode"
                    }
                }
                $bootDisassembly = (& $Objdump -dr $bootObject) -join "`n"
                if (($bootDisassembly -match '(?im)\bsvc\b') -or
                        ($bootDisassembly -match '(?im)\bmsr\b') -or
                        ($bootDisassembly -match '(?im)0xe000ed(?:90|94|98|9c|a0)')) {
                    throw "ARM_CM33_MPU construction unexpectedly touched runtime MPU/SVC state: $regions/$mode"
                }
            }

            $fixtureObject = Join-Path $variantDir "probe-$mode.o"
            & $Compiler @($baseArgs + @("-c", $fixture, "-o", $fixtureObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU construction fixture failed compile ($regions/$mode)"
            }
            $elf = Join-Path $variantDir "construction-$mode.elf"
            & $Compiler @($baseArgs + @(
                "-nostdlib", "-Wl,--gc-sections",
                "-Wl,-T,$fixtureLinker", "-Wl,-T,$linkerContract",
                $bootObject, $fixtureObject, "-o", $elf))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM33_MPU construction/linker proof failed ($regions/$mode)"
            }
            $elfDefined = @(& $Nm -g --defined-only $elf)
            foreach ($symbol in @($requiredBootSymbols + @(
                    "fiber_arm_cm33_mpu_boot_probe",
                    "fiber_port_unprivileged_task_return"))) {
                if (-not ($elfDefined -match
                        "\bT\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM33_MPU synthetic ELF lost symbol: $symbol / $regions/$mode"
                }
            }
            if ($elfDefined -match '\b(?:SVC_Handler|PendSV_Handler)$') {
                throw "ARM_CM33_MPU construction ELF unexpectedly owns handlers: $regions/$mode"
            }
            $elfSymbolTable = @(& $Objdump -t $elf)
            foreach ($symbol in $requiredBootSymbols) {
                $sectionMatch = @($elfSymbolTable | Where-Object {
                    $_ -match "\bF\s+\.fiber_port_privileged_code\s+[0-9a-fA-F]+\s+$([regex]::Escape($symbol))$"
                })
                if ($sectionMatch.Count -ne 1) {
                    throw "ARM_CM33_MPU construction ELF escaped privileged section: $symbol / $regions/$mode"
                }
            }
            $elfDisassembly = (& $Objdump -d $elf) -join "`n"
            if (($elfDisassembly -match '(?im)\bsvc\b') -or
                    ($elfDisassembly -match '(?im)\bmsr\b') -or
                    ($elfDisassembly -match '(?im)0xe000ed(?:90|94|98|9c|a0)')) {
                throw "ARM_CM33_MPU construction ELF unexpectedly touched runtime MPU/SVC state: $regions/$mode"
            }
            $elfSections = (& $Objdump -h $elf) -join "`n"
            foreach ($section in @(
                    ".fiber_port_privileged_code",
                    ".fiber_port_unprivileged_code",
                    ".fiber_port_syscalls",
                    ".fiber_current_context_slot",
                    ".fiber_port_privileged_data",
                    ".fiber_port_unprivileged_ram")) {
                if ($elfSections.IndexOf($section,
                        [System.StringComparison]::Ordinal) -lt 0) {
                    throw "ARM_CM33_MPU synthetic ELF lost required section: $section / $regions/$mode"
                }
            }

            $brokenLinker = Join-Path $variantDir "missing-syscalls-$mode.ld"
            $brokenText = (Get-Content -LiteralPath $fixtureLinker -Raw).
                Replace("__fiber_mpu_unprivileged_syscalls_end__ = 0x08021000;", "")
            Set-Content -LiteralPath $brokenLinker -Value $brokenText -Encoding ASCII
            $negativeLog = Join-Path $variantDir "missing-syscalls-$mode.log"
            $negative = Invoke-CompilerProbe -Compiler $Compiler -Arguments `
                @($baseArgs + @(
                    "-nostdlib", "-Wl,--gc-sections",
                    "-Wl,-T,$brokenLinker", "-Wl,-T,$linkerContract",
                    $bootObject, $fixtureObject, "-o",
                    (Join-Path $variantDir "missing-syscalls-$mode.elf"))) `
                -LogPath $negativeLog
            if (($negative.ExitCode -eq 0) -or
                    ($negative.Output.IndexOf("missing syscall-flash end",
                        [System.StringComparison]::Ordinal) -lt 0)) {
                throw "ARM_CM33_MPU linker contract did not reject a missing syscall boundary: $regions/$mode`n$($negative.Output)"
            }
        }
    }
}

function Test-ArmCm33NtzRuntimeContract {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Objdump,
        [string]$Ar,
        [string]$Objcopy,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot `
        "fiber\port\ARM_CM33_NTZ\non_secure"
    $fixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm33_ntz_layout_probe.c"
    foreach ($required in @(
            (Join-Path $profileDir "fiber_port_types.h"),
            (Join-Path $profileDir "fiber_port_boot_types.h"),
            (Join-Path $profileDir "fiber_portmacro.h"),
            (Join-Path $profileDir "fiber_port_boot.h"),
            (Join-Path $profileDir "fiber_port_private.h"),
            (Join-Path $profileDir "fiber_port.c"),
            (Join-Path $profileDir "fiber_port_boot.c"),
            (Join-Path $profileDir "FREERTOS_PARITY.md"),
            $fixture)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "ARM_CM33_NTZ runtime slice is missing: $required"
        }
    }

    foreach ($forbiddenRuntime in @(
            "fiber_port_exception.c",
            "fiber_portasm.c",
            "fiber_port_mpu.c",
            "fiber_port_secure_context.c")) {
        if (Test-Path -LiteralPath (Join-Path $profileDir $forbiddenRuntime)) {
            throw "ARM_CM33_NTZ runtime slice must not expose unsupported artifact: $forbiddenRuntime"
        }
    }

    $selectors = @(
        (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
        (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h")
    )
    foreach ($selector in $selectors) {
        if ((Get-Content -LiteralPath $selector -Raw).IndexOf(
                "ARM_CM33_NTZ", [System.StringComparison]::Ordinal) -ge 0) {
            throw "Staged ARM_CM33_NTZ profile entered global selection: $selector"
        }
    }

    $typeText = Get-Content -LiteralPath `
        (Join-Path $profileDir "fiber_port_types.h") -Raw
    foreach ($forbiddenTypeDependency in @(
            "mcu_core.h",
            "fiber_compiler.h",
            "fiber_portmacro.h",
            "fiber_port_select.h")) {
        $includePattern = '(?m)^\s*#\s*include\s*["<][^">]*' +
            [regex]::Escape($forbiddenTypeDependency) + '[">]'
        if ([regex]::IsMatch($typeText, $includePattern)) {
            throw "ARM_CM33_NTZ public storage acquired CPU dependency: $forbiddenTypeDependency"
        }
    }

    $parity = Get-Content -LiteralPath `
        (Join-Path $profileDir "FREERTOS_PARITY.md") -Raw
    foreach ($requiredParity in @(
            "a50edad08b29052631aa469d4df6e6ec7ff68878",
            "BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A",
            "F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B",
            "324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2",
            "DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5",
            "00B42952962E48F8C9421F5EC66BBCE9E02465760560728FEE2D743CE1706F3E",
            "live `PSPLIM` value",
            "ten-word software frame",
            "sealed boot record",
            "fiber_port_context_init()",
            "fiber_port_init_context_frame()",
            "First-Start Assembly Parity",
            "0xFFFFFFB8",
            "ldmia saved_sp!, {r2-r11}",
            "msr PSPLIM, r2",
            "mrs CONTROL; orr #2; msr CONTROL",
            "movs #2; msr CONTROL",
            "msr PSP, hardware_frame",
            "Generated-disassembly proof is mandatory",
            "mpu_wrappers_v2_asm.c")) {
        if ($parity.IndexOf($requiredParity,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33_NTZ parity ledger lost reference evidence: $requiredParity"
        }
    }

    $probeDir = Join-Path $BuildRoot "arm-cm33-ntz-layout"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 3U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
#ifndef FIBER_TEST_FPU_USED
#define FIBER_TEST_FPU_USED 0U
#endif
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    SVCall_IRQn = -5, PendSV_IRQn = -2, SysTick_IRQn = -1,
    DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm33.h"
#if FIBER_TEST_FPU_USED != 0U
#undef __FPU_USED
#define __FPU_USED FIBER_TEST_FPU_USED
#endif
#endif
"@
    Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
        -Value $mainHeader -Encoding ASCII

    $typeProbe = Join-Path $probeDir "type-only.c"
    Set-Content -LiteralPath $typeProbe -Encoding ASCII -Value @'
#include "fiber_port_types.h"
_Static_assert(sizeof(FiberPortBoot) == 72u, "boot size");
_Static_assert(sizeof(FiberContext) == 76u, "context size");
_Static_assert(_Alignof(FiberContext) == 4u, "context alignment");
FiberContext fiber_cm33_ntz_type_only_object;
'@
    $typeObject = Join-Path $probeDir "type-only.o"
    $typeArgs = @(
        "-mcpu=cortex-m33", "-mthumb", "-std=c11",
        "-ffreestanding", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
        "-I$profileDir", "-c", $typeProbe, "-o", $typeObject
    )
    & $Compiler @typeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33_NTZ type-only C header failed without CMSIS"
    }

    $cppProbe = Join-Path $probeDir "type-only.cpp"
    Set-Content -LiteralPath $cppProbe -Encoding ASCII -Value @'
#include "fiber_port_types.h"
static_assert(sizeof(FiberPortBoot) == 72u, "boot size");
static_assert(sizeof(FiberContext) == 76u, "context size");
static_assert(alignof(FiberContext) == 4u, "context alignment");
FiberContext fiber_cm33_ntz_cpp_type_only_object;
'@
    $cppObject = Join-Path $probeDir "type-only-cpp.o"
    & $Compiler -x c++ -mcpu=cortex-m33 -mthumb -std=c++17 `
        -ffreestanding -fno-builtin -Wall -Wextra -Werror `
        "-I$profileDir" -c $cppProbe -o $cppObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33_NTZ type-only C++ header failed without CMSIS"
    }

    $layoutObject = Join-Path $probeDir "layout.o"
    $manifestArgs = @(
        "-mcpu=cortex-m33", "-mthumb", "-std=c11",
        "-ffreestanding", "-fno-builtin", "-fno-common",
        "-Wall", "-Wextra", "-Wundef", "-Werror=undef",
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV8M_MAINLINE=1",
        "-I$probeDir", "-I$profileDir",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot", "-I$CmsisPath"
    )
    & $Compiler @manifestArgs -c $fixture -o $layoutObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33_NTZ exact layout manifest failed compile"
    }

    $defined = @(& $Nm -g --defined-only $layoutObject)
    if ($LASTEXITCODE -ne 0) {
        throw "nm failed for ARM_CM33_NTZ layout probe"
    }
    $cohorts = @($defined | ForEach-Object {
        if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
            $Matches[1]
        }
    })
    if ($cohorts.Count -ne 1) {
        throw "ARM_CM33_NTZ layout must define one exact cohort"
    }
    foreach ($token in @(
            "armv8m_mainline",
            "p0x4333334Eu",
            "l0x00010001u",
            "_h1_j1_v1_d1_r1_",
            "_z8u_y0_w2_g3_",
            "_i0_o0xFFFFFFBCu_c0_s1_x0_m0_a0_b0_t1_n1_k0_q0")) {
        if ($cohorts[0].IndexOf($token,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33_NTZ exact cohort lost token ${token}: $($cohorts[0])"
        }
    }

    $frameSourcePath = Join-Path $profileDir "fiber_port.c"
    $bootSourcePath = Join-Path $profileDir "fiber_port_boot.c"
    $privateHeaderPath = Join-Path $profileDir "fiber_port_private.h"
    $macroHeaderPath = Join-Path $profileDir "fiber_portmacro.h"
    $frameSource = Get-Content -LiteralPath $frameSourcePath -Raw
    $bootSource = Get-Content -LiteralPath $bootSourcePath -Raw
    $privateHeader = Get-Content -LiteralPath $privateHeaderPath -Raw
    $macroHeader = Get-Content -LiteralPath $macroHeaderPath -Raw

    foreach ($requiredRuntimeToken in @(
            "void SVC_Handler(void)",
            "void PendSV_Handler(void)",
            "fiber_portSVC_ORIGIN_EXC_RETURN",
            "fiber_port_context_validate_restore",
            "fiber_port_context_validate_save_current",
            "fiber_port_runtime_prepare_start",
            "fiber_port_runtime_select_first",
            "fiber_port_runtime_start_first",
            "fiber_port_runtime_schedule",
            "fiber_port_scheduler_pick_first_from_start",
            "fiber_port_scheduler_pick_next_from_pendsv",
            "fiber_internal_runtime_select_scheduler_candidate(NULL)",
            "fiber_internal_runtime_select_scheduler_candidate(current)",
            "fiber_internal_runtime_publish_current_context(next)",
            "fiber_internal_runtime_require_current_context()",
            "fiber_port_scheduler_critical_enter()",
            "FIBER_REQUIRE(fiber_port_basepri_read() ==",
            "fiber_port_validate_svc_vector()",
            "fiber_port_validate_pendsv_vector()",
            "fiber_port_validate_basepri_priority_policy()",
            "fiber_portNVIC_PENDSVSET_BIT",
            "stmdb r0!, {r2-r11}",
            "ldmia r0!, {r2-r11}",
            "msr   psplim, r2",
            "mrs   r1, psplim",
            "msr   control, r1",
            "msr   psp, r0",
            "bx    r3")) {
        if (($frameSource.IndexOf($requiredRuntimeToken,
                    [System.StringComparison]::Ordinal) -lt 0) -and
                ($bootSource.IndexOf($requiredRuntimeToken,
                    [System.StringComparison]::Ordinal) -lt 0) -and
                ($privateHeader.IndexOf($requiredRuntimeToken,
                    [System.StringComparison]::Ordinal) -lt 0) -and
                ($macroHeader.IndexOf($requiredRuntimeToken,
                    [System.StringComparison]::Ordinal) -lt 0)) {
            throw "ARM_CM33_NTZ runtime source lost contract: $requiredRuntimeToken"
        }
    }

    $frameBody = Get-CFunctionBody -Source $frameSource `
        -Signature "void fiber_port_init_context_frame(FiberContext *const ctx)" `
        -Path $frameSourcePath
    foreach ($assignment in @(
            "frame[fiber_portFRAME_PSPLIM] = (uint32_t)ctx->boot.stack_base;",
            "frame[fiber_portFRAME_EXC_RETURN] = fiber_portINITIAL_EXC_RETURN;",
            "frame[fiber_portFRAME_R4] = 0u;",
            "frame[fiber_portFRAME_R5] = 0u;",
            "frame[fiber_portFRAME_R6] = 0u;",
            "frame[fiber_portFRAME_R7] = 0u;",
            "frame[fiber_portFRAME_R8] = 0u;",
            "frame[fiber_portFRAME_R9] = fiber_port_read_r9();",
            "frame[fiber_portFRAME_R10] = 0u;",
            "frame[fiber_portFRAME_R11] = 0u;",
            "frame[fiber_portFRAME_R0] = (uint32_t)(uintptr_t)ctx->boot.arg;",
            "frame[fiber_portFRAME_R1] = 0u;",
            "frame[fiber_portFRAME_R2] = 0u;",
            "frame[fiber_portFRAME_R3] = 0u;",
            "frame[fiber_portFRAME_R12] = 0u;",
            "frame[fiber_portFRAME_LR] =",
            "frame[fiber_portFRAME_PC] =",
            "frame[fiber_portFRAME_XPSR] = fiber_port_initial_xpsr();")) {
        if ($frameBody.IndexOf($assignment,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33_NTZ initial frame lost required assignment: $assignment"
        }
    }
    $lastAssignment = -1
    foreach ($assignment in @(
            "fiber_portFRAME_PSPLIM] =",
            "fiber_portFRAME_EXC_RETURN] =",
            "fiber_portFRAME_R4] =",
            "fiber_portFRAME_R5] =",
            "fiber_portFRAME_R6] =",
            "fiber_portFRAME_R7] =",
            "fiber_portFRAME_R8] =",
            "fiber_portFRAME_R9] =",
            "fiber_portFRAME_R10] =",
            "fiber_portFRAME_R11] =",
            "fiber_portFRAME_R0] =",
            "fiber_portFRAME_R1] =",
            "fiber_portFRAME_R2] =",
            "fiber_portFRAME_R3] =",
            "fiber_portFRAME_R12] =",
            "fiber_portFRAME_LR] =",
            "fiber_portFRAME_PC] =",
            "fiber_portFRAME_XPSR] =")) {
        $assignmentIndex = $frameBody.IndexOf($assignment,
            [System.StringComparison]::Ordinal)
        if ($assignmentIndex -le $lastAssignment) {
            throw "ARM_CM33_NTZ initial frame lost exact assignment order: $assignment"
        }
        $lastAssignment = $assignmentIndex
    }
    if (([regex]::Matches($frameBody,
            'frame\[fiber_portFRAME_[A-Z0-9_]+\]\s*=')).Count -ne 18) {
        throw "ARM_CM33_NTZ constructor must assign exactly eighteen frame words"
    }
    foreach ($requiredConstructionToken in @(
            "FIBER_PORT_CONTEXT_COHORT_DEFINE();",
            "fiber_port_boot_record_check(&ctx->boot);",
            "ctx->sp = frame;",
            "FIBER_PORT_CONTEXT_COHORT_RETAIN();",
            "ctx->boot = fiber_port_boot_create(stack_begin, stack_end, entry, arg);",
            "fiber_port_init_context_frame(ctx);",
            "fiber_port_validate_initial_frame(ctx);")) {
        if (($frameSource.IndexOf($requiredConstructionToken,
                    [System.StringComparison]::Ordinal) -lt 0) -and
                ($bootSource.IndexOf($requiredConstructionToken,
                    [System.StringComparison]::Ordinal) -lt 0)) {
            throw "ARM_CM33_NTZ construction source lost contract: $requiredConstructionToken"
        }
    }

    $frameObject = Join-Path $probeDir "frame.o"
    $bootObject = Join-Path $probeDir "boot.o"
    $constructionArgs = @($manifestArgs + @(
        "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1", "-O2",
        "-Werror", "-save-temps=obj"))
    & $Compiler @constructionArgs -c $frameSourcePath -o $frameObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33_NTZ frame construction source failed compile"
    }
    & $Compiler @constructionArgs -c $bootSourcePath -o $bootObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33_NTZ boot construction source failed compile"
    }
    $constructionGroup = Join-Path $probeDir "construction-group.o"
    & $Compiler -r $frameObject $bootObject -o $constructionGroup
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33_NTZ construction object group failed relocatable link"
    }
    $constructionDefined = @(& $Nm -g --defined-only $constructionGroup)
    if ($LASTEXITCODE -ne 0) {
        throw "nm failed for ARM_CM33_NTZ construction object group"
    }
    $expectedForwardDefinitions = @(
        "fiber_port_context_init",
        "fiber_port_runtime_memory_barrier",
        "fiber_port_panic_wait",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_runtime_schedule"
    )
    foreach ($expectedForwardDefinition in $expectedForwardDefinitions) {
        $definitions = @($constructionDefined | Where-Object {
            $_ -match ("\bT\s+" +
                [regex]::Escape($expectedForwardDefinition) + "$")
        })
        if ($definitions.Count -ne 1) {
            throw "ARM_CM33_NTZ runtime group must define one $expectedForwardDefinition"
        }
    }
    $constructionCohorts = @($constructionDefined | ForEach-Object {
        if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
            $Matches[1]
        }
    })
    if (($constructionCohorts.Count -ne 1) -or
            ($constructionCohorts[0] -ne $cohorts[0])) {
        throw "ARM_CM33_NTZ construction group disagrees with frozen layout cohort"
    }
    $svcDefinitions = @($constructionDefined | Where-Object {
        $_ -match '\bT\s+SVC_Handler$'
    })
    if ($svcDefinitions.Count -ne 1) {
        throw "ARM_CM33_NTZ runtime group must define one strong SVC_Handler"
    }
    $pendSvDefinitions = @($constructionDefined | Where-Object {
        $_ -match '\bT\s+PendSV_Handler$'
    })
    if ($pendSvDefinitions.Count -ne 1) {
        throw "ARM_CM33_NTZ runtime group must define one strong PendSV_Handler"
    }
    $constructionUndefined = @(& $Nm -u $constructionGroup | ForEach-Object {
        if ($_ -match '^\s*U\s+(\S+)$') {
            $Matches[1]
        }
    } | Sort-Object -Unique)
    $allowedConstructionUndefined = @(
        "fiber_internal_runtime_current_context_slot",
        "fiber_internal_runtime_port_abi_v1_anchor",
        "fiber_internal_runtime_publish_current_context",
        "fiber_internal_runtime_require_current_context",
        "fiber_internal_runtime_select_scheduler_candidate",
        "fiber_internal_task_return",
        "fiber_panic",
        "memcpy"
    )
    $constructionUndefinedDelta = @(Compare-Object `
        -ReferenceObject $allowedConstructionUndefined `
        -DifferenceObject $constructionUndefined)
    if ($constructionUndefinedDelta.Count -ne 0) {
        throw "ARM_CM33_NTZ runtime group must retain the exact reverse/integration dependency set: $($constructionUndefined -join ', ')"
    }

    $sourceVariants = @(
        [pscustomobject]@{
            Name = "production"
            Defines = @(
                "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0",
                "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=0")
        },
        [pscustomobject]@{
            Name = "address-map"
            Defines = @(
                "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=1",
                "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1")
        },
        [pscustomobject]@{
            Name = "no-rewind"
            Defines = @(
                "-DFIBER_REWIND_MSP=0",
                "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0",
                "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=0")
        }
    )
    foreach ($variant in $sourceVariants) {
        $variantRuntime = Join-Path $probeDir "$($variant.Name)-runtime.o"
        $variantBoot = Join-Path $probeDir "$($variant.Name)-boot.o"
        $variantGroup = Join-Path $probeDir "$($variant.Name)-group.o"
        $variantArgs = @($manifestArgs + @(
            "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1",
            "-O2", "-Werror") + $variant.Defines)
        & $Compiler @variantArgs -c $frameSourcePath -o $variantRuntime
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_NTZ $($variant.Name) runtime variant failed compile"
        }
        & $Compiler @variantArgs -c $bootSourcePath -o $variantBoot
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_NTZ $($variant.Name) boot variant failed compile"
        }
        & $Compiler -r $variantRuntime $variantBoot -o $variantGroup
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_NTZ $($variant.Name) object group failed link"
        }
    }

    $frameAssembly = [IO.Path]::ChangeExtension($frameObject, ".s")
    Test-GeneratedCurrentSlotLoadOnly -AssemblyPath $frameAssembly
    $runtimeDisassembly = (& $Objdump -dr $frameObject) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed for ARM_CM33_NTZ runtime object"
    }
    $svcBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
        -Symbol "SVC_Handler" -Path $frameObject
    $startBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
        -Symbol "fiber_port_start_first_context" -Path $frameObject
    $pendSvBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
        -Symbol "PendSV_Handler" -Path $frameObject

    $svcInstructionOrder = @(
        'mrs\s+r3,\s*IPSR',
        'cmp\s+r3,\s*#11',
        'mvn(?:\.w)?\s+r3,\s*#71',
        'cmp\s+lr,\s*r3',
        'mrs\s+r0,\s*MSP',
        'ldr\s+r2,\s*\[r0,\s*#28\]',
        'ldr\s+r3,\s*\[r0,\s*#24\]',
        'ldrb\s+r2,\s*\[r3,\s*#1\]',
        'cmp\s+r2,\s*#223',
        'ldrb\s+r3,\s*\[r3(?:,\s*#0)?\]',
        'cmp\s+r3,\s*#70',
        'cpsid\s+i',
        'msr\s+BASEPRI,\s*r0',
        'mrs\s+r1,\s*BASEPRI',
        'ldr(?:\.w)?\s+r0,\s*\[pc,',
        'ldr\s+r0,\s*\[r0(?:,\s*#0)?\]',
        'fiber_port_context_validate_restore',
        'ldmia(?:\.w)?\s+r0!,\s*\{r2,\s*r3,\s*r4,\s*r5,\s*r6,\s*r7,\s*r8,\s*(?:r9|sb),\s*sl,\s*fp\}',
        'mvn(?:\.w)?\s+r1,\s*#67',
        'cmp\s+r3,\s*r1',
        'msr\s+PSPLIM,\s*r2',
        'mrs\s+r1,\s*PSPLIM',
        'msr\s+CONTROL,\s*r1',
        'mrs\s+r1,\s*CONTROL',
        'msr\s+PSP,\s*r0',
        'mrs\s+r1,\s*PSP',
        'mrs\s+r1,\s*FAULTMASK',
        'cpsie\s+i',
        'bx\s+r3'
    )
    $remainingSvcBody = $svcBody
    foreach ($instructionPattern in $svcInstructionOrder) {
        $instructionMatch = [regex]::Match($remainingSvcBody,
            $instructionPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $instructionMatch.Success) {
            throw "ARM_CM33_NTZ generated SVC lost FreeRTOS-parity instruction order: $instructionPattern`n$svcBody"
        }
        $remainingSvcBody = $remainingSvcBody.Substring(
            $instructionMatch.Index + $instructionMatch.Length)
    }

    $startInstructionOrder = @(
        'cpsid\s+i',
        'msr\s+CONTROL,\s*r3',
        'msr\s+MSP,\s*r0',
        'msr\s+BASEPRI,\s*r0',
        'mrs\s+r3,\s*BASEPRI',
        'mrs\s+r3,\s*FAULTMASK',
        'cpsie\s+f',
        'cpsie\s+i',
        'svc\s+70'
    )
    $remainingStartBody = $startBody
    foreach ($instructionPattern in $startInstructionOrder) {
        $instructionMatch = [regex]::Match($remainingStartBody,
            $instructionPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $instructionMatch.Success) {
            throw "ARM_CM33_NTZ generated first-start helper lost FreeRTOS-parity instruction order: $instructionPattern`n$startBody"
        }
        $remainingStartBody = $remainingStartBody.Substring(
            $instructionMatch.Index + $instructionMatch.Length)
    }

    $pendSvInstructionOrder = @(
        'mrs\s+r3,\s*IPSR',
        'cmp\s+r3,\s*#14',
        'mvn(?:\.w)?\s+r3,\s*#67',
        'cmp\s+lr,\s*r3',
        'mrs\s+r0,\s*PSP',
        'fiber_port_context_validate_save_current',
        'mrs\s+r3,\s*PSPLIM',
        'stmdb\s+r0!,\s*\{r2,\s*r3,\s*r4,\s*r5,\s*r6,\s*r7,\s*r8,\s*(?:r9|sb),\s*sl,\s*fp\}',
        'str\s+r0,\s*\[r1(?:,\s*#0)?\]',
        'mrs\s+r3,\s*BASEPRI',
        'msr\s+BASEPRI,\s*r2',
        'fiber_port_scheduler_pick_next_from_pendsv',
        'msr\s+BASEPRI,\s*r3',
        'mrs\s+r1,\s*BASEPRI',
        'ldmia(?:\.w)?\s+r0!,\s*\{r2,\s*r3,\s*r4,\s*r5,\s*r6,\s*r7,\s*r8,\s*(?:r9|sb),\s*sl,\s*fp\}',
        'msr\s+PSPLIM,\s*r2',
        'mrs\s+r1,\s*PSPLIM',
        'msr\s+PSP,\s*r0',
        'mrs\s+r1,\s*PSP',
        'mrs\s+r1,\s*CONTROL',
        'mrs\s+r1,\s*PRIMASK',
        'mrs\s+r1,\s*FAULTMASK',
        'bx\s+r3'
    )
    $remainingPendSvBody = $pendSvBody
    foreach ($instructionPattern in $pendSvInstructionOrder) {
        $instructionMatch = [regex]::Match($remainingPendSvBody,
            $instructionPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $instructionMatch.Success) {
            throw "ARM_CM33_NTZ generated PendSV lost FreeRTOS-parity instruction order: $instructionPattern`n$pendSvBody"
        }
        $remainingPendSvBody = $remainingPendSvBody.Substring(
            $instructionMatch.Index + $instructionMatch.Length)
    }

    foreach ($forbiddenGeneratedSymbol in @(
            "__aeabi_",
            "__gnu_")) {
        if ($runtimeDisassembly.IndexOf($forbiddenGeneratedSymbol,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM33_NTZ generated runtime contains compiler helper: $forbiddenGeneratedSymbol"
        }
    }

    $adversarialObject = Join-Path $probeDir "adversarial-runtime.o"
    & $Compiler @($manifestArgs + @(
        "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1",
        "-O2", "-Werror", "-finstrument-functions",
        "-fstack-protector-all", "-fprofile-arcs", "-ftest-coverage",
        "-c", $frameSourcePath, "-o", $adversarialObject))
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33_NTZ adversarial runtime source failed compile"
    }
    $adversarialDisassembly = (& $Objdump -dr $adversarialObject) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed for adversarial ARM_CM33_NTZ runtime object"
    }
    Assert-SensitiveFunctionClean -Disassembly $adversarialDisassembly `
        -Symbol "SVC_Handler" -Path $adversarialObject
    Assert-SensitiveFunctionClean -Disassembly $adversarialDisassembly `
        -Symbol "fiber_port_start_first_context" -Path $adversarialObject
    Assert-SensitiveFunctionClean -Disassembly $adversarialDisassembly `
        -Symbol "PendSV_Handler" -Path $adversarialObject

    $elfFixturePath = Join-Path $probeDir "runtime-elf-fixture.c"
    $competingPath = Join-Path $probeDir "competing-handlers.c"
    $linkerPath = Join-Path $probeDir "runtime.ld"
    Set-Content -LiteralPath $elfFixturePath -Encoding ASCII -Value @'
#include <stddef.h>
#include <stdint.h>

#include "fiber_port_types.h"
#include "fiber_runtime_port_abi.h"

extern void fiber_port_runtime_prepare_start(void);
extern void SVC_Handler(void);
extern void PendSV_Handler(void);
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code);

const unsigned char fiber_internal_runtime_port_abi_v1_anchor = 1u;
FiberContext *volatile fiber_internal_runtime_current_context_slot;

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_runtime_select_scheduler_candidate(
        FiberContext *current)
{
    return current;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_current_context(void)
{
    if (fiber_internal_runtime_current_context_slot == NULL) {
        fiber_panic('C');
    }
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_publish_current_context(FiberContext *next)
{
    if (next == NULL) {
        fiber_panic('N');
    }
    fiber_internal_runtime_current_context_slot = next;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_task_return(void)
{
    for (;;) {
        __asm volatile("wfe");
    }
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    (void)code;
    for (;;) {
        __asm volatile("wfe");
    }
}

void *memcpy(void *destination, const void *source, size_t size)
{
    unsigned char *out = (unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;
    while (size-- != 0u) {
        *out++ = *in++;
    }
    return destination;
}

void *memset(void *destination, int value, size_t size)
{
    unsigned char *out = (unsigned char *)destination;
    while (size-- != 0u) {
        *out++ = (unsigned char)value;
    }
    return destination;
}

void Reset_Handler(void)
{
    fiber_port_runtime_prepare_start();
    for (;;) {
        __asm volatile("wfe");
    }
}

typedef void (*FiberVector)(void);
__attribute__((used, section(".isr_vector")))
const FiberVector fiber_vectors[16] = {
    [1] = Reset_Handler,
    [11] = SVC_Handler,
    [14] = PendSV_Handler
};
'@
    Set-Content -LiteralPath $competingPath -Encoding ASCII -Value @'
void SVC_Handler(void)
{
    for (;;) {
    }
}

void PendSV_Handler(void)
{
    for (;;) {
    }
}
'@
    Set-Content -LiteralPath $linkerPath -Encoding ASCII -Value @'
ENTRY(Reset_Handler)
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 64K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
    .text : { *(.text*) *(.rodata*) } > FLASH
    .data : { *(.data*) } > RAM AT> FLASH
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
}
'@

    foreach ($archiveMode in @(
            [pscustomobject]@{ Name = "normal"; Flags = @() },
            [pscustomobject]@{ Name = "lto"; Flags = @("-flto") })) {
        $modeDir = Join-Path $probeDir "archive-$($archiveMode.Name)"
        New-Item -ItemType Directory -Path $modeDir | Out-Null
        $archiveRuntimeObject = Join-Path $modeDir "runtime.o"
        $archiveBootObject = Join-Path $modeDir "boot.o"
        $archivePath = Join-Path $modeDir "libfiber_cm33_ntz_runtime.a"
        $elfFixtureObject = Join-Path $modeDir "fixture.o"
        $competingObject = Join-Path $modeDir "competing.o"
        $elfPath = Join-Path $modeDir "runtime.elf"
        $vectorBinary = Join-Path $modeDir "vectors.bin"
        $archiveArgs = @($manifestArgs + @(
            "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1",
            "-O2", "-Werror", "-ffunction-sections", "-fdata-sections") +
            $archiveMode.Flags)

        & $Compiler @archiveArgs -c $frameSourcePath -o $archiveRuntimeObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_NTZ runtime archive source failed compile ($($archiveMode.Name))"
        }
        & $Compiler @archiveArgs -c $bootSourcePath -o $archiveBootObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_NTZ boot archive source failed compile ($($archiveMode.Name))"
        }
        & $Ar rcs $archivePath $archiveRuntimeObject $archiveBootObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_NTZ runtime archive creation failed ($($archiveMode.Name))"
        }
        & $Compiler @archiveArgs -c $elfFixturePath -o $elfFixtureObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_NTZ runtime ELF fixture failed compile ($($archiveMode.Name))"
        }
        & $Compiler @archiveArgs -c $competingPath -o $competingObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_NTZ competing-handler fixture failed compile ($($archiveMode.Name))"
        }

        $linkArgs = @(
            "-mcpu=cortex-m33", "-mthumb", "-nostdlib") +
            $archiveMode.Flags + @(
            "-Wl,--gc-sections", "-T", $linkerPath,
            $elfFixtureObject, $archivePath, "-o", $elfPath)
        & $Compiler @linkArgs
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33_NTZ runtime archive/ELF proof failed link ($($archiveMode.Name))"
        }
        $objectNm = if ($archiveMode.Name -eq "lto") { $GccNm } else { $Nm }
        $elfDefined = @(& $objectNm -g --defined-only $elfPath)
        if ($LASTEXITCODE -ne 0) {
            throw "nm failed for ARM_CM33_NTZ runtime ELF ($($archiveMode.Name))"
        }
        $svcSymbols = @($elfDefined | Where-Object {
            $_ -match '^([0-9a-fA-F]+)\s+T\s+SVC_Handler$'
        })
        if ($svcSymbols.Count -ne 1) {
            throw "ARM_CM33_NTZ runtime ELF must contain one strong SVC_Handler ($($archiveMode.Name))"
        }
        $pendSvSymbols = @($elfDefined | Where-Object {
            $_ -match '^([0-9a-fA-F]+)\s+T\s+PendSV_Handler$'
        })
        if ($pendSvSymbols.Count -ne 1) {
            throw "ARM_CM33_NTZ runtime ELF must contain one strong PendSV_Handler ($($archiveMode.Name))"
        }
        [void]($svcSymbols[0] -match '^([0-9a-fA-F]+)')
        $svcAddress = [Convert]::ToUInt32($Matches[1], 16)
        [void]($pendSvSymbols[0] -match '^([0-9a-fA-F]+)')
        $pendSvAddress = [Convert]::ToUInt32($Matches[1], 16)
        & $Objcopy -O binary --only-section=.isr_vector $elfPath $vectorBinary
        if ($LASTEXITCODE -ne 0) {
            throw "objcopy failed for ARM_CM33_NTZ runtime vector proof ($($archiveMode.Name))"
        }
        $vectorBytes = [IO.File]::ReadAllBytes($vectorBinary)
        if ($vectorBytes.Length -lt (16 * 4)) {
            throw "ARM_CM33_NTZ synthetic vector table is truncated ($($archiveMode.Name))"
        }
        $svcVector = [BitConverter]::ToUInt32($vectorBytes, 11 * 4)
        $pendSvVector = [BitConverter]::ToUInt32($vectorBytes, 14 * 4)
        if ($svcVector -ne ($svcAddress -bor [uint32]1)) {
            throw "ARM_CM33_NTZ vector slot 11 lost strong SVC_Handler ($($archiveMode.Name))"
        }
        if ($pendSvVector -ne ($pendSvAddress -bor [uint32]1)) {
            throw "ARM_CM33_NTZ vector slot 14 lost strong PendSV_Handler ($($archiveMode.Name))"
        }

        $duplicateLog = Join-Path $modeDir "duplicate-handlers.log"
        $duplicateArgs = @(
            "-mcpu=cortex-m33", "-mthumb", "-nostdlib") +
            $archiveMode.Flags + @(
            "-Wl,--gc-sections", "-T", $linkerPath,
            $elfFixtureObject, $competingObject, $archivePath,
            "-o", (Join-Path $modeDir "duplicate-handlers.elf"))
        $duplicate = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $duplicateArgs -LogPath $duplicateLog
        if (($duplicate.ExitCode -eq 0) -or
                ($duplicate.Output -notmatch 'multiple definition.*(?:SVC_Handler|PendSV_Handler)')) {
            throw "ARM_CM33_NTZ competing strong handlers must fail link ($($archiveMode.Name))`n$($duplicate.Output)"
        }
    }

    $negativeCases = @(
        [pscustomobject]@{
            Name = "selector-mode"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb")
            Defines = @("-DFIBER_PORT_PROFILE=5")
            Diagnostic = "ARM_CM33_NTZ is build-selected only"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "secure-cmse"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb", "-mcmse")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
            Diagnostic = "does not accept a Secure CMSE build"
            Main = $mainHeader
        },
        [pscustomobject]@{
            Name = "no-vtor"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb")
            Defines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
            Diagnostic = "requires __VTOR_PRESENT == 1"
            Main = ($mainHeader -replace '__VTOR_PRESENT 1U', '__VTOR_PRESENT 0U')
        },
        [pscustomobject]@{
            Name = "wrong-core"
            CompilerArgs = @("-mcpu=cortex-m23", "-mthumb")
            Defines = @(
                "-DFIBER_PORT_BUILD_SELECTED=1",
                "-DFIBER_PORT_ARMV8M_MAINLINE=1",
                "-DFIBER_PORT_SELECTION_ALLOW_MISMATCH=1")
            Diagnostic = "requires an ARMv8-M Mainline compiler target"
            Main = ($mainHeader -replace 'core_cm33.h', 'core_cm23.h')
        },
        [pscustomobject]@{
            Name = "fpu-used"
            CompilerArgs = @("-mcpu=cortex-m33", "-mthumb")
            Defines = @(
                "-DFIBER_PORT_BUILD_SELECTED=1",
                "-DFIBER_PORT_ARMV8M_MAINLINE=1",
                "-DFIBER_TEST_FPU_USED=1")
            Diagnostic = "requires __FPU_USED == 0"
            Main = $mainHeader
        }
    )

    foreach ($case in $negativeCases) {
        $caseDir = Join-Path $probeDir $case.Name
        New-Item -ItemType Directory -Path $caseDir | Out-Null
        Set-Content -LiteralPath (Join-Path $caseDir "main.h") `
            -Value $case.Main -Encoding ASCII
        $log = Join-Path $caseDir "compile.log"
        $arguments = @($case.CompilerArgs + @(
            "-std=c11", "-ffreestanding", "-fno-builtin",
            "-Wall", "-Wextra", "-I$caseDir", "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot", "-I$CmsisPath") +
            $case.Defines + @(
            "-c", $fixture, "-o", (Join-Path $caseDir "invalid.o")))
        $result = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $arguments -LogPath $log
        if (($result.ExitCode -eq 0) -or
                ($result.Output.IndexOf($case.Diagnostic,
                [System.StringComparison]::Ordinal) -lt 0)) {
            throw "Invalid ARM_CM33_NTZ manifest failed for the wrong reason: $($case.Name)`n$($result.Output)"
        }
    }
}

function Test-ArmCm33FNtzRuntimeContract {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Objdump,
        [string]$Objcopy,
        [string]$Ar,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot `
        "fiber\port\ARM_CM33F_NTZ\non_secure"
    $layoutFixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm33f_ntz_layout_probe.c"
    $referenceFixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm33f_ntz_freertos_frame_reference.c"
    foreach ($required in @(
            (Join-Path $profileDir "fiber_port_types.h"),
            (Join-Path $profileDir "fiber_port_boot_types.h"),
            (Join-Path $profileDir "fiber_portmacro.h"),
            (Join-Path $profileDir "fiber_port_boot.h"),
            (Join-Path $profileDir "fiber_port_private.h"),
            (Join-Path $profileDir "fiber_port.c"),
            (Join-Path $profileDir "fiber_port_boot.c"),
            (Join-Path $profileDir "FREERTOS_PARITY.md"),
            $layoutFixture,
            $referenceFixture)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "ARM_CM33F_NTZ runtime slice is missing: $required"
        }
    }

    foreach ($forbiddenRuntime in @(
            "fiber_port_exception.c",
            "fiber_portasm.c",
            "fiber_port_mpu.c",
            "fiber_port_secure_context.c")) {
        if (Test-Path -LiteralPath (Join-Path $profileDir $forbiddenRuntime)) {
            throw "ARM_CM33F_NTZ runtime slice exposes unsupported artifact: $forbiddenRuntime"
        }
    }

    foreach ($selector in @(
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h"))) {
        if ((Get-Content -LiteralPath $selector -Raw).IndexOf(
                "ARM_CM33F_NTZ", [System.StringComparison]::Ordinal) -ge 0) {
            throw "Staged ARM_CM33F_NTZ profile entered global selection: $selector"
        }
    }

    $typeText = Get-Content -LiteralPath `
        (Join-Path $profileDir "fiber_port_types.h") -Raw
    foreach ($forbiddenTypeDependency in @(
            "mcu_core.h",
            "fiber_compiler.h",
            "fiber_portmacro.h",
            "fiber_port_select.h")) {
        $includePattern = '(?m)^\s*#\s*include\s*["<][^">]*' +
            [regex]::Escape($forbiddenTypeDependency) + '[">]'
        if ([regex]::IsMatch($typeText, $includePattern)) {
            throw "ARM_CM33F_NTZ public storage acquired CPU dependency: $forbiddenTypeDependency"
        }
    }

    $parity = Get-Content -LiteralPath `
        (Join-Path $profileDir "FREERTOS_PARITY.md") -Raw
    foreach ($requiredParity in @(
            "a50edad08b29052631aa469d4df6e6ec7ff68878",
            "BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A",
            "F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B",
            "324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2",
            "DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5",
            "00B42952962E48F8C9421F5EC66BBCE9E02465760560728FEE2D743CE1706F3E",
            "configENABLE_FPU = 1",
            "0xFFFFFFBC",
            "0xFFFFFFAC",
            "maximum bounded context: 212 bytes",
            "vstmdbeq {s16-s31}",
            "vldmiaeq {s16-s31}",
            "prvSetupFPU()",
            "FPU Setup And SVC First Start",
            "FP-Aware PendSV",
            "FIBER_PORT_RUNTIME_SELECTABLE == 1",
            "vstmdb r0!, {s16-s31}",
            "vldmia r0!, {s16-s31}")) {
        if ($parity.IndexOf($requiredParity,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33F_NTZ parity ledger lost reference evidence: $requiredParity"
        }
    }

    $probeDir = Join-Path $BuildRoot "arm-cm33f-ntz-runtime"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#ifndef FIBER_TEST_FPU_PRESENT
#define FIBER_TEST_FPU_PRESENT 1U
#endif
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 3U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT FIBER_TEST_FPU_PRESENT
#define __FPU_USED 1U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    SVCall_IRQn = -5, PendSV_IRQn = -2, SysTick_IRQn = -1,
    DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm33.h"
#ifdef FIBER_TEST_FPU_USED
#undef __FPU_USED
#define __FPU_USED FIBER_TEST_FPU_USED
#endif
#ifdef FIBER_TEST_CORTEX_M
#undef __CORTEX_M
#define __CORTEX_M FIBER_TEST_CORTEX_M
#endif
#ifdef FIBER_TEST_SECURE_CMSE
#define __ARM_FEATURE_CMSE FIBER_TEST_SECURE_CMSE
#endif
#ifdef FIBER_TEST_MVE
#define __ARM_FEATURE_MVE FIBER_TEST_MVE
#endif
#ifdef FIBER_TEST_PAC
#define __ARM_FEATURE_PAUTH FIBER_TEST_PAC
#endif
#ifdef FIBER_TEST_BTI
#define __ARM_FEATURE_BTI FIBER_TEST_BTI
#endif
#endif
"@
    Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
        -Value $mainHeader -Encoding ASCII

    $typeProbe = Join-Path $probeDir "type-only.c"
    Set-Content -LiteralPath $typeProbe -Encoding ASCII -Value @'
#include "fiber_port_types.h"
_Static_assert(sizeof(FiberPortBoot) == 72u, "boot size");
_Static_assert(sizeof(FiberContext) == 76u, "context size");
_Static_assert(_Alignof(FiberContext) == 4u, "context alignment");
FiberContext fiber_cm33f_ntz_type_only_object;
'@
    & $Compiler -mcpu=cortex-m33 -mthumb -std=c11 -ffreestanding `
        -fno-builtin -Wall -Wextra -Werror "-I$profileDir" `
        -c $typeProbe -o (Join-Path $probeDir "type-only.o")
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33F_NTZ type-only C header failed without CMSIS"
    }

    $cppProbe = Join-Path $probeDir "type-only.cpp"
    Set-Content -LiteralPath $cppProbe -Encoding ASCII -Value @'
#include "fiber_port_types.h"
static_assert(sizeof(FiberPortBoot) == 72u, "boot size");
static_assert(sizeof(FiberContext) == 76u, "context size");
static_assert(alignof(FiberContext) == 4u, "context alignment");
FiberContext fiber_cm33f_ntz_cpp_type_only_object;
'@
    & $Compiler -x c++ -mcpu=cortex-m33 -mthumb -std=c++17 `
        -ffreestanding -fno-builtin -Wall -Wextra -Werror `
        "-I$profileDir" -c $cppProbe -o (Join-Path $probeDir "type-only-cpp.o")
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33F_NTZ type-only C++ header failed without CMSIS"
    }

    $manifestDefines = @(
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV8M_MAINLINE=1"
    )
    $includeArgs = @(
        "-I$probeDir", "-I$profileDir",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot", "-I$CmsisPath"
    )
    $hardCpuArgs = @(
        "-mcpu=cortex-m33", "-mthumb",
        "-mfpu=fpv5-sp-d16", "-mfloat-abi=hard"
    )
    $baseArgs = @(
        "-std=c11", "-ffreestanding", "-fno-builtin", "-fno-common",
        "-Wall", "-Wextra", "-Wundef", "-Werror=undef"
    ) + $manifestDefines + $includeArgs

    $layoutObject = Join-Path $probeDir "layout.o"
    & $Compiler @hardCpuArgs @baseArgs -c $layoutFixture -o $layoutObject
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33F_NTZ exact layout manifest failed compile"
    }
    $layoutDefined = @(& $Nm -g --defined-only $layoutObject)
    if ($LASTEXITCODE -ne 0) {
        throw "nm failed for ARM_CM33F_NTZ layout probe"
    }
    $cohorts = @($layoutDefined | ForEach-Object {
        if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
            $Matches[1]
        }
    })
    if ($cohorts.Count -ne 1) {
        throw "ARM_CM33F_NTZ layout must define one exact cohort"
    }
    foreach ($token in @(
            "armv8m_mainline",
            "p0x4333464Eu",
            "l0x00010001u",
            "_f1_e1_h1_j1_v1_d1_r1_",
            "_z8u_y1_w2_g3_",
            "_i0_o0xFFFFFFBCu_c0_s1_x0_m0_a0_b0_t1_n1_k0_q0")) {
        if ($cohorts[0].IndexOf($token,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM33F_NTZ exact cohort lost token ${token}: $($cohorts[0])"
        }
    }

    $frameSourcePath = Join-Path $profileDir "fiber_port.c"
    $bootSourcePath = Join-Path $profileDir "fiber_port_boot.c"
    $frameSource = Get-Content -LiteralPath $frameSourcePath -Raw
    $bootSource = Get-Content -LiteralPath $bootSourcePath -Raw
    $frameBody = Get-CFunctionBody -Source $frameSource `
        -Signature "void fiber_port_init_context_frame(FiberContext *const ctx)" `
        -Path $frameSourcePath
    $lastAssignment = -1
    foreach ($assignment in @(
            "fiber_portFRAME_PSPLIM] =",
            "fiber_portFRAME_EXC_RETURN] =",
            "fiber_portFRAME_R4] =",
            "fiber_portFRAME_R5] =",
            "fiber_portFRAME_R6] =",
            "fiber_portFRAME_R7] =",
            "fiber_portFRAME_R8] =",
            "fiber_portFRAME_R9] =",
            "fiber_portFRAME_R10] =",
            "fiber_portFRAME_R11] =",
            "fiber_portFRAME_R0] =",
            "fiber_portFRAME_R1] =",
            "fiber_portFRAME_R2] =",
            "fiber_portFRAME_R3] =",
            "fiber_portFRAME_R12] =",
            "fiber_portFRAME_LR] =",
            "fiber_portFRAME_PC] =",
            "fiber_portFRAME_XPSR] =")) {
        $assignmentIndex = $frameBody.IndexOf($assignment,
            [System.StringComparison]::Ordinal)
        if ($assignmentIndex -le $lastAssignment) {
            throw "ARM_CM33F_NTZ initial frame lost exact assignment order: $assignment"
        }
        $lastAssignment = $assignmentIndex
    }
    if (([regex]::Matches($frameBody,
            'frame\[fiber_portFRAME_[A-Z0-9_]+\]\s*=')).Count -ne 18) {
        throw "ARM_CM33F_NTZ constructor must assign exactly eighteen frame words"
    }
    foreach ($requiredConstructionToken in @(
            "FIBER_PORT_CONTEXT_COHORT_DEFINE();",
            "fiber_port_boot_record_check(&ctx->boot);",
            "ctx->sp = frame;",
            "FIBER_PORT_CONTEXT_COHORT_RETAIN();",
            "fiber_port_boot_create(&ctx->boot, stack_begin, stack_end, entry, arg);",
            "fiber_port_init_context_frame(ctx);",
            "fiber_port_validate_initial_frame(ctx);",
            "void fiber_port_fpu_prepare(void)",
            "void fiber_port_fpu_require_configured(void)",
            "void fiber_port_fpu_require_ready(void)",
            "void fiber_port_runtime_prepare_start(void)",
            "FiberContext *fiber_port_runtime_select_first(void)",
            "void fiber_port_runtime_start_first(FiberContext *const first)",
            "void fiber_port_runtime_schedule(void)",
            "void fiber_port_context_validate_restore(FiberContext *const ctx)",
            "void fiber_port_context_validate_save_current(const FiberContext *const ctx)",
            "FiberContext *fiber_port_scheduler_pick_next_from_pendsv(",
            "void SVC_Handler(void)",
            "void PendSV_Handler(void)",
            "vstmdb r0!, {s16-s31}",
            "vldmia r0!, {s16-s31}")) {
        if (($frameSource.IndexOf($requiredConstructionToken,
                    [System.StringComparison]::Ordinal) -lt 0) -and
                ($bootSource.IndexOf($requiredConstructionToken,
                    [System.StringComparison]::Ordinal) -lt 0)) {
            throw "ARM_CM33F_NTZ runtime source lost contract: $requiredConstructionToken"
        }
    }

    $modes = @(
        [pscustomobject]@{
            Name = "hard-o2"
            CpuArgs = $hardCpuArgs
            Optimization = "-O2"
            Defines = @("-DFIBER_FPU_LAZY=0")
        },
        [pscustomobject]@{
            Name = "hard-os"
            CpuArgs = $hardCpuArgs
            Optimization = "-Os"
            Defines = @("-DFIBER_FPU_LAZY=1")
        },
        [pscustomobject]@{
            Name = "softfp-o2"
            CpuArgs = @("-mcpu=cortex-m33", "-mthumb",
                "-mfpu=fpv5-sp-d16", "-mfloat-abi=softfp")
            Optimization = "-O2"
            Defines = @("-DFIBER_FPU_LAZY=0")
        },
        [pscustomobject]@{
            Name = "softfp-os"
            CpuArgs = @("-mcpu=cortex-m33", "-mthumb",
                "-mfpu=fpv5-sp-d16", "-mfloat-abi=softfp")
            Optimization = "-Os"
            Defines = @("-DFIBER_FPU_LAZY=1")
        }
    )
    $expectedForwardDefinitions = @(
        "fiber_port_context_init",
        "fiber_port_runtime_memory_barrier",
        "fiber_port_panic_wait",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_runtime_schedule"
    )
    foreach ($mode in $modes) {
        $modeDir = Join-Path $probeDir $mode.Name
        New-Item -ItemType Directory -Path $modeDir | Out-Null
        $compileArgs = @($mode.CpuArgs + $baseArgs + @(
            $mode.Optimization,
            "-Werror",
            "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1",
            "-save-temps=obj") + $mode.Defines)
        $frameObject = Join-Path $modeDir "frame.o"
        $bootObject = Join-Path $modeDir "boot.o"
        $referenceObject = Join-Path $modeDir "freertos-frame.o"
        & $Compiler @compileArgs -c $frameSourcePath -o $frameObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ frame construction failed compile: $($mode.Name)"
        }
        & $Compiler @compileArgs -c $bootSourcePath -o $bootObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ boot construction failed compile: $($mode.Name)"
        }
        & $Compiler @($mode.CpuArgs + @(
            "-std=c11", "-ffreestanding", "-fno-builtin", "-Wall",
            "-Wextra", "-Werror", $mode.Optimization,
            "-c", $referenceFixture, "-o", $referenceObject))
        if ($LASTEXITCODE -ne 0) {
            throw "Pinned FreeRTOS CM33F frame fixture failed compile: $($mode.Name)"
        }

        $groupObject = Join-Path $modeDir "construction-group.o"
        & $Compiler -r $frameObject $bootObject -o $groupObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ runtime group failed link: $($mode.Name)"
        }
        $defined = @(& $Nm -g --defined-only $groupObject)
        if ($LASTEXITCODE -ne 0) {
            throw "nm failed for ARM_CM33F_NTZ runtime group: $($mode.Name)"
        }
        foreach ($requiredDefinition in $expectedForwardDefinitions) {
            if ((@($defined | Where-Object {
                    $_ -match ("\bT\s+" +
                        [regex]::Escape($requiredDefinition) + "$")
                })).Count -ne 1) {
                throw "ARM_CM33F_NTZ runtime group must define one $requiredDefinition"
            }
        }
        $groupCohorts = @($defined | ForEach-Object {
            if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
                $Matches[1]
            }
        })
        if (($groupCohorts.Count -ne 1) -or
                ($groupCohorts[0] -ne $cohorts[0])) {
            throw "ARM_CM33F_NTZ runtime group disagrees with exact cohort"
        }

        $undefined = @(& $Nm -u $groupObject | ForEach-Object {
            if ($_ -match '^\s*U\s+(\S+)$') { $Matches[1] }
        } | Sort-Object -Unique)
        $svcDefinitions = @($defined | Where-Object {
            $_ -match '\bT\s+SVC_Handler$'
        })
        if ($svcDefinitions.Count -ne 1) {
            throw "ARM_CM33F_NTZ runtime group must define one strong SVC_Handler"
        }
        $pendSvDefinitions = @($defined | Where-Object {
            $_ -match '\bT\s+PendSV_Handler$'
        })
        if ($pendSvDefinitions.Count -ne 1) {
            throw "ARM_CM33F_NTZ runtime group must define one strong PendSV_Handler"
        }

        Assert-ExactSymbolSet -Expected @(
            "fiber_internal_runtime_current_context_slot",
            "fiber_internal_runtime_port_abi_v1_anchor",
            "fiber_internal_runtime_publish_current_context",
            "fiber_internal_runtime_require_current_context",
            "fiber_internal_runtime_select_scheduler_candidate",
            "fiber_internal_task_return",
            "fiber_panic"
        ) -Actual $undefined -Description `
            "ARM_CM33F_NTZ runtime reverse/integration surface ($($mode.Name))"

        $frameDisassembly = (& $Objdump -d $frameObject) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for ARM_CM33F_NTZ frame: $($mode.Name)"
        }
        $referenceDisassembly = (& $Objdump -d $referenceObject) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for FreeRTOS CM33F frame fixture: $($mode.Name)"
        }
        $generatedFrameBody = Get-DisassemblyFunctionBody `
            -Disassembly $frameDisassembly `
            -Symbol "fiber_port_init_context_frame" -Path $frameObject
        $generatedReferenceBody = Get-DisassemblyFunctionBody `
            -Disassembly $referenceDisassembly `
            -Symbol "fiber_test_freertos_cm33f_initialise_stack" `
            -Path $referenceObject
        foreach ($generatedBody in @($generatedFrameBody,
                $generatedReferenceBody)) {
            if ($generatedBody -match
                    '(?im)^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+v[a-z0-9.]+' ) {
                throw "CM33F initial construction emitted FP/MVE instruction: $($mode.Name)"
            }
            if ($generatedBody -notmatch '#-?(?:72|0x48)\b') {
                throw "CM33F initial construction lost the 72-byte basic frame: $($mode.Name)"
            }
        }

        $runtimeDisassembly = (& $Objdump -dr $frameObject) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for ARM_CM33F_NTZ runtime object: $($mode.Name)"
        }
        $svcBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
            -Symbol "SVC_Handler" -Path $frameObject
        $startBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
            -Symbol "fiber_port_start_first_context" -Path $frameObject
        $pendSvBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
            -Symbol "PendSV_Handler" -Path $frameObject
        $fpuBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
            -Symbol "fiber_port_fpu_prepare" -Path $frameObject
        foreach ($generatedBody in @($svcBody, $startBody, $fpuBody)) {
            if ($generatedBody -match
                    '(?im)^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+v[a-z0-9.]+' ) {
                throw "ARM_CM33F_NTZ SVC/start/FPU setup emitted an unexpected FP/MVE instruction: $($mode.Name)"
            }
        }
        $svcInstructionOrder = @(
            'mrs\s+r3,\s*IPSR',
            'cmp\s+r3,\s*#11',
            'mvn(?:\.w)?\s+r3,\s*#71',
            'mrs\s+r0,\s*MSP',
            'ldr\s+r2,\s*\[r0,\s*#28\]',
            'ldr\s+r3,\s*\[r0,\s*#24\]',
            'ldrb\s+r2,\s*\[r3,\s*#1\]',
            'cmp\s+r2,\s*#223',
            'ldrb\s+r3,\s*\[r3(?:,\s*#0)?\]',
            'cmp\s+r3,\s*#70',
            'cpsid\s+i',
            'msr\s+BASEPRI,\s*r0',
            'fiber_port_context_validate_restore',
            'ldmia(?:\.w)?\s+r0!,\s*\{r2,\s*r3,\s*r4,\s*r5,\s*r6,\s*r7,\s*r8,\s*(?:r9|sb),\s*sl,\s*fp\}',
            'mvn(?:\.w)?\s+r1,\s*#67',
            'msr\s+PSPLIM,\s*r2',
            'msr\s+CONTROL,\s*r1',
            'msr\s+PSP,\s*r0',
            'bx\s+r3'
        )
        $remainingSvcBody = $svcBody
        foreach ($instructionPattern in $svcInstructionOrder) {
            $instructionMatch = [regex]::Match($remainingSvcBody,
                $instructionPattern,
                [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if (-not $instructionMatch.Success) {
                throw "ARM_CM33F_NTZ generated SVC lost FreeRTOS-parity instruction order: $instructionPattern`n$svcBody"
            }
            $remainingSvcBody = $remainingSvcBody.Substring(
                $instructionMatch.Index + $instructionMatch.Length)
        }
        $startInstructionOrder = @(
            'cpsid\s+i',
            'msr\s+CONTROL,\s*r3',
            'msr\s+MSP,\s*r0',
            'msr\s+BASEPRI,\s*r0',
            'cpsie\s+f',
            'cpsie\s+i',
            'svc\s+70'
        )
        $remainingStartBody = $startBody
        foreach ($instructionPattern in $startInstructionOrder) {
            $instructionMatch = [regex]::Match($remainingStartBody,
                $instructionPattern,
                [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if (-not $instructionMatch.Success) {
                throw "ARM_CM33F_NTZ generated first-start helper lost FreeRTOS-parity instruction order: $instructionPattern`n$startBody"
            }
            $remainingStartBody = $remainingStartBody.Substring(
                $instructionMatch.Index + $instructionMatch.Length)
        }
        $pendSvInstructionOrder = @(
            'mrs\s+r3,\s*IPSR',
            'cmp\s+r3,\s*#14',
            'mvn(?:\.w)?\s+r3,\s*#67',
            'cmp\s+lr,\s*r3',
            'bic(?:\.w)?\s+r3,\s*r3,\s*#16',
            'mrs\s+r0,\s*PSP',
            'fiber_port_context_validate_save_current',
            'ldr\s+r2,\s*\[r1,\s*#12\]',
            'tst(?:\.w)?\s+lr,\s*#16',
            'subs\s+r3,\s*#64',
            'subs\s+r3,\s*#40',
            'ldr\s+r2,\s*\[r1,\s*#16\]',
            'subs\s+r2,\s*#32',
            'tst(?:\.w)?\s+lr,\s*#16',
            'subs\s+r2,\s*#72',
            'tst(?:\.w)?\s+lr,\s*#16',
            'ldr\s+r3,\s*\[r0,\s*#100\]',
            'ldr\s+r3,\s*\[r0,\s*#28\]',
            'tst(?:\.w)?\s+r3,\s*#512',
            'subs\s+r2,\s*#4',
            'tst(?:\.w)?\s+lr,\s*#16',
            'vstmdb\s+r0!,\s*\{s16-s31\}',
            'mrs\s+r3,\s*PSPLIM',
            'stmdb\s+r0!,\s*\{r2,\s*r3,\s*r4,\s*r5,\s*r6,\s*r7,\s*r8,\s*(?:r9|sb),\s*sl,\s*fp\}',
            'str\s+r0,\s*\[r1(?:,\s*#0)?\]',
            'mrs\s+r3,\s*BASEPRI',
            'msr\s+BASEPRI,\s*r2',
            'fiber_port_scheduler_pick_next_from_pendsv',
            'msr\s+BASEPRI,\s*r3',
            'mrs\s+r1,\s*BASEPRI',
            'ldmia(?:\.w)?\s+r0!,\s*\{r2,\s*r3,\s*r4,\s*r5,\s*r6,\s*r7,\s*r8,\s*(?:r9|sb),\s*sl,\s*fp\}',
            'tst(?:\.w)?\s+r3,\s*#16',
            'vldmia\s+r0!,\s*\{s16-s31\}',
            'msr\s+PSPLIM,\s*r2',
            'mrs\s+r1,\s*PSPLIM',
            'msr\s+PSP,\s*r0',
            'mrs\s+r1,\s*PSP',
            'mrs\s+r1,\s*CONTROL',
            'mrs\s+r1,\s*PRIMASK',
            'mrs\s+r1,\s*FAULTMASK',
            'bx\s+r3'
        )
        $remainingPendSvBody = $pendSvBody
        foreach ($instructionPattern in $pendSvInstructionOrder) {
            $instructionMatch = [regex]::Match($remainingPendSvBody,
                $instructionPattern,
                [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if (-not $instructionMatch.Success) {
                throw "ARM_CM33F_NTZ generated FP-aware PendSV lost FreeRTOS-parity instruction order: $instructionPattern`n$pendSvBody"
            }
            $remainingPendSvBody = $remainingPendSvBody.Substring(
                $instructionMatch.Index + $instructionMatch.Length)
        }
        Test-GeneratedCurrentSlotLoadOnly -AssemblyPath `
            ([IO.Path]::ChangeExtension($frameObject, ".s"))
        Assert-SensitiveFunctionClean -Disassembly $runtimeDisassembly `
            -Symbol "SVC_Handler" -Path $frameObject
        Assert-SensitiveFunctionClean -Disassembly $runtimeDisassembly `
            -Symbol "fiber_port_start_first_context" -Path $frameObject
        Assert-SensitiveFunctionClean -Disassembly $runtimeDisassembly `
            -Symbol "PendSV_Handler" -Path $frameObject
    }

    # Compile the independent hot-path settings explicitly. This port must
    # retain the same frame geometry with either lazy-FP policy and with both
    # production and map/hash validation policies.
    $sourceVariants = @(
        [pscustomobject]@{
            Name = "production"
            Defines = @(
                "-DFIBER_FPU_LAZY=0",
                "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0",
                "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=0")
        },
        [pscustomobject]@{
            Name = "validation-lazy"
            Defines = @(
                "-DFIBER_FPU_LAZY=1",
                "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=1",
                "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1")
        },
        [pscustomobject]@{
            Name = "no-rewind"
            Defines = @(
                "-DFIBER_FPU_LAZY=0",
                "-DFIBER_REWIND_MSP=0",
                "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0",
                "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=0")
        }
    )
    foreach ($variant in $sourceVariants) {
        $variantRuntime = Join-Path $probeDir "$($variant.Name)-runtime.o"
        $variantBoot = Join-Path $probeDir "$($variant.Name)-boot.o"
        $variantGroup = Join-Path $probeDir "$($variant.Name)-group.o"
        $variantArgs = @($hardCpuArgs + $baseArgs + @(
            "-O2", "-Werror", "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1") +
            $variant.Defines)
        & $Compiler @variantArgs -c $frameSourcePath -o $variantRuntime
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ $($variant.Name) runtime variant failed compile"
        }
        & $Compiler @variantArgs -c $bootSourcePath -o $variantBoot
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ $($variant.Name) boot variant failed compile"
        }
        & $Compiler -r $variantRuntime $variantBoot -o $variantGroup
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ $($variant.Name) object group failed link"
        }
    }

    $adversarialObject = Join-Path $probeDir "adversarial-runtime.o"
    & $Compiler @($hardCpuArgs + $baseArgs + @(
        "-O2", "-Werror", "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1",
        "-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs",
        "-ftest-coverage", "-c", $frameSourcePath, "-o", $adversarialObject))
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM33F_NTZ adversarial runtime source failed compile"
    }
    $adversarialDisassembly = (& $Objdump -dr $adversarialObject) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed for adversarial ARM_CM33F_NTZ runtime object"
    }
    foreach ($handler in @(
            "SVC_Handler",
            "fiber_port_start_first_context",
            "PendSV_Handler")) {
        Assert-SensitiveFunctionClean -Disassembly $adversarialDisassembly `
            -Symbol $handler -Path $adversarialObject
    }

    # The selected runtime owns both strong exception handlers. Archive proof
    # must retain both slots under normal and LTO/section-GC links.
    # Keep this fixture self-contained so the port archive has to expose the
    # complete frozen reverse ABI rather than relying on a previous test's
    # helper set.
    $elfFixturePath = Join-Path $probeDir "runtime-elf-fixture.c"
    $competingPath = Join-Path $probeDir "competing-handlers.c"
    $linkerPath = Join-Path $probeDir "runtime.ld"
    Set-Content -LiteralPath $elfFixturePath -Encoding ASCII -Value @'
#include <stddef.h>
#include <stdint.h>

#include "fiber_port_types.h"
#include "fiber_runtime_port_abi.h"

extern void fiber_port_runtime_prepare_start(void);
extern void SVC_Handler(void);
extern void PendSV_Handler(void);
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code);

const unsigned char fiber_internal_runtime_port_abi_v1_anchor = 1u;
FiberContext *volatile fiber_internal_runtime_current_context_slot;

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_runtime_select_scheduler_candidate(
        FiberContext *current)
{
    return current;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_current_context(void)
{
    if (fiber_internal_runtime_current_context_slot == NULL) {
        fiber_panic('C');
    }
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_publish_current_context(FiberContext *next)
{
    if (next == NULL) {
        fiber_panic('N');
    }
    fiber_internal_runtime_current_context_slot = next;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_task_return(void)
{
    for (;;) {
        __asm volatile("wfe");
    }
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    (void)code;
    for (;;) {
        __asm volatile("wfe");
    }
}

void Reset_Handler(void)
{
    fiber_port_runtime_prepare_start();
    for (;;) {
        __asm volatile("wfe");
    }
}

typedef void (*FiberVector)(void);
__attribute__((used, section(".isr_vector")))
const FiberVector fiber_vectors[16] = {
    [1] = Reset_Handler,
    [11] = SVC_Handler,
    [14] = PendSV_Handler
};
'@
    Set-Content -LiteralPath $competingPath -Encoding ASCII -Value @'
void SVC_Handler(void)
{
    for (;;) {
    }
}

void PendSV_Handler(void)
{
    for (;;) {
    }
}
'@
    Set-Content -LiteralPath $linkerPath -Encoding ASCII -Value @'
ENTRY(Reset_Handler)
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 64K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
    .text : { *(.text*) *(.rodata*) } > FLASH
    .data : { *(.data*) } > RAM AT> FLASH
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
}
'@

    foreach ($archiveMode in @(
            [pscustomobject]@{ Name = "normal"; Flags = @() },
            [pscustomobject]@{ Name = "lto"; Flags = @("-flto") })) {
        $modeDir = Join-Path $probeDir "runtime-archive-$($archiveMode.Name)"
        New-Item -ItemType Directory -Path $modeDir | Out-Null
        $archiveRuntimeObject = Join-Path $modeDir "runtime.o"
        $archiveBootObject = Join-Path $modeDir "boot.o"
        $archivePath = Join-Path $modeDir "libfiber_cm33f_ntz_runtime.a"
        $fixtureObject = Join-Path $modeDir "fixture.o"
        $competingObject = Join-Path $modeDir "competing.o"
        $elfPath = Join-Path $modeDir "runtime.elf"
        $vectorBinary = Join-Path $modeDir "vectors.bin"
        $archiveArgs = @($hardCpuArgs + $baseArgs + @(
            "-O2", "-Werror", "-DFIBER_FPU_LAZY=0",
            "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1",
            "-ffunction-sections", "-fdata-sections") + $archiveMode.Flags)

        & $Compiler @archiveArgs -c $frameSourcePath -o $archiveRuntimeObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ runtime archive source failed compile ($($archiveMode.Name))"
        }
        & $Compiler @archiveArgs -c $bootSourcePath -o $archiveBootObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ runtime archive boot failed compile ($($archiveMode.Name))"
        }
        & $Ar rcs $archivePath $archiveRuntimeObject $archiveBootObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ runtime archive creation failed ($($archiveMode.Name))"
        }
        & $Compiler @archiveArgs -c $elfFixturePath -o $fixtureObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ runtime ELF fixture failed compile ($($archiveMode.Name))"
        }
        & $Compiler @archiveArgs -c $competingPath -o $competingObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ competing-handler fixture failed compile ($($archiveMode.Name))"
        }

        $linkArgs = @(
            "-mcpu=cortex-m33", "-mthumb", "-mfpu=fpv5-sp-d16",
            "-mfloat-abi=hard", "-nostdlib") + $archiveMode.Flags + @(
            "-Wl,--gc-sections", "-T", $linkerPath,
            $fixtureObject, $archivePath, "-o", $elfPath)
        & $Compiler @linkArgs
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM33F_NTZ runtime archive/ELF proof failed link ($($archiveMode.Name))"
        }

        $objectNm = if ($archiveMode.Name -eq "lto") { $GccNm } else { $Nm }
        $elfDefined = @(& $objectNm -g --defined-only $elfPath)
        if ($LASTEXITCODE -ne 0) {
            throw "nm failed for ARM_CM33F_NTZ runtime ELF ($($archiveMode.Name))"
        }
        $svcSymbols = @($elfDefined | Where-Object {
            $_ -match '^([0-9a-fA-F]+)\s+T\s+SVC_Handler$'
        })
        if ($svcSymbols.Count -ne 1) {
            throw "ARM_CM33F_NTZ runtime ELF must contain one strong SVC_Handler ($($archiveMode.Name))"
        }
        $pendSvSymbols = @($elfDefined | Where-Object {
            $_ -match '^([0-9a-fA-F]+)\s+T\s+PendSV_Handler$'
        })
        if ($pendSvSymbols.Count -ne 1) {
            throw "ARM_CM33F_NTZ runtime ELF must contain one strong PendSV_Handler ($($archiveMode.Name))"
        }
        $elfCohorts = @($elfDefined | ForEach-Object {
            if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
                $Matches[1]
            }
        })
        if (($elfCohorts.Count -ne 1) -or ($elfCohorts[0] -ne $cohorts[0])) {
            throw "ARM_CM33F_NTZ runtime ELF lost the exact selected cohort ($($archiveMode.Name))"
        }
        [void]($svcSymbols[0] -match '^([0-9a-fA-F]+)')
        $svcAddress = [Convert]::ToUInt32($Matches[1], 16)
        [void]($pendSvSymbols[0] -match '^([0-9a-fA-F]+)')
        $pendSvAddress = [Convert]::ToUInt32($Matches[1], 16)
        & $Objcopy -O binary --only-section=.isr_vector $elfPath $vectorBinary
        if ($LASTEXITCODE -ne 0) {
            throw "objcopy failed for ARM_CM33F_NTZ runtime vector proof ($($archiveMode.Name))"
        }
        $vectorBytes = [IO.File]::ReadAllBytes($vectorBinary)
        if ($vectorBytes.Length -lt (16 * 4)) {
            throw "ARM_CM33F_NTZ runtime synthetic vector table is truncated ($($archiveMode.Name))"
        }
        $svcVector = [BitConverter]::ToUInt32($vectorBytes, 11 * 4)
        $pendSvVector = [BitConverter]::ToUInt32($vectorBytes, 14 * 4)
        if ($svcVector -ne ($svcAddress -bor [uint32]1)) {
            throw "ARM_CM33F_NTZ runtime vector slot 11 lost strong SVC_Handler ($($archiveMode.Name))"
        }
        if ($pendSvVector -ne ($pendSvAddress -bor [uint32]1)) {
            throw "ARM_CM33F_NTZ runtime vector slot 14 lost strong PendSV_Handler ($($archiveMode.Name))"
        }

        $duplicateLog = Join-Path $modeDir "duplicate-handlers.log"
        $duplicateArgs = @(
            "-mcpu=cortex-m33", "-mthumb", "-mfpu=fpv5-sp-d16",
            "-mfloat-abi=hard", "-nostdlib") + $archiveMode.Flags + @(
            "-Wl,--gc-sections", "-T", $linkerPath,
            $fixtureObject, $competingObject, $archivePath,
            "-o", (Join-Path $modeDir "duplicate-handlers.elf"))
        $duplicate = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $duplicateArgs -LogPath $duplicateLog
        if (($duplicate.ExitCode -eq 0) -or
                ($duplicate.Output -notmatch 'multiple definition.*(?:SVC_Handler|PendSV_Handler)')) {
            throw "ARM_CM33F_NTZ competing strong handlers must fail link ($($archiveMode.Name))`n$($duplicate.Output)"
        }
    }

    $invalidCases = @(
        [pscustomobject]@{
            Name = "not-build-selected"
            CpuArgs = $hardCpuArgs
            Defines = @("-DFIBER_PORT_ARMV8M_MAINLINE=1")
            Diagnostic = "ARM_CM33F_NTZ is build-selected only"
        },
        [pscustomobject]@{
            Name = "no-silicon-fpu"
            CpuArgs = $hardCpuArgs
            Defines = $manifestDefines + @("-DFIBER_TEST_FPU_PRESENT=0")
            Diagnostic = "requires CMSIS __FPU_PRESENT == 1"
        },
        [pscustomobject]@{
            Name = "cmsis-fpu-unused"
            CpuArgs = $hardCpuArgs
            Defines = $manifestDefines + @("-DFIBER_TEST_FPU_USED=0")
            Diagnostic = "requires CMSIS __FPU_USED == 1"
        },
        [pscustomobject]@{
            Name = "soft-no-fp-codegen"
            CpuArgs = @("-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft")
            Defines = $manifestDefines
            Diagnostic = "requires compiler FP code generation"
        },
        [pscustomobject]@{
            Name = "secure-cmse"
            CpuArgs = $hardCpuArgs
            Defines = $manifestDefines + @("-DFIBER_TEST_SECURE_CMSE=3")
            Diagnostic = "does not accept a Secure CMSE build"
        },
        [pscustomobject]@{
            Name = "mve"
            CpuArgs = $hardCpuArgs
            Defines = $manifestDefines + @("-DFIBER_TEST_MVE=1")
            Diagnostic = "does not permit MVE"
        },
        [pscustomobject]@{
            Name = "pac"
            CpuArgs = $hardCpuArgs
            Defines = $manifestDefines + @("-DFIBER_TEST_PAC=1")
            Diagnostic = "does not permit PAC"
        },
        [pscustomobject]@{
            Name = "bti"
            CpuArgs = $hardCpuArgs
            Defines = $manifestDefines + @("-DFIBER_TEST_BTI=1")
            Diagnostic = "does not permit BTI"
        },
        [pscustomobject]@{
            Name = "mpu-profile-mix"
            CpuArgs = $hardCpuArgs
            Defines = $manifestDefines + @(
                "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8")
            Diagnostic = "ARM_CM33F_NTZ is non-MPU"
        },
        [pscustomobject]@{
            Name = "wrong-cmsis-core"
            CpuArgs = $hardCpuArgs
            Defines = $manifestDefines + @("-DFIBER_TEST_CORTEX_M=55")
            Diagnostic = "requires CMSIS __CORTEX_M == 33"
        }
    )
    foreach ($case in $invalidCases) {
        $caseDir = Join-Path $probeDir ("invalid-" + $case.Name)
        New-Item -ItemType Directory -Path $caseDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $probeDir "main.h") `
            -Destination (Join-Path $caseDir "main.h")
        $arguments = @($case.CpuArgs + @(
            "-std=c11", "-ffreestanding", "-fno-builtin",
            "-Wall", "-Wextra", "-I$caseDir", "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot", "-I$CmsisPath") +
            $case.Defines + @(
            "-c", $layoutFixture, "-o", (Join-Path $caseDir "invalid.o")))
        $result = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $arguments -LogPath (Join-Path $caseDir "compile.log")
        if (($result.ExitCode -eq 0) -or
                ($result.Output.IndexOf($case.Diagnostic,
                [System.StringComparison]::Ordinal) -lt 0)) {
            throw "Invalid ARM_CM33F_NTZ manifest failed for the wrong reason: $($case.Name)`n$($result.Output)"
        }
    }
}

function Test-ArmCm4MpuSlice5Contract {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$Objdump,
        [string]$Objcopy,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot "fiber\port\ARM_CM4_MPU"
    $probeSource = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm4_mpu_layout_probe.c"
    $probeDir = Join-Path $BuildRoot "arm-cm4-mpu-slice5"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
        -Value "#ifndef MAIN_H_`n#define MAIN_H_`n#endif`n" -Encoding ASCII

    foreach ($requiredFile in @(
            "fiber_port_boot_types.h",
            "fiber_port_types.h",
            "fiber_portmacro.h",
            "fiber_port_boot.h",
            "fiber_port_boot.c",
            "fiber_port_private.h",
            "fiber_port.c",
            "FREERTOS_PARITY.md")) {
        if (-not (Test-Path (Join-Path $profileDir $requiredFile))) {
            throw "ARM_CM4_MPU slice 5 is missing required file: $requiredFile"
        }
    }
    if (-not (Test-Path $probeSource)) {
        throw "ARM_CM4_MPU slice 5 layout fixture is missing"
    }

    foreach ($forbiddenFile in @("fiber_port_exception.c")) {
        if (Test-Path (Join-Path $profileDir $forbiddenFile)) {
            throw "ARM_CM4_MPU slice 5 must not provide exception runtime source: $forbiddenFile"
        }
    }

    foreach ($selectorPath in @(
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h"))) {
        $selectorSource = Get-Content -LiteralPath $selectorPath -Raw
        if ($selectorSource.IndexOf("ARM_CM4_MPU",
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM4_MPU slice 5 must have no global selector route: $selectorPath"
        }
    }

    foreach ($typeHeaderName in @(
            "fiber_port_types.h",
            "fiber_port_boot_types.h")) {
        $typeHeaderPath = Join-Path $profileDir $typeHeaderName
        $typeHeaderSource = Get-Content -LiteralPath $typeHeaderPath -Raw
        if ([regex]::IsMatch($typeHeaderSource,
                '\b(mcu_core|fiber_compiler|fiber_portmacro|SCB|NVIC|__ASM)\b')) {
            throw "ARM_CM4_MPU type header acquired a CMSIS/runtime dependency: $typeHeaderPath"
        }
    }

    $warningArgs = @(
        "-ffreestanding",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wundef",
        "-Werror=undef",
        "-Werror=implicit-function-declaration",
        "-Werror=return-type"
    )
    $typeIncludeArgs = @("-I$profileDir")
    $typeCSource = Join-Path $probeDir "type-only.c"
    $typeCppSource = Join-Path $probeDir "type-only.cpp"
    $typeText = @"
#include <stddef.h>
#include "fiber_port_types.h"

_Static_assert(sizeof(FiberPortProtectedContext) == 212u,
    "[fiber]: ARM_CM4_MPU protected context size changed");
_Static_assert(offsetof(FiberContext, protected_context_cursor) == 0u,
    "[fiber]: ARM_CM4_MPU cursor offset changed");
_Static_assert(offsetof(FiberContext, mpu_regions) == 4u,
    "[fiber]: ARM_CM4_MPU MPU image offset changed");
#if FIBER_PORT_CM4_MPU_TOTAL_REGIONS == 8
_Static_assert(offsetof(FiberContext, protected_context) == 36u,
    "[fiber]: ARM_CM4_MPU 8-region protected offset changed");
_Static_assert(offsetof(FiberContext, runtime_flags) == 248u,
    "[fiber]: ARM_CM4_MPU 8-region flags offset changed");
_Static_assert(offsetof(FiberContext, boot) == 252u,
    "[fiber]: ARM_CM4_MPU 8-region boot offset changed");
_Static_assert(sizeof(FiberContext) == 344u,
    "[fiber]: ARM_CM4_MPU 8-region context size changed");
#else
_Static_assert(offsetof(FiberContext, protected_context) == 100u,
    "[fiber]: ARM_CM4_MPU 16-region protected offset changed");
_Static_assert(offsetof(FiberContext, runtime_flags) == 312u,
    "[fiber]: ARM_CM4_MPU 16-region flags offset changed");
_Static_assert(offsetof(FiberContext, boot) == 316u,
    "[fiber]: ARM_CM4_MPU 16-region boot offset changed");
_Static_assert(sizeof(FiberContext) == 408u,
    "[fiber]: ARM_CM4_MPU 16-region context size changed");
#endif
_Static_assert(_Alignof(FiberContext) == 8u,
    "[fiber]: ARM_CM4_MPU context alignment changed");

int fiber_arm_cm4_mpu_type_only_probe(void)
{
    return 0;
}
"@
    Set-Content -LiteralPath $typeCSource -Value $typeText -Encoding ASCII

    $typeCppText = @"
#include <cstddef>
#include "fiber_port_types.h"

static_assert(sizeof(FiberPortProtectedContext) == 212u,
    "[fiber]: ARM_CM4_MPU C++ protected context size changed");
static_assert(offsetof(FiberContext, mpu_regions) == 4u,
    "[fiber]: ARM_CM4_MPU C++ MPU image offset changed");
#if FIBER_PORT_CM4_MPU_TOTAL_REGIONS == 8
static_assert(offsetof(FiberContext, boot) == 252u,
    "[fiber]: ARM_CM4_MPU C++ 8-region boot offset changed");
static_assert(sizeof(FiberContext) == 344u,
    "[fiber]: ARM_CM4_MPU C++ 8-region context size changed");
#else
static_assert(offsetof(FiberContext, boot) == 316u,
    "[fiber]: ARM_CM4_MPU C++ 16-region boot offset changed");
static_assert(sizeof(FiberContext) == 408u,
    "[fiber]: ARM_CM4_MPU C++ 16-region context size changed");
#endif
static_assert(alignof(FiberContext) == 8u,
    "[fiber]: ARM_CM4_MPU C++ context alignment changed");

int fiber_arm_cm4_mpu_type_only_cpp_probe()
{
    return 0;
}
"@
    Set-Content -LiteralPath $typeCppSource -Value $typeCppText -Encoding ASCII

    foreach ($regionCount in @(8, 16)) {
        $typeObject = Join-Path $probeDir "type-${regionCount}.o"
        $typeArgs = @(
            "-mcpu=cortex-m4",
            "-mthumb",
            "-std=gnu11"
        ) + $warningArgs + @(
            "-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=$regionCount"
        ) + $typeIncludeArgs + @(
            "-c", $typeCSource,
            "-o", $typeObject
        )
        & $Compiler @typeArgs
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM4_MPU $regionCount-region type header failed C compile without CMSIS"
        }

        $cppWarningArgs = @($warningArgs | Where-Object {
            ($_ -ne "-Werror=implicit-function-declaration")
        })
        $cppObject = Join-Path $probeDir "type-${regionCount}-cpp.o"
        $cppArgs = @(
            "-x", "c++",
            "-mcpu=cortex-m4",
            "-mthumb",
            "-std=gnu++17",
            "-fno-exceptions",
            "-fno-rtti"
        ) + $cppWarningArgs + @(
            "-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=$regionCount"
        ) + $typeIncludeArgs + @(
            "-c", $typeCppSource,
            "-o", $cppObject
        )
        & $Compiler @cppArgs
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM4_MPU $regionCount-region type header failed C++ compile without CMSIS"
        }
    }

    $includeArgs = @(
        "-I$probeDir",
        "-I$profileDir",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot",
        "-I$CmsisPath"
    )
    $variants = @(
        [pscustomobject]@{ Name = "m4-r8"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 4; Regions = 8; PortId = "0x434D344Du"; Layout = "0x00010008u"; Errata = 0 },
        [pscustomobject]@{ Name = "m4-r16"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 4; Regions = 16; PortId = "0x434D344Du"; Layout = "0x00010010u"; Errata = 0 },
        [pscustomobject]@{ Name = "m7-r8"; Cpu = "cortex-m7"; Fpu = "fpv5-d16"; Core = 7; Regions = 8; PortId = "0x434D374Du"; Layout = "0x00010008u"; Errata = 1 },
        [pscustomobject]@{ Name = "m7-r16"; Cpu = "cortex-m7"; Fpu = "fpv5-d16"; Core = 7; Regions = 16; PortId = "0x434D374Du"; Layout = "0x00010010u"; Errata = 1 }
    )
    $cohortSymbols = @()
    foreach ($variant in $variants) {
        $objectPath = Join-Path $probeDir "$($variant.Name).o"
        $defines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV7EM=1",
            "-D__CORTEX_M=$($variant.Core)",
            "-D__MPU_PRESENT=1",
            "-D__VTOR_PRESENT=1",
            "-D__FPU_PRESENT=1",
            "-D__FPU_USED=1",
            "-D__NVIC_PRIO_BITS=4",
            "-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=$($variant.Regions)"
        )
        $compileArgs = @(
            "-mcpu=$($variant.Cpu)",
            "-mthumb",
            "-mfpu=$($variant.Fpu)",
            "-mfloat-abi=hard",
            "-std=gnu11"
        ) + $warningArgs + $defines + $includeArgs + @(
            "-c", $probeSource,
            "-o", $objectPath
        )
        & $Compiler @compileArgs
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM4_MPU layout variant failed compile: $($variant.Name)"
        }

        $nmOutput = & $Nm --defined-only $objectPath
        if ($LASTEXITCODE -ne 0) {
            throw "nm failed for ARM_CM4_MPU layout variant: $($variant.Name)"
        }
        $variantCohorts = @()
        foreach ($line in $nmOutput) {
            if ($line -match '\b(?<symbol>fiber_port_context_cohort_\S+)\s*$') {
                $variantCohorts += $Matches['symbol']
            }
            if ($line -match '\b(SVC_Handler|PendSV_Handler|fiber_port_runtime_)\S*\s*$') {
                throw "ARM_CM4_MPU layout probe unexpectedly defines runtime symbol: $line"
            }
        }
        if ($variantCohorts.Count -ne 1) {
            throw "ARM_CM4_MPU $($variant.Name) must define exactly one cohort symbol"
        }
        $expectedPrefix = "fiber_port_context_cohort_armv7em_p$($variant.PortId)_l$($variant.Layout)_"
        if (-not $variantCohorts[0].StartsWith($expectedPrefix,
                [System.StringComparison]::Ordinal)) {
            throw "ARM_CM4_MPU cohort identity mismatch for $($variant.Name): $($variantCohorts[0])"
        }
        if ($variantCohorts[0].IndexOf("_i$($variant.Errata)_",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM4_MPU M7 errata identity mismatch for $($variant.Name)"
        }
        $cohortSymbols += $variantCohorts[0]
    }

    if ((@($cohortSymbols | Sort-Object -Unique)).Count -ne $variants.Count) {
        throw "ARM_CM4_MPU M4/M7 or 8/16-region variants collapsed to one cohort"
    }

    $negativeCases = @(
        [pscustomobject]@{ Name = "missing-region-count"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 4; Defines = @(); Diagnostic = "explicit 8- or 16-region MPU manifest" },
        [pscustomobject]@{ Name = "invalid-region-count"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 4; Defines = @("-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=12"); Diagnostic = "supports exactly 8 or 16 MPU regions" },
        [pscustomobject]@{ Name = "mpu-absent"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 4; Defines = @("-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=8", "-D__MPU_PRESENT=0"); Diagnostic = "requires __MPU_PRESENT == 1" },
        [pscustomobject]@{ Name = "fpu-absent"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 4; Defines = @("-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=8", "-D__FPU_PRESENT=0"); Diagnostic = "requires __FPU_PRESENT == 1" },
        [pscustomobject]@{ Name = "fpu-unused"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 4; Defines = @("-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=8", "-D__FPU_USED=0"); Diagnostic = "requires __FPU_USED == 1" },
        [pscustomobject]@{ Name = "wrong-cmsis-core"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 3; Defines = @("-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=8"); Diagnostic = "requires CMSIS __CORTEX_M 4 or 7" }
    )
    foreach ($case in $negativeCases) {
        $negativeObject = Join-Path $probeDir "$($case.Name).o"
        $negativeLog = Join-Path $probeDir "$($case.Name).log"
        $baseDefines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV7EM=1",
            "-D__CORTEX_M=$($case.Core)",
            "-D__VTOR_PRESENT=1",
            "-D__NVIC_PRIO_BITS=4"
        )
        if (-not ($case.Defines -match '^-D__MPU_PRESENT=')) {
            $baseDefines += "-D__MPU_PRESENT=1"
        }
        if (-not ($case.Defines -match '^-D__FPU_PRESENT=')) {
            $baseDefines += "-D__FPU_PRESENT=1"
        }
        if (-not ($case.Defines -match '^-D__FPU_USED=')) {
            $baseDefines += "-D__FPU_USED=1"
        }
        $negativeArgs = @(
            "-mcpu=$($case.Cpu)",
            "-mthumb",
            "-mfpu=$($case.Fpu)",
            "-mfloat-abi=hard",
            "-std=gnu11"
        ) + $warningArgs + $baseDefines + $case.Defines + $includeArgs + @(
            "-c", $probeSource,
            "-o", $negativeObject
        )
        $negativeResult = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $negativeArgs -LogPath $negativeLog
        if ($negativeResult.ExitCode -eq 0) {
            throw "ARM_CM4_MPU negative manifest unexpectedly compiled: $($case.Name)"
        }
        if ($negativeResult.Output.IndexOf($case.Diagnostic,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM4_MPU negative manifest failed for the wrong reason: $($case.Name)`n$($negativeResult.Output)"
        }
    }

    $bootSource = Join-Path $profileDir "fiber_port_boot.c"
    $bootHeader = Join-Path $profileDir "fiber_port_boot.h"
    $portSource = Join-Path $profileDir "fiber_port.c"
    $privateHeader = Join-Path $profileDir "fiber_port_private.h"
    $bootFixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm4_mpu_boot_probe.c"
    $bootLinker = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm4_mpu_boot.ld"
    foreach ($requiredPath in @($bootSource, $bootHeader, $portSource,
            $privateHeader,
            $bootFixture, $bootLinker)) {
        if (-not (Test-Path $requiredPath)) {
            throw "ARM_CM4_MPU slice 5 proof is missing: $requiredPath"
        }
    }

    $bootText = Get-Content -LiteralPath $bootSource -Raw
    foreach ($requiredText in @(
            "FIBER_PORT_CONTEXT_COHORT_RETAIN();",
            "fiber_port_mpu_try_encode_exact_region",
            "fiber_port_mpu_linker_layout_check",
            "fiber_port_mpu_build_global_regions",
            "fiber_port_context_compute_seal",
            "fiber_port_context_seal_check",
            "fiber_port_context_validate_initial_restore",
            "fiber_port_context_validate_running_svc",
            "fiber_port_context_validate_save_current",
            "fiber_port_context_validate_restore",
            "ARMv7E-M keeps the basic core frame at PSP",
            "fiber_port_context_init",
            "ctx->mpu_regions[fiber_portMPU_STACK_REGION] = stack_region;",
            "ctx->protected_context.basic.core.r9 = fiber_port_read_r9();",
            "&ctx->protected_context.basic.cursor_limit",
            "ctx->runtime_flags = 0u;")) {
        if ($bootText.IndexOf($requiredText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM4_MPU slice 5 lost construction invariant: $requiredText"
        }
    }
    foreach ($forbiddenText in @(
            "void SVC_Handler(",
            "void PendSV_Handler(",
            "fiber_port_runtime_prepare_start(",
            "fiber_port_runtime_schedule(")) {
        if ($bootText.IndexOf($forbiddenText,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM4_MPU boot object acquired runtime ownership: $forbiddenText"
        }
    }

    $portText = Get-Content -LiteralPath $portSource -Raw
    foreach ($requiredText in @(
            "FIBER_PORT_CONTEXT_COHORT_DEFINE();",
            "void fiber_port_runtime_memory_barrier(",
            "void fiber_port_panic_wait(",
            "void fiber_port_require_scheduler_configuration_environment(",
            "void fiber_port_runtime_prepare_start(",
            "FiberContext *fiber_port_runtime_select_first(",
            "void fiber_port_runtime_start_first(",
            "void fiber_port_svc_dispatch(",
            "void fiber_port_runtime_schedule(",
            "void fiber_port_unprivileged_task_return(",
            "void fiber_port_start_first_context(",
            "void fiber_port_restore_first_context_from_svc(",
            "void SVC_Handler(",
            "void PendSV_Handler(",
            "void fiber_port_pendsv_validate_save_current(",
            "FiberContext *fiber_port_scheduler_pick_next_from_pendsv(",
            "void fiber_port_mpu_switch_to_context(",
            "fiber_port_mpu_activate_first_context",
            "fiber_port_mpu_validate_active_context",
            "fiber_port_fpu_prepare();",
            "fiber_portFPCCR_LSPACT_BIT",
            "fiber_portSVC_START",
            "fiber_portSVC_YIELD",
            "fiber_portSVC_RETURN")) {
        if ($portText.IndexOf($requiredText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM4_MPU slice 5 lost runtime invariant: $requiredText"
        }
    }

    $boundarySymbols = @(
        "__fiber_mpu_unprivileged_code_start__",
        "__fiber_mpu_unprivileged_code_end__",
        "__fiber_mpu_privileged_code_start__",
        "__fiber_mpu_privileged_code_end__",
        "__fiber_mpu_privileged_data_start__",
        "__fiber_mpu_privileged_data_end__",
        "__fiber_mpu_current_context_slot_start__",
        "__fiber_mpu_current_context_slot_end__",
        "__fiber_mpu_unprivileged_ram_start__",
        "__fiber_mpu_unprivileged_ram_end__"
    )
    $linkerText = Get-Content -LiteralPath $bootLinker -Raw
    $constructionCohorts = @()

    foreach ($variant in $variants) {
        $variantDir = Join-Path $probeDir "construction-$($variant.Name)"
        New-Item -ItemType Directory -Path $variantDir | Out-Null
        $coreHeader = if ($variant.Core -eq 4) { "core_cm4.h" } else { "core_cm7.h" }
        $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 1U
#define __FPU_USED 1U
#define __DSP_PRESENT 1U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
#define __DTCM_PRESENT 0U
#define __ITCM_PRESENT 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5,
    DebugMonitor_IRQn = -4, PendSV_IRQn = -2,
    SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#include "$coreHeader"
#endif
"@
        Set-Content -LiteralPath (Join-Path $variantDir "main.h") `
            -Value $mainHeader -Encoding ASCII

        $constructionDefines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV7EM=1",
            "-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=$($variant.Regions)"
        )
        $constructionIncludes = @(
            "-I$variantDir",
            "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot",
            "-I$CmsisPath"
        )
        $constructionBase = @(
            "-mcpu=$($variant.Cpu)",
            "-mthumb",
            "-mfpu=$($variant.Fpu)",
            "-mfloat-abi=hard",
            "-std=gnu11",
            "-O2",
            "-ffreestanding",
            "-fno-common",
            "-fno-builtin",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wundef",
            "-Werror=undef",
            "-Werror=implicit-function-declaration",
            "-Werror=return-type"
        ) + $constructionDefines + $constructionIncludes

        $bootObject = Join-Path $variantDir "fiber_port_boot.o"
        & $Compiler @($constructionBase + @(
            "-c", $bootSource, "-o", $bootObject))
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM4_MPU construction source failed compile: $($variant.Name)"
        }

        $portObject = Join-Path $variantDir "fiber_port.o"
        $portAssembly = [IO.Path]::ChangeExtension($portObject, ".s")
        & $Compiler @($constructionBase + @(
            "-save-temps=obj",
            "-c", $portSource, "-o", $portObject))
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM4_MPU protected runtime source failed compile: $($variant.Name)"
        }
        Test-GeneratedCurrentSlotLoadOnly -AssemblyPath $portAssembly

        $lazyPortObject = Join-Path $variantDir "fiber_port_lazy.o"
        $lazyPortAssembly = [IO.Path]::ChangeExtension($lazyPortObject, ".s")
        & $Compiler @($constructionBase + @(
            "-DFIBER_FPU_LAZY=1",
            "-save-temps=obj",
            "-c", $portSource, "-o", $lazyPortObject))
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM4_MPU lazy-FP runtime source failed compile: $($variant.Name)"
        }
        Test-GeneratedCurrentSlotLoadOnly -AssemblyPath $lazyPortAssembly

        $bootDefined = @(& $Nm -g --defined-only $bootObject)
        foreach ($line in $bootDefined) {
            if ($line -match '\b(SVC_Handler|PendSV_Handler|fiber_port_runtime_)\S*\s*$') {
                throw "ARM_CM4_MPU boot object unexpectedly defines runtime symbol: $line"
            }
        }
        $bootUndefined = @(& $Nm -u $bootObject)
        $undefinedNames = @($bootUndefined | ForEach-Object {
            if ($_ -match '\bU\s+(\S+)$') { $Matches[1] }
        })
        foreach ($boundary in $boundarySymbols) {
            if ($undefinedNames -notcontains $boundary) {
                throw "ARM_CM4_MPU construction lost linker boundary relocation: $boundary / $($variant.Name)"
            }
        }
        foreach ($requiredUndefined in @(
                "fiber_panic",
                "fiber_internal_task_return",
                "fiber_port_runtime_memory_barrier",
                "fiber_port_panic_wait",
                "fiber_port_require_scheduler_configuration_environment",
                "fiber_port_runtime_prepare_start",
                "fiber_port_runtime_select_first",
                "fiber_port_runtime_start_first",
                "fiber_port_unprivileged_task_return",
                "fiber_port_runtime_schedule",
                "fiber_port_svc_dispatch",
                "fiber_port_pendsv_validate_save_current",
                "fiber_port_scheduler_pick_next_from_pendsv",
                "fiber_port_mpu_switch_to_context",
                "fiber_port_start_first_context",
                "fiber_port_restore_first_context_from_svc",
                "SVC_Handler",
                "PendSV_Handler")) {
            if ($undefinedNames -notcontains $requiredUndefined) {
                throw "ARM_CM4_MPU construction lost required dependency: $requiredUndefined / $($variant.Name)"
            }
        }
        $variantCohort = @($undefinedNames | Where-Object {
            $_ -match '^fiber_port_context_cohort_'
        })
        if ($variantCohort.Count -ne 1) {
            throw "ARM_CM4_MPU construction must retain one exact cohort: $($variant.Name)"
        }
        $constructionCohorts += $variantCohort[0]
        $allowedUndefined = @($boundarySymbols + @(
            "fiber_panic",
            "fiber_internal_task_return",
            "fiber_port_runtime_memory_barrier",
            "fiber_port_panic_wait",
            "fiber_port_require_scheduler_configuration_environment",
            "fiber_port_runtime_prepare_start",
            "fiber_port_runtime_select_first",
            "fiber_port_runtime_start_first",
            "fiber_port_unprivileged_task_return",
            "fiber_port_runtime_schedule",
            "fiber_port_svc_dispatch",
            "fiber_port_pendsv_validate_save_current",
            "fiber_port_scheduler_pick_next_from_pendsv",
            "fiber_port_mpu_switch_to_context",
            "fiber_port_start_first_context",
            "fiber_port_restore_first_context_from_svc",
            "SVC_Handler",
            "PendSV_Handler",
            $variantCohort[0]
        ))
        foreach ($symbol in $undefinedNames) {
            if ($allowedUndefined -notcontains $symbol) {
                throw "ARM_CM4_MPU construction acquired unexpected dependency: $symbol / $($variant.Name)"
            }
        }

        $portDefined = @(& $Nm -g --defined-only $portObject)
        foreach ($requiredSymbol in @(
                "SVC_Handler",
                "PendSV_Handler",
                "fiber_port_runtime_memory_barrier",
                "fiber_port_panic_wait",
                "fiber_port_require_scheduler_configuration_environment",
                "fiber_port_runtime_prepare_start",
                "fiber_port_runtime_select_first",
                "fiber_port_runtime_start_first",
                "fiber_port_runtime_schedule",
                "fiber_port_unprivileged_task_return",
                "fiber_port_start_first_context",
                "fiber_port_restore_first_context_from_svc",
                "fiber_port_svc_dispatch",
                "fiber_port_pendsv_validate_save_current",
                "fiber_port_scheduler_pick_next_from_pendsv",
                "fiber_port_mpu_switch_to_context")) {
            if (-not ($portDefined -match
                    "\b[TR] \s*$([regex]::Escape($requiredSymbol))$")) {
                throw "ARM_CM4_MPU runtime object lost strong symbol: $requiredSymbol / $($variant.Name)"
            }
        }

        $portUndefined = @(& $Nm -u $portObject | ForEach-Object {
            if ($_ -match '\bU\s+(\S+)$') { $Matches[1] }
        })
        foreach ($requiredUndefined in @(
                "fiber_internal_runtime_current_context_slot",
                "fiber_internal_runtime_port_abi_v1_anchor",
                "fiber_internal_runtime_select_scheduler_candidate",
                "fiber_internal_runtime_publish_current_context",
                "fiber_internal_runtime_require_current_context",
                "fiber_internal_task_return",
                "fiber_panic",
                "fiber_port_context_validate_initial_restore",
                "fiber_port_context_validate_running_svc",
                "fiber_port_context_validate_save_current",
                "fiber_port_context_validate_restore",
                "fiber_port_mpu_build_global_regions",
                "fiber_port_mpu_linker_layout_check",
                "fiber_port_mpu_load_linker_layout")) {
            if ($portUndefined -notcontains $requiredUndefined) {
                throw "ARM_CM4_MPU runtime object lost dependency: $requiredUndefined / $($variant.Name)"
            }
        }
        $expectedPortUndefined = @(
            "fiber_internal_runtime_current_context_slot",
            "fiber_internal_runtime_port_abi_v1_anchor",
            "fiber_internal_runtime_publish_current_context",
            "fiber_internal_runtime_require_current_context",
            "fiber_internal_runtime_select_scheduler_candidate",
            "fiber_internal_task_return",
            "fiber_panic",
            "fiber_port_context_validate_initial_restore",
            "fiber_port_context_validate_restore",
            "fiber_port_context_validate_running_svc",
            "fiber_port_context_validate_save_current",
            "fiber_port_mpu_build_global_regions",
            "fiber_port_mpu_linker_layout_check",
            "fiber_port_mpu_load_linker_layout"
        ) | Sort-Object
        $actualPortUndefined = @($portUndefined | Sort-Object)
        if (($expectedPortUndefined.Count -ne $actualPortUndefined.Count) -or
                (Compare-Object -ReferenceObject $expectedPortUndefined `
                -DifferenceObject $actualPortUndefined)) {
            throw "ARM_CM4_MPU runtime object dependency surface changed: $($variant.Name)`nExpected: $($expectedPortUndefined -join ', ')`nActual: $($actualPortUndefined -join ', ')"
        }
        $portCohorts = @($portDefined | ForEach-Object {
            if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
                $Matches[1]
            }
        })
        if ($portCohorts.Count -ne 1) {
            throw "ARM_CM4_MPU runtime object must define one exact cohort: $($variant.Name)"
        }

        $portSymbolTable = @(& $Objdump -t $portObject)
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for ARM_CM4_MPU runtime object: $($variant.Name)"
        }
        foreach ($symbol in @(
                "SVC_Handler",
                "PendSV_Handler",
                "fiber_port_start_first_context",
                "fiber_port_restore_first_context_from_svc",
                "fiber_port_svc_dispatch",
                "fiber_port_pendsv_validate_save_current",
                "fiber_port_scheduler_pick_next_from_pendsv",
                "fiber_port_mpu_switch_to_context")) {
            $match = @($portSymbolTable | Where-Object {
                $_ -match "\bF\s+\.fiber_port_privileged_functions\s+[0-9a-fA-F]+\s+$([regex]::Escape($symbol))$"
            })
            if ($match.Count -ne 1) {
                throw "ARM_CM4_MPU privileged runtime symbol escaped section: $symbol / $($variant.Name)"
            }
        }
        foreach ($symbol in @(
                "fiber_port_runtime_schedule",
                "fiber_port_unprivileged_task_return")) {
            $match = @($portSymbolTable | Where-Object {
                $_ -match "\bF\s+\.fiber_port_unprivileged_functions\s+[0-9a-fA-F]+\s+$([regex]::Escape($symbol))$"
            })
            if ($match.Count -ne 1) {
                throw "ARM_CM4_MPU unprivileged SVC veneer escaped section: $symbol / $($variant.Name)"
            }
        }

        $portDisassembly = (& $Objdump -dr $portObject) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "objdump disassembly failed for ARM_CM4_MPU runtime object: $($variant.Name)"
        }
        foreach ($shape in @(
                'svc\s+71',
                'svc\s+72',
                'svc\s+70',
                'ldmdb\s+r1!,\s*\{r0,\s*r4,\s*r5,\s*r6,\s*r7,\s*r8,\s*r9,\s*sl,\s*fp\}',
                'msr\s+PSP,\s*r0',
                'stmia(?:\.w)?\s+r0,\s*\{r4,\s*r5,\s*r6,\s*r7,\s*r8,\s*r9,\s*sl,\s*fp\}',
                'msr\s+CONTROL,\s*r3',
                'vstmia(?:eq)?\s+r1!,\s*\{s16-s31\}',
                'vldmia(?:eq)?\s+r0,\s*\{s0-s16\}',
                'vstmia(?:eq)?\s+r1!,\s*\{s0-s16\}',
                'vldmdb(?:eq)?\s+r1!,\s*\{s0-s16\}',
                'vstmia(?:eq)?\s+r0!,\s*\{s0-s16\}',
                'vldmdb(?:eq)?\s+r1!,\s*\{s16-s31\}',
                'fiber_port_scheduler_pick_next_from_pendsv',
                'fiber_port_mpu_switch_to_context',
                'fiber_internal_runtime_current_context_slot')) {
            if ($portDisassembly -notmatch $shape) {
                throw "ARM_CM4_MPU generated SVC/restore shape changed: $shape / $($variant.Name)"
            }
        }
        $svcInstructions = @([regex]::Matches($portDisassembly,
                '(?m)^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+svc\s+'))
        if ($svcInstructions.Count -ne 3) {
            throw "ARM_CM4_MPU runtime must emit exactly three SVC instructions: $($variant.Name)"
        }
        $svcHandler = [regex]::Match($portDisassembly,
                '(?s)<SVC_Handler>:(?<body>.*?)(?=\r?\n[0-9a-fA-F]+\s+<)')
        if (-not $svcHandler.Success) {
            throw "ARM_CM4_MPU generated SVC handler was not found: $($variant.Name)"
        }
        if ($svcHandler.Groups['body'].Value -match
                'add(?:\.w)?\s+r0,\s*r0,\s*#72') {
            throw "ARM_CM4_MPU SVC must keep PSP on the basic core frame: $($variant.Name)"
        }
        if (($variant.Core -eq 7) -and
                (($portDisassembly -notmatch 'mrs\s+ip,\s*PRIMASK') -or
                 ($portDisassembly -notmatch 'msr\s+BASEPRI,\s*r0') -or
                 ($portDisassembly -notmatch 'msr\s+PRIMASK,\s*ip'))) {
            throw "ARM_CM4_MPU M7 restore lost PRIMASK-preserving errata sequence: $($variant.Name)"
        }

        $pendsvBody = Get-DisassemblyFunctionBody `
            -Disassembly $portDisassembly -Symbol "PendSV_Handler" `
            -Path $portObject
        $pendsvOrder = @(
            "fiber_port_pendsv_validate_save_current",
            "vstmiaeq",
            "fiber_port_scheduler_pick_next_from_pendsv",
            "fiber_port_mpu_switch_to_context",
            "vldmdbeq"
        )
        $lastPendSvIndex = -1
        foreach ($step in $pendsvOrder) {
            $stepIndex = $pendsvBody.IndexOf($step,
                [System.StringComparison]::OrdinalIgnoreCase)
            if ($stepIndex -le $lastPendSvIndex) {
                throw "ARM_CM4_MPU PendSV generated order changed at $step / $($variant.Name)"
            }
            $lastPendSvIndex = $stepIndex
        }
        $fpTransferCount = [regex]::Matches($pendsvBody,
            '(?im)^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+v(?:stmia|ldmia|ldmdb)(?:eq)?\b').Count
        if ($fpTransferCount -ne 6) {
            throw "ARM_CM4_MPU PendSV must emit exactly six protected FP transfers: $($variant.Name) / $fpTransferCount"
        }
        if ($pendsvBody.IndexOf(
                "fiber_internal_runtime_current_context_slot",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM4_MPU PendSV lost assembly-only current-slot load: $($variant.Name)"
        }

        $schedulerBody = Get-DisassemblyFunctionBody `
            -Disassembly $portDisassembly `
            -Symbol "fiber_port_scheduler_pick_next_from_pendsv" `
            -Path $portObject
        if ([regex]::IsMatch($schedulerBody,
                '(?im)^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+v[a-z0-9.]+\b')) {
            throw "ARM_CM4_MPU scheduler bridge emitted an FP instruction: $($variant.Name)"
        }

        $symbolTable = & $Objdump -t $bootObject
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for ARM_CM4_MPU construction: $($variant.Name)"
        }
        $privilegedMatches = 0
        foreach ($line in $symbolTable) {
            if ($line -match '\bF\s+(?<section>\S+)\s+[0-9a-fA-F]+\s+(?<symbol>fiber_port_\S+)$') {
                ++$privilegedMatches
                if ($Matches['section'] -ne '.fiber_port_privileged_functions') {
                    throw "ARM_CM4_MPU construction function escaped privileged text: $($Matches['symbol']) -> $($Matches['section'])"
                }
            }
        }
        if ($privilegedMatches -eq 0) {
            throw "ARM_CM4_MPU construction section proof matched no functions"
        }

        $fixtureObject = Join-Path $variantDir "boot_probe.o"
        & $Compiler @($constructionBase + @(
            "-c", $bootFixture, "-o", $fixtureObject))
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM4_MPU construction fixture failed compile: $($variant.Name)"
        }

        $elfPath = Join-Path $variantDir "boot_probe.elf"
        & $Compiler @(
            "-mcpu=$($variant.Cpu)",
            "-mthumb",
            "-mfpu=$($variant.Fpu)",
            "-mfloat-abi=hard",
            "-nostdlib",
            "-Wl,--gc-sections",
            "-T", $bootLinker,
            $fixtureObject,
            $portObject,
            $bootObject,
            "-o", $elfPath
        )
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM4_MPU synthetic construction linker contract failed: $($variant.Name)"
        }

        $elfSymbols = @(& $Nm -g --defined-only $elfPath)
        foreach ($requiredSymbol in @(
                "fiber_port_context_init",
                "fiber_port_context_compute_seal",
                "fiber_port_context_seal_check",
                "fiber_port_context_validate_initial_restore",
                "fiber_port_context_validate_running_svc",
                "fiber_port_context_validate_save_current",
                "fiber_port_context_validate_restore",
                "fiber_port_mpu_try_encode_exact_region",
                "fiber_port_mpu_build_global_regions",
                "fiber_port_unprivileged_task_return",
                "fiber_port_runtime_schedule",
                "fiber_port_start_first_context",
                "fiber_port_restore_first_context_from_svc",
                "fiber_port_svc_dispatch",
                "fiber_port_pendsv_validate_save_current",
                "fiber_port_scheduler_pick_next_from_pendsv",
                "fiber_port_mpu_switch_to_context",
                "SVC_Handler",
                "PendSV_Handler")) {
            if (-not ($elfSymbols -match "\b$([regex]::Escape($requiredSymbol))$")) {
                throw "ARM_CM4_MPU synthetic ELF lost symbol: $requiredSymbol / $($variant.Name)"
            }
        }
        $svcAddress = Get-StrongTextSymbolAddress -NmOutput $elfSymbols `
            -Symbol "SVC_Handler" -Path $elfPath
        $pendsvAddress = Get-StrongTextSymbolAddress -NmOutput $elfSymbols `
            -Symbol "PendSV_Handler" -Path $elfPath

        $vectorPath = Join-Path $variantDir "vectors.bin"
        & $Objcopy -O binary --only-section=.isr_vector $elfPath $vectorPath
        if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $vectorPath))) {
            throw "ARM_CM4_MPU vector extraction failed: $($variant.Name)"
        }
        $vectorBytes = [IO.File]::ReadAllBytes($vectorPath)
        if ($vectorBytes.Length -lt (16 * 4)) {
            throw "ARM_CM4_MPU synthetic vector table is truncated: $($variant.Name)"
        }
        $svcVector = [BitConverter]::ToUInt32($vectorBytes, 11 * 4)
        if ((($svcVector -band 1) -eq 0) -or
                (($svcVector -band [uint32]4294967294) -ne
                ($svcAddress -band [uint32]4294967294))) {
            throw "ARM_CM4_MPU vector slot 11 lost strong SVC: $($variant.Name)"
        }
        $pendsvVector = [BitConverter]::ToUInt32($vectorBytes, 14 * 4)
        if ((($pendsvVector -band 1) -eq 0) -or
                (($pendsvVector -band [uint32]4294967294) -ne
                ($pendsvAddress -band [uint32]4294967294))) {
            throw "ARM_CM4_MPU vector slot 14 lost strong PendSV: $($variant.Name)"
        }

        if ($variant.Name -eq "m4-r8") {
            $competingSource = Join-Path $variantDir "competing-svc.c"
            $competingObject = Join-Path $variantDir "competing-svc.o"
            Set-Content -LiteralPath $competingSource -Encoding ASCII -Value `
                "void SVC_Handler(void) { }`n"
            & $Compiler @($constructionBase + @(
                "-c", $competingSource, "-o", $competingObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM4_MPU competing SVC fixture failed compile"
            }
            $duplicateLog = Join-Path $variantDir "duplicate-svc.log"
            $duplicateResult = Invoke-CompilerProbe -Compiler $Compiler `
                -Arguments @(
                    "-mcpu=$($variant.Cpu)",
                    "-mthumb",
                    "-mfpu=$($variant.Fpu)",
                    "-mfloat-abi=hard",
                    "-nostdlib",
                    "-Wl,--gc-sections",
                    "-T", $bootLinker,
                    $fixtureObject,
                    $portObject,
                    $bootObject,
                    $competingObject,
                    "-o", (Join-Path $variantDir "duplicate-svc.elf")
                ) -LogPath $duplicateLog
            if (($duplicateResult.ExitCode -eq 0) -or
                    ($duplicateResult.Output -notmatch 'multiple definition')) {
                throw "ARM_CM4_MPU competing strong SVC must fail link`n$($duplicateResult.Output)"
            }

            $competingPendSvSource = Join-Path $variantDir `
                "competing-pendsv.c"
            $competingPendSvObject = Join-Path $variantDir `
                "competing-pendsv.o"
            Set-Content -LiteralPath $competingPendSvSource -Encoding ASCII `
                -Value "void PendSV_Handler(void) { }`n"
            & $Compiler @($constructionBase + @(
                "-c", $competingPendSvSource, "-o", $competingPendSvObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM4_MPU competing PendSV fixture failed compile"
            }
            $duplicatePendSvLog = Join-Path $variantDir `
                "duplicate-pendsv.log"
            $duplicatePendSvResult = Invoke-CompilerProbe `
                -Compiler $Compiler `
                -Arguments @(
                    "-mcpu=$($variant.Cpu)",
                    "-mthumb",
                    "-mfpu=$($variant.Fpu)",
                    "-mfloat-abi=hard",
                    "-nostdlib",
                    "-Wl,--gc-sections",
                    "-T", $bootLinker,
                    $fixtureObject,
                    $portObject,
                    $bootObject,
                    $competingPendSvObject,
                    "-o", (Join-Path $variantDir "duplicate-pendsv.elf")
                ) -LogPath $duplicatePendSvLog
            if (($duplicatePendSvResult.ExitCode -eq 0) -or
                    ($duplicatePendSvResult.Output -notmatch
                    'multiple definition')) {
                throw "ARM_CM4_MPU competing strong PendSV must fail link`n$($duplicatePendSvResult.Output)"
            }

            foreach ($boundary in $boundarySymbols) {
                $negativeLinker = Join-Path $variantDir `
                    "missing-$($boundary.Trim('_')).ld"
                $negativeText = $linkerText -replace
                    "(?m)^$([regex]::Escape($boundary))\s*=\s*[^;]+;\r?\n", ""
                Set-Content -LiteralPath $negativeLinker `
                    -Value $negativeText -Encoding ASCII
                $negativeLog = Join-Path $variantDir `
                    "missing-$($boundary.Trim('_')).log"
                $negativeResult = Invoke-CompilerProbe -Compiler $Compiler `
                    -Arguments @(
                        "-mcpu=$($variant.Cpu)",
                        "-mthumb",
                        "-mfpu=$($variant.Fpu)",
                        "-mfloat-abi=hard",
                        "-nostdlib",
                        "-Wl,--gc-sections",
                        "-T", $negativeLinker,
                        $fixtureObject,
                        $portObject,
                        $bootObject,
                        "-o", (Join-Path $variantDir `
                            "missing-$($boundary.Trim('_')).elf")
                    ) -LogPath $negativeLog
                if (($negativeResult.ExitCode -eq 0) -or
                        ($negativeResult.Output.IndexOf($boundary,
                        [System.StringComparison]::Ordinal) -lt 0)) {
                    throw "ARM_CM4_MPU missing linker boundary must fail on $boundary`n$($negativeResult.Output)"
                }
            }
        }
    }

    if ((@($constructionCohorts | Sort-Object -Unique)).Count -ne
            $variants.Count) {
        throw "ARM_CM4_MPU construction objects collapsed distinct exact cohorts"
    }
}

function Test-ArmCm4MpuRuntimeIntegration {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Objdump,
        [string]$Objcopy,
        [string]$Ar,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot "fiber\port\ARM_CM4_MPU"
    $startupSource = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm4_mpu_runtime_startup.c"
    $portableSource = Join-Path $RepositoryRoot `
        "tools\fixtures\portable_application.c"
    $expectationSource = Join-Path $RepositoryRoot `
        "fiber\port\fiber_port_context_cohort_expectation.c"
    $linkerScript = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm4_mpu_runtime.ld"
    foreach ($requiredPath in @($startupSource, $portableSource,
            $expectationSource, $linkerScript)) {
        if (-not (Test-Path -LiteralPath $requiredPath)) {
            throw "ARM_CM4_MPU runtime integration fixture is missing: $requiredPath"
        }
    }

    $commonSources = @(
        "fiber\fiber_core.c",
        "fiber\fiber_runtime_state.c",
        "fiber\fiber_panic.c"
    )
    $portSources = @(
        "fiber\port\ARM_CM4_MPU\fiber_port.c",
        "fiber\port\ARM_CM4_MPU\fiber_port_boot.c"
    )
    $forwardAbiSymbols = @(
        "fiber_port_context_init",
        "fiber_port_runtime_memory_barrier",
        "fiber_port_panic_wait",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_runtime_schedule"
    )
    $counterFlags = @(
        "-fno-instrument-functions",
        "-fno-stack-protector",
        "-fno-profile-arcs",
        "-fno-test-coverage",
        "-fno-sanitize=all",
        "-mgeneral-regs-only"
    )
    $variants = @(
        [pscustomobject]@{ Name = "m4-r8"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 4; Regions = 8 },
        [pscustomobject]@{ Name = "m4-r16"; Cpu = "cortex-m4"; Fpu = "fpv4-sp-d16"; Core = 4; Regions = 16 },
        [pscustomobject]@{ Name = "m7-r8"; Cpu = "cortex-m7"; Fpu = "fpv5-d16"; Core = 7; Regions = 8 },
        [pscustomobject]@{ Name = "m7-r16"; Cpu = "cortex-m7"; Fpu = "fpv5-d16"; Core = 7; Regions = 16 }
    )

    foreach ($variant in $variants) {
        foreach ($useLto in @($false, $true)) {
            $mode = if ($useLto) { "lto" } else { "normal" }
            $probeDir = Join-Path $BuildRoot `
                "arm-cm4-mpu-runtime-$($variant.Name)-$mode"
            New-Item -ItemType Directory -Path $probeDir | Out-Null
            Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
                -Value "#ifndef MAIN_H_`n#define MAIN_H_`n#endif`n" `
                -Encoding ASCII

            $manifestDefines = @(
                "-DFIBER_PORT_BUILD_SELECTED=1",
                "-DFIBER_PORT_ARMV7EM=1",
                "-D__CORTEX_M=$($variant.Core)",
                "-D__MPU_PRESENT=1",
                "-D__VTOR_PRESENT=1",
                "-D__FPU_PRESENT=1",
                "-D__FPU_USED=1",
                "-D__NVIC_PRIO_BITS=4",
                "-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=$($variant.Regions)"
            )
            $ltoArgs = if ($useLto) { @("-flto") } else { @() }
            $stackUsageArgs = if ($useLto) { @() } else { @("-fstack-usage") }
            $baseArgs = @(
                "-mcpu=$($variant.Cpu)",
                "-mthumb",
                "-mfpu=$($variant.Fpu)",
                "-mfloat-abi=hard",
                "-O2",
                "-std=gnu11",
                "-ffreestanding",
                "-fno-common",
                "-fno-builtin",
                "-ffunction-sections",
                "-fdata-sections",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wundef",
                "-Werror=undef",
                "-I$profileDir",
                "-I$(Join-Path $RepositoryRoot 'fiber\port')",
                "-I$(Join-Path $RepositoryRoot 'fiber')",
                "-I$RepositoryRoot",
                "-I$CmsisPath",
                "-I$probeDir"
            ) + $manifestDefines + $ltoArgs

            $archiveObjects = @()
            foreach ($source in ($commonSources + $portSources)) {
                $object = Join-Path $probeDir `
                    (($source -replace '[\\/]', '_') + ".o")
                $sourcePath = Join-Path $RepositoryRoot $source
                $extraFlags = if ($portSources -contains $source) {
                    $counterFlags
                }
                else {
                    @()
                }
                & $Compiler @($baseArgs + $stackUsageArgs + $extraFlags + @(
                    "-c", $sourcePath, "-o", $object))
                if ($LASTEXITCODE -ne 0) {
                    throw "ARM_CM4_MPU runtime archive compile failed ($($variant.Name)/$mode): $source"
                }
                $archiveObjects += $object
            }

            $startupObject = Join-Path $probeDir "startup.o"
            $portableObject = Join-Path $probeDir "portable.o"
            $expectationObject = Join-Path $probeDir "expectation.o"
            foreach ($compile in @(
                    [pscustomobject]@{ Source = $startupSource; Object = $startupObject; Name = "startup" },
                    [pscustomobject]@{ Source = $portableSource; Object = $portableObject; Name = "portable application" },
                    [pscustomobject]@{ Source = $expectationSource; Object = $expectationObject; Name = "cohort expectation" })) {
                $fixtureArgs = $baseArgs
                if ($useLto -and ($compile.Name -eq "portable application")) {
                    $fixtureArgs = @($baseArgs | Where-Object { $_ -ne "-flto" })
                    $fixtureArgs += "-fno-lto"
                }
                & $Compiler @($fixtureArgs + $counterFlags + @(
                    "-c", $compile.Source, "-o", $compile.Object))
                if ($LASTEXITCODE -ne 0) {
                    throw "ARM_CM4_MPU $($compile.Name) compile failed ($($variant.Name)/$mode)"
                }
            }

            $objectNm = if ($useLto) { $GccNm } else { $Nm }
            $expectationUndefined = @(& $objectNm --undefined-only `
                $expectationObject)
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM4_MPU expectation nm failed ($($variant.Name)/$mode)"
            }
            $expectedCohortLines = @($expectationUndefined | Where-Object {
                $_ -match '\bU\s+fiber_port_context_cohort_armv7em_\S+$'
            })
            if ($expectedCohortLines.Count -ne 1) {
                throw "ARM_CM4_MPU expectation must retain one exact cohort relocation ($($variant.Name)/$mode)"
            }
            $null = $expectedCohortLines[0] -match `
                '\bU\s+(fiber_port_context_cohort_armv7em_\S+)$'
            $expectedCohort = $Matches[1]

            $archivePath = Join-Path $probeDir `
                "libfiber-arm-cm4-mpu-$($variant.Name).a"
            & $Ar rcs $archivePath @archiveObjects
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM4_MPU runtime archive creation failed ($($variant.Name)/$mode)"
            }

            $elfPath = Join-Path $probeDir `
                "fiber-arm-cm4-mpu-$($variant.Name).elf"
            $mapPath = Join-Path $probeDir `
                "fiber-arm-cm4-mpu-$($variant.Name).map"
            $linkArgs = @(
                "-mcpu=$($variant.Cpu)",
                "-mthumb",
                "-mfpu=$($variant.Fpu)",
                "-mfloat-abi=hard"
            ) + $ltoArgs + @(
                "-nostdlib",
                "-Wl,--gc-sections",
                "-Wl,-Map,$mapPath",
                "-Wl,-T,$linkerScript",
                $startupObject,
                $portableObject,
                $expectationObject,
                $archivePath,
                "-o", $elfPath
            )
            & $Compiler @linkArgs
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM4_MPU portable archive/link integration failed ($($variant.Name)/$mode)"
            }

            $defined = @(& $Nm -a --defined-only $elfPath)
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM4_MPU final ELF nm failed ($($variant.Name)/$mode)"
            }
            foreach ($symbol in $forwardAbiSymbols) {
                $definitions = @($defined | Where-Object {
                    $_ -match ("\bT\s+" + [regex]::Escape($symbol) + "$")
                })
                if ($definitions.Count -ne 1) {
                    throw "ARM_CM4_MPU final ELF must define one strong forward ABI symbol ($($variant.Name)/$mode): $symbol"
                }
            }

            $cohortDefinitions = @($defined | Where-Object {
                $_ -match ('\b[RT]\s+' + [regex]::Escape($expectedCohort) + '$')
            })
            if ($cohortDefinitions.Count -ne 1) {
                throw "ARM_CM4_MPU final ELF does not satisfy its exact cohort expectation ($($variant.Name)/$mode)"
            }

            $svcAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
                -Symbol "SVC_Handler" -Path $elfPath
            $pendsvAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
                -Symbol "PendSV_Handler" -Path $elfPath

            $symbolRanges = @(
                [pscustomobject]@{
                    Start = [uint32]0x08010000
                    End = [uint32]0x08020000
                    Name = "unprivileged code"
                    Symbols = @(
                        "fiber_current",
                        "fiber_schedule",
                        "fiber_internal_runtime_load_current_context",
                        "fiber_port_runtime_memory_barrier",
                        "fiber_port_runtime_schedule",
                        "fiber_port_unprivileged_task_return"
                    )
                },
                [pscustomobject]@{
                    Start = [uint32]0x08000000
                    End = [uint32]0x08010000
                    Name = "privileged code"
                    Symbols = @(
                        "fiber_init",
                        "fiber_start",
                        "fiber_scheduler_set_pick_next",
                        "fiber_internal_runtime_select_scheduler_candidate",
                        "fiber_internal_runtime_publish_current_context",
                        "fiber_internal_runtime_require_current_context",
                        "fiber_internal_task_return",
                        "fiber_panic",
                        "fiber_port_context_init",
                        "fiber_port_panic_wait",
                        "fiber_port_require_scheduler_configuration_environment",
                        "fiber_port_runtime_prepare_start",
                        "fiber_port_runtime_select_first",
                        "fiber_port_runtime_start_first",
                        "portable_fixture_pick_next",
                        "SVC_Handler",
                        "PendSV_Handler"
                    )
                }
            )
            foreach ($range in $symbolRanges) {
                foreach ($symbol in $range.Symbols) {
                    $lines = @($defined | Where-Object {
                        $_ -match ("^\s*(?<address>[0-9a-fA-F]+)\s+[TtWw]\s+" +
                            [regex]::Escape($symbol) + "$")
                    })
                    if ($lines.Count -ne 1) {
                        throw "ARM_CM4_MPU ELF lost range-audited symbol ($($variant.Name)/$mode): $symbol"
                    }
                    $null = $lines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
                    $address = [Convert]::ToUInt32($Matches['address'], 16)
                    if (($address -lt $range.Start) -or
                            ($address -ge $range.End)) {
                        throw "ARM_CM4_MPU symbol escaped $($range.Name) ($($variant.Name)/$mode): $symbol at 0x$($address.ToString('X8'))"
                    }
                }
            }

            $portableEntryLines = @($defined | Where-Object {
                $_ -match '^\s*(?<address>[0-9a-fA-F]+)\s+[Tt]\s+portable_fixture_entry(\.\S+)?$'
            })
            if ($portableEntryLines.Count -ne 1) {
                throw "ARM_CM4_MPU portable entry must survive in one unprivileged section ($($variant.Name)/$mode)"
            }
            $null = $portableEntryLines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
            $portableEntryAddress = [Convert]::ToUInt32($Matches['address'], 16)
            if (($portableEntryAddress -lt 0x08010000) -or
                    ($portableEntryAddress -ge 0x08020000)) {
                throw "ARM_CM4_MPU portable entry is not unprivileged executable code ($($variant.Name)/$mode)"
            }

            foreach ($stack in @("portable_fixture_stack_1",
                    "portable_fixture_stack_2")) {
                $stackLines = @($defined | Where-Object {
                    $_ -match ("^\s*(?<address>[0-9a-fA-F]+)\s+[Bb]\s+" +
                        [regex]::Escape($stack) + "$")
                })
                if ($stackLines.Count -ne 1) {
                    throw "ARM_CM4_MPU portable stack symbol is missing ($($variant.Name)/$mode): $stack"
                }
                $null = $stackLines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
                $stackAddress = [Convert]::ToUInt32($Matches['address'], 16)
                if (($stackAddress -lt 0x20020000) -or
                        ($stackAddress -ge 0x20030000) -or
                        (($stackAddress -band 0x7FF) -ne 0)) {
                    throw "ARM_CM4_MPU portable stack escaped exact MPU geometry ($($variant.Name)/$mode): $stack"
                }
            }
            foreach ($privilegedObject in @("portable_fixture_context_1",
                    "portable_fixture_context_2",
                    "portable_fixture_scheduler_user")) {
                $objectLines = @($defined | Where-Object {
                    $_ -match ("^\s*(?<address>[0-9a-fA-F]+)\s+[Bb]\s+" +
                        [regex]::Escape($privilegedObject) + "$")
                })
                if ($objectLines.Count -ne 1) {
                    throw "ARM_CM4_MPU privileged application object is missing ($($variant.Name)/$mode): $privilegedObject"
                }
                $null = $objectLines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
                $objectAddress = [Convert]::ToUInt32($Matches['address'], 16)
                if (($objectAddress -lt 0x20010000) -or
                        ($objectAddress -ge 0x20020000)) {
                    throw "ARM_CM4_MPU application object escaped privileged data ($($variant.Name)/$mode): $privilegedObject"
                }
            }

            $slotLines = @($defined | Where-Object {
                $_ -match '^\s*20000000\s+[Bb]\s+fiber_internal_runtime_current_context_slot$'
            })
            if ($slotLines.Count -ne 1) {
                throw "ARM_CM4_MPU current slot escaped its exact 32-byte aperture ($($variant.Name)/$mode)"
            }

            $sections = (& $Objdump -h $elfPath) -join "`n"
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM4_MPU final ELF section audit failed ($($variant.Name)/$mode)"
            }
            foreach ($requiredSection in @(
                    '\.isr_vector\s+00000040\s+08000000\s+',
                    '\.fiber_unprivileged_code\s+[0-9a-fA-F]+\s+08010000\s+',
                    '\.fiber_privileged_code\s+[0-9a-fA-F]+\s+08000040\s+',
                    '\.fiber_current_context_slot\s+00000020\s+20000000\s+',
                    '\.fiber_unprivileged_ram\s+[0-9a-fA-F]+\s+20020000\s+',
                    '\.fiber_privileged_data\s+[0-9a-fA-F]+\s+20010000\s+')) {
                if ($sections -notmatch $requiredSection) {
                    throw "ARM_CM4_MPU final ELF lost exact MPU section ($($variant.Name)/$mode): $requiredSection"
                }
            }

            $vectorPath = Join-Path $probeDir "vectors.bin"
            & $Objcopy -O binary --only-section=.isr_vector $elfPath $vectorPath
            if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $vectorPath))) {
                throw "ARM_CM4_MPU runtime vector extraction failed ($($variant.Name)/$mode)"
            }
            $vectorBytes = [IO.File]::ReadAllBytes($vectorPath)
            if ($vectorBytes.Length -ne 64) {
                throw "ARM_CM4_MPU runtime vector fixture changed size ($($variant.Name)/$mode)"
            }
            if ([BitConverter]::ToUInt32($vectorBytes, 11 * 4) -ne
                    ($svcAddress -bor 1)) {
                throw "ARM_CM4_MPU vector slot 11 lost strong SVC ($($variant.Name)/$mode)"
            }
            if ([BitConverter]::ToUInt32($vectorBytes, 14 * 4) -ne
                    ($pendsvAddress -bor 1)) {
                throw "ARM_CM4_MPU vector slot 14 lost strong PendSV ($($variant.Name)/$mode)"
            }

            if (-not $useLto) {
                $stackUsageFiles = @(Get-ChildItem -LiteralPath $probeDir `
                    -Filter "*.su" -File)
                if ($stackUsageFiles.Count -lt $archiveObjects.Count) {
                    throw "ARM_CM4_MPU runtime proof lost stack-usage artifacts ($($variant.Name))"
                }
                foreach ($stackUsageFile in $stackUsageFiles) {
                    $stackUsage = Get-Content -LiteralPath `
                        $stackUsageFile.FullName -Raw
                    if ($stackUsage -match '(?m)\bdynamic\b') {
                        throw "ARM_CM4_MPU runtime acquired dynamic stack use: $($stackUsageFile.Name)"
                    }
                }
            }

            if ($variant.Name -eq "m4-r8") {
                $competingSource = Join-Path $probeDir "competing.c"
                $competingObject = Join-Path $probeDir "competing.o"
                Set-Content -LiteralPath $competingSource -Encoding ASCII `
                    -Value "void SVC_Handler(void) { }`nvoid PendSV_Handler(void) { }`n"
                & $Compiler @($baseArgs + @(
                    "-c", $competingSource, "-o", $competingObject))
                if ($LASTEXITCODE -ne 0) {
                    throw "ARM_CM4_MPU competing-handler fixture failed compile ($mode)"
                }
                $duplicateLog = Join-Path $probeDir "duplicate.log"
                $duplicateArgs = @($linkArgs[0..($linkArgs.Count - 3)] + @(
                    $competingObject, "-o", (Join-Path $probeDir "duplicate.elf")))
                $duplicate = Invoke-CompilerProbe -Compiler $Compiler `
                    -Arguments $duplicateArgs -LogPath $duplicateLog
                if (($duplicate.ExitCode -eq 0) -or
                        ($duplicate.Output -notmatch 'multiple definition')) {
                    throw "ARM_CM4_MPU competing strong handlers must fail link ($mode)`n$($duplicate.Output)"
                }
            }
        }
    }
}

function Test-ArmCm0MpuLayoutContract {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$Objdump,
        [string]$Objcopy,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileRelative = "fiber\port\ARM_CM0_MPU"
    $profileDir = Join-Path $RepositoryRoot $profileRelative
    $probeSource = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm0_mpu_layout_probe.c"
    $bootProbeSource = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm0_mpu_boot_probe.c"
    $bootSource = Join-Path $profileDir "fiber_port_boot.c"
    $runtimeSource = Join-Path $profileDir "fiber_port.c"
    $linkerContractPath = Join-Path $profileDir "fiber_port_linker_contract.ld"
    $runtimeStateSource = Join-Path $RepositoryRoot "fiber\fiber_runtime_state.c"
    $linkerBoundarySymbols = @(
        "__fiber_mpu_unprivileged_code_start__",
        "__fiber_mpu_unprivileged_code_end__",
        "__fiber_mpu_privileged_code_start__",
        "__fiber_mpu_privileged_code_end__",
        "__fiber_mpu_privileged_data_start__",
        "__fiber_mpu_privileged_data_end__",
        "__fiber_mpu_current_context_slot_start__",
        "__fiber_mpu_current_context_slot_end__",
        "__fiber_mpu_unprivileged_ram_start__",
        "__fiber_mpu_unprivileged_ram_end__"
    )
    $probeDir = Join-Path $BuildRoot "arm-cm0-mpu-layout"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
        -Value "#ifndef MAIN_H_`n#define MAIN_H_`n#endif`n" -Encoding ASCII
    $warningArgs = @(
        "-ffreestanding",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wundef",
        "-Werror=undef",
        "-Werror=implicit-function-declaration",
        "-Werror=return-type"
    )

    foreach ($requiredFile in @(
            "FREERTOS_PARITY.md",
            "fiber_port_boot_types.h",
            "fiber_port_types.h",
            "fiber_portmacro.h",
            "fiber_port_boot.h",
            "fiber_port_boot.c",
            "fiber_port_private.h",
            "fiber_port.c",
            "fiber_port_linker_contract.ld")) {
        if (-not (Test-Path (Join-Path $profileDir $requiredFile))) {
            throw "ARM_CM0_MPU slice 6 is missing required file: $requiredFile"
        }
    }
    if (-not (Test-Path $bootProbeSource)) {
        throw "ARM_CM0_MPU slice 6 is missing its linker/global-image fixture"
    }
    if (-not (Test-Path $runtimeStateSource)) {
        throw "ARM_CM0_MPU linker proof is missing common runtime state"
    }
    $linkerContractText = Get-Content -LiteralPath $linkerContractPath -Raw
    foreach ($boundarySymbol in $linkerBoundarySymbols) {
        if ($linkerContractText.IndexOf("ASSERT(DEFINED($boundarySymbol)",
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM0_MPU linker contract lost required boundary assertion: $boundarySymbol"
        }
    }
    foreach ($requiredLinkerText in @(
            "current-slot aperture must be exactly 256 bytes",
			"current-slot output section must begin at its aperture",
			"current-slot output section must be exactly 256 bytes",
			"current-slot aperture overlaps unprivileged code",
			"current-slot aperture overlaps privileged code",
            "unprivileged code must be an exact MPU region",
            "privileged code must be an exact MPU region",
            "privileged data must be an exact MPU region",
            "unprivileged RAM must be non-empty and 256-byte aligned",
            "privileged code may only be disjoint or nested in unprivileged code")) {
        if ($linkerContractText.IndexOf($requiredLinkerText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM0_MPU linker contract lost mandatory rule: $requiredLinkerText"
        }
    }

    foreach ($forbiddenRuntimeFile in @("fiber_port_exception.c")) {
        if (Test-Path (Join-Path $profileDir $forbiddenRuntimeFile)) {
            throw "ARM_CM0_MPU slice 6 keeps protected runtime in fiber_port.c: $forbiddenRuntimeFile"
        }
    }

    $bootSourceText = Get-Content -LiteralPath $bootSource -Raw
    $runtimeSourceText = Get-Content -LiteralPath $runtimeSource -Raw
    $macroSourceText = Get-Content -LiteralPath (Join-Path $profileDir `
        "fiber_portmacro.h") -Raw
    foreach ($requiredText in @(
            "void fiber_port_context_init(",
            "void fiber_port_context_seal_check(",
            "uint32_t fiber_port_context_compute_seal(",
            "int fiber_port_mpu_try_encode_exact_region(",
			"void fiber_port_mpu_load_linker_layout(",
			"void fiber_port_mpu_linker_layout_check(",
			"void fiber_port_mpu_build_global_regions(",
            "FIBER_PORT_CONTEXT_COHORT_RETAIN();",
			"void fiber_port_context_initial_image_check(",
			"const uint32_t initial_r9 = fiber_port_read_r9();",
            "ctx->protected_context.r4 = 0u;",
			"ctx->protected_context.r5 = 0u;",
			"ctx->protected_context.r6 = 0u;",
			"ctx->protected_context.r7 = 0u;",
            "ctx->protected_context.r8 = 0u;",
			"ctx->protected_context.r9 = initial_r9;",
			"ctx->protected_context.r10 = 0u;",
            "ctx->protected_context.r11 = 0u;",
            "ctx->protected_context.r0 = (uint32_t)(uintptr_t)arg;",
			"ctx->protected_context.r1 = 0u;",
			"ctx->protected_context.r2 = 0u;",
			"ctx->protected_context.r3 = 0u;",
            "ctx->protected_context.r12 = 0u;",
            "ctx->protected_context.lr =",
            "ctx->protected_context.pc =",
            "ctx->protected_context.xpsr = fiber_portINITIAL_XPSR;",
            "ctx->protected_context.psp = (uint32_t)initial_psp;",
            "ctx->protected_context.control = fiber_portINITIAL_CONTROL_UNPRIVILEGED;",
            "ctx->protected_context.exc_return = fiber_portINITIAL_EXC_RETURN;",
            "ctx->protected_context_cursor = &ctx->protected_context.cursor_limit;",
            "ctx->mpu_regions[fiber_portMPU_STACK_REGION] = stack_region;",
			"fiber_portMPU_DEFAULT_STACK_ATTRIBUTES",
			"fiber_portMPU_CURRENT_CONTEXT_APERTURE_BYTES",
			"__fiber_mpu_unprivileged_code_start__",
			"__fiber_mpu_privileged_data_end__",
			"fiber_port_context_initial_image_check(ctx, initial_psp, entry_address, arg,")) {
        if ($bootSourceText.IndexOf($requiredText,
                [System.StringComparison]::Ordinal) -lt 0) {
                throw "ARM_CM0_MPU slice 6 lost required construction behavior: $requiredText"
        }
    }
    if ($macroSourceText.IndexOf("uint32_t fiber_port_read_r9(void)",
            [System.StringComparison]::Ordinal) -lt 0) {
        throw "ARM_CM0_MPU slice 6 lost its live-r9 initial-context helper"
    }
	foreach ($requiredInitialRestoreText in @(
			"void fiber_port_context_validate_initial_restore(const FiberContext *ctx)",
			"image->r8 == 0u && image->r9 == fiber_port_read_r9()")) {
		if ($bootSourceText.IndexOf($requiredInitialRestoreText,
				[System.StringComparison]::Ordinal) -lt 0) {
			throw "ARM_CM0_MPU slice 6 lost complete first-image validation: $requiredInitialRestoreText"
		}
	}
	foreach ($requiredMacroText in @(
			"fiber_portPRIVILEGED_FUNCTION",
			"fiber_portUNPRIVILEGED_FUNCTION",
			"fiber_portPRIVILEGED_DATA",
			"fiber_portMPU_CURRENT_CONTEXT_APERTURE_BYTES",
			"current-context aperture must be one MPU region")) {
		if ($macroSourceText.IndexOf($requiredMacroText,
				[System.StringComparison]::Ordinal) -lt 0) {
			throw "ARM_CM0_MPU linker slice lost section or aperture policy: $requiredMacroText"
		}
	}
    foreach ($forbiddenText in @("MPU->")) {
        if ($bootSourceText.IndexOf($forbiddenText,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM0_MPU slice 6 boot object crossed its staged boundary: $forbiddenText"
        }
    }
    foreach ($requiredRuntimeText in @(
            "void fiber_port_runtime_memory_barrier(void)",
            "void fiber_port_panic_wait(void)",
            "void fiber_port_require_scheduler_configuration_environment(void)",
            "void fiber_port_runtime_prepare_start(void)",
            "FiberContext *fiber_port_runtime_select_first(void)",
            "void fiber_port_runtime_start_first(FiberContext *first)",
			"void fiber_port_svc_dispatch(uint32_t *hardware_frame,",
			"void fiber_port_start_first_context(FiberContext *first",
			"void fiber_port_restore_first_context_from_svc(",
			"void fiber_port_unprivileged_task_return(void)",
			"void fiber_port_runtime_schedule(void)",
			"void SVC_Handler(void)",
			"void PendSV_Handler(void)",
			"fiber_port_mpu_activate_first_context(current);",
            "fiber_port_mpu_validate_active_context(first);",
            "fiber_portSVC_START",
			"fiber_portSVC_YIELD",
			"fiber_port_pendsv_validate_save_current",
			"fiber_port_scheduler_pick_next_from_pendsv",
			"fiber_port_mpu_switch_to_context",
			"void fiber_port_capture_scheduler_mpu_image(",
			"void fiber_port_validate_scheduler_mpu_image(",
			"mpu_regions[fiber_portMPU_TOTAL_REGIONS]",
			"fiber_port_capture_scheduler_mpu_image(state);",
			"fiber_port_validate_scheduler_mpu_image(before);",
			"state->pendsv_pending = fiber_portNVIC_INT_CTRL_REG",
			"fiber_portNVIC_PENDSVSET_BIT) == before->pendsv_pending",
            "fiber_portSVC_RETURN")) {
        if ($runtimeSourceText.IndexOf($requiredRuntimeText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM0_MPU slice 6 lost required protected-switch behavior: $requiredRuntimeText"
        }
    }

    foreach ($selectorPath in @(
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h"))) {
        $selectorSource = Get-Content -LiteralPath $selectorPath -Raw
        if ($selectorSource.IndexOf("ARM_CM0_MPU",
                [System.StringComparison]::Ordinal) -ge 0) {
		throw "ARM_CM0_MPU slice 6 must not enter architecture selection: $selectorPath"
        }
    }

    $typeSource = Join-Path $probeDir "type-only.c"
    $typeObject = Join-Path $probeDir "type-only.o"
    $typeText = @"
#include <stddef.h>
#include "fiber_port_types.h"

_Static_assert(offsetof(FiberContext, protected_context_cursor) == 0u,
    "[fiber]: ARM_CM0_MPU cursor offset changed");
_Static_assert(offsetof(FiberContext, mpu_regions) == 4u,
    "[fiber]: ARM_CM0_MPU MPU image offset changed");
_Static_assert(offsetof(FiberContext, protected_context) == 36u,
    "[fiber]: ARM_CM0_MPU protected context offset changed");
_Static_assert(offsetof(FiberContext, runtime_flags) == 116u,
    "[fiber]: ARM_CM0_MPU runtime flags offset changed");
_Static_assert(offsetof(FiberContext, boot) == 120u,
    "[fiber]: ARM_CM0_MPU boot offset changed");
_Static_assert(sizeof(FiberPortProtectedContext) == 80u,
    "[fiber]: ARM_CM0_MPU protected image changed");
_Static_assert(sizeof(FiberPortBoot) == 88u,
    "[fiber]: ARM_CM0_MPU boot record changed");
_Static_assert(sizeof(FiberContext) == 208u,
    "[fiber]: ARM_CM0_MPU context size changed");
_Static_assert(_Alignof(FiberContext) == 8u,
    "[fiber]: ARM_CM0_MPU context alignment changed");

int fiber_arm_cm0_mpu_type_only_probe(void)
{
    return 0;
}
"@
    Set-Content -LiteralPath $typeSource -Value $typeText -Encoding ASCII

    $typeIncludeArgs = @(
        "-I$profileDir",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot"
    )
    $manifestIncludeArgs = @(
        "-I$probeDir",
        "-I$profileDir",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot",
        "-I$CmsisPath"
    )
    $typeArgs = @(
        "-mcpu=cortex-m0plus",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu11"
    ) + $warningArgs + $typeIncludeArgs + @(
        "-c", $typeSource,
        "-o", $typeObject
    )
    & $Compiler @typeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM0_MPU type-only header failed without CMSIS"
    }

    $selectedFacadeSource = Join-Path $probeDir "selected-facade.c"
    $selectedFacadeObject = Join-Path $probeDir "selected-facade.o"
    $selectedFacadeText = @"
#include <stddef.h>
#include "fiber/fiber_core.h"

_Static_assert(offsetof(FiberContext, protected_context_cursor) == 0u,
    "[fiber]: ARM_CM0_MPU selected facade lost the protected cursor");
_Static_assert(sizeof(FiberContext) == 208u,
    "[fiber]: ARM_CM0_MPU selected facade lost exact context layout");

int fiber_arm_cm0_mpu_selected_facade_probe(void)
{
    return 0;
}
"@
    Set-Content -LiteralPath $selectedFacadeSource -Value $selectedFacadeText `
        -Encoding ASCII
    $selectedFacadeDefines = @(
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV6M=1",
        "-D__CORTEX_M=0",
        "-D__MPU_PRESENT=1",
        "-D__VTOR_PRESENT=1",
        "-D__FPU_PRESENT=0",
        "-D__FPU_USED=0",
        "-D__NVIC_PRIO_BITS=2"
    )
    $selectedFacadeArgs = @(
        "-mcpu=cortex-m0plus",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu11"
    ) + $warningArgs + $selectedFacadeDefines + $manifestIncludeArgs + @(
        "-c", $selectedFacadeSource,
        "-o", $selectedFacadeObject
    )
    & $Compiler @selectedFacadeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM0_MPU build-selected public facade failed compile"
    }
    $selectedFacadePreprocessorArgs = @(
        "-mcpu=cortex-m0plus",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu11"
    ) + $warningArgs + $selectedFacadeDefines + $manifestIncludeArgs + @(
        "-dM", "-E", $selectedFacadeSource
    )
    $selectedFacadeMacros = (& $Compiler @selectedFacadePreprocessorArgs) -join "`n"
    if (($LASTEXITCODE -ne 0) -or ($selectedFacadeMacros -notmatch
            '(?m)^#define FIBER_PORT_NAME "ARM_CM0_MPU"$')) {
        throw "ARM_CM0_MPU build-selected facade lost its exact diagnostic name"
    }

    $variantCohorts = @{}
    foreach ($variant in @(
            [pscustomobject]@{ Name = "vtor-absent"; Vtor = 0 },
            [pscustomobject]@{ Name = "vtor-present"; Vtor = 1 })) {
        $manifestDefines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV6M=1",
            "-D__CORTEX_M=0",
            "-D__MPU_PRESENT=1",
            "-D__VTOR_PRESENT=$($variant.Vtor)",
            "-D__FPU_PRESENT=0",
            "-D__FPU_USED=0",
            "-D__NVIC_PRIO_BITS=2"
        )
        foreach ($optimization in @("-O2", "-Os")) {
            $mode = $optimization.Substring(1).ToLowerInvariant()
            $layoutObject = Join-Path $probeDir `
                ("layout-" + $variant.Name + "-" + $mode + ".o")
            $layoutArgs = @(
                "-mcpu=cortex-m0plus",
                "-mthumb",
                "-mfloat-abi=soft",
                "-std=gnu11",
                $optimization
            ) + $warningArgs + $manifestDefines + $manifestIncludeArgs + @(
                "-c", $probeSource,
                "-o", $layoutObject
            )
            & $Compiler @layoutArgs
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM0_MPU exact layout manifest failed compile ($($variant.Name)/$mode)"
            }

            $nmOutput = & $Nm --defined-only $layoutObject
            if ($LASTEXITCODE -ne 0) {
                throw "nm failed for ARM_CM0_MPU layout probe ($($variant.Name)/$mode)"
            }
            $cohorts = @($nmOutput | ForEach-Object {
                if ($_ -match '\b(?<symbol>fiber_port_context_cohort_\S+)$') {
                    $Matches['symbol']
                }
            })
            if ($cohorts.Count -ne 1) {
                throw "ARM_CM0_MPU layout probe must define exactly one cohort ($($variant.Name)/$mode)"
            }
            $expectedPrefix = "fiber_port_context_cohort_armv6m_p0x434D304Du_l0x00010001u_"
            if (-not $cohorts[0].StartsWith($expectedPrefix,
                    [System.StringComparison]::Ordinal)) {
                throw "ARM_CM0_MPU cohort identity mismatch ($($variant.Name)/$mode): $($cohorts[0])"
            }
            $expectedVtorToken = "_v$($variant.Vtor)_"
            if ($cohorts[0].IndexOf($expectedVtorToken,
                    [System.StringComparison]::Ordinal) -lt 0) {
                throw "ARM_CM0_MPU cohort lost its VTOR fact ($($variant.Name)/$mode): $($cohorts[0])"
            }
            $variantCohorts["$($variant.Name)-$mode"] = $cohorts[0]
        }
    }

    foreach ($mode in @("o2", "os")) {
        if ($variantCohorts["vtor-absent-$mode"] -eq
                $variantCohorts["vtor-present-$mode"]) {
            throw "ARM_CM0_MPU VTOR-present and VTOR-absent manifests collapsed one cohort ($mode)"
        }
    }

    foreach ($optimization in @("-O2", "-Os")) {
        $mode = $optimization.Substring(1).ToLowerInvariant()
        $bootObject = Join-Path $probeDir ("boot-" + $mode + ".o")
		$runtimeObject = Join-Path $probeDir ("runtime-" + $mode + ".o")
        $bootProbeObject = Join-Path $probeDir ("boot-probe-" + $mode + ".o")
        $runtimeStateObject = Join-Path $probeDir ("runtime-state-" + $mode + ".o")
        $linkerScript = Join-Path $probeDir ("linker-" + $mode + ".ld")
        $bootElf = Join-Path $probeDir ("boot-" + $mode + ".elf")
        $sliceCompileArgs = @(
            "-mcpu=cortex-m0plus",
            "-mthumb",
            "-mfloat-abi=soft",
            "-std=gnu11",
            $optimization,
            "-ffunction-sections",
            "-fdata-sections",
            "-save-temps=obj",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables"
        ) + $warningArgs + $selectedFacadeDefines + $manifestIncludeArgs

        foreach ($compileUnit in @(
                [pscustomobject]@{ Source = $bootSource; Object = $bootObject; Label = "source" },
				[pscustomobject]@{ Source = $runtimeSource; Object = $runtimeObject; Label = "first-start runtime" },
                [pscustomobject]@{ Source = $bootProbeSource; Object = $bootProbeObject; Label = "fixture" },
                [pscustomobject]@{ Source = $runtimeStateSource; Object = $runtimeStateObject; Label = "common runtime state" })) {
            & $Compiler @($sliceCompileArgs + @(
                "-c", $compileUnit.Source,
                "-o", $compileUnit.Object
            ))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM0_MPU slice-6 linker/global-image $($compileUnit.Label) failed compile ($mode)"
            }
        }

        $bootDisassembly = (& $Objdump -dr $bootObject) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for ARM_CM0_MPU linker/global-image source ($mode)"
        }
        foreach ($functionName in @(
                "fiber_port_context_init",
                "fiber_port_mpu_build_global_regions")) {
            $functionBody = Get-DisassemblyFunctionBody `
                -Disassembly $bootDisassembly -Symbol $functionName `
                -Path $bootObject
            if ($functionBody -match '\b(svc|cpsid|cpsie|mrs|msr)\b') {
                throw "ARM_CM0_MPU slice-6 $functionName must build/check storage only, not change CPU state ($mode)"
            }
        }

		$runtimeDisassembly = (& $Objdump -dr $runtimeObject) -join "`n"
		if ($LASTEXITCODE -ne 0) {
			throw "objdump failed for ARM_CM0_MPU first-start runtime ($mode)"
		}
		$startBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
			-Symbol "fiber_port_start_first_context" -Path $runtimeObject
		$restoreBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
			-Symbol "fiber_port_restore_first_context_from_svc" -Path $runtimeObject
		$svcBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
			-Symbol "SVC_Handler" -Path $runtimeObject
		$returnBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
			-Symbol "fiber_port_unprivileged_task_return" -Path $runtimeObject
		$yieldBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
			-Symbol "fiber_port_runtime_schedule" -Path $runtimeObject
		$pendsvBody = Get-DisassemblyFunctionBody -Disassembly $runtimeDisassembly `
			-Symbol "PendSV_Handler" -Path $runtimeObject
		foreach ($requiredStartInstruction in @("cpsid", "svc", "70")) {
			if ($startBody.IndexOf($requiredStartInstruction,
					[System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
				throw "ARM_CM0_MPU first-start assembly lost $requiredStartInstruction ($mode)"
			}
		}
		if ($startBody -match "fiber_port_runtime_prepare_start") {
			throw "ARM_CM0_MPU first-start assembly must not repeat common start preparation ($mode)"
		}
		if ($startBody -match '(?i)\bmsr\s+msp\b') {
			throw "ARM_CM0_MPU first-start must preserve FreeRTOS ARM_CM0 no-MSP-rewind behavior ($mode)"
		}
		# objdump may print r10/r11 through their conventional aliases sl/fp.
		# Match the architectural transfer sequence rather than one spelling.
		foreach ($requiredRestorePattern in @(
			'(?i)\bmsr\s+PSP\b',
			'(?i)\bmsr\s+CONTROL\b',
			'(?i)\bldmia\s+r1!?,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
			'(?i)\bstmia\s+r2!?,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
			'(?i)\bmov\s+r8,\s*r4\b',
			'(?i)\bmov\s+r9,\s*r5\b',
			'(?i)\bmov\s+(r10|sl),\s*r6\b',
			'(?i)\bmov\s+(r11|fp),\s*r7\b',
			'(?i)\bbx\s+lr\b')) {
			if ($restoreBody -notmatch $requiredRestorePattern) {
				throw "ARM_CM0_MPU Thumb-1 first restore lost $requiredRestorePattern ($mode)"
			}
		}
		if ($restoreBody -match '(?i)\b(ldmdb|stmdb|vpush|vpop|vldm|vstm)\b') {
			throw "ARM_CM0_MPU first restore acquired a non-ARMv6-M instruction ($mode)"
		}
		foreach ($requiredSvcInstruction in @("mrs", "msp", "psp",
			"fiber_internal_runtime_current_context_slot", "fiber_port_svc_dispatch")) {
			if ($svcBody.IndexOf($requiredSvcInstruction,
					[System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
				throw "ARM_CM0_MPU SVC handler lost $requiredSvcInstruction ($mode)"
			}
		}
		if (($returnBody -notmatch '(?i)\bsvc\b.*\b72\b') -or
			($returnBody -match '(?i)\b(msr|mrs|str|stmia|stmdb)\b')) {
			throw "ARM_CM0_MPU unprivileged return veneer is not one SVC-only route ($mode)"
		}
		if (($yieldBody -notmatch '(?i)\bsvc\b.*\b71\b') -or
			($yieldBody -match '(?i)\b(msr|mrs|str|stmia|stmdb)\b')) {
			throw "ARM_CM0_MPU unprivileged yield veneer is not one SVC-only route ($mode)"
		}
		foreach ($requiredPendSvPattern in @(
			'(?i)\bmrs\s+r0,\s*PSP\b',
			'fiber_port_pendsv_validate_save_current',
			'(?i)\bstmia\s+r3!?,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
			'(?i)\bldmia\s+r0!?,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
			'(?i)\bmrs\s+r2,\s*CONTROL\b',
			'(?i)\bcpsid\s+i\b',
			'fiber_port_scheduler_pick_next_from_pendsv',
			'fiber_port_mpu_switch_to_context',
			'(?i)\bmsr\s+PSP\b',
			'(?i)\bmsr\s+CONTROL\b',
			'(?i)\bmov\s+r8,\s*r4\b',
			'(?i)\bmov\s+r9,\s*r5\b',
			'(?i)\bmov\s+(r10|sl),\s*r6\b',
			'(?i)\bmov\s+(r11|fp),\s*r7\b',
			'(?i)\bcpsie\s+i\b',
			'(?i)\bbx\s+lr\b')) {
			if ($pendsvBody -notmatch $requiredPendSvPattern) {
				throw "ARM_CM0_MPU protected Thumb-1 PendSV lost $requiredPendSvPattern ($mode)"
			}
		}
		if ($pendsvBody -match '(?i)\b(ldmdb|stmdb|vpush|vpop|vldm|vstm|basepri)\b') {
			throw "ARM_CM0_MPU protected PendSV acquired a non-ARMv6-M transfer or mask ($mode)"
		}
		# Prove the assembly-loaded current pointer is used only as an opaque
		# argument until the C preflight has validated its protected cursor and
		# immutable metadata. This is deliberately generated-code evidence, not
		# merely an inline-assembly source-text convention.
		$currentSlotLoad = [regex]::Match($pendsvBody,
			'(?im)^\s*[0-9a-f]+:\s+.*\bldr(?:\.w)?\s+r1,\s*\[r1(?:,\s*#0)?\]')
		$savePreflightCall = [regex]::Match($pendsvBody,
			'(?im)^\s*[0-9a-f]+:\s+.*\bbl(?:\.w)?\s+.*<fiber_port_pendsv_validate_save_current>')
		if ((-not $currentSlotLoad.Success) -or
				(-not $savePreflightCall.Success) -or
				($currentSlotLoad.Index -ge $savePreflightCall.Index)) {
			throw "ARM_CM0_MPU PendSV lost the generated current-slot/preflight order ($mode)"
		}
		$preflightPrefixStart = $currentSlotLoad.Index + $currentSlotLoad.Length
		$preflightPrefix = $pendsvBody.Substring($preflightPrefixStart,
			$savePreflightCall.Index - $preflightPrefixStart)
		if ($preflightPrefix -match
				'(?im)\b(?:ldr|str|ldmia|stmia|ldmdb|stmdb)\b[^\r\n]*\[\s*r1(?:\s*,|\s*\])') {
			throw "ARM_CM0_MPU PendSV dereferenced current before its generated preflight ($mode)"
		}
		$firstCursorLoad = [regex]::Match(
			$pendsvBody.Substring($savePreflightCall.Index +
				$savePreflightCall.Length),
			'(?im)^\s*[0-9a-f]+:\s+.*\bldr(?:\.w)?\s+r3,\s*\[r1(?:,\s*#0)?\]')
		if (-not $firstCursorLoad.Success) {
			throw "ARM_CM0_MPU PendSV lost its post-preflight protected cursor load ($mode)"
		}
		$runtimeDefinedOutput = @(& $Nm --defined-only $runtimeObject)
		if ($LASTEXITCODE -ne 0) {
			throw "nm failed for ARM_CM0_MPU first-start runtime ($mode)"
		}
		foreach ($requiredRuntimeSymbol in @(
				"SVC_Handler",
				"PendSV_Handler",
				"fiber_port_runtime_memory_barrier",
				"fiber_port_panic_wait",
				"fiber_port_require_scheduler_configuration_environment",
				"fiber_port_runtime_prepare_start",
				"fiber_port_runtime_select_first",
				"fiber_port_runtime_start_first",
				"fiber_port_runtime_schedule",
				"fiber_port_pendsv_validate_save_current",
				"fiber_port_scheduler_pick_next_from_pendsv",
				"fiber_port_mpu_switch_to_context")) {
			if (-not ($runtimeDefinedOutput -match ("\b" +
					[regex]::Escape($requiredRuntimeSymbol) + "\s*$"))) {
				throw "ARM_CM0_MPU slice 6 runtime lost required symbol ($mode): $requiredRuntimeSymbol"
			}
		}

        $bootSections = @(& $Objdump -h $bootObject)
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for ARM_CM0_MPU privileged source sections ($mode)"
        }
        if (-not ($bootSections -match '(?m)^\s*\d+\s+\.fiber_port_privileged_functions\b')) {
            throw "ARM_CM0_MPU linker/global-image source lost privileged text section ($mode)"
        }
        $bootSymbolTable = @(& $Objdump -t $bootObject)
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for ARM_CM0_MPU privileged source symbols ($mode)"
        }
        $privilegedFunctionCount = 0
        foreach ($line in $bootSymbolTable) {
            if ($line -notmatch '^\s*[0-9a-fA-F]+\s+\w+\s+F\s+(?<section>\S+)\s+[0-9a-fA-F]+\s+(?<symbol>fiber_port_\S+)\s*$') {
                continue
            }
            ++$privilegedFunctionCount
            if ($Matches['section'] -ne '.fiber_port_privileged_functions') {
                throw "ARM_CM0_MPU port function escaped privileged text ($mode): $($Matches['symbol']) -> $($Matches['section'])"
            }
        }
        if ($privilegedFunctionCount -eq 0) {
            throw "ARM_CM0_MPU privileged text proof matched no port functions ($mode)"
        }

		$runtimeSymbolTable = @(& $Objdump -t $runtimeObject)
		if ($LASTEXITCODE -ne 0) {
			throw "objdump failed for ARM_CM0_MPU first-start runtime symbols ($mode)"
		}
		foreach ($runtimeSymbol in @(
				"fiber_port_panic_wait",
				"fiber_port_require_scheduler_configuration_environment",
				"fiber_port_runtime_prepare_start",
				"fiber_port_runtime_select_first",
				"fiber_port_runtime_start_first",
				"fiber_port_svc_dispatch",
				"fiber_port_start_first_context",
				"fiber_port_restore_first_context_from_svc",
				"fiber_port_pendsv_validate_save_current",
				"fiber_port_scheduler_pick_next_from_pendsv",
				"fiber_port_mpu_switch_to_context",
				"SVC_Handler",
				"PendSV_Handler")) {
			$matches = @($runtimeSymbolTable | Where-Object {
				$_ -match ("\bF\s+\.fiber_port_privileged_functions\s+[0-9a-fA-F]+\s+" +
					[regex]::Escape($runtimeSymbol) + "$")
			})
			if ($matches.Count -ne 1) {
				throw "ARM_CM0_MPU privileged first-start symbol escaped its linker section ($mode): $runtimeSymbol"
			}
		}
		foreach ($unprivilegedRuntimeSymbol in @(
				"fiber_port_unprivileged_task_return",
				"fiber_port_runtime_memory_barrier",
				"fiber_port_runtime_schedule")) {
			$unprivilegedMatches = @($runtimeSymbolTable | Where-Object {
				$_ -match ("\bF\s+\.fiber_port_unprivileged_functions\s+[0-9a-fA-F]+\s+" +
					[regex]::Escape($unprivilegedRuntimeSymbol) + "$")
			})
			if ($unprivilegedMatches.Count -ne 1) {
				throw "ARM_CM0_MPU unprivileged runtime symbol escaped its linker section ($mode): $unprivilegedRuntimeSymbol"
			}
		}

        $fixtureSymbolTable = @(& $Objdump -t $bootProbeObject)
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for ARM_CM0_MPU linker/global-image fixture symbols ($mode)"
        }
        foreach ($fixtureSymbol in @("fiber_arm_cm0_mpu_probe_entry")) {
            $matches = @($fixtureSymbolTable | Where-Object {
                $_ -match ("\bF\s+\.fiber_port_unprivileged_functions\s+[0-9a-fA-F]+\s+" +
                    [regex]::Escape($fixtureSymbol) + "$")
            })
            if ($matches.Count -ne 1) {
                throw "ARM_CM0_MPU unprivileged fixture function escaped its linker section ($mode): $fixtureSymbol"
            }
        }
        foreach ($fixtureSymbol in @(
                "fiber_arm_cm0_mpu_probe_context",
                "fiber_arm_cm0_mpu_probe_global_regions")) {
            $matches = @($fixtureSymbolTable | Where-Object {
                $_ -match ("\bO\s+\.fiber_port_privileged_data\s+[0-9a-fA-F]+\s+" +
                    [regex]::Escape($fixtureSymbol) + "$")
            })
            if ($matches.Count -ne 1) {
                throw "ARM_CM0_MPU privileged fixture storage escaped its linker section ($mode): $fixtureSymbol"
            }
        }

        $bootUndefinedOutput = @(& $Nm --undefined-only $bootObject)
        if ($LASTEXITCODE -ne 0) {
            throw "nm failed for ARM_CM0_MPU linker/global-image source ($mode)"
        }
        $bootUndefined = Get-NmUndefinedSymbolNames -NmOutput $bootUndefinedOutput `
            -Path $bootObject
        $expectedBootUndefined = @(
            "fiber_panic",
			"fiber_port_panic_wait",
			"fiber_internal_task_return",
			"fiber_internal_runtime_select_scheduler_candidate",
			"fiber_internal_runtime_publish_current_context",
			"fiber_internal_runtime_require_current_context",
			"SVC_Handler",
            "fiber_port_svc_dispatch",
            "fiber_port_runtime_memory_barrier",
            "fiber_port_require_scheduler_configuration_environment",
            "fiber_port_runtime_prepare_start",
            "fiber_port_runtime_select_first",
            "fiber_port_runtime_start_first",
            "fiber_port_start_first_context",
            "fiber_port_restore_first_context_from_svc",
            "fiber_port_unprivileged_task_return",
			"fiber_port_runtime_schedule",
			"fiber_port_pendsv_validate_save_current",
			"fiber_port_scheduler_pick_next_from_pendsv",
			"fiber_port_mpu_switch_to_context",
			"PendSV_Handler",
            $variantCohorts["vtor-present-$mode"]
        ) + $linkerBoundarySymbols
        Assert-ExactSymbolSet -Expected $expectedBootUndefined `
            -Actual $bootUndefined `
			-Description "ARM_CM0_MPU slice-6 boot/linker undefined surface ($mode)"

		$runtimeUndefinedOutput = @(& $Nm --undefined-only $runtimeObject)
		if ($LASTEXITCODE -ne 0) {
			throw "nm failed for ARM_CM0_MPU first-start runtime ($mode)"
		}
		$runtimeUndefined = Get-NmUndefinedSymbolNames -NmOutput $runtimeUndefinedOutput `
			-Path $runtimeObject
		Assert-ExactSymbolSet -Expected @(
				"fiber_internal_runtime_current_context_slot",
				"fiber_internal_runtime_port_abi_v1_anchor",
				"fiber_internal_runtime_publish_current_context",
				"fiber_internal_runtime_require_current_context",
				"fiber_internal_runtime_select_scheduler_candidate",
				"fiber_internal_task_return",
				"fiber_panic",
				"fiber_port_context_validate_initial_restore",
				"fiber_port_context_validate_restore",
				"fiber_port_context_validate_running_svc",
				"fiber_port_context_validate_save_current",
				"fiber_port_mpu_build_global_regions",
				"fiber_port_mpu_linker_layout_check",
				"fiber_port_mpu_load_linker_layout") `
			-Actual $runtimeUndefined `
			-Description "ARM_CM0_MPU slice-6 protected runtime undefined surface ($mode)"

        $linkerText = @'
ENTRY(fiber_arm_cm0_mpu_boot_probe)

SECTIONS
{
	.fiber_unprivileged_code 0x08010000 :
	{
		__fiber_mpu_unprivileged_code_start__ = .;
		KEEP(*(.fiber_port_unprivileged_functions))
		KEEP(*(.fiber_test_unprivileged_code))
		__fiber_mpu_unprivileged_code_end__ =
			__fiber_mpu_unprivileged_code_start__ + 0x10000;
	}
	ASSERT(SIZEOF(.fiber_unprivileged_code) <= 0x10000,
		"[fiber]: ARM_CM0_MPU synthetic unprivileged code exceeds its MPU region")

	.fiber_privileged_code 0x08000000 :
	{
		__fiber_mpu_privileged_code_start__ = .;
		KEEP(*(.fiber_port_privileged_functions))
		KEEP(*(.fiber_test_vector_table))
		*(.text*)
		*(.rodata*)
		__fiber_mpu_privileged_code_end__ =
			__fiber_mpu_privileged_code_start__ + 0x10000;
	}
	ASSERT(SIZEOF(.fiber_privileged_code) <= 0x10000,
		"[fiber]: ARM_CM0_MPU synthetic privileged code exceeds its MPU region")

	.fiber_current_context_slot 0x20000000 (NOLOAD) :
	{
		__fiber_mpu_current_context_slot_start__ = .;
		KEEP(*(.bss.fiber_runtime_current_context_slot))
		. = __fiber_mpu_current_context_slot_start__ + 0x100;
		__fiber_mpu_current_context_slot_end__ = .;
	}
	ASSERT(SIZEOF(.fiber_current_context_slot) == 0x100,
		"[fiber]: ARM_CM0_MPU synthetic current-slot aperture changed")

	.fiber_privileged_data 0x20010000 (NOLOAD) :
	{
		__fiber_mpu_privileged_data_start__ = .;
		KEEP(*(.fiber_port_privileged_data))
		*(.data*)
		*(.bss*)
		*(COMMON)
		__fiber_mpu_privileged_data_end__ =
			__fiber_mpu_privileged_data_start__ + 0x10000;
	}
	ASSERT(SIZEOF(.fiber_privileged_data) <= 0x10000,
		"[fiber]: ARM_CM0_MPU synthetic privileged data exceeds its MPU region")

	.fiber_unprivileged_ram 0x20020000 (NOLOAD) :
	{
		__fiber_mpu_unprivileged_ram_start__ = .;
		KEEP(*(.fiber_test_unprivileged_ram))
		__fiber_mpu_unprivileged_ram_end__ =
			__fiber_mpu_unprivileged_ram_start__ + 0x10000;
	}
	ASSERT(SIZEOF(.fiber_unprivileged_ram) <= 0x10000,
		"[fiber]: ARM_CM0_MPU synthetic unprivileged RAM exceeds its integration range")

	/DISCARD/ : { *(.comment*) *(.note*) *(.ARM.attributes) }
}
'@ + "`n" + $linkerContractText
        Set-Content -LiteralPath $linkerScript -Value $linkerText -Encoding ASCII

        $linkArgs = @(
            "-mcpu=cortex-m0plus",
            "-mthumb",
            "-mfloat-abi=soft",
            "-nostdlib",
            "-Wl,--gc-sections",
            "-Wl,-T,$linkerScript",
            $bootObject,
			$runtimeObject,
            $bootProbeObject,
            $runtimeStateObject,
            "-o", $bootElf
        )
        & $Compiler @linkArgs
        if ($LASTEXITCODE -ne 0) {
			throw "ARM_CM0_MPU slice-6 linker/global-image synthetic ELF failed link ($mode)"
        }
        $bootSymbols = @(& $Nm --defined-only $bootElf)
        if ($LASTEXITCODE -ne 0) {
			throw "nm failed for ARM_CM0_MPU slice-6 linker/global-image ELF ($mode)"
        }
        $symbolAddresses = @{}
        foreach ($line in $bootSymbols) {
            if ($line -match '^\s*(?<address>[0-9a-fA-F]+)\s+\S\s+(?<symbol>\S+)\s*$') {
                $symbolAddresses[$Matches['symbol']] =
                    [Convert]::ToUInt64($Matches['address'], 16)
            }
        }
        foreach ($requiredSymbol in @(
                "fiber_port_context_init",
                "fiber_port_context_compute_seal",
                "fiber_port_context_seal_check",
                "fiber_port_mpu_try_encode_exact_region",
                "fiber_port_mpu_load_linker_layout",
                "fiber_port_mpu_linker_layout_check",
			"fiber_port_mpu_build_global_regions",
			"fiber_port_context_validate_initial_restore",
			"fiber_port_context_validate_running_svc",
			"fiber_port_context_validate_save_current",
			"fiber_port_context_validate_restore",
			"fiber_port_runtime_memory_barrier",
			"fiber_port_panic_wait",
			"fiber_port_require_scheduler_configuration_environment",
			"fiber_port_runtime_prepare_start",
			"fiber_port_runtime_select_first",
			"fiber_port_runtime_start_first",
			"fiber_port_svc_dispatch",
			"fiber_port_start_first_context",
			"fiber_port_restore_first_context_from_svc",
			"fiber_port_unprivileged_task_return",
			"fiber_port_runtime_schedule",
			"fiber_port_pendsv_validate_save_current",
			"fiber_port_scheduler_pick_next_from_pendsv",
			"fiber_port_mpu_switch_to_context",
			"SVC_Handler",
			"PendSV_Handler",
			"fiber_internal_runtime_select_scheduler_candidate",
			"fiber_internal_runtime_publish_current_context",
                "fiber_internal_runtime_current_context_slot",
			"fiber_arm_cm0_mpu_probe_vectors",
                "fiber_arm_cm0_mpu_boot_probe")) {
            if (-not $symbolAddresses.ContainsKey($requiredSymbol)) {
			throw "ARM_CM0_MPU slice-6 synthetic ELF lost symbol ($mode): $requiredSymbol"
			}
		}
        foreach ($privilegedTextSymbol in @(
                "fiber_port_context_init",
                "fiber_port_context_compute_seal",
                "fiber_port_context_seal_check",
                "fiber_port_mpu_try_encode_exact_region",
                "fiber_port_mpu_load_linker_layout",
                "fiber_port_mpu_linker_layout_check",
			"fiber_port_mpu_build_global_regions",
			"fiber_port_context_validate_initial_restore",
			"fiber_port_context_validate_running_svc",
			"fiber_port_context_validate_save_current",
			"fiber_port_context_validate_restore",
			"fiber_port_panic_wait",
			"fiber_port_require_scheduler_configuration_environment",
			"fiber_port_runtime_prepare_start",
			"fiber_port_runtime_select_first",
			"fiber_port_runtime_start_first",
			"fiber_port_svc_dispatch",
			"fiber_port_start_first_context",
			"fiber_port_restore_first_context_from_svc",
			"fiber_port_pendsv_validate_save_current",
			"fiber_port_scheduler_pick_next_from_pendsv",
			"fiber_port_mpu_switch_to_context",
			"SVC_Handler",
			"PendSV_Handler",
			"fiber_internal_runtime_select_scheduler_candidate",
			"fiber_internal_runtime_publish_current_context",
			"fiber_internal_task_return",
                "fiber_panic")) {
            if ((-not $symbolAddresses.ContainsKey($privilegedTextSymbol)) -or
                    ($symbolAddresses[$privilegedTextSymbol] -lt 0x08000000) -or
                    ($symbolAddresses[$privilegedTextSymbol] -ge 0x08010000)) {
                throw "ARM_CM0_MPU privileged text symbol escaped its global region ($mode): $privilegedTextSymbol"
            }
        }
		foreach ($unprivilegedTextSymbol in @(
				"fiber_port_unprivileged_task_return",
				"fiber_port_runtime_memory_barrier",
				"fiber_port_runtime_schedule",
				"fiber_arm_cm0_mpu_probe_entry")) {
            if ((-not $symbolAddresses.ContainsKey($unprivilegedTextSymbol)) -or
                    ($symbolAddresses[$unprivilegedTextSymbol] -lt 0x08010000) -or
                    ($symbolAddresses[$unprivilegedTextSymbol] -ge 0x08020000)) {
                throw "ARM_CM0_MPU unprivileged text symbol escaped its global region ($mode): $unprivilegedTextSymbol"
            }
        }
        foreach ($privilegedDataSymbol in @(
                "fiber_arm_cm0_mpu_probe_context",
                "fiber_arm_cm0_mpu_probe_global_regions")) {
            if ((-not $symbolAddresses.ContainsKey($privilegedDataSymbol)) -or
                    ($symbolAddresses[$privilegedDataSymbol] -lt 0x20010000) -or
                    ($symbolAddresses[$privilegedDataSymbol] -ge 0x20020000)) {
                throw "ARM_CM0_MPU privileged data escaped its global region ($mode): $privilegedDataSymbol"
            }
        }
        if (($symbolAddresses["fiber_internal_runtime_current_context_slot"] -ne 0x20000000)) {
            throw "ARM_CM0_MPU current slot escaped its exact aperture ($mode)"
        }
        if ((-not $symbolAddresses.ContainsKey("fiber_arm_cm0_mpu_probe_stack")) -or
                ($symbolAddresses["fiber_arm_cm0_mpu_probe_stack"] -lt 0x20020000) -or
                ($symbolAddresses["fiber_arm_cm0_mpu_probe_stack"] -ge 0x20030000)) {
            throw "ARM_CM0_MPU raw stack escaped unprivileged RAM ($mode)"
        }
        $elfSections = (& $Objdump -h $bootElf) -join "`n"
        if ($LASTEXITCODE -ne 0) {
			throw "objdump failed for ARM_CM0_MPU slice-6 linker/global-image ELF ($mode)"
        }
        if ($elfSections -notmatch '(?m)^\s*\d+\s+\.fiber_current_context_slot\s+00000100\s+20000000\b') {
            throw "ARM_CM0_MPU current-slot linker output is not one exact 256-byte aperture ($mode)"
        }
		$vectorBinary = Join-Path $probeDir ("privileged-code-" + $mode + ".bin")
		& $Objcopy -O binary --only-section=.fiber_privileged_code `
			$bootElf $vectorBinary
		if ($LASTEXITCODE -ne 0) {
			throw "objcopy failed for ARM_CM0_MPU protected vector ELF ($mode)"
		}
		if (($symbolAddresses["SVC_Handler"] -band 1) -ne 0) {
			throw "ARM_CM0_MPU strong SVC handler symbol must have an even code address ($mode)"
		}
		if (($symbolAddresses["PendSV_Handler"] -band 1) -ne 0) {
			throw "ARM_CM0_MPU strong PendSV handler symbol must have an even code address ($mode)"
		}
		if (($symbolAddresses["fiber_arm_cm0_mpu_probe_vectors"] -lt 0x08000000) -or
			($symbolAddresses["fiber_arm_cm0_mpu_probe_vectors"] -ge 0x08010000)) {
			throw "ARM_CM0_MPU synthetic vector table escaped privileged code ($mode)"
		}
		if (($symbolAddresses["fiber_arm_cm0_mpu_probe_vectors"] -band 0x7F) -ne 0) {
			throw "ARM_CM0_MPU synthetic vector table lost 128-byte alignment ($mode)"
		}
		$vectorBytes = [System.IO.File]::ReadAllBytes($vectorBinary)
		$vectorOffset = [uint64]$symbolAddresses["fiber_arm_cm0_mpu_probe_vectors"] -
			[uint64]0x08000000
		$svcSlotOffset = $vectorOffset + ([uint64]11 * [uint64]4)
		if (($svcSlotOffset + [uint64]4) -gt [uint64]$vectorBytes.Length) {
			throw "ARM_CM0_MPU synthetic SVC vector slot lies outside privileged code ($mode)"
		}
		$actualSvcVector = [System.BitConverter]::ToUInt32($vectorBytes,
			[int]$svcSlotOffset)
		$expectedSvcVector = [uint32]([uint64]$symbolAddresses["SVC_Handler"] -bor [uint64]1)
		if ($actualSvcVector -ne $expectedSvcVector) {
			throw ("ARM_CM0_MPU synthetic SVC vector slot mismatch ({0}): expected 0x{1:X8}, got 0x{2:X8}" -f
				$mode, $expectedSvcVector, $actualSvcVector)
		}
		$pendsvSlotOffset = $vectorOffset + ([uint64]14 * [uint64]4)
		if (($pendsvSlotOffset + [uint64]4) -gt [uint64]$vectorBytes.Length) {
			throw "ARM_CM0_MPU synthetic PendSV vector slot lies outside privileged code ($mode)"
		}
		$actualPendSvVector = [System.BitConverter]::ToUInt32($vectorBytes,
			[int]$pendsvSlotOffset)
		$expectedPendSvVector = [uint32]([uint64]$symbolAddresses["PendSV_Handler"] -bor [uint64]1)
		if ($actualPendSvVector -ne $expectedPendSvVector) {
			throw ("ARM_CM0_MPU synthetic PendSV vector slot mismatch ({0}): expected 0x{1:X8}, got 0x{2:X8}" -f
				$mode, $expectedPendSvVector, $actualPendSvVector)
		}

        foreach ($linkerFailure in @(
                [pscustomobject]@{
                    Name = "current-slot-size"
                    Search = ". = __fiber_mpu_current_context_slot_start__ + 0x100;"
                    Replace = ". = __fiber_mpu_current_context_slot_start__ + 0x20;"
                    Diagnostic = "[fiber]: ARM_CM0_MPU current-slot aperture must be exactly 256 bytes"
                },
                [pscustomobject]@{
                    Name = "unprivileged-code-extent"
                    Search = "__fiber_mpu_unprivileged_code_start__ + 0x10000;"
                    Replace = "__fiber_mpu_unprivileged_code_start__ + 0x18000;"
                    Diagnostic = "[fiber]: ARM_CM0_MPU unprivileged code must be an exact MPU region"
                })) {
            if ($linkerText.IndexOf($linkerFailure.Search,
                    [System.StringComparison]::Ordinal) -lt 0) {
                throw "ARM_CM0_MPU synthetic linker negative fixture lost replacement anchor ($mode): $($linkerFailure.Name)"
            }
            $invalidScript = Join-Path $probeDir ("linker-" + $mode + "-invalid-" + $linkerFailure.Name + ".ld")
            $invalidElf = Join-Path $probeDir ("boot-" + $mode + "-invalid-" + $linkerFailure.Name + ".elf")
            Set-Content -LiteralPath $invalidScript -Encoding ASCII -Value `
                $linkerText.Replace($linkerFailure.Search, $linkerFailure.Replace)
            $invalidLog = Join-Path $probeDir ("linker-" + $mode + "-invalid-" + $linkerFailure.Name + ".log")
            $invalidArgs = @(
                "-mcpu=cortex-m0plus",
                "-mthumb",
                "-mfloat-abi=soft",
                "-nostdlib",
                "-Wl,--gc-sections",
                "-Wl,-T,$invalidScript",
                $bootObject,
				$runtimeObject,
                $bootProbeObject,
                $runtimeStateObject,
                "-o", $invalidElf
            )
            $negativeResult = Invoke-CompilerProbe -Compiler $Compiler `
                -Arguments $invalidArgs -LogPath $invalidLog
            if ($negativeResult.ExitCode -eq 0) {
                throw "ARM_CM0_MPU linker contract negative proof failed ($mode): $($linkerFailure.Name)`n$($negativeResult.Output)"
            }
        }

        $r9ProbeSource = Join-Path $probeDir ("r9-static-base-" + $mode + ".c")
        $r9ProbeObject = Join-Path $probeDir ("r9-static-base-" + $mode + ".o")
        $r9ProbeText = @"
#include "fiber_portmacro.h"

uint32_t fiber_arm_cm0_mpu_read_static_base_probe(void)
{
    return fiber_port_read_r9();
}
"@
        Set-Content -LiteralPath $r9ProbeSource -Value $r9ProbeText `
            -Encoding ASCII
        & $Compiler @($sliceCompileArgs + @(
            "-ffixed-r9",
            "-c", $r9ProbeSource,
            "-o", $r9ProbeObject
        ))
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU reserved-r9 static-base probe failed compile ($mode)"
        }
        $r9ProbeDisassembly = (& $Objdump -dr $r9ProbeObject) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "objdump failed for ARM_CM0_MPU reserved-r9 probe ($mode)"
        }
        $r9ProbeBody = Get-DisassemblyFunctionBody `
            -Disassembly $r9ProbeDisassembly `
            -Symbol "fiber_arm_cm0_mpu_read_static_base_probe" `
            -Path $r9ProbeObject
        if (($r9ProbeBody -notmatch '\bmov\s+r0,\s*r9\b') -or
                ($r9ProbeBody -notmatch '\bbx\s+lr\b')) {
            throw "ARM_CM0_MPU reserved-r9 helper no longer reads the live static base ($mode)"
        }

        if ($mode -eq "o2") {
            $ltoBootObject = Join-Path $probeDir "boot-lto.o"
            $ltoRuntimeObject = Join-Path $probeDir "runtime-lto.o"
            $ltoProbeObject = Join-Path $probeDir "boot-probe-lto.o"
            $ltoRuntimeStateObject = Join-Path $probeDir "runtime-state-lto.o"
            $ltoLinkerScript = Join-Path $probeDir "linker-lto.ld"
            $ltoElf = Join-Path $probeDir "boot-lto.elf"
            $ltoCompileArgs = @($sliceCompileArgs + @("-flto"))
            foreach ($compileUnit in @(
                    [pscustomobject]@{ Source = $bootSource; Object = $ltoBootObject; Label = "source" },
					[pscustomobject]@{ Source = $runtimeSource; Object = $ltoRuntimeObject; Label = "protected runtime" },
                    [pscustomobject]@{ Source = $bootProbeSource; Object = $ltoProbeObject; Label = "fixture" },
                    [pscustomobject]@{ Source = $runtimeStateSource; Object = $ltoRuntimeStateObject; Label = "common runtime state" })) {
                & $Compiler @($ltoCompileArgs + @(
                    "-c", $compileUnit.Source,
                    "-o", $compileUnit.Object
                ))
                if ($LASTEXITCODE -ne 0) {
				throw "ARM_CM0_MPU slice-6 LTO $($compileUnit.Label) failed compile"
                }
            }
            Set-Content -LiteralPath $ltoLinkerScript -Value $linkerText `
                -Encoding ASCII
            & $Compiler @(
                "-mcpu=cortex-m0plus",
                "-mthumb",
                "-mfloat-abi=soft",
                "-flto",
                "-nostdlib",
                "-Wl,--gc-sections",
                "-Wl,-T,$ltoLinkerScript",
                $ltoBootObject,
                $ltoRuntimeObject,
                $ltoProbeObject,
                $ltoRuntimeStateObject,
                "-o", $ltoElf
            )
            if ($LASTEXITCODE -ne 0) {
				throw "ARM_CM0_MPU slice-6 protected-runtime LTO ELF failed link"
            }
            $ltoSymbols = @(& $Nm --defined-only $ltoElf)
            if ($LASTEXITCODE -ne 0) {
				throw "nm failed for ARM_CM0_MPU slice-6 LTO ELF"
            }
            foreach ($requiredSymbol in @(
                    "fiber_port_context_init",
                    "fiber_port_context_seal_check",
					"fiber_port_mpu_build_global_regions",
					"fiber_port_runtime_prepare_start",
					"fiber_port_runtime_select_first",
					"fiber_port_runtime_start_first",
					"fiber_port_start_first_context",
					"fiber_port_restore_first_context_from_svc",
					"fiber_port_unprivileged_task_return",
					"fiber_port_runtime_schedule",
					"SVC_Handler",
					"PendSV_Handler",
                    "fiber_internal_runtime_current_context_slot")) {
                if (-not ($ltoSymbols -match "\b$([regex]::Escape($requiredSymbol))\s*$")) {
					throw "ARM_CM0_MPU slice-6 LTO ELF lost retained symbol: $requiredSymbol"
                }
            }
            $ltoSections = (& $Objdump -h $ltoElf) -join "`n"
            if (($LASTEXITCODE -ne 0) -or ($ltoSections -notmatch
                    '(?m)^\s*\d+\s+\.fiber_current_context_slot\s+00000100\s+20000000\b')) {
				throw "ARM_CM0_MPU slice-6 LTO linker output lost the exact current-slot aperture"
            }
        }
    }

    # The first-start runtime must compile with both exact VTOR traits. A
    # no-VTOR board uses the architecture/remap vector base at zero.
    $vtorAbsentDefines = @($selectedFacadeDefines | Where-Object {
        $_ -ne "-D__VTOR_PRESENT=1"
    }) + @("-D__VTOR_PRESENT=0")
    foreach ($optimization in @("-O2", "-Os")) {
        $mode = $optimization.Substring(1).ToLowerInvariant()
        $absentBootObject = Join-Path $probeDir ("boot-vtor-absent-" + $mode + ".o")
		$absentRuntimeObject = Join-Path $probeDir ("runtime-vtor-absent-" + $mode + ".o")
        $absentCompileArgs = @(
            "-mcpu=cortex-m0plus",
            "-mthumb",
            "-mfloat-abi=soft",
            "-std=gnu11",
            $optimization,
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables"
        ) + $warningArgs + $vtorAbsentDefines + $manifestIncludeArgs
        & $Compiler @($absentCompileArgs + @(
            "-c", $bootSource,
            "-o", $absentBootObject
        ))
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU slice-6 boot source failed no-VTOR compile ($mode)"
        }
		& $Compiler @($absentCompileArgs + @(
			"-c", $runtimeSource,
			"-o", $absentRuntimeObject
		))
		if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU slice-6 protected runtime failed no-VTOR compile ($mode)"
		}
        $absentUndefinedOutput = @(& $Nm --undefined-only $absentBootObject)
        if ($LASTEXITCODE -ne 0) {
            throw "nm failed for ARM_CM0_MPU no-VTOR construction source ($mode)"
        }
        $absentUndefined = Get-NmUndefinedSymbolNames `
            -NmOutput $absentUndefinedOutput -Path $absentBootObject
        Assert-ExactSymbolSet -Expected (@(
            "fiber_panic",
			"fiber_port_panic_wait",
            "fiber_internal_task_return",
			"fiber_internal_runtime_select_scheduler_candidate",
			"fiber_internal_runtime_publish_current_context",
			"fiber_internal_runtime_require_current_context",
            "SVC_Handler",
            "fiber_port_svc_dispatch",
            "fiber_port_runtime_memory_barrier",
            "fiber_port_require_scheduler_configuration_environment",
            "fiber_port_runtime_prepare_start",
            "fiber_port_runtime_select_first",
            "fiber_port_runtime_start_first",
            "fiber_port_start_first_context",
            "fiber_port_restore_first_context_from_svc",
            "fiber_port_unprivileged_task_return",
			"fiber_port_runtime_schedule",
			"fiber_port_pendsv_validate_save_current",
			"fiber_port_scheduler_pick_next_from_pendsv",
			"fiber_port_mpu_switch_to_context",
			"PendSV_Handler",
            $variantCohorts["vtor-absent-$mode"]
        ) + $linkerBoundarySymbols) -Actual $absentUndefined `
			-Description "ARM_CM0_MPU no-VTOR slice-6 linker/global-image undefined surface ($mode)"

		$absentRuntimeUndefinedOutput = @(& $Nm --undefined-only $absentRuntimeObject)
		if ($LASTEXITCODE -ne 0) {
			throw "nm failed for ARM_CM0_MPU no-VTOR first-start runtime ($mode)"
		}
		$absentRuntimeUndefined = Get-NmUndefinedSymbolNames `
			-NmOutput $absentRuntimeUndefinedOutput -Path $absentRuntimeObject
		Assert-ExactSymbolSet -Expected @(
				"fiber_internal_runtime_current_context_slot",
				"fiber_internal_runtime_port_abi_v1_anchor",
				"fiber_internal_runtime_publish_current_context",
				"fiber_internal_runtime_require_current_context",
				"fiber_internal_runtime_select_scheduler_candidate",
				"fiber_internal_task_return",
				"fiber_panic",
				"fiber_port_context_validate_initial_restore",
				"fiber_port_context_validate_restore",
				"fiber_port_context_validate_running_svc",
				"fiber_port_context_validate_save_current",
				"fiber_port_mpu_build_global_regions",
				"fiber_port_mpu_linker_layout_check",
				"fiber_port_mpu_load_linker_layout") `
			-Actual $absentRuntimeUndefined `
			-Description "ARM_CM0_MPU no-VTOR slice-6 protected runtime undefined surface ($mode)"
    }

    $negativeBaseArgs = @(
        "-mcpu=cortex-m0plus",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu11"
    ) + $warningArgs + @(
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV6M=1",
        "-D__CORTEX_M=0",
        "-D__NVIC_PRIO_BITS=2"
    ) + $manifestIncludeArgs

    $negativeCases = @(
        [pscustomobject]@{
            Name = "mpu-absent"
            Defines = @("-D__MPU_PRESENT=0", "-D__VTOR_PRESENT=1", "-D__FPU_PRESENT=0", "-D__FPU_USED=0")
            Diagnostic = "[fiber]: ARM_CM0_MPU manifest requires __MPU_PRESENT == 1"
        },
        [pscustomobject]@{
            Name = "fpu-used"
            Defines = @("-D__MPU_PRESENT=1", "-D__VTOR_PRESENT=1", "-D__FPU_PRESENT=0", "-D__FPU_USED=1")
            Diagnostic = "[fiber]: ARM_CM0_MPU requires __FPU_USED == 0"
        },
        [pscustomobject]@{
            Name = "invalid-vtor"
            Defines = @("-D__MPU_PRESENT=1", "-D__VTOR_PRESENT=2", "-D__FPU_PRESENT=0", "-D__FPU_USED=0")
            Diagnostic = "[fiber]: ARM_CM0_MPU requires CMSIS __VTOR_PRESENT == 0 or 1"
        },
        [pscustomobject]@{
            Name = "basepri"
            Defines = @("-D__MPU_PRESENT=1", "-D__VTOR_PRESENT=1", "-D__FPU_PRESENT=0", "-D__FPU_USED=0", "-DFIBER_SCHEDULER_BASEPRI=64")
            Diagnostic = "[fiber]: ARM_CM0_MPU has no BASEPRI; FIBER_SCHEDULER_BASEPRI must be zero"
        },
        [pscustomobject]@{
            Name = "runtime-selectable"
            Defines = @("-D__MPU_PRESENT=1", "-D__VTOR_PRESENT=1", "-D__FPU_PRESENT=0", "-D__FPU_USED=0", "-DFIBER_PORT_RUNTIME_SELECTABLE=1")
            Diagnostic = "[fiber]: ARM_CM0_MPU runtime-selectable state must not be predefined"
        }
    )
    foreach ($case in $negativeCases) {
        $objectPath = Join-Path $probeDir ("invalid-" + $case.Name + ".o")
        $logPath = Join-Path $probeDir ("invalid-" + $case.Name + ".log")
        $result = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments ($negativeBaseArgs + $case.Defines + @(
                "-c", $probeSource, "-o", $objectPath)) `
            -LogPath $logPath
        if ($result.ExitCode -eq 0) {
            throw "Invalid ARM_CM0_MPU layout manifest unexpectedly compiled: $($case.Name)"
        }
        $normalizedOutput = $result.Output -replace '\s+', ' '
        if ($normalizedOutput -notmatch [regex]::Escape($case.Diagnostic)) {
            throw "ARM_CM0_MPU negative probe failed for the wrong reason: $($case.Name)`n$($result.Output)"
        }
    }
}

function Test-ArmCm0MpuRuntimeIntegration {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Objdump,
        [string]$Objcopy,
        [string]$Ar,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot "fiber\port\ARM_CM0_MPU"
    $startupSource = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm0_mpu_runtime_startup.c"
    $portableSource = Join-Path $RepositoryRoot `
        "tools\fixtures\portable_application.c"
    $expectationSource = Join-Path $RepositoryRoot `
        "fiber\port\fiber_port_context_cohort_expectation.c"
    $linkerScript = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm0_mpu_runtime.ld"
    $linkerContract = Join-Path $profileDir "fiber_port_linker_contract.ld"
    foreach ($requiredPath in @($startupSource, $portableSource,
            $expectationSource, $linkerScript, $linkerContract)) {
        if (-not (Test-Path -LiteralPath $requiredPath)) {
            throw "ARM_CM0_MPU runtime integration fixture is missing: $requiredPath"
        }
    }

    $commonSources = @(
        "fiber\fiber_core.c",
        "fiber\fiber_runtime_state.c",
        "fiber\fiber_panic.c"
    )
    $portSources = @(
        "fiber\port\ARM_CM0_MPU\fiber_port.c",
        "fiber\port\ARM_CM0_MPU\fiber_port_boot.c"
    )
    $forwardAbiSymbols = @(
        "fiber_port_context_init",
        "fiber_port_runtime_memory_barrier",
        "fiber_port_panic_wait",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_runtime_schedule"
    )
    $manifestDefines = @(
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV6M=1",
        "-D__CORTEX_M=0",
        "-D__MPU_PRESENT=1",
        "-D__VTOR_PRESENT=1",
        "-D__FPU_PRESENT=0",
        "-D__FPU_USED=0",
        "-D__NVIC_PRIO_BITS=2"
    )
    $counterFlags = @(
        "-fno-instrument-functions",
        "-fno-stack-protector",
        "-fno-profile-arcs",
        "-fno-test-coverage",
        "-fno-sanitize=all",
        "-mgeneral-regs-only"
    )

    foreach ($useLto in @($false, $true)) {
        $mode = if ($useLto) { "lto" } else { "normal" }
        $probeDir = Join-Path $BuildRoot "arm-cm0-mpu-runtime-$mode"
        New-Item -ItemType Directory -Path $probeDir | Out-Null
        Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
            -Value "#ifndef MAIN_H_`n#define MAIN_H_`n#endif`n" `
            -Encoding ASCII

        $ltoArgs = if ($useLto) { @("-flto") } else { @() }
        $baseArgs = @(
            "-mcpu=cortex-m0plus",
            "-mthumb",
            "-mfloat-abi=soft",
            "-O2",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-fno-builtin",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wundef",
            "-Werror=undef",
            "-Werror=implicit-function-declaration",
            "-Werror=return-type",
            "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot",
            "-I$CmsisPath",
            "-I$probeDir"
        ) + $manifestDefines + $ltoArgs

        $archiveObjects = @()
        foreach ($source in ($commonSources + $portSources)) {
            $object = Join-Path $probeDir `
                (($source -replace '[\\/]', '_') + ".o")
            $sourcePath = Join-Path $RepositoryRoot $source
            $extraFlags = if ($portSources -contains $source) {
                $counterFlags
            } else {
                @()
            }
            & $Compiler @($baseArgs + $extraFlags + @(
                "-c", $sourcePath, "-o", $object))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM0_MPU runtime archive compile failed ($mode): $source"
            }
            $archiveObjects += $object
        }

        $startupObject = Join-Path $probeDir "startup.o"
        $portableObject = Join-Path $probeDir "portable.o"
        $expectationObject = Join-Path $probeDir "expectation.o"
        foreach ($compile in @(
                [pscustomobject]@{ Source = $startupSource; Object = $startupObject; Name = "startup" },
                [pscustomobject]@{ Source = $portableSource; Object = $portableObject; Name = "portable application" },
                [pscustomobject]@{ Source = $expectationSource; Object = $expectationObject; Name = "cohort expectation" })) {
            $fixtureArgs = $baseArgs
            if ($useLto -and ($compile.Name -eq "portable application")) {
                $fixtureArgs = @($baseArgs | Where-Object { $_ -ne "-flto" })
                $fixtureArgs += "-fno-lto"
            }
            & $Compiler @($fixtureArgs + $counterFlags + @(
                "-c", $compile.Source, "-o", $compile.Object))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM0_MPU $($compile.Name) compile failed ($mode)"
            }
        }

        $objectNm = if ($useLto) { $GccNm } else { $Nm }
        $expectationUndefined = @(& $objectNm --undefined-only $expectationObject)
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU expectation nm failed ($mode)"
        }
        $expectedCohortLines = @($expectationUndefined | Where-Object {
            $_ -match '\bU\s+fiber_port_context_cohort_armv6m_\S+$'
        })
        if ($expectedCohortLines.Count -ne 1) {
            throw "ARM_CM0_MPU expectation must retain one exact cohort relocation ($mode)"
        }
        $expectedCohort = ($expectedCohortLines[0] -split '\s+')[-1]

        $archivePath = Join-Path $probeDir "libfiber-arm-cm0-mpu.a"
        & $Ar rcs $archivePath @archiveObjects
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU runtime archive creation failed ($mode)"
        }

        $elfPath = Join-Path $probeDir "fiber-arm-cm0-mpu.elf"
        $mapPath = Join-Path $probeDir "fiber-arm-cm0-mpu.map"
        $linkArgs = @(
            "-mcpu=cortex-m0plus",
            "-mthumb",
            "-mfloat-abi=soft"
        ) + $ltoArgs + @(
            "-nostdlib",
            "-Wl,--gc-sections",
            "-Wl,-Map,$mapPath",
            "-Wl,-T,$linkerScript",
            "-Wl,-T,$linkerContract",
            $startupObject,
            $portableObject,
            $expectationObject,
            $archivePath,
            "-o", $elfPath
        )
        & $Compiler @linkArgs
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU portable archive/link integration failed ($mode)"
        }

        $defined = @(& $Nm -a --defined-only $elfPath)
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU final ELF nm failed ($mode)"
        }
        foreach ($symbol in $forwardAbiSymbols) {
            $definitions = @($defined | Where-Object {
                $_ -match ("\bT\s+" + [regex]::Escape($symbol) + "$")
            })
            if ($definitions.Count -ne 1) {
                throw "ARM_CM0_MPU final ELF must define one strong forward ABI symbol ($mode): $symbol"
            }
        }
        $cohortDefinitions = @($defined | Where-Object {
            $_ -match '\b[RT]\s+fiber_port_context_cohort_armv6m_\S+$'
        })
        if ($cohortDefinitions.Count -ne 1) {
            throw "ARM_CM0_MPU final ELF must contain one exact context cohort ($mode)"
        }
        if ($cohortDefinitions[0] -notmatch [regex]::Escape($expectedCohort)) {
            throw "ARM_CM0_MPU final ELF cohort does not satisfy the external expectation ($mode)"
        }

        $svcAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
            -Symbol "SVC_Handler" -Path $elfPath
        $pendsvAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
            -Symbol "PendSV_Handler" -Path $elfPath

        $symbolRanges = @(
            [pscustomobject]@{
                Start = [uint32]0x08010000
                End = [uint32]0x08020000
                Name = "unprivileged code"
                Symbols = @(
                    "fiber_current",
                    "fiber_schedule",
                    "fiber_internal_runtime_load_current_context",
                    "fiber_port_runtime_memory_barrier",
                    "fiber_port_runtime_schedule",
                    "fiber_port_unprivileged_task_return",
                    "portable_fixture_entry"
                )
            },
            [pscustomobject]@{
                Start = [uint32]0x08000000
                End = [uint32]0x08010000
                Name = "privileged code"
                Symbols = @(
                    "fiber_init",
                    "fiber_start",
                    "fiber_scheduler_set_pick_next",
                    "fiber_internal_runtime_select_scheduler_candidate",
                    "fiber_internal_runtime_publish_current_context",
                    "fiber_internal_runtime_require_current_context",
                    "fiber_internal_task_return",
                    "fiber_panic",
                    "fiber_port_context_init",
                    "fiber_port_panic_wait",
                    "fiber_port_require_scheduler_configuration_environment",
                    "fiber_port_runtime_prepare_start",
                    "fiber_port_runtime_select_first",
                    "fiber_port_runtime_start_first",
                    "fiber_port_svc_dispatch",
                    "fiber_port_pendsv_validate_save_current",
                    "fiber_port_scheduler_pick_next_from_pendsv",
                    "fiber_port_mpu_switch_to_context",
                    "portable_fixture_pick_next",
                    "SVC_Handler",
                    "PendSV_Handler"
                )
            }
        )
        foreach ($range in $symbolRanges) {
            foreach ($symbol in $range.Symbols) {
                $lines = @($defined | Where-Object {
                    $_ -match ("^\s*(?<address>[0-9a-fA-F]+)\s+[TtWw]\s+" +
                        [regex]::Escape($symbol) + "$")
                })
                if ($lines.Count -ne 1) {
                    throw "ARM_CM0_MPU ELF lost range-audited symbol ($mode): $symbol"
                }
                $null = $lines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
                $address = [Convert]::ToUInt32($Matches['address'], 16)
                if (($address -lt $range.Start) -or ($address -ge $range.End)) {
                    throw "ARM_CM0_MPU symbol escaped $($range.Name) ($mode): $symbol at 0x$($address.ToString('X8'))"
                }
            }
        }

        foreach ($stack in @("portable_fixture_stack_1",
                "portable_fixture_stack_2")) {
            $stackLines = @($defined | Where-Object {
                $_ -match ("^\s*(?<address>[0-9a-fA-F]+)\s+[Bb]\s+" +
                    [regex]::Escape($stack) + "$")
            })
            if ($stackLines.Count -ne 1) {
                throw "ARM_CM0_MPU portable stack symbol is missing ($mode): $stack"
            }
            $null = $stackLines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
            $stackAddress = [Convert]::ToUInt32($Matches['address'], 16)
            if (($stackAddress -lt 0x20020000) -or
                    ($stackAddress -ge 0x20030000) -or
                    (($stackAddress -band 0x7FF) -ne 0)) {
                throw "ARM_CM0_MPU portable stack escaped exact unprivileged RAM geometry ($mode): $stack"
            }
        }
        foreach ($privilegedObject in @("portable_fixture_context_1",
                "portable_fixture_context_2", "portable_fixture_scheduler_user")) {
            $objectLines = @($defined | Where-Object {
                $_ -match ("^\s*(?<address>[0-9a-fA-F]+)\s+[Bb]\s+" +
                    [regex]::Escape($privilegedObject) + "$")
            })
            if ($objectLines.Count -ne 1) {
                throw "ARM_CM0_MPU privileged application object is missing ($mode): $privilegedObject"
            }
            $null = $objectLines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
            $objectAddress = [Convert]::ToUInt32($Matches['address'], 16)
            if (($objectAddress -lt 0x20010000) -or ($objectAddress -ge 0x20020000)) {
                throw "ARM_CM0_MPU application-owned scheduler/context object escaped privileged data ($mode): $privilegedObject"
            }
        }

        $slotLines = @($defined | Where-Object {
            $_ -match '^\s*20000000\s+[Bb]\s+fiber_internal_runtime_current_context_slot$'
        })
        if ($slotLines.Count -ne 1) {
            throw "ARM_CM0_MPU current slot escaped its exact 256-byte aperture ($mode)"
        }

        $sections = (& $Objdump -h $elfPath) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU final ELF section audit failed ($mode)"
        }
        foreach ($requiredSection in @(
                '\.isr_vector\s+00000040\s+08000000\s+',
                '\.fiber_unprivileged_code\s+[0-9a-fA-F]+\s+08010000\s+',
                '\.fiber_privileged_code\s+[0-9a-fA-F]+\s+08000040\s+',
                '\.fiber_current_context_slot\s+00000100\s+20000000\s+',
                '\.fiber_unprivileged_ram\s+[0-9a-fA-F]+\s+20020000\s+',
                '\.fiber_privileged_data\s+[0-9a-fA-F]+\s+20010000\s+')) {
            if ($sections -notmatch $requiredSection) {
                throw "ARM_CM0_MPU final ELF lost exact MPU output section ($mode): $requiredSection"
            }
        }

        $vectorPath = Join-Path $probeDir "vectors.bin"
        & $Objcopy -O binary --only-section=.isr_vector $elfPath $vectorPath
        if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $vectorPath))) {
            throw "ARM_CM0_MPU runtime vector extraction failed ($mode)"
        }
        $vectorBytes = [IO.File]::ReadAllBytes($vectorPath)
        if ($vectorBytes.Length -ne 64) {
            throw "ARM_CM0_MPU runtime vector fixture changed size ($mode)"
        }
        $svcVector = [BitConverter]::ToUInt32($vectorBytes, 11 * 4)
        $pendsvVector = [BitConverter]::ToUInt32($vectorBytes, 14 * 4)
        if ($svcVector -ne ($svcAddress -bor 1)) {
            throw "ARM_CM0_MPU runtime vector slot 11 lost strong SVC handler ($mode)"
        }
        if ($pendsvVector -ne ($pendsvAddress -bor 1)) {
            throw "ARM_CM0_MPU runtime vector slot 14 lost strong PendSV handler ($mode)"
        }

        $competingSource = Join-Path $probeDir "competing.c"
        $competingObject = Join-Path $probeDir "competing.o"
        Set-Content -LiteralPath $competingSource -Encoding ASCII -Value `
            "void SVC_Handler(void) { }`nvoid PendSV_Handler(void) { }`n"
        & $Compiler @($baseArgs + @(
            "-c", $competingSource, "-o", $competingObject))
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU competing-handler fixture compile failed ($mode)"
        }
        $duplicateLog = Join-Path $probeDir "duplicate.log"
        $duplicateArgs = @($linkArgs[0..($linkArgs.Count - 3)] + @(
            $competingObject, "-o", (Join-Path $probeDir "duplicate.elf")))
        $duplicate = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $duplicateArgs -LogPath $duplicateLog
        if (($duplicate.ExitCode -eq 0) -or
                ($duplicate.Output -notmatch 'multiple definition')) {
            throw "ARM_CM0_MPU competing strong handlers must fail link ($mode)`n$($duplicate.Output)"
        }

        # Build a complete archive with the other exact VTOR cohort. The
        # application-owned expectation object must make both directions fail
        # before a stale private object can become a runnable selected port.
        $staleBaseArgs = @($baseArgs | Where-Object {
            $_ -ne "-D__VTOR_PRESENT=1"
        }) + @("-D__VTOR_PRESENT=0")
        $staleObjects = @()
        foreach ($source in ($commonSources + $portSources)) {
            $object = Join-Path $probeDir `
                ((($source -replace '[\\/]', '_') -replace '\.c$', '') + "-stale.o")
            $sourcePath = Join-Path $RepositoryRoot $source
            $extraFlags = if ($portSources -contains $source) {
                $counterFlags
            } else {
                @()
            }
            & $Compiler @($staleBaseArgs + $extraFlags + @(
                "-c", $sourcePath, "-o", $object))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM0_MPU stale archive compile failed ($mode): $source"
            }
            $staleObjects += $object
        }
        $staleArchive = Join-Path $probeDir "libfiber-arm-cm0-mpu-stale.a"
        & $Ar rcs $staleArchive @staleObjects
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU stale archive creation failed ($mode)"
        }
        $staleArchiveLog = Join-Path $probeDir "stale-archive.log"
        $staleArchiveArgs = @($linkArgs[0..($linkArgs.Count - 4)] + @(
            $staleArchive, "-o", (Join-Path $probeDir "stale-archive.elf")))
        $staleArchiveResult = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $staleArchiveArgs -LogPath $staleArchiveLog
        # PowerShell can wrap a long undefined cohort symbol in a redirected
        # native-tool error record. Whitespace is not semantically part of a
        # linker symbol, so compare the normalized diagnostic.
        $staleArchiveOutput = $staleArchiveResult.Output -replace '\s+', ''
        if (($staleArchiveResult.ExitCode -eq 0) -or
                ($staleArchiveOutput -notmatch [regex]::Escape($expectedCohort))) {
            throw "ARM_CM0_MPU stale archive must fail the exact cohort expectation ($mode)`n$($staleArchiveResult.Output)"
        }

        $staleExpectationObject = Join-Path $probeDir "expectation-stale.o"
        $staleExpectationArgs = @($staleBaseArgs | Where-Object {
            $_ -ne "-flto"
        }) + @("-fno-lto") + $counterFlags + @(
            "-c", $expectationSource, "-o", $staleExpectationObject)
        & $Compiler @staleExpectationArgs
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU stale expectation compile failed ($mode)"
        }
        $staleExpectationUndefined = @(& $Nm --undefined-only $staleExpectationObject)
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM0_MPU stale expectation nm failed ($mode)"
        }
        $staleCohortLines = @($staleExpectationUndefined | Where-Object {
            $_ -match '\bU\s+fiber_port_context_cohort_armv6m_\S+$'
        })
        if ($staleCohortLines.Count -ne 1) {
            throw "ARM_CM0_MPU stale expectation must retain one exact cohort relocation ($mode)"
        }
        $staleCohort = ($staleCohortLines[0] -split '\s+')[-1]
        $staleExpectationLog = Join-Path $probeDir "stale-expectation.log"
        $staleExpectationArgs = @($linkArgs[0..($linkArgs.Count - 5)] + @(
            $staleExpectationObject, $archivePath, "-o",
            (Join-Path $probeDir "stale-expectation.elf")))
        $staleExpectationResult = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $staleExpectationArgs -LogPath $staleExpectationLog
        $staleExpectationOutput = $staleExpectationResult.Output -replace '\s+', ''
        if (($staleExpectationResult.ExitCode -eq 0) -or
                ($staleExpectationOutput -notmatch [regex]::Escape($staleCohort))) {
            throw "ARM_CM0_MPU stale application expectation must reject the archive ($mode)`n$($staleExpectationResult.Output)"
        }
    }
}

function Test-ArmCm3MpuLayoutContract {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$Objdump,
        [string]$Objcopy,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileRelative = "fiber\port\ARM_CM3_MPU"
    $profileDir = Join-Path $RepositoryRoot $profileRelative
    $probeSource = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm3_mpu_layout_probe.c"
    $probeDir = Join-Path $BuildRoot "arm-cm3-mpu-layout"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
        -Value "#ifndef MAIN_H_`n#define MAIN_H_`n#endif`n" -Encoding ASCII

    foreach ($requiredFile in @(
            "fiber_port_boot.h",
            "fiber_port_boot.c",
            "fiber_port_private.h",
            "fiber_port.c")) {
        if (-not (Test-Path (Join-Path $profileDir $requiredFile))) {
            throw "ARM_CM3_MPU slice 7 is missing required source: $requiredFile"
        }
    }

    foreach ($runtimeFile in @("fiber_port_exception.c")) {
        if (Test-Path (Join-Path $profileDir $runtimeFile)) {
            throw "ARM_CM3_MPU keeps SVC and PendSV in fiber_port.c; unexpected source: $runtimeFile"
        }
    }

    $bootSourcePath = Join-Path $profileDir "fiber_port_boot.c"
    $portSourcePath = Join-Path $profileDir "fiber_port.c"
    $macroSourcePath = Join-Path $profileDir "fiber_portmacro.h"
    $bootSourceText = Get-Content -LiteralPath $bootSourcePath -Raw
    $portSourceText = Get-Content -LiteralPath $portSourcePath -Raw
    $macroSourceText = Get-Content -LiteralPath $macroSourcePath -Raw
    if (($macroSourceText.IndexOf("uint32_t fiber_port_read_r9(void)",
                [System.StringComparison]::Ordinal) -lt 0) -or
            ($bootSourceText.IndexOf(
                "ctx->protected_context.r9 = fiber_port_read_r9();",
                [System.StringComparison]::Ordinal) -lt 0)) {
        throw "ARM_CM3_MPU initial context must preserve the live r9 platform/static base"
    }
    foreach ($requiredText in @(
            "void SVC_Handler(void)",
            "void PendSV_Handler(void)",
            "void fiber_port_svc_dispatch(",
            "void fiber_port_pendsv_validate_save_current(",
            "FiberContext *fiber_port_scheduler_pick_next_from_pendsv(",
            "void fiber_port_mpu_switch_to_context(",
            "void fiber_port_runtime_memory_barrier(void)",
            "void fiber_port_panic_wait(void)",
            "void fiber_port_require_scheduler_configuration_environment(void)",
            "void fiber_port_runtime_prepare_start(void)",
            "FiberContext *fiber_port_runtime_select_first(void)",
            "void fiber_port_runtime_start_first(FiberContext *first)",
            "void fiber_port_runtime_schedule(void)",
            "void fiber_port_unprivileged_task_return(void)",
            "void fiber_port_start_first_context(void)",
            "void fiber_port_restore_first_context_from_svc(")) {
        if ($portSourceText.IndexOf($requiredText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM3_MPU slice 7 lost required runtime source: $requiredText"
        }
    }
    foreach ($requiredDispatchText in @(
            "case fiber_portSVC_START:",
            "case fiber_portSVC_YIELD:",
            "case fiber_portSVC_RETURN:",
            "default:",
            "fiber_panic('u');")) {
        if ($portSourceText.IndexOf($requiredDispatchText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM3_MPU SVC dispatch is not fail-closed: $requiredDispatchText"
        }
    }
    $dispatchStart = $portSourceText.IndexOf(
        "void fiber_port_svc_dispatch(",
        [System.StringComparison]::Ordinal)
    $dispatchSource = $portSourceText.Substring($dispatchStart)
    $excReturnCheck = $dispatchSource.IndexOf(
        "FIBER_REQUIRE((exc_return == fiber_portEXC_RETURN_THREAD_MSP)",
        [System.StringComparison]::Ordinal)
    $frameShapeCheck = $dispatchSource.IndexOf(
        "fiber_port_validate_svc_frame_shape(hardware_frame);",
        [System.StringComparison]::Ordinal)
    if (($excReturnCheck -lt 0) -or ($frameShapeCheck -lt 0) -or
            ($excReturnCheck -ge $frameShapeCheck)) {
        throw "ARM_CM3_MPU SVC dispatch must reject foreign EXC_RETURN before reading its selected frame"
    }
    $pendsvPreflightStart = $portSourceText.IndexOf(
        "void fiber_port_pendsv_validate_save_current(",
        [System.StringComparison]::Ordinal)
    $pendsvPreflightSource = $portSourceText.Substring($pendsvPreflightStart)
    $pendsvExcReturnCheck = $pendsvPreflightSource.IndexOf(
        "FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');",
        [System.StringComparison]::Ordinal)
    $pendsvContextCheck = $pendsvPreflightSource.IndexOf(
        "fiber_port_context_validate_save_current(current, hardware_frame);",
        [System.StringComparison]::Ordinal)
    if (($pendsvExcReturnCheck -lt 0) -or ($pendsvContextCheck -lt 0) -or
            ($pendsvExcReturnCheck -ge $pendsvContextCheck)) {
        throw "ARM_CM3_MPU PendSV must reject foreign EXC_RETURN before frame/context validation"
    }
    $schedulerBridgeStart = $portSourceText.IndexOf(
        "FiberContext *fiber_port_scheduler_pick_next_from_pendsv(",
        [System.StringComparison]::Ordinal)
    $schedulerBridgeSource = $portSourceText.Substring($schedulerBridgeStart)
    $nextRestoreCheck = $schedulerBridgeSource.IndexOf(
        "fiber_port_context_validate_restore(next);",
        [System.StringComparison]::Ordinal)
    $nextPublication = $schedulerBridgeSource.IndexOf(
        "fiber_internal_runtime_publish_current_context(next);",
        [System.StringComparison]::Ordinal)
    if (($nextRestoreCheck -lt 0) -or ($nextPublication -lt 0) -or
            ($nextRestoreCheck -ge $nextPublication)) {
        throw "ARM_CM3_MPU scheduler bridge must validate next before publication"
    }
    $mpuSwitchStart = $portSourceText.IndexOf(
        "void fiber_port_mpu_switch_to_context(",
        [System.StringComparison]::Ordinal)
    $mpuSwitchSource = $portSourceText.Substring($mpuSwitchStart)
    $mpuPrimaskCheck = $mpuSwitchSource.IndexOf(
        "FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');",
        [System.StringComparison]::Ordinal)
    $mpuNextFieldRead = $mpuSwitchSource.IndexOf(
        "next->mpu_regions[index]",
        [System.StringComparison]::Ordinal)
    if (($mpuPrimaskCheck -lt 0) -or ($mpuNextFieldRead -lt 0) -or
            ($mpuPrimaskCheck -ge $mpuNextFieldRead)) {
        throw "ARM_CM3_MPU must close PRIMASK before consuming the next MPU image"
    }
    $prioritySetupBody = Get-CFunctionBody -Source $portSourceText `
        -Signature "void fiber_port_configure_exception_priorities(void)" `
        -Path $portSourcePath
    foreach ($requiredPriorityProof in @(
            "lowest << fiber_portNVIC_PENDSV_PRIORITY_SHIFT",
            "FIBER_REQUIRE(pendsv_priority == lowest, 'P');",
            "FIBER_REQUIRE(svc_priority == 0u, 'w');")) {
        if ($prioritySetupBody.IndexOf($requiredPriorityProof,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM3_MPU exact SVC/PendSV priority policy changed: $requiredPriorityProof"
        }
    }
    $firstSelectionBody = Get-CFunctionBody -Source $portSourceText `
        -Signature "FiberContext *fiber_port_runtime_select_first(void)" `
        -Path $portSourcePath
    $firstCriticalEnter = $firstSelectionBody.IndexOf(
        "fiber_port_scheduler_critical_enter();",
        [System.StringComparison]::Ordinal)
    $firstHook = $firstSelectionBody.IndexOf(
        "fiber_internal_runtime_select_scheduler_candidate(NULL);",
        [System.StringComparison]::Ordinal)
    $firstContextValidation = $firstSelectionBody.IndexOf(
        "fiber_port_context_validate_restore(first);",
        [System.StringComparison]::Ordinal)
    $firstCriticalExit = $firstSelectionBody.IndexOf(
        "fiber_port_scheduler_critical_exit(critical_state);",
        [System.StringComparison]::Ordinal)
    if (($firstCriticalEnter -lt 0) -or ($firstHook -lt 0) -or
            ($firstContextValidation -lt 0) -or ($firstCriticalExit -lt 0) -or
            ($firstCriticalEnter -ge $firstHook) -or
            ($firstHook -ge $firstContextValidation) -or
            ($firstContextValidation -ge $firstCriticalExit)) {
        throw "ARM_CM3_MPU first scheduler selection must remain inside its BASEPRI envelope"
    }

    foreach ($selectorPath in @(
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h"))) {
        $selectorSource = Get-Content -LiteralPath $selectorPath -Raw
        if ($selectorSource.IndexOf("ARM_CM3_MPU",
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM3_MPU exact identity must remain build-selected instead of entering architecture auto/profile selection: $selectorPath"
        }
    }

    foreach ($typeHeaderName in @(
            "fiber_port_types.h",
            "fiber_port_boot_types.h")) {
        $typeHeaderPath = Join-Path $profileDir $typeHeaderName
        $typeHeaderSource = Get-Content -LiteralPath $typeHeaderPath -Raw
        if ([regex]::IsMatch($typeHeaderSource,
                '\b(mcu_core|fiber_compiler|fiber_portmacro|SCB|NVIC|__ASM)\b')) {
            throw "ARM_CM3_MPU public type header acquired a CPU/runtime dependency: $typeHeaderPath"
        }
    }

    $includeArgs = @(
        "-I$probeDir",
        "-I$profileDir",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot",
        "-I$CmsisPath"
    )
    $typeIncludeArgs = @("-I$profileDir")
    $manifestDefines = @(
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV7M=1",
        "-D__CORTEX_M=3",
        "-D__MPU_PRESENT=1",
        "-D__VTOR_PRESENT=1",
        "-D__FPU_PRESENT=0",
        "-D__FPU_USED=0",
        "-D__NVIC_PRIO_BITS=4"
    )
    $warningArgs = @(
        "-ffreestanding",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wundef",
        "-Werror=undef",
        "-Werror=implicit-function-declaration",
        "-Werror=return-type"
    )

    $selectedFacadeSource = Join-Path $probeDir "selected-facade.c"
    $selectedFacadeObject = Join-Path $probeDir "selected-facade.o"
    $selectedFacadeText = @"
#include <stddef.h>
#include "fiber/fiber_core.h"

_Static_assert(offsetof(FiberContext, protected_context_cursor) == 0u,
    "[fiber]: build-selected facade did not expose ARM_CM3_MPU context");
_Static_assert(offsetof(FiberContext, mpu_regions) == 4u,
    "[fiber]: build-selected facade lost ARM_CM3_MPU MPU image");
_Static_assert(sizeof(FiberContext) == 200u,
    "[fiber]: build-selected facade exposed the wrong context size");
_Static_assert(_Alignof(FiberContext) == 8u,
    "[fiber]: build-selected facade exposed the wrong context alignment");
_Static_assert(sizeof(FIBER_PORT_NAME) == sizeof("ARM_CM3_MPU"),
    "[fiber]: build-selected facade exposed the wrong diagnostic identity");

int fiber_arm_cm3_mpu_selected_facade_probe(void)
{
    return 0;
}
"@
    Set-Content -LiteralPath $selectedFacadeSource -Value $selectedFacadeText `
        -Encoding ASCII
    $selectedFacadeBaseArgs = @(
        "-mcpu=cortex-m3",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu11"
    ) + $warningArgs + $manifestDefines + $includeArgs
    $selectedFacadeArgs = $selectedFacadeBaseArgs + @(
        "-c", $selectedFacadeSource,
        "-o", $selectedFacadeObject
    )
    & $Compiler @selectedFacadeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM3_MPU build-selected public facade failed compile"
    }
    $selectedFacadeMacros = (& $Compiler @($selectedFacadeBaseArgs + @(
        "-dM", "-E", $selectedFacadeSource))) -join "`n"
    if (($LASTEXITCODE -ne 0) -or
            ($selectedFacadeMacros -notmatch
            '(?m)^#define FIBER_PORT_NAME "ARM_CM3_MPU"$')) {
        throw "ARM_CM3_MPU build-selected facade lost its exact diagnostic name"
    }

    $autoFacadeSource = Join-Path $probeDir "auto-facade.c"
    $autoFacadeObject = Join-Path $probeDir "auto-facade.o"
    $autoFacadeText = @"
#include <stddef.h>
#include "fiber/fiber_core.h"

_Static_assert(offsetof(FiberContext, sp) == 0u,
    "[fiber]: ARMv7-M auto selection inferred MPU privilege policy");
_Static_assert(sizeof(FiberContext) != 200u,
    "[fiber]: ARMv7-M auto selection silently selected ARM_CM3_MPU");

int fiber_arm_cm3_auto_facade_probe(void)
{
    return 0;
}
"@
    Set-Content -LiteralPath $autoFacadeSource -Value $autoFacadeText `
        -Encoding ASCII
    $autoFacadeBaseArgs = @(
        "-mcpu=cortex-m3",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu11"
    ) + $warningArgs + @(
        "-D__MPU_PRESENT=1",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot"
    )
    $autoFacadeArgs = $autoFacadeBaseArgs + @(
        "-c", $autoFacadeSource,
        "-o", $autoFacadeObject
    )
    & $Compiler @autoFacadeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARMv7-M auto selection must remain on privileged ARM_CM3 even when an MPU exists"
    }
    $autoFacadeMacros = (& $Compiler @($autoFacadeBaseArgs + @(
        "-dM", "-E", $autoFacadeSource))) -join "`n"
    if (($LASTEXITCODE -ne 0) -or
            ($autoFacadeMacros -notmatch
            '(?m)^#define FIBER_PORT_NAME "ARM_CM3"$')) {
        throw "ARMv7-M auto selection changed its privileged ARM_CM3 identity"
    }

    $typeSource = Join-Path $probeDir "type-only.c"
    $typeObject = Join-Path $probeDir "type-only.o"
    $typeText = @"
#include <stddef.h>
#include "fiber_port_types.h"

_Static_assert(offsetof(FiberContext, protected_context_cursor) == 0u,
    "[fiber]: ARM_CM3_MPU cursor offset changed");
_Static_assert(offsetof(FiberContext, mpu_regions) == 4u,
    "[fiber]: ARM_CM3_MPU MPU image offset changed");
_Static_assert(offsetof(FiberContext, protected_context) == 36u,
    "[fiber]: ARM_CM3_MPU protected context offset changed");
_Static_assert(offsetof(FiberContext, boot) == 116u,
    "[fiber]: ARM_CM3_MPU boot offset changed");
_Static_assert(sizeof(FiberContext) == 200u,
    "[fiber]: ARM_CM3_MPU context size changed");
_Static_assert(_Alignof(FiberContext) == 8u,
    "[fiber]: ARM_CM3_MPU context alignment changed");

int fiber_arm_cm3_mpu_type_only_probe(void)
{
    return 0;
}
"@
    Set-Content -LiteralPath $typeSource -Value $typeText -Encoding ASCII

    $typeArgs = @(
        "-mcpu=cortex-m3",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu11"
    ) + $warningArgs + $typeIncludeArgs + @(
        "-c", $typeSource,
        "-o", $typeObject
    )
    & $Compiler @typeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM3_MPU type-only header failed without CMSIS"
    }

    $layoutObject = Join-Path $probeDir "layout.o"
    $layoutArgs = @(
        "-mcpu=cortex-m3",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu11"
    ) + $warningArgs + $manifestDefines + $includeArgs + @(
        "-c", $probeSource,
        "-o", $layoutObject
    )
    & $Compiler @layoutArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM3_MPU exact layout manifest failed compile"
    }

    $nmOutput = & $Nm --defined-only $layoutObject
    if ($LASTEXITCODE -ne 0) {
        throw "nm failed for ARM_CM3_MPU layout probe"
    }
    $cohortSymbols = @()
    foreach ($line in $nmOutput) {
        if ($line -match '\b(?<symbol>fiber_port_context_cohort_\S+)\s*$') {
            $cohortSymbols += $Matches['symbol']
        }
    }
    if ($cohortSymbols.Count -ne 1) {
        throw "ARM_CM3_MPU layout probe must define exactly one cohort symbol"
    }
    $expectedIdentity = "fiber_port_context_cohort_armv7m_p0x434D334Du_l0x00010001u_"
    if (-not $cohortSymbols[0].StartsWith($expectedIdentity,
            [System.StringComparison]::Ordinal)) {
        throw "ARM_CM3_MPU cohort identity mismatch: $($cohortSymbols[0])"
    }
    if ($cohortSymbols[0].IndexOf("p0x434D3033u",
            [System.StringComparison]::Ordinal) -ge 0) {
        throw "ARM_CM3_MPU cohort reused privileged ARM_CM3 identity"
    }

    $bootProbeSource = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm3_mpu_boot_probe.c"
    $bootObject = Join-Path $probeDir "boot.o"
    $portObject = Join-Path $probeDir "runtime-port.o"
    $bootProbeObject = Join-Path $probeDir "boot-probe.o"
    $sliceCompileArgs = @(
        "-mcpu=cortex-m3",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu11",
        "-O2",
        "-ffunction-sections",
        "-fdata-sections",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables"
    ) + $warningArgs + $manifestDefines + $includeArgs

    & $Compiler @($sliceCompileArgs + @(
        "-c", $bootSourcePath,
        "-o", $bootObject
    ))
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM3_MPU context construction source failed compile"
    }

    $r9ProbeSource = Join-Path $probeDir "r9-static-base.c"
    $r9ProbeObject = Join-Path $probeDir "r9-static-base.o"
    $r9ProbeText = @"
#include "fiber_portmacro.h"

uint32_t fiber_arm_cm3_mpu_read_static_base_probe(void)
{
    return fiber_port_read_r9();
}
"@
    Set-Content -LiteralPath $r9ProbeSource -Value $r9ProbeText `
        -Encoding ASCII
    & $Compiler @($sliceCompileArgs + @(
        "-ffixed-r9",
        "-c", $r9ProbeSource,
        "-o", $r9ProbeObject
    ))
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM3_MPU reserved-r9 static-base probe failed compile"
    }
    $r9ProbeDisassembly = (& $Objdump -dr $r9ProbeObject) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed for ARM_CM3_MPU reserved-r9 probe"
    }
    $r9ProbeBody = Get-DisassemblyFunctionBody `
        -Disassembly $r9ProbeDisassembly `
        -Symbol "fiber_arm_cm3_mpu_read_static_base_probe" `
        -Path $r9ProbeObject
    if (($r9ProbeBody -notmatch '\bmov\s+r0,\s*r9\b') -or
            ($r9ProbeBody -notmatch '\bbx\s+lr\b')) {
        throw "ARM_CM3_MPU reserved-r9 helper no longer reads the live static base"
    }

    & $Compiler @($sliceCompileArgs + @(
        "-c", $portSourcePath,
        "-o", $portObject
    ))
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM3_MPU SVC slice source failed compile"
    }

    & $Compiler @($sliceCompileArgs + @(
        "-c", $bootProbeSource,
        "-o", $bootProbeObject
    ))
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM3_MPU context construction probe failed compile"
    }

    $bootUndefined = & $Nm --undefined-only $bootObject
    if ($LASTEXITCODE -ne 0) {
        throw "nm failed for ARM_CM3_MPU construction object"
    }
    $allowedUndefined = @(
        "__fiber_mpu_unprivileged_code_start__",
        "__fiber_mpu_unprivileged_code_end__",
        "__fiber_mpu_privileged_code_start__",
        "__fiber_mpu_privileged_code_end__",
        "__fiber_mpu_privileged_data_start__",
        "__fiber_mpu_privileged_data_end__",
        "__fiber_mpu_current_context_slot_start__",
        "__fiber_mpu_current_context_slot_end__",
        "__fiber_mpu_unprivileged_ram_start__",
        "__fiber_mpu_unprivileged_ram_end__",
        "SVC_Handler",
        "PendSV_Handler",
        "fiber_internal_task_return",
        "fiber_panic",
        "fiber_port_panic_wait",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_restore_first_context_from_svc",
        "fiber_port_runtime_memory_barrier",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_schedule",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_start_first_context",
        "fiber_port_svc_dispatch",
        "fiber_port_unprivileged_task_return"
    )
    foreach ($line in $bootUndefined) {
        if ($line -notmatch '\bU\s+(?<symbol>\S+)\s*$') {
            continue
        }
        $symbol = $Matches['symbol']
        if (($allowedUndefined -notcontains $symbol) -and
                (-not $symbol.StartsWith("fiber_port_context_cohort_",
                    [System.StringComparison]::Ordinal))) {
            throw "ARM_CM3_MPU construction acquired unexpected dependency: $symbol"
        }
    }
    foreach ($requiredSymbol in $allowedUndefined) {
        if (-not ($bootUndefined -match "\b$([regex]::Escape($requiredSymbol))\s*$")) {
            throw "ARM_CM3_MPU construction lost required dependency: $requiredSymbol"
        }
    }

    $portUndefined = @(& $Nm --undefined-only $portObject)
    if ($LASTEXITCODE -ne 0) {
        throw "nm failed for ARM_CM3_MPU SVC/PendSV object"
    }
    $allowedPortUndefined = @(
        "fiber_internal_runtime_current_context_slot",
        "fiber_internal_runtime_port_abi_v1_anchor",
        "fiber_internal_runtime_publish_current_context",
        "fiber_internal_runtime_require_current_context",
        "fiber_internal_runtime_select_scheduler_candidate",
        "fiber_internal_task_return",
        "fiber_panic",
        "fiber_port_context_validate_restore",
        "fiber_port_context_validate_running_svc",
        "fiber_port_context_validate_save_current",
        "fiber_port_mpu_build_global_regions",
        "fiber_port_mpu_linker_layout_check",
        "fiber_port_mpu_load_linker_layout"
    )
    $actualPortUndefined = @(Get-NmUndefinedSymbolNames `
        -NmOutput $portUndefined -Path $portObject)
    Assert-ExactSymbolSet -Actual $actualPortUndefined `
        -Expected $allowedPortUndefined `
        -Description "ARM_CM3_MPU SVC/PendSV undefined surface"

    $bootSections = & $Objdump -h $bootObject
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed for ARM_CM3_MPU construction object"
    }
    if (-not ($bootSections -match '\.fiber_port_privileged_functions')) {
        throw "ARM_CM3_MPU construction functions are not in privileged text"
    }
    $bootSymbolTable = & $Objdump -t $bootObject
    if ($LASTEXITCODE -ne 0) {
        throw "objdump symbol-table read failed for ARM_CM3_MPU construction object"
    }
    $definedPortFunctions = 0
    foreach ($line in $bootSymbolTable) {
        if ($line -match '^\s*[0-9a-fA-F]+\s+\w+\s+F\s+(?<section>\S+)\s+[0-9a-fA-F]+\s+(?<symbol>fiber_port_\S+)\s*$') {
            $definedPortFunctions++
            if ($Matches['section'] -ne '.fiber_port_privileged_functions') {
                throw "ARM_CM3_MPU function escaped privileged text: $($Matches['symbol']) -> $($Matches['section'])"
            }
        }
    }
    if ($definedPortFunctions -eq 0) {
        throw "ARM_CM3_MPU privileged function section proof matched no functions"
    }

    $portSections = @(& $Objdump -h $portObject)
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed for ARM_CM3_MPU SVC/PendSV object"
    }
    foreach ($section in @(
            ".fiber_port_privileged_functions",
            ".fiber_port_unprivileged_functions")) {
        if (-not ($portSections -match [regex]::Escape($section))) {
            throw "ARM_CM3_MPU SVC/PendSV object lost section: $section"
        }
    }

    $portSymbolTable = @(& $Objdump -t $portObject)
    if ($LASTEXITCODE -ne 0) {
        throw "objdump symbol-table read failed for ARM_CM3_MPU SVC/PendSV object"
    }
    $unprivilegedFunctions = @(
        "fiber_port_runtime_memory_barrier",
        "fiber_port_runtime_schedule",
        "fiber_port_unprivileged_task_return"
    )
    $matchedSvcFunctions = 0
    foreach ($line in $portSymbolTable) {
        if ($line -notmatch '^\s*[0-9a-fA-F]+\s+\w+\s+F\s+(?<section>\S+)\s+[0-9a-fA-F]+\s+(?<symbol>(fiber_port_\S+|SVC_Handler|PendSV_Handler))\s*$') {
            continue
        }
        $matchedSvcFunctions++
        $expectedSection = ".fiber_port_privileged_functions"
        if ($unprivilegedFunctions -contains $Matches['symbol']) {
            $expectedSection = ".fiber_port_unprivileged_functions"
        }
        if ($Matches['section'] -ne $expectedSection) {
            throw "ARM_CM3_MPU SVC function is in the wrong protection section: $($Matches['symbol']) -> $($Matches['section'])"
        }
    }
    if ($matchedSvcFunctions -eq 0) {
        throw "ARM_CM3_MPU SVC section proof matched no functions"
    }
    $continuationSections = @{
        "fiber_port_svc_start_return_site" =
            ".fiber_port_privileged_functions"
        "fiber_port_svc_yield_return_site" =
            ".fiber_port_unprivileged_functions"
        "fiber_port_svc_return_return_site" =
            ".fiber_port_unprivileged_functions"
    }
    foreach ($continuation in $continuationSections.Keys) {
        $continuationLines = @($portSymbolTable | Where-Object {
            $_ -match ("\s" + [regex]::Escape($continuation) + "\s*$")
        })
        if ($continuationLines.Count -ne 1) {
            throw "ARM_CM3_MPU must emit exactly one SVC continuation symbol: $continuation"
        }
        $continuationFields = @($continuationLines[0].Trim() -split '\s+')
        if (($continuationFields.Count -lt 3) -or
                ($continuationFields[-3] -ne
                    $continuationSections[$continuation])) {
            throw "ARM_CM3_MPU SVC continuation is in the wrong protection section: $continuation"
        }
    }

    $portDisassembly = (& $Objdump -dr $portObject) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "objdump disassembly failed for ARM_CM3_MPU SVC/PendSV object"
    }
    $scheduleBody = Get-DisassemblyFunctionBody `
        -Disassembly $portDisassembly -Symbol "fiber_port_runtime_schedule" `
        -Path $portObject
    $selectFirstBody = Get-DisassemblyFunctionBody `
        -Disassembly $portDisassembly `
        -Symbol "fiber_port_runtime_select_first" -Path $portObject
    $yieldSiteBody = Get-DisassemblyFunctionBody `
        -Disassembly $portDisassembly `
        -Symbol "fiber_port_svc_yield_return_site" -Path $portObject
    $returnBody = Get-DisassemblyFunctionBody `
        -Disassembly $portDisassembly `
        -Symbol "fiber_port_unprivileged_task_return" -Path $portObject
    $returnSiteBody = Get-DisassemblyFunctionBody `
        -Disassembly $portDisassembly `
        -Symbol "fiber_port_svc_return_return_site" -Path $portObject
    if (($scheduleBody -notmatch '\bsvc\s+71\b') -or
            ($yieldSiteBody -notmatch '\bbx\s+lr\b')) {
        throw "ARM_CM3_MPU unprivileged schedule veneer changed generated shape"
    }
    if (($returnBody -notmatch '\bsvc\s+72\b') -or
            ($returnSiteBody -notmatch '\bb(\.w|\.n)?\b')) {
        throw "ARM_CM3_MPU unprivileged return veneer changed generated shape"
    }
    $generatedCall = {
        param([string]$Body, [string]$Symbol)

        return [regex]::Match($Body,
            '(?m)\bbl(?:\.w)?\s+[0-9a-fA-F]+\s+<' +
            [regex]::Escape($Symbol) + '(?:\+0x[0-9a-fA-F]+)?>(?=\r?$)')
    }
    $firstCriticalEnterCall = & $generatedCall $selectFirstBody `
        'fiber_port_scheduler_critical_enter'
    $firstHookCall = & $generatedCall $selectFirstBody `
        'fiber_internal_runtime_select_scheduler_candidate'
    $firstValidationCall = & $generatedCall $selectFirstBody `
        'fiber_port_context_validate_restore'
    $firstCriticalExitCall = & $generatedCall $selectFirstBody `
        'fiber_port_scheduler_critical_exit'
    if ((-not $firstCriticalEnterCall.Success) -or
            (-not $firstHookCall.Success) -or
            (-not $firstValidationCall.Success) -or
            (-not $firstCriticalExitCall.Success) -or
            ($firstCriticalEnterCall.Index -ge $firstHookCall.Index) -or
            ($firstHookCall.Index -ge $firstValidationCall.Index) -or
            ($firstValidationCall.Index -ge $firstCriticalExitCall.Index)) {
        throw "ARM_CM3_MPU first-selection generated critical envelope changed"
    }
    foreach ($veneer in @($scheduleBody, $yieldSiteBody,
            $returnBody, $returnSiteBody)) {
        if ($veneer -match '\b(mrs|msr|cpsid|cpsie|ldr|str|bl|blx)\b') {
            throw "ARM_CM3_MPU unprivileged veneer acquired privileged/stateful instructions"
        }
    }
    $startBody = Get-DisassemblyFunctionBody -Disassembly $portDisassembly `
        -Symbol "fiber_port_start_first_context" -Path $portObject
    if (($startBody -notmatch '\bsvc\s+70\b') -or
            ($startBody -notmatch '\bmsr\s+MSP\b')) {
        throw "ARM_CM3_MPU first-start SVC path changed generated shape"
    }
    $firstRestoreBody = Get-DisassemblyFunctionBody `
        -Disassembly $portDisassembly `
        -Symbol "fiber_port_restore_first_context_from_svc" `
        -Path $portObject
    $firstRestoreMsp = [regex]::Match($firstRestoreBody, '\bmsr\s+MSP\b')
    $firstRestorePsp = [regex]::Match($firstRestoreBody, '\bmsr\s+PSP\b')
    if ((-not $firstRestoreMsp.Success) -or
            (-not $firstRestorePsp.Success) -or
            ($firstRestoreMsp.Index -ge $firstRestorePsp.Index)) {
        throw "ARM_CM3_MPU first restore must discard the SVC/C MSP frames before programming PSP"
    }
    $handlerBody = Get-DisassemblyFunctionBody -Disassembly $portDisassembly `
        -Symbol "SVC_Handler" -Path $portObject
    if (($handlerBody -notmatch
            'R_ARM_ABS32\s+fiber_internal_runtime_current_context_slot') -or
            ($handlerBody -notmatch
            'R_ARM_THM_JUMP24\s+fiber_port_svc_dispatch')) {
        throw "ARM_CM3_MPU strong SVC handler lost current-slot/dispatcher routing"
    }
    $pendsvBody = Get-DisassemblyFunctionBody `
        -Disassembly $portDisassembly -Symbol "PendSV_Handler" `
        -Path $portObject
    foreach ($requiredPendSvPattern in @(
            'R_ARM_ABS32\s+fiber_internal_runtime_current_context_slot',
            'R_ARM_THM_CALL\s+fiber_port_pendsv_validate_save_current',
            'R_ARM_THM_CALL\s+fiber_port_scheduler_pick_next_from_pendsv',
            'R_ARM_THM_CALL\s+fiber_port_mpu_switch_to_context',
            '\bstmia(\.w)?\s+r3!,\s*\{r2,\s*r4[^\r\n]*lr\}',
            '\bldmia(\.w)?\s+r0,\s*\{r4[^\r\n]*fp\}',
            '\bstmia(\.w)?\s+r3!,\s*\{r0,\s*r4[^\r\n]*fp\}',
            '\bldmdb\s+r1!,\s*\{r0,\s*r4[^\r\n]*fp\}',
            '\bmsr\s+PSP\b',
            '\bstmia(\.w)?\s+r0,\s*\{r4[^\r\n]*fp\}',
            '\bldmdb\s+r1!,\s*\{r3,\s*r4[^\r\n]*lr\}',
            '\bmsr\s+CONTROL\b',
            '\bcpsie\s+i\b',
            '\bbx\s+lr\b')) {
        if ($pendsvBody -notmatch $requiredPendSvPattern) {
            throw "ARM_CM3_MPU PendSV lost generated operation: $requiredPendSvPattern"
        }
    }
    $preflightCall = [regex]::Match($pendsvBody,
        'R_ARM_THM_CALL\s+fiber_port_pendsv_validate_save_current')
    $protectedCursorLoad = [regex]::Match($pendsvBody,
        '\bldr\s+r3,\s*\[r1,\s*#0\]')
    $schedulerCall = [regex]::Match($pendsvBody,
        'R_ARM_THM_CALL\s+fiber_port_scheduler_pick_next_from_pendsv')
    $mpuCall = [regex]::Match($pendsvBody,
        'R_ARM_THM_CALL\s+fiber_port_mpu_switch_to_context')
    $cpsid = [regex]::Match($pendsvBody, '\bcpsid\s+i\b')
    $basepriWrites = [regex]::Matches($pendsvBody,
        '\bmsr\s+BASEPRI\b')
    $restorePsp = [regex]::Match($pendsvBody, '\bmsr\s+PSP\b')
    $restoreControl = [regex]::Match($pendsvBody, '\bmsr\s+CONTROL\b')
    $enableInterrupts = [regex]::Match($pendsvBody, '\bcpsie\s+i\b')
    if ((-not $preflightCall.Success) -or
            (-not $protectedCursorLoad.Success) -or
            ($preflightCall.Index -ge $protectedCursorLoad.Index)) {
        throw "ARM_CM3_MPU PendSV must validate current before reading protected context fields"
    }
    $beforeScheduler = $pendsvBody.Substring(0, $schedulerCall.Index)
    if (($beforeScheduler -match
            '\b(stmia|stmdb)(\.w)?\s+r0!?') -or
            ($beforeScheduler -match '\bstr(\.w)?\s+[^\r\n]*\[r0')) {
        throw "ARM_CM3_MPU PendSV must not write a software frame to the unprivileged PSP stack"
    }
    if ($pendsvBody -notmatch '\bmovs\s+r2,\s*#16\b') {
        throw "ARM_CM3_MPU PendSV lost the exact four-priority-bit BASEPRI threshold"
    }
    if (($basepriWrites.Count -ne 2) -or
            (-not $schedulerCall.Success) -or (-not $cpsid.Success) -or
            (-not $mpuCall.Success) -or (-not $restorePsp.Success) -or
            (-not $restoreControl.Success) -or
            (-not $enableInterrupts.Success) -or
            ($basepriWrites[0].Index -ge $schedulerCall.Index) -or
            ($schedulerCall.Index -ge $cpsid.Index) -or
            ($cpsid.Index -ge $mpuCall.Index) -or
            ($mpuCall.Index -ge $basepriWrites[1].Index) -or
            ($basepriWrites[1].Index -ge $restorePsp.Index) -or
            ($restorePsp.Index -ge $restoreControl.Index) -or
            ($restoreControl.Index -ge $enableInterrupts.Index)) {
        throw "ARM_CM3_MPU PendSV scheduler/PRIMASK/MPU/BASEPRI ordering changed"
    }
    $svcInstructions = [regex]::Matches($portDisassembly,
        '(?m)^[ ]*[0-9a-fA-F]+:[^\r\n]*\bsvc\s+(70|71|72)\b')
    if ($svcInstructions.Count -ne 3) {
        throw "ARM_CM3_MPU SVC namespace must generate exactly three service instructions"
    }

    $linkerScript = Join-Path $probeDir "arm-cm3-mpu.ld"
    $linkerText = @"
ENTRY(fiber_arm_cm3_mpu_boot_probe)
SECTIONS
{
    .fiber_privileged_code 0x08000000 :
    {
        __fiber_mpu_privileged_code_start__ = .;
        KEEP(*(.isr_vector))
        KEEP(*(.fiber_port_privileged_functions))
        *(.text*)
        *(.rodata*)
        . = __fiber_mpu_privileged_code_start__ + 0x00010000;
        __fiber_mpu_privileged_code_end__ = .;
    }
    .fiber_unprivileged_code 0x08010000 :
    {
        __fiber_mpu_unprivileged_code_start__ = .;
        KEEP(*(.fiber_port_unprivileged_functions))
        KEEP(*(.fiber_test_unprivileged_code))
        . = __fiber_mpu_unprivileged_code_start__ + 0x00010000;
        __fiber_mpu_unprivileged_code_end__ = .;
    }
    .fiber_current_context_slot 0x20000000 (NOLOAD) :
    {
        __fiber_mpu_current_context_slot_start__ = .;
        KEEP(*(.bss.fiber_runtime_current_context_slot))
        . = __fiber_mpu_current_context_slot_start__ + 0x20;
        __fiber_mpu_current_context_slot_end__ = .;
    }
    .fiber_privileged_data 0x20010000 (NOLOAD) :
    {
        __fiber_mpu_privileged_data_start__ = .;
        KEEP(*(.fiber_port_privileged_data))
        *(.data*)
        *(.bss*)
        . = __fiber_mpu_privileged_data_start__ + 0x00010000;
        __fiber_mpu_privileged_data_end__ = .;
    }
    .fiber_unprivileged_ram 0x20020000 (NOLOAD) :
    {
        __fiber_mpu_unprivileged_ram_start__ = .;
        KEEP(*(.fiber_test_unprivileged_ram))
        . = __fiber_mpu_unprivileged_ram_start__ + 0x00010000;
        __fiber_mpu_unprivileged_ram_end__ = .;
    }
    /DISCARD/ : { *(.comment*) *(.note*) }
}
"@
    Set-Content -LiteralPath $linkerScript -Value $linkerText -Encoding ASCII

    $bootElf = Join-Path $probeDir "arm-cm3-mpu.elf"
    $linkArgs = @(
        "-mcpu=cortex-m3",
        "-mthumb",
        "-mfloat-abi=soft",
        "-nostdlib",
        "-Wl,--gc-sections",
        "-Wl,-T,$linkerScript",
        $bootObject,
        $portObject,
        $bootProbeObject,
        "-o", $bootElf
    )
    & $Compiler @linkArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM3_MPU synthetic linker contract failed"
    }

    $elfSymbols = & $Nm --defined-only $bootElf
    if ($LASTEXITCODE -ne 0) {
        throw "nm failed for ARM_CM3_MPU synthetic ELF"
    }
    foreach ($requiredSymbol in @(
            "fiber_port_context_init",
            "fiber_port_mpu_build_global_regions",
            "fiber_port_context_compute_seal",
            "fiber_port_context_seal_check",
            "fiber_port_runtime_memory_barrier",
            "fiber_port_panic_wait",
            "fiber_port_require_scheduler_configuration_environment",
            "fiber_port_runtime_prepare_start",
            "fiber_port_runtime_select_first",
            "fiber_port_runtime_start_first",
            "fiber_port_runtime_schedule",
            "fiber_port_unprivileged_task_return",
            "fiber_port_start_first_context",
            "fiber_port_restore_first_context_from_svc",
            "fiber_port_svc_dispatch",
            "fiber_port_pendsv_validate_save_current",
            "fiber_port_scheduler_pick_next_from_pendsv",
            "fiber_port_mpu_switch_to_context",
            "SVC_Handler",
            "PendSV_Handler")) {
        if (-not ($elfSymbols -match "\b$([regex]::Escape($requiredSymbol))\s*$")) {
            throw "ARM_CM3_MPU synthetic ELF lost symbol: $requiredSymbol"
        }
    }
    $runtimeStateSource = Get-Content -LiteralPath (Join-Path $RepositoryRoot `
        "fiber\fiber_runtime_state.c") -Raw
    if ($runtimeStateSource.IndexOf(
            '.bss.fiber_runtime_current_context_slot',
            [System.StringComparison]::Ordinal) -lt 0) {
        throw "Common current slot lost its MPU-isolatable .bss subsection"
    }
    $slotSectionOwners = @(Get-ChildItem -LiteralPath (Join-Path `
        $RepositoryRoot "fiber") -Recurse -File -Filter "*.c" | Where-Object {
        (Get-Content -LiteralPath $_.FullName -Raw).IndexOf(
            '.bss.fiber_runtime_current_context_slot',
            [System.StringComparison]::Ordinal) -ge 0
    })
    if (($slotSectionOwners.Count -ne 1) -or
            ($slotSectionOwners[0].FullName -ne (Join-Path $RepositoryRoot `
                "fiber\fiber_runtime_state.c"))) {
        throw "Only common runtime may own the isolated current-slot input section"
    }
    $slotSymbolLines = @($elfSymbols | Where-Object {
        $_ -match '\b[Bb]\s+fiber_internal_runtime_current_context_slot\s*$'
    })
    if ($slotSymbolLines.Count -ne 1) {
        throw "ARM_CM3_MPU synthetic ELF must contain one isolated current slot"
    }
    if ($slotSymbolLines[0] -notmatch
            '^\s*(?<address>[0-9a-fA-F]+)\s+[Bb]\s+') {
        throw "ARM_CM3_MPU current-slot symbol address is unreadable"
    }
    if ([Convert]::ToUInt32($Matches['address'], 16) -ne 0x20000000) {
        throw "ARM_CM3_MPU current slot escaped its exact MPU aperture"
    }
    $elfSections = (& $Objdump -h $bootElf) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "objdump section read failed for ARM_CM3_MPU synthetic ELF"
    }
    if ($elfSections -notmatch
            '\.fiber_current_context_slot\s+00000020\s+20000000\s+') {
        throw "ARM_CM3_MPU current-slot aperture must be exactly 32 bytes"
    }

    $svcAddress = Get-StrongTextSymbolAddress -NmOutput $elfSymbols `
        -Symbol "SVC_Handler" -Path $bootElf
    $pendsvAddress = Get-StrongTextSymbolAddress -NmOutput $elfSymbols `
        -Symbol "PendSV_Handler" -Path $bootElf
    $privilegedBinary = Join-Path $probeDir "arm-cm3-mpu-privileged.bin"
    & $Objcopy -O binary --only-section=.fiber_privileged_code `
        $bootElf $privilegedBinary
    if ($LASTEXITCODE -ne 0) {
        throw "objcopy failed for ARM_CM3_MPU synthetic vector proof"
    }
    $privilegedBytes = [IO.File]::ReadAllBytes($privilegedBinary)
    if ($privilegedBytes.Length -lt 64) {
        throw "ARM_CM3_MPU synthetic vector table is incomplete"
    }
    $initialMsp = [BitConverter]::ToUInt32($privilegedBytes, 0)
    $svcVector = [BitConverter]::ToUInt32($privilegedBytes, 11 * 4)
    $pendsvVector = [BitConverter]::ToUInt32($privilegedBytes, 14 * 4)
    if ($initialMsp -ne 0x20020000) {
        throw "ARM_CM3_MPU synthetic vector initial MSP changed"
    }
    if ($svcVector -ne ($svcAddress -bor 1)) {
        throw "ARM_CM3_MPU vector slot 11 does not resolve to strong SVC_Handler"
    }
    if ($pendsvVector -ne ($pendsvAddress -bor 1)) {
        throw "ARM_CM3_MPU vector slot 14 does not resolve to strong PendSV_Handler"
    }

    $linkerBoundaries = @($allowedUndefined | Where-Object {
        $_.StartsWith("__fiber_mpu_", [System.StringComparison]::Ordinal)
    })
    foreach ($boundary in $linkerBoundaries) {
        $caseName = $boundary.Trim('_').Replace('__', '-').Replace('_', '-')
        $negativeScript = Join-Path $probeDir ("missing-" + $caseName + ".ld")
        $negativeText = $linkerText.Replace($boundary,
            $boundary + "_for_negative_probe")
        Set-Content -LiteralPath $negativeScript -Value $negativeText `
            -Encoding ASCII
        $negativeLog = Join-Path $probeDir ("missing-" + $caseName + ".log")
        $negativeArgs = @(
            "-mcpu=cortex-m3",
            "-mthumb",
            "-mfloat-abi=soft",
            "-nostdlib",
            "-Wl,--gc-sections",
            "-Wl,-T,$negativeScript",
            $bootObject,
            $portObject,
            $bootProbeObject,
            "-o", (Join-Path $probeDir ("missing-" + $caseName + ".elf"))
        )
        $negativeResult = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $negativeArgs -LogPath $negativeLog
        if ($negativeResult.ExitCode -eq 0) {
            throw "ARM_CM3_MPU missing linker boundary unexpectedly linked: $boundary"
        }
        if ($negativeResult.Output -notmatch [regex]::Escape($boundary)) {
            throw "ARM_CM3_MPU missing-boundary link failed for the wrong reason: $boundary`n$($negativeResult.Output)"
        }
    }

    $cppSource = Join-Path $probeDir "type-only.cpp"
    $cppObject = Join-Path $probeDir "type-only-cpp.o"
    $cppText = @"
#include <cstddef>
#include "fiber_port_types.h"

static_assert(offsetof(FiberContext, protected_context_cursor) == 0u,
    "[fiber]: ARM_CM3_MPU C++ cursor offset changed");
static_assert(offsetof(FiberContext, boot) == 116u,
    "[fiber]: ARM_CM3_MPU C++ boot offset changed");
static_assert(sizeof(FiberContext) == 200u,
    "[fiber]: ARM_CM3_MPU C++ context size changed");
static_assert(alignof(FiberContext) == 8u,
    "[fiber]: ARM_CM3_MPU C++ context alignment changed");

int fiber_arm_cm3_mpu_type_only_cpp_probe()
{
    return 0;
}
"@
    Set-Content -LiteralPath $cppSource -Value $cppText -Encoding ASCII
    $cppWarningArgs = @($warningArgs | Where-Object {
        ($_ -ne "-Werror=implicit-function-declaration")
    })
    $cppArgs = @(
        "-x", "c++",
        "-mcpu=cortex-m3",
        "-mthumb",
        "-mfloat-abi=soft",
        "-std=gnu++17",
        "-fno-exceptions",
        "-fno-rtti"
    ) + $cppWarningArgs + $typeIncludeArgs + @(
        "-c", $cppSource,
        "-o", $cppObject
    )
    & $Compiler @cppArgs
    if ($LASTEXITCODE -ne 0) {
        throw "ARM_CM3_MPU type-only header failed C++ compile without CMSIS"
    }

    $negativeCases = @(
        [pscustomobject]@{
            Name = "not-build-selected"
            Cpu = "-mcpu=cortex-m3"
            Defines = @($manifestDefines | Where-Object {
                ($_ -ne "-DFIBER_PORT_BUILD_SELECTED=1") -and
                ($_ -ne "-DFIBER_PORT_ARMV7M=1")
            })
            Diagnostic = "ARM_CM3_MPU is build-selected only"
        },
        [pscustomobject]@{
            Name = "wrong-cpu"
            Cpu = "-mcpu=cortex-m4"
            Defines = $manifestDefines
            Diagnostic = "build-selected FIBER_PORT_ARMV* conflicts with compiler"
        },
        [pscustomobject]@{
            Name = "mpu-absent"
            Cpu = "-mcpu=cortex-m3"
            Defines = @($manifestDefines | Where-Object {
                $_ -ne "-D__MPU_PRESENT=1"
            }) + @("-D__MPU_PRESENT=0")
            Diagnostic = "ARM_CM3_MPU manifest requires __MPU_PRESENT == 1"
        },
        [pscustomobject]@{
            Name = "wrong-cmsis-core"
            Cpu = "-mcpu=cortex-m3"
            Defines = @($manifestDefines | Where-Object {
                $_ -ne "-D__CORTEX_M=3"
            }) + @("-D__CORTEX_M=4")
            Diagnostic = "ARM_CM3_MPU manifest requires CMSIS __CORTEX_M == 3"
        }
    )

    foreach ($case in $negativeCases) {
        $objectPath = Join-Path $probeDir ($case.Name + ".o")
        $logPath = Join-Path $probeDir ($case.Name + ".log")
        $args = @(
            $case.Cpu,
            "-mthumb",
            "-mfloat-abi=soft",
            "-std=gnu11"
        ) + $warningArgs + $case.Defines + $includeArgs + @(
            "-c", $probeSource,
            "-o", $objectPath
        )
        $result = Invoke-CompilerProbe -Compiler $Compiler -Arguments $args `
            -LogPath $logPath
        if ($result.ExitCode -eq 0) {
            throw "Invalid ARM_CM3_MPU layout manifest unexpectedly compiled: $($case.Name)"
        }
        $normalizedOutput = $result.Output -replace '\s+', ' '
        if ($normalizedOutput -notmatch [regex]::Escape($case.Diagnostic)) {
            throw "ARM_CM3_MPU negative probe failed for the wrong reason: $($case.Name)`n$($result.Output)"
        }
    }
}

function Test-ArmCm3MpuRuntimeIntegration {
    param(
        [string]$RepositoryRoot,
        [string]$Compiler,
        [string]$Nm,
        [string]$GccNm,
        [string]$Objdump,
        [string]$Objcopy,
        [string]$Ar,
        [string]$CmsisPath,
        [string]$BuildRoot
    )

    $profileDir = Join-Path $RepositoryRoot "fiber\port\ARM_CM3_MPU"
    $startupSource = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm3_mpu_runtime_startup.c"
    $portableSource = Join-Path $RepositoryRoot `
        "tools\fixtures\portable_application.c"
    $expectationSource = Join-Path $RepositoryRoot `
        "fiber\port\fiber_port_context_cohort_expectation.c"
    $linkerScript = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm3_mpu_runtime.ld"
    foreach ($requiredPath in @($startupSource, $portableSource,
            $expectationSource, $linkerScript)) {
        if (-not (Test-Path -LiteralPath $requiredPath)) {
            throw "ARM_CM3_MPU runtime integration fixture is missing: $requiredPath"
        }
    }

    $commonSources = @(
        "fiber\fiber_core.c",
        "fiber\fiber_runtime_state.c",
        "fiber\fiber_panic.c"
    )
    $portSources = @(
        "fiber\port\ARM_CM3_MPU\fiber_port.c",
        "fiber\port\ARM_CM3_MPU\fiber_port_boot.c"
    )
    $forwardAbiSymbols = @(
        "fiber_port_context_init",
        "fiber_port_runtime_memory_barrier",
        "fiber_port_panic_wait",
        "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_prepare_start",
        "fiber_port_runtime_select_first",
        "fiber_port_runtime_start_first",
        "fiber_port_runtime_schedule"
    )
    $manifestDefines = @(
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV7M=1",
        "-D__CORTEX_M=3",
        "-D__MPU_PRESENT=1",
        "-D__VTOR_PRESENT=1",
        "-D__FPU_PRESENT=0",
        "-D__FPU_USED=0",
        "-D__NVIC_PRIO_BITS=4"
    )
    $counterFlags = @(
        "-fno-instrument-functions",
        "-fno-stack-protector",
        "-fno-profile-arcs",
        "-fno-test-coverage",
        "-fno-sanitize=all",
        "-mgeneral-regs-only"
    )

    foreach ($useLto in @($false, $true)) {
        $mode = if ($useLto) { "lto" } else { "normal" }
        $probeDir = Join-Path $BuildRoot "arm-cm3-mpu-runtime-$mode"
        New-Item -ItemType Directory -Path $probeDir | Out-Null
        Set-Content -LiteralPath (Join-Path $probeDir "main.h") `
            -Value "#ifndef MAIN_H_`n#define MAIN_H_`n#endif`n" `
            -Encoding ASCII

        $ltoArgs = if ($useLto) { @("-flto") } else { @() }
        $stackUsageArgs = if ($useLto) { @() } else { @("-fstack-usage") }
        $baseArgs = @(
            "-mcpu=cortex-m3",
            "-mthumb",
            "-mfloat-abi=soft",
            "-O2",
            "-std=gnu11",
            "-ffreestanding",
            "-fno-common",
            "-fno-builtin",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wundef",
            "-Werror=undef",
            "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot",
            "-I$CmsisPath",
            "-I$probeDir"
        ) + $manifestDefines + $ltoArgs

        $archiveObjects = @()
        foreach ($source in ($commonSources + $portSources)) {
            $object = Join-Path $probeDir `
                (($source -replace '[\\/]', '_') + ".o")
            $sourcePath = Join-Path $RepositoryRoot $source
            $extraFlags = if ($portSources -contains $source) {
                $counterFlags
            }
            else {
                @()
            }
            & $Compiler @($baseArgs + $stackUsageArgs + $extraFlags + @(
                "-c", $sourcePath, "-o", $object))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM3_MPU runtime archive compile failed ($mode): $source"
            }
            $archiveObjects += $object
        }

        $startupObject = Join-Path $probeDir "startup.o"
        $portableObject = Join-Path $probeDir "portable.o"
        $expectationObject = Join-Path $probeDir "expectation.o"
        foreach ($compile in @(
                [pscustomobject]@{ Source = $startupSource; Object = $startupObject; Name = "startup" },
                [pscustomobject]@{ Source = $portableSource; Object = $portableObject; Name = "portable application" },
                [pscustomobject]@{ Source = $expectationSource; Object = $expectationObject; Name = "cohort expectation" })) {
            $fixtureArgs = $baseArgs
            if ($useLto -and ($compile.Name -eq "portable application")) {
                $fixtureArgs = @($baseArgs | Where-Object { $_ -ne "-flto" })
                $fixtureArgs += "-fno-lto"
            }
            & $Compiler @($fixtureArgs + $counterFlags + @(
                "-c", $compile.Source, "-o", $compile.Object))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM3_MPU $($compile.Name) compile failed ($mode)"
            }
        }

        $objectNm = if ($useLto) { $GccNm } else { $Nm }
        $expectationUndefined = @(& $objectNm --undefined-only `
            $expectationObject)
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM3_MPU expectation nm failed ($mode)"
        }
        $expectedCohort = @($expectationUndefined | Where-Object {
            $_ -match '\bU\s+fiber_port_context_cohort_armv7m_\S+$'
        })
        if ($expectedCohort.Count -ne 1) {
            throw "ARM_CM3_MPU expectation must retain one exact cohort relocation ($mode)"
        }

        $archivePath = Join-Path $probeDir "libfiber-arm-cm3-mpu.a"
        & $Ar rcs $archivePath @archiveObjects
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM3_MPU runtime archive creation failed ($mode)"
        }

        $elfPath = Join-Path $probeDir "fiber-arm-cm3-mpu.elf"
        $mapPath = Join-Path $probeDir "fiber-arm-cm3-mpu.map"
        $linkArgs = @(
            "-mcpu=cortex-m3",
            "-mthumb",
            "-mfloat-abi=soft"
        ) + $ltoArgs + @(
            "-nostdlib",
            "-Wl,--gc-sections",
            "-Wl,-Map,$mapPath",
            "-Wl,-T,$linkerScript",
            $startupObject,
            $portableObject,
            $expectationObject,
            $archivePath,
            "-o", $elfPath
        )
        & $Compiler @linkArgs
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM3_MPU portable archive/link integration failed ($mode)"
        }

        $defined = @(& $Nm -a --defined-only $elfPath)
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM3_MPU final ELF nm failed ($mode)"
        }
        foreach ($symbol in $forwardAbiSymbols) {
            $definitions = @($defined | Where-Object {
                $_ -match ("\b[TW]\s+" + [regex]::Escape($symbol) + "$")
            })
            if ($definitions.Count -ne 1) {
                throw "ARM_CM3_MPU final ELF must define one strong forward ABI symbol ($mode): $symbol"
            }
        }

        $cohortDefinitions = @($defined | Where-Object {
            $_ -match '\b[RT]\s+fiber_port_context_cohort_armv7m_\S+$'
        })
        if ($cohortDefinitions.Count -ne 1) {
            throw "ARM_CM3_MPU final ELF must contain one exact context cohort ($mode)"
        }

        $svcAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
            -Symbol "SVC_Handler" -Path $elfPath
        $pendsvAddress = Get-StrongTextSymbolAddress -NmOutput $defined `
            -Symbol "PendSV_Handler" -Path $elfPath

        $symbolRanges = @(
            [pscustomobject]@{
                Start = [uint32]0x08010000
                End = [uint32]0x08020000
                Name = "unprivileged code"
                Symbols = @(
                    "fiber_current",
                    "fiber_schedule",
                    "fiber_internal_runtime_load_current_context",
                    "fiber_port_runtime_memory_barrier",
                    "fiber_port_runtime_schedule",
                    "fiber_port_unprivileged_task_return"
                )
            },
            [pscustomobject]@{
                Start = [uint32]0x08000000
                End = [uint32]0x08010000
                Name = "privileged code"
                Symbols = @(
                    "fiber_init",
                    "fiber_start",
                    "fiber_scheduler_set_pick_next",
                    "fiber_internal_runtime_select_scheduler_candidate",
                    "fiber_internal_runtime_publish_current_context",
                    "fiber_internal_runtime_require_current_context",
                    "fiber_internal_task_return",
                    "fiber_panic",
                    "fiber_port_context_init",
                    "fiber_port_panic_wait",
                    "fiber_port_require_scheduler_configuration_environment",
                    "fiber_port_runtime_prepare_start",
                    "fiber_port_runtime_select_first",
                    "fiber_port_runtime_start_first",
                    "portable_fixture_pick_next",
                    "SVC_Handler",
                    "PendSV_Handler"
                )
            }
        )
        foreach ($range in $symbolRanges) {
            foreach ($symbol in $range.Symbols) {
                $lines = @($defined | Where-Object {
                    $_ -match ("^\s*(?<address>[0-9a-fA-F]+)\s+[TtWw]\s+" +
                        [regex]::Escape($symbol) + "$")
                })
                if ($lines.Count -ne 1) {
                    throw "ARM_CM3_MPU ELF lost range-audited symbol ($mode): $symbol"
                }
                $null = $lines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
                $address = [Convert]::ToUInt32($Matches['address'], 16)
                if (($address -lt $range.Start) -or ($address -ge $range.End)) {
                    throw "ARM_CM3_MPU symbol escaped $($range.Name) ($mode): $symbol at 0x$($address.ToString('X8'))"
                }
            }
        }

        $portableEntryLines = @($defined | Where-Object {
            $_ -match '^\s*(?<address>[0-9a-fA-F]+)\s+[Tt]\s+portable_fixture_entry(\.\S+)?$'
        })
        if ($portableEntryLines.Count -ne 1) {
            throw "ARM_CM3_MPU portable entry must survive in one unprivileged section ($mode)"
        }
        $null = $portableEntryLines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
        $portableEntryAddress = [Convert]::ToUInt32($Matches['address'], 16)
        if (($portableEntryAddress -lt 0x08010000) -or
                ($portableEntryAddress -ge 0x08020000)) {
            throw "ARM_CM3_MPU portable entry is not executable by unprivileged Thread mode ($mode)"
        }

        foreach ($stack in @("portable_fixture_stack_1",
                "portable_fixture_stack_2")) {
            $stackLines = @($defined | Where-Object {
                $_ -match ("^\s*(?<address>[0-9a-fA-F]+)\s+[Bb]\s+" +
                    [regex]::Escape($stack) + "$")
            })
            if ($stackLines.Count -ne 1) {
                throw "ARM_CM3_MPU portable stack symbol is missing ($mode): $stack"
            }
            $null = $stackLines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
            $stackAddress = [Convert]::ToUInt32($Matches['address'], 16)
            if (($stackAddress -lt 0x20020000) -or
                    ($stackAddress -ge 0x20030000) -or
                    (($stackAddress -band 0x7FF) -ne 0)) {
                throw "ARM_CM3_MPU portable stack escaped exact unprivileged RAM geometry ($mode): $stack"
            }
        }
        foreach ($privilegedObject in @("portable_fixture_context_1",
                "portable_fixture_context_2",
                "portable_fixture_scheduler_user")) {
            $objectLines = @($defined | Where-Object {
                $_ -match ("^\s*(?<address>[0-9a-fA-F]+)\s+[Bb]\s+" +
                    [regex]::Escape($privilegedObject) + "$")
            })
            if ($objectLines.Count -ne 1) {
                throw "ARM_CM3_MPU privileged application object is missing ($mode): $privilegedObject"
            }
            $null = $objectLines[0] -match '^\s*(?<address>[0-9a-fA-F]+)'
            $objectAddress = [Convert]::ToUInt32($Matches['address'], 16)
            if (($objectAddress -lt 0x20010000) -or
                    ($objectAddress -ge 0x20020000)) {
                throw "ARM_CM3_MPU application-owned scheduler/context object escaped privileged data ($mode): $privilegedObject"
            }
        }

        $slotLines = @($defined | Where-Object {
            $_ -match '^\s*20000000\s+[Bb]\s+fiber_internal_runtime_current_context_slot$'
        })
        if ($slotLines.Count -ne 1) {
            throw "ARM_CM3_MPU current slot escaped its exact 32-byte aperture ($mode)"
        }

        $sections = (& $Objdump -h $elfPath) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM3_MPU final ELF section audit failed ($mode)"
        }
        foreach ($requiredSection in @(
                '\.isr_vector\s+00000040\s+08000000\s+',
                '\.fiber_unprivileged_code\s+[0-9a-fA-F]+\s+08010000\s+',
                '\.fiber_privileged_code\s+[0-9a-fA-F]+\s+08000040\s+',
                '\.fiber_current_context_slot\s+00000020\s+20000000\s+',
                '\.fiber_unprivileged_ram\s+[0-9a-fA-F]+\s+20020000\s+',
                '\.fiber_privileged_data\s+[0-9a-fA-F]+\s+20010000\s+')) {
            if ($sections -notmatch $requiredSection) {
                throw "ARM_CM3_MPU final ELF lost exact MPU output section ($mode): $requiredSection"
            }
        }

        $vectorPath = Join-Path $probeDir "vectors.bin"
        & $Objcopy -O binary --only-section=.isr_vector $elfPath $vectorPath
        if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $vectorPath))) {
            throw "ARM_CM3_MPU runtime vector extraction failed ($mode)"
        }
        $vectorBytes = [IO.File]::ReadAllBytes($vectorPath)
        if ($vectorBytes.Length -ne 64) {
            throw "ARM_CM3_MPU runtime vector fixture changed size ($mode)"
        }
        $svcVector = [BitConverter]::ToUInt32($vectorBytes, 11 * 4)
        $pendsvVector = [BitConverter]::ToUInt32($vectorBytes, 14 * 4)
        if ($svcVector -ne ($svcAddress -bor 1)) {
            throw "ARM_CM3_MPU runtime vector slot 11 lost strong SVC handler ($mode)"
        }
        if ($pendsvVector -ne ($pendsvAddress -bor 1)) {
            throw "ARM_CM3_MPU runtime vector slot 14 lost strong PendSV handler ($mode)"
        }

        if (-not $useLto) {
            $stackUsageFiles = @(Get-ChildItem -LiteralPath $probeDir `
                -Filter "*.su" -File)
            if ($stackUsageFiles.Count -lt $archiveObjects.Count) {
                throw "ARM_CM3_MPU runtime proof lost compiler stack-usage artifacts"
            }
            foreach ($stackUsageFile in $stackUsageFiles) {
                $stackUsage = Get-Content -LiteralPath $stackUsageFile.FullName -Raw
                if ($stackUsage -match '(?m)\bdynamic\b') {
                    throw "ARM_CM3_MPU runtime call graph acquired dynamic stack use: $($stackUsageFile.Name)"
                }
            }
        }

        $competingSource = Join-Path $probeDir "competing.c"
        $competingObject = Join-Path $probeDir "competing.o"
        Set-Content -LiteralPath $competingSource -Encoding ASCII -Value `
            "void SVC_Handler(void) { }`nvoid PendSV_Handler(void) { }`n"
        & $Compiler @($baseArgs + @(
            "-c", $competingSource, "-o", $competingObject))
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM3_MPU competing-handler fixture compile failed ($mode)"
        }
        $duplicateLog = Join-Path $probeDir "duplicate.log"
        $duplicateArgs = @($linkArgs[0..($linkArgs.Count - 3)] + @(
            $competingObject, "-o", (Join-Path $probeDir "duplicate.elf")))
        $duplicate = Invoke-CompilerProbe -Compiler $Compiler `
            -Arguments $duplicateArgs -LogPath $duplicateLog
        if (($duplicate.ExitCode -eq 0) -or
                ($duplicate.Output -notmatch 'multiple definition')) {
            throw "ARM_CM3_MPU competing strong handlers must fail link ($mode)`n$($duplicate.Output)"
        }
    }
}

$gcc = Find-ArmGcc
$cmsis = Find-CmsisCore
$nm = Join-Path (Split-Path -Parent $gcc) "arm-none-eabi-nm.exe"
if (-not (Test-Path $nm)) {
    throw "arm-none-eabi-nm.exe not found next to compiler: $gcc"
}
$gccNm = Join-Path (Split-Path -Parent $gcc) "arm-none-eabi-gcc-nm.exe"
if (-not (Test-Path $gccNm)) {
    throw "arm-none-eabi-gcc-nm.exe not found next to compiler: $gcc"
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
Test-SelectedPortExceptionFrameGeometry -RepositoryRoot $RepoRoot
Test-SelectedPortHandlerHardening -RepositoryRoot $RepoRoot
Test-PendSvSaveValidationOrdering -RepositoryRoot $RepoRoot
Test-ScheduleValidationOwnership -RepositoryRoot $RepoRoot

$commonSources = @(
    "fiber\fiber_core.c",
    "fiber\fiber_runtime_state.c",
    "fiber\fiber_panic.c"
)

$portableApplicationFixture = "tools\fixtures\portable_application.c"
$selectedPortContextCohortExpectationFixture =
    "fiber\port\fiber_port_context_cohort_expectation.c"
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
    "fiber\port\ARM_CM23_NTZ\non_secure\fiber_port.c",
    "fiber\port\ARM_CM33_NTZ\non_secure\fiber_port.c",
    "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c"
)

$configs = @(
    [pscustomobject]@{ Name = "cortex-m0";          CpuArgs = @("-mcpu=cortex-m0");              Core = "core_cm0.h";     PriorityBits = 4; VtorPresent = 0; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m0plus";      CpuArgs = @("-mcpu=cortex-m0plus");          Core = "core_cm0plus.h"; PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m3";          CpuArgs = @("-mcpu=cortex-m3");              Core = "core_cm3.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m3-prio8";    CpuArgs = @("-mcpu=cortex-m3");              Core = "core_cm3.h";     PriorityBits = 8; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 0; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m4";          CpuArgs = @("-mcpu=cortex-m4");              Core = "core_cm4.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m4f";         CpuArgs = @("-mcpu=cortex-m4");              Core = "core_cm4.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv4-sp-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m4f-softfp-lazy"; CpuArgs = @("-mcpu=cortex-m4");          Core = "core_cm4.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv4-sp-d16", "-mfloat-abi=softfp", "-DFIBER_FPU_LAZY=1") },
    [pscustomobject]@{ Name = "cortex-m4f-prio8";   CpuArgs = @("-mcpu=cortex-m4");              Core = "core_cm4.h";     PriorityBits = 8; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv4-sp-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m7";          CpuArgs = @("-mcpu=cortex-m7");              Core = "core_cm7.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 0; FpuUsed = 0; DspPresent = 1; Extra = @() },
    [pscustomobject]@{ Name = "cortex-m7f";         CpuArgs = @("-mcpu=cortex-m7");              Core = "core_cm7.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv5-d16", "-mfloat-abi=hard") },
    [pscustomobject]@{ Name = "cortex-m7f-softfp-lazy"; CpuArgs = @("-mcpu=cortex-m7");          Core = "core_cm7.h";     PriorityBits = 4; VtorPresent = 1; FpuPresent = 1; FpuUsed = 1; DspPresent = 1; Extra = @("-mfpu=fpv5-d16", "-mfloat-abi=softfp", "-DFIBER_FPU_LAZY=1") },
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
    "cortex-m3-prio8"   = "FIBER_PORT_PROFILE_ARMV7M"
    "cortex-m4"         = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m4f"        = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m4f-softfp-lazy" = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m4f-prio8"  = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m7"         = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m7f"        = "FIBER_PORT_PROFILE_ARMV7EM"
    "cortex-m7f-softfp-lazy" = "FIBER_PORT_PROFILE_ARMV7EM"
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
    "cortex-m7f-softfp-lazy" = "fiber\port\ARM_CM7\r0p1"
    "cortex-m7f-prio8" = "fiber\port\ARM_CM7\r0p1"
    "cortex-m23" = "fiber\port\ARM_CM23_NTZ\non_secure"
    "cortex-m33" = "fiber\port\ARM_CM33_NTZ\non_secure"
}

$buildSelectedPortSourcesByConfig = @{
    "cortex-m7"  = @("fiber\port\ARM_CM7\r0p1\fiber_port.c", "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c", "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c")
    "cortex-m7f" = @("fiber\port\ARM_CM7\r0p1\fiber_port.c", "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c", "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c")
    "cortex-m7f-softfp-lazy" = @("fiber\port\ARM_CM7\r0p1\fiber_port.c", "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c", "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c")
    "cortex-m7f-prio8" = @("fiber\port\ARM_CM7\r0p1\fiber_port.c", "fiber\port\ARM_CM7\r0p1\fiber_port_boot.c", "fiber\port\ARM_CM7\r0p1\fiber_port_exception.c")
    "cortex-m23" = @("fiber\port\ARM_CM23_NTZ\non_secure\fiber_port.c", "fiber\port\ARM_CM23_NTZ\non_secure\fiber_port_boot.c")
    "cortex-m33" = @("fiber\port\ARM_CM33_NTZ\non_secure\fiber_port.c", "fiber\port\ARM_CM33_NTZ\non_secure\fiber_port_boot.c")
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

# Concrete runtime ports may intentionally omit legacy private helper names.
# Their build-selected proof instead requires the frozen common-to-port ABI;
# their own source/ELF cohort proves the port-private SVC/PendSV mechanics.
$requiredForwardPortSymbols = @(
    "fiber_port_context_init",
    "fiber_port_runtime_memory_barrier",
    "fiber_port_panic_wait",
    "fiber_port_require_scheduler_configuration_environment",
    "fiber_port_runtime_prepare_start",
    "fiber_port_runtime_select_first",
    "fiber_port_runtime_start_first",
    "fiber_port_runtime_schedule"
)

$requiredReverseSymbolTypes = @{
    "fiber_internal_runtime_port_abi_v1_anchor"       = "R"
    "fiber_internal_runtime_current_context_slot"     = "B"
    "fiber_internal_runtime_select_scheduler_candidate" = "T"
    "fiber_internal_runtime_publish_current_context"  = "T"
    "fiber_internal_runtime_require_current_context"  = "T"
    "fiber_internal_task_return"                      = "T"
}

$commonOwnedReverseSymbols = @(
    "fiber_internal_runtime_port_abi_v1_anchor",
    "fiber_internal_runtime_current_context_slot",
    "fiber_internal_runtime_select_scheduler_candidate",
    "fiber_internal_runtime_publish_current_context",
    "fiber_internal_runtime_require_current_context",
    "fiber_internal_task_return",
    "fiber_panic"
)

# This is the complete selected-port-to-outside symbol surface after all
# objects from one selected port are combined with a relocatable link.
$selectedPortUndefinedSymbols = @(
    "fiber_addr_plausible_code",
    "fiber_addr_plausible_ram",
    "fiber_internal_runtime_current_context_slot",
    "fiber_internal_runtime_port_abi_v1_anchor",
    "fiber_internal_runtime_publish_current_context",
    "fiber_internal_runtime_require_current_context",
    "fiber_internal_runtime_select_scheduler_candidate",
    "fiber_internal_task_return",
    "fiber_panic",
    "memcpy",
    "memset"
)

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

    Write-Host "== pinned FreeRTOS generated-assembly parity =="
    foreach ($parityOptimization in @("-O2", "-Os")) {
        $parityBuildName = "freertos-asm-parity-" +
            $parityOptimization.Substring(1).ToLowerInvariant()
        & (Join-Path $RepoRoot "tools\freertos_asm_parity.ps1") `
            -ArmGcc $gcc -CmsisCore $cmsis `
            -Optimization $parityOptimization `
            -BuildRoot (Join-Path $buildRoot $parityBuildName)
        if ($LASTEXITCODE -ne 0) {
            throw "Pinned FreeRTOS generated-assembly parity failed for $parityOptimization"
        }
    }

    Write-Host "== common-runtime / no-cmsis =="
    Test-CommonRuntimeWithoutCmsis -RepositoryRoot $RepoRoot -Compiler $gcc `
        -Objdump $objdump -BuildRoot $buildRoot
    Write-Host "== reverse ABI current-slot C isolation =="
    Test-ReverseAbiSlotCIsolation -RepositoryRoot $RepoRoot -Compiler $gcc `
        -BuildRoot $buildRoot
    Write-Host "== reverse ABI version mismatch contract =="
    Test-ReverseAbiVersionMismatch -Compiler $gcc -Ar $ar `
        -BuildRoot $buildRoot
    Write-Host "== sensitive generated-code contract =="
    Test-AdversarialSensitiveGeneratedCode -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Objdump $objdump -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== CM7 strong-handler archive/ELF contract =="
    Test-Cm7StrongHandlerElfOwnership -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -Objcopy $objcopy -Ar $ar `
        -CmsisPath $cmsis -BuildRoot $buildRoot
    Write-Host "== exact selected-port context-cohort contract =="
    Test-SelectedPortContextCohortMismatch -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -GccNm $gccNm -Ar $ar -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== BASEPRI/NVIC exact context-cohort identity =="
    Test-BasepriContextCohortIdentity -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -CmsisPath $cmsis -BuildRoot $buildRoot
    Write-Host "== ARM_CM23_NTZ layout/startup/PendSV source contract =="
    Test-ArmCm23NtzRuntimeContract -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -Objdump $objdump -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== ARM_CM23_NTZ full runtime/archive/ELF contract =="
    Test-ArmCm23NtzRuntimeIntegration -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -GccNm $gccNm -Objdump $objdump `
        -Objcopy $objcopy -Ar $ar -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== ARM_CM33_MPU layout/trait contract through slice 3 =="
    Test-ArmCm33MpuLayoutContract -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== ARM_CM33_MPU sealed construction/linker contract =="
    Test-ArmCm33MpuConstructionContract -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -GccNm $gccNm -Objdump $objdump -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== ARM_CM33_MPU protected SVC first-start contract =="
    Test-ArmCm33MpuFirstStartContract -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -GccNm $gccNm -Objdump $objdump `
        -Objcopy $objcopy -CmsisPath $cmsis -BuildRoot $buildRoot
    Write-Host "== ARM_CM33_NTZ full runtime/archive/ELF contract =="
    Test-ArmCm33NtzRuntimeContract -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -GccNm $gccNm -Objdump $objdump -Ar $ar `
        -Objcopy $objcopy -CmsisPath $cmsis -BuildRoot $buildRoot
    Write-Host "== ARM_CM33F_NTZ full FPU runtime/archive/ELF contract =="
    Test-ArmCm33FNtzRuntimeContract -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -GccNm $gccNm -Objdump $objdump `
        -Objcopy $objcopy -Ar $ar -CmsisPath $cmsis -BuildRoot $buildRoot
    Write-Host "== ARM_CM0_MPU slice-6 forward ABI/linker/cohort contract =="
    Test-ArmCm0MpuLayoutContract -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -Objdump $objdump -Objcopy $objcopy -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== ARM_CM0_MPU full runtime/archive/MPU-linker contract =="
    Test-ArmCm0MpuRuntimeIntegration -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -GccNm $gccNm -Objdump $objdump `
        -Objcopy $objcopy -Ar $ar -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== ARM_CM4_MPU slice-5 full runtime contract =="
    Test-ArmCm4MpuSlice5Contract -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -Objdump $objdump -Objcopy $objcopy `
        -CmsisPath $cmsis -BuildRoot $buildRoot
    Write-Host "== ARM_CM4_MPU full runtime/archive/MPU-linker contract =="
    Test-ArmCm4MpuRuntimeIntegration -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -GccNm $gccNm -Objdump $objdump `
        -Objcopy $objcopy -Ar $ar -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== ARM_CM3_MPU construction/SVC/PendSV contract =="
    Test-ArmCm3MpuLayoutContract -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -Objdump $objdump -Objcopy $objcopy `
        -CmsisPath $cmsis `
        -BuildRoot $buildRoot
    Write-Host "== ARM_CM3_MPU full runtime/archive/MPU-linker contract =="
    Test-ArmCm3MpuRuntimeIntegration -RepositoryRoot $RepoRoot `
        -Compiler $gcc -Nm $nm -GccNm $gccNm -Objdump $objdump `
        -Objcopy $objcopy -Ar $ar -CmsisPath $cmsis `
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
                $sources += @(
                    $portableApplicationFixture,
                    $selectedPortContextCohortExpectationFixture
                )
            }
            $objects = @()
            $portObjects = @()
            $runtimeAbiAnchorReferenceCount = 0
            $strongPortPanicReferenceCount = 0
            $portCohortDefinitions = @()
            $portCohortReferences = @()
            $expectationCohortReferences = @()

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

                $generatedAssemblyPath = $null
                $generatedAssemblyArgs = @()
                if (($mode.Name -eq "build-selected") -and
                        ($mandatoryPortRuntimeSources -contains $source)) {
                    $generatedAssemblyPath = [IO.Path]::ChangeExtension(
                        $objPath, ".s")
                    $generatedAssemblyArgs = @("-save-temps=obj")
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
                ) + $mode.Defines + $dependencyArgs +
                $generatedAssemblyArgs + @(
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

                if ($null -ne $generatedAssemblyPath) {
                    Test-GeneratedCurrentSlotLoadOnly `
                        -AssemblyPath $generatedAssemblyPath
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

                if (($mode.PortSources -contains $source) -or
                        ($source -eq
                        $selectedPortContextCohortExpectationFixture)) {
                    $cohortDefinedOutput = @(
                        & $nm -g --defined-only $objPath)
                    if ($LASTEXITCODE -ne 0) {
                        throw "Context-cohort definition scan failed for $($cfg.Name) / $($mode.Name): $source"
                    }
                    $cohortUndefinedOutput = @(& $nm -u $objPath)
                    if ($LASTEXITCODE -ne 0) {
                        throw "Context-cohort relocation scan failed for $($cfg.Name) / $($mode.Name): $source"
                    }

                    $definitions = @($cohortDefinedOutput |
                        ForEach-Object {
                            if ($_ -match
                                    '\sR\s+(fiber_port_context_cohort_\S+)$') {
                                $Matches[1]
                            }
                        })
                    $references = @($cohortUndefinedOutput |
                        ForEach-Object {
                            if ($_ -match
                                    '\bU\s+(fiber_port_context_cohort_\S+)$') {
                                $Matches[1]
                            }
                        })

                    if ($source -eq
                            $selectedPortContextCohortExpectationFixture) {
                        if ($definitions.Count -ne 0) {
                            throw "Build-owned context-cohort expectation must not define a cohort symbol for $($cfg.Name)"
                        }
                        $expectationCohortReferences += $references
                    }
                    else {
                        $portCohortDefinitions += $definitions
                        $portCohortReferences += $references
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
                if ($mode.PortSources -contains $source) {
                    $portObjects += $objPath
                }
            }

            if ($runtimeAbiAnchorReferenceCount -ne 1) {
                throw "Expected one active selected-port v1 anchor relocation for $($cfg.Name) / $($mode.Name); found $runtimeAbiAnchorReferenceCount"
            }
            if ($strongPortPanicReferenceCount -ne 1) {
                throw "Expected one active selected-port strong panic reference for $($cfg.Name) / $($mode.Name); found $strongPortPanicReferenceCount"
            }

            if ($portCohortDefinitions.Count -ne 1) {
                throw "Expected one exact selected-port context-cohort definition for $($cfg.Name) / $($mode.Name); found $($portCohortDefinitions.Count)"
            }
            # The concrete NTZ ports have two mandatory objects: runtime owns
            # the cohort definition and boot retains it. Other active ports
            # retain it from both boot and a separate exception object.
            $expectedPortCohortReferenceCount = if (
                    ($mode.Name -eq "build-selected") -and
                    (($cfg.Name -eq "cortex-m23") -or
                     ($cfg.Name -eq "cortex-m33"))) {
                1
            }
            else {
                2
            }
            if ($portCohortReferences.Count -ne
                    $expectedPortCohortReferenceCount) {
                throw "Expected $expectedPortCohortReferenceCount selected-port context-cohort relocation(s) for $($cfg.Name) / $($mode.Name); found $($portCohortReferences.Count)"
            }
            foreach ($reference in $portCohortReferences) {
                if ($reference -ne $portCohortDefinitions[0]) {
                    throw "Selected-port private object expects stale context cohort for $($cfg.Name) / $($mode.Name): $reference"
                }
            }
            if ($mode.Name -eq "build-selected") {
                if (($expectationCohortReferences.Count -ne 1) -or
                        ($expectationCohortReferences[0] -ne
                        $portCohortDefinitions[0])) {
                    throw "Build-owned object must expect the exact selected context cohort for $($cfg.Name): $($expectationCohortReferences -join ', ')"
                }
            }
            elseif ($expectationCohortReferences.Count -ne 0) {
                throw "Non-build-selected mode unexpectedly compiled a context-cohort expectation object for $($cfg.Name) / $($mode.Name)"
            }

            if ($portObjects.Count -eq 0) {
                throw "Selected-port object group is empty for $($cfg.Name) / $($mode.Name)"
            }

            $portGroupObject = Join-Path $cfgDir "selected-port-group.o"
            $portGroupLinkArgs = $cfg.CpuArgs + $mode.ExtraArgs +
                @("-mthumb") + $cfg.Extra + @(
                    "-nostdlib",
                    "-r",
                    "-o",
                    $portGroupObject
                ) + $portObjects
            & $gcc @portGroupLinkArgs
            if ($LASTEXITCODE -ne 0) {
                throw "Selected-port relocatable link failed for $($cfg.Name) / $($mode.Name)"
            }

            $portUndefinedOutput = @(& $nm -u $portGroupObject)
            if ($LASTEXITCODE -ne 0) {
                throw "Selected-port unresolved-symbol scan failed for $($cfg.Name) / $($mode.Name)"
            }
            $portUndefinedSymbols = @(Get-NmUndefinedSymbolNames `
                -NmOutput $portUndefinedOutput -Path $portGroupObject)
            Assert-ExactSymbolSet -Expected $selectedPortUndefinedSymbols `
                -Actual $portUndefinedSymbols `
                -Description "Selected-port unresolved ABI for $($cfg.Name) / $($mode.Name)"

            $portDefinedSymbols = @(& $nm -g --defined-only $portGroupObject)
            if ($LASTEXITCODE -ne 0) {
                throw "Selected-port defined-symbol scan failed for $($cfg.Name) / $($mode.Name)"
            }
            foreach ($symbol in $commonOwnedReverseSymbols) {
                if ($portDefinedSymbols -match
                        "\s[A-Za-z]\s+$([regex]::Escape($symbol))$") {
                    throw "Selected port must not define common-owned reverse symbol for $($cfg.Name) / $($mode.Name): $symbol"
                }
            }
            $linkedPortCohorts = @($portDefinedSymbols | ForEach-Object {
                if ($_ -match
                        '\sR\s+(fiber_port_context_cohort_\S+)$') {
                    $Matches[1]
                }
            })
            if (($linkedPortCohorts.Count -ne 1) -or
                    ($linkedPortCohorts[0] -ne
                    $portCohortDefinitions[0])) {
                throw "Selected-port group does not retain exactly one context cohort for $($cfg.Name) / $($mode.Name)"
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

            $requiredSymbolsForMode = $requiredPortSymbols
            if ((($cfg.Name -eq "cortex-m23") -or
                 ($cfg.Name -eq "cortex-m33")) -and
                    ($mode.Name -eq "build-selected")) {
                $requiredSymbolsForMode = $requiredForwardPortSymbols
            }
            foreach ($symbol in $requiredSymbolsForMode) {
                $definitions = @($definedSymbols | Where-Object {
                    $_ -match "\s[TW]\s+$([regex]::Escape($symbol))$"
                })
                if ($definitions.Count -ne 1) {
                    throw "Expected exactly one $symbol definition for $($cfg.Name) / $($mode.Name); found $($definitions.Count)"
                }
            }

            $linkedCohorts = @($definedSymbols | ForEach-Object {
                if ($_ -match
                        '\sR\s+(fiber_port_context_cohort_\S+)$') {
                    $Matches[1]
                }
            })
            if (($linkedCohorts.Count -ne 1) -or
                    ($linkedCohorts[0] -ne $portCohortDefinitions[0])) {
                throw "Final matrix link does not contain the exact selected context cohort for $($cfg.Name) / $($mode.Name)"
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

        Write-Host "== cortex-m33 / transitional-contract-normalized-role-token =="
        $normalizedRoleArgs = $v8ProbeCfg.CpuArgs + @("-mthumb") +
            $v8ProbeCfg.Extra + @(
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
                "-DFIBER_TRANSITIONAL_V8M_RUN_NONSECURE=(1)",
                "-I$v8ProbeDir",
                "-I$RepoRoot",
                "-I$(Join-Path $RepoRoot 'fiber')",
                "-I$cmsis",
                "-c",
                (Join-Path $RepoRoot "fiber\port\transitional_v8m\fiber_port_transitional_v8m.c"),
                "-o",
                (Join-Path $v8ProbeDir "normalized-role-token.o")
            )
        & $gcc @normalizedRoleArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Valid parenthesized transitional v8-M role did not normalize to one cohort token"
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

    Write-Host "== cortex-m0 / settings-contract-reject-basepri =="
    $cm0ProbeDir = Join-Path $buildRoot "cm0-settings-contract"
    New-Item -ItemType Directory -Path $cm0ProbeDir | Out-Null
    $cm0Header = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 0U
#define __VTOR_PRESENT 0U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    SVCall_IRQn = -5, PendSV_IRQn = -2,
    SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm0.h"
#endif
"@
    Set-Content -LiteralPath (Join-Path $cm0ProbeDir "main.h") `
        -Value $cm0Header -Encoding ASCII
    $cm0BasepriArgs = @(
        "-mcpu=cortex-m0",
        "-mthumb",
        "-std=gnu11",
        "-ffreestanding",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-Wundef",
        "-Werror=undef",
        "-DFIBER_PORT_BUILD_SELECTED=1",
        "-DFIBER_PORT_ARMV6M=1",
        "-DFIBER_SCHEDULER_BASEPRI=16",
        "-I$cm0ProbeDir",
        "-I$(Join-Path $RepoRoot 'fiber\port\ARM_CM0')",
        "-I$RepoRoot",
        "-I$(Join-Path $RepoRoot 'fiber')",
        "-I$cmsis",
        "-c", (Join-Path $RepoRoot "fiber\port\ARM_CM0\fiber_port.c"),
        "-o", (Join-Path $cm0ProbeDir "reject-basepri.o")
    )
    $cm0BasepriResult = Invoke-CompilerProbe -Compiler $gcc `
        -Arguments $cm0BasepriArgs `
        -LogPath (Join-Path $cm0ProbeDir "reject-basepri.log")
    if (($cm0BasepriResult.ExitCode -eq 0) -or
            (($cm0BasepriResult.Output -replace '\s+', ' ') -notmatch
            [regex]::Escape("ARM_CM0 has no BASEPRI"))) {
        throw "ARM_CM0 must reject a nonzero scheduler BASEPRI setting:`n$($cm0BasepriResult.Output)"
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
