function Test-ArmCm55MvefMpuSlice1Contract {
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
        "fiber\port\ARM_CM55_MVEF_MPU\non_secure"
    $bootSource = Join-Path $profileDir "fiber_port_boot.c"
    $svcSource = Join-Path $profileDir "fiber_port_svc.c"
	$pendSvSource = Join-Path $profileDir "fiber_port_pendsv.c"
    $linkerContract = Join-Path $profileDir "fiber_port_linker_contract.ld"
    $layoutFixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm55_mvef_mpu_layout_probe.c"
    $runtimeFixture = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm55_mvef_mpu_pendsv_probe.c"
    $fixtureLinker = Join-Path $RepositoryRoot `
        "tools\fixtures\arm_cm55_mvef_mpu_pendsv.ld"

    $expectedFiles = @(
        "FREERTOS_PARITY.md",
        "fiber_port_boot.c",
        "fiber_port_boot.h",
		"fiber_port_boot_types.h",
		"fiber_port_linker_contract.ld",
		"fiber_port_pendsv.c",
		"fiber_port_private.h",
		"fiber_port_svc.c",
		"fiber_port_types.h",
        "fiber_portmacro.h"
    ) | Sort-Object
    $actualFiles = @(Get-ChildItem -LiteralPath $profileDir -File |
        Select-Object -ExpandProperty Name | Sort-Object)
    if (Compare-Object -ReferenceObject $expectedFiles `
            -DifferenceObject $actualFiles) {
        throw "ARM_CM55_MVEF_MPU slice-1 file surface changed"
    }
    foreach ($required in @($bootSource, $svcSource, $pendSvSource, $linkerContract,
            $layoutFixture, $runtimeFixture, $fixtureLinker)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "ARM_CM55_MVEF_MPU slice-1 is missing: $required"
        }
    }
	foreach ($forbidden in @(
			"fiber_port.c",
            "fiber_port_mpu_abi.h",
            "fiber_port_mpu_abi.c",
            "fiber_port_secure_context.c")) {
        if (Test-Path -LiteralPath (Join-Path $profileDir $forbidden)) {
            throw "ARM_CM55_MVEF_MPU slice-1 exposed deferred artifact: $forbidden"
        }
    }

    foreach ($selector in @(
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h"))) {
        if ((Get-Content -LiteralPath $selector -Raw).IndexOf(
                "ARM_CM55_MVEF_MPU", [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM55_MVEF_MPU slice-1 must not enter global selection: $selector"
        }
    }

    $typeText = Get-Content -LiteralPath (Join-Path $profileDir "fiber_port_types.h") -Raw
    foreach ($forbiddenTypeDependency in @(
            "mcu_core.h",
            "fiber_compiler.h",
            "fiber_portmacro.h",
            "fiber_port_select.h")) {
        $includePattern = '(?m)^\s*#\s*include\s*["<][^">]*' +
            [regex]::Escape($forbiddenTypeDependency) + '[">]'
        if ([regex]::IsMatch($typeText, $includePattern)) {
            throw "ARM_CM55_MVEF_MPU public storage acquired CPU dependency: $forbiddenTypeDependency"
        }
    }

    $macro = Get-Content -LiteralPath (Join-Path $profileDir "fiber_portmacro.h") -Raw
    foreach ($token in @(
            "FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS",
            "requires CMSIS __FPU_PRESENT == 1",
            "requires CMSIS __FPU_USED == 1",
            "requires compiler FP code generation",
			"requires MVE FP compiler support",
            "FIBER_PORT_RUNTIME_SELECTABLE 0",
            "FIBER_PORT_HAS_FPU 1",
            "FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 1",
			"FIBER_PORT_HAS_MVE 1",
            "fiber_portPROTECTED_CONTEXT_WORDS 54u",
            "fiber_portPROTECTED_BASIC_RESTORE_WORDS 20u",
            "fiber_portPROTECTED_EXTENDED_RESTORE_WORDS 53u",
            "fiber_portPROTECTED_EXTENDED_ADDITIONAL_WORDS",
            "FIBER_PORT_SOFTWARE_FRAME_WORDS fiber_portPROTECTED_BASIC_RESTORE_WORDS",
			"FIBER_PORT_CONTEXT_ABI_PORT_ID 0x43353557u",
            "FIBER_PORT_CM55_MVEF_MPU_STACK_REQUIRED_BYTES")) {
        if ($macro.IndexOf($token, [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM55_MVEF_MPU portmacro lost frozen trait: $token"
        }
    }

	$bootText = Get-Content -LiteralPath $bootSource -Raw
	foreach ($token in @(
			"FIBER_PORT_CONTEXT_COHORT_RETAIN();",
            "FiberPortProtectedBasicContext *const image",
            "&ctx->protected_context.basic",
            "ctx->protected_context.words[index] = 0u;",
            "fiber_portPROTECTED_CONTEXT_WORDS",
            "fiber_port_fpu_prepare",
            "fiber_port_fpu_require_configured",
            "fiber_port_fpu_require_ready",
            "FIBER_PORT_CM55_MVEF_MPU_STACK_REQUIRED_BYTES")) {
        if ($bootText.IndexOf($token, [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM55_MVEF_MPU construction lost required mechanism: $token"
        }
    }

    foreach ($forbidden in @(
            "void SVC_Handler(",
            "void PendSV_Handler(",
            "fiber_port_runtime_",
            "fiber_internal_runtime_")) {
        if ($bootText.IndexOf($forbidden, [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM55_MVEF_MPU construction acquired runtime ownership: $forbidden"
        }
    }

    $parity = Get-Content -LiteralPath (Join-Path $profileDir "FREERTOS_PARITY.md") -Raw
    foreach ($token in @(
            "a50edad08b29052631aa469d4df6e6ec7ff68878",
            "GCC_ARM_CM55_NTZ_NONSECURE",
            "BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A",
            "DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5",
            "configENABLE_MPU=1",
			"configENABLE_FPU=1",
			"configENABLE_MVE=1",
            "MAX_CONTEXT_SIZE == 54",
            '20 words with `EXC_RETURN` at word 19',
            "33 privileged FP words",
            "logical maximum is 320 bytes",
			"C55W",
			"no VPR software slot",
            "112-byte usable PSP range")) {
        if ($parity.IndexOf($token, [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM55_MVEF_MPU parity ledger lost evidence: $token"
        }
    }

    $probeDir = Join-Path $BuildRoot "arm-cm55-mvef-mpu-slice1"
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
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SecureFault_IRQn = -9,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm55.h"
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
#include <stddef.h>
#include "fiber_port_types.h"

_Static_assert(sizeof(FiberPortBoot) == 88u, "boot size");
_Static_assert(sizeof(FiberPortProtectedContext) == 216u, "protected size");
_Static_assert(_Alignof(FiberContext) == 8u, "context alignment");
#if FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS == 8
_Static_assert(sizeof(FiberContext) == 352u, "8-region context size");
_Static_assert(offsetof(FiberContext, protected_context) == 40u, "8-region protected offset");
#else
_Static_assert(sizeof(FiberContext) == 416u, "16-region context size");
_Static_assert(offsetof(FiberContext, protected_context) == 104u, "16-region protected offset");
#endif
FiberContext fiber_arm_cm55_mvef_mpu_type_only_object;
'@
    $cppProbe = Join-Path $probeDir "type-only.cpp"
    Set-Content -LiteralPath $cppProbe -Encoding ASCII -Value @'
#include <cstddef>
#include "fiber_port_types.h"

static_assert(sizeof(FiberPortBoot) == 88u, "boot size");
static_assert(sizeof(FiberPortProtectedContext) == 216u, "protected size");
static_assert(alignof(FiberContext) == 8u, "context alignment");
#if FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS == 8
static_assert(sizeof(FiberContext) == 352u, "8-region context size");
#else
static_assert(sizeof(FiberContext) == 416u, "16-region context size");
#endif
FiberContext fiber_arm_cm55_mvef_mpu_cpp_type_only_object;
'@

    $warningArgs = @(
        "-ffreestanding", "-fno-builtin", "-fno-common",
        "-ffunction-sections", "-fdata-sections",
        "-Wall", "-Wextra", "-Werror", "-Wundef", "-Werror=undef",
        "-Werror=implicit-function-declaration", "-Werror=return-type"
    )
    $cppWarningArgs = @($warningArgs | Where-Object {
        $_ -ne "-Werror=implicit-function-declaration"
    })
    $includeArgs = @(
        "-I$probeDir", "-I$profileDir",
        "-I$(Join-Path $RepositoryRoot 'fiber\port')",
        "-I$(Join-Path $RepositoryRoot 'fiber')",
        "-I$RepositoryRoot", "-I$CmsisPath"
    )
    $requiredSymbols = @(
        "fiber_port_fpu_require_configured",
        "fiber_port_fpu_require_ready",
        "fiber_port_fpu_prepare",
        "fiber_port_context_init",
        "fiber_port_mpu_load_linker_layout",
        "fiber_port_mpu_linker_layout_check",
        "fiber_port_mpu_try_encode_exact_region",
        "fiber_port_mpu_build_global_regions",
        "fiber_port_context_compute_seal",
        "fiber_port_context_seal_check",
        "fiber_port_context_validate_initial_restore"
    )
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
    $modes = @(
        [pscustomobject]@{ Name = "hard-o2"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard"); Optimization = "-O2"; Lto = $false },
        [pscustomobject]@{ Name = "hard-os"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard"); Optimization = "-Os"; Lto = $false },
        [pscustomobject]@{ Name = "softfp-o2"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=softfp"); Optimization = "-O2"; Lto = $false },
        [pscustomobject]@{ Name = "softfp-os"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=softfp"); Optimization = "-Os"; Lto = $false },
        [pscustomobject]@{ Name = "hard-o2-lto"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard"); Optimization = "-O2"; Lto = $true }
    )

    foreach ($regions in @(8, 16)) {
        $regionDir = Join-Path $probeDir "regions-$regions"
        New-Item -ItemType Directory -Path $regionDir | Out-Null
        $regionDefines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV81M_MAINLINE=1",
            "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=$regions"
        )
        $layoutVersionToken = if ($regions -eq 8) {
            "l0x00010008u"
        }
        else {
            "l0x00010010u"
        }

        $typeObject = Join-Path $regionDir "type-only.o"
        & $Compiler -x c "-march=armv8.1-m.main+mve.fp" -mthumb -mfloat-abi=hard `
            -std=c11 @warningArgs "-I$profileDir" `
            "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=$regions" `
            -c $typeProbe -o $typeObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM55_MVEF_MPU type-only C header failed ($regions regions)"
        }
        $cppObject = Join-Path $regionDir "type-only-cpp.o"
        & $Compiler -x c++ "-march=armv8.1-m.main+mve.fp" -mthumb -mfloat-abi=hard `
            -std=c++17 -fno-exceptions -fno-rtti @cppWarningArgs `
            "-I$profileDir" "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=$regions" `
            -c $cppProbe -o $cppObject
        if ($LASTEXITCODE -ne 0) {
            throw "ARM_CM55_MVEF_MPU type-only C++ header failed ($regions regions)"
        }

        $expectedCohort = $null
        foreach ($mode in $modes) {
            $modeDir = Join-Path $regionDir $mode.Name
            New-Item -ItemType Directory -Path $modeDir | Out-Null
            $ltoArgs = if ($mode.Lto) { @("-flto") } else { @() }
            $baseArgs = @($mode.CpuArgs) + @(
                "-mthumb", "-std=gnu11", $mode.Optimization) + $ltoArgs +
                $warningArgs + $regionDefines + $includeArgs

            $layoutObject = Join-Path $modeDir "layout.o"
            & $Compiler @($baseArgs + @("-c", $layoutFixture,
                "-o", $layoutObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55_MVEF_MPU layout compile failed ($regions/$($mode.Name))"
            }
            $layoutDefined = @(& $GccNm -g --defined-only $layoutObject)
            $layoutCohorts = @($layoutDefined | ForEach-Object {
                if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
                    $Matches[1]
                }
            })
            if ($layoutCohorts.Count -ne 1) {
                throw "ARM_CM55_MVEF_MPU layout must define one exact cohort ($regions/$($mode.Name))"
            }
            foreach ($token in @(
                    "armv81m_mainline",
					"p0x43353557u",
                    $layoutVersionToken,
                    "_f1_e1_h1_j1_v1_d1_r1_",
                    "_z8u_y1_w2_g3_",
					"_i0_o0xFFFFFFBCu_c1_s1_x0_m1_a0_b0_t1_n1_k0_q0")) {
                if ($layoutCohorts[0].IndexOf($token,
                        [System.StringComparison]::Ordinal) -lt 0) {
                    throw "ARM_CM55_MVEF_MPU exact cohort lost token ${token} ($regions/$($mode.Name)): $($layoutCohorts[0])"
                }
            }
            if (($null -ne $expectedCohort) -and
                    ($expectedCohort -ne $layoutCohorts[0])) {
                throw "ARM_CM55_MVEF_MPU cohort changed across ABI/optimization modes ($regions)"
            }
            $expectedCohort = $layoutCohorts[0]

            $bootObject = Join-Path $modeDir "fiber_port_boot.o"
            & $Compiler @($baseArgs + @("-save-temps=obj", "-c", $bootSource,
                "-o", $bootObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55_MVEF_MPU construction compile failed ($regions/$($mode.Name))"
            }
            $svcObject = Join-Path $modeDir "fiber_port_svc.o"
            & $Compiler @($baseArgs + @("-c", $svcSource, "-o", $svcObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55_MVEF_MPU co-owned SVC/runtime compile failed ($regions/$($mode.Name))"
            }
            $pendSvObject = Join-Path $modeDir "fiber_port_pendsv.o"
            & $Compiler @($baseArgs + @("-c", $pendSvSource, "-o", $pendSvObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55_MVEF_MPU PendSV component compile failed ($regions/$($mode.Name))"
            }
            $bootDefined = @(& $GccNm -g --defined-only $bootObject)
            foreach ($symbol in $requiredSymbols) {
                if (-not ($bootDefined -match
                        "\bT\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM55_MVEF_MPU construction lost strong symbol: $symbol / $regions/$($mode.Name)"
                }
            }
            $bootCohorts = @($bootDefined | ForEach-Object {
                if ($_ -match '\b(fiber_port_context_cohort_\S+)$') {
                    $Matches[1]
                }
            })
			if ($bootCohorts.Count -ne 0) {
				throw "ARM_CM55_MVEF_MPU construction must retain, not define, the SVC-owned cohort ($regions/$($mode.Name))"
            }
            if ($bootDefined -match '\b(?:SVC_Handler|PendSV_Handler|fiber_port_runtime_)') {
                throw "ARM_CM55_MVEF_MPU construction object emitted runtime ownership ($regions/$($mode.Name))"
            }

            $nmUndefined = @(& $GccNm -u $bootObject)
            $bootUndefined = @(Get-NmUndefinedSymbolNames -NmOutput $nmUndefined `
                -Path $bootObject)
			$allowedUndefined = @($boundarySymbols + @(
					"fiber_panic", "fiber_port_unprivileged_task_return",
					$expectedCohort) |
                Sort-Object)
            $actualUndefined = @($bootUndefined | Sort-Object)
            if (($allowedUndefined.Count -ne $actualUndefined.Count) -or
                    (Compare-Object -ReferenceObject $allowedUndefined `
                        -DifferenceObject $actualUndefined)) {
                throw "ARM_CM55_MVEF_MPU construction dependency surface changed ($regions/$($mode.Name))`nExpected: $($allowedUndefined -join ', ')`nActual: $($actualUndefined -join ', ')"
            }

            if (-not $mode.Lto) {
                $symbolTable = @(& $Objdump -t $bootObject)
                foreach ($symbol in $requiredSymbols) {
                    $sectionMatch = @($symbolTable | Where-Object {
                        $_ -match "\bF\s+\.fiber_port_privileged_functions\s+[0-9a-fA-F]+\s+$([regex]::Escape($symbol))$"
                    })
                    if ($sectionMatch.Count -ne 1) {
                        throw "ARM_CM55_MVEF_MPU construction escaped privileged section: $symbol / $regions/$($mode.Name)"
                    }
                }
                $assembly = (& $Objdump -dr $bootObject) -join "`n"
                foreach ($forbiddenInstruction in @(
                        '\bsvc\b',
                        '\bmsr\s+(?:PSP|PSPLIM|CONTROL|BASEPRI)\b',
                        '\bv(?:stm|ldm|mov|push|pop|str|ldr)\w*\b',
                        '\b(?:vpr|mve)\b',
                        '0xe000ed(?:90|94|98|9c|a0)')) {
                    if ($assembly -match $forbiddenInstruction) {
                        throw "ARM_CM55_MVEF_MPU construction generated forbidden transfer/state write: $forbiddenInstruction / $regions/$($mode.Name)"
                    }
                }
            }

            $fixtureObject = Join-Path $modeDir "probe.o"
            & $Compiler @($baseArgs + @("-c", $runtimeFixture,
                "-o", $fixtureObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55_MVEF_MPU construction runtime fixture compile failed ($regions/$($mode.Name))"
            }
            $elf = Join-Path $modeDir "construction.elf"
            & $Compiler @($baseArgs + @(
                "-nostdlib", "-Wl,--gc-sections", "-Wl,-T,$fixtureLinker",
                "-Wl,-T,$linkerContract", $bootObject, $svcObject, $pendSvObject, $fixtureObject,
                "-o", $elf))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55_MVEF_MPU construction/linker proof failed ($regions/$($mode.Name))"
            }
            $elfDefined = @(& $GccNm -g --defined-only $elf)
            foreach ($symbol in @($requiredSymbols + @(
                    "fiber_arm_cm55_mvef_mpu_pendsv_probe",
                    "fiber_port_unprivileged_task_return",
                    $expectedCohort))) {
                if (-not ($elfDefined -match
                        "\b[TR]\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM55_MVEF_MPU synthetic ELF lost symbol: $symbol / $regions/$($mode.Name)"
                }
            }
            foreach ($handler in @("SVC_Handler", "PendSV_Handler")) {
                if (-not ($elfDefined -match ("\bT\s+" +
                        [regex]::Escape($handler) + "$"))) {
                    throw ("ARM_CM55_MVEF_MPU construction/runtime link lost strong " +
                        $handler + " ($regions/$($mode.Name))")
                }
            }
            $sections = (& $Objdump -h $elf) -join "`n"
            foreach ($section in @(
                    ".fiber_port_privileged_code",
                    ".fiber_port_unprivileged_code",
                    ".fiber_port_syscalls",
                    ".fiber_current_context_slot",
                    ".fiber_port_privileged_data",
                    ".fiber_port_unprivileged_ram")) {
                if ($sections.IndexOf($section,
                        [System.StringComparison]::Ordinal) -lt 0) {
                    throw "ARM_CM55_MVEF_MPU synthetic ELF lost required section: $section / $regions/$($mode.Name)"
                }
            }

            if ($mode.Name -eq "hard-o2") {
                $brokenLinker = Join-Path $modeDir "missing-syscalls.ld"
                $brokenText = (Get-Content -LiteralPath $fixtureLinker -Raw).
                    Replace("__fiber_mpu_unprivileged_syscalls_end__ = 0x08021000;", "")
                Set-Content -LiteralPath $brokenLinker -Value $brokenText `
                    -Encoding ASCII
                $negative = Invoke-CompilerProbe -Compiler $Compiler `
                    -Arguments @($baseArgs + @(
                        "-nostdlib", "-Wl,--gc-sections", "-Wl,-T,$brokenLinker",
                        "-Wl,-T,$linkerContract", $bootObject, $svcObject, $pendSvObject, $fixtureObject,
                        "-o", (Join-Path $modeDir "missing-syscalls.elf"))) `
                    -LogPath (Join-Path $modeDir "missing-syscalls.log")
                if (($negative.ExitCode -eq 0) -or
                        ($negative.Output.IndexOf("missing syscall-flash end",
                        [System.StringComparison]::Ordinal) -lt 0)) {
                    throw "ARM_CM55_MVEF_MPU linker contract accepted a missing syscall boundary ($regions/$($mode.Name))`n$($negative.Output)"
                }
            }
        }
    }

    $invalidCases = @(
        [pscustomobject]@{ Name = "missing-fpu"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard"); Defines = @("-DFIBER_TEST_FPU_PRESENT=0"); Diagnostic = "requires CMSIS __FPU_PRESENT == 1" },
        [pscustomobject]@{ Name = "fpu-not-used"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard"); Defines = @("-DFIBER_TEST_FPU_USED=0"); Diagnostic = "requires CMSIS __FPU_USED == 1" },
        [pscustomobject]@{ Name = "no-mve-fp"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard"); Defines = @(); Diagnostic = "requires MVE FP compiler support" },
        [pscustomobject]@{ Name = "mve-integer-only"; CpuArgs = @("-march=armv8.1-m.main+mve", "-mfloat-abi=soft"); Defines = @(); Diagnostic = "requires MVE FP compiler support" },
        [pscustomobject]@{ Name = "secure-cmse"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard", "-mcmse"); Defines = @("-DFIBER_TEST_SECURE_CMSE=3"); Diagnostic = "selected profile excludes Secure CMSE builds" },
        [pscustomobject]@{ Name = "wrong-core"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard"); Defines = @("-DFIBER_TEST_CORTEX_M=33"); Diagnostic = "CMSIS __CORTEX_M == 55" },
        [pscustomobject]@{ Name = "invalid-regions"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard"); Defines = @("-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=12"); Diagnostic = "supports exactly 8 or 16 MPU regions" },
        [pscustomobject]@{ Name = "foreign-region-manifest"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard"); Defines = @("-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=8", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8"); Diagnostic = "requires its own MPU-region manifest macro" },
        [pscustomobject]@{ Name = "runtime-selectable"; CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard"); Defines = @("-DFIBER_PORT_RUNTIME_SELECTABLE=1"); Diagnostic = "runtime-selectable state must not be predefined" }
    )
    foreach ($case in $invalidCases) {
        $caseDir = Join-Path $probeDir ("invalid-" + $case.Name)
        New-Item -ItemType Directory -Path $caseDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $probeDir "main.h") `
            -Destination (Join-Path $caseDir "main.h")
        $arguments = @($case.CpuArgs + @(
            "-mthumb", "-std=c11", "-ffreestanding", "-fno-builtin",
            "-fno-common", "-Wall", "-Wextra", "-Wundef", "-Werror=undef",
            "-I$caseDir", "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot", "-I$CmsisPath",
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV81M_MAINLINE=1") + $case.Defines + @(
            "-c", $layoutFixture,
            "-o", (Join-Path $caseDir "invalid.o")))
        $result = Invoke-CompilerProbe -Compiler $Compiler -Arguments $arguments `
            -LogPath (Join-Path $caseDir "compile.log")
        if (($result.ExitCode -eq 0) -or
                ($result.Output.IndexOf($case.Diagnostic,
                [System.StringComparison]::Ordinal) -lt 0)) {
            throw "Invalid ARM_CM55_MVEF_MPU manifest failed for the wrong reason: $($case.Name)`n$($result.Output)"
        }
    }
}
