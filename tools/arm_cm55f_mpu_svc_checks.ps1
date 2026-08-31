function Test-ArmCm55fMpuSvcContract {
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

    $profileDir = Join-Path $RepositoryRoot "fiber\port\ARM_CM55F_MPU\non_secure"
    $bootSource = Join-Path $profileDir "fiber_port_boot.c"
    $svcSource = Join-Path $profileDir "fiber_port_svc.c"
    $pendSvSource = Join-Path $profileDir "fiber_port_pendsv.c"
    $privateHeader = Join-Path $profileDir "fiber_port_private.h"
    $linkerContract = Join-Path $profileDir "fiber_port_linker_contract.ld"
    $fixture = Join-Path $RepositoryRoot "tools\fixtures\arm_cm55f_mpu_svc_probe.c"
    $fixtureLinker = Join-Path $RepositoryRoot "tools\fixtures\arm_cm55f_mpu_svc.ld"
    $competing = Join-Path $RepositoryRoot "tools\fixtures\arm_cm55f_mpu_competing_svc.c"

    foreach ($required in @($bootSource, $svcSource, $pendSvSource, $privateHeader,
            $linkerContract, $fixture, $fixtureLinker, $competing)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "ARM_CM55F_MPU protected SVC slice is missing: $required"
        }
    }
    foreach ($forbidden in @(
            "fiber_port_mpu_abi.h",
            "fiber_port_mpu_abi.c",
            "fiber_port_secure_context.c")) {
        if (Test-Path -LiteralPath (Join-Path $profileDir $forbidden)) {
            throw "ARM_CM55F_MPU protected SVC slice exposed deferred artifact: $forbidden"
        }
    }

    foreach ($selector in @(
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h"))) {
        if ((Get-Content -LiteralPath $selector -Raw).IndexOf(
                "ARM_CM55F_MPU", [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM55F_MPU SVC slice must not enter global selection: $selector"
        }
    }

    $svcText = Get-Content -LiteralPath $svcSource -Raw
    foreach ($requiredText in @(
            "FIBER_RUNTIME_PORT_ABI_RETAIN_V1();",
            "FIBER_PORT_CONTEXT_COHORT_RETAIN();",
            "fiber_port_prepare_first_start",
            "fiber_port_svc_dispatch",
            "fiber_port_mpu_program_global_image_while_disabled",
            "fiber_port_mpu_validate_active_initial_context",
            "fiber_port_start_first_context",
            "fiber_port_restore_first_context_from_svc",
            "fiber_port_unprivileged_task_return",
			"fiber_port_runtime_memory_barrier",
			"fiber_port_panic_wait",
			"fiber_port_require_scheduler_configuration_environment",
			"fiber_port_runtime_prepare_start",
			"fiber_port_runtime_select_first",
			"fiber_port_runtime_start_first",
			"fiber_port_runtime_schedule",
			"fiber_port_handler_bundle_v1_anchor",
            "void SVC_Handler(void)",
            "fiber_portSVC_START",
			"fiber_portSVC_YIELD",
            "fiber_portSVC_RETURN",
			"fiber_port_svc_yield_return_site",
            "fiber_portEXTENDED_EXC_RETURN",
            "fiber_portMPU_MAIR0_REG",
            "fiber_portMPU_CTRL_REQUIRED",
            "fiber_internal_runtime_current_context_slot")) {
        if ($svcText.IndexOf($requiredText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM55F_MPU protected SVC source lost mechanism: $requiredText"
        }
    }
    foreach ($forbiddenText in @(
            "void PendSV_Handler(")) {
        if ($svcText.IndexOf($forbiddenText,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM55F_MPU SVC/runtime object acquired PendSV handler ownership: $forbiddenText"
        }
    }

    $privateText = Get-Content -LiteralPath $privateHeader -Raw
    if ($privateText.IndexOf("fiber_runtime_port_abi.h",
            [System.StringComparison]::Ordinal) -lt 0) {
        throw "ARM_CM55F_MPU SVC must consume frozen reverse ABI v1"
    }
    if ($privateText.IndexOf("fiber_port_runtime_abi.h",
            [System.StringComparison]::Ordinal) -lt 0) {
        throw "ARM_CM55F_MPU mandatory SVC/runtime object must consume the frozen forward ABI"
    }

    $probeDir = Join-Path $BuildRoot "arm-cm55f-mpu-svc"
    New-Item -ItemType Directory -Path $probeDir | Out-Null
    $mainHeader = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 3U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 1U
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
#endif
"@
    $warningArgs = @(
        "-ffreestanding", "-fno-builtin", "-fno-common",
        "-ffunction-sections", "-fdata-sections",
        "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
        "-Wall", "-Wextra", "-Werror", "-Wundef", "-Werror=undef",
        "-Werror=implicit-function-declaration", "-Werror=return-type")
    $requiredSymbols = @(
        "fiber_port_prepare_first_start",
        "fiber_port_svc_dispatch",
        "fiber_port_start_first_context",
        "fiber_port_restore_first_context_from_svc",
        "fiber_port_unprivileged_task_return",
		"fiber_port_runtime_memory_barrier",
		"fiber_port_panic_wait",
		"fiber_port_require_scheduler_configuration_environment",
		"fiber_port_runtime_prepare_start",
		"fiber_port_runtime_select_first",
		"fiber_port_runtime_start_first",
		"fiber_port_runtime_schedule",
		"fiber_port_handler_bundle_v1_anchor",
        "SVC_Handler")
    $modes = @(
        [pscustomobject]@{ Name = "hard-o2"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard"); Optimization = "-O2"; Lto = $false },
        [pscustomobject]@{ Name = "hard-os"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard"); Optimization = "-Os"; Lto = $false },
        [pscustomobject]@{ Name = "softfp-o2"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=softfp"); Optimization = "-O2"; Lto = $false },
        [pscustomobject]@{ Name = "softfp-os"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=softfp"); Optimization = "-Os"; Lto = $false },
        [pscustomobject]@{ Name = "hard-o2-lto"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard"); Optimization = "-O2"; Lto = $true }
    )

    foreach ($regions in @(8, 16)) {
        $regionDir = Join-Path $probeDir "regions-$regions"
        New-Item -ItemType Directory -Path $regionDir | Out-Null
        Set-Content -LiteralPath (Join-Path $regionDir "main.h") `
            -Value $mainHeader -Encoding ASCII
        $defines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV81M_MAINLINE=1",
            "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=$regions")
        $includes = @(
            "-I$regionDir", "-I$profileDir",
            "-I$(Join-Path $RepositoryRoot 'fiber\port')",
            "-I$(Join-Path $RepositoryRoot 'fiber')",
            "-I$RepositoryRoot", "-I$CmsisPath")

        foreach ($mode in $modes) {
            $modeDir = Join-Path $regionDir $mode.Name
            New-Item -ItemType Directory -Path $modeDir | Out-Null
            $ltoArgs = if ($mode.Lto) { @("-flto") } else { @() }
            $baseArgs = @($mode.CpuArgs) + @(
                "-mthumb", "-std=gnu11", $mode.Optimization) + $ltoArgs +
                $warningArgs + $defines + $includes
            $bootObject = Join-Path $modeDir "fiber_port_boot.o"
            $svcObject = Join-Path $modeDir "fiber_port_svc.o"
			$pendSvObject = Join-Path $modeDir "fiber_port_pendsv.o"
            $fixtureObject = Join-Path $modeDir "probe.o"
            & $Compiler @($baseArgs + @("-c", $bootSource, "-o", $bootObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU SVC boot compile failed ($regions/$($mode.Name))"
            }
            & $Compiler @($baseArgs + @("-save-temps=obj", "-c", $svcSource,
                "-o", $svcObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU SVC source compile failed ($regions/$($mode.Name))"
            }
			& $Compiler @($baseArgs + @("-c", $pendSvSource, "-o", $pendSvObject))
			if ($LASTEXITCODE -ne 0) {
				throw "ARM_CM55F_MPU SVC PendSV component compile failed ($regions/$($mode.Name))"
			}
            & $Compiler @($baseArgs + @("-c", $fixture, "-o", $fixtureObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU SVC fixture compile failed ($regions/$($mode.Name))"
            }

            $objectNm = if ($mode.Lto) { $GccNm } else { $Nm }
            $svcDefined = @(& $objectNm -g --defined-only $svcObject)
            foreach ($symbol in $requiredSymbols) {
                if (-not ($svcDefined -match
                        "\bT\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM55F_MPU SVC lost strong symbol: $symbol / $regions/$($mode.Name)"
                }
            }
			if ($svcDefined -match '\bPendSV_Handler$') {
				throw "ARM_CM55F_MPU SVC/runtime object emitted PendSV handler ownership: $regions/$($mode.Name)"
            }

            if (-not $mode.Lto) {
                $symbols = @(& $Objdump -t $svcObject)
                foreach ($symbol in @(
                        "fiber_port_prepare_first_start",
                        "fiber_port_svc_dispatch",
						"fiber_port_panic_wait",
						"fiber_port_require_scheduler_configuration_environment",
						"fiber_port_runtime_prepare_start",
						"fiber_port_runtime_select_first",
						"fiber_port_runtime_start_first",
						"fiber_port_handler_bundle_v1_anchor",
                        "fiber_port_start_first_context",
                        "fiber_port_restore_first_context_from_svc",
                        "SVC_Handler")) {
                    if (-not ($symbols -match
                            "\bF\s+\.fiber_port_privileged_functions\s+[0-9a-fA-F]+\s+$([regex]::Escape($symbol))$")) {
                        throw "ARM_CM55F_MPU SVC escaped privileged flash: $symbol / $regions/$($mode.Name)"
                    }
                }
                if (-not ($symbols -match
                        "\bF\s+\.fiber_port_syscalls\s+[0-9a-fA-F]+\s+fiber_port_unprivileged_task_return$")) {
                    throw "ARM_CM55F_MPU SVC task-return veneer escaped syscall flash: $regions/$($mode.Name)"
                }
				if (-not ($symbols -match
						"\bF\s+\.fiber_port_syscalls\s+[0-9a-fA-F]+\s+fiber_port_runtime_schedule$")) {
					throw "ARM_CM55F_MPU SVC runtime schedule veneer escaped syscall flash: $regions/$($mode.Name)"
				}
				if (-not ($symbols -match
						"\bF\s+\.fiber_port_unprivileged_functions\s+[0-9a-fA-F]+\s+fiber_port_runtime_memory_barrier$")) {
					throw "ARM_CM55F_MPU runtime memory barrier escaped unprivileged flash: $regions/$($mode.Name)"
				}

                $assemblyPath = [IO.Path]::ChangeExtension($svcObject, ".s")
                Test-GeneratedCurrentSlotLoadOnly -AssemblyPath $assemblyPath
                $disassembly = (& $Objdump -dr $svcObject) -join "`n"
                $requiredAssemblyPatterns = @(
                        '(?im)\bsvc\s+70\b',
						'(?im)\bsvc\s+71\b',
                        '(?im)\bsvc\s+72\b',
                        '(?im)0xe000ed08', '(?im)0xe000ed94',
                        '(?im)0xe000ed98', '(?im)0xe000ed9c',
                        '(?im)0xe000edc0', '(?im)\bmsr\s+psp',
                        '(?im)\bmsr\s+psplim', '(?im)\bmsr\s+control',
                        '(?im)\bmsr\s+basepri', '(?im)\bmov\s+lr,\s*r1',
                        '(?im)\bmvn(?:\.w)?\s+r5,\s*#71',
                        '(?im)\bmvn(?:\.w)?\s+r5,\s*#67',
                        '(?im)\bldmia(?:\.w)?\s+r0!?',
                        '(?im)\bstmia(?:\.w)?\s+r2',
                        '(?im)\bldmdb\s+r1!', '(?im)\bbx\s+lr')
                if ($regions -eq 16) {
                    $requiredAssemblyPatterns += @(
                        '(?im)\bmovs(?:\.w)?\s+r3,\s*#8\b',
                        '(?im)\bmovs(?:\.w)?\s+r3,\s*#12\b')
                }
                foreach ($pattern in $requiredAssemblyPatterns) {
                    if ($disassembly -notmatch $pattern) {
                        throw "ARM_CM55F_MPU SVC generated assembly lost $pattern / $regions/$($mode.Name)"
                    }
                }
                foreach ($forbidden in @(
                        '(?im)\bv(?:stm|ldm|mov|push|pop|str|ldr)\w*\b',
                        '(?im)\b(?:vpr|mve)\b')) {
                    if ($disassembly -match $forbidden) {
                        throw "ARM_CM55F_MPU SVC generated forbidden transfer/mechanism: $forbidden / $regions/$($mode.Name)"
                    }
                }
            }

            $elf = Join-Path $modeDir "svc.elf"
            & $Compiler @($baseArgs + @(
                "-nostdlib", "-Wl,--gc-sections", "-Wl,-T,$fixtureLinker",
                "-Wl,-T,$linkerContract", $bootObject, $svcObject, $pendSvObject,
                $fixtureObject, "-o", $elf))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU SVC synthetic ELF failed link ($regions/$($mode.Name))"
            }
            $elfDefined = @(& $objectNm -g --defined-only $elf)
            foreach ($symbol in @($requiredSymbols + @(
                    "fiber_arm_cm55f_mpu_svc_probe"))) {
                if (-not ($elfDefined -match
                        "\bT\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM55F_MPU SVC ELF lost symbol: $symbol / $regions/$($mode.Name)"
                }
            }
			foreach ($handler in @("SVC_Handler", "PendSV_Handler")) {
				$handlerSymbols = @($elfDefined | Where-Object {
					$_ -match ("^([0-9a-fA-F]+)\s+T\s+" +
						[regex]::Escape($handler) + "$")
				})
				if ($handlerSymbols.Count -ne 1) {
					throw "ARM_CM55F_MPU runtime ELF must retain one strong ${handler}: $regions/$($mode.Name)"
				}
			}
			$svcSymbol = @($elfDefined | Where-Object {
				$_ -match '^([0-9a-fA-F]+)\s+T\s+SVC_Handler$'
			})[0]
			[void]($svcSymbol -match '^([0-9a-fA-F]+)')
			$svcAddress = [Convert]::ToUInt32($Matches[1], 16)
			$pendSvSymbol = @($elfDefined | Where-Object {
				$_ -match '^([0-9a-fA-F]+)\s+T\s+PendSV_Handler$'
			})[0]
			[void]($pendSvSymbol -match '^([0-9a-fA-F]+)')
			$pendSvAddress = [Convert]::ToUInt32($Matches[1], 16)
            $vectorBinary = Join-Path $modeDir "vectors.bin"
            & $Objcopy -O binary --only-section=.fiber_test_vectors $elf $vectorBinary
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU SVC vector extraction failed: $regions/$($mode.Name)"
            }
            $vector = [IO.File]::ReadAllBytes($vectorBinary)
            if ($vector.Length -lt (15 * 4)) {
                throw "ARM_CM55F_MPU SVC vector fixture is truncated: $regions/$($mode.Name)"
            }
            if ([BitConverter]::ToUInt32($vector, 11 * 4) -ne
                    ($svcAddress -bor [uint32]1)) {
                throw "ARM_CM55F_MPU SVC vector slot 11 lost strong handler: $regions/$($mode.Name)"
            }
			if ([BitConverter]::ToUInt32($vector, 14 * 4) -ne
					($pendSvAddress -bor [uint32]1)) {
				throw "ARM_CM55F_MPU runtime vector slot 14 lost strong handler: $regions/$($mode.Name)"
			}

            if (($regions -eq 8) -and ($mode.Name -eq "hard-o2")) {
                $competingObject = Join-Path $modeDir "competing.o"
                & $Compiler @($baseArgs + @("-c", $competing,
                    "-o", $competingObject))
                if ($LASTEXITCODE -ne 0) {
                    throw "ARM_CM55F_MPU competing SVC fixture failed compile"
                }
                $duplicate = Invoke-CompilerProbe -Compiler $Compiler `
                    -Arguments @($baseArgs + @(
                        "-nostdlib", "-Wl,--gc-sections",
						"-Wl,-T,$fixtureLinker", "-Wl,-T,$linkerContract",
						$bootObject, $svcObject, $pendSvObject, $fixtureObject, $competingObject,
                        "-o", (Join-Path $modeDir "duplicate.elf"))) `
                    -LogPath (Join-Path $modeDir "duplicate.log")
                if (($duplicate.ExitCode -eq 0) -or
                        ($duplicate.Output -notmatch '(?s)multiple definition.*SVC_Handler')) {
                    throw "ARM_CM55F_MPU competing SVC handlers must fail link`n$($duplicate.Output)"
                }
            }
        }
    }
}
