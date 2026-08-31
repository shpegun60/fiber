function Test-ArmCm55fMpuPendSvContract {
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
    $fixture = Join-Path $RepositoryRoot "tools\fixtures\arm_cm55f_mpu_pendsv_probe.c"
    $fixtureLinker = Join-Path $RepositoryRoot "tools\fixtures\arm_cm55f_mpu_pendsv.ld"
    $competing = Join-Path $RepositoryRoot "tools\fixtures\arm_cm55f_mpu_competing_pendsv.c"

    foreach ($required in @($bootSource, $svcSource, $pendSvSource,
            $privateHeader, $linkerContract, $fixture, $fixtureLinker,
            $competing)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "ARM_CM55F_MPU protected PendSV slice is missing: $required"
        }
    }
    foreach ($selector in @(
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_select.h"),
            (Join-Path $RepositoryRoot "fiber\port\fiber_port_selected.h"))) {
        if ((Get-Content -LiteralPath $selector -Raw).IndexOf(
                "ARM_CM55F_MPU", [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM55F_MPU PendSV slice must remain explicitly build-selected: $selector"
        }
    }

    $pendSvText = Get-Content -LiteralPath $pendSvSource -Raw
    foreach ($requiredText in @(
			"image->extended.cursor_limit",
            "fiber_port_context_validate_restore",
            "fiber_port_pendsv_validate_save_current",
			"fiber_port_scheduler_pick_next_from_pendsv",
            "fiber_port_mpu_switch_to_context",
			"fiber_port_mpu_validate_active_context",
			"fiber_port_scheduler_pick_first_from_start",
			"fiber_port_arm_cm55f_mpu_pendsv_handler_component_v1_anchor",
            "fiber_internal_runtime_select_scheduler_candidate",
            "fiber_internal_runtime_publish_current_context",
            "vstmia r1!, {s16-s31}",
            "vldmia r0, {s0-s16}",
            "vstmia r1!, {s0-s16}",
            "vldmdb r1!, {s0-s16}",
            "vstmia r0!, {s0-s16}",
            "vldmdb r1!, {s16-s31}",
            "void PendSV_Handler(void)")) {
        if ($pendSvText.IndexOf($requiredText,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "ARM_CM55F_MPU protected PendSV source lost mechanism: $requiredText"
        }
    }
    foreach ($forbiddenText in @(
            "fiber_port_runtime_memory_barrier(",
            "fiber_port_panic_wait(",
            "fiber_port_require_scheduler_configuration_environment(",
            "fiber_port_runtime_prepare_start(",
            "fiber_port_runtime_select_first(",
            "fiber_port_runtime_start_first(",
            "fiber_port_runtime_schedule(")) {
        if ($pendSvText.IndexOf($forbiddenText,
                [System.StringComparison]::Ordinal) -ge 0) {
            throw "ARM_CM55F_MPU protected PendSV acquired deferred forward ABI ownership: $forbiddenText"
        }
    }
    $preflightIndex = $pendSvText.IndexOf(
        "bl    fiber_port_pendsv_validate_save_current",
        [System.StringComparison]::Ordinal)
    $cursorLoadIndex = $pendSvText.IndexOf(
        "ldr   r1, [r2, #0]",
        [System.StringComparison]::Ordinal)
    if (($preflightIndex -lt 0) -or ($cursorLoadIndex -lt 0) -or
            ($preflightIndex -ge $cursorLoadIndex)) {
        throw "ARM_CM55F_MPU PendSV must validate current before loading its protected cursor"
    }

    $privateText = Get-Content -LiteralPath $privateHeader -Raw
    if ($privateText.IndexOf("fiber_runtime_port_abi.h",
            [System.StringComparison]::Ordinal) -lt 0) {
        throw "ARM_CM55F_MPU PendSV must consume frozen reverse ABI v1"
    }
    if ($privateText.IndexOf("fiber_port_runtime_abi.h",
            [System.StringComparison]::Ordinal) -lt 0) {
        throw "ARM_CM55F_MPU selected runtime must expose the frozen forward ABI to all private objects"
    }

    $probeDir = Join-Path $BuildRoot "arm-cm55f-mpu-pendsv"
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
    $modes = @(
        [pscustomobject]@{ Name = "hard-o2"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard"); Optimization = "-O2"; Lto = $false },
        [pscustomobject]@{ Name = "hard-os"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard"); Optimization = "-Os"; Lto = $false },
        [pscustomobject]@{ Name = "softfp-o2"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=softfp"); Optimization = "-O2"; Lto = $false },
        [pscustomobject]@{ Name = "softfp-os"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=softfp"); Optimization = "-Os"; Lto = $false },
        [pscustomobject]@{ Name = "hard-o2-lto"; CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard"); Optimization = "-O2"; Lto = $true }
    )
    $requiredPendSvSymbols = @(
        "fiber_port_context_validate_restore",
        "fiber_port_pendsv_validate_save_current",
        "fiber_port_scheduler_pick_next_from_pendsv",
        "fiber_port_scheduler_pick_first_from_start",
        "fiber_port_mpu_validate_active_context",
        "fiber_port_mpu_switch_to_context",
		"fiber_port_arm_cm55f_mpu_pendsv_handler_component_v1_anchor",
		"PendSV_Handler")

    foreach ($regions in @(8, 16)) {
        $regionDir = Join-Path $probeDir "regions-$regions"
        New-Item -ItemType Directory -Path $regionDir | Out-Null
        Set-Content -LiteralPath (Join-Path $regionDir "main.h") `
            -Value $mainHeader -Encoding ASCII
        $defines = @(
            "-DFIBER_PORT_BUILD_SELECTED=1",
            "-DFIBER_PORT_ARMV81M_MAINLINE=1",
            "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=$regions",
            "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1")
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
                throw "ARM_CM55F_MPU PendSV boot compile failed ($regions/$($mode.Name))"
            }
            & $Compiler @($baseArgs + @("-c", $svcSource, "-o", $svcObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU PendSV SVC support compile failed ($regions/$($mode.Name))"
            }
            $saveTemps = if ($mode.Lto) { @() } else { @("-save-temps=obj") }
            & $Compiler @($baseArgs + $saveTemps + @("-c", $pendSvSource,
                "-o", $pendSvObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU protected PendSV compile failed ($regions/$($mode.Name))"
            }
            & $Compiler @($baseArgs + @("-c", $fixture, "-o", $fixtureObject))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU PendSV fixture compile failed ($regions/$($mode.Name))"
            }

            $objectNm = if ($mode.Lto) { $GccNm } else { $Nm }
            $pendSvDefined = @(& $objectNm -g --defined-only $pendSvObject)
            foreach ($symbol in $requiredPendSvSymbols) {
                if (-not ($pendSvDefined -match
                        "\bT\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM55F_MPU PendSV lost strong symbol: $symbol / $regions/$($mode.Name)"
                }
            }
            if ($pendSvDefined -match '\bfiber_port_runtime_') {
                throw "ARM_CM55F_MPU PendSV object emitted deferred forward runtime ownership: $regions/$($mode.Name)"
            }

            if (-not $mode.Lto) {
                $symbols = @(& $Objdump -t $pendSvObject)
                foreach ($symbol in $requiredPendSvSymbols) {
                    if (-not ($symbols -match
                            "\bF\s+\.fiber_port_privileged_functions\s+[0-9a-fA-F]+\s+$([regex]::Escape($symbol))$")) {
                        throw "ARM_CM55F_MPU PendSV escaped privileged flash: $symbol / $regions/$($mode.Name)"
                    }
                }

				$relocations = @(& $Objdump -r $pendSvObject)
				foreach ($requiredRelocation in @(
						"fiber_internal_runtime_port_abi_v1_anchor",
						"fiber_port_context_cohort_")) {
					if (-not ($relocations -match [regex]::Escape($requiredRelocation))) {
						throw "ARM_CM55F_MPU PendSV lost retained link identity: $requiredRelocation / $regions/$($mode.Name)"
					}
				}

                $assemblyPath = [IO.Path]::ChangeExtension($pendSvObject, ".s")
                Test-GeneratedCurrentSlotLoadOnly -AssemblyPath $assemblyPath
                $disassembly = (& $Objdump -dr $pendSvObject) -join "`n"
                $requiredAssemblyPatterns = @(
                    '(?im)\badds?(?:\.w)?\s+r0,\s*#(?:32|0x20)\b',
                    '(?im)\bsubs?(?:\.w)?\s+r0,\s*#(?:32|0x20)\b',
                    '(?im)\bvstmia(?:\.w)?\s+r1!,\s*\{s16(?:-s31|,\s*s17)',
                    '(?im)\bvldmia(?:\.w)?\s+r0,\s*\{s0(?:-s16|,\s*s1)',
                    '(?im)\bvstmia(?:\.w)?\s+r1!,\s*\{s0(?:-s16|,\s*s1)',
                    '(?im)\bvldmdb(?:\.w)?\s+r1!,\s*\{s0(?:-s16|,\s*s1)',
                    '(?im)\bvstmia(?:\.w)?\s+r0!,\s*\{s0(?:-s16|,\s*s1)',
                    '(?im)\bvldmdb(?:\.w)?\s+r1!,\s*\{s16(?:-s31|,\s*s17)',
                    '(?im)\bstmia(?:\.w)?\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
                    '(?im)\bldmia(?:\.w)?\s+r0,\s*\{r4[^\r\n]*(r11|fp)\}',
                    '(?im)\bldmdb(?:\.w)?\s+r1!,\s*\{r0,\s*r3,\s*r4,\s*lr\}',
                    '(?im)\bmsr\s+psp', '(?im)\bmsr\s+psplim',
                    '(?im)\bmsr\s+control', '(?im)\bmsr\s+basepri',
                    '(?im)\bcpsid\s+i', '(?im)\bcpsie\s+i',
                    '(?im)\bfiber_port_pendsv_validate_save_current',
                    '(?im)\bfiber_port_scheduler_pick_next_from_pendsv',
                    '(?im)\bfiber_port_mpu_switch_to_context', '(?im)\bbx\s+lr')
                foreach ($pattern in $requiredAssemblyPatterns) {
                    if ($disassembly -notmatch $pattern) {
                        throw "ARM_CM55F_MPU PendSV generated assembly lost $pattern / $regions/$($mode.Name)"
                    }
                }
                foreach ($forbidden in @(
                        '(?im)\b(?:vpr|mve)\b',
                        '(?im)\bfiber_port_runtime_schedule\b')) {
                    if ($disassembly -match $forbidden) {
                        throw "ARM_CM55F_MPU PendSV generated forbidden mechanism: $forbidden / $regions/$($mode.Name)"
                    }
                }
            }

            $elf = Join-Path $modeDir "pendsv.elf"
            & $Compiler @($baseArgs + @(
                "-nostdlib", "-Wl,--gc-sections", "-Wl,-T,$fixtureLinker",
                "-Wl,-T,$linkerContract", $bootObject, $svcObject,
                $pendSvObject, $fixtureObject, "-o", $elf))
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU PendSV synthetic ELF failed link ($regions/$($mode.Name))"
            }
            $elfDefined = @(& $objectNm -g --defined-only $elf)
            foreach ($symbol in @($requiredPendSvSymbols + @(
                    "SVC_Handler", "fiber_arm_cm55f_mpu_pendsv_probe"))) {
                if (-not ($elfDefined -match
                        "\bT\s+$([regex]::Escape($symbol))$")) {
                    throw "ARM_CM55F_MPU PendSV ELF lost symbol: $symbol / $regions/$($mode.Name)"
                }
            }
            foreach ($handler in @("SVC_Handler", "PendSV_Handler")) {
                $handlers = @($elfDefined | Where-Object {
                    $_ -match ("^[0-9a-fA-F]+\s+T\s+" +
                        [regex]::Escape($handler) + "$")
                })
                if ($handlers.Count -ne 1) {
                    throw "ARM_CM55F_MPU PendSV ELF must retain one strong ${handler}: $regions/$($mode.Name)"
                }
            }

            $vectorBinary = Join-Path $modeDir "vectors.bin"
            & $Objcopy -O binary --only-section=.fiber_test_vectors $elf $vectorBinary
            if ($LASTEXITCODE -ne 0) {
                throw "ARM_CM55F_MPU PendSV vector extraction failed: $regions/$($mode.Name)"
            }
            $vector = [IO.File]::ReadAllBytes($vectorBinary)
            if ($vector.Length -lt (15 * 4)) {
                throw "ARM_CM55F_MPU PendSV vector fixture is truncated: $regions/$($mode.Name)"
            }
            foreach ($vectorExpectation in @(
                    [pscustomobject]@{ Index = 11; Symbol = "SVC_Handler" },
                    [pscustomobject]@{ Index = 14; Symbol = "PendSV_Handler" })) {
                $line = @($elfDefined | Where-Object {
                    $_ -match ("^([0-9a-fA-F]+)\s+T\s+" +
                        [regex]::Escape($vectorExpectation.Symbol) + "$")
                })[0]
                [void]($line -match '^([0-9a-fA-F]+)')
                $address = [Convert]::ToUInt32($Matches[1], 16)
                if ([BitConverter]::ToUInt32($vector,
                        $vectorExpectation.Index * 4) -ne
                        ($address -bor [uint32]1)) {
                    throw "ARM_CM55F_MPU PendSV vector slot $($vectorExpectation.Index) lost $($vectorExpectation.Symbol): $regions/$($mode.Name)"
                }
            }

            if (($regions -eq 8) -and ($mode.Name -eq "hard-o2")) {
                $competingObject = Join-Path $modeDir "competing-pendsv.o"
                & $Compiler @($baseArgs + @("-c", $competing,
                    "-o", $competingObject))
                if ($LASTEXITCODE -ne 0) {
                    throw "ARM_CM55F_MPU competing PendSV fixture failed compile"
                }
                $duplicate = Invoke-CompilerProbe -Compiler $Compiler `
                    -Arguments @($baseArgs + @(
                        "-nostdlib", "-Wl,--gc-sections",
                        "-Wl,-T,$fixtureLinker", "-Wl,-T,$linkerContract",
                        $bootObject, $svcObject, $pendSvObject, $fixtureObject,
                        $competingObject, "-o",
                        (Join-Path $modeDir "duplicate-pendsv.elf"))) `
                    -LogPath (Join-Path $modeDir "duplicate-pendsv.log")
                if (($duplicate.ExitCode -eq 0) -or
                        ($duplicate.Output -notmatch '(?s)multiple definition.*PendSV_Handler')) {
                    throw "ARM_CM55F_MPU competing PendSV handlers must fail link`n$($duplicate.Output)"
                }
            }
        }
    }
}
