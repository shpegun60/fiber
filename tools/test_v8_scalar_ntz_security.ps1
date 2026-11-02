param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$HostGcc,
    [string]$BuildRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$ArmGcc) {
    $found = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $ArmGcc = $found.Source }
    else {
        $found = Get-ChildItem C:\ST -Filter arm-none-eabi-gcc.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $ArmGcc = $found.FullName }
    }
}
if (!$HostGcc) {
    $found = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $HostGcc = $found.Source }
    elseif (Test-Path C:\msys64\ucrt64\bin\gcc.exe) { $HostGcc = 'C:\msys64\ucrt64\bin\gcc.exe' }
}
if (!$CmsisCore) { $CmsisCore = Join-Path $Repo '../../../Drivers/CMSIS/Include' }
foreach ($file in @($ArmGcc, $HostGcc, (Join-Path $CmsisCore 'core_cm33.h'), (Join-Path $CmsisCore 'core_cm55.h'))) {
    if (!$file -or !(Test-Path -LiteralPath $file)) { throw "Required compiler/header missing: $file" }
}
if (!$BuildRoot) { $BuildRoot = Join-Path $env:TEMP ('fiber-v8-scalar-ntz-security-' + [guid]::NewGuid().ToString('N')) }
$null = New-Item -ItemType Directory -Force -Path $BuildRoot
$BuildRoot = (Resolve-Path $BuildRoot).Path
$Bin = Split-Path $ArmGcc
$Ar = Join-Path $Bin 'arm-none-eabi-gcc-ar.exe'
$Nm = Join-Path $Bin 'arm-none-eabi-gcc-nm.exe'
$Objcopy = Join-Path $Bin 'arm-none-eabi-objcopy.exe'

function Run-Tool {
    param([string]$Tool, [string[]]$Arguments, [switch]$MayFail)
    [IO.File]::AppendAllText((Join-Path $BuildRoot 'commands.log'), $Tool + ' ' + ($Arguments -join ' ') + "`n")
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = @(& $Tool @Arguments 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    if ($code -ne 0 -and !$MayFail) { throw "Tool failed ($code): $Tool`n$($output -join "`n")" }
    return [pscustomobject]@{ Code = $code; Text = ($output -join "`n") }
}
function Actual-Function {
    param([string]$Text, [string]$Name)
    $m = [regex]::Match($Text, '(?m)^(?:void|int|uintptr_t|uint32_t|FiberContext \*)\s*' + [regex]::Escape($Name) + '\(')
    if (!$m.Success) { throw "Actual function missing: $Name" }
    $brace = $Text.IndexOf('{', $m.Index)
    $depth = 1
    for ($i = $brace + 1; $i -lt $Text.Length; ++$i) {
        if ($Text[$i] -eq '{') { ++$depth }
        if ($Text[$i] -eq '}') { --$depth; if (!$depth) { return $Text.Substring($m.Index, $i + 1 - $m.Index) + "`n" } }
    }
    throw "Unterminated actual function: $Name"
}
function Source-Instructions {
    param([string]$Function)
    $withoutComments = [regex]::Replace($Function, '(?s)/\*.*?\*/', '')
    return (([regex]::Matches($withoutComments, '"(?:\\.|[^"\\])*"') | ForEach-Object {
        [regex]::Unescape($_.Value.Substring(1, $_.Value.Length - 2))
    }) -join '')
}
function Assembly-Function {
    param([string]$Assembly, [string]$Name)
    $m = [regex]::Match($Assembly,
        '(?ms)^' + [regex]::Escape($Name) + ':\s*(.*?)^\s*\.size\s+' + [regex]::Escape($Name) + '\b')
    if (!$m.Success) { throw "Actual assembly function missing: $Name" }
    return $m.Value
}
function Test-ScalarControlReadback {
    param([string]$Instructions)
    # Armv8-M exception entry clears SPSEL. A later privileged MSR can set it;
    # reading that bit is distinct from Handler mode's physical use of MSP.
    return [regex]::Matches($Instructions,
        'msr\s+control,\s*r4\s+isb\s+mrs\s+r5,\s*control\s+and\s+r5,\s*r5,\s*#3\s+cmp\s+r5,\s*#3\s+bne\b').Count -eq 1
}
function Test-PrivilegedSvcControlReadback {
    param([string]$Instructions)
    return [regex]::Matches($Instructions,
        'movs\s+(?<cr>r[12]),\s*#2\s+msr\s+control,\s*\k<cr>\s+isb\s+mrs\s+\k<cr>,\s*control\s+and\s+\k<cr>,\s*\k<cr>,\s*#(?:3|7)\s+cmp\s+\k<cr>,\s*#2\s+bne\b').Count -eq 1
}
function Test-ScalarEntryControlSource {
    param([string]$Function)
    return [regex]::Matches($Function,
        'FIBER_REQUIRE\((?:__get_CONTROL|fiber_port_cpu_read_control)\(\)\s*==\s*1u,\s*''l''\)').Count -eq 1
}
function Test-ScalarSvcEntryControlSource {
    param([string]$Function)
    return [regex]::Matches($Function,
        '(?s)else if \(exc_return == fiber_portINITIAL_EXC_RETURN\)\s*\{\s*FIBER_REQUIRE\((?:__get_CONTROL|fiber_port_cpu_read_control)\(\) == 1u, ''l''\)').Count -eq 1
}
function Assert-ScalarControlSource {
    param([string]$Runtime, [string]$Boot, [string]$Profile)
    foreach ($name in @('fiber_port_restore_first_context_from_svc', 'PendSV_Handler')) {
        $instructions = Source-Instructions (Actual-Function $Runtime $name)
        if (!(Test-ScalarControlReadback $instructions)) {
            throw "$Profile/$name must read back written CONTROL 3 after MSR, not exception-entry CONTROL 1"
        }
        $stale = [regex]::Replace($instructions,
            '(mrs\s+r5,\s*control\s+and\s+r5,\s*r5,\s*#3\s+cmp\s+r5,\s*)#3', '${1}#1')
        if ($stale -eq $instructions -or (Test-ScalarControlReadback $stale)) {
            throw "$Profile/$name CONTROL assertion does not reject the stale post-MSR readback 1"
        }
    }
    foreach ($name in @('fiber_port_pendsv_validate_save_current',
            'fiber_port_scheduler_pick_next_from_pendsv', 'fiber_port_mpu_switch_to_context')) {
        $body = Actual-Function $Runtime $name
        if (!(Test-ScalarEntryControlSource $body)) {
            throw "$Profile/$name must retain exception-entry Handler CONTROL 1 before any restore MSR"
        }
        foreach ($reader in @('__get_CONTROL', 'fiber_port_cpu_read_control')) {
            $dialect = [regex]::Replace($body, '\b(?:__get_CONTROL|fiber_port_cpu_read_control)(?=\(\))', $reader)
            if (!(Test-ScalarEntryControlSource $dialect)) {
                throw "$Profile/$name assertion rejects qualified CONTROL reader $reader"
            }
            $stale = [regex]::Replace($dialect, '(' + [regex]::Escape($reader) + '\(\)\s*==\s*)1u', '${1}3u')
            if ($stale -eq $dialect -or (Test-ScalarEntryControlSource $stale)) {
                throw "$Profile/$name assertion accepts saved Thread CONTROL 3 at Handler entry ($reader)"
            }
        }
    }
    $svc = Actual-Function $Runtime 'fiber_port_svc_dispatch'
    if (!(Test-ScalarSvcEntryControlSource $svc)) {
        throw "$Profile runtime SVC lost its exception-entry CONTROL 1 check"
    }
    foreach ($reader in @('__get_CONTROL', 'fiber_port_cpu_read_control')) {
        $dialect = [regex]::Replace($svc, '\b(?:__get_CONTROL|fiber_port_cpu_read_control)(?=\(\))', $reader)
        if (!(Test-ScalarSvcEntryControlSource $dialect)) {
            throw "$Profile runtime SVC assertion rejects qualified CONTROL reader $reader"
        }
        $stale = [regex]::Replace($dialect, '(' + [regex]::Escape($reader) + '\(\)\s*==\s*)1u', '${1}3u')
        if ($stale -eq $dialect -or (Test-ScalarSvcEntryControlSource $stale)) {
            throw "$Profile runtime SVC assertion accepts saved Thread CONTROL 3 at Handler entry ($reader)"
        }
    }
    foreach ($name in @('fiber_port_validate_running_context_frame', 'fiber_port_context_validate_restore')) {
        if ((Actual-Function $Runtime $name) -notmatch 'image->control\s*==\s*fiber_portINITIAL_CONTROL_UNPRIVILEGED') {
            throw "$Profile/$name must retain the canonical saved Thread CONTROL contract"
        }
    }
    if ((Actual-Function $Boot 'fiber_port_context_init') -notmatch
            'ctx->protected_context.control\s*=\s*fiber_portINITIAL_CONTROL_UNPRIVILEGED') {
        throw "$Profile initial image no longer seeds canonical Thread CONTROL"
    }
    $save = Source-Instructions (Actual-Function $Runtime 'PendSV_Handler')
    if ($save -notmatch 'mrs\s+r4,\s*control\s+orr\s+r4,\s*r4,\s*#2\s+stmia\s+r1!,\s*\{r0,\s*r3,\s*r4,\s*lr\}') {
        throw "$Profile no longer normalizes entry CONTROL 1 to saved CONTROL 3"
    }
}
function Write-Main {
    param([string]$Dir, [int]$Core, [int]$Fp)
    $header = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT ${Fp}U
#define __FPU_USED ${Fp}U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SecureFault_IRQn = -9,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#include "core_cm${Core}.h"
#endif
"@
    [IO.File]::WriteAllText((Join-Path $Dir 'main.h'), $header)
}
$Base = @('-mthumb', '-std=gnu11', '-ffreestanding', '-fno-builtin', '-fno-common',
    '-ffunction-sections', '-fdata-sections', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
    '-Wall', '-Wextra', '-Werror', '-fno-instrument-functions', '-fno-stack-protector',
    '-fno-profile-arcs', '-fno-test-coverage', '-fno-sanitize=all',
    '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1',
    '-DFIBER_SCHEDULER_BASEPRI=0x10', "-I$Repo", "-I$CmsisCore", "-I$Repo/fiber", "-I$Repo/fiber/port")
$profiles = @('ARM_CM33_NTZ', 'ARM_CM33F_NTZ', 'ARM_CM55_NTZ', 'ARM_CM55F_NTZ',
    'ARM_CM55_MVEF_NTZ', 'ARM_CM33', 'ARM_CM33_TFM', 'ARM_CM33_MPU', 'ARM_CM55_MPU')
$readerControls = @()
foreach ($profile in $profiles) {
    $is55 = $profile.StartsWith('ARM_CM55')
    $core = if ($is55) { 55 } else { 33 }
    $fp = [int]($profile -match 'F_NTZ$')
    $mpu = [int]($profile -match '_MPU$')
    $sourceDir = Join-Path $Repo "fiber/port/$profile/non_secure"
    $runtime = [IO.File]::ReadAllText((Join-Path $sourceDir 'fiber_port.c'))
    $boot = [IO.File]::ReadAllText((Join-Path $sourceDir 'fiber_port_boot.c'))
    if ($mpu) { Assert-ScalarControlSource $runtime $boot $profile }
    if (!$mpu) {
        $svcPath = Join-Path $sourceDir 'fiber_port_svc.c'
        $svc = if (Test-Path -LiteralPath $svcPath) { [IO.File]::ReadAllText($svcPath) } else { $runtime }
        $instructions = Source-Instructions (Actual-Function $svc 'SVC_Handler')
        if (!(Test-PrivilegedSvcControlReadback $instructions)) {
            throw "$profile SVC must read back written CONTROL 2, not exception-entry CONTROL 0"
        }
        $stale = [regex]::Replace($instructions,
            '(mrs\s+r[12],\s*control\s+and\s+r[12],\s*r[12],\s*#(?:3|7)\s+cmp\s+r[12],\s*)#2', '${1}#0')
        if ($stale -eq $instructions -or (Test-PrivilegedSvcControlReadback $stale)) {
            throw "$profile source assertion does not reject the obsolete post-MSR readback 0"
        }
    }
    $cpu = if ($is55 -and $fp) {
        if ($profile -match 'MVE') { @('-march=armv8.1-m.main+mve.fp', '-mfloat-abi=hard') }
        else { @('-march=armv8.1-m.main+fp', '-mfloat-abi=hard') }
    } elseif ($fp) { @('-mcpu=cortex-m33', '-mfpu=fpv5-sp-d16', '-mfloat-abi=hard') }
    else { @("-mcpu=cortex-m$core", '-mfloat-abi=soft') }
    $arch = if ($is55) { '-DFIBER_PORT_ARMV81M_MAINLINE=1' } else { '-DFIBER_PORT_ARMV8M_MAINLINE=1' }
    $regionModes = if ($mpu) { @(8, 16) } else { @(0) }
    foreach ($regions in $regionModes) {
        $dir = Join-Path $BuildRoot "$profile-$regions"
        $null = New-Item -ItemType Directory -Force -Path $dir
        Write-Main $dir $core $fp
        $flags = $Base + $cpu + @($arch, "-I$dir", "-I$sourceDir")
        if ($mpu) { $flags += "-DFIBER_PORT_CM${core}_MPU_TOTAL_REGIONS=$regions" }
        $empty = Join-Path $dir 'empty.c'
        [IO.File]::WriteAllText($empty, '')
        $macros = (Run-Tool $ArmGcc ($flags + @('-dM', '-E', '-include', (Join-Path $sourceDir 'fiber_port_private.h'), $empty))).Text
        if ($mpu) {
            $generation = if ($regions -eq 8) { '0x00020008u' } else { '0x00020010u' }
            if ($macros -notmatch ('#define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION ' + $generation)) {
                throw "$profile requires protected semantic layout generation 2 ($regions regions)"
            }
            if ($macros -notmatch '#define fiber_portINITIAL_CONTROL_UNPRIVILEGED (?:0x0*3|3)u\b') {
                throw "$profile canonical saved CONTROL must remain 3, distinct from entry CONTROL 1"
            }
        }
        $selected = @($macros -split "`n" | Where-Object {
            $_ -match '^#define (fiber_port(?:MPU_|INITIAL_|XPSR_|BYTE_ALIGNMENT|CPACR_CP10_CP11_FULL|FPCCR_.*_BIT)|FIBER_PORT_(?:CM\d+_MPU_TOTAL_REGIONS|EXC_BASE_BYTES|STACK_ALIGNMENT))' -and
            $_ -notmatch '^#define fiber_portMPU_\w+_REG\s'
        })
        [IO.File]::WriteAllLines((Join-Path $dir 'actual_macros.h'), [string[]]$selected)
        $functions = ''
        if ($mpu) {
            foreach ($name in @('fiber_port_range_contains', 'fiber_port_ranges_overlap',
                    'fiber_port_code_address_is_in_range', 'fiber_port_require_32_byte_range',
                    'fiber_port_mpu_rbar_attributes_are_valid', 'fiber_port_mpu_rlar_attributes_are_valid',
                    'fiber_port_mpu_try_encode_exact_region', 'fiber_port_mpu_encode_exact_region',
                    'fiber_port_require_disjoint', 'fiber_port_mpu_linker_layout_check', 'fiber_port_mpu_build_global_regions')) {
                $functions += Actual-Function $boot $name
            }
            foreach ($name in @('fiber_port_code_address', 'fiber_port_validate_svc_frame_shape',
                    'fiber_port_validate_running_context_frame', 'fiber_port_validate_saved_hardware_frame',
                    'fiber_port_context_validate_restore', 'fiber_port_pendsv_validate_save_current')) {
                $functions += Actual-Function $runtime $name
            }
        } else {
            if ($fp) {
                $fpSource = if ($profile -eq 'ARM_CM33F_NTZ') { $runtime } else { $boot }
                foreach ($name in @('fiber_port_fpu_require_configured', 'fiber_port_fpu_require_ready')) {
                    $functions += Actual-Function $fpSource $name
                }
                foreach ($name in @('fiber_port_capture_validation_cpu_state', 'fiber_port_validate_validation_cpu_state')) {
                    $functions += Actual-Function $boot $name
                }
            }
            foreach ($name in @('fiber_port_runtime_schedule', 'fiber_port_scheduler_pick_next_from_pendsv')) {
                $functions += Actual-Function $runtime $name
            }
        }
        [IO.File]::WriteAllText((Join-Path $dir 'actual_functions.inc'), $functions)
        foreach ($lazy in $(if ($fp) { @(0, 1) } else { @(0) })) {
            $exe = Join-Path $dir "host-lazy$lazy.exe"
            $null = Run-Tool $HostGcc @('-std=c11', '-O2', '-Wall', '-Wextra', '-Wno-unused-variable',
                '-Wno-unused-function', '-Werror', "-DTEST_MPU=$mpu", "-DTEST_FP=$fp", "-DFIBER_FPU_LAZY=$lazy",
                "-I$dir", (Join-Path $PSScriptRoot 'fixtures/v8_scalar_ntz_state_host.c'), '-o', $exe)
            Write-Output "$profile regions=$regions lazy=$lazy $((Run-Tool $exe @()).Text)"
        }
        if (!$readerControls.Count) {
            $fixture = Join-Path $PSScriptRoot 'fixtures/v8_scalar_ntz_state_host.c'
            $fixtureText = [IO.File]::ReadAllText($fixture)
            foreach ($prefix in @('fiber_port_cpu_read_', 'fiber_port_cpu_')) {
              foreach ($register in @('IPSR', 'CONTROL', 'PRIMASK', 'FAULTMASK', 'PSPLIM', 'PSP')) {
                $reader = $prefix + $register.ToLowerInvariant()
                $anchor = '(?m)^#define ' + [regex]::Escape($reader) + '\(\) __get_' + $register + '\(\)\r?$'
                if ([regex]::Matches($fixtureText, $anchor).Count -ne 1) {
                    throw "Missing exact host-reader mutation anchor: $reader"
                }
                $mutantText = [regex]::Replace($fixtureText, $anchor, "#define $reader() 0u")
                $mutantDir = Join-Path $dir ('reader-mutant-' + $reader)
                $null = New-Item -ItemType Directory -Force -Path $mutantDir
                $mutantSource = Join-Path $mutantDir 'host.c'
                [IO.File]::WriteAllText($mutantSource, $mutantText)
                $mutantExe = Join-Path $mutantDir 'host.exe'
                $null = Run-Tool $HostGcc @('-std=c11', '-O2', '-Wall', '-Wextra', '-Wno-unused-variable',
                    '-Wno-unused-function', '-Werror', "-DTEST_MPU=$mpu", "-DTEST_FP=$fp", '-DFIBER_FPU_LAZY=0',
                    "-I$dir", $mutantSource, '-o', $mutantExe)
                $negative = Run-Tool $mutantExe @() -MayFail
                [IO.File]::WriteAllText((Join-Path $mutantDir 'host.log'), $negative.Text)
                if ($negative.Code -ne 1 -or $negative.Text.Trim() -cne "local CPU reader mismatch: $reader") {
                    throw "Wrong host-reader observation was not rejected exactly: $reader/$($negative.Code)/$($negative.Text)"
                }
                $readerControls += [pscustomobject]@{ Reader = $reader; ExitCode = $negative.Code; Diagnostic = $negative.Text.Trim() }
                [IO.File]::WriteAllText((Join-Path $BuildRoot 'reader-controls.json'),
                    (ConvertTo-Json -InputObject $readerControls -Depth 4))
                Write-Output "PASS exact host-reader counterexample: $reader"
              }
            }
        }
        if ($mpu) {
            # Mutate only the extracted dictionary. The same raw-numeric fixture
            # must reject SH=1 even when the implementation calls it INNER.
            $mutantDir = Join-Path $dir 'inner1-mutant'
            $null = New-Item -ItemType Directory -Force -Path $mutantDir
            $macroText = $selected -join "`n"
            $innerDefinition = '(?m)^#define[ \t]+fiber_portMPU_REGION_INNER_SHAREABLE[ \t]+[^\r\n]*'
            if ([regex]::Matches($macroText, $innerDefinition).Count -ne 1) {
                throw "$profile must expose exactly one INNER definition for the maintained mutant"
            }
            $mutantMacros = [regex]::Replace($macroText, $innerDefinition,
                '#define fiber_portMPU_REGION_INNER_SHAREABLE (1u << 3u)')
            if ($mutantMacros -eq $macroText) { throw "$profile INNER=1 mutant did not change source" }
            [IO.File]::WriteAllText((Join-Path $mutantDir 'actual_macros.h'), $mutantMacros)
            [IO.File]::WriteAllText((Join-Path $mutantDir 'actual_functions.inc'), $functions)
            foreach ($opt in @('-O2', '-Os')) {
                $mutantExe = Join-Path $mutantDir "host$opt.exe"
                $null = Run-Tool $HostGcc @('-std=c11', $opt, '-Wall', '-Wextra', '-Wno-unused-variable',
                    '-Wno-unused-function', '-Werror', '-DTEST_MPU=1', '-DTEST_FP=0', '-DFIBER_FPU_LAZY=0',
                    "-I$mutantDir", (Join-Path $PSScriptRoot 'fixtures/v8_scalar_ntz_state_host.c'), '-o', $mutantExe)
                $negative = Run-Tool $mutantExe @() -MayFail
                [IO.File]::WriteAllText((Join-Path $mutantDir "host$opt.log"), $negative.Text)
                if ($negative.Code -ne 1 -or $negative.Text -notmatch
                        'MPU SH oracle mismatch: rbar=0x00000008 rlar=0x00000000 expected=0 actual=1') {
                    throw "$profile/$regions/$opt stale INNER=1 was not rejected by the independent SH oracle: $($negative.Text)"
                }
                Write-Output "PASS $profile regions=$regions $opt stale INNER=1 rejected by raw SH oracle"
            }
        }
        foreach ($opt in @('-O2', '-Os')) {
            $asmText = ''
            foreach ($name in @('fiber_port.c', 'fiber_port_boot.c', 'fiber_port_svc.c', 'fiber_port_secure_context.c')) {
                $source = Join-Path $sourceDir $name
                if (!(Test-Path -LiteralPath $source)) { continue }
                $asm = Join-Path $dir ($name + $opt + '.s')
                $null = Run-Tool $ArmGcc ($flags + @($opt, '-DFIBER_FPU_LAZY=1', '-S', $source, '-o', $asm))
                $null = Run-Tool $ArmGcc ($cpu + @('-mthumb', '-c', $asm, '-o', ($asm + '.o')))
                $asmText += [IO.File]::ReadAllText($asm)
            }
            if ($mpu) {
                foreach ($name in @('fiber_port_restore_first_context_from_svc', 'PendSV_Handler')) {
                    if (!(Test-ScalarControlReadback (Assembly-Function $asmText $name))) {
                        throw "$profile $regions $opt $name must preserve CONTROL 3 in its post-MSR readback"
                    }
                }
            }
            if (!$mpu -and
                    !(Test-PrivilegedSvcControlReadback (Assembly-Function $asmText 'SVC_Handler'))) {
                throw "$profile $opt SVC lost exact CONTROL 2 post-write readback"
            }
            if ($fp) {
                $pendSv = [regex]::Match($asmText, '(?ms)^PendSV_Handler:\s*(.*?)^\s*\.size\s+PendSV_Handler')
                if (!$pendSv.Success) { throw "$profile $opt lacks actual PendSV assembly" }
                if ($pendSv.Value -match 'ldr\s+r3, \[r0, #?100\]') { throw "$profile $opt uses extension word as xPSR" }
                if ([regex]::Matches($pendSv.Value, 'ldr\s+r3, \[r0, #?28\]').Count -ne 2) {
                    throw "$profile $opt must read core xPSR at +28 for both basic and extended frames"
                }
            }
            if ($mpu -and $asmText -notmatch 'mrs\s+r4, control\s+orr\s+r4, r4, #2\s+stmia') {
                throw "$profile $opt no longer normalizes its saved CONTROL"
            }
        }
    }
}
if ($readerControls.Count -ne 12) { throw 'The exact twelve local-reader controls did not all execute' }

# A15: fresh runtime/boot/attachment/common plus only a stale actual handler.
# Matching links and strong vector checks distinguish extraction from identity.
$profileDir = Join-Path $Repo 'fiber/port/ARM_CM33/non_secure'
foreach ($mode in @('normal', 'lto')) {
    $dir = Join-Path $BuildRoot "cm33-handler-$mode"
    $null = New-Item -ItemType Directory -Force -Path $dir
    Write-Main $dir 33 0
    $flags = $Base + @('-mcpu=cortex-m33', '-mfloat-abi=soft', '-mgeneral-regs-only',
        '-DFIBER_PORT_ARMV8M_MAINLINE=1', '-O2', "-I$dir", "-I$profileDir")
    if ($mode -eq 'lto') { $flags += '-flto' }
    $ld = Join-Path $dir 'link.ld'
    $ldText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/arm_cm33_secure_gateway_non_secure.ld'))
    $ldText = $ldText.Replace('*(.text*)', 'KEEP(*(.fiber_port_context_cohort_expectation)) *(.text*)')
    [IO.File]::WriteAllText($ld, $ldText)
    $prefix = @()
    foreach ($source in @('fiber/fiber_core.c', 'fiber/fiber_runtime_state.c', 'fiber/fiber_panic.c',
            'fiber/fiber_runtime_context_configuration.c', 'fiber/port/fiber_port_context_cohort_expectation.c',
            'tools/fixtures/portable_application.c', 'tools/fixtures/v8_scalar_security_link_probe.c')) {
        $obj = Join-Path $dir ((Split-Path $source -Leaf) + '.o')
        $null = Run-Tool $ArmGcc ($flags + @('-c', (Join-Path $Repo $source), '-o', $obj))
        $prefix += $obj
    }
    $members = @()
    foreach ($name in @('fiber_port', 'fiber_port_boot', 'fiber_port_secure_context')) {
        $obj = Join-Path $dir ($name + '.o')
        $null = Run-Tool $ArmGcc ($flags + @('-c', (Join-Path $profileDir ($name + '.c')), '-o', $obj))
        $members += $obj
    }
    foreach ($variant in @('matching', 'stale-basepri', 'stale-reverse', 'pre-fix-handler')) {
        $handler = Join-Path $dir ($variant + '.o')
        $handlerFlags = @($flags)
        if ($variant -eq 'stale-basepri') {
            $handlerFlags = @($flags | Where-Object { $_ -ne '-DFIBER_SCHEDULER_BASEPRI=0x10' }) + '-DFIBER_SCHEDULER_BASEPRI=0x20'
        }
        if ($variant -eq 'stale-reverse') {
            $handlerFlags += '-Dfiber_internal_runtime_port_abi_v1_anchor=fiber_internal_runtime_port_abi_v999_anchor'
        }
        $handlerSource = Join-Path $profileDir 'fiber_port_svc.c'
        if ($variant -eq 'pre-fix-handler') {
            $handlerSource = Join-Path $dir 'legacy-handler.c'
            $legacy = (Run-Tool 'git' @('-C', $Repo, 'show', '5c34785088e3496540a8dcbec1351fac241e11ca:fiber/port/ARM_CM33/non_secure/fiber_port_svc.c')).Text
            if ($legacy -match 'handler_component_v1_anchor') { throw 'The fixed pre-audit source pin is no longer a pre-fix handler' }
            [IO.File]::WriteAllText($handlerSource, $legacy)
        }
        $null = Run-Tool $ArmGcc ($handlerFlags + @('-c', $handlerSource, '-o', $handler))
        $archive = Join-Path $dir ("lib-$variant.a")
        $null = Run-Tool $Ar (@('rcs', $archive) + $members + $handler)
        $elf = Join-Path $dir ($variant + '.elf')
        $link = Run-Tool $ArmGcc ($flags + @('-nostdlib', '-Wl,--gc-sections', "-Wl,-T,$ld", "-Wl,-Map,$elf.map") + $prefix + @($archive, '-o', $elf)) -MayFail
        [IO.File]::WriteAllText(($elf + '.log'), $link.Text)
        if ($variant -eq 'matching') {
            if ($link.Code) { throw "Matching $mode handler archive failed: $($link.Text)" }
            $symbols = (Run-Tool $Nm @('-a', $elf)).Text
            foreach ($symbol in @('SVC_Handler', 'PendSV_Handler', 'fiber_port_arm_cm33_secure_context_handler_component_v1_anchor')) {
                if ($symbols -notmatch "(?m)^[0-9a-fA-F]+ T $symbol`$") { throw "Missing strong retained $symbol ($mode)" }
            }
            if ((Run-Tool $Nm @('-u', $elf)).Text.Trim()) { throw "Undefined symbols in matching $mode ELF" }
            $vectors = Join-Path $dir 'vectors.bin'
            $null = Run-Tool $Objcopy @('-O', 'binary', '--only-section=.isr_vector', $elf, $vectors)
            $bytes = [IO.File]::ReadAllBytes($vectors)
            foreach ($entry in @(@(11, 'SVC_Handler'), @(14, 'PendSV_Handler'))) {
                $m = [regex]::Match($symbols, "(?m)^([0-9a-fA-F]+) T $($entry[1])`$")
                $address = [Convert]::ToUInt32($m.Groups[1].Value, 16) -bor 1
                if ([BitConverter]::ToUInt32($bytes, 4 * $entry[0]) -ne $address) { throw "Wrong $mode vector $($entry[0])" }
            }
        } else {
            if ($variant -eq 'pre-fix-handler') { $expected = 'fiber_port_arm_cm33_secure_context_handler_component_v1_anchor' }
            elseif ($variant -eq 'stale-reverse') { $expected = 'fiber_internal_runtime_port_abi_v999_anchor' }
            else {
                $undefined = (Run-Tool $Nm @('-u', $handler)).Text
                $m = [regex]::Match($undefined, 'fiber_port_context_cohort_\w+_u00100000_\w+')
                if (!$m.Success) { throw 'Stale BASEPRI handler does not retain its original exact cohort' }
                $expected = [regex]::Escape($m.Value)
            }
            if (!$link.Code -or $link.Text -notmatch $expected) { throw "Stale $variant $mode was not rejected by its own identity: $($link.Text)" }
        }
        Write-Output "PASS actual CM33 archive $mode $variant"
    }
}
Write-Output "PASS v8 scalar/NTZ/security focused regressions. Artifacts: $BuildRoot"
