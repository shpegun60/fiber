param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$HostGcc = "C:\msys64\ucrt64\bin\gcc.exe"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($ArmGcc) -or
    [string]::IsNullOrWhiteSpace($CmsisCore)) {
    throw "Target compile checks require both -ArmGcc and -CmsisCore (or their environment variables)"
}
if (-not (Test-Path -LiteralPath $ArmGcc -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $CmsisCore "core_cm55.h") -PathType Leaf)) {
    throw "Target compile checks require an existing ARM GCC and CMSIS core_cm55.h"
}
if (-not (Test-Path -LiteralPath $HostGcc)) {
    $HostGcc = (Get-Command gcc -ErrorAction Stop).Source
}
if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $BuildRoot = Join-Path $env:TEMP ("fiber-m55-fp-mpu-state-" + [guid]::NewGuid().ToString("N"))
}
$out = Join-Path $BuildRoot "m55-fp-mpu-state"
New-Item -ItemType Directory -Path $out -Force | Out-Null
$ArmObjdump = Join-Path (Split-Path -Parent $ArmGcc) 'arm-none-eabi-objdump.exe'
if (-not (Test-Path -LiteralPath $ArmObjdump -PathType Leaf)) { throw "Missing ARM objdump: $ArmObjdump" }
$hostRuns = $targetObjects = $targetGuardObjects = $negativeRuns = 0
$hostChecks = 0L
$inputPaths = @($PSCommandPath,
    $ArmGcc, $HostGcc, $ArmObjdump,
    (Join-Path $repo 'basic_types.h'), (Join-Path $repo 'mcu_core.h'),
    (Join-Path $PSScriptRoot 'fixtures\m55_fp_mpu_state_cases.c'),
    (Join-Path $PSScriptRoot 'fixtures\m55_fp_mpu_state_prefix.h'))
$inputPaths += @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'fixtures\m55_fp_mpu_state_target') -Recurse -File |
    Select-Object -ExpandProperty FullName)
$inputPaths += @(Get-ChildItem -LiteralPath (Join-Path $repo 'fiber'), (Join-Path $repo 'fiber\port'), $CmsisCore -File -Filter '*.h' |
    Select-Object -ExpandProperty FullName)
foreach ($profile in @('ARM_CM55F_MPU', 'ARM_CM55_MVEF_MPU')) {
    $dir = Join-Path $repo "fiber\port\$profile\non_secure"
    foreach ($leaf in @('fiber_port_boot.c', 'fiber_port_boot.h', 'fiber_port_svc.c',
            'fiber_port_pendsv.c', 'fiber_portmacro.h', 'fiber_port_types.h')) {
        $inputPaths += Join-Path $dir $leaf
    }
    $inputPaths += @(Get-ChildItem -LiteralPath $dir -File -Filter '*.h' |
        Select-Object -ExpandProperty FullName)
}
$inputPaths += @(Get-ChildItem -LiteralPath (Join-Path $repo 'context') -File -Filter '*.h' |
    Select-Object -ExpandProperty FullName)
$inputHashes = @($inputPaths | Sort-Object -Unique | ForEach-Object {
    [pscustomobject]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash }
})

# Compile real validator bodies, not a separately maintained behavioral model.
# Only hardware register access, architectural assembly, and external integration
# boundaries are stubbed by the fixture. The generated sources remain inspectable.
function Get-StateFunction([string]$Source, [string]$Name) {
    $match = [regex]::Match($Source,
        "(?m)^(?:void|int|uint32_t|uint8_t|uintptr_t|FiberContext\s*\*|const uint32_t\s*\*)\s*" +
        [regex]::Escape($Name) + "\s*\(")
    if (-not $match.Success) { throw "Missing source function: $Name" }
    $open = $Source.IndexOf('{', $match.Index)
    $depth = 0
    for ($i = $open; $i -lt $Source.Length; ++$i) {
        if ($Source[$i] -eq '{') { ++$depth }
        elseif ($Source[$i] -eq '}') {
            --$depth
            if ($depth -eq 0) {
                return $Source.Substring($match.Index, $i - $match.Index + 1)
            }
        }
    }
    throw "Unterminated source function: $Name"
}

# Execute the actual CONTROL restore snippets against the host register model.
# This deliberately handles only this bounded instruction subset and fails when
# source changes introduce an instruction the test cannot model.
function Get-ControlRestoreFunction([string]$Source, [string]$Name, [string]$HostName) {
    $function = Get-StateFunction $Source $Name
    $blocks = [regex]::Matches($function,
        '(?s)"msr\s+control,\s*r4\s*\\n".*?"bne\s+[0-9]+f\s*\\n"')
    if ($blocks.Count -ne 1) { throw "Expected one bounded CONTROL restore in $Name" }
    $body = @("uint32_t $HostName(uint32_t saved_control)", "{",
        "    uint32_t r4 = saved_control, r5 = 0;", "    int equal = 0;")
    foreach ($literal in [regex]::Matches($blocks[0].Value, '"([^"\r\n]*)"')) {
        $instruction = $literal.Groups[1].Value.Replace('\n', '').Trim()
        switch -Regex ($instruction) {
            '^msr\s+control,\s*r4$' { $body += '    __set_CONTROL(r4);'; break }
            '^isb$' { $body += '    fiber_portINST_SYNC_BARRIER();'; break }
            '^mrs\s+r5,\s*control$' { $body += '    r5 = __get_CONTROL();'; break }
            '^and\s+r5,\s*r5,\s*#(\d+)$' { $body += "    r5 &= $($Matches[1])u;"; break }
            '^bic\s+r4,\s*r4,\s*#(\d+)$' { $body += "    r4 &= ~$($Matches[1])u;"; break }
            '^cmp\s+r5,\s*#(\d+)$' { $body += "    equal = r5 == $($Matches[1])u;"; break }
            '^cmp\s+r5,\s*r4$' { $body += '    equal = r5 == r4;'; break }
            '^bne\s+\d+f$' { $body += "    if (!equal) fiber_panic('l');"; break }
            default { throw "Unhandled CONTROL restore instruction in ${Name}: $instruction" }
        }
    }
    $body += @('    return r5;', '}')
    return $body -join "`n"
}

# Translate the actual bounded save block, rather than constructing a second
# idealized image. Every instruction must be understood, including the branch
# which omits FP stores for a basic incoming EXC_RETURN. This is a host transfer
# model, not an exception/FP emulator; target assembly is checked separately.
function Get-ProtectedSaveFunction([string]$Source) {
    $handler = Get-StateFunction $Source 'PendSV_Handler'
    $blocks = [regex]::Matches($handler,
        '(?s)"mov\s+r2,\s*r1\s*\\n".*?"str\s+r1,\s*\[r2,\s*#0\]\s*\\n"')
    if ($blocks.Count -ne 1) { throw 'Expected exactly one protected save block' }
    $body = @('static void host_protected_save(FiberContext *ctx, uint32_t *frame,',
        '        uint32_t exc_return, const uint32_t gp[8], const uint32_t high_fp[16])',
        '{', '    uint32_t *r0 = frame, *r1 = NULL, r[8], s[32] = {0};',
        '    uint32_t r3 = 0; int basic = 0;', '    FiberContext *r2 = NULL;',
        '    memcpy(r, gp, sizeof(r)); memcpy(s + 16, high_fp, 16 * sizeof(*s));')
    foreach ($literal in [regex]::Matches($blocks[0].Value, '"([^"\r\n]*)"')) {
        $instruction = $literal.Groups[1].Value.Replace('\n', '').Trim() -replace '\s+', ' '
        switch -Exact ($instruction) {
            'mov r2, r1' { $body += '    r2 = ctx;'; break }
            'ldr r1, [r2, #0]' { $body += '    r1 = r2->protected_context_cursor;'; break }
            'adds r0, #0x20' { $body += '    r0 += 8;'; break }
            'tst lr, #0x10' { $body += '    basic = (exc_return & 16u) != 0u;'; break }
            'bne 2f' { $body += '    if (!basic) {'; break }
            'vstmia r1!, {s16-s31}' { $body += '        for (unsigned i = 16; i < 32; ++i) *r1++ = s[i];'; break }
            'vldmia r0, {s0-s16}' { $body += '        for (unsigned i = 0; i < 17; ++i) s[i] = r0[i];'; break }
            'vstmia r1!, {s0-s16}' { $body += '        for (unsigned i = 0; i < 17; ++i) *r1++ = s[i];'; break }
            '2:' { $body += '    }'; break }
            'subs r0, #0x20' { $body += '    r0 -= 8;'; break }
            'stmia r1!, {r4-r11}' { $body += '    for (unsigned i = 0; i < 8; ++i) *r1++ = r[i];'; break }
            'ldmia r0, {r4-r11}' { $body += '    for (unsigned i = 0; i < 8; ++i) r[i] = r0[i];'; break }
            'mrs r3, psplim' { $body += '    r3 = __get_PSPLIM();'; break }
            'mrs r4, control' { $body += '    r[0] = __get_CONTROL();'; break }
            'stmia r1!, {r0, r3, r4, lr}' { $body += @(
                '    *r1++ = (uint32_t)(uintptr_t)r0; *r1++ = r3;',
                '    *r1++ = r[0]; *r1++ = exc_return;'); break }
            'str r1, [r2, #0]' { $body += '    r2->protected_context_cursor = r1;'; break }
            default { throw "Unhandled protected save instruction: $instruction" }
        }
    }
    $body += '}'
    return $body -join "`n"
}

function Assert-NegativeExecution([string]$Exe, [string]$Diagnostic, [string]$Log) {
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $negative = @(& $Exe 2>&1 | ForEach-Object { "$_" }) -join "`n"
        $negativeCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    Set-Content -LiteralPath $Log -Value $negative -Encoding ASCII
    if ($negativeCode -ne 1 -or @($negative -split "`r?`n" | Where-Object { $_ -ceq $Diagnostic }).Count -ne 1) {
        throw "Negative control did not produce exactly the expected diagnostic ($Diagnostic): exit=$negativeCode $negative"
    }
}

foreach ($profile in @("ARM_CM55F_MPU", "ARM_CM55_MVEF_MPU")) {
    $dir = Join-Path $repo "fiber\port\$profile\non_secure"
    $boot = Get-Content -LiteralPath (Join-Path $dir "fiber_port_boot.c") -Raw
    $svc = Get-Content -LiteralPath (Join-Path $dir "fiber_port_svc.c") -Raw
    $pend = Get-Content -LiteralPath (Join-Path $dir "fiber_port_pendsv.c") -Raw
    $dictionary = Get-Content -LiteralPath (Join-Path $dir "fiber_portmacro.h") -Raw
    $bootHeader = Get-Content -LiteralPath (Join-Path $dir "fiber_port_boot.h") -Raw
    $functions = @()
    foreach ($name in @(
        "fiber_port_fpu_require_configured", "fiber_port_fpu_require_ready",
        "fiber_port_fpu_prepare", "fiber_port_range_contains",
        "fiber_port_ranges_overlap", "fiber_port_function_address",
        "fiber_port_code_address_is_in_range", "fiber_port_require_32_byte_range",
        "fiber_port_mpu_rbar_attributes_are_valid", "fiber_port_mpu_rlar_attributes_are_valid",
        "fiber_port_mpu_try_encode_exact_region", "fiber_port_mpu_encode_exact_region",
        "fiber_port_require_disjoint", "fiber_port_mpu_linker_layout_check",
        "fiber_port_mpu_build_global_regions", "fiber_port_context_validate_initial_restore")) {
        $functions += Get-StateFunction $boot $name
    }
    foreach ($name in @(
        "fiber_port_require_privileged_thread_start_environment", "fiber_port_require_mpu_geometry",
        "fiber_port_probe_implemented_priority_mask", "fiber_port_count_implemented_priority_bits",
        "fiber_port_validate_basepri_priority_policy", "fiber_port_configure_first_start_exceptions",
        "fiber_port_validate_svc_frame_shape", "fiber_port_validate_start_svc_frame",
        "fiber_port_running_svc_core_frame", "fiber_port_decode_svc_number",
        "fiber_port_validate_exact_svc_site", "fiber_port_require_scheduler_configuration_environment",
        "fiber_port_runtime_prepare_start", "fiber_port_svc_dispatch")) {
        $body = Get-StateFunction $svc $name
        if ($name -eq "fiber_port_probe_implemented_priority_mask") {
            $address = "(volatile uint8_t *)(uintptr_t)0xE000E400u"
            if (-not $body.Contains($address)) { throw "Priority probe MMIO binding changed" }
            $body = $body.Replace($address, "&first_irq_priority")
        }
        $functions += $body
    }
    foreach ($name in @(
        "fiber_port_code_address", "fiber_port_mpu_write_region",
        "fiber_port_mpu_validate_region_readback", "fiber_port_context_saved_form",
        "fiber_port_validate_stack_canary", "fiber_port_validate_saved_hardware_frame",
        "fiber_port_context_validate_restore", "fiber_port_validate_running_context_frame",
        "fiber_port_mpu_validate_active_context", "fiber_port_pendsv_validate_save_current",
        "fiber_port_capture_scheduler_mpu_image", "fiber_port_validate_scheduler_mpu_image",
        "fiber_port_capture_scheduler_cpu_state", "fiber_port_validate_scheduler_cpu_state",
        "fiber_port_scheduler_pick_next_from_pendsv", "fiber_port_mpu_switch_to_context")) {
        $functions += Get-StateFunction $pend $name
    }
    $functionText = $functions -join "`n`n"
    $controlRestores = (Get-ControlRestoreFunction $svc 'fiber_port_restore_first_context_from_svc' 'host_restore_first_control') + "`n" +
        (Get-ControlRestoreFunction $pend 'PendSV_Handler' 'host_restore_runtime_control')
    $protectedSave = Get-ProtectedSaveFunction $pend
    $savedForm = Get-StateFunction $pend 'fiber_port_context_saved_form'
    $trailingGuard = "FIBER_REQUIRE(image->extended.cursor_limit == 0u, 'P');"
    if ([regex]::Matches($savedForm, [regex]::Escape($trailingGuard)).Count -ne 2) {
        throw "$profile must check the permanent guard separately for both recognized saved forms"
    }
    $prototypes = ($functions | ForEach-Object { $_.Substring(0, $_.IndexOf('{')).Trim() + ";" }) -join "`n"
    $layout = [regex]::Match($bootHeader, '(?s)typedef struct FiberPortMpuMemoryLayout \{.*?\} FiberPortMpuMemoryLayout;').Value
    $globalImage = [regex]::Match($bootHeader, '(?s)typedef struct FiberPortMpuGlobalRegionImage \{.*?\} FiberPortMpuGlobalRegionImage;').Value
    $cpuImage = [regex]::Match($pend, '(?s)typedef struct FiberPortMpuSchedulerCpuState \{.*?\} FiberPortMpuSchedulerCpuState;').Value
    if (-not $layout -or -not $globalImage -or -not $cpuImage) { throw "Missing actual source types" }

    # Resolve the constants used by the actual functions directly from the port
    # dictionary, including their dependent aliases. Hardware lvalues stay stubs.
    $definitions = @{}
    $lines = $dictionary -split "`n"
    for ($i = 0; $i -lt $lines.Count; ++$i) {
        if ($lines[$i] -match '^#define\s+(\w+)\s+') {
            $name = $Matches[1]
            $definition = $lines[$i]
            while ($lines[$i].TrimEnd().EndsWith('\')) { ++$i; $definition += "`n" + $lines[$i] }
            $definitions[$name] = $definition
        }
    }
    $macros = @{}
    $prefix = Get-Content -LiteralPath (Join-Path $PSScriptRoot "fixtures\m55_fp_mpu_state_prefix.h") -Raw
    $cases = Get-Content -LiteralPath (Join-Path $PSScriptRoot "fixtures\m55_fp_mpu_state_cases.c") -Raw
    $pending = $functionText + $globalImage + $cpuImage + $prefix + $cases
    while ($true) {
        $added = $false
        foreach ($token in [regex]::Matches($pending, '\b(?:fiber_port|FIBER_PORT_)\w+')) {
            $name = $token.Value
            if ($definitions.ContainsKey($name) -and -not $macros.ContainsKey($name) -and
                $name -notmatch '_REG$|BARRIER$') {
                $macros[$name] = $definitions[$name]
                $added = $true
            }
        }
        if (-not $added) { break }
        $pending = $macros.Values -join "`n"
    }
    $constantText = ($macros.GetEnumerator() | Sort-Object Name | ForEach-Object { $_.Value }) -join "`n"
    foreach ($regions in @(8, 16)) {
        foreach ($lazy in @(0, 1)) {
            $stem = "$profile-r$regions-lazy$lazy"
            $source = Join-Path $out "$stem.c"
            $text = "#include <stdint.h>`n#define FIBER_PORT_${profile}_TOTAL_REGIONS $regions`n"
            # Public manifest spelling omits ARM_.
            $text = $text.Replace("FIBER_PORT_ARM_", "FIBER_PORT_")
            $text += "#define FIBER_FPU_LAZY $lazy`n#include `"$($dir.Replace('\','/'))/fiber_port_types.h`"`n"
            $text += $constantText + "`n" + $layout + "`n" + $globalImage + "`n" + $cpuImage + "`n"
            $text += $prefix + "`n" + $prototypes + "`n" + $functionText + "`n" + $controlRestores + "`n" + $protectedSave + "`n" + $cases
            Set-Content -LiteralPath $source -Value $text -Encoding ASCII
            # The actual encoder plus a stale dictionary must fail the same raw
            # SH oracle, not an assertion whose expected value uses that macro.
            $innerDefinition = '(?m)^#define[ \t]+fiber_portMPU_REGION_INNER_SHAREABLE[ \t]+[^\r\n]*'
            if ([regex]::Matches($text, $innerDefinition).Count -ne 1) {
                throw "$stem must expose exactly one INNER definition for the maintained mutant"
            }
            $mutantText = [regex]::Replace($text, $innerDefinition,
                '#define fiber_portMPU_REGION_INNER_SHAREABLE (1u << 3u)')
            if ($mutantText -eq $text) { throw "$stem INNER=1 mutant did not change source" }
            $mutantSource = Join-Path $out "$stem-inner1.c"
            Set-Content -LiteralPath $mutantSource -Value $mutantText -Encoding ASCII
            foreach ($optimization in @("-O0", "-O2", "-Os")) {
                $exe = Join-Path $out "$stem$optimization.exe"
                & $HostGcc -std=c11 $optimization -Wall -Wextra -Werror `
                    '-Wl,--image-base,0x400000,--disable-dynamicbase,--disable-high-entropy-va' $source -o $exe
                if ($LASTEXITCODE -ne 0) { throw "Host validator compile failed: $stem $optimization" }
                $positive = @(& $exe | ForEach-Object { "$_" }) -join "`n"
                if ($LASTEXITCODE -ne 0) { throw "Host validator execution failed: $stem $optimization" }
                Set-Content -LiteralPath (Join-Path $out "$stem$optimization.log") -Value $positive -Encoding ASCII
                Write-Host $positive
                $countMatch = [regex]::Match($positive, '(?m)^PASS: (\d+) source-derived state checks,')
                if (-not $countMatch.Success) { throw "Missing host check count: $stem $optimization" }
                $hostChecks += [long]$countMatch.Groups[1].Value
                ++$hostRuns
                $mutantExe = Join-Path $out "$stem$optimization-inner1.exe"
                & $HostGcc -std=c11 $optimization -Wall -Wextra -Werror `
                    '-Wl,--image-base,0x400000,--disable-dynamicbase,--disable-high-entropy-va' $mutantSource -o $mutantExe
                if ($LASTEXITCODE -ne 0) { throw "Host mutant compile failed: $stem $optimization" }
                Assert-NegativeExecution $mutantExe `
                    'MPU SH oracle mismatch: rbar=0x00000008 rlar=0x00000000 expected=0 actual=1' `
                    (Join-Path $out "$stem$optimization-inner1.log")
                ++$negativeRuns
                Write-Host "PASS: $stem $optimization stale INNER=1 rejected by raw SH oracle"
                foreach ($mutation in @('old-basic-guard', 'no-basic-guard', 'no-extended-guard')) {
                    $guardAt = if ($mutation -eq 'no-extended-guard') {
                        $savedForm.LastIndexOf($trailingGuard)
                    } else { $savedForm.IndexOf($trailingGuard) }
                    $replacement = if ($mutation -eq 'old-basic-guard') {
                        "FIBER_REQUIRE(image->basic.cursor_limit == 0u, 'P');"
                    } else { '/* maintained guard-removal counterexample */' }
                    $changed = $savedForm.Remove($guardAt, $trailingGuard.Length).Insert($guardAt, $replacement)
                    $guardSource = Join-Path $out "$stem$optimization-$mutation.c"
                    $guardExe = [IO.Path]::ChangeExtension($guardSource, '.exe')
                    if ([regex]::Matches($text, [regex]::Escape($savedForm)).Count -ne 1) {
                        throw 'Saved-form mutant must replace exactly one actual function body'
                    }
                    Set-Content -LiteralPath $guardSource -Value ($text.Replace($savedForm, $changed)) -Encoding ASCII
                    & $HostGcc -std=c11 $optimization -Wall -Wextra -Werror `
                        '-Wl,--image-base,0x400000,--disable-dynamicbase,--disable-high-entropy-va' $guardSource -o $guardExe
                    if ($LASTEXITCODE -ne 0) { throw "Guard mutant compile failed: $stem/$optimization/$mutation" }
                    $diagnostic = switch ($mutation) {
                        'old-basic-guard' { 'same-context basic-after-extended rejected: panic=P S4=0x71000004 guard53=0x00000000' }
                        'no-basic-guard' { 'guard53 corruption accepted: form=basic' }
                        'no-extended-guard' { 'guard53 corruption accepted: form=extended' }
                    }
                    Assert-NegativeExecution $guardExe $diagnostic (Join-Path $out "$stem$optimization-$mutation.log")
                    ++$negativeRuns
                }
                Write-Host "PASS: $stem $optimization old/basic/extended guard counterexamples rejected"
            }
        }
    }
    if ($ArmGcc) {
        foreach ($regions in @(8, 16)) {
            foreach ($optimization in @("-O2", "-Os")) {
                $arch = if ($profile -eq "ARM_CM55F_MPU") { "-march=armv8.1-m.main+fp" } else { "-march=armv8.1-m.main+mve.fp" }
                $manifest = $profile.Replace("ARM_", "")
                $arguments = @($arch, "-mthumb", "-mfloat-abi=hard", "-std=gnu11", $optimization,
                    "-ffreestanding", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
                    "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1",
                    "-DFIBER_PORT_${manifest}_TOTAL_REGIONS=$regions",
                    "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1",
                    "-I$(Join-Path $PSScriptRoot 'fixtures\m55_fp_mpu_state_target')",
                    "-I$dir", "-I$(Join-Path $repo 'fiber\port')", "-I$repo", "-I$CmsisCore")
                foreach ($component in @("boot", "svc", "pendsv")) {
                    $assembly = Join-Path $out "$profile-r$regions$optimization-$component.s"
                    $object = [IO.Path]::ChangeExtension($assembly, ".o")
                    & $ArmGcc @arguments -save-temps=obj -c (Join-Path $dir "fiber_port_$component.c") -o $object
                    if ($LASTEXITCODE -ne 0) { throw "Target source compile failed: $profile/$regions/$optimization/$component" }
                    ++$targetObjects
                    if ($component -eq "svc") {
                        $text = Get-Content -LiteralPath $assembly -Raw
                        $start = $text.IndexOf("fiber_port_restore_first_context_from_svc:")
                        $restore = $text.Substring($start)
                        if ($restore -notmatch 'msr\s+control, r4\s+isb\s+mrs\s+r5, control\s+and\s+r5, r5, #7\s+cmp\s+r5, #3') {
                            throw "First restore must read back written CONTROL=3, not entry CONTROL=1"
                        }
                    }
                    if ($component -eq "pendsv") {
                        $disassembly = @(& $ArmObjdump -dr $object) -join "`n"
                        if ($LASTEXITCODE -ne 0) { throw 'Target PendSV disassembly failed' }
                        Set-Content -LiteralPath ([IO.Path]::ChangeExtension($assembly, '.dis')) -Value $disassembly -Encoding ASCII
                        $text = Get-Content -LiteralPath $assembly -Raw
                        $start = $text.IndexOf("PendSV_Handler:")
                        $restore = $text.Substring($start)
                        if ($restore -notmatch 'msr\s+control, r4\s+isb\s+mrs\s+r5, control\s+and\s+r5, r5, #7\s+cmp\s+r5, r4') {
                            throw "Runtime restore must read back exact written CONTROL, including SPSEL"
                        }
                        foreach ($transfer in @('vstmia r1!, {s16-s31}', 'vldmia r0, {s0-s16}',
                            'vstmia r1!, {s0-s16}', 'vldmdb r1!, {s0-s16}',
                            'vstmia r0!, {s0-s16}', 'vldmdb r1!, {s16-s31}')) {
                            if (-not $restore.Contains($transfer)) { throw "Lost pinned protected FP transfer: $transfer" }
                        }
                        # The exact source save block must survive the compiler;
                        # no extra store/clear of word 20 or 53 is allowed here.
                        $block = [regex]::Match((Get-StateFunction $pend 'PendSV_Handler'),
                            '(?s)"mov\s+r2,\s*r1\s*\\n".*?"str\s+r1,\s*\[r2,\s*#0\]\s*\\n"').Value
                        $instructions = @([regex]::Matches($block, '"([^"\r\n]*)"') | ForEach-Object {
                            $_.Groups[1].Value.Replace('\n', '').Trim() -replace '\s+', ' '
                        })
                        $normalized = ($restore -replace '(?m)^\s*@[^\r\n]*', '') -replace '\s+', ' '
                        if (-not $normalized.Contains(($instructions -join ' '))) {
                            throw 'Compiled PendSV save no longer matches the source-derived transfer model'
                        }
                    }
                }
                # Compile the exact production classifier with actual public
                # storage types. Numeric offsets are an independent geometry
                # oracle, not derived from the field expression under test.
                foreach ($floatAbi in @('hard', 'softfp')) {
                    $guardStem = "$profile-r$regions$optimization-$floatAbi-saved-form"
                    $guardSource = Join-Path $out "$guardStem.c"
                    $guardObject = Join-Path $out "$guardStem.o"
                    $guardOffset = if ($regions -eq 8) { 252 } else { 316 }
                    $basicOffset = if ($regions -eq 8) { 120 } else { 184 }
                    $guardText = @"
#include <stddef.h>
#define FIBER_PORT_${manifest}_TOTAL_REGIONS $regions
#include "$($dir.Replace('\','/'))/fiber_port_types.h"
#include "$($repo.Replace('\','/'))/fiber/fiber_api_attributes.h"
extern FIBER_API_NORETURN void fiber_panic(char);
#define FIBER_REQUIRE(c, code) do { if (!(c)) fiber_panic(code); } while (0)
_Static_assert(offsetof(FiberContext, protected_context.words[53]) == $guardOffset, "permanent guard geometry");
_Static_assert(offsetof(FiberContext, protected_context.words[20]) == $basicOffset, "basic cursor geometry");
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
$savedForm
"@
                    Set-Content -LiteralPath $guardSource -Value $guardText -Encoding ASCII
                    & $ArmGcc $arch -mthumb "-mfloat-abi=$floatAbi" $optimization -std=gnu11 `
                        -ffreestanding -fno-builtin -Wall -Wextra -Werror -c $guardSource -o $guardObject
                    if ($LASTEXITCODE -ne 0) { throw "Actual saved-form target compile failed: $guardStem" }
                    $disassembly = @(& $ArmObjdump -dr $guardObject) -join "`n"
                    if ($LASTEXITCODE -ne 0) { throw "Saved-form disassembly failed: $guardStem" }
                    Set-Content -LiteralPath (Join-Path $out "$guardStem.dis") -Value $disassembly -Encoding ASCII
                    if ($disassembly -notmatch "ldr(?:\.w)?\s+r\d+,\s*\[r0,\s*#$guardOffset\]" -or
                        $disassembly -match "ldr(?:\.w)?\s+r\d+,\s*\[r0,\s*#$basicOffset\]" -or
                        $disassembly -match '(?m)^\s*[0-9a-f]+:\s+(?:[0-9a-f]{4}\s+)+v\w+\s') {
                        throw "Saved-form machine code must load guard53, never basic word20 or FP: $guardStem"
                    }
                    ++$targetGuardObjects
                }
            }
        }
    }
}
foreach ($input in $inputHashes) {
    if ((Get-FileHash -LiteralPath $input.path -Algorithm SHA256).Hash -ne $input.sha256) {
        throw "Input changed during qualification: $($input.path)"
    }
}
$receipt = [ordered]@{
    status = 'PASS'; armGcc = $ArmGcc; hostGcc = $HostGcc; cmsisCore = $CmsisCore
    hostRuns = $hostRuns; hostChecks = $hostChecks; negativeRuns = $negativeRuns
    targetProductionObjects = $targetObjects; targetSavedFormObjects = $targetGuardObjects
    proofBoundary = 'Saved-representation host C/save model plus actual ARM compilation/disassembly; no five-API FPCA teardown reachability, exception/FP execution or hardware claim'
    inputs = $inputHashes
}
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'receipt.json') -Encoding ASCII
Write-Host "PASS: $hostRuns host runs/$hostChecks checks, $negativeRuns maintained negatives, $targetObjects production ARM objects, $targetGuardObjects ARM classifiers ($out)"
