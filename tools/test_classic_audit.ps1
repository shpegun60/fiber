param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$Python = "python",
    [string]$PythonModules = $env:FIBER_CLASSIC_AUDIT_PYTHONPATH,
    [string]$FreeRtosRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixtures = Join-Path $PSScriptRoot "fixtures\classic_audit"
if (-not $ArmGcc) {
    $command = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($command) { $ArmGcc = $command.Source }
    else {
        $found = Get-ChildItem -Path C:\ST -Recurse -Filter arm-none-eabi-gcc.exe `
            -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $ArmGcc = $found.FullName }
    }
}
if (-not $ArmGcc -or -not (Test-Path -LiteralPath $ArmGcc)) {
    throw "Set -ArmGcc to arm-none-eabi-gcc.exe"
}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin "arm-none-eabi-nm.exe"
$ar = Join-Path $bin "arm-none-eabi-gcc-ar.exe"
$objdump = Join-Path $bin "arm-none-eabi-objdump.exe"
if (-not $CmsisCore) {
    $CmsisCore = Join-Path $repo "..\..\..\Drivers\CMSIS\Include"
}
foreach ($required in @($nm, $ar, $objdump,
        (Join-Path $CmsisCore "core_cm0.h"),
        (Join-Path $CmsisCore "core_cm0plus.h"))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Missing dependency: $required" }
}
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
if (-not $FreeRtosRoot) {
    $FreeRtosRoot = Join-Path $repo "..\..\..\..\_reference\FreeRTOS-Kernel"
}
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
if (-not $BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ("fiber-classic-audit-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $build -Force | Out-Null
$transcript = Join-Path $build "commands.log"

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    Add-Content -LiteralPath $transcript -Value `
        ((@($Program) + $Arguments | ConvertTo-Json -Compress)) -Encoding ASCII
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $result = @(& $Program @Arguments 2>&1)
    $status = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($result.Count) {
        Add-Content -LiteralPath $transcript -Value ($result -join "`n") -Encoding ASCII
    }
    if ($status -ne 0) { throw "$Program failed ($status): $($result -join "`n")" }
}

$pythonPreflight = @'
import sys, importlib.metadata as m
if sys.flags.optimize:
    raise SystemExit('Disable PYTHONOPTIMIZE and do not use -O/-OO for classic audit regressions')
for name, expected in (('unicorn', '2.1.4'), ('pyelftools', '0.33')):
    actual = m.version(name)
    if actual != expected:
        raise SystemExit(f'Classic audit requires {name}=={expected}; found {actual}')
    print(f'{name} {actual}')
print(sys.executable)
print(sys.version)
'@
$pythonPreflightTests = @'
import subprocess, sys
source, fixture = sys.argv[1:]
pinned = {'unicorn': '2.1.4', 'pyelftools': '0.33'}
optimization_error = 'Disable PYTHONOPTIMIZE and do not use -O/-OO for classic audit regressions'
def expected_rejection(result, diagnostic):
    return (result.returncode == 1
            and result.stderr.splitlines() == [diagnostic])
cases = (
    ('pinned', [], pinned, 0, 'pyelftools 0.33'),
    ('wrong-unicorn', [], dict(pinned, unicorn='0.0'), 1, 'Classic audit requires unicorn==2.1.4; found 0.0'),
    ('wrong-pyelftools', [], dict(pinned, pyelftools='0.0'), 1, 'Classic audit requires pyelftools==0.33; found 0.0'),
    ('optimized', ['-O'], pinned, 1, optimization_error),
    ('double-optimized', ['-OO'], pinned, 1, optimization_error),
)
for name, flags, versions, expected_status, expected_text in cases:
    # Override metadata only in the child; do not alter installed packages.
    prefix = f'import importlib.metadata as m\nm.version = {versions!r}.__getitem__\n'
    result = subprocess.run([sys.executable, *flags, '-c', prefix + source],
                            capture_output=True, text=True, timeout=15)
    accepted = (result.returncode == 0 and not result.stderr and expected_text in result.stdout
                if expected_status == 0 else expected_rejection(result, expected_text))
    if not accepted:
        raise SystemExit(f'Preflight regression {name}: {result.returncode}: {result.stdout}{result.stderr}')
for flag in ('-O', '-OO'):
    result = subprocess.run([sys.executable, flag, fixture],
                            capture_output=True, text=True, timeout=15)
    if not expected_rejection(result, optimization_error):
        raise SystemExit(f'Fixture optimization regression {flag}: {result.returncode}: {result.stdout}{result.stderr}')
counterfeit = subprocess.run(
    [sys.executable, '-c', f'raise RuntimeError({optimization_error!r})'],
    capture_output=True, text=True, timeout=15)
if (counterfeit.returncode != 1
        or counterfeit.stderr.splitlines()[-1:] != [f'RuntimeError: {optimization_error}']
        or expected_rejection(counterfeit, optimization_error)):
    raise SystemExit('Counterfeit RuntimeError rejection regression failed')
print('PASS counterfeit RuntimeError diagnostic rejected')
print('PASS classic Python preflight regressions (8 cases)')
'@

$oldPythonPath = $env:PYTHONPATH
try {
    if (-not $PythonModules) {
        $cachedModules = Join-Path ([IO.Path]::GetTempPath()) "fiber-classic-audit-python"
        if (Test-Path -LiteralPath $cachedModules) { $PythonModules = $cachedModules }
    }
    if ($PythonModules) {
        $env:PYTHONPATH = $PythonModules + [IO.Path]::PathSeparator + $oldPythonPath
    }
    try {
        Invoke-Checked $Python @("-c", $pythonPreflight)
    }
    catch {
        throw "Classic audit Python preflight failed: disable optimized Python and use the pinned audit-only dependencies from tools/fixtures/classic_audit/requirements.txt (see its README.md). $($_.Exception.Message)"
    }
    Invoke-Checked $Python @("-c", $pythonPreflightTests, $pythonPreflight,
        (Join-Path $fixtures "run_guards.py"))
    $pin = "a50edad08b29052631aa469d4df6e6ec7ff68878"
    $actualPin = (& git -C $FreeRtosRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualPin -ne $pin) {
        throw "FreeRTOS HEAD differs from the audited pin: $actualPin"
    }
    Invoke-Checked "git" @("-C", $FreeRtosRoot, "diff", "--exit-code", "HEAD", "--")
    $referenceFiles = @("ARM_CM0/port.c", "ARM_CM0/portasm.c", "ARM_CM0/portmacro.h",
        "ARM_CM3/port.c", "ARM_CM4F/port.c", "ARM_CM7/r0p1/port.c")
    $evidence = foreach ($relative in $referenceFiles) {
        $source = Join-Path $FreeRtosRoot ("portable/GCC/" + $relative)
        [pscustomobject]@{ Path = $relative; Sha256 = (Get-FileHash $source -Algorithm SHA256).Hash }
    }
    $referencePort = Get-Content (Join-Path $FreeRtosRoot "portable/GCC/ARM_CM0/port.c") -Raw
    $referenceAsm = Get-Content (Join-Path $FreeRtosRoot "portable/GCC/ARM_CM0/portasm.c") -Raw
    if ($referencePort -notmatch 'ulContext\[ 5 \] = 0x09090909' -or
            $referenceAsm -notmatch "Don't reset the MSP stack") {
        throw "Pinned CM0 comparison assumptions changed"
    }
    [pscustomobject]@{ Pin = $pin; Files = @($evidence);
        Comparison = @(
            "FreeRTOS CM0 preserves MSP; Fiber explicitly reads the board vector with asm.",
            "FreeRTOS MPU seeds r9 diagnostically, without a later live-register equality.",
            "RO vector-placement and raw-allocation canary checks are Fiber hardening, not parity claims."
        ) } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $build "reference.json") -Encoding ASCII
    Invoke-Checked $ArmGcc @("--version")

    $profiles = @(
        @{ Name="cm0"; Port="ARM_CM0"; Cpu="cortex-m0"; Core=0; Vtor=0; Mpu=0; Arch="ARMV6M" },
        @{ Name="cm0plus-novtor"; Port="ARM_CM0"; Cpu="cortex-m0plus"; Core=1; Vtor=0; Mpu=0; Arch="ARMV6M" },
        @{ Name="cm3"; Port="ARM_CM3"; Cpu="cortex-m3"; Core=3; Vtor=1; Mpu=0; Arch="ARMV7M" },
        @{ Name="cm4"; Port="ARM_CM4"; Cpu="cortex-m4"; Core=4; Vtor=1; Mpu=0; Arch="ARMV7EM" },
        @{ Name="cm7"; Port="ARM_CM7/r0p1"; Cpu="cortex-m7"; Core=7; Vtor=1; Mpu=0; Arch="ARMV7EM" },
        @{ Name="cm0mpu"; Port="ARM_CM0_MPU"; Cpu="cortex-m0plus"; Core=1; Vtor=1; Mpu=1; Arch="ARMV6M" },
        @{ Name="cm0mpu-novtor"; Port="ARM_CM0_MPU"; Cpu="cortex-m0plus"; Core=1; Vtor=0; Mpu=1; Arch="ARMV6M" }
    )
    $runs = @()
    foreach ($profile in $profiles) {
        foreach ($optimization in @("-O2", "-Os")) {
            $ltoModes = @($false)
            if (-not $profile.Mpu) { $ltoModes += $true }
            foreach ($lto in $ltoModes) {
                $name = $profile.Name + "-" + $optimization.Substring(1)
                if ($lto) { $name += "-lto" }
                $dir = Join-Path $build $name
                New-Item -ItemType Directory -Path $dir | Out-Null
                $portDir = Join-Path $repo ("fiber/port/" + $profile.Port)
                $flags = @("-mcpu=$($profile.Cpu)", "-mthumb", "-mfloat-abi=soft",
                    "-std=gnu11", $optimization, "-ffreestanding", "-fno-builtin",
                    "-ffunction-sections", "-fdata-sections", "-fno-common",
                    "-Wall", "-Wextra", "-Werror=implicit-function-declaration",
                    "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_$($profile.Arch)=1",
                    "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1",
                    "-DAUDIT_CORE=$($profile.Core)", "-DAUDIT_MPU=$($profile.Mpu)",
                    "-DAUDIT_VTOR=$($profile.Vtor)",
                    "-I$portDir", "-I$fixtures", "-I$repo", "-I$(Join-Path $repo 'fiber')",
                    "-I$CmsisCore")
                if ($lto) { $flags += "-flto" }
                $sources = @{
                    boot = Join-Path $fixtures "boot_unit.c"
                    port = Join-Path $fixtures "port_unit.c"
                    fixture = Join-Path $fixtures "fixture.c"
                }
                if (-not $profile.Mpu) {
                    $sources["override"] = Join-Path $fixtures "fallback_override.c"
                    $sources["exception"] = Join-Path $portDir "fiber_port_exception.c"
                }
                foreach ($key in $sources.Keys) {
                    $compile = $flags + @("-save-temps=obj", "-c", $sources[$key],
                        "-o", (Join-Path $dir "$key.o"))
                    Invoke-Checked $ArmGcc $compile
                }
                $flashBase = "0x08000000"
                if ($profile.Mpu -and -not $profile.Vtor) { $flashBase = "0" }
                $link = $flags + @("-nostdlib", "-Wl,--gc-sections", "-Wl,--no-undefined",
                    "-Wl,--defsym,audit_flash_base=$flashBase",
                    "-Wl,-T,$(Join-Path $fixtures 'probe.ld')", "-Wl,-u,audit_validate")
                if ($profile.Mpu) {
                    $link += "-Wl,-u,audit_vectors"
                    $orders = @(@{Name="direct"; Inputs=@("boot.o")})
                }
                else {
                    $link += @("-Wl,-u,audit_fallback_result", "-Wl,-u,audit_prepare_msp",
                        "-Wl,-u,audit_boot_check", "-Wl,-u,fiber_fallback_initial_msp")
                    Invoke-Checked $ar @("rcs", (Join-Path $dir "boot.a"), (Join-Path $dir "boot.o"))
                    Invoke-Checked $ar @("rcs", (Join-Path $dir "override.a"), (Join-Path $dir "override.o"))
                    $orders = @(
                        @{Name="default-first"; Inputs=@("boot.o", "override.o")},
                        @{Name="override-first"; Inputs=@("override.o", "boot.o")},
                        @{Name="default-archive-first"; Inputs=@("boot.a", "override.a")},
                        @{Name="override-archive-first"; Inputs=@("override.a", "boot.a")}
                    )
                    if (-not $lto) {
                        $overrideSymbols = (& $nm --defined-only (Join-Path $dir "override.o")) -join "`n"
                        $bootSymbols = (& $nm --defined-only (Join-Path $dir "boot.o")) -join "`n"
                        if ($overrideSymbols -notmatch '\bT fiber_fallback_initial_msp' -or
                                $bootSymbols -notmatch '\bW fiber_fallback_initial_msp') {
                            throw "Fallback binding is not strong override / weak default ($name)"
                        }
                    }
                }
                foreach ($order in $orders) {
                    $elf = Join-Path $dir ($order.Name + ".elf")
                    $inputs = @((Join-Path $dir "fixture.o"), (Join-Path $dir "port.o"))
                    if (-not $profile.Mpu) { $inputs += Join-Path $dir "exception.o" }
                    $inputs += @($order.Inputs | ForEach-Object { Join-Path $dir $_ })
                    # -u is needed to extract a boot archive independently of ELF ENTRY.
                    Invoke-Checked $ArmGcc ($link + @("-Wl,-u,audit_init") + $inputs + @("-o", $elf))
                    $undefined = @(& $nm -u $elf)
                    if ($LASTEXITCODE -ne 0 -or $undefined.Count -ne 0) {
                        throw "Unexpected undefined symbols: $elf : $undefined"
                    }
                    $disassembly = (& $objdump -dr $elf) -join "`n"
                    if ($LASTEXITCODE -ne 0) { throw "objdump failed: $elf" }
                    Set-Content ([IO.Path]::ChangeExtension($elf, ".dis")) $disassembly -Encoding ASCII
                    if ($profile.Core -le 1 -and -not $profile.Mpu -and
                            $disassembly -match '\budf\b|\.inst\s+0xdeff') {
                        throw "Optimized no-VTOR code contains an undefined-instruction trap: $elf"
                    }
                    $runs += [pscustomobject]@{ Elf=$elf; Mpu=[bool]$profile.Mpu;
                        Core=$profile.Core; Vtor=$profile.Vtor; Name=($name + "/" + $order.Name) }
                }
                Write-Host "Built $name"
            }
        }
    }
    $manifest = Join-Path $build "runs.json"
    ConvertTo-Json -InputObject @($runs) -Depth 5 | Set-Content $manifest -Encoding ASCII
    Invoke-Checked $Python @((Join-Path $fixtures "run_guards.py"), $manifest)
    $result = Get-Content (Join-Path $build "results.json") -Raw | ConvertFrom-Json
    Write-Host "Executed $($result.checks) focused guard checks"
    Write-Host "PASS classic audit A09/A10/A11/A13/A14 ($($runs.Count) real ARM ELFs)"
    Write-Host "Evidence: $build"
}
finally {
    $env:PYTHONPATH = $oldPythonPath
}
