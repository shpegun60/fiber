param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$Python = "python",
    [string]$PythonModules = $env:FIBER_CLASSIC_AUDIT_PYTHONPATH
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixtures = Join-Path $PSScriptRoot "fixtures\cm33f_mpu_constructor"
$port = Join-Path $repo "fiber\port\ARM_CM33F_MPU\non_secure"
if (-not $ArmGcc) {
    $command = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($command) { $ArmGcc = $command.Source }
    else {
        $found = Get-ChildItem C:\ST -Recurse -Filter arm-none-eabi-gcc.exe `
            -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $ArmGcc = $found.FullName }
    }
}
if (-not $ArmGcc -or -not (Test-Path -LiteralPath $ArmGcc)) {
    throw "Set -ArmGcc to the existing ARM GCC executable"
}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin "arm-none-eabi-nm.exe"
$gxx = Join-Path $bin "arm-none-eabi-g++.exe"
$objdump = Join-Path $bin "arm-none-eabi-objdump.exe"
$readelf = Join-Path $bin "arm-none-eabi-readelf.exe"
if (-not $CmsisCore) { $CmsisCore = Join-Path $repo "..\..\..\Drivers\CMSIS\Include" }
if (-not $FreeRtosRoot) { $FreeRtosRoot = Join-Path $repo "..\..\..\..\_reference\FreeRTOS-Kernel" }
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
$reference = Join-Path $FreeRtosRoot "portable\GCC\ARM_CM33_NTZ\non_secure"
$boot = Join-Path $port "fiber_port_boot.c"
$contract = Join-Path $port "fiber_port_linker_contract.ld"
foreach ($required in @($nm, $gxx, $objdump, $readelf, $boot, $contract,
        (Join-Path $port "fiber_port_boot.h"), (Join-Path $CmsisCore "core_cm33.h"),
        (Join-Path $reference "port.c"), (Join-Path $fixtures "run_constructor.py"))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Missing constructor-proof dependency: $required" }
}
if (-not $BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ("cm33f-mpu-constructor-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $build -Force | Out-Null
$commands = Join-Path $build "commands.log"
Write-Host "C3FP constructor artifacts: $build"

function Invoke-Proof {
    param([string]$Program, [string[]]$Arguments, [string]$Log, [switch]$AllowFailure)
    Add-Content -LiteralPath $commands -Encoding ASCII -Value `
        ((@($Program) + $Arguments | ConvertTo-Json -Compress))
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $lines = @(& $Program @Arguments 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $saved }
    $output = $lines -join "`n"
    if ($Log) { Set-Content -LiteralPath $Log -Value $output -Encoding ASCII }
    if ($output) { Add-Content -LiteralPath $commands -Value $output -Encoding ASCII }
    if (-not $AllowFailure -and $code -ne 0) { throw "Proof command failed ($code): $Program`n$output" }
    return [pscustomobject]@{ ExitCode=$code; Output=$output }
}

function Test-ExactPythonRejection {
    param([object]$Result, [string]$Diagnostic)
    # Invoke-Proof joins captured lines without a terminal newline. Exact,
    # case-sensitive equality requires one diagnostic and no traceback/noise.
    return ($Result.ExitCode -eq 1 -and $Result.Output -ceq $Diagnostic)
}

function Assert-PythonCounterfeitRejected {
    param([object]$Result, [string]$Diagnostic, [string]$Name)
    if ($Result.ExitCode -ne 1 -or
            $Result.Output -cnotmatch '(?m)^Traceback \(most recent call last\):$' -or
            $Result.Output -cnotmatch ('(?m)^RuntimeError: ' + [regex]::Escape($Diagnostic) + '$')) {
        throw "Counterfeit did not exercise the intended traceback: $Name`n$($Result.Output)"
    }
    if (Test-ExactPythonRejection $Result $Diagnostic) {
        throw "Diagnostic classifier accepted a RuntimeError counterfeit: $Name"
    }
}

$oldPythonPath = $env:PYTHONPATH
$oldPythonOptimize = $env:PYTHONOPTIMIZE
try {
    if (-not $PythonModules) {
        $cached = Join-Path ([IO.Path]::GetTempPath()) "fiber-classic-audit-python"
        if (Test-Path -LiteralPath $cached) { $PythonModules = $cached }
    }
    if ($PythonModules) { $env:PYTHONPATH = $PythonModules + [IO.Path]::PathSeparator + $oldPythonPath }
    $optimizationDiagnostic = "C3FP proof rejects Python optimization; remove -O/-OO and unset PYTHONOPTIMIZE"
    $pythonPreflight = @'
import sys
if sys.flags.optimize or not __debug__:
    raise SystemExit('C3FP proof rejects Python optimization; remove -O/-OO and unset PYTHONOPTIMIZE')
import importlib.metadata as metadata
for package, expected in (('unicorn', '2.1.4'), ('pyelftools', '0.33')):
    try:
        actual = metadata.version(package)
    except metadata.PackageNotFoundError:
        raise SystemExit(f'Required package {package}=={expected} is unavailable')
    if actual != expected:
        raise SystemExit(f'Required package {package}=={expected}; found {actual}')
from unicorn.arm_const import UC_CPU_ARM_CORTEX_M33
print(sys.executable)
print(sys.version)
'@
    Invoke-Proof $Python @("-c", $pythonPreflight) `
        -Log (Join-Path $build "python-version.txt") | Out-Null
    $runner = Join-Path $fixtures "run_constructor.py"
    $controls = @()
    $optimizationCount = 0
    $counterfeitCount = 0
    $normalArguments = @((Join-Path $build "must-not-read-optimized.json"))
    $extractArguments = @("--extract-reference", (Join-Path $build "must-not-read-optimized.s"),
        (Join-Path $build "must-not-write-optimized.s"))
    $classifierImport = "import runpy, sys; namespace=runpy.run_path(sys.argv[1], run_name='constructor_classifier'); sys.exit('ERROR: optimized classifier import was accepted')"
    $entryPoints = @(
        @{Name="preflight"; Arguments=@("-c", $pythonPreflight); Source=$pythonPreflight; Tail=@()},
        @{Name="normal"; Arguments=@($runner) + $normalArguments; Source=$runner; Tail=$normalArguments},
        @{Name="classifier-import"; Arguments=@("-c", $classifierImport, $runner); Source=$runner; Tail=@()},
        @{Name="extract-reference"; Arguments=@($runner) + $extractArguments; Source=$runner; Tail=$extractArguments}
    )
    foreach ($activation in @("command-line-O", "command-line-OO", "environment-1", "environment-2")) {
        try {
            $pythonFlags = @()
            if ($activation -eq "command-line-O") { $pythonFlags += "-O" }
            elseif ($activation -eq "command-line-OO") { $pythonFlags += "-OO" }
            elseif ($activation -eq "environment-2") { $env:PYTHONOPTIMIZE = "2" }
            else { $env:PYTHONOPTIMIZE = "1" }
            foreach ($entry in $entryPoints) {
                $name = "optimization-$activation-$($entry.Name)"
                $control = Invoke-Proof $Python ($pythonFlags + $entry.Arguments) `
                    -Log (Join-Path $build ($name + ".log")) -AllowFailure
                if (-not (Test-ExactPythonRejection $control $optimizationDiagnostic)) {
                    throw "Optimization negative did not reject for the intended diagnostic: $name`n$($control.Output)"
                }
                $controls += [pscustomobject]@{Name=$name; ExitCode=$control.ExitCode; Diagnostic=$optimizationDiagnostic}
                $optimizationCount++
            }
        }
        finally { $env:PYTHONOPTIMIZE = $oldPythonOptimize }
    }
    $compiledEntry = @'
import sys
from pathlib import Path
if sys.flags.optimize or not __debug__:
    raise SystemExit('ERROR: compiled-import control must use an ordinary interpreter')
kind, level, source = sys.argv[1:4]
tail = sys.argv[4:]
if kind == 'preflight':
    filename = '<C3FP preflight>'
    namespace = {'__name__': '__main__', '__file__': filename}
else:
    filename = source
    source = Path(filename).read_text()
    namespace = {'__name__': 'constructor_classifier' if kind == 'classifier-import' else '__main__', '__file__': filename}
sys.argv = [filename] + tail
exec(compile(source, filename, 'exec', optimize=int(level)), namespace)
raise SystemExit('ERROR: optimized compiled entry was accepted')
'@
    foreach ($level in @(1, 2)) {
        foreach ($entry in $entryPoints) {
            $name = "optimization-compiled-$level-$($entry.Name)"
            $control = Invoke-Proof $Python (@("-c", $compiledEntry, $entry.Name, "$level", $entry.Source) + $entry.Tail) `
                -Log (Join-Path $build ($name + ".log")) -AllowFailure
            if (-not (Test-ExactPythonRejection $control $optimizationDiagnostic)) {
                throw "Compiled optimization negative missed the intended diagnostic: $name`n$($control.Output)"
            }
            $controls += [pscustomobject]@{Name=$name; ExitCode=$control.ExitCode; Diagnostic=$optimizationDiagnostic}
            $optimizationCount++
        }
    }
    # A diagnostic substring in a traceback is not an intentional SystemExit.
    # Mutate actual guard sources only in the artifact directory, then require
    # the same exact-output classifier to reject every counterfeit entry path.
    $guardSource = Get-Content -LiteralPath $runner -Raw
    $guardExit = 'raise SystemExit("' + $optimizationDiagnostic + '")'
    if ([regex]::Matches($guardSource, [regex]::Escape($guardExit)).Count -ne 1) {
        throw "Python optimization guard mutation anchor changed"
    }
    $counterfeitRunner = Join-Path $build "counterfeit-guard.py"
    $counterfeitSource = $guardSource.Replace($guardExit, 'raise RuntimeError("' + $optimizationDiagnostic + '")')
    Set-Content -LiteralPath $counterfeitRunner -Value $counterfeitSource -Encoding ASCII
    $counterfeitPreflight = $pythonPreflight.Replace("raise SystemExit(", "raise RuntimeError(")
    $counterfeitEntries = @(
        @{Name="preflight"; Arguments=@("-c", $counterfeitPreflight)},
        @{Name="normal"; Arguments=@($counterfeitRunner) + $normalArguments},
        @{Name="classifier-import"; Arguments=@("-c", $classifierImport, $counterfeitRunner)},
        @{Name="extract-reference"; Arguments=@($counterfeitRunner) + $extractArguments}
    )
    foreach ($entry in $counterfeitEntries) {
        $name = "counterfeit-runtimeerror-$($entry.Name)"
        $control = Invoke-Proof $Python (@("-O") + $entry.Arguments) `
            -Log (Join-Path $build ($name + ".log")) -AllowFailure
        Assert-PythonCounterfeitRejected $control $optimizationDiagnostic $name
        $controls += [pscustomobject]@{Name=$name; ExitCode=$control.ExitCode;
            Diagnostic=$optimizationDiagnostic; Disposition="CounterfeitRejected"}
        $counterfeitCount++
    }
    # Fault only the version-query result in a separate preflight process; do
    # not change installed packages or use assertions as the version gate.
    foreach ($package in @("unicorn", "pyelftools")) {
        $versionImport = "import importlib.metadata as metadata"
        $versionFault = $versionImport + "`noriginal_version = metadata.version`n" +
            "metadata.version = lambda name: '0.0.0-c3fp-control' if name == '$package' else original_version(name)"
        $badPreflight = $pythonPreflight.Replace($versionImport, $versionFault)
        $control = Invoke-Proof $Python @("-c", $badPreflight) `
            -Log (Join-Path $build ("package-version-$package.log")) -AllowFailure
        $expected = if ($package -eq "unicorn") { "2.1.4" } else { "0.33" }
        $diagnostic = "Required package $package==$expected; found 0.0.0-c3fp-control"
        if (-not (Test-ExactPythonRejection $control $diagnostic)) {
            throw "Package-version negative did not reject for the intended diagnostic: $package`n$($control.Output)"
        }
        $controls += [pscustomobject]@{Name="package-version-$package"; ExitCode=$control.ExitCode; Diagnostic=$diagnostic}
        $counterfeit = Invoke-Proof $Python @("-c", $badPreflight.Replace("raise SystemExit(", "raise RuntimeError(")) `
            -Log (Join-Path $build ("counterfeit-runtimeerror-package-$package.log")) -AllowFailure
        Assert-PythonCounterfeitRejected $counterfeit $diagnostic "package-$package"
        $controls += [pscustomobject]@{Name="counterfeit-runtimeerror-package-$package"; ExitCode=$counterfeit.ExitCode;
            Diagnostic=$diagnostic; Disposition="CounterfeitRejected"}
        $counterfeitCount++
    }
    ConvertTo-Json -InputObject $controls | Set-Content (Join-Path $build "python-negative-controls.json") -Encoding ASCII
    Write-Host "Python guard controls PASS: $optimizationCount optimization negatives, 2 package-version negatives, $counterfeitCount counterfeit rejections"
    $pin = "a50edad08b29052631aa469d4df6e6ec7ff68878"
    $head = (& git -C $FreeRtosRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -ne $pin) { throw "FreeRTOS reference pin mismatch: $head" }
    Invoke-Proof "git" @("-C", $FreeRtosRoot, "diff", "--exit-code", "HEAD", "--") | Out-Null
    Invoke-Proof $ArmGcc @("--version") -Log (Join-Path $build "gcc-version.txt") | Out-Null
    $sourcePaths = @($PSCommandPath, (Join-Path $repo "tools\fixtures\freertos_asm_parity\FreeRTOSConfig.h"),
        (Join-Path $reference "port.c"), (Join-Path $reference "portmacro.h"),
        (Join-Path $reference "portmacrocommon.h"), (Join-Path $CmsisCore "core_cm33.h"),
        (Join-Path $CmsisCore "cmsis_gcc.h"), (Join-Path $repo "fiber\fiber_api_attributes.h"))
    $sourcePaths += @(Get-ChildItem -LiteralPath $port -File | Select-Object -ExpandProperty FullName)
    $sourcePaths += @(Get-ChildItem -LiteralPath $fixtures -Recurse -File | Select-Object -ExpandProperty FullName)
    foreach ($directory in @($repo, (Join-Path $repo "fiber"), (Join-Path $repo "fiber\port"),
            $CmsisCore, (Join-Path $FreeRtosRoot "include"), $reference)) {
        $sourcePaths += @(Get-ChildItem -LiteralPath $directory -File -Filter *.h | Select-Object -ExpandProperty FullName)
    }
    $hashes = @($sourcePaths | Sort-Object -Unique | ForEach-Object {
        [pscustomobject]@{Path=$_; Sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
    })
    ConvertTo-Json -InputObject $hashes | Set-Content (Join-Path $build "sources.json") -Encoding ASCII
    [pscustomobject]@{Pin=$pin; Reference=(Join-Path $reference "port.c");
        Manifest="Actual M33_NTZ MPU=1 FPU=1, wrappers v2, MVE/TrustZone/PAC/BTI=0; unmodified pxPortInitialiseStack executed.";
        Difference="Reference debug seeds and untouched tail versus Fiber zero seeds, live r9, cleared 54-word backing, sealed map/metadata. Reference task-return address is a fixture-only symbol.";
        Shareability="Independent raw SH 0/2/3 valid, 1 reserved. Pinned reference SH=1 is a known defect, not a parity oracle.";
        Boundary="Compiled ARM constructor execution only. No handlers, scheduler runtime, MPU enforcement, FP exception behavior, or board proof."
    } | ConvertTo-Json | Set-Content (Join-Path $build "reference.json") -Encoding ASCII

    $common = @("-mcpu=cortex-m33", "-mthumb", "-mfpu=fpv5-sp-d16", "-std=gnu11",
        "-ffreestanding", "-fno-builtin", "-fno-common", "-fstrict-aliasing",
        "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Werror", "-Wundef")
    $includes = @("-I$fixtures", "-I$port", "-I$repo", "-I$(Join-Path $repo 'fiber')",
        "-I$(Join-Path $repo 'fiber\port')", "-I$CmsisCore")
    $selected = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
    $runs = @()
    $linkNegatives = @()
    foreach ($regions in @(8, 16)) {
        foreach ($abi in @("hard", "softfp")) {
            foreach ($optimization in @("-O2", "-Os")) {
                $name = "r$regions-$abi-$($optimization.Substring(1))"
                $dir = Join-Path $build $name
                New-Item -ItemType Directory -Path $dir | Out-Null
                $base = $common + @("-mfloat-abi=$abi", $optimization)
                $flags = $base + $selected + @("-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$regions") + $includes
                $cpp = Join-Path $dir "linkage.o"
                $cppFlags = @($flags | Where-Object { $_ -ne "-std=gnu11" }) + @("-std=c++17", "-fno-exceptions", "-fno-rtti")
                Invoke-Proof $gxx ($cppFlags + @("-c", (Join-Path $fixtures "linkage.cpp"), "-o", $cpp)) | Out-Null
                $elfs = @{}
                foreach ($policy in @("eager", "lazy")) {
                    $lazy = if ($policy -eq "lazy") { 1 } else { 0 }
                    $object = Join-Path $dir "boot-$policy.o"
                    Invoke-Proof $ArmGcc ($flags + @("-DFIBER_FPU_LAZY=$lazy", "-save-temps=obj", "-MMD", "-c", $boot, "-o", $object)) | Out-Null
                    Invoke-Proof $objdump @("-dr", $object) -Log (Join-Path $dir "boot-$policy.dis") | Out-Null
                    Invoke-Proof $nm @("-u", $object) -Log (Join-Path $dir "boot-$policy.undefined") | Out-Null
                    Invoke-Proof $readelf @("-A", $object) -Log (Join-Path $dir "boot-$policy.attributes") | Out-Null
                    # Lazy policy changes the exact cohort; compile its test-only
                    # provider consistently, without inventing a runtime object.
                    $policyProbe = Join-Path $dir "probe-$policy.o"
                    Invoke-Proof $ArmGcc ($flags + @("-DFIBER_FPU_LAZY=$lazy", "-c", (Join-Path $fixtures "probe.c"), "-o", $policyProbe)) | Out-Null
                    $providers = Invoke-Proof $nm @('-g', '--defined-only', $policyProbe) -Log ($policyProbe + '.providers')
                    foreach ($prefix in @('fiber_port_context_cohort_', 'fiber_port_storage_cohort_')) {
                        if ([regex]::Matches($providers.Output, '(?m)^\S+\s+R\s+' + $prefix + '\w+\s*$').Count -ne 1) {
                            throw "Constructor-only fixture must own exactly one readonly provider: $name/$policy/$prefix"
                        }
                    }
                    $elf = Join-Path $dir "constructor-$policy.elf"
                    Invoke-Proof $ArmGcc ($flags + @("-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings",
                        "-Wl,-T,$(Join-Path $fixtures 'constructor.ld')", "-Wl,-T,$contract",
                        "-Wl,-Map,$(Join-Path $dir "constructor-$policy.map")", $object, $policyProbe, $cpp, "-o", $elf)) | Out-Null
                    Invoke-Proof $objdump @("-dr", $elf) -Log (Join-Path $dir "constructor-$policy.dis") | Out-Null
                    $surface = Invoke-Proof $nm @('-g', '--defined-only', $elf) -Log ($elf + '.exports')
                    if ($surface.Output -match '\b(?:SVC_Handler|PendSV_Handler|fiber_port_(?:runtime_\w+|panic_wait|require_scheduler_configuration_environment|handler_bundle_v1_anchor|scheduler_pick_first_from_start))\b') {
                        throw "Constructor-only proof accidentally linked a production runtime/handler: $name/$policy"
                    }
                    $symbols = Invoke-Proof $readelf @('-sW', $elf) -Log ($elf + '.symbols')
                    foreach ($prefix in @('fiber_port_context_cohort_', 'fiber_port_storage_cohort_')) {
                        # nm calls readonly objects T after the board script
                        # merges rodata into its RX output; require OBJECT/size
                        # and the readonly flash envelope independently.
                        $rows = [regex]::Matches($symbols.Output,
                            '(?m)^\s*\d+:\s+([0-9a-fA-F]+)\s+1\s+OBJECT\s+GLOBAL\s+DEFAULT\s+[0-9]+\s+' + $prefix + '\w+\r?$')
                        if ($rows.Count -ne 1 -or
                                [Convert]::ToUInt32($rows[0].Groups[1].Value, 16) -lt 0x08000000 -or
                                [Convert]::ToUInt32($rows[0].Groups[1].Value, 16) -ge 0x08010000) {
                            throw "Constructor-only final ELF lost its exact fixture provider: $name/$policy/$prefix"
                        }
                    }
                    $elfs[$policy] = $elf
                }
                $hostile = Join-Path $dir "boot-hostile.o"
                Invoke-Proof $ArmGcc ($flags + @("-finstrument-functions", "-fstack-protector-all",
                    "-fprofile-arcs", "-ftest-coverage", "-fsanitize=undefined", "-c", $boot, "-o", $hostile)) | Out-Null
                Invoke-Proof $objdump @("-dr", $hostile) -Log (Join-Path $dir "boot-hostile.dis") | Out-Null

                $refDir = Join-Path $dir "reference"
                New-Item -ItemType Directory -Path $refDir | Out-Null
                $refFlags = $base + @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1",
                    "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=$regions", "-I$(Join-Path $fixtures 'reference')",
                    "-I$(Join-Path $FreeRtosRoot 'include')", "-I$reference")
                $refObjects = @()
                foreach ($unit in @("port.c", "probe.c")) {
                    $source = if ($unit -eq "port.c") { Join-Path $reference $unit } else { Join-Path $fixtures "reference\probe.c" }
                    $object = Join-Path $refDir $unit.Replace(".c", ".o")
                    # Pinned kernel code is compiled as-is, without applying
                    # Fiber's warning policy to unrelated discarded functions.
                    $refCompile = @($refFlags | Where-Object { $_ -notin @("-Wall", "-Wextra", "-Werror", "-Wundef") })
                    Invoke-Proof $ArmGcc ($refCompile + @("-save-temps=obj", "-MMD", "-c", $source, "-o", $object)) | Out-Null
                    Invoke-Proof $objdump @("-dr", $object) -Log ([IO.Path]::ChangeExtension($object, ".dis")) | Out-Null
                    $refObjects += $object
                }
                # FreeRTOS puts many unrelated functions in one privileged
                # section. Isolate only GCC's actual constructor assembly,
                # then independently check bytes/relocations against port.o.
                $liftedAssembly = Join-Path $refDir "constructor.s"
                Invoke-Proof $Python @((Join-Path $fixtures "run_constructor.py"), "--extract-reference",
                    (Join-Path $refDir "port.s"), $liftedAssembly) | Out-Null
                $liftedObject = Join-Path $refDir "constructor.o"
                Invoke-Proof $ArmGcc ($base + @("-c", $liftedAssembly, "-o", $liftedObject)) | Out-Null
                $refObjects = @($liftedObject, (Join-Path $refDir "probe.o"))
                $refElf = Join-Path $refDir "reference.elf"
                Invoke-Proof $ArmGcc ($refFlags + @("-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings",
                    "-Wl,-T,$(Join-Path $fixtures 'reference.ld')", "-Wl,-Map,$(Join-Path $refDir 'reference.map')") +
                    $refObjects + @("-o", $refElf)) | Out-Null
                Invoke-Proof $objdump @("-dr", $refElf) -Log (Join-Path $refDir "reference.dis") | Out-Null
                Invoke-Proof $readelf @("-A", $refElf) -Log (Join-Path $refDir "reference.attributes") | Out-Null
                $runs += [pscustomobject]@{Name=$name; Regions=$regions; Eager=$elfs.eager; Lazy=$elfs.lazy;
                    Reference=$refElf; Directory=$dir; Hostile=$hostile}
                Write-Host "Compiled C3FP constructor + actual pinned M33 constructor: $name"

                # The same twelve-symbol contract is checked for each region
                # geometry. Negative link products/logs remain in the archive.
                if ($abi -eq "hard" -and $optimization -eq "-O2") {
                    $original = Get-Content -LiteralPath (Join-Path $fixtures "constructor.ld") -Raw
                    $boundaries = [regex]::Matches($original, '(?m)^(__fiber_mpu_\w+__) = (0x[0-9A-Fa-f]+);')
                    if ($boundaries.Count -ne 12) { throw "Fixture boundary inventory changed" }
                    $cases = @()
                    foreach ($boundary in $boundaries) {
                        $symbol = $boundary.Groups[1].Value
                        $cases += @{Name="missing-$symbol"; Text=$original.Replace($boundary.Value, ""); Diagnostic="missing"}
                    }
                    $cases += @(
                        @{Name="overlap-slot-rw"; Text=$original.Replace("privileged_sram_start__ = 0x30000020", "privileged_sram_start__ = 0x30000000"); Diagnostic="current slot must end"},
                        @{Name="slot-size"; Text=$original.Replace("current_context_slot_end__ = 0x30000020", "current_context_slot_end__ = 0x30000040"); Diagnostic="exactly 32 bytes"},
                        @{Name="unaligned-ram"; Text=$original.Replace("unprivileged_ram_start__ = 0x24000000", "unprivileged_ram_start__ = 0x24000001"); Diagnostic="32-byte aligned"},
                        @{Name="code-containment"; Text=$original.Replace(".fiber_port_privileged_code 0x08000000", ".fiber_port_privileged_code 0x08030000"); Diagnostic="escaped privileged flash"},
                        @{Name="context-containment"; Text=$original.Replace(".fiber_port_privileged_data 0x30000020", ".fiber_port_privileged_data 0x30010000"); Diagnostic="escaped privileged SRAM"}
                    )
                    $negativeDir = Join-Path $dir "link-negatives"
                    New-Item -ItemType Directory -Path $negativeDir | Out-Null
                    foreach ($case in $cases) {
                        $linker = Join-Path $negativeDir ($case.Name + ".ld")
                        Set-Content -LiteralPath $linker -Value $case.Text -Encoding ASCII
                        $result = Invoke-Proof $ArmGcc ($flags + @("-nostdlib", "-Wl,--gc-sections",
                            "-Wl,-T,$linker", "-Wl,-T,$contract", (Join-Path $dir "boot-eager.o"),
                            (Join-Path $dir "probe-eager.o"), $cpp, "-o", (Join-Path $negativeDir ($case.Name + ".elf")))) `
                            -Log (Join-Path $negativeDir ($case.Name + ".log")) -AllowFailure
                        if ($result.ExitCode -eq 0 -or $result.Output -notmatch [regex]::Escape($case.Diagnostic)) {
                            throw "Linker negative missed intended diagnostic: $($case.Name)`n$($result.Output)"
                        }
                        $linkNegatives += [pscustomobject]@{Regions=$regions; Name=$case.Name; Diagnostic=$case.Diagnostic}
                    }
                }
            }
        }
    }
    ConvertTo-Json -InputObject $runs -Depth 5 | Set-Content (Join-Path $build "runs.json") -Encoding ASCII
    ConvertTo-Json -InputObject $linkNegatives | Set-Content (Join-Path $build "link-negatives.json") -Encoding ASCII
    $result = Invoke-Proof $Python @((Join-Path $fixtures "run_constructor.py"), (Join-Path $build "runs.json")) `
        -Log (Join-Path $build "execution.log") -AllowFailure
    Write-Host $result.Output
    foreach ($hash in $hashes) {
        if ((Get-FileHash -LiteralPath $hash.Path -Algorithm SHA256).Hash -ne $hash.Sha256) {
            throw "Input changed during qualification: $($hash.Path); rerun on stable sources"
        }
    }
    $artifacts = @(Get-ChildItem -LiteralPath $build -Recurse -File | ForEach-Object {
        [pscustomobject]@{Path=$_.FullName.Substring($build.Length + 1); Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    ConvertTo-Json -InputObject $artifacts | Set-Content (Join-Path $build "artifacts.json") -Encoding ASCII
    if ($result.ExitCode -ne 0) { throw "Constructor execution/static qualification failed; preserved evidence: $build" }
    Write-Host "PASS C3FP constructor: 8 configurations; $($linkNegatives.Count) linker negatives; $($controls.Count) Python guard negatives; artifacts $build"
}
finally {
    $env:PYTHONPATH = $oldPythonPath
    $env:PYTHONOPTIMIZE = $oldPythonOptimize
}
