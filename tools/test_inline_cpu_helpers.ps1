param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$HostGcc,
    [string]$BuildRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixtures = Join-Path $PSScriptRoot 'fixtures/inline_cpu_helpers'
if (-not $ArmGcc) {
    $found = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $ArmGcc = $found.Source }
    else {
        $found = Get-ChildItem C:/ST -Recurse -Filter arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $ArmGcc = $found.FullName }
    }
}
if (-not $HostGcc) {
    $found = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $HostGcc = $found.Source }
    elseif (Test-Path -LiteralPath C:/msys64/ucrt64/bin/gcc.exe) { $HostGcc = 'C:/msys64/ucrt64/bin/gcc.exe' }
}
if (-not $CmsisCore) { $CmsisCore = Join-Path $repo '../../../Drivers/CMSIS/Include' }
foreach ($path in @($ArmGcc, $HostGcc, $CmsisCore)) {
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { throw "Missing required compiler/header directory: $path" }
}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$HostGcc = (Resolve-Path -LiteralPath $HostGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$armCpp = Join-Path (Split-Path $ArmGcc) 'arm-none-eabi-g++.exe'
$hostCpp = Join-Path (Split-Path $HostGcc) 'g++.exe'
$nm = Join-Path (Split-Path $ArmGcc) 'arm-none-eabi-nm.exe'
$objdump = Join-Path (Split-Path $ArmGcc) 'arm-none-eabi-objdump.exe'
$readelf = Join-Path (Split-Path $ArmGcc) 'arm-none-eabi-readelf.exe'
foreach ($path in @($armCpp, $hostCpp, $nm, $objdump, $readelf,
        (Join-Path $CmsisCore 'core_cm33.h'), (Join-Path $CmsisCore 'core_cm55.h'))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing required proof input: $path" }
}
if (-not $BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ('fiber-inline-cpu-helpers-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $build -Force
$build = (Resolve-Path -LiteralPath $build).Path
$commands = Join-Path $build 'commands.jsonl'
Write-Output "Inline CPU helper artifacts: $build"

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments, [string]$Log)
    ConvertTo-Json -InputObject (@($Program) + $Arguments) -Compress | Add-Content -LiteralPath $commands -Encoding ASCII
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $Program @Arguments 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $saved }
    $output = $lines -join "`n"
    if ($Log) { [IO.File]::WriteAllText($Log, $output) }
    if ($code -ne 0) { throw "Proof command failed ($code): $Program`n$output" }
    return $output
}

function Assert-ExactSet {
    param([string[]]$Actual, [string[]]$Expected, [string]$Name)
    $a = @($Actual | Sort-Object -Unique)
    $e = @($Expected | Sort-Object -Unique)
    if (($a -join "`n") -cne ($e -join "`n")) {
        throw "Exact set failed: $Name`nExpected: $($e -join ', ')`nActual: $($a -join ', ')"
    }
}

$helpers = @('read_r9', 'basepri_read', 'basepri_write', 'vectors_base_addr',
    'vectors_base_ptr', 'read_vector_slot', 'read_initial_msp', 'exc_return_is_valid')
$wrappers = @($helpers | ForEach-Object { "inline_cpu_$_"; "inline_cpu_$($_)_ordinary" })

function Read-Object {
    param([string]$Object)
    $stem = Join-Path (Split-Path $Object) ([IO.Path]::GetFileNameWithoutExtension($Object))
    $undefinedText = Invoke-Checked $nm @('-u', '--format=posix', $Object) "$stem.undefined"
    $symbols = Invoke-Checked $nm @('-a', '--format=posix', $Object) "$stem.symbols"
    $sections = Invoke-Checked $readelf @('-SW', $Object) "$stem.sections"
    $disassembly = Invoke-Checked $objdump @('-dr', $Object) "$stem.dis"
    $undefined = @($undefinedText -split "`n" | Where-Object { $_.Trim() } | ForEach-Object {
        if ($_ -notmatch '^(\S+)\s+[Uuwv]\b') { throw "Unrecognized undefined symbol row: $_" }
        $Matches[1]
    })
    $functions = @([regex]::Matches($symbols, '(?m)^([^.$\s]\S*)\s+[Tt]\s') | ForEach-Object { $_.Groups[1].Value })
    $instructions = @([regex]::Matches($disassembly,
        '(?m)^\s*[0-9a-f]+:\s+(?:[0-9a-f]{4}[ \t]+){1,2}(?<op>[a-z][a-z0-9.]*)(?<args>[^\r\n]*)') |
        ForEach-Object { $_.Groups['op'].Value + $_.Groups['args'].Value })
    if (-not $instructions.Count) { throw "No decoded Thumb instructions: $Object" }
    $counters = @([regex]::Matches($symbols, '(?m)^(__gcov\S+)\s+[bBdDrR]\b') |
        ForEach-Object { $_.Groups[1].Value })
    return [pscustomobject]@{Object=$Object; Undefined=$undefined; Symbols=$symbols;
        Sections=$sections; Functions=$functions; Instructions=$instructions; Counters=$counters;
        Disassembly=([regex]::Replace($disassembly, '(?m)^.*: +file format [^\r\n]+', '')).Trim();
        Assembly=(Get-Content -LiteralPath "$stem.s" -Raw)}
}

function Assert-Clean {
    param($Artifact)
    if ($Artifact.Symbols -match '__cyg_profile|__gcov|__stack_chk|__ubsan|__sanitizer' -or
            $Artifact.Sections -match '\.gcov|\.sancov|\.ubsan|\.init_array|\.fini_array') {
        throw 'INLINE_CPU_INSTRUMENTATION_ESCAPE'
    }
    Assert-ExactSet $Artifact.Undefined @() 'normal header-only dependencies'
    Assert-ExactSet $Artifact.Counters @() 'runtime counters'
    Assert-ExactSet $Artifact.Functions $wrappers 'actual wrapper inventory'
    $writable = [regex]::Matches($Artifact.Sections, '(?m)^\s*\[\s*\d+\]\s+\S+\s+\S+\s+' +
        '[0-9a-f]+\s+[0-9a-f]+\s+(?<size>[0-9a-f]+)\s+[0-9a-f]+\s+\S*W\S*\s+')
    foreach ($section in $writable) {
        if ([Convert]::ToUInt64($section.Groups['size'].Value, 16) -ne 0) {
            throw 'INLINE_CPU_WRITABLE_STORAGE_ESCAPE'
        }
    }
    foreach ($instruction in $Artifact.Instructions) {
        if ($instruction -match '^(?:v\w*|[dw]lstp\w*|letp\w*|lctp\w*)\b' -or
                $instruction -match '\b(?:[sdq](?:[0-9]|[12][0-9]|3[01]))\b') {
            throw 'INLINE_CPU_FP_ESCAPE'
        }
    }
}

function Require-Rejection {
    param([scriptblock]$Action, [string]$Diagnostic)
    $message = $null
    try { & $Action }
    catch { $message = $_.Exception.Message }
    if ($message -cne $Diagnostic) {
        throw "Expected exact classifier diagnostic '$Diagnostic', got '$message'"
    }
}

function Assert-MutantRejected {
    param($Artifact, [string]$Helper)
    Require-Rejection { Assert-Clean $Artifact } 'INLINE_CPU_INSTRUMENTATION_ESCAPE'
    foreach ($hook in @('__cyg_profile_func_enter', '__cyg_profile_func_exit')) {
        if ($Artifact.Undefined -cnotcontains $hook) { throw "Compiled mutant lacks actual $hook dependency" }
    }
    Assert-ExactSet $Artifact.Counters @("__gcov0.fiber_port_$Helper", "__gcov_.fiber_port_$Helper") 'mutated helper counters'
    foreach ($suffix in @('', '_ordinary')) {
        $carrier = "inline_cpu_$Helper$suffix"
        $body = [regex]::Match($Artifact.Assembly, '(?ms)^' + [regex]::Escape($carrier) +
            ':.*?^\s*\.size\s+' + [regex]::Escape($carrier) + ',[^\r\n]*').Value
        if (-not $body -or $body -notmatch '\bbl\s+__cyg_profile_func_enter\b' -or
                $body -notmatch '\bbl\s+__cyg_profile_func_exit\b') {
            throw "Instrumentation must escape inside actual $carrier, not just an unused helper copy"
        }
    }
    [IO.File]::WriteAllText(($Artifact.Object + '.negative.log'),
        "INLINE_CPU_INSTRUMENTATION_ESCAPE`nHelper: $Helper`nUndefined: $($Artifact.Undefined -join ', ')`nCounters: $($Artifact.Counters -join ', ')")
}

function Remove-OneAnnotation {
    param([string]$Preprocessed, [string]$Helper)
    $marker = [regex]::Match($Preprocessed, '(?m)^(?<bundle>[^\r\n]+?) +void inline_cpu_attribute_marker\(void\);')
    if (-not $marker.Success) { throw 'Missing actual expanded inline-sensitive attribute marker' }
    $bundle = [regex]::Escape($marker.Groups['bundle'].Value)
    $pattern = '(?m)^' + $bundle + '(?<tail>[ \t]+__attribute__\(\(target\("general-regs-only"\)\)\)' +
        '[\r\n \t]+[^\r\n{};]*\bfiber_port_' + [regex]::Escape($Helper) + '\()'
    if ([regex]::Matches($Preprocessed, $pattern).Count -ne 1) {
        throw "Expected one actual sensitive annotation on fiber_port_$Helper"
    }
    return [regex]::Replace($Preprocessed, $pattern, '${tail}')
}

$profiles = @(
    @{Name='ARM_CM33_MPU'; Manifest='CM33_MPU'; Core=33; Fp=0; Arch=@('-mcpu=cortex-m33'); Abi=@('soft')},
    @{Name='ARM_CM55_MPU'; Manifest='CM55_MPU'; Core=55; Fp=0; Arch=@('-mcpu=cortex-m55'); Abi=@('soft')},
    @{Name='ARM_CM33F_MPU'; Manifest='CM33F_MPU'; Core=33; Fp=1; Arch=@('-mcpu=cortex-m33','-mfpu=fpv5-sp-d16'); Abi=@('hard','softfp')},
    @{Name='ARM_CM55F_MPU'; Manifest='CM55F_MPU'; Core=55; Fp=1; Arch=@('-march=armv8.1-m.main+fp'); Abi=@('hard','softfp')},
    @{Name='ARM_CM55_MVEF_MPU'; Manifest='CM55_MVEF_MPU'; Core=55; Fp=1; Arch=@('-march=armv8.1-m.main+mve.fp'); Abi=@('hard','softfp')}
)
$traitsPath = Join-Path $repo 'fiber/port/fiber_port_traits.h'
$traits = Get-Content -LiteralPath $traitsPath -Raw
if ($traits -notmatch '#include "../fiber_api_attributes.h"') { throw 'Traits must directly include CPU-neutral API attributes' }
$traitNames = @([regex]::Matches($traits, '(?m)^#ifndef (FIBER_PORT_\w+)\s*$') | ForEach-Object { $_.Groups[1].Value })
$traitNames += @('FIBER_PORT_MASK_PRIMASK', 'FIBER_PORT_MASK_BASEPRI', 'FIBER_PORT_SCHEDULER_BASEPRI')
$traitNames = @($traitNames | Where-Object { $_ -ne 'FIBER_PORT_FIBER_PORT_TRAITS_H_' } | Sort-Object -Unique)
foreach ($profile in $profiles) {
    $header = Get-Content -LiteralPath (Join-Path $repo "fiber/port/$($profile.Name)/non_secure/fiber_portmacro.h") -Raw
    foreach ($helper in $helpers) {
        $text = if ($helper -eq 'exc_return_is_valid') { $traits } else { $header }
        $pattern = '(?m)^FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY\r?\n' +
            '[^\r\n]*\bfiber_port_' + $helper + '\('
        if ([regex]::Matches($text, $pattern).Count -ne 1) {
            throw "$($profile.Name)/${helper}: awaiting canonical inline-sensitive/general-register annotations"
        }
    }
}

$inputHashes = @{}
function Record-Input {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not $inputHashes.ContainsKey($resolved)) { $inputHashes[$resolved] = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash }
}
Record-Input $PSCommandPath
foreach ($file in Get-ChildItem -LiteralPath $fixtures -File) { Record-Input $file.FullName }
# Hash selected source headers before any compile; dependency files below also
# capture the precise CMSIS/toolchain closure used by each actual translation.
foreach ($directory in @((Join-Path $repo 'fiber'), (Join-Path $repo 'fiber/port'), $CmsisCore) +
        @($profiles | ForEach-Object { Join-Path $repo "fiber/port/$($_.Name)/non_secure" })) {
    foreach ($file in Get-ChildItem -LiteralPath $directory -File -Filter *.h) { Record-Input $file.FullName }
}
$null = Invoke-Checked $ArmGcc @('--version') (Join-Path $build 'arm-compiler.txt')
$null = Invoke-Checked $HostGcc @('--version') (Join-Path $build 'host-compiler.txt')
$common = @('-mthumb', '-ffreestanding', '-fno-builtin', '-fno-common', '-fstrict-aliasing',
    '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror', '-Wundef',
    '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_SCHEDULER_BASEPRI=0x20', '-DFIBER_FPU_LAZY=1',
    "-I$repo", "-I$repo/fiber", "-I$repo/fiber/port", "-I$CmsisCore", "-I$fixtures")
$hostile = @('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs', '-ftest-coverage',
    '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
$runs = @()
$mutants = 0
$hostRuns = 0
$classifierChecks = 0

foreach ($profile in $profiles) {
    $port = Join-Path $repo "fiber/port/$($profile.Name)/non_secure"
    $archMacro = if ($profile.Core -eq 55) { '-DFIBER_PORT_ARMV81M_MAINLINE=1' } else { '-DFIBER_PORT_ARMV8M_MAINLINE=1' }
    foreach ($regions in @(8,16)) {
        $profileFlags = $common + $profile.Arch + @($archMacro, "-I$port",
            "-DINLINE_CPU_CORE=$($profile.Core)", "-DINLINE_CPU_FP=$($profile.Fp)",
            "-DFIBER_PORT_$($profile.Manifest)_TOTAL_REGIONS=$regions")
        foreach ($abi in $profile.Abi) {
            foreach ($opt in @('O2','Os')) {
                $name = "$($profile.Name)-r$regions-$abi-$opt"
                $dir = Join-Path $build $name
                $null = New-Item -ItemType Directory -Path $dir
                $flags = $profileFlags + @("-mfloat-abi=$abi", "-$opt")
                $normalObject = Join-Path $dir 'normal.o'
                $null = Invoke-Checked $ArmGcc ($flags + @('-std=gnu11', '-MD', '-MF', (Join-Path $dir 'normal.d'),
                    '-save-temps=obj', '-c', (Join-Path $fixtures 'probe.c'), '-o', $normalObject)) (Join-Path $dir 'normal.compile.log')
                $dependencies = (Get-Content -LiteralPath (Join-Path $dir 'normal.d') -Raw) -replace '\\\r?\n', ''
                $dependencies = $dependencies -replace '^[^\r\n]*?\.o:\s*', ''
                foreach ($dependency in [regex]::Split($dependencies.Trim(), '(?<!\\)\s+')) {
                    Record-Input ($dependency -replace '\\ ', ' ')
                }
                $normal = Read-Object $normalObject
                Assert-Clean $normal
                $positiveObject = Join-Path $dir 'hostile.o'
                $null = Invoke-Checked $ArmGcc ($flags + $hostile + @('-std=gnu11', '-save-temps=obj', '-c',
                    (Join-Path $fixtures 'probe.c'), '-o', $positiveObject)) (Join-Path $dir 'hostile.compile.log')
                $positive = Read-Object $positiveObject
                Assert-Clean $positive
                Assert-ExactSet $positive.Undefined $normal.Undefined 'ordinary versus hostile dependency parity'
                if ($normal.Disassembly -cne $positive.Disassembly) { throw "Hostile flags changed actual wrapper bytes: $name" }
                $cppObject = Join-Path $dir 'cpp.o'
                $null = Invoke-Checked $armCpp ($flags + $hostile + @('-x', 'c++', '-std=gnu++11', '-save-temps=obj', '-c',
                    (Join-Path $fixtures 'probe.c'), '-o', $cppObject)) (Join-Path $dir 'cpp.compile.log')
                $cpp = Read-Object $cppObject
                Assert-Clean $cpp
                if ($normal.Disassembly -cne $cpp.Disassembly) { throw "C++ changed actual wrapper bytes or target compatibility: $name" }

                if (-not $classifierChecks) {
                    # Synthetic classifier controls complement compiled mutants. Exact
                    # exceptions prevent unrelated parser failures counting as kills.
                    $counterexample = $positive.PSObject.Copy()
                    $counterexample.Symbols += "`n__gcov0.counterexample b 0 8"
                    Require-Rejection { Assert-Clean $counterexample } 'INLINE_CPU_INSTRUMENTATION_ESCAPE'
                    $counterexample = $positive.PSObject.Copy()
                    $counterexample.Instructions += 'vadd.f32 s0, s0, s1'
                    Require-Rejection { Assert-Clean $counterexample } 'INLINE_CPU_FP_ESCAPE'
                    $counterexample = $positive.PSObject.Copy()
                    $counterexample.Undefined += 'unexpected_external_dependency'
                    Require-Rejection { Assert-Clean $counterexample } "Exact set failed: normal header-only dependencies`nExpected: `nActual: unexpected_external_dependency"
                    $counterexample = $positive.PSObject.Copy()
                    $counterexample.Sections += "`n  [99] .data.anonymous PROGBITS 00000000 000034 000004 00 WA 0 0 4"
                    Require-Rejection { Assert-Clean $counterexample } 'INLINE_CPU_WRITABLE_STORAGE_ESCAPE'
                    $classifierChecks = 4
                }

                $preprocessed = Get-Content -LiteralPath (Join-Path $dir 'hostile.i') -Raw
                foreach ($helper in $helpers) {
                    $mutantInput = Join-Path $dir "mutant-$helper.i"
                    [IO.File]::WriteAllText($mutantInput, (Remove-OneAnnotation $preprocessed $helper))
                    $mutantObject = Join-Path $dir "mutant-$helper.o"
                    $null = Invoke-Checked $ArmGcc ($flags + $hostile + @('-std=gnu11', '-save-temps=obj', '-c',
                        $mutantInput, '-o', $mutantObject)) (Join-Path $dir "mutant-$helper.compile.log")
                    Assert-MutantRejected (Read-Object $mutantObject) $helper
                    ++$mutants
                }
                $runs += [pscustomobject]@{Profile=$profile.Name; Regions=$regions; Abi=$abi; Optimization=$opt; Mutants=8}
                Write-Output "PASS $name actual C/C++ headers, exact dependencies/bytes, eight compiled mutants rejected"

                if ($abi -eq $profile.Abi[0] -and $opt -eq 'O2') {
                    $export = '#include "fiber_portmacro.h"' + "`n" + (($traitNames | ForEach-Object {
                        "INLINE_CPU_TRAIT(`"$_`", $_)"
                    }) -join "`n") + "`n"
                    $exportPath = Join-Path $dir 'traits-export.c'
                    [IO.File]::WriteAllText($exportPath, $export)
                    $expanded = Invoke-Checked $ArmGcc ($flags + @('-E', '-P', $exportPath)) (Join-Path $dir 'traits-export.txt')
                    $exports = @([regex]::Matches($expanded, '(?m)^INLINE_CPU_TRAIT\("(?<name>FIBER_PORT_\w+)", (?<value>[^\r\n]+)\)\s*$'))
                    Assert-ExactSet @($exports | ForEach-Object { $_.Groups['name'].Value }) $traitNames 'actual expanded traits'
                    [IO.File]::WriteAllText((Join-Path $dir 'actual_traits.h'), (($exports | ForEach-Object {
                        '#define ' + $_.Groups['name'].Value + ' ' + $_.Groups['value'].Value
                    }) -join "`n") + "`n")
                    foreach ($hostOpt in @('O2','Os')) {
                        foreach ($language in @('c','c++')) {
                            $program = if ($language -eq 'c') { $HostGcc } else { $hostCpp }
                            $standard = if ($language -eq 'c') { '-std=gnu11' } else { '-std=gnu++11' }
                            $exe = Join-Path $dir "traits-$hostOpt-$language.exe"
                            $null = Invoke-Checked $program @('-x', $language, $standard, "-$hostOpt", '-Wall', '-Wextra', '-Werror',
                                "-DINLINE_CPU_FP=$($profile.Fp)", "-I$dir", "-I$repo/fiber/port",
                                (Join-Path $fixtures 'traits_host.c'), '-o', $exe) "$exe.compile.log"
                            $result = Invoke-Checked $exe @() "$exe.run.log"
                            if ($result -cne 'PASS traits host: 131104 cases') { throw "Unexpected traits host result: $result" }
                            ++$hostRuns
                        }
                    }
                }
            }
        }
    }
}

$sources = @($inputHashes.Keys | Sort-Object | ForEach-Object {
    if ((Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash -cne $inputHashes[$_]) { throw "Proof input changed during run: $_" }
    [pscustomobject]@{Path=$_; Sha256=$inputHashes[$_]}
})
$sources | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $build 'sources.json') -Encoding ASCII
[pscustomobject]@{Configurations=$runs; CompiledMutants=$mutants; HostExecutions=$hostRuns; ClassifierControls=$classifierChecks;
    OtherPorts='coverage pending'; Scope='actual inline CPU helpers only; no exception/hardware execution claim'} |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $build 'results.json') -Encoding ASCII
if ($runs.Count -ne 32 -or $mutants -ne 256 -or $hostRuns -ne 40 -or $classifierChecks -ne 4) {
    throw 'Focused proof grid incomplete'
}
Write-Output "PASS inline CPU helpers: 32 configurations, 96 C/C++ objects, 256 compiled annotation-removal mutants, 40 host executions; other ports coverage pending"
