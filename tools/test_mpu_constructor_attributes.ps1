param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixtures = Join-Path $PSScriptRoot 'fixtures/mpu_constructor_attributes'
if (-not $ArmGcc) {
    $found = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $ArmGcc = $found.Source }
    else {
        $found = Get-ChildItem C:/ST -Recurse -Filter arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $ArmGcc = $found.FullName }
    }
}
if (-not $CmsisCore) { $CmsisCore = Join-Path $repo '../../../Drivers/CMSIS/Include' }
if (-not $ArmGcc -or -not (Test-Path -LiteralPath $ArmGcc)) { throw 'Set -ArmGcc to an existing ARM GCC' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin 'arm-none-eabi-nm.exe'
$objdump = Join-Path $bin 'arm-none-eabi-objdump.exe'
$objcopy = Join-Path $bin 'arm-none-eabi-objcopy.exe'
foreach ($path in @($nm, $objdump, $objcopy, (Join-Path $CmsisCore 'core_cm33.h'),
        (Join-Path $CmsisCore 'core_cm55.h'), (Join-Path $fixtures 'main.h'), (Join-Path $fixtures 'probe.c'),
        (Join-Path $fixtures 'README.md'), (Join-Path $repo 'context/context_api_types.h'))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing proof input: $path" }
}
if (-not $BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ('mpu-constructor-attributes-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $build -Force
$commands = Join-Path $build 'commands.jsonl'
Write-Output "MPU constructor attribute artifacts: $build"

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
    if ($Log) { Set-Content -LiteralPath $Log -Value $output -Encoding ASCII }
    if ($code -ne 0) { throw "Proof command failed ($code): $Program`n$output" }
    return $output
}

function Assert-ExactSet {
    param([string[]]$Actual, [string[]]$Expected, [string]$Name)
    $a = @($Actual | Sort-Object -Unique)
    $e = @($Expected | Sort-Object -Unique)
    if (($a -join "`n") -ne ($e -join "`n")) {
        throw "Exact symbol contract failed: $Name`nExpected: $($e -join ', ')`nActual: $($a -join ', ')"
    }
}

function Read-Object {
    param([string]$Object)
    $stem = Join-Path ([IO.Path]::GetDirectoryName($Object)) ([IO.Path]::GetFileNameWithoutExtension($Object))
    $undefinedText = Invoke-Checked $nm @('-u', '--format=posix', $Object) "$stem.undefined"
    $symbols = Invoke-Checked $nm @('-a', '--format=posix', $Object) "$stem.symbols"
    $disassembly = Invoke-Checked $objdump @('-dr', $Object) "$stem.dis"
    $undefined = @($undefinedText -split "`n" | Where-Object { $_.Trim() } | ForEach-Object {
        if ($_ -notmatch '^(\S+)\s+[Uuwv]\b') { throw "Unrecognized nm undefined row: $_" }
        $Matches[1]
    })
    $counters = @([regex]::Matches($symbols, '(?m)^(?<name>__gcov\S+)\s+[bBdDrR]\b') |
        ForEach-Object { $_.Groups['name'].Value } | Sort-Object -Unique)
    return [pscustomobject]@{Object=$Object; Undefined=$undefined; Symbols=$symbols; Counters=$counters;
        Disassembly=([regex]::Replace($disassembly, '(?m)^.*: +file format [^\r\n]+', '')).Trim();
        Assembly=(Get-Content -LiteralPath "$stem.s" -Raw)}
}

function Assert-Clean {
    param($Artifact, [string[]]$Expected)
    if ($Artifact.Symbols -match '__cyg_profile|__gcov|__stack_chk|__ubsan|__sanitizer') {
        throw "ATTRIBUTE_INSTRUMENTATION_ESCAPE: $($Artifact.Object)"
    }
    Assert-ExactSet $Artifact.Undefined $Expected $Artifact.Object
    Assert-ExactSet $Artifact.Counters @() "$($Artifact.Object) counters"
}

function Assert-R9Semantics {
    param($Artifact)
    foreach ($name in @('fiber_attributes_read_r9', 'fiber_attributes_read_r9_ordinary')) {
        $binary = $Artifact.Object + '.' + $name + '.bin'
        $null = Invoke-Checked $objcopy @('-O', 'binary', '-j', ".text.$name", $Artifact.Object, $binary)
        # Independent Thumb oracle: MOV r0,r9; BX lr. No call, stack operation,
        # altered return register, or FP ABI dependency may be hidden here.
        $bytes = [BitConverter]::ToString([IO.File]::ReadAllBytes($binary))
        if ($bytes -ne '48-46-70-47') { throw "Changed r9 leaf semantics in $name`: $bytes" }
    }
}

function Assert-MutantRejected {
    param($Artifact, [string[]]$Expected, [string]$Carrier)
    $escaped = $false
    try { Assert-Clean $Artifact $Expected }
    catch {
        if ($_.Exception.Message -notlike 'ATTRIBUTE_INSTRUMENTATION_ESCAPE:*') { throw }
        $escaped = $true
    }
    if (-not $escaped) { throw "Annotation-removal mutant was accepted: $($Artifact.Object)" }
    $extra = @('__cyg_profile_func_enter', '__cyg_profile_func_exit', '__gcov_exit', '__gcov_init',
        '__gcov_merge_add', '__stack_chk_fail', '__stack_chk_guard', '__sanitizer_cov_trace_pc')
    Assert-ExactSet $Artifact.Undefined ($Expected + $extra) "$($Artifact.Object) escaped dependencies"
    Assert-ExactSet $Artifact.Counters @('__gcov0.fiber_port_read_r9', '__gcov_.fiber_port_read_r9') "$($Artifact.Object) escaped counters"
    $body = [regex]::Match($Artifact.Assembly, '(?ms)^' + [regex]::Escape($Carrier) +
        ':.*?^\s*\.size\s+' + [regex]::Escape($Carrier) + ',[^\r\n]*').Value
    if (-not $body -or $body -notmatch '\bbl\s+__cyg_profile_func_enter\b' -or
            $body -notmatch '\bbl\s+__cyg_profile_func_exit\b') {
        throw "Mutant must escape inside actual $Carrier, not only an unused helper copy"
    }
    Set-Content -LiteralPath ($Artifact.Object + '.negative.log') -Encoding ASCII -Value `
        ("ATTRIBUTE_INSTRUMENTATION_ESCAPE: compiled mutant rejected in $Carrier`n" +
         "Undefined: $($Artifact.Undefined -join ', ')`nCounters: $($Artifact.Counters -join ', ')")
}

$profiles = @(
    @{Name='ARM_CM33_MPU'; Manifest='CM33_MPU'; Core=33; Fp=0; Arch=@('-mcpu=cortex-m33'); Abi=@('soft'); Units=@('fiber_port.c')},
    @{Name='ARM_CM55_MPU'; Manifest='CM55_MPU'; Core=55; Fp=0; Arch=@('-mcpu=cortex-m55'); Abi=@('soft'); Units=@('fiber_port.c')},
    @{Name='ARM_CM55F_MPU'; Manifest='CM55F_MPU'; Core=55; Fp=1; Arch=@('-march=armv8.1-m.main+fp'); Abi=@('hard','softfp'); Units=@('fiber_port_svc.c','fiber_port_pendsv.c')},
    @{Name='ARM_CM55_MVEF_MPU'; Manifest='CM55_MVEF_MPU'; Core=55; Fp=1; Arch=@('-march=armv8.1-m.main+mve.fp'); Abi=@('hard','softfp'); Units=@('fiber_port_svc.c','fiber_port_pendsv.c')}
)
$helpers = @('read_r9', 'basepri_read', 'basepri_write', 'vectors_base_addr', 'vectors_base_ptr', 'read_vector_slot', 'read_initial_msp')
$headers = @(Get-ChildItem -LiteralPath $repo -File -Filter *.h | Select-Object -ExpandProperty FullName)
$headers += @(Get-ChildItem -LiteralPath (Join-Path $repo 'context') -File -Filter *.h | Select-Object -ExpandProperty FullName)
$headers += @(Get-ChildItem -LiteralPath (Join-Path $repo 'fiber') -File -Filter *.h | Select-Object -ExpandProperty FullName)
$headers += @(Get-ChildItem -LiteralPath (Join-Path $repo 'fiber/port') -File -Filter *.h | Select-Object -ExpandProperty FullName)
foreach ($profile in $profiles) {
    $port = Join-Path $repo "fiber/port/$($profile.Name)/non_secure"
    $headers += @(Get-ChildItem -LiteralPath $port -File -Filter *.h | Select-Object -ExpandProperty FullName)
}
$sources = @($profiles | ForEach-Object {
    $profile = $_
    foreach ($unit in (@('fiber_port_boot.c') + $profile.Units)) {
        $path = Join-Path $repo "fiber/port/$($profile.Name)/non_secure/$unit"
        if (-not (Test-Path -LiteralPath $path)) { throw "Missing required constructor/caller source: $path" }
        $path
    }
})
$cmsisHeaders = @(Get-ChildItem -LiteralPath $CmsisCore -File -Filter *.h | Select-Object -ExpandProperty FullName)
$inputs = @($headers + $PSCommandPath + (Join-Path $fixtures 'main.h') + (Join-Path $fixtures 'probe.c') + (Join-Path $fixtures 'README.md') +
    $sources + $cmsisHeaders | Sort-Object -Unique)
$hashes = @($inputs | ForEach-Object { [pscustomobject]@{Path=$_; Sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash} })
$hashes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $build 'sources.json') -Encoding ASCII
$null = Invoke-Checked $ArmGcc @('--version') (Join-Path $build 'compiler-version.txt')

# A private header/source snapshot preserves relative includes. Only the actual
# read_r9 annotation is removed; no implementation, mask, or test oracle changes.
$shadow = Join-Path $build 'annotation-removal'
foreach ($inputPath in $headers) {
    $destination = Join-Path $shadow $inputPath.Substring($repo.Length + 1)
    $null = New-Item -ItemType Directory -Path (Split-Path $destination) -Force
    Copy-Item -LiteralPath $inputPath -Destination $destination
}

# A missing copied canonical header must be a distinct input failure, never an
# accepted annotation mutant or an implicit fallback to the live source tree.
$canonicalProbe = Join-Path $build 'canonical-input.c'
Set-Content -LiteralPath $canonicalProbe -Encoding ASCII -Value '#include "fiber/fiber_api_types.h"'
$canonicalFlags = @('-mcpu=cortex-m33', '-mthumb', '-std=gnu11', '-ffreestanding', '-E', '-P')
$null = Invoke-Checked $ArmGcc ($canonicalFlags + @("-I$shadow", $canonicalProbe)) (Join-Path $build 'canonical-input-positive.i')
$missingRoot = Join-Path $build 'missing-canonical-input'
$null = New-Item -ItemType Directory -Path (Join-Path $missingRoot 'fiber') -Force
Copy-Item -LiteralPath (Join-Path $shadow 'fiber/fiber_api_types.h') -Destination (Join-Path $missingRoot 'fiber/fiber_api_types.h')
$missingLog = Join-Path $build 'missing-canonical-input.log'
$missingRejected = $false
try {
    $null = Invoke-Checked $ArmGcc ($canonicalFlags + @("-I$missingRoot", $canonicalProbe)) $missingLog
} catch {
    $diagnostic = Get-Content -LiteralPath $missingLog -Raw
    $expected = '(?m)fatal error: \.\.[\\/]context[\\/]context_api_types\.h: No such file or directory'
    if ($_.Exception.Message -notlike 'Proof command failed (1):*' -or
            [regex]::Matches($diagnostic, $expected).Count -ne 1) { throw }
    $missingRejected = $true
}
if (-not $missingRejected) { throw 'Missing canonical header was accepted or resolved outside the explicit snapshot' }
[pscustomobject]@{ Status='PASS'; Positive='canonical-input-positive.i';
    MissingCanonicalInputRejected=$true; Diagnostic='missing-canonical-input.log';
    OmittedPath='context/context_api_types.h'; AnnotationMutant=$false } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $build 'canonical-input-control.json') -Encoding ASCII

foreach ($profile in $profiles) {
    $relative = "fiber/port/$($profile.Name)/non_secure"
    $port = Join-Path $repo $relative
    $mutantPort = Join-Path $shadow $relative
    Copy-Item -LiteralPath (Join-Path $port 'fiber_port_boot.c') -Destination $mutantPort
    $dictionary = Get-Content -LiteralPath (Join-Path $port 'fiber_portmacro.h') -Raw
    foreach ($helper in $helpers) {
        $pattern = '(?m)^FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY\r?\n' +
            'fiber_portFORCE_INLINE[^\r\n]*\bfiber_port_' + $helper + '\('
        if ([regex]::Matches($dictionary, $pattern).Count -ne 1) { throw "$($profile.Name)/$helper requires canonical inline protections" }
    }
    $annotation = '(?m)^FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY\r?\n' +
        '(?=fiber_portFORCE_INLINE uint32_t fiber_port_read_r9\(void\))'
    $mutant = [regex]::Replace($dictionary, $annotation, '')
    if ($mutant -eq $dictionary) { throw "No annotation removed for $($profile.Name)" }
    [IO.File]::WriteAllText((Join-Path $mutantPort 'fiber_portmacro.h'), $mutant)
}

$common = @('-mthumb', '-std=gnu11', '-ffreestanding', '-fno-builtin', '-fno-common',
    '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror', '-Wundef',
    '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_SCHEDULER_BASEPRI=0x20', '-DFIBER_FPU_LAZY=1')
$hostile = @('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs', '-ftest-coverage',
    '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
$linkerSymbols = @('privileged_flash', 'unprivileged_flash', 'unprivileged_syscalls', 'privileged_sram',
    'current_context_slot', 'unprivileged_ram') | ForEach-Object { "__fiber_mpu_$($_)_start__"; "__fiber_mpu_$($_)_end__" }
$runs = @()
$callerCompiles = 0
foreach ($profile in $profiles) {
    $relative = "fiber/port/$($profile.Name)/non_secure"
    foreach ($regions in @(8,16)) {
        foreach ($abi in $profile.Abi) {
            foreach ($optimization in @('-O2','-Os')) {
                $name = "$($profile.Name)-r$regions-$abi-$($optimization.Substring(1))"
                $dir = Join-Path $build $name
                $null = New-Item -ItemType Directory -Path $dir
                $arch = if ($profile.Core -eq 33) { '-DFIBER_PORT_ARMV8M_MAINLINE=1' } else { '-DFIBER_PORT_ARMV81M_MAINLINE=1' }
                $flags = $common + $profile.Arch + @($optimization, "-mfloat-abi=$abi", $arch,
                    "-DATTRIBUTES_CORE=$($profile.Core)", "-DATTRIBUTES_FP=$($profile.Fp)",
                    "-DFIBER_PORT_$($profile.Manifest)_TOTAL_REGIONS=$regions")
                $normalPort = Join-Path $repo $relative
                $normalIncludes = @("-I$fixtures", "-I$normalPort", "-I$repo", "-I$repo/fiber", "-I$repo/fiber/port", "-I$CmsisCore")
                $preprocessed = Invoke-Checked $ArmGcc ($flags + $normalIncludes + @('-E','-P',(Join-Path $fixtures 'probe.c'))) (Join-Path $dir 'expected.i')
                $cohort = [regex]::Match($preprocessed, 'fiber_attributes_expected_cohort\[\]\s*=\s*"(?<name>fiber_port_context_cohort_\w+)"\s*;')
                if (-not $cohort.Success) { throw "Cannot derive exact selected-cohort dependency: $name" }
                $expected = @($linkerSymbols + 'fiber_panic' + 'fiber_port_unprivileged_task_return' +
                    'fiber_internal_runtime_port_abi_v1_anchor' + $cohort.Groups['name'].Value)
                $artifacts = @{}
                foreach ($variant in @('normal', 'normal-mutant', 'hostile', 'hostile-mutant')) {
                    $root = if ($variant.EndsWith('mutant')) { $shadow } else { $repo }
                    $port = Join-Path $root $relative
                    $includes = @("-I$fixtures", "-I$port", "-I$root", "-I$root/fiber", "-I$root/fiber/port", "-I$CmsisCore")
                    $compile = $flags + $includes
                    if ($variant.StartsWith('hostile')) { $compile += $hostile }
                    foreach ($unit in @('boot','probe')) {
                        $source = if ($unit -eq 'boot') { Join-Path $port 'fiber_port_boot.c' } else { Join-Path $fixtures 'probe.c' }
                        $object = Join-Path $dir "$variant-$unit.o"
                        # Compile failure is always fatal, including mutants.
                        $null = Invoke-Checked $ArmGcc ($compile + @('-save-temps=obj','-MMD','-c',$source,'-o',$object)) "$object.compile.log"
                        $artifact = Read-Object $object
                        $dependencies = if ($unit -eq 'boot') { $expected } else { @() }
                        if ($variant -eq 'hostile-mutant') {
                            $carrier = if ($unit -eq 'boot') { 'fiber_port_context_init' } else { 'fiber_attributes_read_r9' }
                            Assert-MutantRejected $artifact $dependencies $carrier
                        } else {
                            Assert-Clean $artifact $dependencies
                            if ($unit -eq 'probe') { Assert-R9Semantics $artifact }
                        }
                        $artifacts["$variant-$unit"] = $artifact
                    }
                }
                foreach ($unit in @('boot','probe')) {
                    if ($artifacts["normal-$unit"].Disassembly -ne $artifacts["normal-mutant-$unit"].Disassembly) {
                        throw "Annotations changed normal $unit instructions/relocations: $name"
                    }
                }
                # Compile the real selected-port consumers, without asserting
                # unrelated runtime/CMSIS hostile-instrumentation closure.
                foreach ($unit in $profile.Units) {
                    $source = Join-Path $normalPort $unit
                    $object = Join-Path $dir ($unit + '.caller.o')
                    $null = Invoke-Checked $ArmGcc ($flags + $normalIncludes + @('-c',$source,'-o',$object)) "$object.compile.log"
                    ++$callerCompiles
                }
                $runs += [pscustomobject]@{Name=$name; ExpectedUndefined=$expected; ProbeUndefined=@();
                    NormalUndefined=$artifacts['normal-boot'].Undefined; HostileUndefined=$artifacts['hostile-boot'].Undefined;
                    NormalCounters=$artifacts['normal-boot'].Counters; HostileCounters=$artifacts['hostile-boot'].Counters;
                    MutantUndefined=$artifacts['hostile-mutant-boot'].Undefined; MutantCounters=$artifacts['hostile-mutant-boot'].Counters;
                    NormalDisassemblyUnchanged=$true; LeafBytes='48-46-70-47'; CompiledMutantsRejected=2}
                Write-Output "PASS $name`: exact normal/hostile deps, unchanged normal code, two compiled annotation mutants rejected"
            }
        }
    }
}
$runs | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $build 'results.json') -Encoding ASCII
foreach ($inputHash in $hashes) {
    if ((Get-FileHash -LiteralPath $inputHash.Path -Algorithm SHA256).Hash -ne $inputHash.Sha256) {
        throw "Proof input changed during execution: $($inputHash.Path); rerun after sources stabilize"
    }
}
Write-Output "PASS MPU constructor attributes: $($runs.Count) configurations, $($runs.Count * 2) compiled hostile mutants rejected, $callerCompiles real caller compiles. Artifacts: $build"
