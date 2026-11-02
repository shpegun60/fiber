param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$BuildRoot,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture = Join-Path $PSScriptRoot 'fixtures\cm33f_secure_reference'
if (!$ArmGcc) {
    $found = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($found) {$ArmGcc = $found.Source}
    else {
        $found = Get-ChildItem C:\ST -Recurse -File -Filter arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {$ArmGcc = $found.FullName}
    }
}
if (!$ArmGcc) {throw 'Supply an existing -ArmGcc; no tool installation is supported'}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
if (!$FreeRtosRoot) {$FreeRtosRoot = Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel'}
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
$reference = Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM33'
$ns = Join-Path $reference 'non_secure'
$secure = Join-Path $reference 'secure'
$pin = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin 'arm-none-eabi-nm.exe'
$readelf = Join-Path $bin 'arm-none-eabi-readelf.exe'
$objdump = Join-Path $bin 'arm-none-eabi-objdump.exe'
foreach ($path in @($ArmGcc, $nm, $readelf, $objdump, (Join-Path $fixture 'check.py'),
        (Join-Path $ns 'port.c'), (Join-Path $ns 'portasm.c'), (Join-Path $secure 'secure_context.c'),
        (Join-Path $secure 'secure_context_port.c'), (Join-Path $secure 'secure_init.c'), (Join-Path $secure 'secure_heap.c'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {throw "Missing reference-proof input: $path"}
}
if (!$BuildRoot) {$BuildRoot = [IO.Path]::GetTempPath()}
$build = Join-Path $BuildRoot ('cm33f-secure-reference-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $build -Force
$commands = Join-Path $build 'commands.jsonl'
$checks = New-Object System.Collections.Generic.List[object]
$runs = New-Object System.Collections.Generic.List[object]
$controls = New-Object System.Collections.Generic.List[object]
Write-Host "C33F Secure reference evidence: $build"

function Json([string]$Path, [object]$Value) {
    ConvertTo-Json -Depth 10 -InputObject $Value | Set-Content -LiteralPath $Path -Encoding ASCII
}
function Recorded([string]$Program, [string[]]$Arguments, [string]$Log, [switch]$AllowFailure) {
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $Program @Arguments 2>&1 | ForEach-Object {"$_"})
        $code = $LASTEXITCODE
    } finally {$ErrorActionPreference = $old}
    $output = $lines -join "`n"
    if ($Log) {$output | Set-Content -LiteralPath $Log -Encoding ASCII}
    @{Program=$Program; Arguments=$Arguments; ExitCode=$code; Log=$Log; Output=$output} |
        ConvertTo-Json -Depth 5 -Compress | Add-Content -LiteralPath $commands -Encoding ASCII
    if ($code -ne 0 -and !$AllowFailure) {throw "Reference command failed ($code): $Log`n$output"}
    [pscustomobject]@{ExitCode=$code; Output=$output}
}
function Check([string]$Name, [bool]$Passed, [object]$Evidence) {
    $checks.Add([pscustomobject]@{Name=$Name; Passed=$Passed; Evidence=[string]$Evidence})
    if (!$Passed) {throw "Reference check failed: $Name"}
}
function Compile([string]$Source, [string]$Object, [string[]]$Flags, [switch]$FixtureSource) {
    $extra = if ($FixtureSource) {@('-Wall','-Wextra','-Werror','-Wundef')} else {@('-Wall','-Wextra')}
    $null = Recorded $ArmGcc ($Flags + $extra + @('-save-temps=obj','-MD','-fstack-usage','-c',$Source,'-o',$Object)) ($Object + '.compile.log')
    $null = Recorded $objdump @('-drwC',$Object) ($Object + '.dis')
    $null = Recorded $readelf @('-hA','-SW','-sW','-rW',$Object) ($Object + '.readelf')
    $null = Recorded $nm @('-u',$Object) ($Object + '.undefined')
}
function ElfEvidence([string]$Elf) {
    $null = Recorded $objdump @('-dwC',$Elf) ($Elf + '.dis')
    $null = Recorded $readelf @('-hA','-SW','-sW',$Elf) ($Elf + '.readelf')
    $undefined = Recorded $nm @('-u',$Elf) ($Elf + '.undefined')
    Check ($Elf + '/no-undefined') ([string]::IsNullOrWhiteSpace($undefined.Output)) $undefined.Output
}
function RetainedBodies([string]$Elf, [string[]]$Objects) {
    $final = Get-Content -LiteralPath ($Elf + '.readelf') -Raw
    $map = Get-Content -LiteralPath ($Elf + '.map') -Raw
    $count = 0
    $seen = @{}
    foreach ($object in $Objects) {
        $objectText = Get-Content -LiteralPath ($object + '.readelf') -Raw
        $functions = [regex]::Matches($objectText, '(?m)^\s*\d+:\s+[0-9a-f]+\s+([0-9]+)\s+FUNC\s+\w+\s+DEFAULT\s+\d+\s+(\S+)\s*$')
        foreach ($function in $functions) {
            if ([int]$function.Groups[1].Value -eq 0) {continue}
            $name = $function.Groups[2].Value
            # CMSE's public spelling becomes the SG veneer; the compiler's
            # zero-sized __acle_se alias names its original body start. Prove
            # that entire input section's actual retained span in the map.
            if (!$name.StartsWith('__acle_se_') -and $objectText -match ('(?m)\b__acle_se_' + [regex]::Escape($name) + '\s*$')) {
                $section = [regex]::Matches($map, '(?m)^\s*\.text\.' + [regex]::Escape($name) +
                    '\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+' + [regex]::Escape($object) + '\s*$')
                $alias = [regex]::Matches($final, '(?m)^\s*\d+:\s+([0-9a-f]+)\s+0\s+FUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+__acle_se_' +
                    [regex]::Escape($name) + '\s*$')
                $inputSection = [regex]::Matches($objectText, '(?m)^\s*\[\s*\d+\]\s+\.text\.' + [regex]::Escape($name) +
                    '\s+PROGBITS\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)\s+\d+\s+AX\s+\d+\s+\d+\s+\d+\s*$')
                $complete = $section.Count -eq 1 -and $alias.Count -eq 1 -and $inputSection.Count -eq 1
                if ($complete) {
                    $inputSize = [Convert]::ToUInt32($inputSection[0].Groups[1].Value,16)
                    $complete = [Convert]::ToUInt32($section[0].Groups[2].Value.Substring(2),16) -eq $inputSize -and
                        $inputSize -ge [uint32]$function.Groups[1].Value -and
                        [Convert]::ToUInt32($section[0].Groups[1].Value.Substring(2),16) -eq
                        ([Convert]::ToUInt32($alias[0].Groups[1].Value,16) -band [uint32]4294967294)
                }
                Check ($Elf + '/complete-generated-CMSE-body/' + $name) $complete $object
                ++$count
                continue
            }
            if ($seen.ContainsKey($name)) {continue}
            $seen[$name] = $true
            $pattern = '(?m)^\s*\d+:\s+[0-9a-f]+\s+' + $function.Groups[1].Value + '\s+FUNC\s+\w+\s+DEFAULT\s+\d+\s+' + [regex]::Escape($name) + '\s*$'
            Check ($Elf + '/complete-generated-body/' + $name) ([regex]::Matches($final, $pattern).Count -eq 1) $object
            ++$count
        }
    }
    $count
}
function Oracle([hashtable]$Manifest, [string]$Path, [string]$ExpectedRejection) {
    Json $Path $Manifest
    $result = Recorded $Python @('-B',(Join-Path $fixture 'check.py'),$Path) ($Path + '.log') -AllowFailure
    if ($ExpectedRejection) {
        Check ($Path + '/exact-negative/' + $ExpectedRejection) ($result.ExitCode -eq 1 -and
            $result.Output -cmatch ('^REJECT:' + $ExpectedRejection + ':') -and $result.Output -notmatch 'Traceback') $result.Output
    } else {
        Check ($Path + '/static-reference-oracle') ($result.ExitCode -eq 0) $result.Output
    }
    $result.Output
}

$inputs = @($PSCommandPath,$ArmGcc,$nm,$readelf,$objdump)
foreach ($tool in @('cc1','as','ld','collect2')) {
    $query = Recorded $ArmGcc @("-print-prog-name=$tool") (Join-Path $build ("tool-$tool.txt"))
    $inputs += (Resolve-Path -LiteralPath $query.Output.Trim()).Path
}
$compilerIncludes = Recorded $ArmGcc @('-print-file-name=include') (Join-Path $build 'compiler-includes.txt')
foreach ($directory in @($compilerIncludes.Output.Trim(), (Join-Path (Split-Path $bin) 'arm-none-eabi\include'),
        (Join-Path $FreeRtosRoot 'include'),$reference,$fixture)) {
    $inputs += @(Get-ChildItem -LiteralPath $directory -Recurse -File |
        Where-Object {$_.FullName -notmatch '[\\/]__pycache__[\\/]'} | Select-Object -ExpandProperty FullName)
}
$baselineDirectories = @('fiber\port\ARM_CM33\non_secure','fiber\port\ARM_CM33\secure')
$baseline = @()
foreach ($relative in $baselineDirectories) {
    $baseline += @(Get-ChildItem -LiteralPath (Join-Path $repo $relative) -File |
        Where-Object {$_.Extension -in @('.h','.c','.ld')} | Select-Object -ExpandProperty FullName)
}
$inputs += $baseline
$before = @($inputs | Sort-Object -Unique | ForEach-Object {
    [pscustomobject]@{Path=$_; Sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
})
Json (Join-Path $build 'inputs.before.json') $before
Json (Join-Path $build 'scalar-baseline.json') @($before | Where-Object {$_.Path -in $baseline})
$success = $false
try {
    $head = Recorded 'git' @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $build 'reference-head.txt')
    Check 'reference/exact-pin' ($head.Output.Trim() -ceq $pin) $head.Output
    $clean = Recorded 'git' @('-C',$FreeRtosRoot,'status','--porcelain','--untracked-files=all') (Join-Path $build 'reference-status.before.txt')
    Check 'reference/clean-before' ([string]::IsNullOrWhiteSpace($clean.Output)) $clean.Output
    $null = Recorded $ArmGcc @('--version') (Join-Path $build 'compiler.txt')
    $null = Recorded $Python @('-B','-c','import sys; print(sys.executable); print(sys.version)') (Join-Path $build 'python.txt')
    foreach ($source in Get-ChildItem -LiteralPath $reference -File -Recurse) {
        $destination = Join-Path (Join-Path $build 'reference-source') $source.FullName.Substring($reference.Length + 1)
        $null = New-Item -ItemType Directory -Path (Split-Path $destination) -Force
        Copy-Item -LiteralPath $source.FullName -Destination $destination
    }
    $base = @('-mcpu=cortex-m33','-mthumb','-mfpu=fpv5-sp-d16','-std=gnu11','-ffreestanding','-fno-builtin',
        '-fno-common','-ffunction-sections','-fdata-sections','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
        "-I$fixture","-I$ns","-I$secure","-I$(Join-Path $FreeRtosRoot 'include')")
    foreach ($abi in @('hard','softfp')) {
        foreach ($optimization in @('-O2','-Os')) {
            $name = $abi + '-' + $optimization.Substring(1)
            $dir = Join-Path $build $name
            $null = New-Item -ItemType Directory -Path $dir
            $flags = $base + @("-mfloat-abi=$abi",$optimization)
            $secureFlags = $flags + @('-mcmse','-DREFERENCE_SECURE=1')
            $secureObjects = @()
            foreach ($unit in @('secure_context.c','secure_context_port.c','secure_init.c','secure_heap.c')) {
                $object = Join-Path $dir ($unit.Replace('.c','.o'))
                Compile (Join-Path $secure $unit) $object $secureFlags
                $secureObjects += $object
            }
            $secureGeometry = Join-Path $dir 'secure-geometry.o'
            Compile (Join-Path $fixture 'geometry.c') $secureGeometry $secureFlags -FixtureSource
            $secureObjects += $secureGeometry
            $secureElf = Join-Path $dir 'secure.elf'
            $imports = Join-Path $dir 'secure-imports.a'
            $secureLink = $secureFlags + @('-nostdlib','-nostartfiles','-Wl,--no-undefined','-Wl,--fatal-warnings',
                '-Wl,--cmse-implib',"-Wl,--out-implib=$imports",'-Wl,--section-start=.gnu.sgstubs=0x10020000',
                '-T',(Join-Path $fixture 'secure.ld'))
            $null = Recorded $ArmGcc ($secureLink + $secureObjects + @("-Wl,-Map,$secureElf.map",'-o',$secureElf)) ($secureElf + '.link.log')
            ElfEvidence $secureElf
            $secureBodies = RetainedBodies $secureElf $secureObjects
            $null = Recorded $readelf @('-hA','-sW',$imports) ($imports + '.readelf')

            $nsObjects = @()
            foreach ($unit in @('port.c','portasm.c')) {
                $object = Join-Path $dir ('ns-' + $unit.Replace('.c','.o'))
                Compile (Join-Path $ns $unit) $object $flags
                $nsObjects += $object
            }
            foreach ($unit in @('geometry.c','ns_providers.c')) {
                $object = Join-Path $dir ('ns-' + $unit.Replace('.c','.o'))
                Compile (Join-Path $fixture $unit) $object $flags -FixtureSource
                $nsObjects += $object
            }
            $nsElf = Join-Path $dir 'nonsecure.elf'
            $nsLink = $flags + @('-nostdlib','-nostartfiles','-Wl,--no-undefined','-Wl,--fatal-warnings',
                '-T',(Join-Path $fixture 'nonsecure.ld'))
            $null = Recorded $ArmGcc ($nsLink + $nsObjects + @($imports,"-Wl,-Map,$nsElf.map",'-o',$nsElf)) ($nsElf + '.link.log')
            ElfEvidence $nsElf
            $nsBodies = RetainedBodies $nsElf $nsObjects
            foreach ($item in @(@{State='nonsecure'; Source=(Join-Path $ns 'port.c'); Flags=$flags; Elf=$nsElf},
                    @{State='secure'; Source=(Join-Path $secure 'secure_context.c'); Flags=$secureFlags; Elf=$secureElf})) {
                $macroPath = Join-Path $dir ($item.State + '-macros.txt')
                $macros = Recorded $ArmGcc ($item.Flags + @('-E','-dM',$item.Source)) $macroPath
                Check ($name + '/' + $item.State + '/scalar-SP-facts') ($macros.Output -match '(?m)^#define __ARM_FP 4\s*$' -and
                    $macros.Output -match '(?m)^#define configENABLE_MPU 0\s*$' -and
                    $macros.Output -match '(?m)^#define configENABLE_TRUSTZONE 1\s*$') $macroPath
                $attributes = Get-Content -LiteralPath ($item.Elf + '.readelf') -Raw
                Check ($name + '/' + $item.State + '/actual-v8-M-main-ELF') ($attributes -match 'Tag_CPU_arch:\s+v8-M.main' -and
                    $attributes -notmatch 'Tag_CPU_arch:\s+v8.1-M.main') ($item.Elf + '.readelf')
                Check ($name + '/' + $item.State + '/actual-float-ABI') (($abi -eq 'hard' -and $attributes -match 'Tag_ABI_VFP_args:\s+VFP registers') -or
                    ($abi -eq 'softfp' -and $attributes -notmatch 'Tag_ABI_VFP_args:\s+VFP registers')) ($item.Elf + '.readelf')
            }
            $nsMacros = Get-Content -LiteralPath (Join-Path $dir 'nonsecure-macros.txt') -Raw
            Check ($name + '/initial-EXC_RETURN-BC-DCRS1-basic') ($nsMacros -match '(?m)^#define portINITIAL_EXC_RETURN\s+\(\s*0xffffffbc\s*\)\s*$') $nsMacros
            $manifest = @{Abi=$abi; NonsecureElf=$nsElf; SecureElf=$secureElf;
                NonsecureAssembly=(Join-Path $dir 'ns-port.s'); SecureInitAssembly=(Join-Path $dir 'secure_init.s');
                SecureContextAssembly=(Join-Path $dir 'secure_context.s')}
            $observation = Oracle $manifest (Join-Path $dir 'oracle.json')
            $runs.Add([pscustomobject]@{Name=$name; SecureElf=$secureElf; NonsecureElf=$nsElf; ActualCmseImports=$imports;
                RetainedSecureBodies=$secureBodies; RetainedNonsecureBodies=$nsBodies; Observation=($observation | ConvertFrom-Json)})

            # Actual FPU-disabled reference branches, not source-string edits.
            # The mixed control image is intentionally not an accepted tuple.
            foreach ($state in @('nonsecure','secure')) {
                $object = Join-Path $dir ($state + '-fpu-disabled-control.o')
                $controlElf = Join-Path $dir ($state + '-fpu-disabled-control.elf')
                $broken = $manifest.Clone()
                if ($state -eq 'nonsecure') {
                    Compile (Join-Path $ns 'portasm.c') $object ($flags + @('-DREFERENCE_ENABLE_FPU=0'))
                    $null = Recorded $ArmGcc ($nsLink + @($nsObjects | Where-Object {$_ -ne (Join-Path $dir 'ns-portasm.o')}) +
                        @($object,$imports,'-o',$controlElf)) ($controlElf + '.link.log')
                    $broken.NonsecureElf = $controlElf
                    $code = 'NS_FP'
                } else {
                    Compile (Join-Path $secure 'secure_context_port.c') $object ($secureFlags + @('-DREFERENCE_ENABLE_FPU=0'))
                    $controlLink = @($secureLink | Where-Object {$_ -notlike '-Wl,--out-implib=*'}) +
                        @("-Wl,--out-implib=$controlElf.imports.a")
                    $null = Recorded $ArmGcc ($controlLink + @($secureObjects | Where-Object {$_ -ne (Join-Path $dir 'secure_context_port.o')}) +
                        @($object,'-o',$controlElf)) ($controlElf + '.link.log')
                    $broken.SecureElf = $controlElf
                    $code = 'SECURE_FP_TRIGGER'
                }
                ElfEvidence $controlElf
                $null = Oracle $broken ($controlElf + '.json') $code
                $controls.Add([pscustomobject]@{Name=$name; State=$state; ExpectedRejection=$code; Elf=$controlElf})
            }
            Write-Host "C33F Secure reference PASS: $name / actual NS+Secure + two compiled controls"
        }
    }
    Check 'complete/four-real-pairs-eight-controls' ($runs.Count -eq 4 -and $controls.Count -eq 8) @($runs.Count,$controls.Count)
    $clean = Recorded 'git' @('-C',$FreeRtosRoot,'status','--porcelain','--untracked-files=all') (Join-Path $build 'reference-status.after.txt')
    Check 'reference/clean-after' ([string]::IsNullOrWhiteSpace($clean.Output)) $clean.Output
    $success = $true
} finally {
    $after = @($before | ForEach-Object {[pscustomobject]@{Path=$_.Path; Sha256=(Get-FileHash -LiteralPath $_.Path -Algorithm SHA256).Hash}})
    Json (Join-Path $build 'inputs.after.json') $after
    $lookup = @{}
    foreach ($item in $before) {$lookup[$item.Path] = $item.Sha256}
    $drift = @($after | Where-Object {$_.Sha256 -cne $lookup[$_.Path]})
    Json (Join-Path $build 'runs.json') $runs.ToArray()
    Json (Join-Path $build 'controls.json') $controls.ToArray()
    Json (Join-Path $build 'checks.json') $checks.ToArray()
    Json (Join-Path $build 'receipt.json') @{Verdict=$(if ($success -and !$drift.Count) {'PASS'} else {'FAIL'});
        ReferencePin=$pin; Configurations=$runs.Count; PositiveElfs=2*$runs.Count; ReferenceObjects=6*$runs.Count;
        FixtureObjects=3*$runs.Count; CompiledControls=$controls.Count; Checks=$checks.Count; Inputs=$before.Count;
        InputDrift=$drift; Evidence=$build; WholeGeneratedBodiesRetained=$success; Executed=$false;
        Limits='Actual reference compile/link and bounded static evidence only; no Fiber equivalence, branch execution, stack-depth or hardware qualification.'}
    $artifacts = @(Get-ChildItem -LiteralPath $build -File -Recurse | ForEach-Object {
        [pscustomobject]@{Path=$_.FullName.Substring($build.Length+1); Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    Json (Join-Path $build 'artifacts.json') $artifacts
    if ($drift.Count) {throw "Reference proof input drift; qualification refused: $build"}
}
Write-Host "PASS C33F Secure reference: four real pairs, eight compiled branch controls, $($checks.Count) static checks; no execution; evidence $build"
