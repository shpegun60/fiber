param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$RepositoryRoot,
    [switch]$ControlOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if (!$RepositoryRoot) { $RepositoryRoot = Join-Path $PSScriptRoot '..' }
$repo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
. (Join-Path $repo 'tools/runtime_sources.ps1')
$runtimeRoles = @('engine','state','panic','legacy_compat')
$runtimeSources = @(Get-RuntimeSourcePaths -RepositoryRoot $repo -Roles $runtimeRoles)
$stateSource = @(Get-RuntimeSourcePaths -RepositoryRoot $repo -Roles 'state')[0]
$panicSource = @(Get-RuntimeSourcePaths -RepositoryRoot $repo -Roles 'panic')[0]
$fixture = Join-Path $PSScriptRoot 'fixtures/reverse_abi_constructor'
$port = Join-Path $repo 'fiber/port/ARM_CM7/r0p1'
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply existing -ArmGcc' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '../../../Drivers/CMSIS/Include' }
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$bin = Split-Path $ArmGcc
$ar = Join-Path $bin 'arm-none-eabi-gcc-ar.exe'
$nm = Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$dump = Join-Path $bin 'arm-none-eabi-objdump.exe'
foreach ($path in @($ar,$nm,$dump,(Join-Path $CmsisCore 'core_cm7.h'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing test dependency: $path" }
}
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ('fiber-reverse-abi-constructor-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out
$commands = Join-Path $out 'commands.jsonl'
$checks = New-Object System.Collections.Generic.List[object]
$cases = New-Object System.Collections.Generic.List[object]
$failures = New-Object System.Collections.Generic.List[string]
$verdict = 'FAIL'
$v1 = 'fiber_internal_runtime_port_abi_v1_anchor'
$v2 = 'fiber_internal_runtime_port_abi_v2_anchor'
$portSources = @('fiber_port','fiber_port_boot','fiber_port_exception')
$inputs = @($PSCommandPath,$ArmGcc,$ar,$nm,$dump,
    (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h')) +
    @(Get-RuntimeSourceInputs -RepositoryRoot $repo -Roles $runtimeRoles) +
    @(Get-ChildItem (Join-Path $repo 'context') -File | Where-Object {$_.Extension -in @('.c','.h')} | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath (Join-Path $repo 'fiber') -Recurse -File |
        Where-Object { $_.Extension -in @('.c','.h') } | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath $CmsisCore -Recurse -File -Filter '*.h' | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath $fixture -Recurse -File | Select-Object -ExpandProperty FullName)
function HashInputs {
    @($inputs | Sort-Object -Unique | ForEach-Object {
        Get-FileHash -LiteralPath $_ -Algorithm SHA256
    } | Select-Object Path,Hash)
}
function Check([string]$Name,[bool]$Passed,[object]$Evidence) {
    # Keep reports scalar; native strings can carry PowerShell adapter metadata.
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$Passed;Evidence=[string]$Evidence})
    if (!$Passed) { $failures.Add($Name) }
}
function Recorded([string]$Program,[string[]]$Arguments,[string]$Log) {
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $Program @Arguments 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $saved }
    $text = $lines -join "`n"
    $text | Set-Content -LiteralPath $Log -Encoding ASCII
    [pscustomobject]@{Program=$Program;Arguments=$Arguments;ExitCode=$code;Log=$Log} |
        ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath $commands -Encoding ASCII
    [pscustomobject]@{Code=$code;Text=$text}
}
function Required([string]$Program,[string[]]$Arguments,[string]$Log) {
    $r = Recorded $Program $Arguments $Log
    if ($r.Code -ne 0) { throw "Command failed ($($r.Code)): $Log`n$($r.Text)" }
    $r.Text
}
function ExactMissingV1([object]$Result) {
    if ($Result.Code -ne 1) { return $false }
    $mentions = @([regex]::Matches($Result.Text,'undefined reference to [`'']([^`'']+)[`'']'))
    if (!$mentions.Count) { return $false }
    foreach ($mention in $mentions) {
        if ($mention.Groups[1].Value -cne $v1) { return $false }
    }
    $diagnostics = @($Result.Text -split '\r?\n' | Where-Object {
        $_ -match 'undefined reference|\berror:|cannot find|multiple definition|not found|overlap|overflow|unrecognized|fatal|not compatible|incompatible'
    })
    foreach ($line in $diagnostics) {
        if ($line -match 'undefined reference to [`'']fiber_internal_runtime_port_abi_v1_anchor[`'']') { continue }
        if ($line -match '(?:^|[/\\])collect2(?:\.exe)?: error: ld returned 1 exit status$') { continue }
        if ($line -cmatch '^collect2(?:\.exe)?: error: ld returned 1 exit status$') { continue }
        return $false
    }
    return $true
}
function SymbolNames([string]$Text) {
    @([regex]::Matches($Text,'(?m)^[0-9a-fA-F]+[ \t]+\S[ \t]+([^ \t\r\n]+)[ \t]*\r?$') |
        ForEach-Object { $_.Groups[1].Value })
}
function ConstructorCode([string]$Source) {
    $definitions = [regex]::Matches($Source,
        '(?m)^[ \t]*void[ \t]+fiber_port_context_init[ \t]*\([^;{}]*\)\s*\{')
    if ($definitions.Count -ne 1) { throw 'Expected exactly one complete context_init definition' }
    $start = $definitions[0].Index + $definitions[0].Length - 1
    $code = New-Object System.Text.StringBuilder
    $depth = 0
    $state = 'code'
    for ($i=$start; $i -lt $Source.Length; ++$i) {
        $c = $Source[$i]
        $next = if ($i+1 -lt $Source.Length) { $Source[$i+1] } else { [char]0 }
        if ($state -ceq 'line') {
            if ($c -eq "`n") { $state='code';$null=$code.Append("`n") }
            continue
        }
        if ($state -ceq 'block') {
            if ($c -eq '*' -and $next -eq '/') { ++$i;$state='code' }
            elseif ($c -eq "`n") { $null=$code.Append("`n") }
            continue
        }
        if ($state -ceq 'string' -or $state -ceq 'char') {
            if ($c -eq '\') { ++$i;continue }
            if (($state -ceq 'string' -and $c -eq '"') -or
                ($state -ceq 'char' -and $c -eq "'")) { $state='code' }
            continue
        }
        if ($c -eq '/' -and $next -eq '/') { ++$i;$state='line';$null=$code.Append(' ');continue }
        if ($c -eq '/' -and $next -eq '*') { ++$i;$state='block';$null=$code.Append(' ');continue }
        if ($c -eq '"') { $state='string';$null=$code.Append(' ');continue }
        if ($c -eq "'") { $state='char';$null=$code.Append(' ');continue }
        $null=$code.Append($c)
        if ($c -eq '{') { ++$depth }
        if ($c -eq '}') {
            --$depth
            if ($depth -eq 0) { return $code.ToString() }
        }
    }
    throw 'Unterminated context_init definition'
}
function AuditConstructors {
    $expected = @(
        'ARM_CM0/fiber_port_boot.c','ARM_CM0_MPU/fiber_port_boot.c',
        'ARM_CM3/fiber_port_boot.c','ARM_CM3_MPU/fiber_port_boot.c',
        'ARM_CM4/fiber_port_boot.c','ARM_CM4_MPU/fiber_port_boot.c',
        'ARM_CM7/r0p1/fiber_port_boot.c','ARM_CM23_NTZ/non_secure/fiber_port_boot.c',
        'ARM_CM33/non_secure/fiber_port_boot.c','ARM_CM33_NTZ/non_secure/fiber_port_boot.c',
        'ARM_CM33F/non_secure/fiber_port_boot.c',
        'ARM_CM33F_TFM/non_secure/fiber_port_boot.c',
        'ARM_CM33_SECURE_ONLY/secure/fiber_port_boot.c',
        'ARM_CM55_SECURE_ONLY/secure/fiber_port_boot.c',
        'ARM_CM33F_NTZ/non_secure/fiber_port_boot.c','ARM_CM33_TFM/non_secure/fiber_port_boot.c',
        'ARM_CM33_MPU/non_secure/fiber_port_boot.c','ARM_CM33F_MPU/non_secure/fiber_port_boot.c',
        'ARM_CM55/non_secure/fiber_port_boot.c','ARM_CM55_NTZ/non_secure/fiber_port_boot.c',
        'ARM_CM55_TFM/non_secure/fiber_port_boot.c',
        'ARM_CM55F_NTZ/non_secure/fiber_port_boot.c','ARM_CM55_MVEF_NTZ/non_secure/fiber_port_boot.c',
        'ARM_CM55_MPU/non_secure/fiber_port_boot.c','ARM_CM55F_MPU/non_secure/fiber_port_boot.c',
        'ARM_CM55_MVEF_MPU/non_secure/fiber_port_boot.c')
    $portRoot = Join-Path $repo 'fiber/port'
    $actual = @(Get-ChildItem -LiteralPath $portRoot -File -Recurse -Filter '*.c' | Where-Object {
        (Get-Content -LiteralPath $_.FullName -Raw) -match
            '(?m)^[ \t]*void[ \t]+fiber_port_context_init[ \t]*\([^;{}]*\)\s*\{'
    } | ForEach-Object { $_.FullName.Substring($portRoot.Length+1).Replace('\','/') })
    $difference = @(Compare-Object ($expected|Sort-Object) ($actual|Sort-Object))
    Check 'source-audit/exact-26-constructor-inventory' ($actual.Count -eq 26 -and !$difference.Count) ($difference|Out-String)
    $guard = '(?m)^[ \t]*FIBER_RUNTIME_PORT_ABI_RETAIN_V1[ \t]*\([ \t]*\)[ \t]*;'
    foreach ($relative in $expected) {
        $path = Join-Path $portRoot $relative
        if (!(Test-Path -LiteralPath $path)) { Check "source-audit/$relative" $false 'Missing source';continue }
        $code = ConstructorCode (Get-Content -LiteralPath $path -Raw)
        $retains = [regex]::Matches($code,$guard)
        Check "source-audit/$relative/direct-cold-read" ($retains.Count -eq 1) $code
        $r9 = [regex]::Match($code,'\binitial_r9\s*=\s*fiber_port_read_r9\s*\(\s*\)\s*;')
        if ($r9.Success -and $retains.Count -eq 1) {
            Check "source-audit/$relative/r9-capture-first" ($r9.Index -lt $retains[0].Index) $code
        }
    }
    foreach ($sample in @(
        @{Name='real-read';Text='void fiber_port_context_init(void) { FIBER_RUNTIME_PORT_ABI_RETAIN_V1(); }';Count=1},
        @{Name='comment-only';Text='void fiber_port_context_init(void) { /* FIBER_RUNTIME_PORT_ABI_RETAIN_V1(); } */ }';Count=0},
        @{Name='string-only';Text='void fiber_port_context_init(void) { const char *x="FIBER_RUNTIME_PORT_ABI_RETAIN_V1(); }"; }';Count=0})) {
        $body = ConstructorCode $sample.Text
        Check ('source-audit-parser/' + $sample.Name) (
            [regex]::Matches($body,'\bFIBER_RUNTIME_PORT_ABI_RETAIN_V1\s*\(\s*\)\s*;').Count -eq $sample.Count) $body
    }
}
function InspectPositive([string]$Name,[string]$Elf,[bool]$Start,[bool]$Lto,[string]$Anchor) {
    $symbols = Required $nm @('--defined-only',$Elf) ($Elf + '.defined.txt')
    $undefined = Required $nm @('-u',$Elf) ($Elf + '.undefined.txt')
    $assembly = Required $dump @('-d',$Elf) ($Elf + '.asm')
    $names = @(SymbolNames $symbols)
    Check "$Name/no-undefined" ([string]::IsNullOrWhiteSpace($undefined)) $undefined
    Check "$Name/actual-constructor-live" ($names -ccontains 'fiber_port_context_init') $symbols
    Check "$Name/entry-live" ($names -ccontains 'Reset_Handler') $symbols
    if (!$Lto) { Check "$Name/public-init-live" ($names -ccontains 'fiber_init') $symbols }
    $entryBody = [regex]::Match($assembly,
        '(?ms)^[0-9a-fA-F]+ <Reset_Handler>:\r?\n(?<body>.*?)(?=^[0-9a-fA-F]+ <|\z)')
    Check "$Name/entry-calls-actual-init" ($entryBody.Success -and
        ($entryBody.Groups['body'].Value -cmatch '(?m)\bbl(?:\.w)?\s+[^\r\n]*<(?:fiber_init|fiber_port_context_init)>')) ($Elf + '.asm')
    if (!$Start) {
        $forbidden = @('fiber_start','fiber_port_runtime_prepare_start','fiber_port_runtime_start_first',
            'fiber_port_start_first_context','fiber_port_runtime_select_first','SVC_Handler','PendSV_Handler')
        $live = @($forbidden | Where-Object { $names -ccontains $_ })
        Check "$Name/start-and-handlers-discarded" ($live.Count -eq 0) $live
    } else {
        Check "$Name/start-read-live" ($names -ccontains 'fiber_port_runtime_prepare_start') $symbols
    }
    if ($Anchor) { Check "$Name/expected-anchor-live" ($names -ccontains $Anchor) $symbols }
}
function LinkProbe([string]$Name,[string[]]$Flags,[string[]]$Objects,[string]$Dir) {
    $elf = Join-Path $Dir ($Name + '.elf')
    $args = $Flags + @('-nostdlib','-nostartfiles',
        "-T$(Join-Path $fixture 'image.ld')",'-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none',
        "-Wl,-Map=$elf.map") + $Objects + @('-o',$elf)
    $result = Recorded $ArmGcc $args ($elf + '.link.log')
    [pscustomobject]@{Elf=$elf;Result=$result}
}

$before = HashInputs
$before | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'inputs-before.json') -Encoding ASCII
try {
    $null = Required $ArmGcc @('--version') (Join-Path $out 'compiler-version.txt')
    $commonPath = $stateSource
    $commonText = Get-Content -LiteralPath $commonPath -Raw
    $pattern = 'const unsigned char fiber_internal_runtime_port_abi_v1_anchor\s*=\s*\(unsigned char\)FIBER_RUNTIME_PORT_ABI_VERSION;'
    if ([regex]::Matches($commonText,$pattern).Count -ne 1) { throw 'Common-v2 fixture requires one exact production anchor definition' }
    $v2Path = Join-Path $out 'common_v2_state.c'
    [regex]::Replace($commonText,$pattern,'const unsigned char fiber_internal_runtime_port_abi_v2_anchor = 2u;') |
        Set-Content -LiteralPath $v2Path -Encoding ASCII

    # Generate the negative control from the same current boot source used by
    # positives. Delete one call only; resolve its quoted includes at the
    # original source directory when compiling this test-local copy.
    $bootPath = Join-Path $port 'fiber_port_boot.c'
    $bootText = Get-Content -LiteralPath $bootPath -Raw
    $guardPattern = '\bFIBER_RUNTIME_PORT_ABI_RETAIN_V1[ \t]*\([ \t]*\)[ \t]*;'
    $guardMatches = [regex]::Matches($bootText,$guardPattern)
    if ($guardMatches.Count -ne 1 -or
        [regex]::Matches((ConstructorCode $bootText),$guardPattern).Count -ne 1) {
        throw 'Guard-removal control requires exactly one constructor RETAIN call in the actual boot source'
    }
    $deletion = $guardMatches[0]
    $mutantText = $bootText.Remove($deletion.Index,$deletion.Length)
    if ($mutantText.Insert($deletion.Index,$deletion.Value) -cne $bootText -or
        ($bootText.Length-$mutantText.Length) -ne $deletion.Length -or
        [regex]::Matches((ConstructorCode $mutantText),$guardPattern).Count -ne 0) {
        throw 'Guard-removal control changed more than its single constructor RETAIN call'
    }
    $mutantDir = Join-Path $out 'guard-removal-control'
    $null = New-Item -ItemType Directory -Path $mutantDir
    $originalCopy = Join-Path $mutantDir 'original_fiber_port_boot.c'
    Copy-Item -LiteralPath $bootPath -Destination $originalCopy
    $mutantPath = Join-Path $mutantDir 'fiber_port_boot.c'
    [IO.File]::WriteAllText($mutantPath,$mutantText,[Text.UTF8Encoding]::new($false))
    $writtenMutant = [IO.File]::ReadAllText($mutantPath)
    if ($writtenMutant.Insert($deletion.Index,$deletion.Value) -cne $bootText) {
        throw 'Written guard-removal control failed exact reinsertion proof'
    }
    $mutation = [pscustomobject]@{Original=$bootPath;OriginalHash=(Get-FileHash -LiteralPath $bootPath -Algorithm SHA256).Hash;
        Snapshot=$originalCopy;SnapshotHash=(Get-FileHash -LiteralPath $originalCopy -Algorithm SHA256).Hash;
        Mutant=$mutantPath;MutantHash=(Get-FileHash -LiteralPath $mutantPath -Algorithm SHA256).Hash;
        RemovedText=$deletion.Value;CharacterOffset=$deletion.Index;RemovedCharacters=$deletion.Length;
        ExactSingleTextDeletion=$true;ReinsertionRestoresSourceText=$true;
        QuotedIncludeDirectory=$port;StartReadSource=(Join-Path $port 'fiber_port.c');StartReadSourceModified=$false}
    if ($mutation.OriginalHash -cne $mutation.SnapshotHash) { throw 'Original control snapshot is not byte-identical' }
    $mutation | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'guard-removal.json') -Encoding ASCII

    $parserGood = "ld.exe: in function 'fiber_port_context_init':`nunit.o: undefined reference to ``$v1'`ncollect2.exe: error: ld returned 1 exit status"
    foreach ($p in @(
        @{Name='exact-anchor';Code=1;Text=$parserGood;Expected=$true},
        @{Name='successful-link';Code=0;Text=$parserGood;Expected=$false},
        @{Name='wrong-anchor';Code=1;Text=$parserGood.Replace($v1,$v2);Expected=$false},
        @{Name='extra-missing';Code=1;Text=($parserGood+"`nunit.o: undefined reference to ``other_missing'");Expected=$false},
        @{Name='extra-error';Code=1;Text=($parserGood+"`nld.exe: error: section overlap");Expected=$false},
        @{Name='empty';Code=1;Text='';Expected=$false},
        @{Name='crash-code';Code=99;Text=$parserGood;Expected=$false})) {
        Check ('diagnostic-oracle/' + $p.Name) ((ExactMissingV1 $p) -eq $p.Expected) $p
    }
    if (!$ControlOnly) { AuditConstructors }

    foreach ($optimization in @('O2','Os')) {
        foreach ($lto in @($false,$true)) {
            $mode = $optimization + $(if ($lto) { '-lto' } else { '' })
            $dir = Join-Path $out $mode
            $null = New-Item -ItemType Directory -Path $dir
            $flags = @('-mcpu=cortex-m7','-mthumb','-mfloat-abi=soft',"-$optimization",'-std=gnu11',
                '-ffreestanding','-fno-builtin','-fno-common','-ffunction-sections','-fdata-sections',
                '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra',
                '-Werror=implicit-function-declaration','-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV7EM=1',
                "-I$port","-I$repo","-I$(Join-Path $repo 'fiber')","-I$fixture","-I$CmsisCore")
            if ($lto) { $flags += '-flto' }
            $objects = @{}
            $commonBySource = @{}
            foreach ($source in $runtimeSources) {
                $unit = $source.Substring($repo.Length+1).Replace('\','_').Replace('/','_')
                $obj = Join-Path $dir ($unit + '.o')
                $null = Required $ArmGcc ($flags + @('-c',$source,'-o',$obj)) ($obj + '.compile.log')
                $commonBySource[$source] = $obj
            }
            $engineObjects = @($runtimeSources | Where-Object {$_ -ne $stateSource -and $_ -ne $panicSource} | ForEach-Object {$commonBySource[$_]})
            foreach ($unit in $portSources + @('integration','common_v2_state')) {
                $source = if ($portSources -contains $unit) { Join-Path $port "$unit.c" }
                    elseif ($unit -ceq 'integration') { Join-Path $fixture 'integration.c' }
                    else { $v2Path }
                $obj = Join-Path $dir ($unit + '.o')
                $null = Required $ArmGcc ($flags + @("-I$(Split-Path $stateSource)",'-c',$source,'-o',$obj)) ($obj + '.compile.log')
                $objects[$unit] = $obj
            }
            $macroObject = Join-Path $dir 'macro_visibility.o'
            $null = Required $ArmGcc ($flags + @('-Werror=implicit-function-declaration','-c',
                (Join-Path $fixture 'macro_visibility.c'),'-o',$macroObject)) ($macroObject+'.compile.log')
            $macroUndefined = Required $nm @('-u',$macroObject) ($macroObject+'.undefined.txt')
            $macroNames = @([regex]::Matches($macroUndefined,'(?m)^\s*U\s+(\S+)\r?$') |
                ForEach-Object { $_.Groups[1].Value })
            Check "$mode/direct-macro-exact-data-dependency" (
                $macroNames.Count -eq 1 -and $macroNames[0] -ceq $v1) $macroUndefined
            $v2Symbols = Required $nm @('--defined-only',$objects.common_v2_state) (Join-Path $dir 'common-v2.defined.txt')
            $v2Names = @(SymbolNames $v2Symbols)
            Check "$mode/v2-only-common-fixture" (($v2Names -ccontains $v2) -and ($v2Names -cnotcontains $v1)) $v2Symbols
            $archive = Join-Path $dir 'production.a'
            $production = $engineObjects + @($portSources | ForEach-Object { $objects[$_] })
            $null = Required $ar (@('rcs',$archive) + $production) (Join-Path $dir 'archive.log')
            $null = Required $ar @('t',$archive) (Join-Path $dir 'archive-members.txt')
            $bootUndefined = Required $nm @('-u',$objects.fiber_port_boot) (Join-Path $dir 'boot.undefined.txt')
            if (!$ControlOnly) {
                Check "$mode/constructor-object-v1-reference" ($bootUndefined -cmatch ('(?m)\bU\s+' + $v1 + '\r?$')) $bootUndefined
                $groupUndefined = Required $nm (@('-u') + @($portSources | ForEach-Object { $objects[$_] })) (Join-Path $dir 'group.undefined.txt')
                Check "$mode/two-group-object-v1-references" (
                    [regex]::Matches($groupUndefined,'(?m)\bU\s+fiber_internal_runtime_port_abi_v1_anchor\r?$').Count -eq 2) $groupUndefined
            }

            $mutantObject = Join-Path $dir 'guard_removed_boot.o'
            $dependencies = Join-Path $dir 'guard_removed_boot.d'
            $null = Required $ArmGcc ($flags + @('-iquote',$port,'-MMD','-MF',$dependencies,
                '-c',$mutantPath,'-o',$mutantObject)) ($mutantObject+'.compile.log')
            $mutantUndefined = Required $nm @('-u',$mutantObject) ($mutantObject+'.undefined.txt')
            Check "$mode/control-constructor-anchor-removed" (
                $mutantUndefined -cnotmatch ('(?m)\bU\s+'+$v1+'\r?$')) $mutantUndefined
            $dependencyText = (Get-Content -LiteralPath $dependencies -Raw).Replace('\','/')
            Check "$mode/control-original-private-header-resolution" ($dependencyText.Contains(
                (Join-Path $port 'fiber_port_private.h').Replace('\','/'))) $dependencyText
            $controlProduction = $engineObjects + @($objects.fiber_port,$mutantObject,$objects.fiber_port_exception)
            $controlArchive = Join-Path $dir 'guard_removed.a'
            $null = Required $ar (@('rcs',$controlArchive)+$controlProduction) (Join-Path $dir 'guard_removed.archive.log')
            $controlUndefined = Required $nm @('-u',$controlArchive) (Join-Path $dir 'guard_removed.undefined.txt')
            Check "$mode/control-start-group-reference-preserved" (
                [regex]::Matches($controlUndefined,'(?m)\bU\s+fiber_internal_runtime_port_abi_v1_anchor\r?$').Count -eq 1) $controlUndefined

            $entries = @{}
            foreach ($start in @(0,1)) {
                $entry = Join-Path $dir "entry-$start.o"
                $null = Required $ArmGcc ($flags + @("-DFIBER_REVERSE_CONSTRUCTOR_START=$start",'-c',
                    (Join-Path $fixture 'entry.c'),'-o',$entry)) ($entry + '.compile.log')
                $entries[$start] = $entry
            }
            if (!$ControlOnly) {
                foreach ($version in @(1,2)) {
                    $state = if ($version -eq 1) { $commonBySource[$stateSource] } else { $objects.common_v2_state }
                    foreach ($start in @(0,1)) {
                        foreach ($kind in @('direct','archive')) {
                            $name = "$kind-v$version-start$start"
                            $selected = if ($kind -ceq 'archive') { @($archive) } else { $production }
                            $linked = LinkProbe $name $flags (@($entries[$start],$state,$commonBySource[$panicSource],$objects.integration) + $selected) $dir
                            $negative = $version -eq 2
                            $accepted = if ($negative) { (ExactMissingV1 $linked.Result) -and !(Test-Path -LiteralPath $linked.Elf) }
                                else { $linked.Result.Code -eq 0 }
                            Check "$mode/$name/expected-link-outcome" $accepted $linked.Result
                            if ($negative -and $start -eq 0 -and $accepted) {
                                Check "$mode/$name/constructor-not-start-diagnostic" (
                                    $linked.Result.Text -cmatch 'fiber_port_context_init' -and
                                    $linked.Result.Text -cnotmatch 'fiber_port_runtime_prepare_start|fiber_port_runtime_start_first|fiber_port_start_first_context') $linked.Result.Text
                            }
                            $cases.Add([pscustomobject]@{Kind='production';Mode=$mode;Link=$kind;Version=$version;
                                Start=[bool]$start;Expected=$(if ($negative) {'EXACT-V1-FAIL'} else {'LINK-PASS'});
                                Passed=$accepted;ExitCode=$linked.Result.Code;Log=($linked.Elf+'.link.log')})
                            if (!$negative -and $linked.Result.Code -eq 0) {
                                InspectPositive "$mode/$name" $linked.Elf ([bool]$start) $lto $v1
                            }
                        }
                    }
                }
            }

            # All other objects are the production positives' exact objects.
            # This successful bad link must fail the same negative oracle.
            foreach ($kind in @('direct','archive')) {
                $controlObjects = if ($kind -ceq 'archive') { @($controlArchive) } else { $controlProduction }
                $name = "guard-removed-$kind-v2-init-only"
                $linked = LinkProbe $name $flags (@($entries[0],$objects.common_v2_state,$commonBySource[$panicSource],$objects.integration) + $controlObjects) $dir
                $exposesGap = ($linked.Result.Code -eq 0) -and !(ExactMissingV1 $linked.Result)
                Check "$mode/$name/oracle-rejects-guard-removal" $exposesGap $linked.Result
                $cases.Add([pscustomobject]@{Kind='guard-removal-control';Mode=$mode;Link=$kind;Version=2;Start=$false;
                    Expected='LINK-PASS-ORACLE-MUST-REJECT';Passed=$exposesGap;ExitCode=$linked.Result.Code;Log=($linked.Elf+'.link.log')})
                if ($linked.Result.Code -eq 0) {
                    InspectPositive "$mode/$name" $linked.Elf $false $lto ''
                    $controlSymbols = Get-Content -LiteralPath ($linked.Elf+'.defined.txt') -Raw
                    Check "$mode/$name/no-live-v1-anchor" ((SymbolNames $controlSymbols) -cnotcontains $v1) $controlSymbols
                }
            }
        }
    }
    $productionCases = @($cases | Where-Object { $_.Kind -ceq 'production' })
    $controlCases = @($cases | Where-Object { $_.Kind -ceq 'guard-removal-control' })
    Check 'complete/guard-removal-control-count' ($controlCases.Count -eq 8) $controlCases.Count
    if (!$ControlOnly) {
        Check 'complete/production-32' ($productionCases.Count -eq 32) $productionCases.Count
        Check 'complete/production-positive-16' (@($productionCases | Where-Object { $_.Expected -ceq 'LINK-PASS' }).Count -eq 16) $productionCases.Count
        Check 'complete/production-negative-16' (@($productionCases | Where-Object { $_.Expected -ceq 'EXACT-V1-FAIL' }).Count -eq 16) $productionCases.Count
    }
    if ($failures.Count) { throw ('Reverse constructor checks failed: ' + ($failures -join ', ')) }
    $verdict = if ($ControlOnly) { 'CONTROL-ONLY-PASS' } else { 'PASS' }
} catch {
    $failures.Add($_.Exception.Message)
    throw
} finally {
    $after = HashInputs
    $after | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $drift = @(Compare-Object $before $after -Property Path,Hash)
    if ($drift.Count) { $verdict='FAIL';$failures.Add('input-drift') }
    $checks.ToArray() | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $out 'checks.json') -Encoding ASCII
    $cases.ToArray() | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'cases.json') -Encoding ASCII
    $artifacts = @(Get-ChildItem -LiteralPath $out -File -Recurse |
        Where-Object { $_.Name -notin @('artifact-hashes.json','receipt.json') } |
        ForEach-Object { Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 } | Select-Object Path,Hash)
    $artifacts | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'artifact-hashes.json') -Encoding ASCII
    [pscustomobject]@{Verdict=$verdict;ProductionQualification=(!$ControlOnly -and $verdict -ceq 'PASS');
        ProductionLinks=@($cases | Where-Object {$_.Kind -ceq 'production'}).Count;
        GuardRemovalControlLinks=@($cases | Where-Object {$_.Kind -ceq 'guard-removal-control'}).Count;
        Checks=$checks.Count;Failures=$failures.ToArray();InputCount=$before.Count;InputDriftCount=$drift.Count;InputDrift=$drift;
        CommandsHash=(Get-FileHash -LiteralPath $commands -Algorithm SHA256).Hash;
        InputsHash=(Get-FileHash -LiteralPath (Join-Path $out 'inputs-before.json') -Algorithm SHA256).Hash;
        ArtifactManifestHash=(Get-FileHash -LiteralPath (Join-Path $out 'artifact-hashes.json') -Algorithm SHA256).Hash;
        ExecutedFirmware=$false;CommonV2Fixture='Only production runtime-state anchor definition replaced';
        ProductionPortSourceTransformation=$false;ControlPortSourceTransformation='Exactly one current constructor RETAIN call deleted';
        GuardRemovalManifestHash=$(if(Test-Path -LiteralPath (Join-Path $out 'guard-removal.json')){
            (Get-FileHash -LiteralPath (Join-Path $out 'guard-removal.json') -Algorithm SHA256).Hash}else{''});
        ConstructorSourceAudit=$(if($ControlOnly){'NOT_RUN'}else{'26 concrete expected definitions; direct cold read; r9 capture order'});
        ObjectVisibilityScope='Actual CM7 constructor and direct reverse-header macro; other profile compilation belongs to aggregate';Evidence=$out} |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $out 'receipt.json') -Encoding ASCII
    if ($drift.Count) { throw "Input drift: $out" }
}
Write-Host "$verdict reverse constructor; evidence $out"
