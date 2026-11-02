param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$QemuRoot,
    [string]$WslDistro = 'Ubuntu-24.04',
    [string]$BuildRoot,
    [ValidateRange(2,120)][int]$TimeoutSeconds = 30,
    [string[]]$DevelopmentModes,
    [int[]]$DevelopmentCases
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture = Join-Path $PSScriptRoot 'fixtures\m55_secure_attachment'
$ns = Join-Path $repo 'fiber\port\ARM_CM55\non_secure'
$secure = Join-Path $repo 'fiber\port\ARM_CM55\secure'
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply existing -ArmGcc' }
if (!$QemuRoot -or !$QemuRoot.StartsWith('/')) { throw 'Explicit existing absolute WSL -QemuRoot required; no installation/skip' }
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
if (!$FreeRtosRoot) { $FreeRtosRoot = Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
$reference = Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM55\non_secure'
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$objdump = Join-Path $bin 'arm-none-eabi-objdump.exe'
$objcopy = Join-Path $bin 'arm-none-eabi-objcopy.exe'
$wsl = (Get-Command wsl.exe -ErrorAction Stop).Source
$rsp = Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards\aircr_rsp.py'
$inspect = Join-Path $PSScriptRoot 'fixtures\arm_control\qemu.sh'
foreach ($path in @($nm,$objdump,$objcopy,$rsp,$inspect,(Join-Path $reference 'port.c'),
        (Join-Path $ns 'fiber_port_boot.c'),(Join-Path $ns 'fiber_port_secure_context.c'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing input: $path" }
}
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ('fiber-m55-secure-attachment-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out -Force
$out = (Resolve-Path -LiteralPath $out).Path
$commands = Join-Path $out 'commands.jsonl'
$runs = New-Object System.Collections.Generic.List[object]
$checks = New-Object System.Collections.Generic.List[object]
$verdict = 'FAIL'
Write-Host "C55S attachment evidence: $out"
function Recorded([string]$Program,[string[]]$Arguments,[string]$Log,[switch]$AllowFailure) {
    [pscustomobject]@{Program=$Program;Arguments=$Arguments;Log=$Log} |
        ConvertTo-Json -Depth 6 -Compress | Add-Content -LiteralPath $commands -Encoding ASCII
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $Program @Arguments 2>&1 | ForEach-Object {"$_"})
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    [IO.File]::WriteAllLines($Log,[string[]]$lines)
    if ($code -ne 0 -and !$AllowFailure) { throw "Command failed ($code): $Log`n$($lines -join "`n")" }
    return [pscustomobject]@{ExitCode=$code;Text=($lines -join "`n")}
}
function WslPath([string]$Path) {
    $r = Recorded $wsl @('-d',$WslDistro,'--exec','wslpath','-u',$Path) (Join-Path $out ('wslpath-'+[guid]::NewGuid().ToString('N')+'.txt'))
    return $r.Text.Trim()
}
function Check([string]$Name,[bool]$Condition) {
    if (!$Condition) { throw "Failed maintained check: $Name" }
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$true})
}
function Defined([string]$Symbols,[string]$Name) {
    $matches = [regex]::Matches($Symbols,'(?m)^([0-9a-fA-F]+)\s+[a-zA-Z]\s+'+[regex]::Escape($Name)+'\r?$')
    if ($matches.Count -ne 1) { throw "Missing unique symbol $Name" }
    return [Convert]::ToUInt32($matches[0].Groups[1].Value,16)
}
function RejectLink([string]$Name,[string[]]$Flags,[string[]]$Objects,[string]$Directory,[string[]]$Missing) {
    $r = Recorded $ArmGcc ($Flags+$Objects+@('-o',(Join-Path $Directory ($Name+'.elf')))) (Join-Path $Directory ($Name+'.log')) -AllowFailure
    Check "$Name actual failed link" ($r.ExitCode -ne 0)
    $actual = @([regex]::Matches($r.Text,"undefined reference to ``([^']+)'") | ForEach-Object {$_.Groups[1].Value} | Sort-Object -Unique)
    Check "$Name exact missing symbol set" (!(Compare-Object @($Missing | Sort-Object) $actual))
}
function UndefinedNames([string]$Object,[string]$Log) {
    $r=Recorded $nm @('-u',$Object) $Log
    return @($r.Text -split "`n" | ForEach-Object {if ($_ -match '^\s*U\s+(\S+)\s*$') {$Matches[1]}} | Sort-Object -Unique)
}
function ExecuteCase([string]$Label,[int]$Number,[string]$NsElf,[string]$SElf,[string]$Directory,
        [object[]]$Entries,[int]$OracleFailure=-1,[string]$RunnerFailure='') {
    $caseDir=Join-Path $Directory $Label
    $null=New-Item -ItemType Directory -Path $caseDir
    $word=Join-Path $caseDir 'case.bin'
    [IO.File]::WriteAllBytes($word,[BitConverter]::GetBytes([uint32]$Number))
    $nElf=Join-Path $caseDir 'nonsecure.elf'
    $null=Recorded $objcopy @('--update-section',".fixture_case=$word",$NsElf,$nElf) (Join-Path $caseDir 'patch-case.log')
    $marker=if ($Number -eq 0) {"PASS:C55S-ATTACH:real-SG-eight-query`n"} elseif ($Number -eq 1) {"PASS:C55S-ATTACH:labelled-NS-query-doubles`n"} else {"PASS:C55S-ATTACH:rejected case=0x$($Number.ToString('x8'))`n"}
    $manifest=@{case=$Number;kind=$(if ($Number -eq 0) {'real-SG'} else {'labelled-NS-doubles'});
        secure=(WslPath $SElf);nonsecure=(WslPath $nElf);
        secure_sha256=(Get-FileHash $SElf -Algorithm SHA256).Hash;
        nonsecure_sha256=(Get-FileHash $nElf -Algorithm SHA256).Hash;
        queries=$Entries;expected_marker=$marker}
    if ($OracleFailure -ge 0) { $manifest.oracle_failure='0x'+$OracleFailure.ToString('x8') }
    $manifestPath=Join-Path $caseDir 'manifest.json'
    $manifest | ConvertTo-Json -Depth 7 | Set-Content $manifestPath -Encoding ASCII
    $seconds=if ($RunnerFailure -eq 'TimeoutExpired') {2} else {$TimeoutSeconds}
    $r=Recorded $wsl @('-d',$WslDistro,'--exec','python3',"$wslFixture/run.py",$QemuRoot,"$seconds",(WslPath $manifestPath),$wslRsp) (Join-Path $caseDir 'run.log') -AllowFailure
    $receipt=Get-Content (Join-Path $caseDir 'receipt.json') -Raw | ConvertFrom-Json
    if ($RunnerFailure) {
        Check "$Label runner rejects compiled control" ($r.ExitCode -ne 0 -and $receipt.result -eq 'FAIL')
        if ($RunnerFailure -eq 'TimeoutExpired') { Check "$Label exact timeout" ($receipt.error_type -eq 'TimeoutExpired') }
        else { Check "$Label exact rejection" ($receipt.error.StartsWith($RunnerFailure)) }
    } else {
        Check "$Label execution" ($r.ExitCode -eq 0 -and $receipt.result -eq 'PASS')
    }
    $runs.Add([pscustomobject]@{Mode=$mode.Name;Case=$Number;Label=$Label;Kind=$manifest.kind;
        Result=$(if ($RunnerFailure) {'EXPECTED-REJECTION'} else {$receipt.result});
        Receipt=(Join-Path $caseDir 'receipt.json')})
}
$queries = @('fiber_secure_gateway_c55s_v1_abi_version','fiber_secure_gateway_c55s_v1_context_port_id',
    'fiber_secure_gateway_c55s_v1_context_layout_version','fiber_secure_gateway_c55s_v1_context_feature_mask',
    'fiber_secure_context_gateway_c55s_v1_abi_version','fiber_secure_context_gateway_c55s_v1_stack_alignment',
    'fiber_secure_context_gateway_c55s_v1_max_contexts','fiber_secure_context_gateway_c55s_v1_max_stack_bytes')
$inputPaths = @($PSCommandPath,$ArmGcc,$nm,$objdump,$objcopy,$rsp,$inspect,
    (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h')) +
    @(Get-ChildItem (Join-Path $repo 'fiber') -File | Where-Object {$_.Extension -in @('.h','.c')} | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem (Join-Path $repo 'fiber\port') -File | Where-Object {$_.Extension -eq '.h'} | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem $ns,$secure -File | Where-Object {$_.Extension -in @('.h','.c','.ld')} | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem $CmsisCore -File -Filter '*.h' | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem (Join-Path $FreeRtosRoot 'include'),$reference,(Join-Path $reference '..\secure') -File | Where-Object {$_.Extension -in @('.h','.c')} | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem $fixture -Recurse -File | Where-Object {$_.Extension -ne '.pyc'} | Select-Object -ExpandProperty FullName)
$inputPaths = @($inputPaths | Sort-Object -Unique)
$before = @($inputPaths | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
$before | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII
$allModes = @(@{Name='o0';Flags=@('-O0')},@{Name='o2';Flags=@('-O2')},@{Name='os';Flags=@('-Os')},
    @{Name='o2-lto';Flags=@('-O2','-flto')},@{Name='os-lto';Flags=@('-Os','-flto')},
    @{Name='o2-hostile';Flags=@('-O2');Hostile=$true},@{Name='os-hostile';Flags=@('-Os');Hostile=$true})
$modes = $allModes
if ($DevelopmentModes) {
    foreach ($name in $DevelopmentModes) { if ($name -notin $allModes.Name) { throw "Unknown development mode $name" } }
    $modes = @($allModes | Where-Object {$_.Name -in $DevelopmentModes})
}
$allCases = @(0,1) + @(100..109) + @(200..247) + @(300..316) + @((400..418) | Where-Object {$_ -ne 408}) + @(500..511) + @(1000..1011)
$cases = $allCases
if ($PSBoundParameters.ContainsKey('DevelopmentCases')) {
    foreach ($n in $DevelopmentCases) { if ($n -notin $allCases) { throw "Unknown development case $n" } }
    $cases = @($DevelopmentCases | Sort-Object -Unique)
}
try {
    $pin=Recorded 'git' @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.txt')
    Check 'actual FreeRTOS pin' ($pin.Text.Trim() -eq 'a50edad08b29052631aa469d4df6e6ec7ff68878')
    $null=Recorded 'git' @('-C',$FreeRtosRoot,'diff','--exit-code','HEAD','--') (Join-Path $out 'reference-status.txt')
    $null=Recorded $ArmGcc @('--version') (Join-Path $out 'compiler-version.txt')
    $wslOut=WslPath $out
    $wslFixture=WslPath $fixture
    $wslRsp=WslPath $rsp
    $null=Recorded $wsl @('-d',$WslDistro,'--exec','bash',(WslPath $inspect),'inspect',$QemuRoot,$wslOut) (Join-Path $out 'qemu-inspect.log')
    Check 'existing QEMU M55 model' ((Get-Content (Join-Path $out 'qemu-machines.txt') -Raw) -match '(?m)^mps3-an547\s')
    $base=@('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-mgeneral-regs-only','-ffreestanding','-fno-builtin','-fno-common',
        '-ffunction-sections','-fdata-sections','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
        '-fstrict-aliasing','-Wstrict-aliasing=3','-Wall','-Wextra','-Werror','-g3')
    $selected=@('-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV81M_MAINLINE=1')
    $link=@('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none')
    foreach ($mode in $modes) {
        $dir=Join-Path $out $mode.Name
        $null=New-Item -ItemType Directory -Path $dir
        $flags=$base+$mode.Flags
        $nflags=$flags+$selected+@('-std=c11',"-I$fixture","-I$ns","-I$repo","-I$CmsisCore")
        $sflags=$flags+$selected+@('-std=c11','-mcmse','-DATTACH_SECURE=1',
            '-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3u','-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=128u',
            "-I$fixture","-I$secure","-I$repo","-I$CmsisCore")
        $hostile=@()
        if ($mode.ContainsKey('Hostile')) {
            $hostile=@('-finstrument-functions','-fstack-protector-all','-fprofile-arcs','-ftest-coverage',
                '-fsanitize=undefined','-fsanitize-coverage=trace-pc','-fstack-check=generic')
        }
        $sobjects=@()
        foreach ($unit in @(@{Name='secure-fixture';Path=(Join-Path $fixture 'secure.c')},
                @{Name='secure-start';Path=(Join-Path $fixture 'startup.S')},
                @{Name='identity';Path=(Join-Path $secure 'fiber_secure_gateway.c')},
                @{Name='gateway';Path=(Join-Path $secure 'fiber_secure_context_gateway.c')},
                @{Name='pool';Path=(Join-Path $secure 'fiber_secure_context_pool.c')})) {
            $object=Join-Path $dir ($unit.Name+'.o')
            $null=Recorded $ArmGcc ($sflags+@('-save-temps=obj','-MMD','-c',$unit.Path,'-o',$object)) (Join-Path $dir ($unit.Name+'-compile.log'))
            $sobjects+=$object
        }
        $sElf=Join-Path $dir 'secure.elf'; $import=Join-Path $dir 'secure-import.o'
        $roots=@($queries | ForEach-Object {"-Wl,-u,$_"})
        $null=Recorded $ArmGcc ($sflags+$link+$roots+@('-Wl,--section-start=.gnu.sgstubs=0x10008000',
            '-T',(Join-Path $fixture 'secure.ld'),"-Wl,--cmse-implib,--out-implib=$import", "-Wl,-Map,$dir/secure.map")+$sobjects+@('-o',$sElf)) (Join-Path $dir 'secure-link.log')
        $sSymbols=(Recorded $nm @('-g','--defined-only',$sElf) (Join-Path $dir 'secure.nm')).Text
        $null=Recorded $objdump @('-drwC',$sElf) (Join-Path $dir 'secure.dis')
        $imports=(Recorded $nm @('-g','--defined-only',$import) (Join-Path $dir 'secure-import.nm')).Text
        $exported=@($imports -split "`n" | ForEach-Object {if ($_ -match '^\s*[a-fA-F0-9]+\s+[A-Za-z]\s+(\S+)\s*$') {$Matches[1]}} | Sort-Object)
        # CMSE entry points are naturally retained by the compiler, including
        # current lifecycle entries. All eight query imports must be genuine.
        $expectedExports=$queries+@('fiber_secure_context_gateway_c55s_v1_initialize',
            'fiber_secure_context_gateway_c55s_v1_allocate','fiber_secure_context_gateway_c55s_v1_load',
            'fiber_secure_context_gateway_c55s_v1_save')
        Check "$($mode.Name) exact current CMSE import surface" (!(Compare-Object @($expectedExports | Sort-Object) $exported))
        foreach ($query in $queries) {
            $address=Defined $imports $query
            Check "$($mode.Name) exact NSC aperture $query" ($address -ge 0x10008000 -and $address -lt 0x10009000)
        }
        $queryEntries=@($queries | ForEach-Object {@{name=$_;address=(Defined $sSymbols ('__acle_se_'+$_))}})
        $nobjects=@{}
        foreach ($unit in @(@{Name='boot';Path=(Join-Path $ns 'fiber_port_boot.c');Hostile=$true},
                @{Name='attach';Path=(Join-Path $ns 'fiber_port_secure_context.c');Hostile=$true},
                @{Name='configuration';Path=(Join-Path $repo 'fiber\fiber_runtime_context_configuration.c')},
                @{Name='state';Path=(Join-Path $repo 'fiber\fiber_runtime_state.c')},
                @{Name='fixture';Path=(Join-Path $fixture 'nonsecure.c')},
                @{Name='startup';Path=(Join-Path $fixture 'startup.S')},
                @{Name='doubles';Path=(Join-Path $fixture 'query_doubles.c')})) {
            $object=Join-Path $dir ($unit.Name+'.o')
            $extra=if ($unit.ContainsKey('Hostile')) {$hostile} else {@()}
            $null=Recorded $ArmGcc ($nflags+$extra+@('-save-temps=obj','-MMD','-c',$unit.Path,'-o',$object)) (Join-Path $dir ($unit.Name+'-compile.log'))
            $nobjects[$unit.Name]=$object
            if ($unit.ContainsKey('Hostile') -and $hostile.Count) {
                $baseline=Join-Path $dir ($unit.Name+'-normal.o')
                $null=Recorded $ArmGcc ($nflags+@('-c',$unit.Path,'-o',$baseline)) (Join-Path $dir ($unit.Name+'-normal-compile.log'))
                $normalDeps=@(UndefinedNames $baseline (Join-Path $dir ($unit.Name+'-normal-undefined.txt')))
                $hostileDeps=@(UndefinedNames $object (Join-Path $dir ($unit.Name+'-hostile-undefined.txt')))
                Check "$($mode.Name) $($unit.Name) normal/hostile exact undefined contract" (!(Compare-Object $normalDeps $hostileDeps))
            }
        }
        $rflags=$flags+@('-std=c11',"-I$fixture/reference","-I$FreeRtosRoot/include","-I$reference","-I$reference/../secure")
        $refObject=Join-Path $dir 'reference.o'
        $null=Recorded $ArmGcc ($rflags+@('-save-temps=obj','-MMD','-c',(Join-Path $reference 'port.c'),'-o',$refObject)) (Join-Path $dir 'reference-compile.log')
        $common=@($nobjects.boot,$nobjects.attach,$nobjects.configuration,$nobjects.state,$nobjects.fixture,$nobjects.startup,$refObject)
        $nlink=$nflags+$link+@('-T',(Join-Path $fixture 'nonsecure.ld'))
        foreach ($kind in @('real','double')) {
            $objects=$common+@(if ($kind -eq 'real') {$import} else {$nobjects.doubles})
            $elf=Join-Path $dir ($kind+'.elf')
            $null=Recorded $ArmGcc ($nlink+$objects+@("-Wl,-Map,$dir/$kind.map",'-o',$elf)) (Join-Path $dir ($kind+'-link.log'))
            $undefined=(Recorded $nm @('-u',$elf) (Join-Path $dir ($kind+'-undefined.txt'))).Text.Trim()
            Check "$($mode.Name) $kind exact empty undefined set" ($undefined.Length -eq 0)
            $symbols=(Recorded $nm @('-a',$elf) (Join-Path $dir ($kind+'.nm'))).Text
            Check "$($mode.Name) $kind no instrumentation dependency/counter" ($symbols -notmatch '(?i)(__cyg_profile|__gcov|__ubsan|__asan|__tsan|__sanitizer|__stack_chk|__morestack|__chkstk|__mcount|__stack_check)')
            $disassembly=(Recorded $objdump @('-drwC',$elf) (Join-Path $dir ($kind+'.dis'))).Text
            if ($kind -eq 'real') {
                $calls=@([regex]::Matches($disassembly,'(?m)^\s*([0-9a-f]+):\s+([0-9a-f]{4})\s+([0-9a-f]{4})\s+bl\s+[0-9a-f]+\s+<__(fiber_secure_(?:context_)?gateway_c55s_v1_\w+)_veneer>\r?$'))
                Check "$($mode.Name) exact generated query call inventory" ($calls.Count -eq 8)
                for ($i=0; $i -lt 8; ++$i) {
                    Check "$($mode.Name) generated query call order $i" ($calls[$i].Groups[4].Value -ceq $queries[$i])
                    $queryEntries[$i].ns_return=[Convert]::ToUInt32($calls[$i].Groups[1].Value,16)+4
                }
            }
        }
        $attachUndefined=(Recorded $nm @('-u',$nobjects.attach) (Join-Path $dir 'attach-undefined.txt')).Text
        $anchor='fiber_internal_runtime_context_configuration_abi_v1_anchor'
        Check "$($mode.Name) actual optional ABI anchor dependency" ($attachUndefined -match [regex]::Escape($anchor))
        $withoutConfig=@($common | Where-Object {$_ -ne $nobjects.configuration})+@($nobjects.doubles)
        RejectLink ($mode.Name+'-missing-configuration') $nlink $withoutConfig $dir @($anchor,'fiber_internal_runtime_require_context_configuration_open')
        $staleSource=Join-Path $dir 'stale-configuration.c'
        $configText=Get-Content (Join-Path $repo 'fiber\fiber_runtime_context_configuration.c') -Raw
        Check "$($mode.Name) unique actual anchor definition" ([regex]::Matches($configText,[regex]::Escape($anchor)).Count -eq 1)
        [IO.File]::WriteAllText($staleSource,$configText.Replace($anchor,'fiber_internal_runtime_context_configuration_abi_v2_anchor'))
        $stale=Join-Path $dir 'stale-configuration.o'
        $null=Recorded $ArmGcc ($nflags+@("-I$repo/fiber",'-c',$staleSource,'-o',$stale)) (Join-Path $dir 'stale-configuration-compile.log')
        RejectLink ($mode.Name+'-stale-configuration') $nlink ($withoutConfig+@($stale)) $dir @($anchor)
        $cohortNames=@(UndefinedNames $nobjects.boot (Join-Path $dir 'boot-undefined.txt') |
            Where-Object {$_ -like 'fiber_port_context_cohort_*'})
        Check "$($mode.Name) exact staged cohort dependency" ($cohortNames.Count -eq 1)
        $noCohort=Join-Path $dir 'no-cohort-fixture.o'
        $null=Recorded $ArmGcc ($nflags+@('-DOMIT_COHORT=1','-c',(Join-Path $fixture 'nonsecure.c'),'-o',$noCohort)) (Join-Path $dir 'no-cohort-compile.log')
        $noCohortObjects=@($common | ForEach-Object {if ($_ -eq $nobjects.fixture) {$noCohort} else {$_}})+@($nobjects.doubles)
        RejectLink ($mode.Name+'-missing-cohort') $nlink $noCohortObjects $dir $cohortNames
        foreach ($n in $cases) {
            $kind=if ($n -eq 0) {'real'} else {'double'}
            ExecuteCase ('case-'+$n) $n (Join-Path $dir ($kind+'.elf')) $sElf $dir $queryEntries
        }
        # These controls compile mutated ACTUAL source, then must fail at an
        # exact independent assertion. A compile error never counts as proof.
        $mutations=@(@{Name='captured-r9';Unit='boot';Source=(Join-Path $ns 'fiber_port_boot.c');
                Pattern='const uint32_t initial_r9 = fiber_port_read_r9\(\);';
                Replacement='const uint32_t initial_r9 = fiber_port_read_r9() ^ 1u;';Case=1;Check=3208})
        foreach ($field in @('ipsr','primask','basepri','faultmask','control','psplim')) {
            $index=@('ipsr','primask','basepri','faultmask','control','psplim').IndexOf($field)
            $mutations+=@{Name=('removed-cpu-'+$field);Unit='attach';Source=(Join-Path $ns 'fiber_port_secure_context.c');
                Pattern=('FIBER_REQUIRE\(after\.'+$field+' == before->'+$field+", '[^']'\);");
                Replacement='((void)0);';Case=(242+$index);Check=5300}
        }
        $mutations+=@{Name='reference-preload';Unit='reference';Source=(Join-Path $reference 'port.c');
            Pattern='(?m)^#define portPRELOAD_REGISTERS    1\r?$';Replacement='#define portPRELOAD_REGISTERS    0';Case=1;Check=4603}
        foreach ($mutation in $mutations) {
            $sourceText=Get-Content -LiteralPath $mutation.Source -Raw
            Check "$($mode.Name) $($mutation.Name) unique mutation site" ([regex]::Matches($sourceText,$mutation.Pattern).Count -eq 1)
            $source=Join-Path $dir ($mutation.Name+'.c')
            [IO.File]::WriteAllText($source,[regex]::Replace($sourceText,$mutation.Pattern,$mutation.Replacement))
            $object=Join-Path $dir ($mutation.Name+'.o')
            $mutantFlags=if ($mutation.Unit -eq 'reference') {$rflags} else {$nflags+$hostile}
            $null=Recorded $ArmGcc ($mutantFlags+@('-c',$source,'-o',$object)) (Join-Path $dir ($mutation.Name+'-compile.log'))
            $old=if ($mutation.Unit -eq 'reference') {$refObject} else {$nobjects[$mutation.Unit]}
            $objects=@($common | ForEach-Object {if ($_ -eq $old) {$object} else {$_}})+@($nobjects.doubles)
            $elf=Join-Path $dir ($mutation.Name+'.elf')
            $null=Recorded $ArmGcc ($nlink+$objects+@('-o',$elf)) (Join-Path $dir ($mutation.Name+'-link.log'))
            ExecuteCase $mutation.Name $mutation.Case $elf $sElf $dir $queryEntries $mutation.Check
        }
        if ($mode.Name -eq 'o2') {
            ExecuteCase 'classifier-fault' 900 (Join-Path $dir 'double.elf') $sElf $dir $queryEntries -RunnerFailure 'QEMU exit 91:'
            ExecuteCase 'classifier-missing-report' 901 (Join-Path $dir 'double.elf') $sElf $dir $queryEntries -RunnerFailure 'Missing/duplicate exact completion report'
            ExecuteCase 'classifier-timeout' 902 (Join-Path $dir 'double.elf') $sElf $dir $queryEntries -RunnerFailure 'TimeoutExpired'
        }
        Write-Host "PASS C55S attachment $($mode.Name): $($cases.Count) execution cases"
    }
    Check 'exact run inventory' ($runs.Count -eq $modes.Count*($cases.Count+8)+$(if ('o2' -in $modes.Name) {3} else {0}))
    $verdict='PASS'
} finally {
    $after=@($inputPaths | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
    $after | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $drift=@(Compare-Object $before $after -Property Path,Hash)
    if ($drift.Count) {$verdict='FAIL'}
    [pscustomobject]@{Verdict=$verdict;CompleteSuite=(!$PSBoundParameters.ContainsKey('DevelopmentModes') -and !$PSBoundParameters.ContainsKey('DevelopmentCases'));
        Modes=@($modes.Name);ExecutionCases=$runs.Count;Checks=$checks.Count;InputCount=$before.Count;
        InputDrift=$drift.Count;Runs=@($runs.ToArray());Assertions=@($checks.ToArray());
        Limits=@('staged NS constructor/attach only; no runtime/provider/start/switch qualification',
            'real two-image eight-query positive; explicitly labelled same-state NS query doubles for failures',
            'actual pinned no-MPU/no-FP/no-MVE initializer; preloaded GPR policy differs intentionally',
            'QEMU TCG mps3-an547, not hardware')} | ConvertTo-Json -Depth 8 |
        Set-Content (Join-Path $out 'results.json') -Encoding ASCII
    $artifacts=@(Get-ChildItem $out -Recurse -File | Where-Object {$_.Name -ne 'sha256.csv'})
    $artifacts | ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256} | Select-Object Path,Hash |
        Export-Csv (Join-Path $out 'sha256.csv') -NoTypeInformation -Encoding ASCII
    if ($drift.Count) {throw "C55S attachment inputs changed during run: $out"}
}
if ($verdict -ne 'PASS') {throw "C55S attachment failed: $out"}
Write-Host "PASS C55S attachment: $($runs.Count) execution cases; evidence $out"
