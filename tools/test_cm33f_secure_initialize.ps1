param(
    [string]$ArmGcc=$env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore=$env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot=$env:FREERTOS_KERNEL_REFERENCE,
    [string]$BuildRoot,
    [Parameter(Mandatory=$true)][string]$QemuRoot,
    [string]$WslDistro='Ubuntu-24.04',
    [string]$Python='python',
    [string]$PythonModules=$env:FIBER_CLASSIC_AUDIT_PYTHONPATH,
    [ValidateRange(5,120)][int]$TimeoutSeconds=30,
    [switch]$Smoke
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture=Join-Path $PSScriptRoot 'fixtures\cm33f_secure_initialize'
$previousFixture=Join-Path $PSScriptRoot 'fixtures\cm33f_secure_manifest'
$port=Join-Path $repo 'fiber\port\ARM_CM33F'
$secure=Join-Path $port 'secure'
$ns=Join-Path $port 'non_secure'
if (!$ArmGcc) {throw 'Supply existing ARM GCC; no provisioning or skip'}
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
if (!$QemuRoot.StartsWith('/')) {throw 'QemuRoot must name an existing absolute WSL path'}
if (!$CmsisCore) {$CmsisCore=Join-Path $repo '..\..\..\Drivers\CMSIS\Include'}
if (!$FreeRtosRoot) {$FreeRtosRoot=Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel'}
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot=(Resolve-Path -LiteralPath $FreeRtosRoot).Path
$reference=Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM33'
$bin=Split-Path $ArmGcc
$objdump=Join-Path $bin 'arm-none-eabi-objdump.exe'
$readelf=Join-Path $bin 'arm-none-eabi-readelf.exe'
$nm=Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$wsl=(Get-Command wsl.exe -ErrorAction Stop).Source
if (!$BuildRoot) {$BuildRoot=[IO.Path]::GetTempPath()}
$out=Join-Path $BuildRoot ('cm33f-secure-initialize-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out
$commands=Join-Path $out 'commands.jsonl'
$checks=New-Object System.Collections.Generic.List[object]
$runs=New-Object System.Collections.Generic.List[object]
$controls=New-Object System.Collections.Generic.List[object]
Write-Host "C3FS actual paired initializer evidence: $out"
# Reuse only generic command/evidence functions, not the old register model.
$generic=Join-Path $PSScriptRoot 'test_cm33f_secure_manifest.ps1'
$tokens=$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($generic,[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'Generic evidence helper source does not parse'}
foreach($name in @('Json','Run','Check','Compile','Elf')) {
    $definitions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object {$_.Name -eq $name})
    if ($definitions.Count -ne 1) {throw "Missing unique evidence function $name"}
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
function WslPath([string]$Path) {
    $r=Run $wsl @('-d',$WslDistro,'--exec','wslpath','-u',$Path) (Join-Path $out ('wslpath-'+[guid]::NewGuid().ToString('N')+'.txt'))
    return $r.Text.Trim()
}
function ExecuteCase([string]$Directory,[string]$SecureElf,[string]$NsElf,[string]$Manifest,[string]$Case,[string]$Control='none') {
    $r=Run $wsl @('-d',$WslDistro,'--exec','bash',($script:fixtureWsl+'/qemu.sh'),$QemuRoot,
        (WslPath $SecureElf),(WslPath $NsElf),"$TimeoutSeconds",(WslPath $Manifest),$Case,$Control) (Join-Path $Directory ($Case+'.log'))
    Check ($Directory+'/'+$Case) ($r.ExitCode -eq 0)
    $receipt=Get-Content -LiteralPath (Join-Path (Join-Path $Directory $Case) 'receipt.json') -Raw | ConvertFrom-Json
    if($receipt.Verdict -cne 'PASS') {throw "Execution receipt not PASS: $Case"}
    $runs.Add(@{Directory=$Directory;Case=$Case;Control=$Control;Outcome=$receipt.Outcome})
}
function LinkPair([string]$Directory,[string[]]$Flags,[string[]]$Production,[string[]]$SecureFixtures,[string[]]$NsFixtures,[string]$Control='none') {
    $se=Join-Path $Directory 'secure.elf'; $ne=Join-Path $Directory 'nonsecure.elf'; $imports=Join-Path $Directory 'imports.a'
    $null=Run $ArmGcc ($Flags+@('-mcmse','-save-temps=obj','-nostdlib','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--fatal-warnings',
        '-Wl,--cmse-implib',"-Wl,--out-implib=$imports",'-Wl,--section-start=.gnu.sgstubs=0x10008000',
        '-Wl,-e,Reset_Handler','-Wl,-u,fixture_real_imports','-Wl,-u,fixture_word_store','-Wl,-u,fixture_word_load',
        '-Wl,-u,fixture_control_store','-Wl,-u,fixture_control_ns_store','-Wl,-u,fixture_control_load','-Wl,-u,fixture_control_ns_load','-Wl,-u,fixture_masks_store',
        '-Wl,-u,fixture_basepri_store','-Wl,-u,fixture_faultmask_store',
        '-T',(Join-Path $fixture 'secure.ld'),'-T',(Join-Path $secure 'fiber_secure_context_cohort_contract.ld'))+
        $Production+$SecureFixtures+@("-Wl,-Map,$se.map",'-o',$se)) ($se+'.log')
    Elf $se
    $null=Run $ArmGcc ($Flags+@('-save-temps=obj','-nostdlib','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--fatal-warnings',
        '-Wl,-e,NS_Reset_Handler','-T',(Join-Path $fixture 'nonsecure.ld'))+$NsFixtures+@($imports,"-Wl,-Map,$ne.map",'-o',$ne)) ($ne+'.log')
    Elf $ne
    $manifest=Join-Path $Directory 'inspection.json'
    $r=Run $Python @('-B',(Join-Path $fixture 'image_audit.py'),$se,$ne,$manifest,$Control) (Join-Path $Directory 'inspection.log') -Fail
    if($Control -eq 'GRO') {
        Check ($Directory+'/exact-FP-envelope-rejection') ($r.ExitCode -eq 1 -and $r.Text -ceq 'REJECT:FP_ENVELOPE')
        return @{CodegenRejected=$true}
    }
    Check ($Directory+'/exact-production-text-byte-inspection') ($r.ExitCode -eq 0)
    return @{Secure=$se;Nonsecure=$ne;Manifest=$manifest}
}
$oldPythonPath=$env:PYTHONPATH
if (!$PythonModules) {$PythonModules=Join-Path $env:TEMP 'fiber-classic-audit-python'}
$env:PYTHONPATH=$PythonModules+[IO.Path]::PathSeparator+$oldPythonPath
$before=@(); $success=$false; $copies=New-Object System.Collections.Generic.List[object]
try {
    $r=Run $Python @('-B','-c',@'
import ctypes,sys
if sys.flags.optimize: raise SystemExit('No Python optimization permitted')
path=ctypes.create_unicode_buffer(32768)
if not ctypes.windll.kernel32.GetModuleFileNameW(None,path,len(path)): raise SystemExit('Interpreter image resolution failed')
print(path.value)
print(sys.version)
'@) (Join-Path $out 'python.txt')
    $inputs=@($PSCommandPath,$generic,$ArmGcc,$nm,$objdump,$readelf,$wsl,($r.Text -split "`n")[0].Trim(),
        (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h'),
        (Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards\aircr_rsp.py'))
    foreach($tool in @('cc1','lto1','lto-wrapper','as','ld','collect2')) {
        $r=Run $ArmGcc @("-print-prog-name=$tool") (Join-Path $out ("tool-$tool.txt"))
        $inputs+=(Resolve-Path -LiteralPath $r.Text.Trim()).Path
    }
    $r=Run $ArmGcc @('-print-file-name=include') (Join-Path $out 'compiler-include.txt')
    foreach($dir in @($port,$fixture,$previousFixture,$reference,$CmsisCore,$PythonModules,$r.Text.Trim(),
        (Join-Path $FreeRtosRoot 'include'),(Join-Path (Split-Path $bin) 'arm-none-eabi\include'))) {
        $inputs+=@(Get-ChildItem -LiteralPath $dir -Recurse -File | Where-Object {$_.FullName -notmatch '[\\/]__pycache__[\\/]'} | Select-Object -ExpandProperty FullName)
    }
    $inputs+=@(Get-ChildItem -LiteralPath (Join-Path $repo 'fiber'),(Join-Path $repo 'fiber\port') -File | Where-Object {$_.Extension -in @('.c','.h')} | Select-Object -ExpandProperty FullName)
    $before=@($inputs | Sort-Object -Unique | ForEach-Object {[pscustomobject]@{Path=$_;SHA256=(Get-FileHash -LiteralPath $_).Hash}})
    Json (Join-Path $out 'inputs.before.json') $before
    $snapshot=Join-Path $out 'source-snapshot'; $null=New-Item -ItemType Directory -Path $snapshot
    $serial=0
    foreach($item in $before) {
        if([IO.Path]::GetExtension($item.Path) -in @('.c','.h','.S','.ld','.py','.ps1','.sh')) {
            $serial++; $destination=Join-Path $snapshot ('{0:D4}-{1}' -f $serial,[IO.Path]::GetFileName($item.Path))
            Copy-Item -LiteralPath $item.Path -Destination $destination
            $copies.Add(@{Input=$item.Path;Snapshot=$destination;SHA256=$item.SHA256})
        }
    }
    Json (Join-Path $out 'source-snapshot.json') $copies.ToArray()
    $r=Run git @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.txt')
    Check 'exact-reference-pin' ($r.Text.Trim() -ceq 'a50edad08b29052631aa469d4df6e6ec7ff68878')
    $r=Run git @('-C',$FreeRtosRoot,'status','--porcelain','--untracked-files=all') (Join-Path $out 'reference-status.txt')
    Check 'reference-clean' ([string]::IsNullOrWhiteSpace($r.Text))
    $script:fixtureWsl=WslPath $fixture
    $wslOut=WslPath $out
    $envCommand=@('-d',$WslDistro,'--exec','env',"LD_LIBRARY_PATH=$QemuRoot/usr/lib/x86_64-linux-gnu",'python3',($script:fixtureWsl+'/environment.py'),$QemuRoot)
    $null=Run $wsl ($envCommand+@($wslOut+'/environment.before.json')) (Join-Path $out 'environment.before.log')
    $environment=Get-Content -LiteralPath (Join-Path $out 'environment.before.json') -Raw | ConvertFrom-Json
    Check 'actual-QEMU-AN505' ($environment.Machines -match '(?m)^mps2-an505\s')
    $base=@('-mcpu=cortex-m33','-mthumb','-mfpu=fpv5-sp-d16','-std=gnu11','-ffreestanding','-fno-builtin','-fno-common',
        '-ffunction-sections','-fdata-sections','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror',
        '-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV8M_MAINLINE=1',
        '-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT=3','-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES=256',
        "-I$fixture","-I$previousFixture","-I$secure","-I$ns","-I$repo","-I$(Join-Path $repo 'fiber')","-I$CmsisCore")
    $hostile=@('-finstrument-functions','-fstack-protector-all','-fsanitize=undefined','-fprofile-arcs','-ftest-coverage','-fsanitize-coverage=trace-pc')
    $cases=@('success','secure-spSEL2','masks','gate-init','gate-ready','gate-unknown','pool-marker-init','pool-marker-ready','pool-marker-unknown',
        'control-4','control-6','control-8','control-10','control-14','ns-control-4','ns-control-6','control-ns-read-4','control-ns-read-6','lspact-s','lspact-ns','lspact-both','bfhfnmins',
        'init-cpacr0','init-cpacr3','init-cpacr5','init-npriv','readback-aircr','readback-psplim','readback-psp',
        'pool-result-0','pool-result-2','readback-control-6','readback-control-10','readback-control-14',
        'readback-nsacr','readback-lspens','readback-ts','trap-gate-initial','trap-gate-ready','trap-pool-initial','trap-pool-ready',
        'scrub-first','scrub-last','pool-state-corrupt','pool-entry-unknown','pool-entry-init','pool-entry-ready')
    foreach($index in 0..7) {$cases+=@("query-$index-cpacr0","query-$index-npriv")}
    $cases+=@('query-0-cpacr3','query-0-cpacr5')
    foreach($abi in @('hard','softfp')) {foreach($opt in @('-O2','-Os')) {foreach($lto in @($false,$true)) {
        if($Smoke -and ($abi -ne 'hard' -or $opt -ne '-O2' -or $lto)) {continue}
        $flags=$base+@("-mfloat-abi=$abi",$opt); if($lto){$flags+=@('-flto')}
        $name=$abi+'-'+$opt.Substring(1)+'-'+$(if($lto){'lto'}else{'normal'})
        $directory=Join-Path $out $name; $null=New-Item -ItemType Directory -Path $directory
        $secureFixtures=@(); $nsFixtures=@()
        foreach($unit in @('startup.S','secure.c','support.c')) {
            $object=Join-Path $directory ('fixture-secure-'+$unit+'.o')
            Compile (Join-Path $fixture $unit) $object ($flags+@('-mcmse','-DFIXTURE_SECURE=1'))
            $secureFixtures+=$object
        }
        $root=Join-Path $directory 'real-import-roots.o'
        Compile (Join-Path $previousFixture 'queries.c') $root ($flags+@('-mcmse'))
        $secureFixtures+=$root
        foreach($unit in @('startup.S','nonsecure.c','support.c')) {
            $object=Join-Path $directory ('fixture-NS-'+$unit+'.o')
            Compile (Join-Path $fixture $unit) $object $flags; $nsFixtures+=$object
        }
        foreach($kind in @('normal','hostile')) {
            if($Smoke -and $kind -eq 'hostile'){continue}
            $mode=Join-Path $directory $kind; $null=New-Item -ItemType Directory -Path $mode
            $pf=$flags+@('-mcmse'); if($kind -eq 'hostile'){$pf+=$hostile}
            $production=@()
            foreach($unit in @('fiber_secure_gateway','fiber_secure_context_gateway','fiber_secure_context_pool')) {
                $object=Join-Path $mode ($unit+'.o'); Compile (Join-Path $secure ($unit+'.c')) $object $pf; $production+=$object
            }
            $pair=LinkPair $mode $flags $production $secureFixtures $nsFixtures
            Check ($name+'/'+$kind+'/no-hidden-hooks') ((Get-Content -LiteralPath ($pair.Secure+'.nm') -Raw) -notmatch '__cyg_profile|__stack_chk|__ubsan|__asan|__gcov|__sanitizer|\bmcount\b')
            $selected=$cases
            if($kind -eq 'hostile') {$selected=@('success','init-cpacr0','init-npriv','query-0-cpacr0','query-0-npriv',
                'ns-control-4','control-8','lspact-s','lspact-ns','readback-control-6','trap-gate-initial')}
            if($Smoke){$selected=@('success','masks','query-0-npriv','control-ns-read-4','scrub-last')}
            foreach($case in $selected) {ExecuteCase $mode $pair.Secure $pair.Nonsecure $pair.Manifest $case}
            Write-Host "PASS paired C3FS $name $kind / $($selected.Count) actual CPU cases"
            if(!$Smoke -and !$lto -and $kind -eq 'normal') {
                $changes=@(
                    @{Name='query-preflight';Unit='fiber_secure_gateway';From='    fiber_secure_c3fs_query_preflight();';To='';FirstOnly=$true;Case='query-0-cpacr0'},
                    @{Name='ns-fpca';Unit='fiber_secure_context_gateway';From='((control_ns & 4u) != 0u)';To='(0u != 0u)';Case='control-ns-read-4'},
                    @{Name='pool-exact';Unit='fiber_secure_context_gateway';From='fiber_secure_context_pool_boot_initialize() != 1u';To='fiber_secure_context_pool_boot_initialize() == 0u';Case='pool-result-2'},
                    @{Name='control-exact';Unit='fiber_secure_context_gateway';From='if (control != 2u)';To='if (0u != 0u)';Case='readback-control-6'},
                    @{Name='GRO';Unit='fiber_secure_gateway';Case='none'},
                    @{Name='fp-nop';Unit='nonsecure';Case='success'})
                foreach($change in $changes) {
                    $cd=Join-Path $mode ('control-'+$change.Name); $null=New-Item -ItemType Directory -Path $cd
                    $objects=@($production); $nf=@($nsFixtures)
                    if($change.Name -eq 'fp-nop') {
                        $object=Join-Path $cd 'nonsecure.o'
                        Compile (Join-Path $fixture 'nonsecure.c') $object ($flags+@('-DFIXTURE_FP_NOP_CONTROL=1'))
                        $nf=@($nsFixtures | ForEach-Object {if([IO.Path]::GetFileName($_) -eq 'fixture-NS-nonsecure.c.o'){$object}else{$_}})
                    } else {
                        $original=Join-Path $secure ($change.Unit+'.c')
                        $object=Join-Path $cd 'mutant.o'; $controlFlags=$pf
                        if($change.Name -eq 'GRO') {
                            $source=$original; $controlFlags+=@('-DFIBER_GENERAL_REGS_ONLY=')
                            Json (Join-Path $cd 'mutation.json') @{Original=$original;OriginalSHA256=(Get-FileHash -LiteralPath $original).Hash;
                                CompilerControl='FIBER_GENERAL_REGS_ONLY=';SemanticChanges=1}
                        } else {
                            $text=Get-Content -LiteralPath $original -Raw
                            $matches=[regex]::Matches($text,[regex]::Escape($change.From))
                            $firstOnly=$change.ContainsKey('FirstOnly')
                            Check ($cd+'/exact-mutation-count') ($matches.Count -eq $(if($firstOnly){4}else{1}))
                            $position=$text.IndexOf($change.From)
                            $mutant=$text.Remove($position,$change.From.Length).Insert($position,$change.To)
                            $source=Join-Path $cd 'mutant.c'; $mutant | Set-Content -LiteralPath $source -Encoding ASCII
                            Json (Join-Path $cd 'mutation.json') @{Original=$original;OriginalSHA256=(Get-FileHash -LiteralPath $original).Hash;
                                Mutant=$source;MutantSHA256=(Get-FileHash -LiteralPath $source).Hash;From=$change.From;To=$change.To;SemanticChanges=1}
                        }
                        Compile $source $object $controlFlags
                        $objects=@($production | ForEach-Object {if([IO.Path]::GetFileName($_) -eq ($change.Unit+'.o')){$object}else{$_}})
                    }
                    $cp=LinkPair $cd $flags $objects $secureFixtures $nf $change.Name
                    if($change.Name -ne 'GRO') {ExecuteCase $cd $cp.Secure $cp.Nonsecure $cp.Manifest $change.Case $change.Name}
                    $controls.Add(@{Configuration=$name;Name=$change.Name;Directory=$cd;Status='PASS'})
                }
                # Preserve complete current pinned NS/Secure FP source bodies,
                # not reference-shaped rewrites or an integer-only reference.
                $rd=Join-Path $directory 'reference'; $null=New-Item -ItemType Directory -Path $rd
                $rf=@('-mcpu=cortex-m33','-mthumb','-mfpu=fpv5-sp-d16',"-mfloat-abi=$abi",$opt,'-std=gnu11',
                    '-ffreestanding','-fno-builtin','-ffunction-sections','-fdata-sections',"-I$previousFixture",
                    "-I$(Join-Path $reference 'secure')","-I$(Join-Path $reference 'non_secure')","-I$(Join-Path $FreeRtosRoot 'include')")
                foreach($unit in @('secure_context','secure_context_port','secure_init','secure_heap')) {
                    Compile (Join-Path $reference ('secure\'+$unit+'.c')) (Join-Path $rd ($unit+'.o')) ($rf+@('-mcmse'))
                }
                foreach($unit in @('port','portasm')) {Compile (Join-Path $reference ('non_secure\'+$unit+'.c')) (Join-Path $rd ($unit+'.o')) $rf}
            }
        }
    }}}
    $null=Run $wsl ($envCommand+@($wslOut+'/environment.after.json')) (Join-Path $out 'environment.after.log')
    Check 'WSL-QEMU-interpreter-DSO-inputs-unchanged' ((Get-FileHash -LiteralPath (Join-Path $out 'environment.before.json')).Hash -ceq
        (Get-FileHash -LiteralPath (Join-Path $out 'environment.after.json')).Hash)
    $success=$true
} finally {
    $env:PYTHONPATH=$oldPythonPath
    $after=@($before | ForEach-Object {[pscustomobject]@{Path=$_.Path;SHA256=(Get-FileHash -LiteralPath $_.Path).Hash}})
    Json (Join-Path $out 'inputs.after.json') $after
    $lookup=@{}; foreach($item in $before){$lookup[$item.Path]=$item.SHA256}
    $drift=@($after | Where-Object {$_.SHA256 -cne $lookup[$_.Path]})
    Json (Join-Path $out 'checks.json') $checks.ToArray()
    Json (Join-Path $out 'runs.json') $runs.ToArray()
    Json (Join-Path $out 'controls.json') $controls.ToArray()
    Json (Join-Path $out 'receipt.json') @{Verdict=$(if($success -and !$drift.Count){'PASS'}else{'FAIL'});DevelopmentOnly=[bool]$Smoke;
        Cases=$runs.Count;Checks=$checks.Count;Controls=$controls.Count;Inputs=$before.Count;InputDrift=$drift;Evidence=$out;
        Limits='Actual AN505 SG and banked FP initialization, with labelled hardware-register/memory fault injections; no allocation, lazy FP save/load, full runtime or board equivalence.'}
    $artifacts=@(Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object {[pscustomobject]@{Path=$_.FullName.Substring($out.Length+1);SHA256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
    Json (Join-Path $out 'artifacts.json') $artifacts
    if($drift.Count){throw "C3FS paired input drift: $out"}
}
Write-Host "PASS C3FS paired initializer $($runs.Count) CPU cases: $out"
