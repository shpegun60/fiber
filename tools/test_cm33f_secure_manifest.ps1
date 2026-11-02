param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$BuildRoot,
    [string]$Python = 'python',
    [string]$PythonModules = $env:FIBER_CLASSIC_AUDIT_PYTHONPATH
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $repo 'tools/runtime_sources.ps1')
$runtimeRoles=@('engine','legacy_compat')
$coldCommonSources=@(Get-RuntimeSourcePaths -RepositoryRoot $repo -Roles $runtimeRoles)
$coldCommonNames=@($coldCommonSources | ForEach-Object {$_.Substring($repo.Length+1).Replace('\','_').Replace('/','_')+'.o'})
$fixture=Join-Path $PSScriptRoot 'fixtures\cm33f_secure_manifest'
$port=Join-Path $repo 'fiber\port\ARM_CM33F'
$ns=Join-Path $port 'non_secure'
$secure=Join-Path $port 'secure'
if (!$ArmGcc) {
    $found=Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($found) {$ArmGcc=$found.Source}
}
if (!$ArmGcc) {throw 'Supply existing -ArmGcc; no installation/skip'}
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
if (!$CmsisCore) {$CmsisCore=Join-Path $repo '..\..\..\Drivers\CMSIS\Include'}
if (!$FreeRtosRoot) {$FreeRtosRoot=Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel'}
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot=(Resolve-Path -LiteralPath $FreeRtosRoot).Path
$reference=Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM33'
$bin=Split-Path $ArmGcc
$gxx=Join-Path $bin 'arm-none-eabi-g++.exe'
$nm=Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$ar=Join-Path $bin 'arm-none-eabi-gcc-ar.exe'
$objdump=Join-Path $bin 'arm-none-eabi-objdump.exe'
$readelf=Join-Path $bin 'arm-none-eabi-readelf.exe'
foreach ($p in @($gxx,$nm,$ar,$objdump,$readelf,(Join-Path $CmsisCore 'core_cm33.h'),
        (Join-Path $ns 'fiber_port_boot.c'),(Join-Path $fixture 'run.py'))) {
    if (!(Test-Path -LiteralPath $p -PathType Leaf)) {throw "Missing input $p"}
}
if (!$BuildRoot) {$BuildRoot=[IO.Path]::GetTempPath()}
$out=Join-Path $BuildRoot ('cm33f-secure-manifest-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out
Write-Host "C3FS staged manifest evidence: $out"
$commands=Join-Path $out 'commands.jsonl'
$checks=New-Object System.Collections.Generic.List[object]
$runs=New-Object System.Collections.Generic.List[object]
$executions=New-Object System.Collections.Generic.List[object]
$controls=New-Object System.Collections.Generic.List[object]
$initializers=New-Object System.Collections.Generic.List[object]
function Json([string]$Path,[object]$Value) {
    ConvertTo-Json -InputObject $Value -Depth 10 | Set-Content -LiteralPath $Path -Encoding ASCII
}
function Run([string]$Program,[string[]]$Arguments,[string]$Log,[switch]$Fail) {
    $old=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $lines=@(& $Program @Arguments 2>&1 | ForEach-Object {"$_"})
        $code=$LASTEXITCODE
    } finally {$ErrorActionPreference=$old}
    $text=$lines -join "`n"
    $text | Set-Content -LiteralPath $Log -Encoding ASCII
    @{Program=$Program;Arguments=$Arguments;ExitCode=$code;Log=$Log} |
        ConvertTo-Json -Compress -Depth 6 | Add-Content -LiteralPath $commands -Encoding ASCII
    if ($code -ne 0 -and !$Fail) {throw "Command failed ($code): $Log`n$text"}
    [pscustomobject]@{ExitCode=$code;Text=$text}
}
function Check([string]$Name,[bool]$Condition) {
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$Condition})
    if (!$Condition) {throw "C3FS check failed: $Name"}
}
function Compile([string]$Source,[string]$Object,[string[]]$Flags) {
    $null=Run $ArmGcc ($Flags+@('-save-temps=obj','-MD','-fstack-usage','-c',$Source,'-o',$Object)) ($Object+'.log')
    $null=Run $objdump @('-drwC',$Object) ($Object+'.dis')
    $null=Run $readelf @('-hA','-sW','-SW','-rW',$Object) ($Object+'.attributes')
}
function Elf([string]$Path) {
    $r=Run $nm @('-u',$Path) ($Path+'.undefined')
    Check ($Path+'/no-undefined') ([string]::IsNullOrWhiteSpace($r.Text))
    $null=Run $nm @('-S',$Path) ($Path+'.nm')
    $r=Run $readelf @('-hA','-SW','-sW',$Path) ($Path+'.attributes')
    Check ($Path+'/v8-M-only') ($r.Text -match 'Tag_CPU_arch:\s+v8-M.main' -and
        $r.Text -notmatch 'Tag_CPU_arch:\s+v8.1-M|Tag_MVE_arch|Tag_PAC_extension|Tag_BTI_extension')
    $null=Run $objdump @('-dwC','-z',$Path) ($Path+'.dis')
}
function NegativeCompile([string]$Name,[string]$Source,[string[]]$Flags,[string]$Diagnostic) {
    $r=Run $ArmGcc ($Flags+@('-c',$Source,'-o',(Join-Path $out ($Name+'.o')))) (Join-Path $out ($Name+'.log')) -Fail
    Check ($Name+'/compile-rejection') ($r.ExitCode -ne 0 -and $r.Text.Contains($Diagnostic))
}
function IdentityBodies([string]$Elf,[string]$Path) {
    $parts=@()
    foreach($suffix in @('abi_version','context_port_id','context_layout_version','context_feature_mask')) {
        $r=Run $objdump @('-dwC',"--disassemble=__acle_se_fiber_secure_gateway_c3fs_v1_$suffix",$Elf) ($Path+'.'+$suffix)
        $parts+=$r.Text
    }
    $parts -join "`n" | Set-Content -LiteralPath $Path -Encoding ASCII
}
function OracleReject([string]$Mode,[string]$Path,[string]$Diagnostic,[string]$Log,[string]$Kind='CompiledSource') {
    $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),$Mode,$Path) $Log -Fail
    Check ($Log+'/exact-rejection') ($r.ExitCode -eq 1 -and $r.Text -ceq ('REJECT:'+$Diagnostic))
    $controls.Add(@{Mode=$Mode;Artifact=$Path;Rejection=$Diagnostic;Kind=$Kind})
}
function MissingOnly([string]$Name,[string[]]$Arguments,[string[]]$Expected) {
    $r=Run $ArmGcc $Arguments (Join-Path $out ($Name+'.log')) -Fail
    $actual=@([regex]::Matches($r.Text,"undefined reference to ``([^']+)'") |
        ForEach-Object {$_.Groups[1].Value} | Sort-Object -Unique)
    Check ($Name+'/exact-missing-set') ($r.ExitCode -ne 0 -and $actual.Count -eq $Expected.Count -and
        !(Compare-Object @($Expected|Sort-Object) $actual))
}
$oldPythonPath=$env:PYTHONPATH
if (!$PythonModules) {$PythonModules=Join-Path $env:TEMP 'fiber-classic-audit-python'}
$env:PYTHONPATH=$PythonModules+[IO.Path]::PathSeparator+$oldPythonPath
$pythonInfo=Run $Python @('-B','-c',@'
import sys, ctypes, importlib.metadata as m
if sys.flags.optimize: raise SystemExit('C3FS proof rejects Python optimization')
for name, version in [('unicorn','2.1.4'),('pyelftools','0.33')]:
    if m.version(name)!=version: raise SystemExit('Required '+name+'=='+version)
image=ctypes.create_unicode_buffer(32768)
if not ctypes.windll.kernel32.GetModuleFileNameW(None,image,len(image)):
    raise SystemExit('Cannot resolve actual Python executable image')
print(image.value)
print(sys.version)
'@) (Join-Path $out 'python.txt')
$inputs=@($PSCommandPath,$ArmGcc,$gxx,$nm,$ar,$objdump,$readelf,
    (($pythonInfo.Text -split "`n")[0].Trim()))+
    @(Get-RuntimeSourceInputs -RepositoryRoot $repo -Roles $runtimeRoles)+
    @(Get-ChildItem (Join-Path $repo 'context') -File|Where-Object {$_.Extension -in @('.c','.h')}|Select-Object -ExpandProperty FullName)
foreach ($tool in @('cc1','cc1plus','lto1','lto-wrapper','as','ld','collect2')) {
    $r=Run $ArmGcc @("-print-prog-name=$tool") (Join-Path $out ("tool-$tool.txt"))
    $inputs+=(Resolve-Path -LiteralPath $r.Text.Trim()).Path
}
$r=Run $ArmGcc @('-print-file-name=include') (Join-Path $out 'compiler-includes.txt')
foreach ($dir in @($fixture,$port,$CmsisCore,$reference,(Join-Path $FreeRtosRoot 'include'),
        $r.Text.Trim(),(Join-Path (Split-Path $bin) 'arm-none-eabi\include'),$PythonModules)) {
    $inputs+=@(Get-ChildItem -LiteralPath $dir -Recurse -File |
        Where-Object {$_.FullName -notmatch '[\\/]__pycache__[\\/]'} | Select-Object -ExpandProperty FullName)
}
$inputs+=@(Get-ChildItem -LiteralPath (Join-Path $repo 'fiber'),(Join-Path $repo 'fiber\port') -File |
    Where-Object {$_.Extension -in @('.c','.h')} | Select-Object -ExpandProperty FullName)
$before=@($inputs | Sort-Object -Unique | ForEach-Object {
    [pscustomobject]@{Path=$_;Sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
})
Json (Join-Path $out 'inputs.before.json') $before
$snapshot=Join-Path $out 'source-snapshot'
$null=New-Item -ItemType Directory -Path $snapshot
$copies=New-Object System.Collections.Generic.List[object]
$serial=0
foreach($input in $before) {
    if([IO.Path]::GetExtension($input.Path) -in @('.c','.h','.ld','.py','.ps1')) {
        $serial++
        $destination=Join-Path $snapshot ('{0:D4}-{1}' -f $serial,[IO.Path]::GetFileName($input.Path))
        Copy-Item -LiteralPath $input.Path -Destination $destination
        $copies.Add(@{Input=$input.Path;Snapshot=$destination;SHA256=$input.Sha256})
    }
}
Json (Join-Path $out 'source-snapshot.json') $copies.ToArray()
$ok=$false
try {
    $r=Run git @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.txt')
    Check 'exact-reference-pin' ($r.Text.Trim() -ceq 'a50edad08b29052631aa469d4df6e6ec7ff68878')
    $r=Run git @('-C',$FreeRtosRoot,'status','--porcelain','--untracked-files=all') (Join-Path $out 'reference-status.txt')
    Check 'clean-reference' ([string]::IsNullOrWhiteSpace($r.Text))
    $null=Run $ArmGcc @('--version') (Join-Path $out 'compiler.txt')
    $base=@('-mcpu=cortex-m33','-mthumb','-mfpu=fpv5-sp-d16','-std=gnu11','-ffreestanding',
        '-fno-builtin','-fno-common','-ffunction-sections','-fdata-sections','-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror',
        '-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV8M_MAINLINE=1',
        "-I$fixture","-I$ns","-I$secure","-I$repo","-I$(Join-Path $repo 'fiber')","-I$CmsisCore")
    foreach ($abi in @('hard','softfp')) {
      foreach ($opt in @('-O2','-Os')) {
       foreach ($lto in @($false,$true)) {
        $name=$abi+'-'+$opt.Substring(1)+'-'+$(if($lto){'lto'}else{'normal'})
        $dir=Join-Path $out $name
        $null=New-Item -ItemType Directory -Path $dir
        $flags=$base+@("-mfloat-abi=$abi",$opt)
        if ($lto) {$flags+=@('-flto')}
        foreach ($language in @('c','c++')) {
            $compiler=if($language -eq 'c'){$ArmGcc}else{$gxx}
            $std=if($language -eq 'c'){'-std=gnu11'}else{'-std=c++17'}
            $lf=@($flags | Where-Object {$_ -ne '-std=gnu11'})+@('-x',$language,$std)
            foreach ($file in @('manifest.c','public.c','queries.c')) {
                $r=Run $compiler ($lf+@('-c',(Join-Path $fixture $file),'-o',(Join-Path $dir ($file+'.'+$language+'.o')))) (Join-Path $dir ($file+'.'+$language+'.log'))
                Check ($name+'/'+$language+'/'+$file) ($r.ExitCode -eq 0)
            }
        }
        $sf=$flags+@('-mcmse','-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT=(1+2)',
            '-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES=(32*8)')
        $hostile=@('-finstrument-functions','-fstack-protector-all','-fsanitize=undefined',
            '-fprofile-arcs','-ftest-coverage','-fsanitize-coverage=trace-pc')
        $so=@()
        foreach ($unit in @('fiber_secure_gateway','fiber_secure_context_gateway','fiber_secure_context_pool')) {
            $object=Join-Path $dir ($unit+'.o')
            Compile (Join-Path $secure ($unit+'.c')) $object $sf
            $so+=$object
        }
        $archive=Join-Path $dir 'companion.a'
        $null=Run $ar (@('rcs',$archive)+$so) (Join-Path $dir 'archive.log')
        $secureRoot=Join-Path $dir 'secure-root.o'
        Compile (Join-Path $fixture 'queries.c') $secureRoot $sf
        $se=Join-Path $dir 'secure.elf'
        $imports=Join-Path $dir 'imports.a'
        # Ordinary C calls root eight queries plus init and extract the pool
        # helper. No whole-archive, -u cohort/helper or magic linker extractor.
        $sl=$sf+@('-save-temps=obj','-nostdlib','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--fatal-warnings',
            '-Wl,--cmse-implib',"-Wl,--out-implib=$imports",'-Wl,--section-start=.gnu.sgstubs=0x10020000',
            '-T',(Join-Path $fixture 'secure.ld'),'-T',(Join-Path $secure 'fiber_secure_context_cohort_contract.ld'))
        $null=Run $ArmGcc ($sl+@('-Wl,-e,fixture_real_imports',$secureRoot,$archive,"-Wl,-Map,$se.map",'-o',$se)) ($se+'.log')
        Elf $se
        $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),'query-bodies',$se) ($se+'.body-execution.json')
        $executions.Add(($r.Text | ConvertFrom-Json))
        $hostileSecure=@()
        foreach($unit in @('fiber_secure_gateway','fiber_secure_context_gateway','fiber_secure_context_pool')) {
            $object=Join-Path $dir ($unit+'-hostile.o')
            Compile (Join-Path $secure ($unit+'.c')) $object ($sf+$hostile)
            $hostileSecure+=$object
        }
        $he=Join-Path $dir 'secure-hostile.elf'
        $hsl=@($sl | Where-Object {$_ -notlike '-Wl,--out-implib=*'})+
            @("-Wl,--out-implib=$he.imports.a")
        $null=Run $ArmGcc ($hsl+@('-Wl,-e,fixture_real_imports',$secureRoot)+$hostileSecure+@('-o',$he)) ($he+'.log')
        Elf $he
        Check ($name+'/raw-hostile-Secure-no-instrumentation') ((Get-Content -LiteralPath ($he+'.nm') -Raw) -notmatch '__cyg_profile|__stack_chk|__ubsan|__asan|__gcov|__sanitizer')
        $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),'query-bodies',$he) ($he+'.body-execution.json')
        $executions.Add(($r.Text | ConvertFrom-Json))
        $defined=Get-Content -LiteralPath ($se+'.nm') -Raw
        Check ($name+'/one-exact-key') ([regex]::Matches($defined,'(?m)^\S+\s+00000001\s+R\s+fiber_secure_context_cohort_c3fs_g2_').Count -eq 1)
        Check ($name+'/no-transfer-export') ($defined -notmatch 'c3fs_v1_(allocate|load|save)\b|fiber_port_runtime_|SVC_Handler|PendSV_Handler')
        # Audit both final image sets, including hostile/LTO CMSE envelopes.
        foreach($codeImage in @(@{Kind='normal';Elf=$se},@{Kind='hostile';Elf=$he})) {
          $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),'init-codegen',$codeImage.Elf) ($codeImage.Elf+'.initializer-codegen.json')
          Check ($name+'/'+$codeImage.Kind+'/initializer-no-FP-envelope') ($r.ExitCode -eq 0)
          $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),'init-bodies',$codeImage.Elf) ($codeImage.Elf+'.initializer-execution.json')
          $initializers.Add(($r.Text | ConvertFrom-Json))
          $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),'query-entries',$codeImage.Elf) ($codeImage.Elf+'.entries.json')
          Check ($name+'/'+$codeImage.Kind+'/actual-SG-entries') ($r.ExitCode -eq 0)
          foreach ($unit in @('fiber_secure_gateway','fiber_secure_context_gateway')) {
            $body=Join-Path $dir ($unit+'.'+$codeImage.Kind+'.bodies.dis')
            $names=if($unit -eq 'fiber_secure_gateway'){@('abi_version','context_port_id','context_layout_version','context_feature_mask')}else{@('abi_version','stack_alignment','max_stack_bytes','max_contexts')}
            $prefix=if($unit -eq 'fiber_secure_gateway'){'fiber_secure_gateway'}else{'fiber_secure_context_gateway'}
            $bodyText=@()
            foreach ($suffix in $names) {
                $r=Run $objdump @('-dwC',"--disassemble=__acle_se_${prefix}_c3fs_v1_$suffix",$codeImage.Elf) (Join-Path $dir ($unit+'-'+$codeImage.Kind+'-'+$suffix+'.dis'))
                $bodyText+=$r.Text
            }
            $bodyText -join "`n" | Set-Content -LiteralPath $body -Encoding ASCII
            $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),'query-codegen',$body) ($body+'.json')
            Check ($name+'/'+$unit+'/'+$codeImage.Kind+'/preflight-no-FP-envelope') ($r.ExitCode -eq 0)
          }
        }
        $qe=Join-Path $dir 'actual-imports.elf'
        $null=Run $ArmGcc ($flags+@('-nostdlib','-Wl,--gc-sections','-Wl,--no-undefined',
            '-Wl,-e,fixture_real_imports','-T',(Join-Path $fixture 'image.ld'),
            (Join-Path $dir 'queries.c.c.o'),$imports,'-o',$qe)) ($qe+'.log')
        Elf $qe
        foreach ($reserved in @($false,$true)) {
            $mode=$name+'-'+$(if($reserved){'reserved-r9'}else{'ordinary-r9'})
            $cd=Join-Path $dir $(if($reserved){'reserved'}else{'ordinary'})
            $null=New-Item -ItemType Directory -Path $cd
            $cf=$flags
            if($reserved){$cf+=@('-ffixed-r9')}
            $objects=@();$coldCommonObjects=@()
            foreach ($source in (@((Join-Path $ns 'fiber_port_boot.c'),(Join-Path $ns 'fiber_port_secure_context.c'))+
                $coldCommonSources+@((Join-Path $fixture 'probe.c')))) {
                $isCommon=$source -in $coldCommonSources
                $objectName=if($isCommon){$source.Substring($repo.Length+1).Replace('\','_').Replace('/','_')+'.o'}else{[IO.Path]::GetFileNameWithoutExtension($source)+'.o'}
                $object=Join-Path $cd $objectName
                $unitFlags=$cf
                if($isCommon) {
                    # fiber_init/task_return are unchanged actual functions.
                    # Only other, discarded APIs carry this placement macro;
                    # prevent LTO merging them into attachment's section. No
                    # fabricated schedule/current/forward operation is linked.
                    $unitFlags+=@('-DFIBER_API_THREAD_FUNCTION=')
                }
                Compile $source $object $unitFlags
                $objects+=$object
                if($isCommon){$coldCommonObjects+=$object}
            }
            $elf=Join-Path $cd 'constructor.elf'
            $coldLink=$cf+@('-save-temps=obj','-nostdlib','-Wl,--gc-sections','-Wl,--no-undefined',
                '-Wl,-u,fiber_port_secure_context_attach','-Wl,-u,fixture_task',
                '-Wl,-u,c3fs_consumer_storage','-T',(Join-Path $fixture 'image.ld'))
            $null=Run $ArmGcc ($coldLink+$objects+@((Join-Path $dir 'public.c.c++.o'),'-o',$elf)) ($elf+'.log')
            Elf $elf
            $symbols=Get-Content -LiteralPath ($elf+'.nm') -Raw
            Check ($mode+'/no-fake-runtime') ($symbols -notmatch '\b(?:SVC_Handler|PendSV_Handler|fiber_port_runtime_\w+|fiber_port_runtime_bundle_\w+)\b')
            $manifest=Join-Path $cd 'execute.json'
            Json $manifest @{Name=$mode;Elf=$elf;Reserved=$reserved}
            $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),'execute',$manifest) (Join-Path $cd 'execution.json')
            $executions.Add(($r.Text | ConvertFrom-Json))
            if(!$reserved) {
                $hostileCold=@()
                foreach($unit in @('fiber_port_boot','fiber_port_secure_context')) {
                    $object=Join-Path $cd ($unit+'-hostile.o')
                    Compile (Join-Path $ns ($unit+'.c')) $object ($cf+$hostile)
                    $hostileCold+=$object
                }
                $he=Join-Path $cd 'constructor-hostile.elf'
                $null=Run $ArmGcc ($coldLink+$hostileCold+$coldCommonObjects+@(
                    (Join-Path $cd 'probe.o'),(Join-Path $dir 'public.c.c++.o'),'-o',$he)) ($he+'.log')
                Elf $he
                Check ($name+'/raw-hostile-NS-no-instrumentation') ((Get-Content -LiteralPath ($he+'.nm') -Raw) -notmatch '__cyg_profile|__stack_chk|__ubsan|__asan|__gcov|__sanitizer')
                $hm=Join-Path $cd 'execute-hostile.json'
                Json $hm @{Name=($mode+'-raw-hostile-port');Elf=$he;Reserved=$false}
                $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),'execute',$hm) (Join-Path $cd 'execution-hostile.json')
                $executions.Add(($r.Text | ConvertFrom-Json))
            }
        }
        # Actual unchanged reference constructor, retained alone under GC.
        if (!$lto) {
            $rf=@('-mcpu=cortex-m33','-mthumb','-mfpu=fpv5-sp-d16',"-mfloat-abi=$abi",$opt,
                '-std=gnu11','-ffreestanding','-ffunction-sections','-fdata-sections',"-I$fixture",
                "-I$(Join-Path $reference 'non_secure')","-I$(Join-Path $reference 'secure')",
                "-I$(Join-Path $FreeRtosRoot 'include')")
            $ro=Join-Path $dir 'reference.o'
            Compile (Join-Path $reference 'non_secure\port.c') $ro $rf
            $ra=Join-Path $dir 'reference-portasm.o'
            Compile (Join-Path $reference 'non_secure\portasm.c') $ra $rf
            $re=Join-Path $dir 'reference.elf'
            $null=Run $ArmGcc ($rf+@('-nostdlib','-Wl,--gc-sections','-Wl,--no-undefined',
                '-Wl,-e,pxPortInitialiseStack','-T',(Join-Path $fixture 'image.ld'),$ro,$ra,'-o',$re)) ($re+'.log')
            Elf $re
            $r=Run $Python @('-B',(Join-Path $fixture 'run.py'),'reference',$re) ($re+'.execution.json')
            $executions.Add(($r.Text | ConvertFrom-Json))
            # Actual unchanged FP Secure source bytes and complete generated
            # functions, not a rewritten reference-shaped implementation.
            foreach($unit in @('secure_context','secure_context_port','secure_init','secure_heap')) {
                $object=Join-Path $dir ('reference-'+$unit+'.o')
                Compile (Join-Path $reference ('secure\'+$unit+'.c')) $object ($rf+@('-mcmse'))
            }
            $referenceInit=Get-Content -LiteralPath (Join-Path $dir 'reference-secure_init.o.dis') -Raw
            Check ($name+'/actual-reference-FP-policy-functions') ($referenceInit -match 'SecureInit_EnableNSFPUAccess' -and
                $referenceInit -match 'SecureInit_DePrioritizeNSExceptions')
        }
        $runs.Add(@{Name=$name;Companion=$se;ActualImports=$qe})
        Write-Host "PASS C3FS $name / C,C++ + nine-entry companion + two actual constructor ABI modes"
       }
      }
    }
    $nf=$base+@('-mfloat-abi=hard','-O2')
    NegativeCompile 'soft-no-FP' (Join-Path $fixture 'manifest.c') ($base+@('-mfloat-abi=soft')) 'scalar-SP __ARM_FP == 4'
    NegativeCompile 'double-FP' (Join-Path $fixture 'manifest.c') ($nf+@('-mfpu=fpv5-d16')) 'scalar-SP __ARM_FP == 4'
    NegativeCompile 'Secure-as-NS' (Join-Path $fixture 'manifest.c') ($nf+@('-mcmse')) 'Non-secure CMSE level 1'
    NegativeCompile 'missing-FPU' (Join-Path $fixture 'manifest.c') ($nf+@('-D__FPU_PRESENT=0')) 'scalar-SP __ARM_FP == 4'
    NegativeCompile 'runtime-override' (Join-Path $fixture 'manifest.c') ($nf+@('-DFIBER_PORT_RUNTIME_SELECTABLE=1')) 'must not be predefined'
    NegativeCompile 'MPU-region' (Join-Path $fixture 'manifest.c') ($nf+@('-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=8')) 'does not accept an MPU region manifest'
    NegativeCompile 'MVE' (Join-Path $fixture 'manifest.c') ($nf+@('-D__ARM_FEATURE_MVE=1')) 'does not permit MVE'
    NegativeCompile 'PAC' (Join-Path $fixture 'manifest.c') ($nf+@('-D__ARM_FEATURE_PAUTH=1')) 'excludes ARMv8.1-M, PAC and BTI'
    NegativeCompile 'BTI' (Join-Path $fixture 'manifest.c') ($nf+@('-D__ARM_FEATURE_BTI=1')) 'excludes ARMv8.1-M, PAC and BTI'
    $sfn=$nf+@('-mcmse','-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT=3','-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES=256')
    NegativeCompile 'NS-as-Secure' (Join-Path $secure 'fiber_secure_gateway.c') $nf 'CMSE3'
    NegativeCompile 'missing-capacity' (Join-Path $secure 'fiber_secure_gateway.c') ($nf+@('-mcmse')) 'C3FS manifest requires'
    NegativeCompile 'zero-count' (Join-Path $secure 'fiber_secure_gateway.c') ($sfn+@('-UFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT','-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT=0')) 'count must be nonzero'
    NegativeCompile 'unaligned-capacity' (Join-Path $secure 'fiber_secure_gateway.c') ($sfn+@('-UFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES','-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES=255')) 'eight-byte aligned'
    Check 'twentyfour-constructor-four-reference-sixteen-query-body-runs' ($executions.Count -eq 44)
    # Test-local source mutations are compiled, never prebuilt control blobs.
    # Preserve exact original/mutant hashes and make one semantic deletion.
    $controlDir=Join-Path $out 'compiled-controls'
    $null=New-Item -ItemType Directory -Path $controlDir
    $production=Join-Path $secure 'fiber_secure_gateway.c'
    $original=Get-Content -LiteralPath $production -Raw
    $needle='    fiber_secure_c3fs_query_preflight();'
    Check 'exact-four-query-preflight-calls' ([regex]::Matches($original,[regex]::Escape($needle)).Count -eq 4)
    $position=$original.IndexOf($needle)
    $mutant=$original.Remove($position,$needle.Length)
    $mutantPath=Join-Path $controlDir 'without-first-preflight.c'
    $mutant | Set-Content -LiteralPath $mutantPath -Encoding ASCII
    Json (Join-Path $controlDir 'source-mutation.json') @{Original=$production;
        OriginalSHA256=(Get-FileHash -LiteralPath $production).Hash;
        Mutant=$mutantPath;MutantSHA256=(Get-FileHash -LiteralPath $mutantPath).Hash;
        SemanticDeletion=$needle;Count=1}
    $first=Join-Path $out 'hard-O2-normal'
    $other=@((Join-Path $first 'secure-root.o'),(Join-Path $first 'fiber_secure_context_gateway.o'),
        (Join-Path $first 'fiber_secure_context_pool.o'))
    $controlFlags=$sfn+@('-nostdlib','-Wl,--no-undefined','-Wl,--cmse-implib',
        '-Wl,--section-start=.gnu.sgstubs=0x10020000','-T',(Join-Path $fixture 'secure.ld'))
    foreach($kind in @('preflight','GRO')) {
        $object=Join-Path $controlDir ($kind+'.o')
        if($kind -eq 'preflight') {Compile $mutantPath $object $sfn}
        else {Compile $production $object ($sfn+@('-DFIBER_GENERAL_REGS_ONLY='))}
        $ce=Join-Path $controlDir ($kind+'.elf')
        $null=Run $ArmGcc ($controlFlags+$other+@($object,"-Wl,--out-implib=$ce.imports.a",'-o',$ce)) ($ce+'.log')
        Elf $ce
        $body=$ce+'.bodies.dis'
        IdentityBodies $ce $body
        OracleReject 'query-codegen' $body $(if($kind -eq 'preflight'){'QUERY_PREFLIGHT'}else{'QUERY_FP_ENVELOPE'}) ($ce+'.rejection.json')
        if($kind -eq 'preflight') {OracleReject 'query-bodies' $ce 'QUERY_ADMISSION' ($ce+'.body-rejection.json')}
        else {OracleReject 'init-codegen' $ce 'INIT_FP_ENVELOPE' ($ce+'.whole-text-rejection.json')}
    }
    # Compile controls from the actual initializer, deleting one predicate at
    # a time. The execution oracle must reject them, rather than blessing a
    # source string assertion or a precompiled compiler-specific blob.
    $initSource=Join-Path $secure 'fiber_secure_context_gateway.c'
    $initOriginal=Get-Content -LiteralPath $initSource -Raw
    foreach($change in @(
        @{Name='NS-FPCA';From='((control_ns & 4u) != 0u)';To='(0u != 0u)';Diagnostic='INIT_ADMISSION'},
        @{Name='pool-exact-one';From='fiber_secure_context_pool_boot_initialize() != 1u';To='fiber_secure_context_pool_boot_initialize() == 0u';Diagnostic='INIT_STICKY_FAILURE'},
        @{Name='CONTROL-exact-two';From='if (control != 2u)';To='if (0u != 0u)';Diagnostic='INIT_STICKY_FAILURE'})) {
        Check ($change.Name+'/one-exact-source-mutation') ([regex]::Matches($initOriginal,[regex]::Escape($change.From)).Count -eq 1)
        $source=Join-Path $controlDir ($change.Name+'.c')
        $initOriginal.Replace($change.From,$change.To) | Set-Content -LiteralPath $source -Encoding ASCII
        Json ($source+'.mutation.json') @{Original=$initSource;OriginalSHA256=(Get-FileHash -LiteralPath $initSource).Hash;
            Mutant=$source;MutantSHA256=(Get-FileHash -LiteralPath $source).Hash;From=$change.From;To=$change.To;Count=1}
        $object=Join-Path $controlDir ($change.Name+'.o')
        Compile $source $object $sfn
        $elf=Join-Path $controlDir ($change.Name+'.elf')
        $null=Run $ArmGcc ($controlFlags+@((Join-Path $first 'secure-root.o'),
            (Join-Path $first 'fiber_secure_gateway.o'),(Join-Path $first 'fiber_secure_context_pool.o'),
            $object,"-Wl,--out-implib=$elf.imports.a",'-o',$elf)) ($elf+'.log')
        Elf $elf
        OracleReject 'init-bodies' $elf $change.Diagnostic ($elf+'.rejection.json')
    }
    $actualElf=Join-Path $first 'secure.elf'
    $actualDis=Get-Content -LiteralPath ($actualElf+'.dis') -Raw
    foreach($function in @('__acle_se_fiber_secure_context_gateway_c3fs_v1_initialize',
                          'fiber_secure_context_pool_c3fs_g2_cohort_provider')) {
        $pattern='(?m)^[0-9a-f]+ <'+[regex]::Escape($function)+'>:\r?\n([^\r\n]+)'
        $match=[regex]::Match($actualDis,$pattern)
        Check ($function+'/decoder-control-function') $match.Success
        $line=$match.Groups[1].Value
        Check ($function+'/decoder-control-one-line') ([regex]::Matches($actualDis,[regex]::Escape($line)).Count -eq 1)
        $copy=Join-Path $controlDir ($function+'-decode.elf')
        Copy-Item -LiteralPath $actualElf -Destination $copy
        $actualDis.Replace($line,'') | Set-Content -LiteralPath ($copy+'.dis') -Encoding ASCII
        Json ($copy+'.mutation.json') @{ActualElf=$actualElf;ActualElfSHA256=(Get-FileHash -LiteralPath $actualElf).Hash;
            CopiedElfSHA256=(Get-FileHash -LiteralPath $copy).Hash;OriginalDisassemblySHA256=(Get-FileHash -LiteralPath ($actualElf+'.dis')).Hash;
            MutantDisassemblySHA256=(Get-FileHash -LiteralPath ($copy+'.dis')).Hash;SemanticDeletion=$line;Count=1}
        OracleReject 'init-codegen' $copy 'INIT_TEXT_DECODE_COVERAGE' ($copy+'.rejection.json') 'ByteDecoder'
    }
    $generation=Join-Path $controlDir 'generation.o'
    Compile (Join-Path $fixture 'generation.c') $generation $sfn
    $r=Run $ArmGcc ($sfn+@('-nostdlib','-Wl,--gc-sections','-Wl,-e,fixture_without_pool_generation',
        '-T',(Join-Path $fixture 'image.ld'),'-T',(Join-Path $secure 'fiber_secure_context_cohort_contract.ld'),
        $generation,'-o',(Join-Path $controlDir 'no-generation.elf'))) (Join-Path $controlDir 'no-generation.log') -Fail
    Check 'missing-pool-generation-exact-ASSERT' ($r.ExitCode -ne 0 -and
        $r.Text.Contains('[fiber]: C3FS Secure exact-pool generation 2 required') -and
        $r.Text -notmatch 'undefined reference')
    $mixedObject=Join-Path $controlDir 'manifest-other-capacity.o'
    Compile (Join-Path $secure 'fiber_secure_context_pool.c') $mixedObject ($sfn+@(
        '-UFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT','-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT=2',
        '-UFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES','-DFIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES=400'))
    $r=Run $ArmGcc ($controlFlags+@((Join-Path $first 'secure-root.o'),
        (Join-Path $first 'fiber_secure_gateway.o'),(Join-Path $first 'fiber_secure_context_gateway.o'),
        $mixedObject,"-Wl,--out-implib=$controlDir/mixed.imports.a",'-o',(Join-Path $controlDir 'mixed.elf'))) (Join-Path $controlDir 'mixed.log') -Fail
    Check 'mixed-actual-manifest-exact-key-rejected' ($r.ExitCode -ne 0 -and
        $r.Text -match 'undefined reference to .fiber_secure_context_cohort_c3fs_g2_' -and
        $r.Text -notmatch 'undefined reference to .fiber_secure_context_pool_c3fs_g2_cohort_provider')
    $cold=Join-Path $first 'ordinary'
    $link=$nf+@('-nostdlib','-Wl,--gc-sections','-Wl,--no-undefined',
        '-Wl,-u,fiber_port_secure_context_attach','-Wl,-u,fixture_task',
        '-Wl,-u,c3fs_consumer_storage','-T',(Join-Path $fixture 'image.ld'))
    $actualCold=@((Join-Path $cold 'fiber_port_boot.o'),(Join-Path $cold 'fiber_port_secure_context.o'))+
        @($coldCommonNames | ForEach-Object {Join-Path $cold $_})
    $r=Run $nm @('-u',(Join-Path $cold 'fiber_port_boot.o')) (Join-Path $out 'actual-cold-undefined.txt')
    $cohort=@([regex]::Matches($r.Text,'(?m)\bU\s+(fiber_port_context_cohort_\S+)') | ForEach-Object {$_.Groups[1].Value})
    Check 'actual-cold-one-context-expectation' ($cohort.Count -eq 1)
    foreach($kind in @('COHORT','REVERSE')) {
        $object=Join-Path $controlDir ('omit-'+$kind+'.o')
        Compile (Join-Path $fixture 'probe.c') $object ($nf+@("-DFIXTURE_OMIT_$kind=1"))
        $missing=if($kind -eq 'COHORT'){@($cohort[0],'fiber_port_storage_cohort_arm_cm33f_v1_r0')}else{@('fiber_internal_runtime_port_abi_v1_anchor')}
        MissingOnly ('missing-'+$kind) ($link+$actualCold+@($object,(Join-Path $first 'public.c.c++.o'),'-o',(Join-Path $controlDir ('missing-'+$kind+'.elf')))) $missing
    }
    $oldNs=Join-Path $repo 'fiber\port\ARM_CM33\non_secure'
    $stale=Join-Path $controlDir 'scalar-storage.o'
    Compile (Join-Path $fixture 'public.c') $stale (@("-I$oldNs")+$nf)
    MissingOnly 'scalar-storage' ($link+$actualCold+@((Join-Path $cold 'probe.o'),$stale,
        '-o',(Join-Path $controlDir 'scalar-storage.elf'))) @('fiber_port_storage_cohort_arm_cm33_v1_r0')
    $importNames=@('fiber_secure_gateway_c3fs_v1_abi_version','fiber_secure_gateway_c3fs_v1_context_port_id',
        'fiber_secure_gateway_c3fs_v1_context_layout_version','fiber_secure_gateway_c3fs_v1_context_feature_mask',
        'fiber_secure_context_gateway_c3fs_v1_abi_version','fiber_secure_context_gateway_c3fs_v1_stack_alignment',
        'fiber_secure_context_gateway_c3fs_v1_max_stack_bytes','fiber_secure_context_gateway_c3fs_v1_max_contexts',
        'fiber_secure_context_gateway_c3fs_v1_initialize')
    MissingOnly 'missing-C3FS-imports' ($nf+@('-nostdlib','-Wl,--gc-sections','-Wl,--no-undefined',
        '-Wl,-e,fixture_real_imports','-T',(Join-Path $fixture 'image.ld'),(Join-Path $first 'queries.c.c.o'),
        '-o',(Join-Path $controlDir 'missing-imports.elf'))) $importNames
    $wrongIsa=Join-Path $controlDir 'M55-target.o'
    Compile (Join-Path $ns 'fiber_port_boot.c') $wrongIsa ($nf+@('-mcpu=cortex-m55+nomve'))
    $attributes=Get-Content -LiteralPath ($wrongIsa+'.attributes') -Raw
    Check 'M55-ceiling-is-build-admission-not-preprocessor-claim' ($attributes -match 'Tag_CPU_arch:\s+v8.1-M')
    $ok=$true
} finally {
    $env:PYTHONPATH=$oldPythonPath
    $after=@($before | ForEach-Object {[pscustomobject]@{Path=$_.Path;Sha256=(Get-FileHash -LiteralPath $_.Path -Algorithm SHA256).Hash}})
    Json (Join-Path $out 'inputs.after.json') $after
    $lookup=@{}; foreach($item in $before){$lookup[$item.Path]=$item.Sha256}
    $drift=@($after | Where-Object {$_.Sha256 -cne $lookup[$_.Path]})
    Json (Join-Path $out 'checks.json') $checks.ToArray()
    Json (Join-Path $out 'runs.json') $runs.ToArray()
    Json (Join-Path $out 'executions.json') $executions.ToArray()
    Json (Join-Path $out 'controls.json') $controls.ToArray()
    Json (Join-Path $out 'initializers.json') $initializers.ToArray()
    $calls=0; $bodyCalls=0; $referenceCalls=0; $initializerCalls=0
    foreach($execution in $initializers) {$initializerCalls += $execution.InitializerBodyCalls}
    foreach($execution in $executions) {
        if($execution.PSObject.Properties['Calls']) {$calls += $execution.Calls}
        if($execution.PSObject.Properties['QueryBodyCalls']) {$bodyCalls += $execution.QueryBodyCalls}
        if($execution.PSObject.Properties['ReferenceCalls']) {$referenceCalls += $execution.ReferenceCalls}
    }
    Json (Join-Path $out 'receipt.json') @{Verdict=$(if($ok -and !$drift.Count){'PASS'}else{'FAIL'});
        Configurations=$runs.Count;Checks=$checks.Count;Executions=$executions.Count;
        ConstructorCalls=$calls;QueryBodyCalls=$bodyCalls;ReferenceCalls=$referenceCalls;
        CompiledControlRejections=@($controls | Where-Object {$_.Kind -eq 'CompiledSource'}).Count;
        ByteDecoderControlRejections=@($controls | Where-Object {$_.Kind -eq 'ByteDecoder'}).Count;
        InitializerBodyRuns=$initializers.Count;
        InitializerBodyCalls=$initializerCalls;
        Inputs=$before.Count;InputDrift=$drift;SourceSnapshots=$copies.Count;Evidence=$out;
        Limits='Staged construction/attachment with labelled NS query doubles; real pool and nine-entry companion compile/link/codegen; actual query/initializer bodies with explicit register/MMIO fault doubles, stopping before BXNS. No SG, FP stacking, switching or hardware qualification.'}
    $artifacts=@(Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object {
        [pscustomobject]@{Path=$_.FullName.Substring($out.Length+1);Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
    Json (Join-Path $out 'artifacts.json') $artifacts
    if($drift.Count){throw "C3FS input drift: $out"}
}
Write-Host "PASS C3FS staged manifest: $($checks.Count) checks; evidence $out"
