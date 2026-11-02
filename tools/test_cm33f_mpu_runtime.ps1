param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$QemuRoot,
    [string]$WslDistro = 'Ubuntu-24.04',
    [string]$BuildRoot,
    [ValidateSet(0,1)][int]$ExpectedRuntimeSelectable = 1,
    [ValidateRange(1,60)][int]$TimeoutSeconds = 10
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture = Join-Path $PSScriptRoot 'fixtures\cm33f_mpu_runtime'
$component = Join-Path $PSScriptRoot 'fixtures\cm33f_mpu_running_execution'
$bootstrap = Join-Path $PSScriptRoot 'fixtures\cm33f_mpu_first_start_execution'
$port = Join-Path $repo 'fiber\port\ARM_CM33F_MPU\non_secure'
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {throw 'Supply existing -ArmGcc'}
if (!$QemuRoot -or !$QemuRoot.StartsWith('/')) {throw 'Supply an explicit existing absolute WSL -QemuRoot; no provisioning'}
if (!$CmsisCore) {$CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include'}
if (!$FreeRtosRoot) {$FreeRtosRoot = Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel'}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
$referenceRelative = 'portable/GCC/ARM_CM33_NTZ/non_secure'
$reference = Join-Path $FreeRtosRoot $referenceRelative
$pin = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin 'arm-none-eabi-nm.exe'
$objdump = Join-Path $bin 'arm-none-eabi-objdump.exe'
$readelf = Join-Path $bin 'arm-none-eabi-readelf.exe'
$ar = Join-Path $bin 'arm-none-eabi-gcc-ar.exe'
$gccnm = Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$contract = Join-Path $port 'fiber_port_linker_contract.ld'
foreach ($path in @($nm,$objdump,$readelf,$ar,$gccnm,$contract,(Join-Path $port 'fiber_port_pendsv.c'),
        (Join-Path $CmsisCore 'core_cm33.h'),(Join-Path $bootstrap 'qemu.sh'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {throw "Missing running execution dependency: $path"}
}
if (!$BuildRoot) {$BuildRoot = [IO.Path]::GetTempPath()}
$out = Join-Path $BuildRoot ('cm33f-mpu-runtime-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out -Force
$commands = Join-Path $out 'commands.jsonl'
$checks = New-Object System.Collections.Generic.List[object]
$runs = New-Object System.Collections.Generic.List[object]
$verdict = 'FAIL'
$referenceChecked = $false
$failure = ''
$inputs = @($PSCommandPath,$ArmGcc,$nm,$objdump,$readelf,$ar,$gccnm,
    (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h')) +
    @(Get-ChildItem $fixture -File -Recurse | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem $port -File -Recurse | Where-Object {$_.Extension -in @('.c','.h','.S','.ld')} | Select-Object -ExpandProperty FullName) +
    @('main.h','report.h','startup.S','secure.c','secure.ld','qemu.sh' | ForEach-Object {Join-Path $bootstrap $_}) +
    (Join-Path $component 'qemu.sh') +
    @(Get-ChildItem (Join-Path $repo 'fiber') -File | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem (Join-Path $repo 'fiber\port') -File | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem $CmsisCore -Filter '*.h' -File -Recurse | Select-Object -ExpandProperty FullName) +
    @('port.c','portasm.c','portasm.h','portmacro.h' | ForEach-Object {Join-Path $reference $_})
function Recorded([string]$File,[string[]]$Arguments,[string]$Log) {
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $File @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally {$ErrorActionPreference = $old}
    $text = ($lines | ForEach-Object {"$_"}) -join "`n"
    $text | Set-Content -LiteralPath $Log -Encoding ASCII
    @{File=$File;Arguments=$Arguments;ExitCode=$code;Log=$Log} | ConvertTo-Json -Compress -Depth 5 |
        Add-Content -LiteralPath $commands -Encoding ASCII
    [pscustomobject]@{Code=$code;Text=$text}
}
function RequireCommand([string]$File,[string[]]$Arguments,[string]$Log) {
    $result = Recorded $File $Arguments $Log
    if ($result.Code -ne 0) {throw "Command failed ($($result.Code)): $Log`n$($result.Text)"}
    $result.Text
}
function Check([string]$Name,[bool]$Condition,[object]$Evidence) {
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$Condition;Evidence=$Evidence})
    if (!$Condition) {throw "Running execution proof failed: $Name"}
}
function HashInputs {
    @($inputs | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
}
function WslPath([string]$Path) {
    (RequireCommand 'wsl.exe' @('-d',$WslDistro,'--exec','wslpath','-u',$Path) (Join-Path $out 'wslpath-last.log')).Trim()
}
function BuildSecure([string]$Name,[switch]$Probe) {
    $dir = Join-Path $out $Name
    $null = New-Item -ItemType Directory -Path $dir
    $flags = $base + @('-O2','-mfloat-abi=soft','-mgeneral-regs-only','-mcmse','-DEXEC_SECURE=1',"-I$bootstrap","-I$CmsisCore")
    if ($Probe) {$flags += '-DEXEC_PROBE_ONLY=1'}
    $objects = @()
    foreach ($unit in @('startup.S','secure.c')) {
        $object = Join-Path $dir ($unit.Replace('.','-')+'.o')
        $null = RequireCommand $ArmGcc ($flags + @('-save-temps=obj','-MD','-c',(Join-Path $bootstrap $unit),'-o',$object)) (Join-Path $dir ($unit+'.log'))
        $objects += $object
    }
    $elf = Join-Path $dir 'secure.elf'
    $null = RequireCommand $ArmGcc ($flags + @('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined',
        '-T',(Join-Path $bootstrap 'secure.ld'),"-Wl,-Map,$dir/secure.map") + $objects + @('-o',$elf)) (Join-Path $dir 'link.log')
    $null = RequireCommand $objdump @('-drwC',$elf) (Join-Path $dir 'disassembly.txt')
    $elf
}
function Execute([string]$Name,[string]$SecureElf,[string]$NonsecureElf,[string]$Marker) {
    $dir = if ($NonsecureElf -eq 'none') {Split-Path $SecureElf} else {Split-Path $NonsecureElf}
    $s = WslPath $SecureElf
    $ns = if ($NonsecureElf -eq 'none') {'none'} else {WslPath $NonsecureElf}
    $log = Join-Path $dir 'qemu.log'
    $result = Recorded 'wsl.exe' @('-d',$WslDistro,'--exec','bash',$qemuScript,'run',$QemuRoot,$wslOut,$s,$ns,[string]$TimeoutSeconds) $log
    $runs.Add([pscustomobject]@{Name=$Name;Executed=$true;ExitCode=$result.Code;Marker=$Marker;Log=$log;SecureELF=$SecureElf;NonsecureELF=$NonsecureElf})
    $nonempty = @($result.Text -split "`n" | Where-Object {!([string]::IsNullOrWhiteSpace($_))})
    Check "$Name/strict-exit-and-sole-terminal-marker" ($result.Code -eq 0 -and
        @($result.Text -split "`n" | Where-Object {$_.TrimEnd("`r") -ceq $Marker}).Count -eq 1 -and
        $nonempty.Count -gt 0 -and $nonempty[-1].TrimEnd("`r") -ceq $Marker -and
        $result.Text -cnotmatch '(FAIL:|FAILED_CHECK|Traceback|fatal:|Lockup|timed out)') $result.Text
    $result.Text
}
function ScalarValue([string]$Text,[string]$Name) {
    $found = [regex]::Matches($Text,'(?m)^'+[regex]::Escape($Name)+'=0x([0-9a-f]{8})\r?$')
    if ($found.Count -ne 1) {throw "Missing/duplicate CPU observation: $Name"}
    [Convert]::ToUInt32($found[0].Groups[1].Value,16)
}

$generic = @('fiber_port_context_init','fiber_port_runtime_memory_barrier','fiber_port_panic_wait',
    'fiber_port_require_scheduler_configuration_environment','fiber_port_runtime_prepare_start',
    'fiber_port_runtime_select_first','fiber_port_runtime_start_first','fiber_port_runtime_schedule')
function CompileUnit([string]$Source,[string]$Object,[string[]]$Flags) {
    $null=RequireCommand $ArmGcc ($Flags+@('-save-temps=obj','-MD','-c',$Source,'-o',$Object)) ($Object+'.log')
}
function Archive([string]$Path,[string[]]$Objects) {$null=RequireCommand $ar (@('rcs',$Path)+$Objects) ($Path+'.log')}
function LinkImage([string]$Elf,[string[]]$Members,[string[]]$Flags,[string]$Script) {
    Recorded $ArmGcc ($Flags+@('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined',
        '-T',$Script,'-T',$contract,"-Wl,-Map,$Elf.map")+$Members+@('-o',$Elf)) ($Elf+'.link.log')
}
function Defined([string]$Object) {RequireCommand $gccnm @('--defined-only','-g',$Object) ($Object+'.defined.txt')}
function ExpectUndefined([string]$Name,[object]$Result,[string]$Symbol) {
    Check $Name ($Result.Code -ne 0 -and $Result.Text -match
        ('undefined reference to [^\r\n]*\b'+[regex]::Escape($Symbol)+'\b') -and
        $Result.Text -notmatch '(cannot find|file format not recognized|syntax error)') $Result.Text
}
function InspectImage([string]$Name,[string]$Elf) {
    $dump=RequireCommand $objdump @('-drwC',$Elf) ($Elf+'.disassembly.txt')
    $symbols=RequireCommand $nm @('-n','-S',$Elf) ($Elf+'.symbols.txt')
    $undefined=RequireCommand $nm @('-u',$Elf) ($Elf+'.undefined.txt')
    $attributes=RequireCommand $readelf @('-hASsW',$Elf) ($Elf+'.attributes.txt')
    Check "$Name/no-undefined" ([string]::IsNullOrWhiteSpace($undefined)) $Elf
    $addresses=@{}
    foreach($m in [regex]::Matches($symbols,'(?m)^([0-9a-f]+)\s+[0-9a-f]+\s+([A-Za-z])\s+(\S+)\r?$')) {
        $addresses[$m.Groups[3].Value]=[Convert]::ToUInt32($m.Groups[1].Value,16)
    }
    foreach($symbol in $generic+@('SVC_Handler','PendSV_Handler','fiber_port_handler_bundle_v1_anchor',
            'fiber_internal_task_return')) {
        Check "$Name/exact-live-$symbol" (@([regex]::Matches($symbols,
            '(?m)^[0-9a-f]+\s+[0-9a-f]+\s+T\s+'+[regex]::Escape($symbol)+'\r?$')).Count -eq 1) $Elf
    }
    # Whole-program LTO may localize the real common data anchor. It must
    # remain exactly one byte and a live OBJECT; v2-only input still must fail.
    Check "$Name/exact-live-common-v1-object" (@([regex]::Matches($attributes,
        '(?m)^\s*\d+:\s+[0-9a-f]+\s+1\s+OBJECT\s+(?:LOCAL|GLOBAL)\s+\S+\s+\d+\s+fiber_internal_runtime_port_abi_v1_anchor\r?$')).Count -eq 1) $Elf
    foreach($symbol in @('fiber_current','fiber_schedule','fiber_internal_runtime_load_current_context','fiber_port_runtime_memory_barrier')) {
        Check "$Name/unprivileged-$symbol" ($addresses.ContainsKey($symbol) -and
            $addresses[$symbol] -ge 0x20000 -and $addresses[$symbol] -lt 0x28000) $Elf
    }
    Check "$Name/syscall-adapter" ($addresses['fiber_port_runtime_schedule'] -ge 0x28000 -and
        $addresses['fiber_port_runtime_schedule'] -lt 0x29000) $Elf
    foreach($symbol in $generic | Where-Object {$_ -notin @('fiber_port_runtime_memory_barrier','fiber_port_runtime_schedule')}) {
        Check "$Name/privileged-$symbol" ($addresses[$symbol] -ge 0x10800 -and $addresses[$symbol] -lt 0x20000) $Elf
    }
    foreach($service in @(70,71,72)) {
        $opcode='{0:x4}' -f (0xdf00+$service)
        Check "$Name/owned-SVC$service-present" ($dump -match "(?m)^\s*[0-9a-f]+:\s+$opcode\s+svc\s+$service\s*") $Elf
    }
    Check "$Name/no-fixture-barrier-provider" ($symbols -notmatch '\bfixture_common_memory_barrier\b') $Elf
    foreach($symbol in @($cohort,"fiber_port_storage_cohort_arm_cm33f_mpu_v1_r$regions")) {
        $objects=[regex]::Matches($attributes,'(?m)^\s*\d+:\s+([0-9a-f]+)\s+1\s+OBJECT\s+GLOBAL\s+\S+\s+(\d+)\s+'+[regex]::Escape($symbol)+'\r?$')
        Check "$Name/exact-one-byte-object-provider-$symbol" ($objects.Count -eq 1) $Elf
        $sectionIndex=$objects[0].Groups[2].Value
        $sections=[regex]::Matches($attributes,'(?m)^\s*\[\s*'+$sectionIndex+'\]\s+\S+\s+PROGBITS\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+([A-Z]+)\s')
        $value=[Convert]::ToUInt32($objects[0].Groups[1].Value,16)
        Check "$Name/allocated-nonwritable-flash-provider-$symbol" ($sections.Count -eq 1 -and
            $sections[0].Groups[1].Value.Contains('A') -and !$sections[0].Groups[1].Value.Contains('W') -and
            $value -ge 0x10000 -and $value -lt 0x20000) $Elf
    }
    $vectorFile=$Elf+'.vectors.bin'
    $section=[regex]::Matches($attributes,'(?m)^\s*\[\s*\d+\]\s+\.vectors\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\s')
    Check "$Name/exact-vector-section" ($section.Count -eq 1) $Elf
    $offset=[Convert]::ToInt32($section[0].Groups[1].Value,16)
    $length=[Convert]::ToInt32($section[0].Groups[2].Value,16)
    $bytes=[IO.File]::ReadAllBytes($Elf)
    Check "$Name/bounded-vector-file-span" ($length -eq 2048 -and $offset -ge 0 -and $offset+$length -le $bytes.Length) $Elf
    [byte[]]$vectors=$bytes[$offset..($offset+$length-1)]
    [IO.File]::WriteAllBytes($vectorFile,$vectors)
    Check "$Name/exact-vector-bindings" ($vectors.Length -eq 2048 -and
        ([BitConverter]::ToUInt32($vectors,44) -band 0xfffffffeL) -eq $addresses['SVC_Handler'] -and
        ([BitConverter]::ToUInt32($vectors,56) -band 0xfffffffeL) -eq $addresses['PendSV_Handler'] -and
        $addresses['SVC_Handler'] -ne $addresses['fixture_fault_handler'] -and
        $addresses['PendSV_Handler'] -ne $addresses['fixture_fault_handler']) $vectorFile
}

# Record the actual compiler subprocesses and system include headers, not only gcc.exe.
foreach ($program in @('cc1','as','ld','collect2','lto1')) {
    $path = (RequireCommand $ArmGcc @("-print-prog-name=$program") (Join-Path $out ($program+'-path.txt'))).Trim()
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {throw "Unresolved compiler subprocess: $program ($path)"}
    $inputs += (Resolve-Path -LiteralPath $path).Path
}
$systemInclude = (RequireCommand $ArmGcc @('-print-file-name=include') (Join-Path $out 'system-include-path.txt')).Trim()
if (!(Test-Path -LiteralPath $systemInclude -PathType Container)) {throw 'Missing compiler system include directory'}
$inputs += @(Get-ChildItem -LiteralPath $systemInclude -File -Recurse | Select-Object -ExpandProperty FullName)
$before = HashInputs
$before | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII
$snapshot = Join-Path $out 'input-copies'
$null = New-Item -ItemType Directory -Path $snapshot
$copyMap = @(); $copyIndex = 0
foreach ($row in $before) {
    if ([IO.Path]::GetExtension($row.Path) -in @('.exe','.dll')) {continue}
    $copy = Join-Path $snapshot ('{0:D3}-{1}' -f $copyIndex++, [IO.Path]::GetFileName($row.Path))
    [IO.File]::Copy($row.Path,$copy)
    if ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -cne $row.Hash) {throw "Input copy drift: $($row.Path)"}
    $copyMap += [pscustomobject]@{Original=$row.Path;Copy=$copy;SHA256=$row.Hash}
}
$copyMap | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'input-copy-map.json') -Encoding ASCII
try {
    Write-Host "C3FP full runtime evidence: $out"
    $null = RequireCommand $ArmGcc @('--version') (Join-Path $out 'compiler.txt')
    $actualPin = (RequireCommand 'git' @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.txt')).Trim()
    Check 'reference/exact-identity-pin' ($actualPin -ceq $pin) $actualPin
    $null = RequireCommand 'git' @('-C',$FreeRtosRoot,'diff','--exit-code','HEAD','--',
        "$referenceRelative/port.c","$referenceRelative/portasm.c","$referenceRelative/portasm.h","$referenceRelative/portmacro.h") (Join-Path $out 'reference-diff.txt')
    $referenceChecked = $true
    $base = @('-mcpu=cortex-m33','-mthumb','-std=gnu11','-ffreestanding','-fno-builtin','-fno-common',
        '-ffunction-sections','-fdata-sections','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
        '-fno-instrument-functions','-fno-stack-protector','-fno-profile-arcs','-fno-test-coverage',
        '-fno-profile','-fno-stack-check','-fno-sanitize=all','-fno-sanitize-coverage=trace-pc',
        '-Wall','-Wextra','-Werror','-Wundef')
    $wslOut = WslPath $out
    $qemuScript = WslPath (Join-Path $component 'qemu.sh')
    $null = RequireCommand 'wsl.exe' @('-d',$WslDistro,'--exec','bash',$qemuScript,'inspect',$QemuRoot,$wslOut) (Join-Path $out 'qemu-inspect.log')
    $probe = BuildSecure 'model-probe' -Probe
    $probeLog = Execute 'model-probe' $probe 'none' 'PASS:C3FP-MODEL-PROBE'
    $mpuType = ScalarValue $probeLog 'MODEL_MPU_TYPE'
    $priorityMask = ScalarValue $probeLog 'MODEL_PRIORITY_MASK'
    Check 'model/actual-eight-regions' (($mpuType -band 0xff00) -eq 0x800) $mpuType
    $priorityBits = 0; $remaining = $priorityMask
    while ($remaining -band 0x80) {++$priorityBits; $remaining = ($remaining -shl 1) -band 0xff}
    Check 'model/contiguous-priority-mask' ($priorityBits -ge 1 -and $priorityBits -le 8 -and $remaining -eq 0) $priorityMask
    @{MPUType=$mpuType;ExecutedRegions=8;CompileOnlyRegions=16;CmsisPriorityBits=$priorityBits;
        PriorityMask=$priorityMask;NSACR=(ScalarValue $probeLog 'SECURE_NSACR');MVFR0=(ScalarValue $probeLog 'MODEL_MVFR0')} |
        ConvertTo-Json | Set-Content (Join-Path $out 'model.json') -Encoding ASCII
    $secureElf = BuildSecure 'secure-bootstrap'
    foreach ($optimization in @('-O2','-Os')) {
        foreach ($abi in @('hard','softfp')) {
            foreach ($lto in @(0,1)) {
                foreach ($regions in @(8,16)) {
                    foreach ($lazy in @(0,1)) {
                        $mode="r$regions-$abi-$($optimization.Substring(1))-lto$lto-lazy$lazy"
                        $dir=Join-Path $out $mode
                        $null=New-Item -ItemType Directory -Path $dir
                        $flags=$base+@($optimization,'-mfpu=fpv5-sp-d16',"-mfloat-abi=$abi",'-ffixed-r9',
                            '-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV8M_MAINLINE=1',
                            "-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$regions","-DFIBER_FPU_LAZY=$lazy",
                            "-DEXEC_NVIC_PRIO_BITS=$priorityBits","-DEXEC_EXPECT_RUNTIME_SELECTABLE=$ExpectedRuntimeSelectable",
                            "-I$fixture","-I$port","-I$repo","-I$repo/fiber","-I$repo/fiber/port","-I$CmsisCore")
                        if($lto) {$flags+=@('-flto','-ffat-lto-objects')}
                        $portObjects=@()
                        foreach($unit in @('fiber_port_boot.c','fiber_port_svc.c','fiber_port_pendsv.c')) {
                            $object=Join-Path $dir ($unit.Replace('.c','.o'))
                            CompileUnit (Join-Path $port $unit) $object $flags
                            $portObjects+=$object
                        }
                        $commonObjects=@()
                        $commonFlags=@($flags | Where-Object {$_ -notin @("-I$fixture","-I$port","-I$CmsisCore")})+@('-mgeneral-regs-only')
                        foreach($unit in @('fiber_core.c','fiber_runtime_state.c','fiber_panic.c')) {
                            $object=Join-Path $dir ($unit.Replace('.c','.o'))
                            CompileUnit (Join-Path $repo ('fiber/'+$unit)) $object $commonFlags
                            $deps=[IO.File]::ReadAllText([IO.Path]::ChangeExtension($object,'.d'))
                            Check "$mode/common-free-of-selected-CMSIS-$unit" ($deps -notmatch '(fiber_port_(private|types|selected|context_cohort)\.h|core_cm[0-9]+\.h)') $deps
                            $commonObjects+=$object
                        }
                        $portArchive=Join-Path $dir 'libport.a';$commonArchive=Join-Path $dir 'libcommon.a'
                        Archive $portArchive $portObjects;Archive $commonArchive $commonObjects
                        $owned=@{}
                        for($i=0;$i -lt $portObjects.Count;++$i) {
                            $definitions=Defined $portObjects[$i]
                            $operationNames=@([regex]::Matches($definitions,'(?m)^[0-9a-f]+\s+[A-Z]\s+(fiber_port_runtime_\S+)\r?$') |
                                ForEach-Object {$_.Groups[1].Value})
                            Check "$mode/no-unfrozen-runtime-operation-$i" (@($operationNames | Where-Object {$_ -notin $generic}).Count -eq 0) $operationNames
                            foreach($symbol in $generic) {
                                if($definitions -match ('(?m)^[0-9a-f]+\s+[A-Z]\s+'+[regex]::Escape($symbol)+'\r?$')) {
                                    Check "$mode/unique-owner-$symbol" (!$owned.ContainsKey($symbol)) $definitions
                                    $owned[$symbol]=$i
                                }
                            }
                        }
                        Check "$mode/exact-eight-operation-owners" ($owned.Count -eq 8 -and $owned['fiber_port_context_init'] -eq 0 -and
                            @($generic | Where-Object {$_ -ne 'fiber_port_context_init' -and $owned[$_] -ne 1}).Count -eq 0) $owned
                        $expectation=Join-Path $dir 'expectation.o'
                        CompileUnit (Join-Path $repo 'fiber/port/fiber_port_context_cohort_expectation.c') $expectation $flags
                        $cohortNames=Defined $portObjects[1]
                        # gcc-nm's LTO plugin labels constant IR definitions D;
                        # InspectImage requires one-byte OBJECTs in allocated,
                        # nonwritable flash in every final ELF (nm may say T).
                        $cohortMatches=[regex]::Matches($cohortNames,'(?m)^[0-9a-f]+\s+[RD]\s+(fiber_port_context_cohort_\S+)\r?$')
                        Check "$mode/single-production-cohort" ($cohortMatches.Count -eq 1) $cohortNames
                        $cohort=$cohortMatches[0].Groups[1].Value
                        $cases=@(@{Id=0;FP=0;Name='basic'},@{Id=0;FP=1;Name='extended'},@{Id=0;FP=2;Name='mixed'})
                        if($regions -eq 8 -and $lazy -eq 0) {
                            foreach($id in 1..13) {$cases+=@{Id=$id;FP=0;Name="negative-$id"}}
                        }
                        foreach($case in $cases) {
                            $name=$mode+'-'+$case.Name
                            $caseDir=Join-Path $dir $case.Name
                            $null=New-Item -ItemType Directory -Path $caseDir
                            $caseFlags=$flags+@("-DEXEC_CASE=$($case.Id)","-DEXEC_FP=$($case.FP)",'-DEXEC_WEAK_STARTUP=1')
                            $fixtureObjects=@()
                            foreach($unit in @('startup.S','tasks.S','application.c','oracle.c')) {
                                $object=Join-Path $caseDir ($unit.Replace('.','-')+'.o')
                                CompileUnit (Join-Path $fixture $unit) $object ($caseFlags+@('-mgeneral-regs-only'))
                                $fixtureObjects+=$object
                            }
                            $members=@($fixtureObjects)+@($expectation,'-Wl,--start-group',$commonArchive,$portArchive,'-Wl,--end-group')
                            $elf=Join-Path $caseDir 'nonsecure.elf'
                            $script=Join-Path $fixture 'nonsecure.ld'
                            if($case.Id -eq 13) {
                                $script=Join-Path $caseDir 'misplaced-common.ld'
                                $text=[IO.File]::ReadAllText((Join-Path $fixture 'nonsecure.ld'))
                                Check "$name/single-boundary-mutation" ([regex]::Matches($text,[regex]::Escape('*(.text.fiber_runtime_thread_functions)')).Count -eq 1) $script
                                [IO.File]::WriteAllText($script,$text.Replace('*(.text.fiber_runtime_thread_functions)','/* Deliberate negative: common Thread code falls into privileged .text*. */'))
                            }
                            $link=LinkImage $elf $members $flags $script
                            Check "$name/archive-weak-startup-link" ($link.Code -eq 0) $link.Text
                            if($case.Id -ne 13) {InspectImage $name $elf}
                            else {
                                $null=RequireCommand $objdump @('-drwC',$elf) ($elf+'.disassembly.txt')
                                $null=RequireCommand $nm @('-n','-S',$elf) ($elf+'.symbols.txt')
                                $null=RequireCommand $readelf @('-hASW',$elf) ($elf+'.attributes.txt')
                            }
                            if($regions -eq 16) {
                                $runs.Add([pscustomobject]@{Name=$name;Executed=$false;NonsecureELF=$elf;Reason='Compile/link only: AN505 has eight MPU regions'})
                            } else {
                                $marker=if($case.Id -eq 0) {'PASS:C3FP-FULL-RUNTIME'} else {'PASS:C3FP-RUNTIME-NEGATIVE'}
                                $log=Execute $name $secureElf $elf $marker
                                if($case.Id -eq 0) {
                                    $fpTasks=if($case.FP -eq 1){2}elseif($case.FP -eq 2){1}else{0}
                                    Check "$name/real-first-before-six-switches" ($log.Contains('PASS:C3FP-REAL-FIRST-SELECTION') -and
                                        (ScalarValue $log 'VERIFIED_SWITCHES') -eq 6 -and (ScalarValue $log 'VERIFIED_FP_TASKS') -eq $fpTasks) $log
                                    $tracePath=Join-Path $caseDir 'qemu-exceptions.log'
                                    $trace=[IO.File]::ReadAllText($tracePath)
                                    $tails=[regex]::Matches($trace,'(?m)^Exception return: magic PC ffffff(bc|ac) previous exception 11\r?\n\.\.\.tailchaining to pending exception\r?\n\.\.\.taking pending nonsecure exception 14\r?$')
                                    Check "$name/six-actual-tailchains" ($tails.Count -eq 6 -and
                                        @($tails | Where-Object {$_.Groups[1].Value -ceq 'ac'}).Count -eq 3*$fpTasks) $tracePath
                                }
                            }
                            if($case.Id -ne 0 -or $case.FP -ne 0 -or $lazy -ne 0) {continue}
                            # A direct link with strong startup imports is an independent positive.
                            $strong=Join-Path $caseDir 'strong-startup.o'
                            CompileUnit (Join-Path $fixture 'startup.S') $strong (@($caseFlags | Where-Object {$_ -ne '-DEXEC_WEAK_STARTUP=1'})+@('-DEXEC_WEAK_STARTUP=0'))
                            $directMembers=@($strong)+@($fixtureObjects | Select-Object -Skip 1)+@($expectation)+$commonObjects+$portObjects
                            $directDir=Join-Path $caseDir 'direct'
                            $null=New-Item -ItemType Directory -Path $directDir
                            $direct=Join-Path $directDir 'nonsecure.elf'
                            $result=LinkImage $direct $directMembers $flags (Join-Path $fixture 'nonsecure.ld')
                            Check "$name/direct-strong-positive" ($result.Code -eq 0) $result.Text
                            InspectImage ($name+'-direct') $direct
                            if($regions -eq 8) {
                                $null=Execute ($name+'-direct') $secureElf $direct 'PASS:C3FP-FULL-RUNTIME'
                            } else {$runs.Add([pscustomobject]@{Name=$name+'-direct';Executed=$false;NonsecureELF=$direct;Reason='Sixteen-region direct-link compile-only'})}
                            $defaultDir=Join-Path $caseDir 'default-panic'
                            $null=New-Item -ItemType Directory -Path $defaultDir
                            $defaultOracle=Join-Path $defaultDir 'oracle.o'
                            CompileUnit (Join-Path $fixture 'oracle.c') $defaultOracle ($caseFlags+@('-mgeneral-regs-only','-DEXEC_DEFAULT_PANIC=1'))
                            $defaultElf=Join-Path $defaultDir 'nonsecure.elf'
                            $defaultMembers=@($fixtureObjects | Select-Object -First 3)+@($defaultOracle,$expectation,'-Wl,--start-group',$commonArchive,$portArchive,'-Wl,--end-group')
                            $defaultLink=LinkImage $defaultElf $defaultMembers $flags (Join-Path $fixture 'nonsecure.ld')
                            Check "$name/default-common-panic-link" ($defaultLink.Code -eq 0) $defaultLink.Text
                            InspectImage ($name+'-default-panic') $defaultElf
                            $defaultSymbols=[IO.File]::ReadAllText($defaultElf+'.symbols.txt')
                            $weakInput=Defined $commonObjects[2]
                            $oracleInput=Defined $defaultOracle
                            Check "$name/sole-weak-input-panic" ($weakInput -match '(?m)^[0-9a-f]+\s+W\s+fiber_panic\r?$' -and
                                $oracleInput -notmatch '(?m)\bfiber_panic\r?$') $weakInput
                            # Closed-world LTO resolves the selected weak input
                            # to a final strong definition; do not demand W then.
                            $binding=if($lto){'[TW]'}else{'W'}
                            Check "$name/actual-default-panic" ($defaultSymbols -match ('(?m)^[0-9a-f]+\s+[0-9a-f]+\s+'+$binding+'\s+fiber_panic\r?$')) $defaultElf
                            $defaultDump=[IO.File]::ReadAllText($defaultElf+'.disassembly.txt')
                            $panicBodies=[regex]::Matches($defaultDump,'(?ms)^[0-9a-f]+ <fiber_panic>:\r?\n(.*?)(?=^[0-9a-f]+ <|\z)')
                            Check "$name/exact-default-panic-function" ($panicBodies.Count -eq 1) $defaultElf
                            $body=$panicBodies[0].Groups[1].Value
                            $barrierCall=[regex]::Match($body,'\b(?:bl|b\.w)\s+[0-9a-f]+ <fiber_port_runtime_memory_barrier>')
                            $waitCall=[regex]::Match($body,'\b(?:bl|b\.w)\s+[0-9a-f]+ <fiber_port_panic_wait>')
                            Check "$name/default-panic-real-barrier-then-wait" ($barrierCall.Success -and $waitCall.Success -and
                                $barrierCall.Index -lt $waitCall.Index) $defaultElf
                            $runs.Add([pscustomobject]@{Name=$name+'-default-panic';Executed=$false;NonsecureELF=$defaultElf;
                                Reason='Default weak common panic build/link only; terminal wait intentionally not executed'})
                            foreach($isSvc in @(0,1)) {
                                $duplicate=Join-Path $caseDir ("duplicate-$isSvc.o")
                                CompileUnit (Join-Path $fixture 'duplicate.c') $duplicate ($flags+@("-DDUPLICATE_SVC=$isSvc"))
                                $symbol=if($isSvc){'SVC_Handler'}else{'PendSV_Handler'}
                                $bad=LinkImage (Join-Path $caseDir ("duplicate-$isSvc.elf")) ($members+@($duplicate)) $flags (Join-Path $fixture 'nonsecure.ld')
                                Check "$name/duplicate-$symbol-rejected" ($bad.Code -ne 0 -and $bad.Text -match ('multiple definition of [^\r\n]*\b'+$symbol+'\b')) $bad.Text
                            }
                            $stateText=[IO.File]::ReadAllText((Join-Path $repo 'fiber/fiber_runtime_state.c'))
                            Check "$name/single-v1-definition-control" ([regex]::Matches($stateText,'fiber_internal_runtime_port_abi_v1_anchor').Count -eq 1) $stateText
                            $badStateSource=Join-Path $caseDir 'v2-state.c'
                            [IO.File]::WriteAllText($badStateSource,$stateText.Replace('fiber_internal_runtime_port_abi_v1_anchor','fiber_internal_runtime_port_abi_v2_anchor'))
                            $badState=Join-Path $caseDir 'v2-state.o'
                            CompileUnit $badStateSource $badState $commonFlags
                            $bad=LinkImage (Join-Path $caseDir 'missing-v1.elf') (@($fixtureObjects)+@($expectation,$commonObjects[0],$badState,$commonObjects[2])+$portObjects) $flags (Join-Path $fixture 'nonsecure.ld')
                            ExpectUndefined "$name/missing-v1-exact-rejection" $bad 'fiber_internal_runtime_port_abi_v1_anchor'
                            $svcText=[IO.File]::ReadAllText((Join-Path $port 'fiber_port_svc.c'))
                            Check "$name/single-provider-removal-control" ([regex]::Matches($svcText,'FIBER_PORT_CONTEXT_COHORT_DEFINE\(\);').Count -eq 1) $cohort
                            $badSvcSource=Join-Path $caseDir 'missing-cohort.c'
                            [IO.File]::WriteAllText($badSvcSource,$svcText.Replace('FIBER_PORT_CONTEXT_COHORT_DEFINE();','/* Deliberate negative: sole provider removed. */'))
                            $badSvc=Join-Path $caseDir 'missing-cohort.o'
                            CompileUnit $badSvcSource $badSvc $flags
                            $bad=LinkImage (Join-Path $caseDir 'missing-cohort.elf') (@($fixtureObjects)+@($expectation)+$commonObjects+@($portObjects[0],$badSvc,$portObjects[2])) $flags (Join-Path $fixture 'nonsecure.ld')
                            ExpectUndefined "$name/missing-cohort-exact-rejection" $bad $cohort
                            $other=if($regions -eq 8){16}else{8}
                            $otherFlags=@($flags | Where-Object {$_ -notlike '-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=*'})+@("-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$other")
                            foreach($stale in @(0,1)) {
                                $storage=Join-Path $caseDir ("stale-storage-$stale.o")
                                $storageFlags=if($stale){$flags}else{$otherFlags}
                                CompileUnit (Join-Path $fixture 'storage.c') $storage ($storageFlags+@("-DSTALE_REVISION=$stale"))
                                $symbol=if($stale){"fiber_port_storage_cohort_arm_cm33f_mpu_v0_r$regions"}else{"fiber_port_storage_cohort_arm_cm33f_mpu_v1_r$other"}
                                $bad=LinkImage (Join-Path $caseDir ("stale-storage-$stale.elf")) ($members+@($storage)) $flags (Join-Path $fixture 'nonsecure.ld')
                                ExpectUndefined "$name/stale-storage-$stale-exact-rejection" $bad $symbol
                            }
                            $wrongExpectation=Join-Path $caseDir 'other-expectation.o'
                            CompileUnit (Join-Path $repo 'fiber/port/fiber_port_context_cohort_expectation.c') $wrongExpectation $otherFlags
                            $u=RequireCommand $gccnm @('-u',$wrongExpectation) ($wrongExpectation+'.undefined.txt')
                            $otherCohort=[regex]::Match($u,'\bU\s+(fiber_port_context_cohort_\S+)').Groups[1].Value
                            Check "$name/other-cohort-nonempty" (![string]::IsNullOrWhiteSpace($otherCohort) -and $otherCohort -cne $cohort) $u
                            $bad=LinkImage (Join-Path $caseDir 'wrong-build-expectation.elf') (@($fixtureObjects)+@($wrongExpectation,'-Wl,--start-group',$commonArchive,$portArchive,'-Wl,--end-group')) $flags (Join-Path $fixture 'nonsecure.ld')
                            ExpectUndefined "$name/wrong-build-expectation-exact-rejection" $bad $otherCohort
                            $wrongBoot=Join-Path $caseDir 'other-boot.o'
                            CompileUnit (Join-Path $port 'fiber_port_boot.c') $wrongBoot $otherFlags
                            $bad=LinkImage (Join-Path $caseDir 'mixed-private-geometry.elf') (@($fixtureObjects)+@($expectation)+$commonObjects+@($wrongBoot,$portObjects[1],$portObjects[2])) $flags (Join-Path $fixture 'nonsecure.ld')
                            ExpectUndefined "$name/mixed-private-geometry-exact-rejection" $bad $otherCohort
                            $noPd=Join-Path $caseDir 'lib-no-pendsv.a'
                            Archive $noPd @($portObjects[0],$portObjects[1])
                            $bad=LinkImage (Join-Path $caseDir 'missing-pendsv.elf') (@($fixtureObjects)+@($expectation,'-Wl,--start-group',$commonArchive,$noPd,'-Wl,--end-group')) $flags (Join-Path $fixture 'nonsecure.ld')
                            ExpectUndefined "$name/weak-startup-cannot-hide-missing-pendsv" $bad 'fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor'
                            $noSvc=Join-Path $caseDir 'lib-no-svc.a'
                            Archive $noSvc @($portObjects[0],$portObjects[2])
                            $bad=LinkImage (Join-Path $caseDir 'missing-svc.elf') (@($fixtureObjects)+@($expectation,'-Wl,--start-group',$commonArchive,$noSvc,'-Wl,--end-group')) $flags (Join-Path $fixture 'nonsecure.ld')
                            ExpectUndefined "$name/weak-startup-cannot-hide-missing-svc" $bad 'fiber_port_runtime_prepare_start'
                        }
                    }
                }
            }
        }
    }
    $executed=@($runs | Where-Object {$_.Executed})
    Check 'receipt/unique-execution-logs' (@($executed.Log | Sort-Object -Unique).Count -eq $executed.Count) $executed.Count
    $verdict = 'PASS'
} catch {
    $failure=$_.Exception.Message
    [IO.File]::WriteAllText((Join-Path $out 'failure.txt'),$failure)
    throw
} finally {
    $after = HashInputs
    $after | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $drift = @(Compare-Object @($before | ForEach-Object {$_.Path+'='+$_.Hash}) @($after | ForEach-Object {$_.Path+'='+$_.Hash}))
    if ($drift.Count) {$verdict = 'FAIL'}
    $checks.ToArray() | ConvertTo-Json -Depth 7 | Set-Content (Join-Path $out 'checks.json') -Encoding ASCII
    $runs.ToArray() | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $out 'runs.json') -Encoding ASCII
    @{Verdict=$verdict;Evidence=$out;Checks=$checks.Count;Drift=$drift;Failure=$failure;
        Executed=@($runs | Where-Object {$_.Executed}).Count;CompileOnly=@($runs | Where-Object {!$_.Executed}).Count;
        SixteenRegionImages=@($runs | Where-Object {!$_.Executed -and $_.Name -like 'r16-*'}).Count;
        DefaultPanicLinkOnly=@($runs | Where-Object {!$_.Executed -and $_.Reason -like 'Default weak*'}).Count;
        ReferencePin=$pin;ReferenceIdentityChecked=$referenceChecked;ReferenceAssemblyCompared=$false;ReferenceExecuted=$false;
        ExpectedRuntimeSelectable=$ExpectedRuntimeSelectable;QemuRoot=$QemuRoot;
        Boundary='Real five-operation common runtime with production eight-operation provider; AN505 r8 execution, r16 compile/link only; no FreeRTOS execution, assembly parity, or hardware claim'} |
        ConvertTo-Json -Depth 7 | Set-Content (Join-Path $out 'receipt.json') -Encoding ASCII
    Get-ChildItem -LiteralPath $out -File -Recurse | Where-Object {$_.Name -ne 'artifact-hashes.json'} |
        ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256} | Select-Object Path,Hash |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'artifact-hashes.json') -Encoding ASCII
    if ($drift.Count) {throw "Running execution inputs changed during run: $out"}
}
Write-Host "PASS: C3FP full runtime ($($checks.Count) checks); evidence $out"
