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
. (Join-Path $repo 'tools/runtime_sources.ps1')
$runtimeRoles = @('engine','state','panic','legacy_compat')
$runtimeSources = @(Get-RuntimeSourcePaths -RepositoryRoot $repo -Roles $runtimeRoles)
$fixture = Join-Path $PSScriptRoot 'fixtures\cm33f_mpu_running_execution'
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
$contract = Join-Path $port 'fiber_port_linker_contract.ld'
foreach ($path in @($nm,$objdump,$readelf,$contract,(Join-Path $port 'fiber_port_pendsv.c'),
        (Join-Path $CmsisCore 'core_cm33.h'),(Join-Path $bootstrap 'qemu.sh'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {throw "Missing running execution dependency: $path"}
}
if (!$BuildRoot) {$BuildRoot = [IO.Path]::GetTempPath()}
$out = Join-Path $BuildRoot ('cm33f-mpu-running-execution-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out -Force
$commands = Join-Path $out 'commands.jsonl'
$checks = New-Object System.Collections.Generic.List[object]
$runs = New-Object System.Collections.Generic.List[object]
$verdict = 'FAIL'
$referenceChecked = $false
$failure = ''
$inputs = @($PSCommandPath,$ArmGcc,$nm,$objdump,$readelf,
    (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h')) +
    @(Get-RuntimeSourceInputs -RepositoryRoot $repo -Roles $runtimeRoles) +
    @(Get-ChildItem (Join-Path $repo 'context') -File | Where-Object {$_.Extension -in @('.c','.h')} | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem $fixture -File -Recurse | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem $port -File -Recurse | Where-Object {$_.Extension -in @('.c','.h','.S','.ld')} | Select-Object -ExpandProperty FullName) +
    @('main.h','report.h','startup.S','secure.c','secure.ld','qemu.sh' | ForEach-Object {Join-Path $bootstrap $_}) +
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
# Record the actual compiler subprocesses and system include headers, not only gcc.exe.
foreach ($program in @('cc1','as','ld')) {
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
    Write-Host "C3FP actual running execution evidence: $out"
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
    $qemuScript = WslPath (Join-Path $fixture 'qemu.sh')
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
            foreach ($regions in @(8,16)) {
                foreach ($lazy in @(0,1)) {
                    $mode = "r$regions-$abi-$($optimization.Substring(1))-lazy$lazy"
                    $dir = Join-Path $out $mode
                    $null = New-Item -ItemType Directory -Path $dir
                    $flags = $base + @($optimization,'-mfpu=fpv5-sp-d16',"-mfloat-abi=$abi",'-ffixed-r9',
                        '-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV8M_MAINLINE=1',
                        "-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$regions","-DFIBER_FPU_LAZY=$lazy", "-DEXEC_NVIC_PRIO_BITS=$priorityBits",
                        "-I$fixture","-I$port","-I$repo","-I$repo/fiber","-I$repo/fiber/port","-I$CmsisCore")
                    $portObjects = @()
                    foreach ($unit in @('fiber_port_boot.c','fiber_port_svc.c','fiber_port_pendsv.c')) {
                        $object = Join-Path $dir ($unit.Replace('.c','.o'))
                        $null = RequireCommand $ArmGcc ($flags + @('-save-temps=obj','-MD','-c',(Join-Path $port $unit),'-o',$object)) (Join-Path $dir ($unit+'.log'))
                        $portObjects += $object
                    }
                    foreach ($source in $runtimeSources) {
                        $unit = $source.Substring($repo.Length+1).Replace('\','_').Replace('/','_')
                        $object = Join-Path $dir $unit.Replace('.c','.o')
                        $null = RequireCommand $ArmGcc ($flags + @('-mgeneral-regs-only','-save-temps=obj','-MD','-c',
                            $source,'-o',$object)) (Join-Path $dir ($unit+'.log'))
                        $portObjects += $object
                    }
                    $cases = @(@{Id=0;FP=0;Name='basic';Marker='PASS:C3FP-RUNNING-EXECUTION'},
                        @{Id=0;FP=1;Name='extended';Marker='PASS:C3FP-RUNNING-EXECUTION'},
                        @{Id=0;FP=2;Name='mixed';Marker='PASS:C3FP-RUNNING-EXECUTION'})
                    if ($regions -eq 8 -and $lazy -eq 0) {
                        foreach ($id in 1..8) {
                            $marker = if ($id -le 2) {'PASS:C3FP-UNOWNED-SVC-REJECTED'} elseif ($id -eq 8) {'PASS:C3FP-CURRENT-WRITE-DENIED'} else {'PASS:C3FP-CANDIDATE-OR-CALLBACK-REJECTED'}
                            $cases += @{Id=$id;FP=0;Name="negative-$id";Marker=$marker}
                        }
                    }
                    foreach ($case in $cases) {
                        $name = $mode+'-'+$case.Name
                        $caseDir = Join-Path $dir $case.Name
                        $null = New-Item -ItemType Directory -Path $caseDir
                        $caseFlags = $flags + @("-DEXEC_CASE=$($case.Id)","-DEXEC_FP=$($case.FP)",
                            "-DEXEC_EXPECT_RUNTIME_SELECTABLE=$ExpectedRuntimeSelectable")
                        $objects = @($portObjects)
                        foreach ($unit in @('startup.S','nonsecure.c')) {
                            $object = Join-Path $caseDir ($unit.Replace('.','-')+'.o')
                            $null = RequireCommand $ArmGcc ($caseFlags + @('-save-temps=obj','-MD','-c',(Join-Path $fixture $unit),'-o',$object)) (Join-Path $caseDir ($unit+'.log'))
                            $objects += $object
                        }
                        $elf = Join-Path $caseDir 'nonsecure.elf'
                        $null = RequireCommand $ArmGcc ($caseFlags + @('-nostdlib','-nostartfiles','-Wl,--gc-sections',
                            '-Wl,--no-undefined','-T',(Join-Path $fixture 'nonsecure.ld'),'-T',$contract,"-Wl,-Map,$caseDir/nonsecure.map") + $objects + @('-o',$elf)) (Join-Path $caseDir 'link.log')
                        $assembly = RequireCommand $objdump @('-drwC',$elf) (Join-Path $caseDir 'disassembly.txt')
                        $symbols = RequireCommand $nm @('-a','-S',$elf) (Join-Path $caseDir 'symbols.txt')
                        $undefined = RequireCommand $nm @('-u',$elf) (Join-Path $caseDir 'undefined.txt')
                        $null = RequireCommand $readelf @('-hAW',$elf) (Join-Path $caseDir 'elf-attributes.txt')
                        Check "$name/no-undefined" ([string]::IsNullOrWhiteSpace($undefined)) $undefined
                        foreach ($service in @(70,71,72)) {
                            $opcode = '{0:x4}' -f (0xdf00+$service)
                            Check "$name/actual-SVC$service" ($assembly -match "(?m)^\s*[0-9a-f]+:\s+$opcode\s+svc\s+$service\s*" ) $elf
                        }
                        foreach ($symbol in @('SVC_Handler','PendSV_Handler','fiber_internal_runtime_select_scheduler_candidate',
                                'fiber_internal_runtime_publish_current_context','fiber_internal_runtime_port_abi_v1_anchor')) {
                            Check "$name/exact-definition-$symbol" (@([regex]::Matches($symbols,"(?m)^[0-9a-f]+\s+[0-9a-f]+\s+[A-Za-z]\s+"+[regex]::Escape($symbol)+'\r?$')).Count -eq 1) $elf
                        }
                        Check "$name/real-production-barrier" ($symbols -match '(?m)^[0-9a-f]+\s+[0-9a-f]+\s+T\s+fiber_port_runtime_memory_barrier\r?$' -and
                            $symbols -notmatch '(?m)\bfixture_common_memory_barrier\r?$') $elf
                        if ($regions -eq 16) {
                            $runs.Add([pscustomobject]@{Name=$name;Executed=$false;NonsecureELF=$elf;Reason='Compile/link only: AN505 reports eight MPU regions'})
                            continue
                        }
                        $log = Execute $name $secureElf $elf $case.Marker
                        Check "$name/actual-common-policy" ($log.Contains('PASS:C3FP-REAL-COMMON-POLICY')) $log
                        if ($case.Id -eq 0) {
                            Check "$name/six-observed-PendSV-selections" (@([regex]::Matches($log,'(?m)^PENDSV_SELECTION=0x[0-9a-f]{8}\r?$')).Count -eq 6 -and (ScalarValue $log 'VERIFIED_SWITCHES') -eq 6) $log
                            $fpTasks = if ($case.FP -eq 1) {2} elseif ($case.FP -eq 2) {1} else {0}
                            Check "$name/FP-observation" ((ScalarValue $log 'VERIFIED_FP_REGISTERS') -eq (32*[int]($case.FP -ne 0)) -and
                                (ScalarValue $log 'VERIFIED_FP_TASKS') -eq $fpTasks) $log
                            $tracePath = Join-Path $caseDir 'qemu-exceptions.log'
                            $trace = [IO.File]::ReadAllText($tracePath)
                            $tailchains = [regex]::Matches($trace,'(?m)^Exception return: magic PC ffffff(bc|ac) previous exception 11\r?\n\.\.\.tailchaining to pending exception\r?\n\.\.\.taking pending nonsecure exception 14\r?$')
                            $extendedCount = @($tailchains | Where-Object {$_.Groups[1].Value -ceq 'ac'}).Count
                            $expectedExtended = 3*$fpTasks
                            Check "$name/actual-six-SVC-to-PendSV-tailchains" ($tailchains.Count -eq 6 -and $extendedCount -eq $expectedExtended -and
                                @([regex]::Matches($trace,'(?m)^\.\.\.taking pending nonsecure exception 14\r?$')).Count -eq 6 -and
                                @([regex]::Matches($trace,'(?m)^Exception return: magic PC ffffff(?:bc|ac) previous exception 14\r?\n\.\.\.successful exception return\r?$')).Count -eq 6) $tracePath
                        }
                    }
                }
            }
        }
    }
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
        ReferencePin=$pin;ReferenceIdentityChecked=$referenceChecked;ReferenceAssemblyCompared=$false;ReferenceExecuted=$false;
        ExpectedRuntimeSelectable=$ExpectedRuntimeSelectable;QemuRoot=$QemuRoot;
        Boundary='AN505 M33 private component entry with actual common/provider objects and production barrier; not public start/schedule integration; r16 compile-only; no parity or hardware claim'} |
        ConvertTo-Json -Depth 7 | Set-Content (Join-Path $out 'receipt.json') -Encoding ASCII
    Get-ChildItem -LiteralPath $out -File -Recurse | Where-Object {$_.Name -ne 'artifact-hashes.json'} |
        ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256} | Select-Object Path,Hash |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'artifact-hashes.json') -Encoding ASCII
    if ($drift.Count) {throw "Running execution inputs changed during run: $out"}
}
Write-Host "PASS: C3FP actual running execution ($($checks.Count) checks); evidence $out"
