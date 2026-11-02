param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$QemuRoot,
    [string]$WslDistro = 'Ubuntu-24.04',
    [string]$BuildRoot,
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 10
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture = Join-Path $PSScriptRoot 'fixtures\cm33f_mpu_first_start_execution'
$port = Join-Path $repo 'fiber\port\ARM_CM33F_MPU\non_secure'
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {throw 'Supply existing -ArmGcc'}
if (!$QemuRoot -or !$QemuRoot.StartsWith('/')) {
    throw 'An explicit existing absolute WSL -QemuRoot is required; no provisioning is supported'
}
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
foreach ($path in @($nm, $objdump, $readelf, $contract, (Join-Path $CmsisCore 'core_cm33.h'),
        (Join-Path $port 'fiber_port_pendsv.c'),
        (Join-Path $reference 'portasm.c'), (Join-Path $reference 'port.c'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {throw "Missing execution test dependency: $path"}
}
if (!$BuildRoot) {$BuildRoot = [IO.Path]::GetTempPath()}
$out = Join-Path $BuildRoot ('cm33f-mpu-first-start-execution-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out -Force
$commands = Join-Path $out 'commands.jsonl'
$checks = New-Object System.Collections.Generic.List[object]
$surfaceChecks = New-Object System.Collections.Generic.List[object]
$runs = New-Object System.Collections.Generic.List[object]
$verdict = 'FAIL'
$inputs = @($PSCommandPath, $ArmGcc, $nm, $objdump, $readelf,
    (Join-Path $repo 'mcu_core.h'), (Join-Path $repo 'basic_types.h')) +
    @(Get-ChildItem $fixture, $port -File -Recurse | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem (Join-Path $repo 'fiber') -File | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem (Join-Path $repo 'fiber\port') -File | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem $CmsisCore -Filter '*.h' -File -Recurse | Select-Object -ExpandProperty FullName) +
    @('port.c', 'portasm.c', 'portasm.h', 'portmacro.h' | ForEach-Object {Join-Path $reference $_})
function HashInputs {
    @($inputs | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} |
        Select-Object Path, Hash)
}
function Recorded([string]$File, [string[]]$Arguments, [string]$Log) {
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $File @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally {$ErrorActionPreference = $old}
    $text = ($lines | ForEach-Object {"$_"}) -join "`n"
    $text | Set-Content -LiteralPath $Log -Encoding ASCII
    @{File = $File; Arguments = $Arguments; ExitCode = $code; Log = $Log} |
        ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath $commands -Encoding ASCII
    [pscustomobject]@{Code = $code; Text = $text}
}
function RequireCommand([string]$File, [string[]]$Arguments, [string]$Log) {
    $result = Recorded $File $Arguments $Log
    if ($result.Code -ne 0) {throw "Command failed ($($result.Code)): $Log`n$($result.Text)"}
    $result.Text
}
function Check([string]$Name, [bool]$Condition, [object]$Evidence) {
    $checks.Add([pscustomobject]@{Name = $Name; Passed = $Condition; Evidence = $Evidence})
    if (!$Condition) {throw "Execution proof failed: $Name"}
}
function WslPath([string]$Path) {
    $result = RequireCommand 'wsl.exe' @('-d', $WslDistro, '--exec', 'wslpath', '-u', $Path) (Join-Path $out 'wslpath-last.log')
    $result.Trim()
}
function BuildSecure([string]$Name, [switch]$Probe) {
    $dir = Join-Path $out $Name
    $null = New-Item -ItemType Directory -Path $dir
    $flags = $base + @('-O2', '-mfloat-abi=soft', '-mgeneral-regs-only', '-mcmse',
        '-DEXEC_SECURE=1', "-I$fixture", "-I$CmsisCore")
    if ($Probe) {$flags += '-DEXEC_PROBE_ONLY=1'}
    $objects = @()
    foreach ($unit in @('startup.S', 'secure.c')) {
        $object = Join-Path $dir ($unit.Replace('.', '-') + '.o')
        $null = RequireCommand $ArmGcc ($flags + @('-save-temps=obj', '-MD', '-c',
            (Join-Path $fixture $unit), '-o', $object)) (Join-Path $dir ($unit + '.log'))
        $objects += $object
    }
    $elf = Join-Path $dir 'secure.elf'
    $null = RequireCommand $ArmGcc ($flags + @('-nostdlib', '-nostartfiles', '-Wl,--gc-sections',
        '-Wl,--no-undefined', '-T', (Join-Path $fixture 'secure.ld'), "-Wl,-Map,$dir/secure.map") +
        $objects + @('-o', $elf)) (Join-Path $dir 'link.log')
    $null = RequireCommand $objdump @('-drwC', $elf) (Join-Path $dir 'disassembly.txt')
    $elf
}
function Execute([string]$Name, [string]$SecureElf, [string]$NonsecureElf, [string]$Marker) {
    $dir = if ($NonsecureElf -eq 'none') {Split-Path $SecureElf} else {Split-Path $NonsecureElf}
    $securePath = WslPath $SecureElf
    $nonsecurePath = if ($NonsecureElf -eq 'none') {'none'} else {WslPath $NonsecureElf}
    $log = Join-Path $dir 'qemu.log'
    $result = Recorded 'wsl.exe' @('-d', $WslDistro, '--exec', 'bash', $qemuScript, 'run',
        $QemuRoot, $wslOut, $securePath, $nonsecurePath, [string]$TimeoutSeconds) $log
    $runs.Add([pscustomobject]@{Name = $Name; Executed = $true; ExitCode = $result.Code;
        Marker = $Marker; Log = $log; SecureELF = $SecureElf; NonsecureELF = $NonsecureElf})
    $nonempty = @($result.Text -split "`n" | Where-Object {!([string]::IsNullOrWhiteSpace($_))})
    Check "$Name/strict-exit-and-exact-terminal-marker" ($result.Code -eq 0 -and
        @($result.Text -split "`n" | Where-Object {$_.TrimEnd("`r") -ceq $Marker}).Count -eq 1 -and
        $nonempty.Count -gt 0 -and $nonempty[-1].TrimEnd("`r") -ceq $Marker -and
        $result.Text -cnotmatch '(FAIL:|FAILED_CHECK|Traceback|fatal:|Lockup|timed out)') $result.Text
    $result.Text
}
function ScalarValue([string]$Text, [string]$Name) {
    $found = [regex]::Matches($Text, '(?m)^' + [regex]::Escape($Name) + '=0x([0-9a-f]{8})\r?$')
    if ($found.Count -ne 1) {throw "Missing/duplicate actual CPU observation: $Name"}
    [Convert]::ToUInt32($found[0].Groups[1].Value, 16)
}
function Check-ServiceSurface([string]$Name, [string]$Elf, [string]$Directory, [string]$Assembly) {
    # Link/surface compatibility is recorded separately, leaving all 120 SVC70
    # execution checks intact. Neither generic adapter nor PendSV is executed here.
    $symbols = RequireCommand $readelf @('-sW', $Elf) (Join-Path $Directory 'surface-symbols.txt')
    $values = @{}
    foreach ($symbol in @('SVC_Handler', 'PendSV_Handler', 'fiber_port_yield_from_thread',
            'fiber_port_unprivileged_task_return', 'fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor',
            'fiber_port_handler_bundle_v1_anchor', 'fiber_port_runtime_memory_barrier', 'fiber_port_panic_wait',
            'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_prepare_start',
            'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first', 'fiber_port_runtime_schedule',
            'fiber_port_scheduler_pick_first_from_start', 'fiber_current', 'fiber_schedule')) {
        $rows = [regex]::Matches($symbols, '(?m)^\s*\d+:\s+([0-9a-fA-F]+)\s+([0-9]+)\s+FUNC\s+(\w+)\s+DEFAULT\s+[0-9]+\s+' +
            [regex]::Escape($symbol) + '\r?$')
        if ($rows.Count -ne 1 -or $rows[0].Groups[3].Value -cne 'GLOBAL' -or
                [Convert]::ToUInt32($rows[0].Groups[2].Value, 10) -eq 0) {
            throw "Missing/ambiguous strong production function: $Name/$symbol"
        }
        $values[$symbol] = [Convert]::ToUInt32($rows[0].Groups[1].Value, 16)
    }
    foreach ($symbol in @('fiber_port_handler_bundle_v1_anchor', 'fiber_port_panic_wait',
            'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_prepare_start',
            'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first', 'fiber_port_scheduler_pick_first_from_start')) {
        $address = $values[$symbol] -band [uint32]4294967294
        if ($address -lt 0x10000 -or $address -ge 0x20000) { throw "Adapter outside privileged code: $Name/$symbol" }
    }
    foreach ($symbol in @('fiber_port_runtime_memory_barrier', 'fiber_current', 'fiber_schedule')) {
        $address = $values[$symbol] -band [uint32]4294967294
        if ($address -lt 0x20000 -or $address -ge 0x28000) { throw "Thread dependency outside unprivileged code: $Name/$symbol" }
    }
    $schedule = $values['fiber_port_runtime_schedule'] -band [uint32]4294967294
    if ($schedule -lt 0x28000 -or $schedule -ge 0x29000) { throw "Schedule adapter outside syscall region: $Name" }
    foreach ($prefix in @('fiber_port_context_cohort_', 'fiber_port_storage_cohort_')) {
        $rows = [regex]::Matches($symbols, '(?m)^\s*\d+:\s+([0-9a-fA-F]+)\s+1\s+OBJECT\s+GLOBAL\s+DEFAULT\s+[0-9]+\s+' + $prefix + '\w+\r?$')
        if ($rows.Count -ne 1) { throw "Missing/duplicate production cohort provider: $Name/$prefix" }
        $address = [Convert]::ToUInt32($rows[0].Groups[1].Value, 16)
        if ($address -lt 0x10000 -or $address -ge 0x20000) { throw "Cohort provider outside readonly code: $Name/$prefix" }
    }
    $vectors = RequireCommand $objdump @('-s', '-j', '.vectors', $Elf) (Join-Path $Directory 'surface-vectors.txt')
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($line in ($vectors -split "`n")) {
        if ($line -match '^\s*[0-9a-f]+\s+((?:[0-9a-f]{8}(?:\s+|$)){1,4})') {
            foreach ($word in ($Matches[1].Trim() -split '\s+')) {
                for ($i = 0; $i -lt 8; $i += 2) {$bytes.Add([Convert]::ToByte($word.Substring($i, 2), 16))}
            }
        }
    }
    if ($bytes.Count -ne 2048 -or ![BitConverter]::IsLittleEndian) {throw "Invalid full vector image: $Name"}
    $data = $bytes.ToArray()
    foreach ($entry in @(@{Slot=11; Symbol='SVC_Handler'}, @{Slot=14; Symbol='PendSV_Handler'})) {
        if ([BitConverter]::ToUInt32($data, $entry.Slot * 4) -ne ($values[$entry.Symbol] -bor 1)) {
            throw "Vector does not reference exact strong production handler: $Name/$($entry.Slot)"
        }
    }
    foreach ($entry in @(@{Function='fiber_port_yield_from_thread'; Service=71; Opcode='df47'; Site='fiber_port_svc_yield_return_site'},
            @{Function='fiber_port_unprivileged_task_return'; Service=72; Opcode='df48'; Site='fiber_port_svc_return_return_site'})) {
        $address = $values[$entry.Function] -band [uint32]4294967294
        # GNU objdump may annotate the immediate with its matching hex value.
        $pattern = '(?m)^\s*0*' + $address.ToString('x') + ':\s+' + $entry.Opcode + '\s+svc\s+' +
            $entry.Service + '(?:\s+@\s+0x' + $entry.Service.ToString('x') + ')?\s*$'
        $sites = [regex]::Matches($symbols, '(?m)^\s*\d+:\s+([0-9a-fA-F]+)\s+0\s+NOTYPE\s+(\w+)\s+DEFAULT\s+[0-9]+\s+' +
            [regex]::Escape($entry.Site) + '\r?$')
        if ($Assembly -cnotmatch $pattern -or $sites.Count -ne 1 -or $sites[0].Groups[2].Value -cne 'GLOBAL' -or
                [Convert]::ToUInt32($sites[0].Groups[1].Value, 16) -ne ($address + 2)) {
            throw "Wrong real service veneer/owned return site: $Name/$($entry.Service)"
        }
    }
    $surfaceChecks.Add([pscustomobject]@{Name=$Name; Passed=$true; StrongVectors=@(11,14);
        ProductionServices=@(71,72); StrongColdComponentAnchor=$true;
        ProductionForwardOperations=8; StrongProductionBundle=$true; ProductionCohortProviders=2;
        NewServicesExecuted=$false; GenericAdaptersExecuted=$false; PendSvExecuted=$false; Elf=$Elf})
}
$before = HashInputs
$before | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII
try {
    Write-Host "C3FP actual first-start evidence: $out"
    $null = RequireCommand $ArmGcc @('--version') (Join-Path $out 'compiler.txt')
    $actualPin = (RequireCommand 'git' @('-C', $FreeRtosRoot, 'rev-parse', 'HEAD') (Join-Path $out 'reference-head.txt')).Trim()
    Check 'reference/exact-comparison-pin' ($actualPin -ceq $pin) $actualPin
    $null = RequireCommand 'git' @('-C', $FreeRtosRoot, 'diff', '--exit-code', 'HEAD', '--',
        "$referenceRelative/port.c", "$referenceRelative/portasm.c", "$referenceRelative/portasm.h", "$referenceRelative/portmacro.h") (Join-Path $out 'reference-comparison-diff.txt')
    $base = @('-mcpu=cortex-m33', '-mthumb', '-std=gnu11', '-ffreestanding', '-fno-builtin',
        '-fno-common', '-ffunction-sections', '-fdata-sections', '-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables', '-fno-instrument-functions', '-fno-stack-protector',
        '-fno-profile-arcs', '-fno-test-coverage', '-fno-profile', '-fno-stack-check',
        '-fno-sanitize=all', '-fno-sanitize-coverage=trace-pc', '-Wall', '-Wextra', '-Werror', '-Wundef')
    $wslOut = WslPath $out
    $qemuScript = WslPath (Join-Path $fixture 'qemu.sh')
    $null = RequireCommand 'wsl.exe' @('-d', $WslDistro, '--exec', 'bash', $qemuScript,
        'inspect', $QemuRoot, $wslOut) (Join-Path $out 'qemu-inspect.log')
    $probe = BuildSecure 'model-probe' -Probe
    $probeLog = Execute 'model-probe' $probe 'none' 'PASS:C3FP-MODEL-PROBE'
    $mpuType = ScalarValue $probeLog 'MODEL_MPU_TYPE'
    $priorityMask = ScalarValue $probeLog 'MODEL_PRIORITY_MASK'
    Check 'model/actual-eight-regions-not-forced-sixteen' (($mpuType -band 0xff00) -eq 0x800) $mpuType
    $priorityBits = 0
    $remaining = $priorityMask
    while ($remaining -band 0x80) {++$priorityBits; $remaining = ($remaining -shl 1) -band 0xff}
    Check 'model/actual-contiguous-priority-mask' ($priorityBits -ge 1 -and $priorityBits -le 8 -and $remaining -eq 0) $priorityMask
    @{MPUType = $mpuType; ExecutedRegions = 8; CompileOnlyRegions = 16; PriorityMask = $priorityMask;
        CmsisPriorityBits = $priorityBits; NSACR = (ScalarValue $probeLog 'SECURE_NSACR');
        MVFR0 = (ScalarValue $probeLog 'MODEL_MVFR0')} | ConvertTo-Json |
        Set-Content (Join-Path $out 'model.json') -Encoding ASCII
    $secureElf = BuildSecure 'secure-bootstrap'
    $cases = @(
        @{Id = 0; Name = 'initial-task'; Marker = 'PASS:C3FP-FIRST-START-EXECUTION'},
        @{Id = 1; Name = 'bad-control'; Marker = 'PASS:C3FP-BAD-INITIAL-CONTROL-REJECTED'},
        @{Id = 2; Name = 'missing-current'; Marker = 'PASS:C3FP-MISSING-CURRENT-REJECTED'},
        @{Id = 3; Name = 'private-read'; Marker = 'PASS:C3FP-UNPRIVILEGED-PRIVATE-READ-DENIED'},
        @{Id = 4; Name = 'unowned-svc70'; Marker = 'PASS:C3FP-UNOWNED-SVC70-REJECTED'},
        @{Id = 5; Name = 'current-write'; Marker = 'PASS:C3FP-UNPRIVILEGED-CURRENT-WRITE-DENIED'}
    )
    foreach ($optimization in @('-O2', '-Os')) {
        foreach ($abi in @('hard', 'softfp')) {
            foreach ($regions in @(8, 16)) {
                $mode = "r$regions-$abi-$($optimization.Substring(1))"
                $dir = Join-Path $out $mode
                $null = New-Item -ItemType Directory -Path $dir
                $flags = $base + @($optimization, '-mfpu=fpv5-sp-d16', "-mfloat-abi=$abi", '-ffixed-r9',
                    '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_ARMV8M_MAINLINE=1',
                    "-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$regions", "-DEXEC_NVIC_PRIO_BITS=$priorityBits",
                    '-DFIBER_FPU_LAZY=0', "-I$fixture", "-I$port", "-I$repo", "-I$repo/fiber",
                    "-I$repo/fiber/port", "-I$CmsisCore")
                $portObjects = @()
                foreach ($unit in @('fiber_port_boot.c', 'fiber_port_svc.c', 'fiber_port_pendsv.c')) {
                    $object = Join-Path $dir ($unit.Replace('.c', '.o'))
                    $null = RequireCommand $ArmGcc ($flags + @('-save-temps=obj', '-MD', '-c',
                        (Join-Path $port $unit), '-o', $object)) (Join-Path $dir ($unit + '.log'))
                    $exports = RequireCommand $nm @('-g', '--defined-only', $object) ($object + '.exports')
                    $cohorts = @([regex]::Matches($exports, '(?m)^\S+\s+R\s+(fiber_port_(?:context|storage)_cohort_\w+)\s*$') |
                        ForEach-Object {$_.Groups[1].Value})
                    if ($unit -eq 'fiber_port_svc.c') {
                        if ($cohorts.Count -ne 2 -or
                                @($cohorts | Where-Object {$_ -cmatch '^fiber_port_context_cohort_armv8m_mainline_p0x43334650u_l0x000100(?:08|10)u_'}).Count -ne 1 -or
                                @($cohorts | Where-Object {$_ -ceq "fiber_port_storage_cohort_arm_cm33f_mpu_v1_r$regions"}).Count -ne 1) {
                            throw "Production SVC must own the exact C3FP context/storage provider pair: $mode"
                        }
                    } elseif ($cohorts.Count) { throw "Only production SVC may own providers: $mode/$unit" }
                    $portObjects += $object
                }
                $selectedCases = if ($regions -eq 8) {$cases} else {@($cases[0])}
                foreach ($case in $selectedCases) {
                    $name = $mode + '-' + $case.Name
                    $caseDir = Join-Path $dir $case.Name
                    $null = New-Item -ItemType Directory -Path $caseDir
                    $caseFlags = $flags + @("-DEXEC_CASE=$($case.Id)")
                    $objects = @($portObjects)
                    foreach ($unit in @('startup.S', 'nonsecure.c')) {
                        $object = Join-Path $caseDir ($unit.Replace('.', '-') + '.o')
                        $null = RequireCommand $ArmGcc ($caseFlags + @('-save-temps=obj', '-MD', '-c',
                            (Join-Path $fixture $unit), '-o', $object)) (Join-Path $caseDir ($unit + '.log'))
                        $exports = RequireCommand $nm @('-g', '--defined-only', $object) ($object + '.exports')
                        if ($exports -match '\bfiber_port_(?:context|storage)_cohort_|\bfiber_port_(?:runtime_\w+|panic_wait|require_scheduler_configuration_environment|handler_bundle_v1_anchor)\b') {
                            throw "Execution fixture must not define production adapters/bundle/cohorts: $name/$unit"
                        }
                        $objects += $object
                    }
                    $elf = Join-Path $caseDir 'nonsecure.elf'
                    $null = RequireCommand $ArmGcc ($caseFlags + @('-nostdlib', '-nostartfiles',
                        '-Wl,--gc-sections', '-Wl,--no-undefined', '-T', (Join-Path $fixture 'nonsecure.ld'),
                        '-T', $contract, "-Wl,-Map,$caseDir/nonsecure.map") + $objects + @('-o', $elf)) (Join-Path $caseDir 'link.log')
                    $assembly = RequireCommand $objdump @('-drwC', $elf) (Join-Path $caseDir 'disassembly.txt')
                    $null = RequireCommand $nm @('-a', '-S', $elf) (Join-Path $caseDir 'symbols.txt')
                    $undefined = RequireCommand $nm @('-u', $elf) (Join-Path $caseDir 'undefined.txt')
                    $null = RequireCommand $readelf @('-hAW', $elf) (Join-Path $caseDir 'elf-attributes.txt')
                    Check "$name/no-undefined-symbols" ([string]::IsNullOrWhiteSpace($undefined)) $undefined
                    Check "$name/actual-owned-SVC70-opcode" ($assembly -match '(?m)^\s*[0-9a-f]+:\s+df46\s+svc\s+70\s*') $elf
                    Check-ServiceSurface $name $elf $caseDir $assembly
                    if ($regions -eq 16) {
                        $runs.Add([pscustomobject]@{Name = $name; Executed = $false;
                            Reason = 'Compile/link only: actual AN505 model reports eight MPU regions'; NonsecureELF = $elf})
                        continue
                    }
                    $log = Execute $name $secureElf $elf $case.Marker
                    Check "$name/actual-constructor-reached" ($log.Contains('PASS:C3FP-CONSTRUCTOR-REAL-CPU')) $log
                    if ($case.Id -in @(0, 3, 5)) {
                        Check "$name/actual-unprivileged-task-state-reached" ($log.Contains('PASS:C3FP-INITIAL-TASK-STATE')) $log
                    }
                }
            }
        }
    }
    if ($checks.Count -ne 120 -or $surfaceChecks.Count -ne 28) {
        throw 'Incomplete original 120-check SVC70 subset or 28-ELF service-surface compatibility grid'
    }
    $verdict = 'PASS'
} finally {
    $after = HashInputs
    $after | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $beforeLines = @($before | ForEach-Object {$_.Path + '=' + $_.Hash})
    $afterLines = @($after | ForEach-Object {$_.Path + '=' + $_.Hash})
    $drift = @(Compare-Object $beforeLines $afterLines)
    if ($drift.Count) {$verdict = 'FAIL'}
    $checks.ToArray() | ConvertTo-Json -Depth 7 | Set-Content (Join-Path $out 'checks.json') -Encoding ASCII
    $runs.ToArray() | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $out 'runs.json') -Encoding ASCII
    $surfaceChecks.ToArray() | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $out 'surface-checks.json') -Encoding ASCII
    @{Verdict = $verdict; Evidence = $out; Checks = $checks.Count; Drift = $drift;
        Executed = @($runs | Where-Object {$_.Executed}).Count;
        CompileOnly = @($runs | Where-Object {!$_.Executed}).Count;
        FirstStartSubsetChecks = $checks.Count; SurfaceCompatibilityChecks = $surfaceChecks.Count;
        ReferencePin = $pin; ReferenceIdentityChecked = $true;
        ReferenceAssemblyCompared = $false; ReferenceExecuted = $false;
        ReferenceAssemblyRunner = 'test_cm33f_mpu_first_start_codegen.ps1'; QemuRoot = $QemuRoot;
        Boundary = 'NS first basic restore only; no complete runtime, PendSV, FP context stress, or hardware claim'} |
        ConvertTo-Json -Depth 7 | Set-Content (Join-Path $out 'receipt.json') -Encoding ASCII
    Get-ChildItem -LiteralPath $out -File -Recurse | Where-Object {$_.Name -ne 'artifact-hashes.json'} |
        ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256} | Select-Object Path, Hash |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'artifact-hashes.json') -Encoding ASCII
    if ($drift.Count) {throw "Execution inputs changed during run: $out"}
}
Write-Host "PASS: C3FP actual first-start ($($checks.Count) checks); evidence $out"
