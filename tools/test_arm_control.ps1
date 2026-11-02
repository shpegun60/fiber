param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$BuildRoot,
    [string]$WslDistro = "Ubuntu-24.04",
    [string]$QemuRoot,
    [switch]$ProvisionQemu,
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 10
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
if ([string]::IsNullOrWhiteSpace($ArmGcc) -or
    -not (Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {
    throw "Actual ARM execution requires an existing -ArmGcc (or ARM_NONE_EABI_GCC)"
}
if ([string]::IsNullOrWhiteSpace($QemuRoot) -and -not $ProvisionQemu) {
    throw "Supply an existing isolated -QemuRoot; network provisioning requires explicit -ProvisionQemu"
}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$objdump = Join-Path (Split-Path $ArmGcc) "arm-none-eabi-objdump.exe"
if (-not (Test-Path -LiteralPath $objdump)) { throw "Missing ARM objdump: $objdump" }
if ([string]::IsNullOrWhiteSpace($BuildRoot)) { $BuildRoot = $env:TEMP }
$out = Join-Path $BuildRoot ("arm-control-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $out -Force | Out-Null
$out = (Resolve-Path -LiteralPath $out).Path
$fixture = Join-Path $PSScriptRoot "fixtures\arm_control"
$script:commands = Join-Path $out "commands.txt"

function Invoke-Recorded([string]$Executable, [string[]]$Arguments, [string]$Log) {
    Add-Content -LiteralPath $script:commands -Encoding ASCII -Value (
        '& "' + $Executable + '" ' + (($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '))
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $lines = & $Executable @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    $lines | Out-File -LiteralPath $Log -Encoding utf8
    return $code
}

function Convert-ToWsl([string]$Path) {
    $result = & wsl.exe -d $WslDistro --exec wslpath -u $Path
    if ($LASTEXITCODE -ne 0 -or -not $result) { throw "Cannot translate WSL path: $Path" }
    return ($result -join "").Trim()
}

$wslOut = Convert-ToWsl $out
$wslScript = Convert-ToWsl (Join-Path $fixture "qemu.sh")
if ([string]::IsNullOrWhiteSpace($QemuRoot)) {
    $rootResult = & wsl.exe -d $WslDistro --exec bash -c 'mktemp -d ~/fiber-qemu-control.XXXXXXXX'
    if ($LASTEXITCODE -ne 0) { throw "Cannot create isolated WSL QEMU directory" }
    $QemuRoot = ($rootResult -join "").Trim()
}
if (-not $QemuRoot.StartsWith("/")) { throw "-QemuRoot must be an absolute WSL path" }
$inputPaths = @($PSCommandPath, $ArmGcc, $objdump) +
    @(Get-ChildItem -LiteralPath $fixture -File | Select-Object -ExpandProperty FullName)
$inputsBefore = @($inputPaths | Sort-Object -Unique | ForEach-Object {
    Get-FileHash -LiteralPath $_
} |
    Select-Object Path,Hash)
$inputsBefore | ConvertTo-Json | Set-Content -LiteralPath `
    (Join-Path $out 'inputs-before.json') -Encoding ASCII
$caseRecords = New-Object System.Collections.Generic.List[object]
$expectedCases = 0
$verdict = 'FAIL'
try {
Write-Host "ARM CONTROL evidence: $out"
Write-Host "Isolated WSL QEMU: $QemuRoot"
Get-ChildItem -LiteralPath $fixture -File | Get-FileHash -Algorithm SHA256 |
    Format-Table -AutoSize | Out-File (Join-Path $out "fixture-sha256.txt") -Width 300
if ((Invoke-Recorded $ArmGcc @("--version") (Join-Path $out "compiler-version.txt")) -ne 0) {
    throw "ARM compiler identity failed"
}
$action = if ($ProvisionQemu) { "provision" } else { "inspect" }
$wslArguments = @("-d", $WslDistro, "--exec", "bash", $wslScript, $action, $QemuRoot, $wslOut)
if ((Invoke-Recorded "wsl.exe" $wslArguments (Join-Path $out "provision.log")) -ne 0) {
    throw "Isolated QEMU $action failed; see $out\provision.log (no sudo/install attempted)"
}
$machines = Get-Content -LiteralPath (Join-Path $out "qemu-machines.txt") -Raw
foreach ($machine in @("mps2-an505", "mps2-an385", "mps3-an547")) {
    if ($machines -notmatch "(?m)^$machine\s") { throw "QEMU lacks maintained machine $machine" }
}

$cases = @(
    @{ Name="m33"; Cpu="cortex-m33"; Machine="mps2-an505"; Rom="0x10000000"; Ram="0x30000000"; Two=2; Three=3; Exit=0; Marker="PASS:CONTROL:M33"; Define="" },
    @{ Name="m3"; Cpu="cortex-m3"; Machine="mps2-an385"; Rom="0"; Ram="0x20000000"; Two=0; Three=1; Exit=0; Marker="PASS:CONTROL:M3"; Define="" },
    @{ Name="m55"; Cpu="cortex-m55"; Machine="mps3-an547"; Rom="0"; Ram="0x20000000"; Two=2; Three=3; Exit=0; Marker="PASS:CONTROL:M55"; Define="" },
    @{ Name="m33-reject-raz-two"; Cpu="cortex-m33"; Machine="mps2-an505"; Rom="0x10000000"; Ram="0x30000000"; Two=2; Three=3; Exit=42; Marker="FAIL:CONTROL:bug-RAZ-two"; Define="-DBUG_RAZ_TWO=1" },
    @{ Name="m33-reject-raz-three"; Cpu="cortex-m33"; Machine="mps2-an505"; Rom="0x10000000"; Ram="0x30000000"; Two=2; Three=3; Exit=43; Marker="FAIL:CONTROL:bug-RAZ-three"; Define="-DBUG_RAZ_THREE=1" },
    @{ Name="m33-banked-sg"; Cpu="cortex-m33"; Machine="mps2-an505"; Rom="0x10000000"; Ram="0x30000000"; Two=2; Three=3; Exit=0; Marker="PASS:CONTROL:M33-banked-SG"; Define=""; Banked=$true },
    @{ Name="m33-secure-origin"; Cpu="cortex-m33"; Machine="mps2-an505"; Rom="0x10000000"; Ram="0x30000000"; Two=2; Three=3; Exit=0; Marker="PASS:CONTROL:M33-Secure-origin-NS-PendSV"; Define=""; Banked=$true; Source="origin" },
    @{ Name="m33-origin-no-pendsv"; Cpu="cortex-m33"; Machine="mps2-an505"; Rom="0x10000000"; Ram="0x30000000"; Two=2; Three=3; Exit=81; Marker="FAIL:ORIGIN:EXC_RETURN"; Define="-DORIGIN_DROP_PENDSV=1"; Banked=$true; Source="origin" },
    @{ Name="m33-origin-no-clobber"; Cpu="cortex-m33"; Machine="mps2-an505"; Rom="0x10000000"; Ram="0x30000000"; Two=2; Three=3; Exit=88; Marker="FAIL:ORIGIN:missing-NS-clobber"; Define="-DORIGIN_KEEP_SECURE_GPRS=1"; Banked=$true; Source="origin" },
    @{ Name="m33-origin-wrong-ns-frame"; Cpu="cortex-m33"; Machine="mps2-an505"; Rom="0x10000000"; Ram="0x30000000"; Two=2; Three=3; Exit=83; Marker="FAIL:ORIGIN:NS-PSP"; Define="-DORIGIN_EXPECT_NS_HARDWARE_FRAME=1"; Banked=$true; Source="origin" }
)
$expectedCases = $cases.Count
foreach ($case in $cases) {
    $elf = Join-Path $out ($case.Name + ".elf")
    $cpuName = switch ($case.Cpu) {
        "cortex-m33" { "M33" }
        "cortex-m55" { "M55" }
        "cortex-m3" { "M3" }
        default { throw "Unknown maintained CPU: $($case.Cpu)" }
    }
    $source = if ($case.ContainsKey("Banked")) { "banked" } else { "control" }
    $linker = $source
    if ($case.ContainsKey("Source")) { $source = $case.Source }
    $arguments = @("-mcpu=$($case.Cpu)", "-mthumb", "-mfloat-abi=soft", "-mgeneral-regs-only",
        "-std=c11", "-O2", "-g3", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
        "-Wall", "-Wextra", "-Werror", "-nostdlib", "-nostartfiles",
        "-DEXPECT_TWO=$($case.Two)", "-DEXPECT_THREE=$($case.Three)",
        "-DCONTROL_CPU=$cpuName", "-Wl,--build-id=none",
        "-Wl,--defsym,ROM_BASE=$($case.Rom),--defsym,RAM_BASE=$($case.Ram)",
        "-Wl,-Map,$($elf.Replace('.elf', '.map'))", "-T", (Join-Path $fixture "$linker.ld"),
        (Join-Path $fixture "$source.S"), (Join-Path $fixture "$source.c"), "-o", $elf)
    if ($case.ContainsKey("Banked")) { $arguments += "-mcmse" }
    if ($case.Define) { $arguments += $case.Define }
    if ((Invoke-Recorded $ArmGcc $arguments (Join-Path $out ($case.Name + "-compile.log"))) -ne 0) {
        throw "ARM compile failed: $($case.Name); evidence $out"
    }
    if ((Invoke-Recorded $objdump @("-drwC", $elf) (Join-Path $out ($case.Name + ".dis"))) -ne 0) {
        throw "ARM disassembly failed: $($case.Name)"
    }
    $log = Join-Path $out ($case.Name + "-qemu.log")
    $arguments = @("-d", $WslDistro, "--exec", "bash", $wslScript, "run", $QemuRoot,
        $wslOut, $case.Machine, (Convert-ToWsl $elf), "$TimeoutSeconds")
    $code = Invoke-Recorded "wsl.exe" $arguments $log
    $trace = Get-Content -LiteralPath $log -Raw
    if ($code -ne $case.Exit -or $trace -notmatch ([regex]::Escape($case.Marker) + "(?:\r?\n|$)")) {
        throw "QEMU $($case.Name): exit $code, expected $($case.Exit) and $($case.Marker); see $log"
    }
    Add-Content -LiteralPath (Join-Path $out "results.txt") -Encoding ASCII -Value (
        "$($case.Name): exit=$code marker=$($case.Marker)")
    $caseRecords.Add([pscustomobject]@{Name=$case.Name;Exit=$code;
        Marker=$case.Marker;Elf=$elf;Log=$log})
    Write-Host "PASS: $($case.Name) (actual QEMU exit $code)"
}
Get-ChildItem -LiteralPath $out -Filter *.elf | Get-FileHash -Algorithm SHA256 |
    Format-Table -AutoSize | Out-File (Join-Path $out "elf-sha256.txt") -Width 300
Write-Host "PASS: actual ARM CONTROL transitions; evidence $out"
$verdict = 'PASS'
} finally {
    $drift = @($inputsBefore | Where-Object {
        !(Test-Path -LiteralPath $_.Path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $_.Path).Hash -cne $_.Hash
    })
    if ($drift.Count -ne 0) { $verdict = 'FAIL' }
    [pscustomobject]@{Status=$verdict;ExpectedCases=$expectedCases;
        CompletedCases=$caseRecords.Count;Cases=$caseRecords.ToArray();
        InputDrift=$drift;QemuRoot=$QemuRoot;WslDistro=$WslDistro;
        Boundary='Actual QEMU architecture probes and fixture controls; no production-port or board execution'} |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath `
            (Join-Path $out 'receipt.json') -Encoding ASCII
    Get-ChildItem -LiteralPath $out -File | Where-Object Name -ne 'artifacts.json' |
        Get-FileHash | Select-Object Path,Hash | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $out 'artifacts.json') -Encoding ASCII
    if ($drift.Count -ne 0) { throw "Architecture-probe input drift: $out" }
}
