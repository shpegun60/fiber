param(
    [Parameter(Mandatory=$true)][string]$ArmGcc,
    [Parameter(Mandatory=$true)][string]$CmsisCore,
    [Parameter(Mandatory=$true)][string]$FreeRtosRoot,
    [Parameter(Mandatory=$true)][string]$QemuRoot,
    [string]$WslDistro = 'Ubuntu-24.04',
    [string]$BuildRoot,
    [string]$Python = 'python',
    [string]$PythonModules = $env:FIBER_CLASSIC_AUDIT_PYTHONPATH,
    [switch]$ExecutePilot
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
function Assert-Cm4MpuPilotReceipt {
    param([object]$Receipt,[bool]$Execute)
    $verdict=if($Execute){'PILOT-PASS'}else{'COMPILE-PREFLIGHT-PASS'}
    $execution=if($Execute){'PILOT_ONLY'}else{'NOT_RUN'}
    $status=if($Execute){'PASS'}else{'COMPILED'}
    if (!($Receipt -is [pscustomobject]) -or !($Receipt.Verdict -is [string]) -or $Receipt.Verdict -cne $verdict -or
            !($Receipt.Execution -is [string]) -or $Receipt.Execution -cne $execution -or
            !($Receipt.CompleteSuite -is [bool]) -or $Receipt.CompleteSuite -ne $false -or
            !($Receipt.CompileOnly -is [bool]) -or $Receipt.CompileOnly -ne (-not $Execute)) {
        throw 'Pilot request-bound mode mismatch'
    }
    if (!($Receipt.ArtifactsVerifiedBeforePass -is [bool]) -or $Receipt.ArtifactsVerifiedBeforePass -ne $true) {
        throw 'Pilot artifacts were not verified before pass'
    }
    if (!($Receipt.Rows -is [array]) -or $Receipt.Rows.Count -ne 6) { throw 'Pilot needs six ordered rows' }
    function Assert-PilotActual([object]$Actual) {
        if (!($Actual -is [pscustomobject]) -or !($Actual.Exit -is [int]) -or $Actual.Exit -ne 0 -or
                !($Actual.TimedOut -is [bool]) -or $Actual.TimedOut -ne $false -or
                !($Actual.Stdout -is [string]) -or $Actual.Stdout -cne '' -or
                !($Actual.Stderr -is [string]) -or $Actual.Stderr.Length -eq 0) { throw 'Pilot execution evidence missing/invalid' }
    }
    $consumers=@('context','context','context','fiber','fiber','fiber')
    $cases=@(0,1,2,0,1,2)
    $keys=@()
    for($i=0;$i -lt 6;$i++) {
        $row=$Receipt.Rows[$i]
        if (!($row.Consumer -is [string]) -or $row.Consumer -cne $consumers[$i] -or
                !($row.Case -is [int]) -or $row.Case -ne $cases[$i]) { throw 'Pilot exact ordered consumer/case mismatch' }
        $keys+=($row.Consumer+':'+$row.Case)
        if (!($row.Status -is [string]) -or $row.Status -cne $status -or
                !($row.Executed -is [bool]) -or $row.Executed -ne $Execute) { throw 'Pilot row execution state mismatch' }
        if ($Execute) {
            if ($null -eq $row.PSObject.Properties['Actual']) { throw 'Pilot row execution evidence missing' }
            Assert-PilotActual $row.Actual
        } elseif ($null -ne $row.PSObject.Properties['Actual']) { throw 'Compile row contains execution evidence' }
    }
    if (@($keys | Sort-Object -CaseSensitive -Unique).Count -ne 6) { throw 'Pilot duplicate consumer/case rows' }
    $model=$Receipt.ModelProbe
    if (!($model -is [pscustomobject]) -or !($model.Name -is [string]) -or $model.Name -cne 'model' -or
            !($model.Consumer -is [string]) -or $model.Consumer -cne 'context' -or
            !($model.Case -is [int]) -or $model.Case -ne 0) { throw 'Pilot explicit model identity mismatch' }
    if (!($model.Status -is [string]) -or $model.Status -cne $status -or
            !($model.Executed -is [bool]) -or $model.Executed -ne $Execute) { throw 'Pilot model execution state mismatch' }
    if ($Execute) {
        if ($null -eq $model.PSObject.Properties['Actual'] -or $null -eq $Receipt.PSObject.Properties['ObservedModel']) {
            throw 'Pilot observed model evidence missing'
        }
        Assert-PilotActual $model.Actual
        $observed=$Receipt.ObservedModel
        $fields=@('CPUID','MPU_TYPE','NVIC_MASK','MVFR0','MPU_CTRL')
        if (!($observed -is [pscustomobject]) -or @(Compare-Object -CaseSensitive $fields @($observed.PSObject.Properties.Name)).Count) {
            throw 'Pilot observed model fields mismatch'
        }
        foreach($field in $fields) { if (!($observed.$field -is [int])) { throw 'Pilot observed model field type mismatch' } }
        if (($observed.CPUID -band 0xFF0FFFF0) -ne 0x410FC240 -or $observed.MPU_TYPE -ne 0x800 -or
                $observed.NVIC_MASK -ne 0xFF -or ($observed.MVFR0 -band 0xFFF) -ne 0x21 -or $observed.MPU_CTRL -ne 0) {
            throw 'Pilot observed model facts mismatch'
        }
    } elseif ($null -ne $model.PSObject.Properties['Actual'] -or $null -ne $Receipt.PSObject.Properties['ObservedModel']) {
        throw 'Compile model contains execution evidence'
    }
}
function Test-Cm4MpuPilotClosingControls {
    param([object]$Controls)
    $suffixes=@('positive','verdict','execution','completion','completion-type','compile-only',
        'artifacts-unverified','artifacts-type','artifacts-missing','order','duplicate','missing',
        'case-bool','consumer','row-status','row-executed','row-executed-type','model-status','model-executed','model-executed-type',
        'row-actual','model-actual','observed-model')
    $names=@()
    foreach($prefix in @('compile-','execute-')) { foreach($suffix in $suffixes) { $names+=($prefix+$suffix) } }
    $names+=@('execute-skipped-0','execute-skipped-1','execute-skipped-2','execute-skipped-3','execute-skipped-4','execute-skipped-5','execute-skipped-model')
    if (!($Controls -is [array]) -or $Controls.Count -ne 53) { throw 'Pilot needs 53 synthetic closing controls' }
    for($i=0;$i -lt 53;$i++) {
        $control=$Controls[$i]
        $execute=$names[$i].StartsWith('execute-',[StringComparison]::Ordinal)
        $expected=$names[$i] -ceq 'compile-positive' -or $names[$i] -ceq 'execute-positive'
        if ($control.Name -cne $names[$i] -or !($control.ExecutePilot -is [bool]) -or $control.ExecutePilot -ne $execute -or
                !($control.Accepted -is [bool]) -or $control.Accepted -ne $expected) { throw 'Pilot closing control inventory mismatch' }
        $accepted=$true
        try { Assert-Cm4MpuPilotReceipt -Receipt $control.Receipt -Execute $execute } catch { $accepted=$false }
        if ($accepted -ne $expected) { throw ('Pilot PowerShell closing control failed: '+$control.Name) }
    }
}
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$BuildRoot) { $BuildRoot=Join-Path $env:TEMP ('classic-cm4-mpu-pilot-'+[guid]::NewGuid().ToString('N')) }
if (Test-Path -LiteralPath $BuildRoot) { throw 'Use a new evidence directory' }
if (!$QemuRoot.StartsWith('/')) { throw 'Supply explicit existing absolute WSL QemuRoot; no provisioning' }
$arguments=@('-B',(Join-Path $PSScriptRoot 'fixtures/classic_cm4_mpu_context_runtime/run.py'),
    '--repo',$repo,'--gcc',(Resolve-Path -LiteralPath $ArmGcc).Path,
    '--cmsis',(Resolve-Path -LiteralPath $CmsisCore).Path,
    '--freertos',(Resolve-Path -LiteralPath $FreeRtosRoot).Path,
    '--qemu-root',$QemuRoot,'--wsl-distro',$WslDistro,'--build-root',$BuildRoot)
if ($ExecutePilot) { $arguments+='--execute-pilot' } else { $arguments+='--compile-preflight' }
$oldPythonPath=$env:PYTHONPATH
try {
    if (!$PythonModules) { $PythonModules=Join-Path $env:TEMP 'fiber-classic-audit-python' }
    if (!(Test-Path -LiteralPath $PythonModules -PathType Container)) { throw 'Existing pyelftools 0.33 required; no installation' }
    $env:PYTHONPATH=$PythonModules+[IO.Path]::PathSeparator+$oldPythonPath
    & $Python @arguments
    if ($LASTEXITCODE -ne 0) { throw "Pilot failed; preserve $BuildRoot" }
    $r=Get-Content -LiteralPath (Join-Path $BuildRoot 'results.json') -Raw | ConvertFrom-Json
    Test-Cm4MpuPilotClosingControls $r.ClosingContractControls.Controls
    Assert-Cm4MpuPilotReceipt -Receipt $r -Execute $ExecutePilot.IsPresent
    if (!($r.FinalizerControls.Controls -is [array]) -or $r.FinalizerControls.Controls.Count -ne 4) {
        throw 'Actual-finish orchestration controls missing'
    }
    $finalizerNames=@('positive','first-manifest','final-manifest','prior-error')
    for($i=0;$i -lt 4;$i++) {
        $control=$r.FinalizerControls.Controls[$i]
        $expected=$i -eq 0
        $verdict=if($expected){'COMPILE-PREFLIGHT-PASS'}else{'FAIL'}
        if ($control.Name -cne $finalizerNames[$i] -or !($control.Accepted -is [bool]) -or
                $control.Accepted -ne $expected -or $control.PersistedVerdict -cne $verdict) {
            throw 'Wrong actual-finish orchestration result'
        }
    }
} finally { $env:PYTHONPATH=$oldPythonPath }
