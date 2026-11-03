param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [Parameter(Mandatory=$true)][string]$QemuRoot,
    [string]$WslDistro = 'Ubuntu-24.04',
    [string]$BuildRoot,
    [string]$Python = 'python',
    [string]$PythonModules = $env:FIBER_CLASSIC_AUDIT_PYTHONPATH,
    [switch]$DevelopmentSmoke,
    [switch]$FullOptimizationGridFP
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($ArmGcc) -or
        -not (Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {
    throw 'Supply an existing -ArmGcc; this runner does not discover a compiler'
}
if ([string]::IsNullOrWhiteSpace($CmsisCore) -or
        -not (Test-Path -LiteralPath (Join-Path $CmsisCore 'core_cm7.h') -PathType Leaf)) {
    throw 'Supply an existing -CmsisCore containing core_cm7.h'
}
if ([string]::IsNullOrWhiteSpace($QemuRoot) -or -not $QemuRoot.StartsWith('/')) {
    throw 'Supply an existing absolute WSL -QemuRoot; provisioning is not supported'
}
if ([string]::IsNullOrWhiteSpace($FreeRtosRoot)) {
    $FreeRtosRoot = Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel'
}
if (-not (Test-Path -LiteralPath $FreeRtosRoot -PathType Container)) {
    throw 'Supply the clean pinned FreeRTOS checkout with -FreeRtosRoot'
}
if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $BuildRoot = Join-Path $env:TEMP ('classic-cm7-fp-context-runtime-' + [guid]::NewGuid().ToString('N'))
}
if (Test-Path -LiteralPath $BuildRoot) {
    throw "Runtime evidence output must not already exist: $BuildRoot"
}

$arguments = @(
    (Join-Path $PSScriptRoot 'fixtures\classic_cm7_fp_context_runtime\run.py'),
    '--repo', $repo,
    '--gcc', (Resolve-Path -LiteralPath $ArmGcc).Path,
    '--cmsis', (Resolve-Path -LiteralPath $CmsisCore).Path,
    '--freertos', (Resolve-Path -LiteralPath $FreeRtosRoot).Path,
    '--qemu-root', $QemuRoot,
    '--wsl-distro', $WslDistro,
    '--build-root', $BuildRoot
)
if ($DevelopmentSmoke) { $arguments += '--development-smoke' }
if ($FullOptimizationGridFP) { $arguments += '--full-optimization-grid-fp' }
$oldPythonPath = $env:PYTHONPATH
try {
    if ([string]::IsNullOrWhiteSpace($PythonModules)) {
        $cache = Join-Path $env:TEMP 'fiber-classic-audit-python'
        if (Test-Path -LiteralPath $cache -PathType Container) { $PythonModules = $cache }
    }
    if (-not [string]::IsNullOrWhiteSpace($PythonModules)) {
        $env:PYTHONPATH = $PythonModules + [IO.Path]::PathSeparator + $oldPythonPath
    }
    & $Python @arguments
    if ($LASTEXITCODE -ne 0) { throw "Classic CM7 FP Context runtime failed; preserve $BuildRoot" }
    $receipt = Get-Content -LiteralPath (Join-Path $BuildRoot 'results.json') -Raw | ConvertFrom-Json
    if (-not ($receipt.Verdict -is [string]) -or $receipt.Verdict -cne 'PASS') {
        throw 'Missing classic CM7 FP runtime PASS receipt'
    }
    if ($receipt.Profile.name -cne 'CM7' -or -not ($receipt.CompleteSuite -is [bool]) -or
            -not ($receipt.FullOptimizationGridFP -is [bool]) -or -not ($receipt.DevelopmentSmoke -is [bool]) -or
            $receipt.FullOptimizationGridFP -ne $FullOptimizationGridFP.IsPresent -or
            $receipt.DevelopmentSmoke -ne $DevelopmentSmoke.IsPresent -or
            $receipt.CompleteSuite -ne (-not $DevelopmentSmoke.IsPresent)) {
        throw 'Wrong profile, requested options or completion verdict'
    }
    $expectedRows = if ($DevelopmentSmoke) { if ($FullOptimizationGridFP) { 11 } else { 9 } } else { if ($FullOptimizationGridFP) { 504 } else { 288 } }
    $expectedPositive = if ($DevelopmentSmoke) { if ($FullOptimizationGridFP) { 4 } else { 2 } } else { if ($FullOptimizationGridFP) { 112 } else { 64 } }
    $expectedCausal = if ($DevelopmentSmoke) { 7 } elseif ($FullOptimizationGridFP) { 392 } else { 224 }
    $expectedReferences = if ($FullOptimizationGridFP) { 14 } else { 8 }
    if (-not ($receipt.Rows -is [array]) -or -not ($receipt.ReferenceParity -is [array]) -or
            -not ($receipt.ReferencePairs -is [array]) -or $receipt.Rows.Count -ne $expectedRows -or
            @($receipt.Rows | Where-Object { $_.Kind -ceq 'Positive' }).Count -ne $expectedPositive -or
            @($receipt.Rows | Where-Object { $_.Kind -ceq 'CompiledControl' }).Count -ne $expectedCausal -or
            @($receipt.Rows | Where-Object { $_.Status -cne 'PASS' }).Count -ne 0 -or
            @($receipt.Rows | ForEach-Object { $_.Name } | Sort-Object -CaseSensitive -Unique).Count -ne $expectedRows -or
            $receipt.ReferenceParity.Count -ne $expectedReferences -or $receipt.ReferencePairs.Count -ne $expectedPositive -or
            $receipt.ObserverCompiledControls.Controls.Count -ne 32) {
        throw 'Incomplete exact classic CM7 FP execution/reference grid'
    }
} finally {
    $env:PYTHONPATH = $oldPythonPath
}
