param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [Parameter(Mandatory=$true)][string]$QemuRoot,
    [string]$WslDistro = 'Ubuntu-24.04',
    [string]$BuildRoot,
    [string]$Python = 'python',
    [string]$PythonModules = $env:FIBER_CLASSIC_AUDIT_PYTHONPATH,
    [switch]$DevelopmentSmoke
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($ArmGcc) -or
        -not (Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {
    throw 'Supply an existing -ArmGcc; this runner does not discover a compiler'
}
if ([string]::IsNullOrWhiteSpace($CmsisCore) -or
        -not (Test-Path -LiteralPath (Join-Path $CmsisCore 'core_cm4.h') -PathType Leaf)) {
    throw 'Supply an existing -CmsisCore containing core_cm4.h'
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
    $BuildRoot = Join-Path $env:TEMP ('classic-fp-context-runtime-' + [guid]::NewGuid().ToString('N'))
}
if (Test-Path -LiteralPath $BuildRoot) {
    throw "Runtime evidence output must not already exist: $BuildRoot"
}

$arguments = @(
    (Join-Path $PSScriptRoot 'fixtures\classic_fp_context_runtime\run.py'),
    '--repo', $repo,
    '--gcc', (Resolve-Path -LiteralPath $ArmGcc).Path,
    '--cmsis', (Resolve-Path -LiteralPath $CmsisCore).Path,
    '--freertos', (Resolve-Path -LiteralPath $FreeRtosRoot).Path,
    '--qemu-root', $QemuRoot,
    '--wsl-distro', $WslDistro,
    '--build-root', $BuildRoot
)
if ($DevelopmentSmoke) { $arguments += '--development-smoke' }
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
    if ($LASTEXITCODE -ne 0) { throw "Classic FP Context runtime failed; preserve $BuildRoot" }
    $receipt = Get-Content -LiteralPath (Join-Path $BuildRoot 'results.json') -Raw | ConvertFrom-Json
    if ($receipt.Verdict -cne 'PASS') { throw 'Missing classic FP runtime PASS receipt' }
    if ($DevelopmentSmoke) {
        if ($receipt.CompleteSuite) { throw 'Development mode must not claim full qualification' }
    } elseif (-not $receipt.CompleteSuite -or $receipt.Rows.Count -ne 288) {
        throw 'Incomplete standard classic FP runtime suite'
    }
} finally {
    $env:PYTHONPATH = $oldPythonPath
}
