param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosKernel = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$BuildRoot,
    [string]$Python = 'python',
    [string]$PythonModules = $env:FIBER_CLASSIC_AUDIT_PYTHONPATH
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
foreach ($entry in @(@('ArmGcc', $ArmGcc), @('CmsisCore', $CmsisCore), @('FreeRtosKernel', $FreeRtosKernel))) {
    if ([string]::IsNullOrWhiteSpace($entry[1]) -or -not (Test-Path -LiteralPath $entry[1])) {
        throw "Explicit existing $($entry[0]) is required; this test never provisions tools"
    }
}
if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $BuildRoot = Join-Path ([IO.Path]::GetTempPath()) ('fiber-cm0-freeze-parity-' + [Guid]::NewGuid().ToString('N'))
}
if (Test-Path -LiteralPath $BuildRoot) { throw 'BuildRoot must be the exact absent output directory' }
if ([string]::IsNullOrWhiteSpace($PythonModules)) {
    $candidate = Join-Path ([IO.Path]::GetTempPath()) 'fiber-classic-audit-python'
    if (Test-Path -LiteralPath $candidate) { $PythonModules = $candidate }
}
$saved = $env:PYTHONPATH
try {
    if (-not [string]::IsNullOrWhiteSpace($PythonModules)) {
        if (-not (Test-Path -LiteralPath $PythonModules -PathType Container)) { throw 'PythonModules must exist' }
        $env:PYTHONPATH = $PythonModules + $(if ($saved) { [IO.Path]::PathSeparator + $saved } else { '' })
    }
    & $Python (Join-Path $PSScriptRoot 'fixtures/cm0_freeze_parity/run.py') `
        --repo $repo --gcc (Resolve-Path -LiteralPath $ArmGcc).Path `
        --cmsis (Resolve-Path -LiteralPath $CmsisCore).Path `
        --freertos (Resolve-Path -LiteralPath $FreeRtosKernel).Path --build-root $BuildRoot
    if ($LASTEXITCODE -ne 0) { throw "CM0/CM0+ freeze parity failed; evidence: $BuildRoot" }
} finally {
    $env:PYTHONPATH = $saved
}
Write-Host "PASS CM0/CM0+ non-MPU optimization/final-ELF parity: $BuildRoot"
