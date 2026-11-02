param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$BuildRoot,
    [string]$Python = 'python',
    [string]$PythonModules = $env:FIBER_CONSTRUCTOR_R9_PYTHONPATH,
    [string[]]$DevelopmentOptimizations
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$ArmGcc) { $ArmGcc = (Get-Command arm-none-eabi-gcc.exe -ErrorAction Stop).Source }
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
if (!$FreeRtosRoot) { $FreeRtosRoot = Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ('fiber-cm33-tfm-raw-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $build -Force
if (!$PythonModules) {
    foreach ($name in @('fiber-constructor-r9-python','fiber-classic-audit-python')) {
        $candidate = Join-Path ([IO.Path]::GetTempPath()) $name
        if (Test-Path -LiteralPath $candidate -PathType Container) { $PythonModules = $candidate; break }
    }
}
$oldPath = $env:PYTHONPATH
try {
    if ($PythonModules) {
        $env:PYTHONPATH = (Resolve-Path -LiteralPath $PythonModules).Path
        if ($oldPath) { $env:PYTHONPATH += [IO.Path]::PathSeparator + $oldPath }
    }
    $arguments = @('-B',(Join-Path $PSScriptRoot 'fixtures\cm33_tfm_raw_compiler\run.py'),
        '--repo',$repo,'--arm-gcc',$ArmGcc,'--cmsis-core',$CmsisCore,
        '--freertos',$FreeRtosRoot,'--build',$build)
    if ($DevelopmentOptimizations) { $arguments += @('--development-optimizations',($DevelopmentOptimizations -join ',')) }
    Write-Host "CM33 TF-M raw compiler evidence: $build"
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Python @arguments
        $status = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    if ($status -ne 0) { throw "CM33 TF-M compiler qualification failed ($status): $build\results.json" }
    $receipt = Get-Content -LiteralPath (Join-Path $build 'results.json') -Raw | ConvertFrom-Json
    if ($receipt.Status -ne 'PASS') { throw 'Missing PASS receipt' }
    if ($DevelopmentOptimizations) { Write-Host "PASS CM33 TF-M compiler development subset: $build" }
    elseif (!$receipt.CompleteSuite) { throw 'Incomplete standard CM33 TF-M suite' }
    else { Write-Host "PASS CM33 TF-M raw compiler: $build" }
} finally { $env:PYTHONPATH = $oldPath }
