param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$Python = 'python',
    [string]$PythonModules
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply -ArmGcc' }
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '../../../Drivers/CMSIS/Include' }
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ('fiber-thumb1-vector-constraints-' + [guid]::NewGuid().ToString('N'))
if (!$PythonModules) { $PythonModules = Join-Path ([IO.Path]::GetTempPath()) 'fiber-classic-audit-python' }
$old = $env:PYTHONPATH
try {
    $env:PYTHONPATH = (Resolve-Path -LiteralPath $PythonModules).Path
    if ($old) { $env:PYTHONPATH += [IO.Path]::PathSeparator + $old }
    $arguments = @('-B', (Join-Path $PSScriptRoot 'fixtures/thumb1_vector_constraints/run.py'),
        '--repo', $repo, '--arm-gcc', (Resolve-Path -LiteralPath $ArmGcc).Path,
        '--cmsis-core', $CmsisCore, '--build', $build)
    & $Python @arguments
    if ($LASTEXITCODE -ne 0) { throw "Thumb-1 vector constraint gate failed: $build" }
} finally { $env:PYTHONPATH = $old }
