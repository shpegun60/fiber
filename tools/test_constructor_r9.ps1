param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$Python = 'python',
    [string]$PythonModules = $env:FIBER_CONSTRUCTOR_R9_PYTHONPATH,
    [switch]$ImmutableInputs,
    [string[]]$DevelopmentProfiles,
    [string[]]$DevelopmentModes,
    [ValidateSet('legacy','fiber')][string[]]$ConstructorCohorts
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture = Join-Path $PSScriptRoot 'fixtures\constructor_r9'
if (!$ArmGcc) {
    $found = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $ArmGcc = $found.Source }
}
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply -ArmGcc' }
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ('fiber-constructor-r9-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $build -Force
$build = (Resolve-Path -LiteralPath $build).Path
if (!$PythonModules) {
    foreach ($name in @('fiber-constructor-r9-python','fiber-classic-audit-python')) {
        $candidate = Join-Path ([IO.Path]::GetTempPath()) $name
        if (Test-Path -LiteralPath $candidate -PathType Container) { $PythonModules = $candidate; break }
    }
}
$oldPath = $env:PYTHONPATH
try {
    if ($PythonModules) {
        $PythonModules = (Resolve-Path -LiteralPath $PythonModules).Path
        $env:PYTHONPATH = $PythonModules
        if ($oldPath) { $env:PYTHONPATH += [IO.Path]::PathSeparator + $oldPath }
    }
    $arguments = @('-B',(Join-Path $fixture 'run.py'),'--repo',$repo,
        '--arm-gcc',$ArmGcc,'--cmsis-core',$CmsisCore,'--build',$build)
    if ($DevelopmentProfiles) { $arguments += @('--profiles',($DevelopmentProfiles -join ',')) }
    if ($DevelopmentModes) { $arguments += @('--modes',($DevelopmentModes -join ',')) }
    if ($ConstructorCohorts) { $arguments += @('--constructor-cohorts',($ConstructorCohorts -join ',')) }
    if ($ImmutableInputs) { $arguments += '--immutable-inputs' }
    Write-Host "Constructor R9 evidence: $build"
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Python @arguments
        $status = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    if ($status -ne 0) { throw "Constructor R9 regression failed ($status); inspect $build\results.json" }
    if ($DevelopmentProfiles -or $DevelopmentModes -or ($ConstructorCohorts -and $ConstructorCohorts.Count -lt 2)) { Write-Host "PASS constructor R9 development subset: $build" }
    else { Write-Host "PASS constructor R9: $build" }
} finally { $env:PYTHONPATH = $oldPath }
