[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$BootProjectRoot,
    [string]$CubeIdeRoot = 'C:\ST\STM32CubeIDE_2.0.0\STM32CubeIDE',
    [string]$ArmGcc,
    [string]$MakeExe,
    [string]$Python = 'python',
    [string]$PythonModules,
    [string]$BuildRoot,
    [string]$SourceCommit = '471ec5cfd1e69aefc273f6dd47d487bb1b4e5c6a',
    [ValidateRange(30, 3600)][int]$TimeoutSeconds = 900,
    [switch]$PreflightOnly
)
$ErrorActionPreference = 'Stop'
if ($env:PYTHONOPTIMIZE) { throw 'PYTHONOPTIMIZE must be unset.' }
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
if (-not $BootProjectRoot) {
    $BootProjectRoot = Split-Path -Parent (Split-Path -Parent $RepoRoot)
}
if (-not $ArmGcc) {
    $ArmGcc = Join-Path $CubeIdeRoot 'plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.14.3.rel1.win32_1.0.100.202602081740\tools\bin\arm-none-eabi-gcc.exe'
}
if (-not $MakeExe) {
    $MakeExe = Join-Path $CubeIdeRoot 'plugins\com.st.stm32cube.ide.mcu.externaltools.make.win32_2.2.200.202604021615\tools\bin\make.exe'
}
if ($PythonModules) { $env:PYTHONPATH = (Resolve-Path -LiteralPath $PythonModules).Path }
$arguments = @('-B', (Join-Path $PSScriptRoot 'fixtures\h7s_snapshot_build\audit.py'),
    '--repo', $RepoRoot, '--boot', $BootProjectRoot, '--ide', $CubeIdeRoot,
    '--gcc', $ArmGcc, '--make', $MakeExe, '--commit', $SourceCommit,
    '--timeout', $TimeoutSeconds)
if ($BuildRoot) { $arguments += @('--build-root', $BuildRoot) }
if ($PreflightOnly) { $arguments += '--preflight-only' }
& $Python @arguments
if ($LASTEXITCODE -ne 0) { throw "H7S snapshot qualification failed ($LASTEXITCODE)." }
