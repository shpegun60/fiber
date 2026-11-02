param(
    [string]$ArmGcc,
    [string]$CmsisCore,
    [string]$HostGcc = 'C:\msys64\ucrt64\bin\gcc.exe',
    [string]$Python = 'python',
    [string]$BuildRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path $PSScriptRoot -Parent
if (-not $ArmGcc) {
    $found = Get-Command arm-none-eabi-gcc -ErrorAction SilentlyContinue
    if ($found) { $ArmGcc = $found.Source }
    else { throw 'Supply -ArmGcc; no compiler is installed by this test.' }
}
if (-not $CmsisCore) { $CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
if (-not $BuildRoot) { $BuildRoot = Join-Path $env:TEMP 'fiber-lifecycle' }
$output = Join-Path $BuildRoot ([guid]::NewGuid().ToString('N'))
& $Python (Join-Path $PSScriptRoot 'fixtures\fiber_lifecycle\run.py') `
    --repo $repo --arm $ArmGcc --cmsis $CmsisCore --host $HostGcc --build $output
if ($LASTEXITCODE -ne 0) { throw "Fiber lifecycle qualification failed ($LASTEXITCODE): $output" }
Write-Host "PASS fiber lifecycle: $output"
