param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$Python = 'python',
    [ValidateSet('O0','Og','O2','Os','O3')]
    [string[]]$Optimizations = @('O0','Og','O2','Os','O3')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply -ArmGcc' }
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
if (!(Test-Path -LiteralPath (Join-Path $CmsisCore 'core_cm55.h'))) { throw 'Supply CMSIS core headers' }
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ('fiber-v8-mpu-raw-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $build -Force
$build = (Resolve-Path -LiteralPath $build).Path
Write-Host "V8 MPU raw compiler evidence: $build"
& $Python -B (Join-Path $PSScriptRoot 'fixtures\v8_mpu_raw_compiler\run.py') `
    --repo $repo --arm-gcc $ArmGcc --cmsis-core $CmsisCore --build $build `
    --optimizations ($Optimizations -join ',')
if ($LASTEXITCODE -ne 0) { throw "V8 MPU raw compiler proof failed: $build\results.json" }
$receipt = Get-Content -LiteralPath (Join-Path $build 'results.json') -Raw | ConvertFrom-Json
if ($receipt.Status -ne 'PASS') { throw "V8 MPU runner lacks PASS: $build\results.json" }
if ($receipt.CompleteSuite) { Write-Host "PASS v8 MPU complete raw compiler grid: $build" }
else { Write-Host "PASS v8 MPU development subset (CompleteSuite=false): $build" }
