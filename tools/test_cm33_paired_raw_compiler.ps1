param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$ArmGcc) {
    $found = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $ArmGcc = $found.Source }
}
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply -ArmGcc' }
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
if (!(Test-Path -LiteralPath (Join-Path $CmsisCore 'core_cm33.h'))) { throw 'Supply -CmsisCore' }
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ('fiber-cm33-paired-raw-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out
Write-Host "CM33 paired raw compiler evidence: $out"
& $Python -B (Join-Path $PSScriptRoot 'fixtures\cm33_paired_raw_compiler\run.py') `
    --repo $repo --arm-gcc $ArmGcc --cmsis-core $CmsisCore --build $out
if ($LASTEXITCODE -ne 0) { throw "CM33 paired raw compiler qualification failed: $out" }
$receipt = Get-Content -LiteralPath (Join-Path $out 'results.json') -Raw | ConvertFrom-Json
if ($receipt.Status -ne 'PASS' -or !$receipt.CompleteSuite) { throw 'Missing complete PASS receipt' }
Write-Host "PASS CM33 paired raw compiler closure: $out"
