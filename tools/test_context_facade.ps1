param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$HostGcc = $env:HOST_GCC,
    [string]$Python = $env:PYTHON,
    [string]$BuildRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$ArmGcc) {
    $tool = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($tool) { $ArmGcc = $tool.Source }
    elseif (Test-Path 'C:\ST') {
        $tool = Get-ChildItem 'C:\ST' -Recurse -Filter arm-none-eabi-gcc.exe | Select-Object -First 1
        if ($tool) { $ArmGcc = $tool.FullName }
    }
}
if (!$HostGcc) {
    $tool = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($tool) { $HostGcc = $tool.Source }
    elseif (Test-Path 'C:\msys64\ucrt64\bin\gcc.exe') { $HostGcc = 'C:\msys64\ucrt64\bin\gcc.exe' }
}
if (!$Python) {
    $tool = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($tool) { $Python = $tool.Source }
}
if (!$CmsisCore) { $CmsisCore = Join-Path $Repo '../../../Drivers/CMSIS/Include' }
foreach ($item in @($ArmGcc, $HostGcc, $Python)) {
    if (!$item -or !(Test-Path -LiteralPath $item)) { throw 'Required compiler/Python missing; pass explicit tool paths.' }
}
if (!(Test-Path (Join-Path $CmsisCore 'core_cm0.h'))) { throw 'Real CMSIS core headers are required.' }
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$Build = Join-Path $BuildRoot ('fiber-context-facade-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $Build -Force
Write-Output "Context facade artifacts: $Build"
& $Python (Join-Path $PSScriptRoot 'fixtures/context_facade/run.py') --repo $Repo --build $Build `
    --arm-gcc (Resolve-Path $ArmGcc).Path --host-gcc (Resolve-Path $HostGcc).Path `
    --cmsis (Resolve-Path $CmsisCore).Path
if ($LASTEXITCODE -ne 0) { throw "Context facade qualification failed; artifacts: $Build" }
Write-Output "PASS context facade; $Build/results.json"
