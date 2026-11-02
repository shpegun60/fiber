param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$HostGcc,
    [ValidateSet(0, 1)][int]$ExpectedRuntimeSelectable = 0,
    [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $ArmGcc) {
    $found = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $ArmGcc = $found.Source }
    else {
        $found = Get-ChildItem C:\ST -Filter arm-none-eabi-gcc.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $ArmGcc = $found.FullName }
    }
}
if (-not $HostGcc) {
    $found = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $HostGcc = $found.Source }
    elseif (Test-Path -LiteralPath "C:\msys64\ucrt64\bin\gcc.exe") {
        $HostGcc = "C:\msys64\ucrt64\bin\gcc.exe"
    }
}
if (-not $ArmGcc -or -not $HostGcc) { throw "Supply -ArmGcc and -HostGcc; maintained host adapter tests cannot be skipped" }
if (-not $CmsisCore) { $CmsisCore = Join-Path $repo "..\..\..\Drivers\CMSIS\Include" }
if (-not $FreeRtosRoot) { $FreeRtosRoot = Join-Path $repo "..\..\..\..\_reference\FreeRTOS-Kernel" }
if (-not $BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ("cm33f-tfm-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $build -Force | Out-Null
Write-Host "C3FT consumer artifacts: $build"
$arguments = @("-B", (Join-Path $PSScriptRoot "fixtures\cm33f_tfm\run.py"),
    "--repo", $repo, "--arm-gcc", (Resolve-Path -LiteralPath $ArmGcc).Path,
    "--host-gcc", (Resolve-Path -LiteralPath $HostGcc).Path,
    "--cmsis", (Resolve-Path -LiteralPath $CmsisCore).Path,
    "--reference", (Resolve-Path -LiteralPath $FreeRtosRoot).Path,
    "--build", $build, "--expected-runtime-selectable", "$ExpectedRuntimeSelectable")
$savedPath = $env:PATH
$pythonPath = (Get-Command $Python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$proofExitCode = 1
try {
    # MinGW compiler helpers and host executables need their adjacent DLLs.
    $env:PATH = (Split-Path (Resolve-Path -LiteralPath $HostGcc).Path) + ";" + $savedPath
    & $pythonPath @arguments
    $proofExitCode = $LASTEXITCODE
}
finally { $env:PATH = $savedPath }
if ($proofExitCode -ne 0) { throw "C3FT qualification failed; preserved evidence: $build" }
Write-Host "PASS C3FT independent consumer qualification: $build"
