param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot,
    [string]$Python = 'python',
    [string[]]$Profiles,
    [ValidateSet('O0','Og','O2','Os','O3')][string[]]$Optimizations = @('O2','Os'),
    [ValidateSet('baseline','raw','instrument','ssp','coverage','ubsan','tracepc','pg')]
    [string[]]$Bundles = @('baseline','raw'),
    [ValidateSet('sectioned','unsectioned')][string[]]$NativeLtoSections = @('sectioned','unsectioned'),
    [ValidateSet('0','1')][string[]]$Cm0Vtor = @('0'),
    [switch]$AllProfiles,
    [switch]$AuditOnly,
    [switch]$ImmutableInputs,
    [string]$Cm7PrefixRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$ArmGcc) {
    $command = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($command) { $ArmGcc = $command.Source }
}
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply -ArmGcc' }
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ('fiber-sensitive-port-closure-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $build -Force
$build = (Resolve-Path -LiteralPath $build).Path
$selection = if ($Profiles) { $Profiles -join ',' } else { '*' }
$arguments = @('-B',(Join-Path $PSScriptRoot 'fixtures\sensitive_port_closure\run.py'),
    '--repo',$repo,'--arm-gcc',$ArmGcc,'--cmsis-core',$CmsisCore,'--build',$build,
    '--profiles',$selection,'--optimizations',($Optimizations -join ','),
    '--bundles',($Bundles -join ','),'--native-lto-sections',($NativeLtoSections -join ','),
    '--cm0-vtor',($Cm0Vtor -join ','))
if ($AllProfiles -or !$Profiles) { $arguments += '--all-profiles' }
if ($AuditOnly) { $arguments += '--audit-only' }
if ($ImmutableInputs) { $arguments += '--immutable-inputs' }
if ($Cm7PrefixRoot) { $arguments += @('--cm7-prefix-root',(Resolve-Path -LiteralPath $Cm7PrefixRoot).Path) }
Write-Host "Sensitive port compiler closure evidence: $build"
$previous = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    & $Python @arguments
    $status = $LASTEXITCODE
} finally { $ErrorActionPreference = $previous }
if ($status -ne 0) { throw "Sensitive port compiler closure failed ($status): $build\results.json" }
$receipt = Get-Content -LiteralPath (Join-Path $build 'results.json') -Raw | ConvertFrom-Json
if ($receipt.Status -eq 'PASS') { Write-Host "PASS sensitive port compiler closure: $build" }
elseif ($AuditOnly -and $receipt.Status -eq 'FAIL') { Write-Host "AUDIT ONLY: receipt remains FAIL: $build" }
else { throw "Compiler closure returned success without a PASS receipt: $build" }
