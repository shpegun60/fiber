param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$BuildRoot,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
if (!$ArmGcc) { $ArmGcc = (Get-Command arm-none-eabi-gcc.exe -ErrorAction Stop).Source }
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ('sensitive-data-reachability-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $build -Force | Out-Null
& $Python -B (Join-Path $PSScriptRoot 'fixtures\sensitive_port_closure_readiness\run.py') `
    --repo (Resolve-Path (Join-Path $PSScriptRoot '..')).Path `
    --arm-gcc (Resolve-Path -LiteralPath $ArmGcc).Path --build $build
if ($LASTEXITCODE -ne 0) { throw "Sensitive data reachability failed: $build" }
