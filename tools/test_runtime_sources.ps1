param(
    [string]$Python = 'python',
    [string]$BuildRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture = Join-Path $PSScriptRoot 'fixtures/runtime_sources'
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ('runtime-sources-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out -Force
$powershell = (Get-Process -Id $PID).Path
$arguments = @('-B', (Join-Path $fixture 'run.py'), '--repo', $repo,
    '--build', $out, '--powershell', $powershell)
@{Tool=$Python; Arguments=$arguments} | ConvertTo-Json -Depth 4 |
    Set-Content (Join-Path $out 'invocation.json') -Encoding ASCII
$old = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $lines = @(& $Python @arguments 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
}
finally { $ErrorActionPreference = $old }
$lines | Set-Content (Join-Path $out 'console.log') -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
$artifacts = [ordered]@{}
Get-ChildItem -LiteralPath $out -Recurse -File | Where-Object {
    $_.FullName -ne (Join-Path $out 'artifact-hashes.json')
} | Sort-Object FullName | ForEach-Object {
    $artifacts[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
}
$artifacts | ConvertTo-Json -Depth 3 |
    Set-Content (Join-Path $out 'artifact-hashes.json') -Encoding UTF8
if ($code -ne 0) { throw "Runtime source inventory proof failed: $out" }
