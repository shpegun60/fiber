param([string]$BuildRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'matrix_artifacts.ps1')
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ('matrix-artifact-paths-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out
$checks = New-Object System.Collections.Generic.List[object]
function Check([string]$Name, [bool]$Passed) {
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$Passed})
    if (!$Passed) { throw "Matrix output regression failed: $Name" }
}
function Expect-Rejection([string]$Name, [scriptblock]$Action, [string]$Diagnostic) {
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_.Exception.Message }
    Check $Name ($null -ne $caught -and $caught.Contains($Diagnostic))
}
$explicitPath = Join-Path $out 'explicit-output'
$explicit = New-FiberMatrixBuildDirectory $explicitPath
Check 'explicit/exact-path' ($explicit.Path -ceq [IO.Path]::GetFullPath($explicitPath))
Check 'explicit/application-owned' (!$explicit.Automatic)
$sentinel = Join-Path $explicit.Path 'sentinel.txt'
[IO.File]::WriteAllText($sentinel, 'preserve-exact-existing-output')
$sentinelHash = (Get-FileHash -LiteralPath $sentinel).Hash
Expect-Rejection 'explicit/existing-directory' {
    New-FiberMatrixBuildDirectory $explicitPath
} 'already exists; refusing stale outputs'
Expect-Rejection 'explicit/no-cleanup' {
    Remove-FiberAutomaticMatrixBuildDirectory $explicit
} 'application-owned'
Check 'explicit/sentinel-preserved' ((Get-FileHash -LiteralPath $sentinel).Hash -ceq $sentinelHash)
Expect-Rejection 'explicit/existing-file' {
    New-FiberMatrixBuildDirectory $sentinel
} 'already exists; refusing stale outputs'
Expect-Rejection 'explicit/wildcard' {
    New-FiberMatrixBuildDirectory (Join-Path $out 'unsafe[0]')
} 'wildcard characters'
$automatic = New-FiberMatrixBuildDirectory
Check 'automatic/owned' $automatic.Automatic
Check 'automatic/exact-leaf' ([IO.Path]::GetFileName($automatic.Path) -cmatch
    '^fiber-compile-matrix-[0-9a-f]{32}$')
$automaticFile = Join-Path $automatic.Path 'generated.txt'
[IO.File]::WriteAllText($automaticFile, 'test-only-generated-output')
Remove-FiberAutomaticMatrixBuildDirectory $automatic
Check 'automatic/cleanup' (!(Test-Path -LiteralPath $automatic.Path))
Expect-Rejection 'cleanup/forged-explicit' {
    Remove-FiberAutomaticMatrixBuildDirectory ([pscustomobject]@{Path=$explicit.Path;Automatic=$true})
} 'outside its exact automatic temporary directory'
Expect-Rejection 'cleanup/filesystem-root' {
    Remove-FiberAutomaticMatrixBuildDirectory ([pscustomobject]@{
        Path=[IO.Path]::GetPathRoot($out);Automatic=$true})
} 'outside its exact automatic temporary directory'
$nested = Join-Path $out ('fiber-compile-matrix-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $nested
Expect-Rejection 'cleanup/nested-temp-impostor' {
    Remove-FiberAutomaticMatrixBuildDirectory ([pscustomobject]@{Path=$nested;Automatic=$true})
} 'outside its exact automatic temporary directory'
Check 'cleanup/impostors-preserved' ((Test-Path -LiteralPath $sentinel) -and
    (Test-Path -LiteralPath $nested))
$junctionOwner = New-FiberMatrixBuildDirectory
$junction = Join-Path $junctionOwner.Path 'outside-output'
$null = New-Item -ItemType Junction -Path $junction -Value $explicit.Path
Expect-Rejection 'cleanup/descendant-junction' {
    Remove-FiberAutomaticMatrixBuildDirectory $junctionOwner
} 'descendant reparse point'
Check 'cleanup/junction-target-preserved' (
    (Get-FileHash -LiteralPath $sentinel).Hash -ceq $sentinelHash)
# Nonrecursive deletion unlinks this test-owned junction, never its target.
[IO.Directory]::Delete($junction)
Remove-FiberAutomaticMatrixBuildDirectory $junctionOwner
Check 'cleanup/unlinked-owner' (!(Test-Path -LiteralPath $junctionOwner.Path))
$matrixPath = Join-Path $PSScriptRoot 'compile_matrix.ps1'
$source = Get-Content -LiteralPath $matrixPath -Raw
Check 'matrix/explicit-kept' ($source -cmatch
    '\$KeepBuild\s+-or\s+!\$matrixDirectory\.Automatic\s+-or\s+!\$matrixPassed')
Check 'matrix/success-recorded' ($source -cmatch
    '(?s)\$matrixPassed\s*=\s*\$true\s+Write-Host\s+""\s+Write-Host\s+"PASS: compile matrix completed\."')
Check 'matrix/safe-cleanup-only' ([regex]::Matches($source,
    'Remove-FiberAutomaticMatrixBuildDirectory\s+\$matrixDirectory').Count -eq 1 -and
    $source -cnotmatch 'Remove-Item\s+-LiteralPath\s+\$buildRoot')
$parseErrors = $null
$parseTokens = $null
$ast = [Management.Automation.Language.Parser]::ParseInput(
    $source, [ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Cannot exercise a syntactically invalid matrix cleanup' }
$cleanup = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst] -and
    $null -ne $_.Finally -and $_.Finally.Extent.Text.Contains(
        'Remove-FiberAutomaticMatrixBuildDirectory $matrixDirectory')
})
if ($cleanup.Count -ne 1) { throw 'Expected one actual top-level matrix cleanup block' }
$cleanupBlock = [scriptblock]::Create(
    ($cleanup[0].Finally.Statements | ForEach-Object { $_.Extent.Text }) -join "`n")
foreach ($auto in @($false,$true)) {
    foreach ($keep in @($false,$true)) {
        foreach ($passed in @($false,$true)) {
            $name = "retention/auto-$auto-keep-$keep-pass-$passed"
            $matrixDirectory = if ($auto) { New-FiberMatrixBuildDirectory } else {
                New-FiberMatrixBuildDirectory (Join-Path $out ($name.Replace('/','-')))
            }
            $buildRoot = $matrixDirectory.Path
            $KeepBuild = $keep
            $matrixPassed = $passed
            & $cleanupBlock 6>&1 | Out-Null
            $expectedKept = $keep -or !$auto -or !$passed
            Check $name ((Test-Path -LiteralPath $buildRoot) -eq $expectedKept)
            if ($auto -and $expectedKept) {
                Remove-FiberAutomaticMatrixBuildDirectory $matrixDirectory
            }
        }
    }
}
$result = [pscustomobject]@{Status='PASS';Checks=$checks.Count;Cases=$checks.ToArray();
    Scope='Filesystem-only output admission and cleanup; no compiler or runtime qualification';
    Inputs=@((Get-FileHash -LiteralPath $PSCommandPath),
        (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'matrix_artifacts.ps1')),
        (Get-FileHash -LiteralPath $matrixPath)) | Select-Object Path,Hash}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'results.json') -Encoding ASCII
Write-Host "PASS matrix output paths: $($checks.Count) checks; $out"
