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
function Test-MatrixSuccessPublication([string]$Source) {
    $errors = $null
    $tokens = $null
    $tree = [Management.Automation.Language.Parser]::ParseInput(
        $Source, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { return $false }
    $top = @($tree.EndBlock.Statements)
    if ($top.Count -lt 3) { return $false }
    $guard = $top[-3]
    if ($guard -isnot [Management.Automation.Language.TryStatementAst] -or
            $null -eq $guard.Finally -or
            $guard.CatchClauses.Count -ne 0 -or
            !$guard.Finally.Extent.Text.Contains(
                'Remove-FiberAutomaticMatrixBuildDirectory $matrixDirectory')) {
        return $false
    }
    # Publish only after the real cleanup/drift finally block has completed.
    if ($top[-2].Extent.Text -cnotmatch '^Write-Host\s+""$' -or
            $top[-1].Extent.Text -cnotmatch
                '^Write-Host\s+"PASS: compile matrix completed\."$') {
        return $false
    }
    $initial = @($top | Where-Object {
        $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
        $_.Extent.Text -cmatch '^\$matrixPassed\s*=\s*\$false$' -and
        $_.Extent.StartOffset -lt $guard.Extent.StartOffset
    })
    $success = @($tree.FindAll({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Extent.Text -cmatch '^\$matrixPassed\s*=\s*\$true$'
    }, $true))
    $body = @($guard.Body.Statements)
    if ($initial.Count -ne 1 -or $success.Count -ne 1 -or !$body.Count -or
            $success[0].Extent.StartOffset -ne $body[-1].Extent.StartOffset) {
        return $false
    }
    $banners = @($tree.FindAll({param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.Extent.Text -cmatch '^Write-Host\s+"PASS: compile matrix completed\."$'
    }, $true))
    return $banners.Count -eq 1
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
Check 'matrix/success-recorded' (Test-MatrixSuccessPublication $source)
$successNeedle = '$matrixPassed = $true'
$bannerNeedle = 'Write-Host "PASS: compile matrix completed."'
$initialNeedle = '$matrixPassed = $false'
$earlySuccess = $source.Insert($source.IndexOf($initialNeedle) +
    $initialNeedle.Length, ("`n" + $successNeedle))
$finallyOffset = $source.LastIndexOf("`nfinally {")
Check 'matrix/success-control-finally-anchor' ($finallyOffset -ge 0)
$swallowedFailure = $source.Insert($finallyOffset + 1, "catch {}`n")
$successMutants = @(
    @{Name='missing-initial-state';Source=$source.Replace('$matrixPassed = $false', '$unused = $false')},
    @{Name='missing-success-state';Source=$source.Replace($successNeedle, '$unused = $true')},
    @{Name='early-success-state';Source=$earlySuccess},
    @{Name='duplicate-banner';Source=($source + "`n" + $bannerNeedle)},
    @{Name='banner-before-finally';Source=$source.Replace($bannerNeedle, '').Replace(
        $successNeedle, ($successNeedle + "`n" + $bannerNeedle))},
    @{Name='conditional-final-banner';Source=$source.Replace($bannerNeedle,
        ('if ($false) { ' + $bannerNeedle + ' }'))},
    @{Name='comment-only-banner';Source=$source.Replace($bannerNeedle,
        ('# ' + $bannerNeedle))},
    @{Name='swallowed-build-failure';Source=$swallowedFailure}
)
foreach ($mutant in $successMutants) {
    $errors = $null
    $tokens = $null
    $null = [Management.Automation.Language.Parser]::ParseInput(
        $mutant.Source, [ref]$tokens, [ref]$errors)
    Check ('matrix/success-control-parses-' + $mutant.Name) ($errors.Count -eq 0)
    Check ('matrix/success-rejects-' + $mutant.Name) (
        !(Test-MatrixSuccessPublication $mutant.Source))
}
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
            $runtimeSourceInputHashesBefore = [ordered]@{}
            $runtimeSourceInputHashesBefore[$sentinel] = $sentinelHash
            . $cleanupBlock 6>&1 | Out-Null
            $expectedKept = $keep -or !$auto -or !$passed
            Check $name ((Test-Path -LiteralPath $buildRoot) -eq $expectedKept)
            if ($expectedKept) {
                $afterPath = Join-Path $buildRoot 'runtime-source-inputs-after.json'
                $after = Get-Content -LiteralPath $afterPath -Raw | ConvertFrom-Json
                Check ($name + '/hash-recorded') (
                    $after.PSObject.Properties[$sentinel].Value -ceq $sentinelHash)
            }
            if ($auto -and $expectedKept) {
                Remove-FiberAutomaticMatrixBuildDirectory $matrixDirectory
            }
        }
    }
}
$driftInput = Join-Path $out 'drift-input.txt'
foreach ($auto in @($false, $true)) {
    foreach ($keep in @($false, $true)) {
        $name = "drift/auto-$auto-keep-$keep"
        $matrixDirectory = if ($auto) { New-FiberMatrixBuildDirectory } else {
            New-FiberMatrixBuildDirectory (Join-Path $out ($name.Replace('/','-')))
        }
        $buildRoot = $matrixDirectory.Path
        $KeepBuild = $keep
        $matrixPassed = $true
        [IO.File]::WriteAllText($driftInput, 'captured-input')
        $runtimeSourceInputHashesBefore = [ordered]@{}
        $runtimeSourceInputHashesBefore[$driftInput] = (Get-FileHash $driftInput).Hash
        [IO.File]::WriteAllText($driftInput, 'changed-input')
        $caught = $null
        try { . $cleanupBlock 6>&1 | Out-Null } catch { $caught = $_.Exception.Message }
        Check ($name + '/terminal') ($caught -ceq
            "Common source-inventory input drift: $driftInput")
        Check ($name + '/not-passed') (!$matrixPassed)
        Check ($name + '/evidence-kept') (Test-Path -LiteralPath $buildRoot)
        $afterPath = Join-Path $buildRoot 'runtime-source-inputs-after.json'
        $after = Get-Content -LiteralPath $afterPath -Raw | ConvertFrom-Json
        Check ($name + '/changed-hash-recorded') (
            $after.PSObject.Properties[$driftInput].Value -ceq (Get-FileHash $driftInput).Hash)
        if ($auto) { Remove-FiberAutomaticMatrixBuildDirectory $matrixDirectory }
    }
}
$result = [pscustomobject]@{Status='PASS';Checks=$checks.Count;Cases=$checks.ToArray();
    Scope='Filesystem-only output admission and cleanup; no compiler or runtime qualification';
    Inputs=@((Get-FileHash -LiteralPath $PSCommandPath),
        (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'matrix_artifacts.ps1')),
        (Get-FileHash -LiteralPath $matrixPath)) | Select-Object Path,Hash}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'results.json') -Encoding ASCII
Write-Host "PASS matrix output paths: $($checks.Count) checks; $out"
