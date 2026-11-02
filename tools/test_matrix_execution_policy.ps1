param([string]$BuildRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ('matrix-execution-policy-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out
$checks = New-Object System.Collections.Generic.List[object]
function Check([string]$Name, [bool]$Passed) {
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$Passed})
    if (!$Passed) { throw "Matrix execution-policy regression failed: $Name" }
}
$matrixPath = Join-Path $PSScriptRoot 'compile_matrix.ps1'
$source = Get-Content -LiteralPath $matrixPath -Raw
$parseErrors = $null
$parseTokens = $null
$ast = [Management.Automation.Language.Parser]::ParseInput(
    $source, [ref]$parseTokens, [ref]$parseErrors)
Check 'matrix/parses' ($parseErrors.Count -eq 0)
$policies = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $_.Name -ceq 'Assert-MatrixExecutionPolicy'
})
Check 'matrix/one-policy' ($policies.Count -eq 1)
. ([scriptblock]::Create($policies[0].Extent.Text))
$calls = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.PipelineAst] -and
    $_.Extent.Text -cmatch '^Assert-MatrixExecutionPolicy\s'
})
Check 'matrix/one-top-level-call' ($calls.Count -eq 1)
Check 'matrix/policy-before-tool-discovery' (
    $calls[0].Extent.StartOffset -lt $source.IndexOf('$gcc = Find-ArmGcc'))
Check 'matrix/policy-before-output-creation' (
    $calls[0].Extent.StartOffset -lt $source.IndexOf('$matrixDirectory = New-FiberMatrixBuildDirectory'))
Check 'matrix/exact-policy-arguments' ($calls[0].Extent.Text -cmatch
    '(?s)^Assert-MatrixExecutionPolicy -Required \$RequireArchitectureExecution\s+`\s+-SettingsSubset \$SettingsOnly -QemuRoot \$ControlQemuRoot$')
$cases = @(
    @{Name='local/no-qemu';Required=$false;Subset=$false;Root=$null;Diagnostic=$null},
    @{Name='local/with-qemu';Required=$false;Subset=$false;Root='/existing/prefix';Diagnostic=$null},
    @{Name='local/subset';Required=$false;Subset=$true;Root=$null;Diagnostic=$null},
    @{Name='required/null-qemu';Required=$true;Subset=$false;Root=$null;Diagnostic='needs an explicit -ControlQemuRoot'},
    @{Name='required/empty-qemu';Required=$true;Subset=$false;Root='';Diagnostic='needs an explicit -ControlQemuRoot'},
    @{Name='required/whitespace-qemu';Required=$true;Subset=$false;Root=" `t ";Diagnostic='needs an explicit -ControlQemuRoot'},
    @{Name='required/subset-with-qemu';Required=$true;Subset=$true;Root='/existing/prefix';Diagnostic='cannot use -SettingsOnly'},
    @{Name='required/subset-without-qemu';Required=$true;Subset=$true;Root=$null;Diagnostic='cannot use -SettingsOnly'},
    @{Name='required/explicit-qemu';Required=$true;Subset=$false;Root='/existing/prefix';Diagnostic=$null}
)
foreach ($case in $cases) {
    $caught = $null
    try {
        Assert-MatrixExecutionPolicy -Required $case.Required `
            -SettingsSubset $case.Subset -QemuRoot $case.Root
    } catch { $caught = $_.Exception.Message }
    $passed = if ($null -eq $case.Diagnostic) { $null -eq $caught } else {
        $null -ne $caught -and $caught.Contains($case.Diagnostic)
    }
    Check $case.Name $passed
}
# Guard complete dispatch, independently of the expensive execution itself.
$commands = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand
}, $true))
foreach ($runner in @('test_cm33f_secure_initialize', 'test_m55_secure_runtime',
        'test_cm33_secure_only_runtime', 'test_cm55_secure_only_runtime')) {
    $needle = '"tools\' + $runner + '.ps1"'
    $dispatch = @($commands | Where-Object {$_.Extent.Text.Contains($needle)})
    Check ($runner + '/one-dispatch') ($dispatch.Count -eq 1)
    $text = $dispatch[0].Extent.Text
    Check ($runner + '/real-tool-inputs') ($text -cmatch '-ArmGcc \$gcc' -and
        $text -cmatch '-CmsisCore \$cmsis')
    Check ($runner + '/explicit-execution-inputs') ($text -cmatch
        '-QemuRoot \$ControlQemuRoot' -and $text -cmatch '-WslDistro \$ControlWslDistro')
    Check ($runner + '/no-development-subset') ($text -notmatch
        '-(?:Development\w*|Smoke|CompilerAdversarialOnly|AdmissionOnly)\b')
    $parent = $dispatch[0].Parent
    $guarded = $false
    while ($null -ne $parent) {
        if ($parent -is [Management.Automation.Language.IfStatementAst] -and
            $parent.Clauses[0].Item1.Extent.Text -ceq
                '-not [string]::IsNullOrWhiteSpace($ControlQemuRoot)') {
            $guarded = $true
        }
        $parent = $parent.Parent
    }
    Check ($runner + '/inside-explicit-qemu-guard') $guarded
    if ($runner -match 'secure_only') {
        Check ($runner + '/staged-not-promoted') ($text -cmatch
            '-ExpectedRuntimeSelectable 0\b')
    }
}
$tfmDispatch = @($commands | Where-Object {
    $_.Extent.Text.Contains('"tools\test_cm33f_tfm.ps1"')
})
Check 'C3FT/one-dispatch' ($tfmDispatch.Count -eq 1)
Check 'C3FT/exact-argument-binding' ($tfmDispatch[0].Extent.Text -cmatch
    '@cm33fTfmArguments$')
Check 'C3FT/staged-base-arguments' ($source -cmatch
    '(?s)\$cm33fTfmArguments = @\{\s+ArmGcc = \$gcc\s+CmsisCore = \$cmsis\s+ExpectedRuntimeSelectable = 0\s+BuildRoot = \(Join-Path \$buildRoot "audit-cm33f-tfm"\)\s+\}')
Check 'C3FT/optional-execution-forwarding' ($source -cmatch
    '(?s)if \(-not \[string\]::IsNullOrWhiteSpace\(\$ControlQemuRoot\)\) \{\s+\$cm33fTfmArguments.QemuRoot = \$ControlQemuRoot\s+\$cm33fTfmArguments.WslDistro = \$ControlWslDistro\s+\}')
$result = [pscustomobject]@{
    Status='PASS';Checks=$checks.Count;Cases=$checks.ToArray()
    Scope='Configuration admission and complete staged-runner dispatch only; no compiler, QEMU or board execution'
    Inputs=@((Get-FileHash -LiteralPath $PSCommandPath),
        (Get-FileHash -LiteralPath $matrixPath)) | Select-Object Path,Hash
}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'results.json') -Encoding ASCII
Write-Host "PASS matrix execution policy: $($checks.Count) checks; $out"
