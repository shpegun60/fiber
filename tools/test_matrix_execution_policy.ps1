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
$result = [pscustomobject]@{
    Status='PASS';Checks=$checks.Count;Cases=$checks.ToArray()
    Scope='Configuration admission only; no compiler, QEMU or board execution'
    Inputs=@((Get-FileHash -LiteralPath $PSCommandPath),
        (Get-FileHash -LiteralPath $matrixPath)) | Select-Object Path,Hash
}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'results.json') -Encoding ASCII
Write-Host "PASS matrix execution policy: $($checks.Count) checks; $out"
