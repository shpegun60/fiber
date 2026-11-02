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
$shellDispatch = @($commands | Where-Object {
    $_.Extent.Text.Contains('"tools\test_shell_exports.ps1"')
})
Check 'shell-export/one-dispatch' ($shellDispatch.Count -eq 1)
Check 'shell-export/before-parity' ($shellDispatch[0].Extent.StartOffset -lt
    $source.IndexOf('foreach ($parityOptimization'))
Check 'shell-export/dedicated-artifacts' ($shellDispatch[0].Extent.Text.Contains(
    '-BuildRoot (Join-Path $buildRoot "audit-shell-exports")'))
$selectionDispatch = @($commands | Where-Object {
    $_.Extent.Text.Contains('"tools\test_concrete_port_selection.ps1"')
})
Check 'concrete-selection/one-dispatch' ($selectionDispatch.Count -eq 1)
Check 'concrete-selection/before-parity' ($selectionDispatch[0].Extent.StartOffset -lt
    $source.IndexOf('foreach ($parityOptimization'))
Check 'concrete-selection/compiler-and-artifacts' ($selectionDispatch[0].Extent.Text -cmatch
    '-ArmGcc \$gcc -BuildRoot \(Join-Path \$buildRoot "audit-concrete-selection"\)')
foreach ($runner in @('test_cm33f_secure_initialize', 'test_m55_secure_runtime_admission',
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
$admissionGuards = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $_.Name -ceq 'Assert-MatrixC55sAdmissionReceipt'
})
Check 'C55S/one-receipt-guard' ($admissionGuards.Count -eq 1)
. ([scriptblock]::Create($admissionGuards[0].Extent.Text))
Check 'C55S/no-duplicate-legacy-runtime-dispatch' (
    @($commands | Where-Object {
        $_.Extent.Text.Contains('"tools\test_m55_secure_runtime.ps1"')
    }).Count -eq 0)
Check 'C55S/fresh-root-required-before-dispatch' ($source -cmatch
    '(?s)if \(Test-Path -LiteralPath \$c55sAdmissionRoot\) \{\s+throw "C55S admission requires a fresh evidence directory:[^\r\n]+\s+\}\s+& \(Join-Path \$RepoRoot "tools\\test_m55_secure_runtime_admission.ps1"\)')
Check 'C55S/post-dispatch-receipt-required' ($source -cmatch
    '(?s)-BuildRoot \$c55sAdmissionRoot\s+Assert-MatrixC55sAdmissionReceipt -EvidenceRoot \$c55sAdmissionRoot')
$receiptCases = @(
    @{Name='complete';Field=$null;Value=$null;Reject=$false},
    @{Name='failed';Field='Verdict';Value='FAIL';Reject=$true},
    @{Name='boolean-verdict';Field='Verdict';Value=$true;Reject=$true},
    @{Name='development';Field='CompleteSuite';Value=$false;Reject=$true},
    @{Name='truthy-string';Field='CompleteSuite';Value='true';Reject=$true},
    @{Name='null-complete';Field='CompleteSuite';Value=$null;Reject=$true},
    @{Name='short-runtime';Field='OriginalRuntimeLaunches';Value=2489;Reject=$true},
    @{Name='boolean-runtime';Field='OriginalRuntimeLaunches';Value=$true;Reject=$true},
    @{Name='string-runtime';Field='OriginalRuntimeLaunches';Value='2490';Reject=$true},
    @{Name='short-default';Field='DefaultLaunches';Value=79;Reject=$true},
    @{Name='boolean-default';Field='DefaultLaunches';Value=$true;Reject=$true},
    @{Name='fractional-default';Field='DefaultLaunches';Value=80.5;Reject=$true},
    @{Name='drift';Field='InputDrift';Value=1;Reject=$true},
    @{Name='boolean-drift';Field='InputDrift';Value=$false;Reject=$true},
    @{Name='promoted';Field='RuntimeSelectable';Value=1;Reject=$true},
    @{Name='string-selection';Field='RuntimeSelectable';Value='0';Reject=$true},
    @{Name='missing-field';Field=$null;Value=$null;Reject=$true},
    @{Name='missing-file';Field=$null;Value=$null;Reject=$true},
    @{Name='missing-directory';Field=$null;Value=$null;Reject=$true},
    @{Name='multiple';Field=$null;Value=$null;Reject=$true},
    @{Name='malformed';Field=$null;Value=$null;Reject=$true}
)
foreach ($case in $receiptCases) {
    $root = Join-Path $out ('receipt-' + $case.Name)
    $dir = Join-Path $root 'c55sa-fixture'
    $null = New-Item -ItemType Directory -Path $dir -Force
    $receipt = [ordered]@{Verdict='PASS';CompleteSuite=$true;OriginalRuntimeLaunches=2490;
        DefaultLaunches=80;InputDrift=0;RuntimeSelectable=0}
    if ($null -ne $case.Field) { $receipt[$case.Field] = $case.Value }
    if ($case.Name -eq 'missing-field') { $receipt.Remove('DefaultLaunches') }
    if ($case.Name -ne 'missing-file' -and $case.Name -ne 'missing-directory') {
        $text = if ($case.Name -eq 'malformed') { '{ invalid JSON' } else {
            $receipt | ConvertTo-Json
        }
        [IO.File]::WriteAllText((Join-Path $dir 'results.json'), $text)
    }
    if ($case.Name -eq 'missing-directory') {
        $empty = Join-Path $root 'empty'
        $null = New-Item -ItemType Directory -Path $empty
        $root = $empty
    }
    if ($case.Name -eq 'multiple') {
        $null = New-Item -ItemType Directory -Path (Join-Path $root 'c55sa-other')
    }
    $caught = $null
    try { Assert-MatrixC55sAdmissionReceipt -EvidenceRoot $root }
    catch { $caught = $_.Exception.Message }
    Check ('C55S/receipt-' + $case.Name) (($null -ne $caught) -eq $case.Reject)
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
