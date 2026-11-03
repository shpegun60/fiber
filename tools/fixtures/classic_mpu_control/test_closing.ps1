param(
    [Parameter(Mandatory=$true)][string]$ReceiptPath,
    [Parameter(Mandatory=$true)][string]$BuildRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if (Test-Path -LiteralPath $BuildRoot) { throw 'Use a fresh closing-control evidence root' }
[void](New-Item -ItemType Directory -Path $BuildRoot)
$launcher = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../test_classic_mpu_control.ps1'))
$receiptFile = (Resolve-Path -LiteralPath $ReceiptPath).Path
$inputs = [ordered]@{}
foreach ($path in @($launcher, $receiptFile, $PSCommandPath, (Get-Process -Id $PID).Path)) {
    $inputs[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}
$rows = New-Object 'System.Collections.Generic.List[object]'
$report = [ordered]@{Verdict='FAIL'; Scope='Actual AST-extracted PowerShell receipt checker; no CPU/build';
    CPUExecuted=$false; CompleteSuite=$false; Cases=$rows; InputsBefore=$inputs; InputDrift=@(); Errors=@()}
$resultPath = Join-Path $BuildRoot 'results.json'
$report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $resultPath -Encoding ASCII
try {
    $errors=$null
    $tokens=$null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($launcher, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Launcher AST failed' }
    $functions = @($ast.FindAll({param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-ClassicMpuControlReceipt'
    }, $true))
    if ($functions.Count -ne 1) { throw 'Expected one actual receipt checker' }
    $body = $functions[0].Extent.Text
    $body | Set-Content -LiteralPath (Join-Path $BuildRoot 'actual-checker.ps1') -Encoding ASCII
    . ([scriptblock]::Create($body))
    $seedText = Get-Content -LiteralPath $receiptFile -Raw
    $seed = $seedText | ConvertFrom-Json
    Assert-ClassicMpuControlReceipt $seed
    $rows.Add([pscustomobject]@{Name='authentic-complete-receipt'; Expected='ACCEPT'; Actual='ACCEPT'})

    function RejectValue([string]$Name, $Value, [string]$Reason) {
        $observed = $null
        try { Assert-ClassicMpuControlReceipt $Value } catch { $observed = $_.Exception.Message }
        $expected = "Classic MPU CONTROL receipt rejected: $Reason"
        if ($observed -cne $expected) { throw "Closing control $Name expected '$expected', observed '$observed'" }
        $rows.Add([pscustomobject]@{Name=$Name; Expected='REJECT'; Actual='REJECT'; Diagnostic=$observed})
    }
    function Negative([string]$Name, [scriptblock]$Edit, [string]$Reason) {
        $value = $seedText | ConvertFrom-Json
        & $Edit $value
        RejectValue $Name $value $Reason
    }

    foreach ($field in @('Verdict', 'CompleteSuite', 'CPUExecuted', 'ArtifactsVerifiedBeforePass',
            'Errors', 'InputDrift', 'Counts', 'ControlCounts', 'Cases', 'Controls')) {
        Negative "missing-$field" {param($r) $r.PSObject.Properties.Remove($field)} 'receipt fields'
    }
    RejectValue 'null-receipt' $null 'receipt object type'
    RejectValue 'string-receipt' 'PASS' 'receipt object type'
    RejectValue 'bool-receipt' $true 'receipt object type'
    RejectValue 'array-receipt' @($seed) 'receipt object type'
    RejectValue 'hashtable-receipt' @{} 'receipt object type'
    RejectValue 'parent-coerced-incomplete-reproduction' ([pscustomobject]@{
        Verdict='PASS'; CompleteSuite='True'; CPUExecuted='False'; InputDrift=@();
        ArtifactsVerifiedBeforePass=$false
    }) 'receipt fields'
    foreach ($field in @('CompleteSuite', 'CPUExecuted', 'ArtifactsVerifiedBeforePass')) {
        Negative "null-$field" {param($r) $r.$field=$null} "$field boolean"
        Negative "string-$field" {param($r) $r.$field=[string]$r.$field} "$field boolean"
        Negative "integer-$field" {param($r) $r.$field=1} "$field boolean"
        Negative "opposite-$field" {param($r) $r.$field=-not $r.$field} "$field boolean"
    }
    Negative 'failed-verdict' {param($r) $r.Verdict='FAIL'} 'Verdict'
    Negative 'skip-verdict' {param($r) $r.Verdict='SKIP'} 'Verdict'
    Negative 'lowercase-verdict' {param($r) $r.Verdict='pass'} 'Verdict'
    Negative 'bool-verdict' {param($r) $r.Verdict=$true} 'Verdict'
    foreach ($field in @('Errors', 'InputDrift')) {
        Negative "null-$field" {param($r) $r.$field=$null} "$field array"
        Negative "string-$field" {param($r) $r.$field=''} "$field array"
        Negative "count-object-$field" {param($r) $r.$field=[pscustomobject]@{Count=0}} "$field array"
        Negative "nonempty-$field" {param($r) $r.$field=@('failure')} "$field nonempty"
    }
    foreach ($group in @('Counts', 'ControlCounts')) {
        Negative "null-$group" {param($r) $r.$group=$null} "$group object type"
        Negative "string-$group" {param($r) $r.$group='complete'} "$group object type"
        Negative "array-$group" {param($r) $r.$group=@()} "$group object type"
        Negative "extra-$group" {param($r) $r.$group | Add-Member -NotePropertyName Extra -NotePropertyValue 0} "$group fields"
        foreach ($field in @($seed.$group.PSObject.Properties.Name)) {
            Negative "missing-$group-$field" {param($r) $r.$group.PSObject.Properties.Remove($field)} "$group fields"
            Negative "wrong-$group-$field" {param($r) $r.$group.$field+=1} "$group.$field integer"
            Negative "string-$group-$field" {param($r) $r.$group.$field=[string]$r.$group.$field} "$group.$field integer"
            Negative "bool-$group-$field" {param($r) $r.$group.$field=$true} "$group.$field integer"
            Negative "float-$group-$field" {param($r) $r.$group.$field=[double]$r.$group.$field} "$group.$field integer"
        }
    }
    foreach ($field in @('Scope', 'PythonImage', 'Python')) {
        Negative "empty-$field" {param($r) $r.$field=''} "$field text"
        Negative "bool-$field" {param($r) $r.$field=$true} "$field text"
    }
    Negative 'zero-Commands' {param($r) $r.Commands=0} 'Commands integer'
    Negative 'string-Commands' {param($r) $r.Commands=[string]$r.Commands} 'Commands integer'
    Negative 'missing-tool' {param($r) $r.Tools.PSObject.Properties.Remove('plugin')} 'Tools fields'
    Negative 'bool-tool' {param($r) $r.Tools.cc1=$false} 'Tools.cc1 text'
    foreach ($field in @('Cases', 'Controls')) {
        Negative "null-$field" {param($r) $r.$field=$null} "$field array"
        Negative "object-$field" {param($r) $r.$field=[pscustomobject]@{Count=0}} "$field array"
        Negative "empty-$field" {param($r) $r.$field=@()} "$field incomplete"
        Negative "null-row-$field" {param($r) $r.$field[0]=$null} "$field row object type"
        Negative "missing-Kind-$field" {param($r) $r.$field[0].PSObject.Properties.Remove('Kind')} "$field row Kind missing"
        Negative "skip-Kind-$field" {param($r) $r.$field[0].Kind='SKIP'} "$field Kind"
        Negative "skip-status-$field" {param($r) $r.$field[0] | Add-Member -NotePropertyName Status -NotePropertyValue 'SKIP'} "$field row fields"
    }
    Negative 'duplicate-case' {param($r) $r.Cases[1]=$r.Cases[0]} 'Cases duplicate/unknown: HOST-GUARDS|CM0-v0|O0'
    Negative 'one-case-missing-counts-unchanged' {param($r) $r.Cases=@($r.Cases | Select-Object -Skip 1)} 'Cases incomplete'
    Negative 'wrong-case-checks' {param($r) $r.Cases[0].Checks=0} 'Cases Checks integer'
    Negative 'string-case-guards' {param($r) $r.Cases[0].Guards=[string]$r.Cases[0].Guards} 'Cases Guards integer'
    Negative 'string-case-mode' {param($r) ($r.Cases | Where-Object Kind -CEQ 'ARM-CODEGEN' | Select-Object -First 1).NativeLTO='False'} 'Cases mode boolean'
    Negative 'wrong-case-origin' {param($r) $r.Cases[0].Profile='CM0-v2'} 'Cases Profile'
    Negative 'missing-pre-MRS-root' {param($r) ($r.Cases | Where-Object Kind -CEQ 'ARM-CODEGEN' | Select-Object -First 1).PreMRSClosure=@('unrelated')} 'Cases PreMRSClosure roots'
    Negative 'unexpected-pre-MRS-external' {param($r) ($r.Cases | Where-Object Kind -CEQ 'ARM-CODEGEN' | Select-Object -First 1).ExternalTerminal=@('memcpy')} 'Cases ExternalTerminal members'
    foreach ($field in @('Profile', 'Optimization', 'Packaging', 'ProviderGeneration')) {
        foreach ($shape in @('bool', 'array')) {
            Negative "$shape-case-$field" {
                param($r)
                $row=$r.Cases | Where-Object { @($_.PSObject.Properties.Name) -ccontains $field } | Select-Object -First 1
                if($shape -ceq 'bool'){$row.$field=$true}else{$row.$field=@($row.$field)}
            } "Cases $field text"
        }
    }
    Negative 'lowercase-case-opt' {param($r) $r.Cases[0].Optimization='o0'} 'Cases duplicate/unknown: HOST-GUARDS|CM0-v0|o0'
    Negative 'case-package-capitalization' {param($r) ($r.Cases | Where-Object Kind -CEQ 'COHORT-MATCHING-LINK' | Select-Object -First 1).Packaging='Direct'} 'Cases duplicate/unknown: COHORT-MATCHING-LINK|CM0-v0|False|v2|Direct'
    Negative 'bool-pre-MRS-external' {param($r) ($r.Cases | Where-Object Kind -CEQ 'ARM-CODEGEN' | Select-Object -First 1).ExternalTerminal=@($true)} 'Cases ExternalTerminal member text'
    Negative 'duplicate-pre-MRS-name' {param($r) $row=$r.Cases | Where-Object Kind -CEQ 'ARM-CODEGEN' | Select-Object -First 1; $row.PreMRSClosure[1]=$row.PreMRSClosure[0]} 'Cases PreMRSClosure duplicate'
    $guard = ($seed.Controls | Where-Object Kind -CEQ 'COMPILED-GUARD-MUTATION' | Select-Object -First 1).Guard
    Negative 'duplicate-control' {param($r) $r.Controls[1]=$r.Controls[0]} "Controls duplicate/unknown: COMPILED-GUARD-MUTATION|CM0-v0|$guard"
    Negative 'one-control-missing-counts-unchanged' {param($r) $r.Controls=@($r.Controls | Select-Object -Skip 1)} 'Controls incomplete'
    Negative 'wrong-control-witness' {param($r) $r.Controls[0].Diagnostic=$r.Controls[0].Diagnostic -replace 'actual=1$', 'actual=0'} 'Controls Diagnostic witness'
    Negative 'string-control-mode' {param($r) ($r.Controls | Where-Object Kind -CEQ 'ACTUAL-RUNTIME-V1-V2-COHORT' | Select-Object -First 1).NativeLTO='False'} 'Controls mode boolean'
    Negative 'wrong-readback-count' {param($r) ($r.Controls | Where-Object Kind -CEQ 'COMPILED-OLD-CM0-READBACK' | Select-Object -First 1).ExpectedBadReadbacks=3} 'Controls ExpectedBadReadbacks integer'
    Negative 'short-provider-hash' {param($r) ($r.Controls | Where-Object Kind -CEQ 'ACTUAL-RUNTIME-V1-V2-COHORT' | Select-Object -First 1).ProviderSHA256='ABCD'} 'Controls ProviderSHA256'
    Negative 'duplicate-active-family' {param($r) $row=$r.Controls | Where-Object Kind -CEQ 'COMPILED-RAW-FAMILIES' | Select-Object -First 1; $row.Observed[1]=$row.Observed[0]} 'Controls Observed duplicate/unknown: coverage'
    Negative 'missing-active-family' {param($r) ($r.Controls | Where-Object Kind -CEQ 'COMPILED-RAW-FAMILIES' | Select-Object -First 1).Observed=@('coverage')} 'Controls Observed inventory'
    Negative 'active-family-capitalization' {param($r) ($r.Controls | Where-Object Kind -CEQ 'COMPILED-RAW-FAMILIES' | Select-Object -First 1).Observed[0]='Coverage'} 'Controls Observed duplicate/unknown: Coverage'
    $changedGuard=$guard.Replace('context_fast_check', 'context_FAST_check')
    Negative 'guard-identity-capitalization' {param($r) $r.Controls[0].Guard=$changedGuard; $r.Controls[0].Diagnostic=$r.Controls[0].Diagnostic.Replace($guard,$changedGuard)} "Controls duplicate/unknown: COMPILED-GUARD-MUTATION|CM0-v0|$changedGuard"

    $names = @($rows | ForEach-Object Name | Sort-Object -Unique)
    if ($names.Count -ne $rows.Count) { throw 'Duplicate closing-control identity' }
    $report.Positive = @($rows | Where-Object Expected -CEQ 'ACCEPT').Count
    $report.Negative = @($rows | Where-Object Expected -CEQ 'REJECT').Count
    if ($report.Positive -ne 1 -or $report.Negative -ne 162) { throw 'Incomplete exact closing-control inventory' }
    $report.CompleteSuite = $true
} catch {
    $report.Errors = @($_.Exception.Message)
} finally {
    $after = [ordered]@{}
    foreach ($path in $inputs.Keys) {
        $after[$path] = if (Test-Path -LiteralPath $path -PathType Leaf) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } else { $null }
    }
    $report.InputsAfter = $after
    $report.InputDrift = @($inputs.Keys | Where-Object { $inputs[$_] -cne $after[$_] })
    if ($report.CompleteSuite -and $report.Errors.Count -eq 0 -and $report.InputDrift.Count -eq 0) { $report.Verdict='PASS' }
    $report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $resultPath -Encoding ASCII
}
if ($report.Verdict -cne 'PASS') { throw "Closing controls failed: $resultPath ($($report.Errors -join '; '))" }
Write-Host "PASS classic MPU CONTROL closing controls: $BuildRoot"
