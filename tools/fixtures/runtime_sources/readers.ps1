param([string]$CaseList, [string]$OutputPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$cases = Get-Content -LiteralPath $CaseList -Raw | ConvertFrom-Json
$results = New-Object System.Collections.Generic.List[object]
foreach ($case in $cases) {
    try {
        . (Join-Path $case.root 'tools/runtime_sources.ps1')
    }
    catch {
        $failure = @{accepted=$false;error=$_.Exception.Message}
        $results.Add([pscustomobject]@{name=$case.name;apis=@{paths=$failure;inputs=$failure}})
        continue
    }
    $apis = @{}
    foreach ($api in @('paths', 'inputs')) {
        $command = if ($api -eq 'paths') { 'Get-RuntimeSourcePaths' } else { 'Get-RuntimeSourceInputs' }
        try {
            if ($case.omit_roles) {
                $value = @(& $command -RepositoryRoot $case.root)
            }
            else {
                $value = @(& $command -RepositoryRoot $case.root -Roles $case.roles)
            }
            $apis[$api] = @{accepted=$true;value=$value}
        }
        catch {
            $apis[$api] = @{accepted=$false;error=$_.Exception.Message}
        }
    }
    $results.Add([pscustomobject]@{name=$case.name;apis=$apis})
}
$results.ToArray() | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $OutputPath -Encoding UTF8
