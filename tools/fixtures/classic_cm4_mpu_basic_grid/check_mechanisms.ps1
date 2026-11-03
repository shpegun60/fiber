param([string]$Source,[string]$LedgerPath,[string]$Reference,[string]$Subject,[string]$Output,[string]$ExpectedFailure='')
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Maintained mechanism source parse failure'}
foreach($name in @('Get-DisassemblyFunctionBody','Assert-OrderedPatterns','Assert-MechanismParity')) {
 $f=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
 if($f.Count -ne 1){throw "Exact maintained function missing: $name"}
 Invoke-Expression $f[0].Extent.Text
}
$blocks=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] -and $n.Variable.VariablePath.UserPath -eq 'mpuPort'},$true))
if($blocks.Count -ne 1){throw 'Exact MPU mechanism block not unique'}
$body=$blocks[0].Body.Extent.Text
if($body -notmatch 'PendSV-MPU' -or $body -notmatch 'first-restore' -or $body -notmatch 'SVC-dispatch'){throw 'Maintained mechanism set changed'}
$compiled=@{ ARM_CM4_MPU=[pscustomobject]@{
 Reference=(Get-Content -LiteralPath $Reference -Raw); ReferencePath=$Reference
 Fiber=(Get-Content -LiteralPath $Subject -Raw); FiberPath=$Subject } }
$ledger=Get-Content -LiteralPath $LedgerPath -Raw
$ClassicOnly=$true; $script:cm0Mechanisms=@()
$mpuPort=[pscustomobject]@{Name='ARM_CM4_MPU';HasFp=$true}
$failure=''
try { Invoke-Expression $body.Substring(1,$body.Length-2) }
catch { $failure=$_.Exception.Message }
if($ExpectedFailure) {
 if(-not $failure.StartsWith($ExpectedFailure,[System.StringComparison]::Ordinal)){throw "Wrong mechanism control failure: $failure"}
 $status='REJECTED'
} else {
 if($failure){throw $failure}
 if($script:cm0Mechanisms.Count -ne 3){throw 'Three literal mechanism checks required'}
 $status='PASS'
}
$sha=[System.Security.Cryptography.SHA256]::Create()
$encoded=[Text.Encoding]::UTF8.GetBytes($blocks[0].Extent.Text)
$blockSha=([BitConverter]::ToString($sha.ComputeHash($encoded))).Replace('-','')
[ordered]@{Status=$status;Failure=$failure;ExpectedFailure=$ExpectedFailure;Checks=$script:cm0Mechanisms;
 Source=$Source;BlockSha256=$blockSha;Reference=$Reference;Subject=$Subject;
 Scope='Imported maintained ordered decoded mechanisms only; no byte equivalence or execution'} |
 ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Output -Encoding ascii
