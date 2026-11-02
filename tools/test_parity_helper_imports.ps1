param(
    [Parameter(Mandatory=$true)][string]$ArmGcc,
    [string]$BuildRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$objdump = Join-Path (Split-Path $ArmGcc) 'arm-none-eabi-objdump.exe'
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$build = Join-Path $BuildRoot ('parity-helper-imports-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $build -Force | Out-Null
$path = Join-Path $repo 'tools\freertos_asm_parity.ps1'
$sourceHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
$tokens = $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$names = @('Invoke-Compile','Add-BoundCallRelocationTargets','Get-ObjectDisassembly',
    'Get-DisassemblyFunctionBody','Assert-OrderedPatterns','Assert-MechanismParity')
foreach ($name in $names) {
    $definitions = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $name
    })
    if ($definitions.Count -ne 1) { throw "Nonunique imported helper: $name" }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
$c = Join-Path $build 'probe.c'
'unsigned parity_helper_probe(void) { return 17u; }' | Set-Content -LiteralPath $c -Encoding ASCII
$script:cm0Mechanisms = @()
$cases = @()
foreach ($mode in @('absent','disabled','enabled')) {
    if ($mode -eq 'absent') {
        if (Get-Variable -Name ClassicOnly -ErrorAction SilentlyContinue) {
            throw 'Absent caller-state fixture unexpectedly inherited ClassicOnly'
        }
    } else { $ClassicOnly = $mode -eq 'enabled' }
    $BuildRoot = $build
    $ClassicEvidence = $mode
    $logDir = Join-Path $build $mode
    New-Item -ItemType Directory -Path $logDir | Out-Null
    $object = Join-Path $logDir 'probe.o'
    Invoke-Compile -Compiler $ArmGcc -Arguments @('-mcpu=cortex-m3','-mthumb',
        '-O2','-ffreestanding','-ffunction-sections','-c',$c,'-o',$object) -Label $mode
    $disassembly = Get-ObjectDisassembly -Objdump $objdump -ObjectPath $object
    $disassembly | Set-Content -LiteralPath ($object+'.dis') -Encoding ASCII
    $arguments = @{PortName='IMPORT-FIXTURE';Mechanism=$mode;
        ReferenceDisassembly=$disassembly;ReferenceSymbol='parity_helper_probe';
        ReferencePatterns=@('\bmovs\s+r0,\s*#17\b','\bbx\s+lr\b');ReferencePath=$object;
        FiberDisassembly=$disassembly;FiberSymbol='parity_helper_probe';
        FiberPatterns=@('\bmovs\s+r0,\s*#17\b','\bbx\s+lr\b');FiberPath=$object;
        DifferenceIds=@('HELPER-IMPORT-FIXTURE');Ledger='HELPER-IMPORT-FIXTURE'}
    Assert-MechanismParity @arguments
    $negative = $arguments.Clone()
    $negative.FiberPatterns = @('\bsvc\s+255\b')
    $rejected = $false
    try { Assert-MechanismParity @negative } catch {
        if (!$_.Exception.Message.StartsWith(
                "IMPORT-FIXTURE Fiber $mode lost ordered generated instruction: \bsvc\s+255\b",
                [StringComparison]::Ordinal)) { throw }
        $rejected = $true
    }
    if (!$rejected) { throw "Missing instruction accepted: $mode" }
    $log = Join-Path $logDir 'commands.jsonl'
    if ($mode -eq 'enabled') {
        if (!(Test-Path $log) -or @(Get-Content -LiteralPath $log).Count -ne 2 -or
                $script:cm0Mechanisms.Count -ne 1) { throw 'Focused evidence lost commands/mechanism' }
    } elseif ((Test-Path $log) -or $script:cm0Mechanisms.Count) {
        throw "Inactive caller unexpectedly enabled focused recording: $mode"
    }
    $cases += [ordered]@{Mode=$mode;Object=$object;Sha256=(Get-FileHash -LiteralPath $object).Hash;
        MissingInstructionRejected=$true;FocusedRecording=($mode -eq 'enabled')}
}
$compileDefinition = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Invoke-Compile'
})[0].Extent.Text
$safeGuard = '(Get-Variable -Name ClassicOnly -ValueOnly -ErrorAction SilentlyContinue) -eq $true'
if ([regex]::Matches($compileDefinition,[regex]::Escape($safeGuard)).Count -ne 1) {
    throw 'Unique optional-telemetry guard required for regression control'
}
$mutant = Join-Path $build 'old-caller-dependency.ps1'
@('Set-StrictMode -Version 2.0', '$ErrorActionPreference = ''Stop''',
    $compileDefinition.Replace($safeGuard,'$ClassicOnly'),
    "Invoke-Compile -Compiler '$ArmGcc' -Arguments @('-c','$c','-o','$build/old.o') -Label old") |
    Set-Content -LiteralPath $mutant -Encoding ASCII
$previous = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $failure = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $mutant 2>&1 | ForEach-Object { "$_" })
    $exitCode = $LASTEXITCODE
} finally { $ErrorActionPreference = $previous }
$diagnostic = $failure -join "`n"
$diagnostic | Set-Content -LiteralPath ($mutant+'.log') -Encoding ASCII
if ($exitCode -eq 0 -or !$diagnostic.Contains("The variable '`$ClassicOnly' cannot be retrieved")) {
    throw 'Old caller-dependency control did not reproduce the intended strict-mode failure'
}
if ((Get-FileHash -LiteralPath $path).Hash -ne $sourceHash) { throw 'Imported helper source drift' }
[ordered]@{Status='PASS';Cases=$cases;Source=$path;SourceSha256=$sourceHash;
    OldCallerDependencyRejected=$true;
    Scope='Strict-mode helper imports with absent/false/true optional caller telemetry; real tiny ARM objects, not FreeRTOS semantic parity'} |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $build 'results.json') -Encoding ASCII
Write-Host "PASS parity helper imports: 3 compiler objects and 4 negative controls; $build"
