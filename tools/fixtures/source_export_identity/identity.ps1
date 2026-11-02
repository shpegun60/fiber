param(
    [switch]$RunProof,
    [string]$ProofArmGcc,
    [string]$ProofCmsisCore,
    [string]$ProofFreeRtosRoot,
    [string]$ProofQemuRoot,
    [string]$ProofWslDistro='Ubuntu-24.04',
    [string]$ProofBuildRoot
)

function Write-SourceExportManifest {
    param([string]$RepositoryRoot,[object[]]$InputHashes,
        [string]$OutputDirectory,[ValidateSet('before','after')][string]$Label)
    $root=[IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([char[]]'\/')
    $prefix=$root+[IO.Path]::DirectorySeparatorChar
    $byPath=New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($row in $InputHashes) {
        $absolute=[IO.Path]::GetFullPath([string]$row.Path)
        if(!$absolute.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){continue}
        $relative=$absolute.Substring($prefix.Length).Replace('\','/')
        $hash=[string]$row.Hash
        if($relative -match '[\r\n]' -or $hash -cnotmatch '^[0-9A-Fa-f]{64}$' -or !$seen.Add($relative)) {
            throw "Invalid/duplicate source manifest input: $relative"
        }
        $byPath.Add($relative,$hash.ToLowerInvariant())
    }
    if(!$byPath.Count){throw 'Source manifest contains no repository input bytes'}
    [string[]]$paths=@($byPath.Keys)
    [Array]::Sort($paths,[StringComparer]::Ordinal)
    $canonical=New-Object Text.StringBuilder
    $null=$canonical.Append("fiber-source-byte-manifest-v1`n")
    $files=@(foreach($path in $paths) {
        $null=$canonical.Append($byPath[$path]).Append('  ').Append($path).Append("`n")
        [pscustomobject]@{Path=$path;SHA256=$byPath[$path]}
    })
    $encoding=New-Object Text.UTF8Encoding($false)
    $bytes=$encoding.GetBytes($canonical.ToString())
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}
    finally {$sha.Dispose()}
    $manifest=Join-Path $OutputDirectory ("source-manifest-$Label.sha256")
    [IO.File]::WriteAllBytes($manifest,$bytes)
    $identity=[pscustomobject]@{
        Schema='fiber-source-byte-manifest-v1';IdentityKind='Source-byte SHA256 manifest; not a Git commit';
        Manifest=$manifest;ManifestSHA256=$digest;Files=$files
    }
    $identity | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory ("source-manifest-$Label.json")) -Encoding UTF8
    return $identity
}

function Get-SourceExportHeadMetadata {
    param([string]$RepositoryRoot,[scriptblock]$InvokeGit)
    $root=[IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([char[]]'\/')
    $metadata=[pscustomobject]@{Status='NoRootGitMetadata';Head=$null;ExactRepositoryRoot=$false;
        Detail='Optional attribution only; source-byte manifests remain authoritative'}
    if(!(Test-Path -LiteralPath (Join-Path $root '.git'))){return $metadata}
    try {
        $top=& $InvokeGit -GitArguments @('--no-optional-locks','-C',$root,'rev-parse','--show-toplevel')
        if($top.Code -ne 0){$metadata.Status='GitMetadataUnavailable';return $metadata}
        $actual=[IO.Path]::GetFullPath($top.Text.Trim()).TrimEnd([char[]]'\/')
        if(![string]::Equals($actual,$root,[StringComparison]::OrdinalIgnoreCase)) {
            $metadata.Status='RejectedDifferentRepositoryRoot';return $metadata
        }
        $head=& $InvokeGit -GitArguments @('--no-optional-locks','-C',$root,'rev-parse','--verify','HEAD^{commit}')
        if($head.Code -ne 0 -or $head.Text.Trim() -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
            $metadata.Status='GitHeadUnavailableOrInvalid';return $metadata
        }
        $metadata.Status='AvailableExactRoot';$metadata.Head=$head.Text.Trim();$metadata.ExactRepositoryRoot=$true
    } catch {$metadata.Status='GitMetadataUnavailable';$metadata.Detail=$_.Exception.Message}
    return $metadata
}

if($RunProof) {
    $ErrorActionPreference='Stop'
    Set-StrictMode -Version 2.0
    $liveRepo=(Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
    if(!$ProofBuildRoot){$ProofBuildRoot=[IO.Path]::GetTempPath()}
    $proof=Join-Path $ProofBuildRoot ('source-export-identity-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $proof
    $proofCommands=Join-Path $proof 'commands.jsonl'
    $proofChecks=New-Object System.Collections.Generic.List[object]
    $proofInputs=New-Object System.Collections.Generic.List[object]
    $proofVerdict='FAIL';$proofFailure='';$proofReceipts=@();$proofLtoTools=@()
    function ProofCheck([string]$Name,[bool]$Passed,[object]$Evidence) {
        $proofChecks.Add([pscustomobject]@{Name=$Name;Passed=$Passed;Evidence=$Evidence})
        if(!$Passed){throw "Source export identity proof failed: $Name"}
    }
    function ProofRun([string]$Program,[string[]]$Arguments,[string]$Log) {
        $old=$ErrorActionPreference
        try {$ErrorActionPreference='Continue';$output=@(& $Program @Arguments 2>&1 | ForEach-Object {"$_"});$code=$LASTEXITCODE}
        finally {$ErrorActionPreference=$old}
        $text=$output -join "`n";[IO.File]::WriteAllText($Log,$text)
        @{Program=$Program;Arguments=$Arguments;ExitCode=$code;Log=$Log} | ConvertTo-Json -Compress -Depth 5 | Add-Content $proofCommands -Encoding ASCII
        [pscustomobject]@{Code=$code;Text=$text}
    }
    try {
        Write-Host "Source export identity proof: $proof"
        foreach($required in @($ProofArmGcc,$ProofCmsisCore,$ProofFreeRtosRoot)) {
            if(!$required -or !(Test-Path -LiteralPath $required)){throw 'Supply existing compiler, CMSIS and FreeRTOS paths'}
        }
        if(!$ProofQemuRoot -or !$ProofQemuRoot.StartsWith('/')){throw 'Supply existing absolute WSL -ProofQemuRoot'}
        foreach($query in @(
            @{Name='lto-wrapper';Argument='-print-prog-name=lto-wrapper'},
            @{Name='liblto_plugin.dll';Argument='-print-file-name=liblto_plugin.dll'})) {
            $result=ProofRun $ProofArmGcc @($query.Argument) (Join-Path $proof ($query.Name+'-path.txt'))
            ProofCheck "tools/GCC-located-$($query.Name)" ($result.Code -eq 0 -and
                (Test-Path -LiteralPath $result.Text.Trim() -PathType Leaf)) $result.Text
            $resolved=(Resolve-Path -LiteralPath $result.Text.Trim()).Path
            $proofLtoTools+=@([pscustomobject]@{Name=$query.Name;Path=$resolved;SHA256=(Get-FileHash -LiteralPath $resolved).Hash})
        }
        $snapshot=Join-Path $proof 'source'
        $null=New-Item -ItemType Directory -Path $snapshot
        $sourceFiles=@((Get-Item -LiteralPath $PSCommandPath),
            (Get-Item (Join-Path $liveRepo 'tools/test_cm33_secure_only_runtime.ps1')),
            (Get-Item (Join-Path $liveRepo 'tools/test_cm55_secure_only_runtime.ps1')),
            (Get-Item (Join-Path $liveRepo 'tools/fixtures/portable_application.c')),
            (Get-Item (Join-Path $liveRepo 'mcu_core.h')),(Get-Item (Join-Path $liveRepo 'basic_types.h')))+
            @(Get-ChildItem (Join-Path $liveRepo 'fiber') -File | Where-Object {$_.Extension -in @('.c','.h')})+
            @(Get-ChildItem (Join-Path $liveRepo 'fiber/port') -File | Where-Object {$_.Extension -in @('.c','.h')})+
            @(Get-ChildItem (Join-Path $liveRepo 'fiber/port/ARM_CM33_SECURE_ONLY/secure'),
                (Join-Path $liveRepo 'fiber/port/ARM_CM55_SECURE_ONLY/secure') -File | Where-Object {$_.Extension -in @('.c','.h','.S','.ld')})+
            @(Get-ChildItem (Join-Path $liveRepo 'tools/fixtures/cm33_secure_only_runtime'),
                (Join-Path $liveRepo 'tools/fixtures/cm55_secure_only_runtime'),$PSScriptRoot -Recurse -File)
        foreach($file in @($sourceFiles | Sort-Object FullName -Unique)) {
            $relative=$file.FullName.Substring($liveRepo.Length+1)
            $copy=Join-Path $snapshot $relative
            $null=New-Item -ItemType Directory -Path (Split-Path $copy) -Force
            $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            [IO.File]::Copy($file.FullName,$copy)
            if((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -cne $hash){throw "Source snapshot copy race: $relative"}
            $proofInputs.Add([pscustomobject]@{Source=$file.FullName;Snapshot=$copy;SHA256=$hash})
        }
        $proofInputs.ToArray() | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $proof 'source-snapshot.json') -Encoding UTF8
        foreach($row in $proofInputs){(Get-Item -LiteralPath $row.Snapshot).IsReadOnly=$true}
        ProofCheck 'export/no-root-git-metadata' (!(Test-Path (Join-Path $snapshot '.git'))) $snapshot

        $control=Join-Path $proof 'controls';$null=New-Item -ItemType Directory -Path $control
        $a=Join-Path $control 'a.c';$b=Join-Path $control 'b.h'
        [IO.File]::WriteAllText($a,'unsigned a;');[IO.File]::WriteAllText($b,'extern unsigned a;')
        $controlHashes=@(Get-FileHash -LiteralPath $b,$a -Algorithm SHA256 | Select-Object Path,Hash)
        $m1=Write-SourceExportManifest $control $controlHashes $control before
        $m2=Write-SourceExportManifest $control @($controlHashes[1],$controlHashes[0]) $control after
        ProofCheck 'manifest/order-independent-and-byte-hash' ($m1.ManifestSHA256 -ceq $m2.ManifestSHA256 -and
            (Get-FileHash $m1.Manifest -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $m1.ManifestSHA256) $m1.ManifestSHA256
        $moved=Join-Path $proof 'relocated';$null=New-Item -ItemType Directory -Path $moved
        $movedHashes=@($controlHashes | ForEach-Object {[pscustomobject]@{Path=(Join-Path $moved ([IO.Path]::GetFileName($_.Path)));Hash=$_.Hash}})
        $m3=Write-SourceExportManifest $moved $movedHashes $moved before
        ProofCheck 'manifest/export-root-independent' ($m1.ManifestSHA256 -ceq $m3.ManifestSHA256) $m3.ManifestSHA256
        foreach($profile in @('cm33','cm55')) {
            $wrapper=Join-Path $snapshot ("tools/test_${profile}_secure_only_runtime.ps1")
            $tokens=$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($wrapper,[ref]$tokens,[ref]$errors)
            ProofCheck "$profile/wrapper-parser" ($errors.Count -eq 0) $wrapper
            $hashFunctions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'HashInputs'},$true))
            ProofCheck "$profile/exact-real-hash-input-function" ($hashFunctions.Count -eq 1) $wrapper
            . ([scriptblock]::Create($hashFunctions[0].Extent.Text))
            $driftAssignments=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$drift'},$true))
            ProofCheck "$profile/exact-real-drift-expression" ($driftAssignments.Count -eq 1) $wrapper
            $driftGuards=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
                $n.Clauses.Count -eq 1 -and $n.Clauses[0].Item1.Extent.Text -ceq '$drift.Count'},$true))
            ProofCheck "$profile/exact-real-drift-failure-guards" ($driftGuards.Count -eq 2) $wrapper
            $gateText='$after=HashInputs'+"`n"+$driftAssignments[0].Extent.Text+"`n"+
                ($driftGuards | ForEach-Object {$_.Extent.Text} | Out-String)
            $gate=Join-Path $control ($profile+'-real-drift-gate.ps1')
            [IO.File]::WriteAllText($gate,$gateText)
            $mutantText=$gateText
            foreach($guard in $driftGuards){$mutantText=$mutantText.Replace($guard.Extent.Text,'')}
            $mutant=Join-Path $control ($profile+'-removed-drift-guards.ps1')
            [IO.File]::WriteAllText($mutant,$mutantText)
            $inputs=@($a,$b);$before=HashInputs
            [IO.File]::AppendAllText($b,' /* changed fixture input */')
            $out=$control;$verdict='PASS';$mutationRejected=$false
            try {. $gate} catch {$mutationRejected=$_.Exception.Message -match '^C[35]SO inputs changed during run:'}
            ProofCheck "$profile/real-byte-gate-rejects-mutation" ($mutationRejected -and $verdict -ceq 'FAIL') $drift
            $verdict='PASS';. $mutant
            ProofCheck "$profile/removed-guards-causal-control-accepts-mutation" ($verdict -ceq 'PASS' -and $drift.Count -ne 0) $mutant
            $changed=Write-SourceExportManifest $control $after $control after
            ProofCheck "$profile/source-digest-detects-mutation" ($changed.ManifestSHA256 -cne $m1.ManifestSHA256) $changed.ManifestSHA256
            $saved=Join-Path $control 'b.saved';[IO.File]::Move($b,$saved)
            $missingRejected=$false
            try {$null=HashInputs} catch {$missingRejected=$_.Exception.Message -match 'cannot find|does not exist|not exist'}
            finally {[IO.File]::Move($saved,$b)}
            ProofCheck "$profile/real-byte-gate-rejects-removed-input" $missingRejected 'Actual wrapper HashInputs, isolated mutable fixture only'
            [IO.File]::WriteAllText($b,'extern unsigned a;')
            foreach($tool in $proofLtoTools) {
                $toolControl=Join-Path $control ($profile+'-'+$tool.Name)
                $null=New-Item -ItemType Directory -Path $toolControl
                $fixtureToolPath=Join-Path $toolControl ([IO.Path]::GetFileName($tool.Path))
                [IO.File]::Copy($tool.Path,$fixtureToolPath)
                ProofCheck "$profile/$($tool.Name)/tool-copy-matches-installed-bytes" (
                    (Get-FileHash -LiteralPath $fixtureToolPath).Hash -ceq $tool.SHA256) $fixtureToolPath
                $marker=if($tool.Name -eq 'lto-wrapper'){'Missing compiler subprocess: $program'}else{'Missing compiler LTO plugin: liblto_plugin.dll'}
                $admission=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
                    $n.Extent.Text.Contains($marker)},$true))
                ProofCheck "$profile/$($tool.Name)/exact-real-existence-guard" ($admission.Count -eq 1) $wrapper
                $setup=if($tool.Name -eq 'lto-wrapper'){'$path=$fixtureToolPath;$program=''lto-wrapper'''}else{'$ltoPlugin=$fixtureToolPath'}
                $admit=Join-Path $toolControl 'actual-admission.ps1'
                [IO.File]::WriteAllText($admit,$setup+"`n"+$admission[0].Extent.Text)
                $admitMutant=Join-Path $toolControl 'removed-existence-guard.ps1'
                [IO.File]::WriteAllText($admitMutant,$setup)
                . $admit
                $inputs=@((Join-Path $snapshot 'fiber/fiber_core.c'),$fixtureToolPath);$before=HashInputs
                $sourceBefore=Write-SourceExportManifest $snapshot $before $toolControl before
                $stream=[IO.File]::Open($fixtureToolPath,[IO.FileMode]::Append,[IO.FileAccess]::Write)
                try {$stream.WriteByte(0)} finally {$stream.Dispose()}
                $out=$toolControl;$verdict='PASS';$mutationRejected=$false
                try {. $gate} catch {$mutationRejected=$_.Exception.Message -match '^C[35]SO inputs changed during run:'}
                ProofCheck "$profile/$($tool.Name)/actual-tool-drift-rejected" ($mutationRejected -and $verdict -ceq 'FAIL') $drift
                $verdict='PASS';. $mutant
                ProofCheck "$profile/$($tool.Name)/removed-drift-guards-causal-control" ($verdict -ceq 'PASS' -and $drift.Count -ne 0) $mutant
                $sourceAfter=Write-SourceExportManifest $snapshot $after $toolControl after
                ProofCheck "$profile/$($tool.Name)/tool-drift-does-not-relabel-source-bytes" (
                    $sourceBefore.ManifestSHA256 -ceq $sourceAfter.ManifestSHA256) $sourceAfter.ManifestSHA256
                $removed=$fixtureToolPath+'.removed';[IO.File]::Move($fixtureToolPath,$removed)
                try {
                    $missingRejected=$false
                    try {. $admit} catch {$missingRejected=$_.Exception.Message -match '^Missing compiler (subprocess: lto-wrapper|LTO plugin: liblto_plugin\.dll)$'}
                    ProofCheck "$profile/$($tool.Name)/actual-missing-admission-rejected" $missingRejected $admit
                    . $admitMutant
                    ProofCheck "$profile/$($tool.Name)/removed-existence-guard-causal-control" (!(Test-Path -LiteralPath $fixtureToolPath)) $admitMutant
                    $missingRejected=$false
                    try {$null=HashInputs} catch {$missingRejected=$_.Exception.Message -match 'cannot find|does not exist|not exist'}
                    ProofCheck "$profile/$($tool.Name)/actual-missing-input-hash-rejected" $missingRejected $fixtureToolPath
                } finally {[IO.File]::Move($removed,$fixtureToolPath)}
            }
        }
        $noGit=Get-SourceExportHeadMetadata $snapshot {throw 'No-root-metadata must not invoke Git'}
        ProofCheck 'head/no-root-metadata-is-null' ($null -eq $noGit.Head -and $noGit.Status -ceq 'NoRootGitMetadata') $noGit
        $gitFixture=Join-Path $control '.git';$null=New-Item -ItemType Directory -Path $gitFixture
        $wrong=Get-SourceExportHeadMetadata $control { [pscustomobject]@{Code=0;Text=$snapshot} }
        ProofCheck 'head/rejects-inherited-or-foreign-root' ($null -eq $wrong.Head -and $wrong.Status -ceq 'RejectedDifferentRepositoryRoot') $wrong
        $invalid=Get-SourceExportHeadMetadata $control {
            param([string[]]$GitArguments)
            if($GitArguments -contains '--show-toplevel'){[pscustomobject]@{Code=0;Text=$control}}
            else {[pscustomobject]@{Code=0;Text='not-a-commit'}}
        }
        ProofCheck 'head/rejects-invalid-head' ($null -eq $invalid.Head -and $invalid.Status -ceq 'GitHeadUnavailableOrInvalid') $invalid
        $failed=Get-SourceExportHeadMetadata $control {[pscustomobject]@{Code=128;Text='unavailable fixture metadata'}}
        ProofCheck 'head/failed-git-remains-optional' ($null -eq $failed.Head -and $failed.Status -ceq 'GitMetadataUnavailable') $failed
        $thrown=Get-SourceExportHeadMetadata $control {throw 'fixture Git executable unavailable'}
        ProofCheck 'head/absent-git-remains-optional' ($null -eq $thrown.Head -and $thrown.Status -ceq 'GitMetadataUnavailable') $thrown
        $broken=Get-SourceExportHeadMetadata $control {
            param([string[]]$GitArguments)
            ProofRun 'git' $GitArguments (Join-Path $control ('broken-git-'+[guid]::NewGuid().ToString('N')+'.log'))
        }
        ProofCheck 'head/real-broken-metadata-remains-optional' ($null -eq $broken.Head -and $broken.Status -ceq 'GitMetadataUnavailable') $broken
        $actual=Get-SourceExportHeadMetadata $liveRepo {
            param([string[]]$GitArguments)
            ProofRun 'git' $GitArguments (Join-Path $control ('git-'+[guid]::NewGuid().ToString('N')+'.log'))
        }
        ProofCheck 'head/live-attribution-is-exact-root-or-explicitly-unavailable' (
            ($actual.Status -ceq 'AvailableExactRoot' -and $actual.ExactRepositoryRoot) -or
            ($null -eq $actual.Head -and !$actual.ExactRepositoryRoot)) $actual
        foreach($profile in @('cm33','cm55')) {
            $wrapper=Join-Path $snapshot ("tools/test_${profile}_secure_only_runtime.ps1")
            $childRoot=Join-Path $proof $profile;$null=New-Item -ItemType Directory -Path $childRoot
            $run=ProofRun 'powershell.exe' @('-NoProfile','-ExecutionPolicy','Bypass','-File',$wrapper,
                '-ArmGcc',$ProofArmGcc,'-CmsisCore',$ProofCmsisCore,'-FreeRtosRoot',$ProofFreeRtosRoot,
                '-QemuRoot',$ProofQemuRoot,'-WslDistro',$ProofWslDistro,'-BuildRoot',$childRoot,'-AdmissionOnly') (Join-Path $proof ($profile+'.log'))
            ProofCheck "$profile/actual-no-git-export-admission-exit" ($run.Code -eq 0) $run.Text
            $receipts=@(Get-ChildItem $childRoot -Recurse -Filter receipt.json -File)
            ProofCheck "$profile/exact-one-child-receipt" ($receipts.Count -eq 1) $receipts.FullName
            $receipt=Get-Content -LiteralPath $receipts[0].FullName -Raw | ConvertFrom-Json
            ProofCheck "$profile/actual-architecture-proof-and-source-stability" ($receipt.Verdict -ceq 'PASS' -and $receipt.AdmissionOnly -and
                !$receipt.CompleteSuite -and $receipt.Executed -gt 0 -and @($receipt.Drift).Count -eq 0 -and
                $receipt.SourceManifestStable -and $null -eq $receipt.RepositoryHEADBefore -and $null -eq $receipt.RepositoryHEADAfter -and
                $receipt.RepositoryMetadataBefore.Status -ceq 'NoRootGitMetadata' -and $receipt.RepositoryMetadataAfter.Status -ceq 'NoRootGitMetadata' -and
                $receipt.ReferenceIdentityChecked) $receipts[0].FullName
            $childBefore=Get-Content (Join-Path $receipts[0].DirectoryName 'inputs-before.json') -Raw | ConvertFrom-Json
            $childAfter=Get-Content (Join-Path $receipts[0].DirectoryName 'inputs-after.json') -Raw | ConvertFrom-Json
            ProofCheck "$profile/receipt-exact-two-LTO-tools" ($receipt.CompilerLtoToolsBefore.Count -eq 2 -and
                $receipt.CompilerLtoToolsAfter.Count -eq 2) $receipts[0].FullName
            foreach($tool in $proofLtoTools) {
                foreach($census in @(
                    @{Name='inputs-before';Rows=$childBefore},@{Name='inputs-after';Rows=$childAfter},
                    @{Name='receipt-before';Rows=$receipt.CompilerLtoToolsBefore},@{Name='receipt-after';Rows=$receipt.CompilerLtoToolsAfter})) {
                    $matches=@($census.Rows | Where-Object {$_.Path -ceq $tool.Path -and $_.Hash -ceq $tool.SHA256})
                    ProofCheck "$profile/$($tool.Name)/actual-path-and-hash-in-$($census.Name)" ($matches.Count -eq 1) $tool.Path
                }
            }
            $identity=Get-Content (Join-Path $receipts[0].DirectoryName 'source-manifest-before.json') -Raw | ConvertFrom-Json
            ProofCheck "$profile/source-manifest-includes-wrapper-and-shared-helper" (
                @($identity.Files | Where-Object {$_.Path -ceq "tools/test_${profile}_secure_only_runtime.ps1"}).Count -eq 1 -and
                @($identity.Files | Where-Object {$_.Path -ceq 'tools/fixtures/source_export_identity/identity.ps1'}).Count -eq 1 -and
                (Get-FileHash -LiteralPath $identity.Manifest -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $identity.ManifestSHA256) $identity.Manifest
            $proofReceipts+=@([pscustomobject]@{Profile=$profile;Receipt=$receipts[0].FullName;SHA256=(Get-FileHash $receipts[0].FullName).Hash;
                SourceManifestSHA256=$receipt.SourceManifestSHA256Before;Checks=$receipt.Checks;Executed=$receipt.Executed})
        }
        foreach($row in $proofInputs) {
            ProofCheck 'snapshot/immutable-source-bytes-stable' ((Get-FileHash -LiteralPath $row.Snapshot).Hash -ceq $row.SHA256) $row.Snapshot
        }
        foreach($tool in $proofLtoTools) {
            ProofCheck 'tools/installed-LTO-bytes-unchanged' ((Get-FileHash -LiteralPath $tool.Path).Hash -ceq $tool.SHA256) $tool.Path
        }
        $proofVerdict='PASS'
    } catch {$proofFailure=$_.Exception.Message;throw}
    finally {
        @{Verdict=$proofVerdict;Failure=$proofFailure;Checks=$proofChecks.ToArray();Receipts=$proofReceipts;CompilerLtoTools=$proofLtoTools;
            Boundary='Two actual no-Git exported AdmissionOnly QEMU gates; helper provenance and AST-extracted wrapper byte/failure-guard controls; not full runtime or hardware qualification'} |
            ConvertTo-Json -Depth 9 | Set-Content (Join-Path $proof 'receipt.json') -Encoding UTF8
        Get-ChildItem $proof -Recurse -File | Where-Object {$_.Name -ne 'artifacts.sha256.json'} |
            ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256} | Select-Object Path,Hash |
            ConvertTo-Json -Depth 4 | Set-Content (Join-Path $proof 'artifacts.sha256.json') -Encoding UTF8
    }
    Write-Host "PASS source export identity: $($proofChecks.Count) checks; $proof"
}
