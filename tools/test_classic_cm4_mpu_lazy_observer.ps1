[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ArmGcc,
    [Parameter(Mandatory=$true)][string]$PilotReceipt,
    [Parameter(Mandatory=$true)][string]$QemuRoot,
    [string]$BuildRoot,
    [string]$Python='python',
    [string]$PythonModules=$env:FIBER_CLASSIC_AUDIT_PYTHONPATH,
    [string]$WslDistro='Ubuntu-24.04'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=Split-Path -Parent $PSScriptRoot
if(-not $BuildRoot){$BuildRoot=Join-Path $env:TEMP ('cm4-mpu-lazy-observer-'+[guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $BuildRoot){throw 'Use a fresh external observer output root'}
if(-not $QemuRoot.StartsWith('/')){throw 'Explicit existing absolute QemuRoot required; never provisions'}
if(-not [IO.Path]::IsPathRooted($Python)){$Python=(Get-Command $Python -CommandType Application -ErrorAction Stop).Source}
$Python=(Resolve-Path -LiteralPath $Python).Path
if((Get-Item -LiteralPath $Python).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Use an actual Python executable, not an activation alias'}
$oldPath=$env:PYTHONPATH;$oldBytecode=$env:PYTHONDONTWRITEBYTECODE;$oldOptimize=$env:PYTHONOPTIMIZE
try{
    $env:PYTHONDONTWRITEBYTECODE='1';$env:PYTHONOPTIMIZE=$null
    if($PythonModules){$env:PYTHONPATH=$PythonModules}
    & $Python '-B' (Join-Path $repo 'tools/fixtures/classic_cm4_mpu_lazy_observer/run.py') `
        '--repo' $repo '--gcc' $ArmGcc '--pilot-receipt' $PilotReceipt '--build-root' $BuildRoot `
        '--qemu-root' $QemuRoot '--wsl-distro' $WslDistro
    if($LASTEXITCODE -ne 0){throw ('Lazy observer failed; preserve '+$BuildRoot)}
    $receipt=Join-Path $BuildRoot 'evidence/results.json'
    $hash=(Get-FileHash -LiteralPath $receipt).Hash
    $r=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    if($r.Verdict -cne 'LAZY-OBSERVER-PASS' -or $r.Execution -cne 'BOUNDED_LAZY_OBSERVER' -or
       $null -eq $r.PSObject.Properties['Error'] -or $null -ne $r.Error){throw 'Wrong observer verdict/error'}
    foreach($pair in @(@('CompleteSuite',$false),@('RequestedInventoryComplete',$true),
        @('NoCompilation',$true),@('TargetElfModified',$false),@('ReferenceExecuted',$false),
        @('NewFinalReferenceParity',$false),@('HardwareValidated',$false),@('PreSaveLspactObserved',$true),
        @('ArtifactsVerifiedBeforePass',$true),@('QemuIdentityMatchesPilot',$true))){
        $p=$r.PSObject.Properties[$pair[0]]
        if($null -eq $p -or $p.Value -isnot [bool] -or $p.Value -ne $pair[1]){throw ('Invalid observer '+$pair[0])}
    }
    foreach($pair in @(@('CompilerInvocations',0),@('Executions',4),@('PairedSaves',88),
        @('ExtendedPairs',60),@('BasicPairs',28),@('Snapshots',176))){
        $p=$r.PSObject.Properties[$pair[0]]
        if($null -eq $p -or $p.Value -isnot [int] -or $p.Value -ne $pair[1]){throw ('Invalid observer '+$pair[0])}
    }
    if($r.Rows -isnot [array] -or $r.Rows.Count -ne 4 -or
       $r.InputDrift -isnot [array] -or $r.InputDrift.Count -ne 0 -or
       $r.QemuDrift -isnot [array] -or $r.QemuDrift.Count -ne 0){throw 'Observer inventory/drift'}
    $i=0
    foreach($consumer in @('context','fiber')){foreach($lazy in @($false,$true)){
        $row=$r.Rows[$i];$i++
        if($row.Consumer -cne $consumer -or $row.Lazy -isnot [bool] -or $row.Lazy -ne $lazy -or
           $row.Status -cne 'PASS' -or $row.Executed -isnot [bool] -or -not $row.Executed -or
           $row.ElfSha256 -cnotmatch '^[0-9A-F]{64}$' -or $row.TraceSha256 -cnotmatch '^[0-9A-F]{64}$' -or
           (Get-FileHash -LiteralPath $row.Elf).Hash -cne $row.ElfSha256 -or
           (Get-FileHash -LiteralPath $row.Trace).Hash -cne $row.TraceSha256){throw 'Observer row identity'}
    }}
    $manifest=Get-Content -LiteralPath (Join-Path $BuildRoot 'evidence/artifacts.json') -Raw | ConvertFrom-Json
    if($manifest.ResultsSha256 -cne $hash){throw 'Observer manifest/receipt binding'}
    $root=(Resolve-Path -LiteralPath (Join-Path $BuildRoot 'evidence')).Path
    $actual=@(Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object {$_.FullName -cne (Join-Path $root 'artifacts.json')})
    if($actual.Count -ne @($manifest.Artifacts.PSObject.Properties).Count){throw 'Observer artifact inventory'}
    foreach($file in $actual){
        $relative=$file.FullName.Substring($root.Length+1).Replace('\','/')
        $property=$manifest.Artifacts.PSObject.Properties[$relative]
        if($null -eq $property -or (Get-FileHash -LiteralPath $file.FullName).Hash -cne $property.Value){throw 'Observer artifact bytes'}
    }
    if((Get-FileHash -LiteralPath $receipt).Hash -cne $hash){throw 'Observer receipt changed during check'}
    Write-Output ('CM4_MPU_LAZY_OBSERVER_PASS '+$receipt)
}finally{
    $env:PYTHONPATH=$oldPath;$env:PYTHONDONTWRITEBYTECODE=$oldBytecode;$env:PYTHONOPTIMIZE=$oldOptimize
}
