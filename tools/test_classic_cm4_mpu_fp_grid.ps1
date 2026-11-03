[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ArmGcc,
    [Parameter(Mandatory=$true)][string]$CmsisCore,
    [Parameter(Mandatory=$true)][string]$FreeRtosRoot,
    [string]$BuildRoot,
    [string]$Python='python',
    [string]$PythonModules=$env:FIBER_CLASSIC_AUDIT_PYTHONPATH,
    [string]$QemuRoot,
    [string]$WslDistro='Ubuntu-24.04',
    [switch]$ExecuteGrid
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0

# Base types only; the captured evidence checker below is mandatory for admission.
function Assert-Cm4MpuFpGridReceipt {
    param([object]$Receipt,[object]$Execute)
    function Need([bool]$OK,[string]$Why){if(-not $OK){throw ('CM4 MPU FP grid receipt: '+$Why)}}
    Need ($Receipt -is [pscustomobject] -and $Execute -is [bool]) 'typed receipt/request'
    Need ($null -ne $Receipt.PSObject.Properties['Error'] -and $null -eq $Receipt.Error) 'null Error required'
    $verdict=if($Execute){'FP-GRID-PASS'}else{'COMPILE-PREFLIGHT-PASS'}
    $mode=if($Execute){'BOUNDED_FP_GRID'}else{'NOT_RUN'}
    Need ($Receipt.Verdict -is [string] -and $Receipt.Verdict -ceq $verdict -and
          $Receipt.Execution -is [string] -and $Receipt.Execution -ceq $mode) 'request-bound mode'
    foreach($pair in @(@('CompleteSuite',$false),@('RequestedInventoryComplete',$true),
        @('CompileOnly',(-not $Execute)),@('ArtifactsVerifiedBeforePass',$true),@('ReferenceExecuted',$false),
        @('NewFinalReferenceParity',$false),@('PreSaveLspactObserved',$false))){
        $p=$Receipt.PSObject.Properties[$pair[0]]
        Need ($null -ne $p -and $p.Value -is [bool] -and $p.Value -eq $pair[1]) $pair[0]
    }
    foreach($pair in @(@('Rows',32),@('Controls',20),@('References',8),@('Associations',32))){
        $p=$Receipt.PSObject.Properties[$pair[0]]
        Need ($null -ne $p -and $p.Value -is [array] -and $p.Value.Count -eq $pair[1]) ($pair[0]+' inventory')
    }
    Need ($Receipt.InputDrift -is [array] -and $Receipt.InputDrift.Count -eq 0) 'input drift'
}

$repo=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if(-not $BuildRoot){$BuildRoot=Join-Path $env:TEMP ('cm4-mpu-fp-grid-'+[guid]::NewGuid().ToString('N'))}
$BuildRoot=[IO.Path]::GetFullPath($BuildRoot)
if((Test-Path -LiteralPath $BuildRoot) -or $BuildRoot -ieq $repo -or
    $BuildRoot.StartsWith($repo+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Use a fresh external output root'}
if($ExecuteGrid -and (-not $QemuRoot -or -not $QemuRoot.StartsWith('/') -or -not $WslDistro)){
    throw 'Execution requires an explicit existing absolute QemuRoot and WSL distro'
}
if(-not [IO.Path]::IsPathRooted($Python)){$Python=(Get-Command $Python -CommandType Application -ErrorAction Stop).Source}
$Python=(Resolve-Path -LiteralPath $Python).Path
if((Get-Item -LiteralPath $Python).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Use an actual Python executable, not an activation alias'}
$oldPath=$env:PYTHONPATH;$oldBytecode=$env:PYTHONDONTWRITEBYTECODE;$oldOptimize=$env:PYTHONOPTIMIZE
try{
    $env:PYTHONDONTWRITEBYTECODE='1';$env:PYTHONOPTIMIZE=$null
    if($PythonModules){$env:PYTHONPATH=$PythonModules}
    $arguments=@('-B',(Join-Path $repo 'tools/fixtures/classic_cm4_mpu_fp_grid/run.py'),
        '--repo',$repo,'--gcc',(Resolve-Path -LiteralPath $ArmGcc).Path,
        '--cmsis',(Resolve-Path -LiteralPath $CmsisCore).Path,
        '--freertos',(Resolve-Path -LiteralPath $FreeRtosRoot).Path,'--build-root',$BuildRoot)
    if($ExecuteGrid){$arguments+=@('--execute-grid','--qemu-root',$QemuRoot,'--wsl-distro',$WslDistro)}
    else{$arguments+='--compile-only'}
    & $Python @arguments
    if($LASTEXITCODE -ne 0){throw ('FP grid failed; preserve '+$BuildRoot)}
    $receipt=Join-Path $BuildRoot 'evidence/results.json'
    $before=(Get-FileHash -LiteralPath $receipt -Algorithm SHA256).Hash
    $parsed=Get-Content -LiteralPath $receipt -Raw|ConvertFrom-Json
    Assert-Cm4MpuFpGridReceipt -Receipt $parsed -Execute ([bool]$ExecuteGrid)
    $checker=(Resolve-Path -LiteralPath (Join-Path $BuildRoot 'source/tools/fixtures/classic_cm4_mpu_fp_grid/check_receipt.ps1')).Path
    $capturePath=(Resolve-Path -LiteralPath (Join-Path $BuildRoot 'capture.json')).Path
    $captureHash=(Get-FileHash -LiteralPath $capturePath -Algorithm SHA256).Hash
    $capture=Get-Content -LiteralPath $capturePath -Raw|ConvertFrom-Json
    $checkerRows=@($capture.Files|Where-Object{$_.Captured -ceq $checker})
    if($checkerRows.Count -ne 1 -or $checkerRows[0].Sha256 -isnot [string] -or
        $checkerRows[0].Sha256 -cnotmatch '^[0-9A-F]{64}$' -or
        (Get-FileHash -LiteralPath $checker -Algorithm SHA256).Hash -cne $checkerRows[0].Sha256){
        throw 'Uncaptured/drifting receipt checker'
    }
    if($parsed.CaptureManifest -cne $capturePath -or $parsed.SourceIdentity.Manifest -cne $capturePath -or
        $parsed.SourceIdentity.ManifestSha256 -cne $captureHash){throw 'Receipt/capture manifest binding mismatch'}
    . $checker
    Assert-Cm4MpuFpGridEvidence -Receipt $parsed -Execute ([bool]$ExecuteGrid) -BuildRoot (Split-Path -Parent $receipt)
    if((Get-FileHash -LiteralPath $receipt -Algorithm SHA256).Hash -cne $before -or
        (Get-FileHash -LiteralPath $capturePath -Algorithm SHA256).Hash -cne $captureHash -or
        (Get-FileHash -LiteralPath $checker -Algorithm SHA256).Hash -cne $checkerRows[0].Sha256){
        throw 'Receipt/capture/checker changed while checking'
    }
    Write-Output ('CM4_MPU_FP_GRID_PASS '+$receipt)
}finally{
    $env:PYTHONPATH=$oldPath;$env:PYTHONDONTWRITEBYTECODE=$oldBytecode;$env:PYTHONOPTIMIZE=$oldOptimize
}
