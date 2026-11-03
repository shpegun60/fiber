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
    [switch]$ExecutePilot
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0

function Assert-Cm4MpuFpPilotReceipt {
    param([object]$Receipt,[bool]$Execute)
    function Need([bool]$OK,[string]$Message) { if(-not $OK){throw ('CM4 MPU FP pilot: '+$Message)} }
    function Sha([object]$Value) {return ($Value -is [string] -and $Value -cmatch '^[0-9A-F]{64}$')}
    Need ($Receipt -is [pscustomobject]) 'object receipt'
    Need ($null -ne $Receipt.PSObject.Properties['Error'] -and $null -eq $Receipt.Error) 'null error required'
    $verdict=if($Execute){'FP-PILOT-PASS'}else{'COMPILE-PREFLIGHT-PASS'}
    $mode=if($Execute){'FP_ACTIVE_PILOT'}else{'NOT_RUN'}
    Need ($Receipt.Verdict -is [string] -and $Receipt.Verdict -ceq $verdict -and
          $Receipt.Execution -is [string] -and $Receipt.Execution -ceq $mode) 'request-bound mode'
    foreach($pair in @(@('CompleteSuite',$false),@('RequestedInventoryComplete',$true),
        @('CompileOnly',(-not $Execute)),@('ArtifactsVerifiedBeforePass',$true),@('ReferenceExecuted',$false),
        @('NewFinalReferenceParity',$false),@('PreSaveLspactObserved',$false))) {
        $p=$Receipt.PSObject.Properties[$pair[0]]
        Need ($null -ne $p -and $p.Value -is [bool] -and $p.Value -eq $pair[1]) $pair[0]
    }
    Need ($Receipt.Rows -is [array] -and $Receipt.Rows.Count -eq 4 -and
          $Receipt.Controls -is [array] -and $Receipt.Controls.Count -eq 10 -and
          $Receipt.References -is [array] -and $Receipt.References.Count -eq 1 -and
          $Receipt.Associations -is [array] -and $Receipt.Associations.Count -eq 4) 'literal pilot inventory'
    Need ($Receipt.InputDrift -is [array] -and $Receipt.InputDrift.Count -eq 0) 'input drift'
    $index=0
    foreach($consumer in @('context','fiber')){foreach($lazy in @($false,$true)){
        $r=$Receipt.Rows[$index];$index++
        Need ($r.Consumer -is [string] -and $r.Consumer -ceq $consumer -and
              $r.Lazy -is [bool] -and $r.Lazy -eq $lazy -and $null -eq $r.Mutation -and
              $r.Model -is [bool] -and -not $r.Model) 'ordered positive keys'
    }}
    $mutations=@('omit-high-save','omit-high-restore','omit-low-save','omit-low-restore','corrupt-fpscr-save')
    $index=0
    foreach($lazy in @($false,$true)){foreach($mutation in $mutations){
        $r=$Receipt.Controls[$index];$index++
        Need ($r.Consumer -ceq 'context' -and $r.Lazy -is [bool] -and $r.Lazy -eq $lazy -and
              $r.Mutation -is [string] -and $r.Mutation -ceq $mutation -and $r.Model -is [bool] -and -not $r.Model) 'ordered control keys'
    }}
    $model=$Receipt.ModelProbe
    Need ($model.Model -is [bool] -and $model.Model -eq $true -and $model.Name -ceq 'model' -and
          $model.Consumer -ceq 'context' -and $model.Lazy -is [bool] -and -not $model.Lazy -and
          $null -eq $model.Mutation) 'model identity'
    foreach($r in @($model)+$Receipt.Rows+$Receipt.Controls){
        Need ($r.Elf -is [string] -and -not [string]::IsNullOrWhiteSpace($r.Elf) -and (Sha $r.ElfSha256) -and
              $r.Optimization -ceq 'O2' -and $r.LTO -is [bool] -and -not $r.LTO -and
              $r.Archive -is [bool] -and -not $r.Archive -and
              $r.Executed -is [bool] -and $r.Executed -eq $Execute) 'row identity/mode'
        $status=if(-not $Execute){'COMPILED'}elseif($null -ne $r.Mutation){'EXPECTED_FP_MISMATCH'}else{'PASS'}
        Need ($r.Status -is [string] -and $r.Status -ceq $status) 'row status'
        if($Execute){
            $exit=if($null -ne $r.Mutation){66}else{0}
            Need ($r.Actual -is [pscustomobject] -and $r.Actual.Exit -is [int] -and $r.Actual.Exit -eq $exit -and
                  $r.Actual.TimedOut -is [bool] -and -not $r.Actual.TimedOut -and
                  $r.Actual.Stdout -is [string] -and $r.Actual.Stdout -ceq '' -and
                  $r.Actual.Stderr -is [string] -and $r.Observed -is [pscustomobject]) 'actual execution types/outcome'
        }else{
            Need ($null -eq $r.PSObject.Properties['Actual'] -and $null -eq $r.PSObject.Properties['Observed']) 'invented execution'
        }
    }
    $reference=$Receipt.References[0]
    Need ($reference.Status -ceq 'LINKED' -and $reference.Executed -is [bool] -and -not $reference.Executed -and
          $reference.Optimization -ceq 'O2' -and $reference.LTO -is [bool] -and -not $reference.LTO -and
          $reference.Archive -is [bool] -and -not $reference.Archive -and (Sha $reference.ElfSha256)) 'link-only reference'
    for($index=0;$index -lt 4;$index++){
        $a=$Receipt.Associations[$index];$r=$Receipt.Rows[$index]
        Need ($a.Consumer -ceq $r.Consumer -and $a.Lazy -is [bool] -and $a.Lazy -eq $r.Lazy -and
              $a.Executed -is [bool] -and -not $a.Executed -and
              $a.SubjectElf -ceq $r.Elf -and $a.SubjectSha256 -ceq $r.ElfSha256 -and
              $a.ReferenceElf -ceq $reference.Elf -and $a.ReferenceSha256 -ceq $reference.ElfSha256 -and
              (Sha $a.EvidenceSha256) -and $a.NamedMechanismResults -is [int] -and $a.NamedMechanismResults -eq 3) 'hash-bound reference association'
    }
}

$repo=Split-Path -Parent $PSScriptRoot
if(-not $BuildRoot){$BuildRoot=Join-Path $env:TEMP ('cm4-mpu-fp-pilot-'+[guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $BuildRoot){throw 'Use a fresh external output root'}
if($ExecutePilot -and (-not $QemuRoot -or -not $QemuRoot.StartsWith('/'))){throw 'Explicit existing absolute QemuRoot required'}
if(-not [IO.Path]::IsPathRooted($Python)){$Python=(Get-Command $Python -CommandType Application -ErrorAction Stop).Source}
$Python=(Resolve-Path -LiteralPath $Python).Path
if((Get-Item -LiteralPath $Python).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Use an actual Python executable, not an activation alias'}
$oldPath=$env:PYTHONPATH;$oldBytecode=$env:PYTHONDONTWRITEBYTECODE;$oldOptimize=$env:PYTHONOPTIMIZE
try{
    $env:PYTHONDONTWRITEBYTECODE='1';$env:PYTHONOPTIMIZE=$null
    if($PythonModules){$env:PYTHONPATH=$PythonModules}
    $arguments=@('-B',(Join-Path $repo 'tools/fixtures/classic_cm4_mpu_fp_pilot/run.py'),
        '--repo',$repo,'--gcc',$ArmGcc,'--cmsis',$CmsisCore,'--freertos',$FreeRtosRoot,'--build-root',$BuildRoot)
    if($ExecutePilot){$arguments+=@('--execute-pilot','--qemu-root',$QemuRoot,'--wsl-distro',$WslDistro)}
    else{$arguments+='--compile-only'}
    & $Python @arguments
    if($LASTEXITCODE -ne 0){throw ('FP pilot failed; preserve '+$BuildRoot)}
    $receipt=Join-Path $BuildRoot 'evidence/results.json'
    $before=(Get-FileHash -LiteralPath $receipt).Hash
    $parsed=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    Assert-Cm4MpuFpPilotReceipt -Receipt $parsed -Execute ([bool]$ExecutePilot)
    $checker=(Resolve-Path -LiteralPath (Join-Path $BuildRoot 'source/tools/fixtures/classic_cm4_mpu_fp_pilot/check_receipt.ps1')).Path
    $capture=Get-Content -LiteralPath (Join-Path $BuildRoot 'capture.json') -Raw | ConvertFrom-Json
    $checkerRows=@($capture.Files | Where-Object {$_.Captured -ceq $checker})
    if($checkerRows.Count -ne 1 -or (Get-FileHash -LiteralPath $checker).Hash -cne $checkerRows[0].Sha256){throw 'Uncaptured/drifting receipt checker'}
    . $checker
    Assert-Cm4MpuFpPilotEvidence -Receipt $parsed -Execute ([bool]$ExecutePilot) -BuildRoot (Split-Path -Parent $receipt)
    if((Get-FileHash -LiteralPath $receipt).Hash -cne $before){throw 'Receipt changed while checking'}
    Write-Output ('CM4_MPU_FP_PILOT_PASS '+$receipt)
}finally{
    $env:PYTHONPATH=$oldPath;$env:PYTHONDONTWRITEBYTECODE=$oldBytecode;$env:PYTHONOPTIMIZE=$oldOptimize
}
