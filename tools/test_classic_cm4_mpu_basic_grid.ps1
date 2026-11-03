[CmdletBinding(DefaultParameterSetName='Run')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Run')][string]$ArmGcc,
    [Parameter(Mandatory=$true,ParameterSetName='Run')][string]$CmsisCore,
    [Parameter(Mandatory=$true,ParameterSetName='Run')][string]$FreeRtosRoot,
    [Parameter(ParameterSetName='Run')][string]$QemuRoot,
    [Parameter(ParameterSetName='Run')][string]$WslDistro='Ubuntu-24.04',
    [Parameter(ParameterSetName='Run')][string]$BuildRoot,
    [Parameter(ParameterSetName='Run')][string]$Python='python',
    [Parameter(ParameterSetName='Run')][string]$PythonModules=$env:FIBER_CLASSIC_AUDIT_PYTHONPATH,
    [Parameter(ParameterSetName='Run')][switch]$ExecuteGrid,
    [Parameter(Mandatory=$true,ParameterSetName='Controls')][string]$ContractControls,
    [Parameter(Mandatory=$true,ParameterSetName='Controls')][string]$ContractControlsOutput
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0

function Assert-Cm4MpuBasicGridReceipt {
    param([object]$Receipt,[bool]$Execute)
    function Need([bool]$OK,[string]$Message) { if(-not $OK){throw ('CM4 MPU basic-grid receipt: '+$Message)} }
    function IsSha([object]$Value) { return ($Value -is [string] -and $Value -cmatch '^[0-9A-F]{64}$') }
    function IsKey([object]$R,[string]$C,[int]$Case,[string]$Opt,[bool]$Lto,[bool]$Archive) {
        return ($R -is [pscustomobject] -and $R.Consumer -is [string] -and $R.Consumer -ceq $C -and
            $R.Case -is [int] -and $R.Case -eq $Case -and $R.Optimization -is [string] -and $R.Optimization -ceq $Opt -and
            $R.LTO -is [bool] -and $R.LTO -eq $Lto -and $R.Archive -is [bool] -and $R.Archive -eq $Archive)
    }
    function IsRefKey([object]$R,[string]$Opt,[bool]$Lto,[bool]$Archive) {
        return ($R -is [pscustomobject] -and $R.Optimization -is [string] -and $R.Optimization -ceq $Opt -and
            $R.LTO -is [bool] -and $R.LTO -eq $Lto -and $R.Archive -is [bool] -and $R.Archive -eq $Archive)
    }
    function CheckActual([object]$Actual) {
        Need ($Actual -is [pscustomobject] -and $Actual.Exit -is [int] -and $Actual.Exit -eq 0 -and
            $Actual.TimedOut -is [bool] -and -not $Actual.TimedOut -and $Actual.Stdout -is [string] -and
            $Actual.Stdout -ceq '' -and $Actual.Stderr -is [string]) 'actual types/channel/exit'
    }
    function CheckFrame([string]$PSP,[string]$XPSR) {
        $sp=[Convert]::ToUInt32($PSP,16);$x=[Convert]::ToUInt32($XPSR,16)
        $bytes=32;if($x -band 0x200){$bytes+=4}
        Need (($sp % 8) -eq 0 -and $sp -ge 0x20002000 -and $sp -le (0x20003000-$bytes) -and
            ($x -band 0x010001FF) -eq 0x01000000) 'complete basic frame/T/IPSR/padding'
    }
    $verdict=if($Execute){'BASIC-GRID-PASS'}else{'COMPILE-PREFLIGHT-PASS'}
    $execution=if($Execute){'BOUNDED_BASIC_GRID'}else{'NOT_RUN'}
    Need ($Receipt -is [pscustomobject] -and $Receipt.Verdict -is [string] -and $Receipt.Verdict -ceq $verdict -and
        $Receipt.Execution -is [string] -and $Receipt.Execution -ceq $execution) 'request-bound verdict/execution'
    Need ($null -ne $Receipt.PSObject.Properties['Error'] -and $null -eq $Receipt.Error) 'non-null error'
    foreach($pair in @(@('CompleteSuite',$Execute),@('CompileOnly',(-not $Execute)),@('ArtifactsVerifiedBeforePass',$true),@('ReferenceExecuted',$false),@('NewFinalReferenceParity',$false))) {
        $property=$Receipt.PSObject.Properties[$pair[0]]
        Need ($null -ne $property -and $property.Value -is [bool] -and $property.Value -eq $pair[1]) $pair[0]
    }
    Need ($Receipt.InputDrift -is [array] -and $Receipt.InputDrift.Count -eq 0) 'input drift'
    foreach($pair in @(@('Rows',48),@('References',8),@('Associations',48),@('CompiledControls',32),@('ReferenceControls',8))) {
        $p=$Receipt.PSObject.Properties[$pair[0]]
        Need ($null -ne $p -and $p.Value -is [array] -and $p.Value.Count -eq $pair[1]) ($pair[0]+' count')
    }
    $modes=@(@('O2',$false),@('O2',$true),@('Os',$false),@('Os',$true))
    $refs=@{};$ri=0
    foreach($mode in $modes){foreach($archive in @($false,$true)){
        $r=$Receipt.References[$ri];$ri++
        Need (IsRefKey $r $mode[0] $mode[1] $archive) 'ordered reference key'
        Need ($r.Status -ceq 'LINKED' -and $r.Executed -is [bool] -and -not $r.Executed -and
            $r.Elf -is [string] -and (IsSha $r.ElfSha256)) 'reference state'
        $refs[($mode[0]+':'+$mode[1]+':'+$archive)]=$r
    }}
    $i=0
    foreach($consumer in @('context','fiber')){foreach($mode in $modes){foreach($archive in @($false,$true)){foreach($case in @(0,1,2)){
        $row=$Receipt.Rows[$i];$a=$Receipt.Associations[$i];$i++
        Need (IsKey $row $consumer $case $mode[0] $mode[1] $archive) 'ordered production key'
        Need ($row.Elf -is [string] -and (IsSha $row.ElfSha256)) 'production ELF identity'
        $reference=$refs[($mode[0]+':'+$mode[1]+':'+$archive)]
        Need ((IsKey $a $consumer $case $mode[0] $mode[1] $archive) -and $a.Status -ceq 'PASS' -and
            $a.Executed -is [bool] -and -not $a.Executed -and $a.Checks -is [int] -and $a.Checks -eq 3 -and
            (IsSha $a.BlockSha256) -and (IsSha $a.MechanismEvidenceSha256) -and
            $a.SubjectElf -ceq $row.Elf -and $a.SubjectSha256 -ceq $row.ElfSha256 -and
            $a.ReferenceElf -ceq $reference.Elf -and $a.ReferenceSha256 -ceq $reference.ElfSha256) 'hash-bound association'
    }}}}
    $subjectMutants=@('no-save-r4','no-save-r9','no-svc71','no-slot-store','no-peer-load','no-oracle-r9',
        'no-sp-compare','no-sp-reject','no-cookie12-compare','no-cookie12-reject','no-cookie16-compare','no-cookie16-reject',
        'no-control-compare','no-control-reject','no-ipsr-compare','no-ipsr-reject')
    $subjectReasons=@('PENDSV_RAW_SAVE_TRANSFER','PENDSV_RAW_SAVE_TRANSFER','SVC71_OPCODE','FAULT_SLOT_OPCODE','FAULT_PEER_OPCODE','GPR_COMPARE_R9',
        'SP_EXACT_CHECK','SP_EXACT_CHECK','COOKIE12_EXACT_CHECK','COOKIE12_EXACT_CHECK','COOKIE16_EXACT_CHECK','COOKIE16_EXACT_CHECK',
        'CONTROL3_EXACT_CHECK','CONTROL3_EXACT_CHECK','IPSR0_EXACT_CHECK','IPSR0_EXACT_CHECK')
    $i=0
    foreach($tuple in @(@('context','O2',$false,$false),@('fiber','Os',$true,$true))){for($j=0;$j -lt 16;$j++){
        $row=$Receipt.CompiledControls[$i];$i++
        $case=0;if($subjectMutants[$j] -ceq 'no-slot-store'){$case=1};if($subjectMutants[$j] -ceq 'no-peer-load'){$case=2}
        Need ((IsKey $row $tuple[0] $case $tuple[1] $tuple[2] $tuple[3]) -and $row.Mutation -ceq $subjectMutants[$j] -and
            $row.Status -ceq 'CODEGEN_CONTROL_REJECTED' -and $row.Executed -is [bool] -and -not $row.Executed -and
            (IsSha $row.ElfSha256) -and $row.ExpectedCodegenRejection -ceq $subjectReasons[$j] -and
            $row.ActualCodegenRejection -ceq $subjectReasons[$j]) 'compiled subject control'
    }}
    $mutants=@('first-psp','raw-control','scheduler-mask','first-copy')
    $reasons=@('REF_FIRST_PSP','REF_RAW_CONTROL_BEFORE_FP','REF_BASEPRI_SCHEDULER','REF_FIRST_MPU_MAP')
    $i=0
    foreach($tuple in @(@('O2',$false,$false),@('Os',$true,$true))){for($j=0;$j -lt 4;$j++){
        $r=$Receipt.ReferenceControls[$i];$i++
        Need ((IsRefKey $r $tuple[0] $tuple[1] $tuple[2]) -and $r.Mutation -ceq $mutants[$j] -and
            $r.Status -ceq 'REJECTED' -and $r.Executed -is [bool] -and -not $r.Executed -and (IsSha $r.ElfSha256) -and
            $r.ExpectedCodegenRejection -ceq $reasons[$j] -and $r.ActualCodegenRejection -ceq $reasons[$j]) 'compiled reference control'
    }}
    $model=$Receipt.ModelProbe
    Need ((IsKey $model 'context' 0 'O2' $false $false) -and $model.Name -ceq 'model') 'model identity'
    Need ($model.Elf -is [string] -and -not [string]::IsNullOrWhiteSpace($model.Elf) -and
        (IsSha $model.ElfSha256)) 'model ELF identity'
    $binding=$Receipt.ModelArtifactBinding
    Need ($binding -is [pscustomobject] -and $binding.Verified -is [bool] -and $binding.Verified -eq $true -and
        $binding.ArtifactRelative -ceq 'model/runtime.elf' -and $binding.Elf -is [string] -and
        $binding.Elf -ceq $model.Elf -and (IsSha $binding.ElfSha256) -and (IsSha $binding.ManifestEntrySha256) -and
        $binding.ElfSha256 -ceq $model.ElfSha256 -and $binding.ManifestEntrySha256 -ceq $model.ElfSha256) 'model artifact binding'
    foreach($row in @($model)+$Receipt.Rows){
        $status=if($Execute){'PASS'}else{'COMPILED'}
        Need ($row.Status -is [string] -and $row.Status -ceq $status -and $row.Executed -is [bool] -and $row.Executed -eq $Execute) 'row execution state'
        if(-not $Execute){Need ($null -eq $row.PSObject.Properties['Actual']) 'compile row contains Actual';continue}
        CheckActual $row.Actual
        $text=$row.Actual.Stderr
        if($row -eq $model){
            $pattern='\AMODEL:CM4-MPU:CPUID=([0-9A-F]{8}):MPU_TYPE=([0-9A-F]{8}):NVIC_MASK=([0-9A-F]{8}):MVFR0=([0-9A-F]{8}):MPU_CTRL=([0-9A-F]{8})\r?\nPASS:CM4-MPU:MODEL\r?\n\z'
            $m=[regex]::Match($text,$pattern);Need $m.Success 'exact model terminal'
            $fields=@('CPUID','MPU_TYPE','NVIC_MASK','MVFR0','MPU_CTRL');$v=@()
            Need ($Receipt.ObservedModel -is [pscustomobject] -and @(Compare-Object -CaseSensitive $fields @($Receipt.ObservedModel.PSObject.Properties.Name)).Count -eq 0) 'observed model fields'
            for($j=0;$j -lt 5;$j++){
                $v += [Convert]::ToUInt32($m.Groups[$j+1].Value,16)
                Need ($Receipt.ObservedModel.($fields[$j]) -is [int] -and $Receipt.ObservedModel.($fields[$j]) -eq $v[$j]) 'observed model value/type'
            }
            Need (($v[0] -band 0xFF0FFFF0) -eq 0x410FC240 -and $v[1] -eq 0x800 -and $v[2] -eq 255 -and ($v[3] -band 0xFFF) -eq 0x21 -and $v[4] -eq 0) 'model facts'
            continue
        }
        $label=if($row.Consumer -ceq 'context'){'CONTEXT'}else{'FIBERV1'}
        if($row.Case -eq 0){
            $pattern='\ARETURN:CM4-MPU:CODE=00000052:IPSR=0000000B:PC=([0-9A-F]{8}):PSP=([0-9A-F]{8}):XPSR=([0-9A-F]{8}):CALLS=00000020:SELF=00000001:CROSS=0000001E\r?\nSTRESS:CM4-MPU:R4-R11=0000000F:SP=0000000F:COOKIES=0000001E:PUBLIC=00000010:DIRECT=0000000F\r?\nPASS:CM4-MPU:'+$label+'\r?\n\z'
            $m=[regex]::Match($text,$pattern);Need $m.Success 'exact return/stress terminal'
            Need ([Convert]::ToUInt32($m.Groups[1].Value,16) -eq $row.Audit.Addresses.return) 'exact return PC'
            CheckFrame $m.Groups[2].Value $m.Groups[3].Value
        }else{
            $pattern='\AFAULT:CM4-MPU:IPSR=00000004:EXC=FFFFFFFD:CFSR=00000082:HFSR=00000000:MMFAR=([0-9A-F]{8}):PC=([0-9A-F]{8}):PSP=([0-9A-F]{8}):XPSR=([0-9A-F]{8})\r?\nPASS:CM4-MPU:'+$label+'\r?\n\z'
            $m=[regex]::Match($text,$pattern);Need $m.Success 'exact MemManage terminal'
            $address=if($row.Case -eq 1){0x20000000}else{0x20004080}
            $pc=if($row.Case -eq 1){$row.Audit.Addresses.slot}else{$row.Audit.Addresses.peer}
            Need ([Convert]::ToUInt32($m.Groups[1].Value,16) -eq $address -and [Convert]::ToUInt32($m.Groups[2].Value,16) -eq $pc) 'exact MMFAR/fault PC'
            CheckFrame $m.Groups[3].Value $m.Groups[4].Value
        }
    }
    if(-not $Execute){Need ($null -eq $Receipt.PSObject.Properties['ObservedModel']) 'compile receipt contains model observation'}
}

function Test-Cm4MpuBasicGridClosingControls {
    param([object]$Report)
    $names=@()
    $suffixes=@('missing-row','duplicate-row','wrong-order','case-bool','lto-int','row-status','row-executed-type',
        'missing-model','missing-ref','ref-key','ref-executed','assoc-hash','assoc-case','assoc-check-bool','subject-control-reason','reference-control-reason')
    foreach($prefix in @('compile-','execute-')){
        $execute=$prefix -ceq 'execute-';$bool=if($execute){'False'}else{'True'};$integer=if($execute){'1'}else{'0'}
        $names+=($prefix+'positive'),($prefix+'Verdict-True'),($prefix+"Execution-'PASS'"),($prefix+'CompleteSuite-'+$bool),
            ($prefix+'CompleteSuite-'+$integer),($prefix+'ArtifactsVerifiedBeforePass-False'),($prefix+"InputDrift-['changed']")
        foreach($suffix in $suffixes){$names+=($prefix+$suffix)}
        if($execute){for($i=0;$i -lt 48;$i++){$names+=($prefix+'skipped-'+$i)};foreach($s in @('model-skipped','bool-exit','split-channel','timeout','wrong-model')){$names+=($prefix+$s)}}
        else{$names+=($prefix+'invented-observation')}
    }
    if($names.Count -ne 100){throw 'Original 100 closing IDs changed'}
    $added=@('error-empty','error-zero','error-false','error-text','error-missing',
        'model-missing-elf','model-missing-hash','model-missing-identity','model-elf-bool','model-elf-empty',
        'model-hash-bool','model-hash-empty','model-hash-malformed','model-binding-missing','model-binding-hash','model-binding-verified-type')
    foreach($prefix in @('compile-','execute-')){foreach($suffix in $added){$names+=($prefix+$suffix)}}
    if($names.Count -ne 132 -or !($Report.Controls -is [array]) -or $Report.Controls.Count -ne 132){throw 'Literal 132 closing controls required'}
    for($i=0;$i -lt 132;$i++){
        $c=$Report.Controls[$i];$execute=$names[$i].StartsWith('execute-',[StringComparison]::Ordinal)
        $expected=$names[$i] -cin @('compile-positive','execute-positive')
        if($c.Name -cne $names[$i] -or !($c.Execute -is [bool]) -or $c.Execute -ne $execute -or !($c.Expected -is [bool]) -or $c.Expected -ne $expected){throw 'Closing control inventory/type mismatch'}
        $accepted=$true
        try { Assert-Cm4MpuBasicGridReceipt $c.Receipt $execute } catch { $accepted=$false }
        if($accepted -ne $expected){throw ('PowerShell closing control failed: '+$c.Name)}
    }
}

function Assert-Cm4MpuBasicGridFinalizerControls {
    param([object]$Controls)
    function Need([bool]$OK,[string]$Why){if(-not $OK){throw ('Actual-finalizer controls: '+$Why)}}
    $names=@('positive','first-manifest','final-manifest','prior-error','empty-error','zero-error','false-error','empty-exception','model-artifact-hash','model-artifact-path')
    $errors=@($null,'finalizer: SYNTHETIC_MANIFEST_FAILURE_1','finalizer: SYNTHETIC_MANIFEST_FAILURE_2',
        'SYNTHETIC_RUN_FAILURE','',0,$false,'RuntimeError: ','finalizer: model-artifact-hash','finalizer: model-artifact-path')
    Need ($Controls -is [array] -and $Controls.Count -eq 10) 'literal ten controls'
    for($i=0;$i -lt 10;$i++){
        $c=$Controls[$i];$expected=$i -eq 0
        $verdict=if($expected){'COMPILE-PREFLIGHT-PASS'}else{'FAIL'}
        Need ($c -is [pscustomobject] -and $c.Name -is [string] -and $c.Name -ceq $names[$i] -and
            $c.Accepted -is [bool] -and $c.Accepted -eq $expected -and
            $c.PersistedVerdict -is [string] -and $c.PersistedVerdict -ceq $verdict) 'identity/typed outcome'
        Need ($null -ne $c.PSObject.Properties['Error']) 'missing Error'
        if($null -eq $errors[$i]){Need ($null -eq $c.Error) 'positive Error'}
        elseif($errors[$i] -is [bool]){Need ($c.Error -is [bool] -and $c.Error -eq $errors[$i]) 'boolean Error'}
        elseif($errors[$i] -is [int]){Need ($c.Error -is [int] -and $c.Error -eq $errors[$i]) 'integer Error'}
        else{Need ($c.Error -is [string] -and $c.Error -ceq $errors[$i]) 'string Error'}
        $calls=,@($true,'FAIL',$false)
        if($i -eq 0){$calls+=,@($true,'COMPILE-PREFLIGHT-PASS',$true)}
        elseif($i -eq 2){$calls+=,@($true,'COMPILE-PREFLIGHT-PASS',$true);$calls+=,@($false,'FAIL',$false)}
        elseif($i -in @(1,8,9)){$calls+=,@($false,'FAIL',$false)}
        Need ($c.Calls -is [array] -and $c.Calls.Count -eq $calls.Count) 'call count'
        for($j=0;$j -lt $calls.Count;$j++){
            $call=$c.Calls[$j];$shape=$calls[$j]
            Need ($call -is [pscustomobject] -and
                $call.Verify -is [bool] -and $call.Verify -eq $shape[0] -and
                $call.Verdict -is [string] -and $call.Verdict -ceq $shape[1] -and
                $call.ArtifactsVerifiedBeforePass -is [bool] -and $call.ArtifactsVerifiedBeforePass -eq $shape[2]) 'typed call state'
        }
    }
}

function Test-Cm4MpuBasicGridFinalizerAssertions {
    param([object]$Controls)
    function Clone([object]$Value){return ,(ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 20))}
    $results=New-Object 'System.Collections.Generic.List[object]'
    function RecordCase([string]$Name,[object]$Value,[bool]$Expected){
        $accepted=$true
        try{Assert-Cm4MpuBasicGridFinalizerControls $Value}catch{$accepted=$false}
        if($accepted -ne $Expected){throw ('Actual PowerShell finalizer assertion control failed: '+$Name)}
        $results.Add([ordered]@{Name=$Name;Expected=$Expected;Accepted=$accepted})
    }
    RecordCase 'positive' $Controls $true
    for($i=0;$i -lt 10;$i++){
        $copy=Clone $Controls;$copy[$i].Calls[0].ArtifactsVerifiedBeforePass='False'
        RecordCase ('call0-artifacts-string-'+$i) $copy $false
    }
    for($i=0;$i -lt 10;$i++){
        $copy=Clone $Controls;$copy[$i].Calls[0].Verify=1
        RecordCase ('call0-verify-int-'+$i) $copy $false
    }
    $copy=Clone $Controls;$copy[0].Calls[1].ArtifactsVerifiedBeforePass=1
    RecordCase 'positive-final-artifacts-int' $copy $false
    $copy=Clone $Controls;$copy[2].Calls[2].ArtifactsVerifiedBeforePass='False'
    RecordCase 'recovery-artifacts-string' $copy $false
    $copy=Clone $Controls;$copy[5].Error=$false
    RecordCase 'zero-error-bool' $copy $false
    $copy=Clone $Controls;$copy[6].Error=0
    RecordCase 'false-error-int' $copy $false
    if($results.Count -ne 25 -or @($results|Where-Object{$_.Accepted}).Count -ne 1){throw 'Literal 25 PowerShell finalizer assertion controls'}
    return [ordered]@{Controls=@($results.ToArray());Scope='Mutations passed through actual shared Assert-Cm4MpuBasicGridFinalizerControls; synthetic orchestration only'}
}

if($PSCmdlet.ParameterSetName -ceq 'Controls'){
    $payload=Get-Content -LiteralPath $ContractControls -Raw|ConvertFrom-Json
    Test-Cm4MpuBasicGridClosingControls $payload.ClosingContractControls
    Assert-Cm4MpuBasicGridFinalizerControls $payload.FinalizerControls.Controls
    Test-Cm4MpuBasicGridFinalizerAssertions $payload.FinalizerControls.Controls |
        ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ContractControlsOutput -Encoding ascii
    Write-Output 'CM4_MPU_BASIC_GRID_CONTRACT_CONTROLS_PASS'
    return
}
$repo=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if(-not $BuildRoot){$BuildRoot=Join-Path $env:TEMP ('classic-cm4-mpu-basic-grid-'+[guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $BuildRoot){throw 'Use a fresh evidence directory'}
if($ExecuteGrid -and (-not $QemuRoot -or -not $QemuRoot.StartsWith('/'))){throw 'Execution requires an explicit existing absolute WSL QemuRoot'}
$arguments=@('-B',(Join-Path $PSScriptRoot 'fixtures/classic_cm4_mpu_basic_grid/run.py'),'--repo',$repo,
    '--gcc',(Resolve-Path -LiteralPath $ArmGcc).Path,'--cmsis',(Resolve-Path -LiteralPath $CmsisCore).Path,
    '--freertos',(Resolve-Path -LiteralPath $FreeRtosRoot).Path,'--build-root',$BuildRoot)
if($ExecuteGrid){$arguments+=@('--execute-grid','--qemu-root',$QemuRoot,'--wsl-distro',$WslDistro)}else{$arguments+='--compile-only'}
$old=$env:PYTHONPATH
try {
    if(-not $PythonModules){$PythonModules=Join-Path $env:TEMP 'fiber-classic-audit-python'}
    if(-not(Test-Path -LiteralPath $PythonModules -PathType Container)){throw 'Existing pyelftools 0.33 required; no provisioning'}
    $env:PYTHONPATH=$PythonModules+[IO.Path]::PathSeparator+$old
    & $Python @arguments
    if($LASTEXITCODE -ne 0){throw ('Basic grid failed; preserve '+$BuildRoot)}
    $evidence=Join-Path $BuildRoot 'evidence'
    $receipt=Join-Path $evidence 'results.json'
    $r=Get-Content -LiteralPath $receipt -Raw|ConvertFrom-Json
    Assert-Cm4MpuBasicGridReceipt $r $ExecuteGrid.IsPresent
    Test-Cm4MpuBasicGridClosingControls $r.ClosingContractControls
    Assert-Cm4MpuBasicGridFinalizerControls $r.FinalizerControls.Controls
    $psFinalizer=Test-Cm4MpuBasicGridFinalizerAssertions $r.FinalizerControls.Controls
    if((ConvertTo-Json -InputObject $psFinalizer -Depth 10 -Compress) -cne
        (ConvertTo-Json -InputObject $r.PowerShellFinalizerControls -Depth 10 -Compress)){throw 'PowerShell actual-assertion control receipt differs'}
    $manifest=Get-Content -LiteralPath (Join-Path $evidence 'artifacts.json') -Raw|ConvertFrom-Json
    if($manifest.ResultsSha256 -cne (Get-FileHash -LiteralPath $receipt -Algorithm SHA256).Hash){throw 'Stale results manifest'}
    foreach($entry in $manifest.Artifacts.PSObject.Properties){
        $path=[IO.Path]::GetFullPath((Join-Path $evidence $entry.Name))
        if(-not $path.StartsWith(([IO.Path]::GetFullPath($evidence)+[IO.Path]::DirectorySeparatorChar),[StringComparison]::OrdinalIgnoreCase) -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $entry.Value){throw 'Artifact path/hash mismatch'}
    }
    $modelPath=[IO.Path]::GetFullPath((Join-Path $evidence 'model/runtime.elf'))
    if(-not [string]::Equals($modelPath,[IO.Path]::GetFullPath($r.ModelProbe.Elf),[StringComparison]::OrdinalIgnoreCase) -or
        (Get-FileHash -LiteralPath $modelPath -Algorithm SHA256).Hash -cne $r.ModelProbe.ElfSha256 -or
        $manifest.Artifacts.'model/runtime.elf' -cne $r.ModelProbe.ElfSha256){throw 'Actual model artifact binding mismatch'}
    $before=Get-Content -LiteralPath (Join-Path $evidence 'inputs.before.json') -Raw|ConvertFrom-Json
    $after=Get-Content -LiteralPath (Join-Path $evidence 'inputs.after.json') -Raw|ConvertFrom-Json
    if($before.Count -ne $after.Count){throw 'Opening/closing input count mismatch'}
    $closing=@{};foreach($row in $after){$closing[$row.Path]=$row.Sha256}
    foreach($row in $before){if($closing[$row.Path] -cne $row.Sha256 -or (Get-FileHash -LiteralPath $row.Path -Algorithm SHA256).Hash -cne $row.Sha256){throw 'Opening/closing/live input hash mismatch'}}
    Write-Output ($r.Verdict+' '+$receipt)
} finally {$env:PYTHONPATH=$old}
