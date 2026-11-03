# Dot-source only. BuildRoot is the evidence directory, not the capture root.
function Assert-Cm4MpuFpGridEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object]$Receipt,
        [Parameter(Mandatory=$true)][object]$Execute,
        [Parameter(Mandatory=$true)][string]$BuildRoot
    )
    $ErrorActionPreference='Stop'
    Set-StrictMode -Version 2.0
    function Need([bool]$OK,[string]$Why){if(-not $OK){throw ('CM4 MPU FP grid evidence: '+$Why)}}
    function Sha([object]$Value){return ($Value -is [string] -and $Value -cmatch '^[0-9A-F]{64}$')}
    function Word([object]$Value){return (($Value -is [int] -or $Value -is [long] -or $Value -is [uint32]) -and $Value -ge 0 -and $Value -le 4294967295L)}
    function SameJson([object]$Left,[object]$Right){
        return ((ConvertTo-Json -InputObject $Left -Depth 100 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 100 -Compress))
    }
    function Facts([object]$Observed,[System.Collections.IDictionary]$Expected){
        Need ($Observed -is [pscustomobject] -and @($Observed.PSObject.Properties).Count -eq $Expected.Count) 'observed field inventory'
        foreach($key in $Expected.Keys){
            $p=$Observed.PSObject.Properties[$key]
            Need ($null -ne $p -and (Word $p.Value) -and $p.Value -eq $Expected[$key]) ('observed '+$key)
        }
    }
    function ReadJson([string]$Path){
        # The framework reader retains duplicate JSON member names; ConvertFrom-Json alone does not.
        Add-Type -AssemblyName System.Runtime.Serialization
        $bytes=[IO.File]::ReadAllBytes($Path)
        $reader=[Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes,[Xml.XmlDictionaryReaderQuotas]::Max)
        $scopes=@{}
        try{
            while($reader.Read()){
                if($reader.NodeType -ne [Xml.XmlNodeType]::Element){continue}
                $depth=$reader.Depth
                if($depth -gt 0 -and $scopes.ContainsKey($depth-1) -and $null -ne $scopes[$depth-1]){
                    $name=if($reader.NamespaceURI -ceq 'item'){$reader.GetAttribute('item')}else{$reader.LocalName}
                    Need ($scopes[$depth-1].Add($name)) 'duplicate/case-aliased JSON member'
                }
                $scopes[$depth]=$null
                if($reader.GetAttribute('type') -ceq 'object'){
                    $scopes[$depth]=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                }
            }
        }finally{$reader.Close()}
        return ([Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json)
    }
    function NoLink([string]$Path){
        $item=Get-Item -LiteralPath $Path -Force
        Need (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'reparse evidence path'
    }
    Need ($Receipt -is [pscustomobject] -and $Execute -is [bool]) 'typed receipt/request'
    Need ($null -ne $Receipt.PSObject.Properties['Error'] -and $null -eq $Receipt.Error) 'null Error required'
    Need ($Receipt.CompleteSuite -is [bool] -and -not $Receipt.CompleteSuite -and
          $Receipt.RequestedInventoryComplete -is [bool] -and $Receipt.RequestedInventoryComplete -and
          $Receipt.ArtifactsVerifiedBeforePass -is [bool] -and $Receipt.ArtifactsVerifiedBeforePass -and
          $Receipt.CompileOnly -is [bool] -and $Receipt.CompileOnly -eq (-not $Execute)) 'typed grid flags'
    foreach($field in @('ReferenceExecuted','NewFinalReferenceParity','PreSaveLspactObserved')){
        $p=$Receipt.PSObject.Properties[$field]
        Need ($null -ne $p -and $p.Value -is [bool] -and -not $p.Value) $field
    }
    Need ($Receipt.InputDrift -is [array] -and $Receipt.InputDrift.Count -eq 0) 'input drift'
    $verdict=if($Execute){'FP-GRID-PASS'}else{'COMPILE-PREFLIGHT-PASS'}
    $mode=if($Execute){'BOUNDED_FP_GRID'}else{'NOT_RUN'}
    Need ($Receipt.Verdict -is [string] -and $Receipt.Verdict -ceq $verdict -and
          $Receipt.Execution -is [string] -and $Receipt.Execution -ceq $mode) 'request-bound mode'
    Need ($Receipt.Rows -is [array] -and $Receipt.Rows.Count -eq 32 -and
          $Receipt.Controls -is [array] -and $Receipt.Controls.Count -eq 20 -and
          $Receipt.References -is [array] -and $Receipt.References.Count -eq 8 -and
          $Receipt.Associations -is [array] -and $Receipt.Associations.Count -eq 32) 'ordered 32/20/8/32 inventory'
    function Key([object]$Row,[string]$Consumer,[bool]$Lazy,[string]$Opt,[bool]$Lto,[bool]$Archive){
        return ($Row -is [pscustomobject] -and $Row.Consumer -is [string] -and $Row.Consumer -ceq $Consumer -and
                $Row.Lazy -is [bool] -and $Row.Lazy -eq $Lazy -and $Row.Optimization -is [string] -and
                $Row.Optimization -ceq $Opt -and $Row.LTO -is [bool] -and $Row.LTO -eq $Lto -and
                $Row.Archive -is [bool] -and $Row.Archive -eq $Archive)
    }
    function RefKey([string]$Opt,[bool]$Lto,[bool]$Archive){return ($Opt+':'+[int]$Lto+':'+[int]$Archive)}
    $mutations=@('omit-high-save','omit-high-restore','omit-low-save','omit-low-restore','corrupt-fpscr-save')
    $reasons=@(131,131,134,134,132)
    $phases=@(1,1,2,2,2)
    $codegen=@('FP_HIGH_SAVE','FP_HIGH_RESTORE','FP_LOW_SAVE','FP_LOW_RESTORE',$null)
    $index=0
    foreach($consumer in @('context','fiber')){foreach($lazy in @($false,$true)){
        foreach($opt in @('O2','Os')){foreach($lto in @($false,$true)){foreach($archive in @($false,$true)){
            $row=$Receipt.Rows[$index];$index++
            Need ((Key $row $consumer $lazy $opt $lto $archive) -and
                  $row.Model -is [bool] -and -not $row.Model -and $null -eq $row.Mutation -and
                  $null -eq $row.CodegenRejection) 'ordered positive key/codegen'
        }}}
    }}
    $index=0
    foreach($tuple in @(@('context','O2',$false,$false),@('fiber','Os',$true,$true))){
        foreach($lazy in @($false,$true)){for($m=0;$m -lt 5;$m++){
            $row=$Receipt.Controls[$index];$index++
            Need ((Key $row $tuple[0] $lazy $tuple[1] $tuple[2] $tuple[3]) -and
                  $row.Model -is [bool] -and -not $row.Model -and $row.Mutation -is [string] -and
                  $row.Mutation -ceq $mutations[$m] -and (SameJson $row.CodegenRejection $codegen[$m])) 'ordered control key/codegen'
        }}
    }
    $model=$Receipt.ModelProbe
    Need ($model -is [pscustomobject] -and $model.Model -is [bool] -and $model.Model -and
          $model.Name -ceq 'model' -and (Key $model 'context' $false 'O2' $false $false) -and
          $null -eq $model.Mutation) 'model identity'
    $references=@{};$index=0
    foreach($opt in @('O2','Os')){foreach($lto in @($false,$true)){foreach($archive in @($false,$true)){
        $reference=$Receipt.References[$index];$index++
        Need ($reference -is [pscustomobject] -and $reference.Optimization -is [string] -and
              $reference.Optimization -ceq $opt -and $reference.LTO -is [bool] -and $reference.LTO -eq $lto -and
              $reference.Archive -is [bool] -and $reference.Archive -eq $archive -and
              $reference.Executed -is [bool] -and -not $reference.Executed -and
              $reference.Status -is [string] -and $reference.Status -ceq 'LINKED') 'ordered link-only references'
        $references.Add((RefKey $opt $lto $archive),$reference)
    }}}
    $all=@($model)+$Receipt.Rows+$Receipt.Controls
    foreach($row in $all){
        Need ($row.Case -is [int] -and $row.Case -eq 0 -and
              $row.Executed -is [bool] -and $row.Executed -eq $Execute) 'row mode/key'
        $status=if(-not $Execute){'COMPILED'}elseif($null -ne $row.Mutation){'EXPECTED_FP_MISMATCH'}else{'PASS'}
        Need ($row.Status -is [string] -and $row.Status -ceq $status) 'row status'
        if(-not $Execute){
            Need ($null -eq $row.PSObject.Properties['Actual'] -and $null -eq $row.PSObject.Properties['Observed']) 'invented observation'
            continue
        }
        $a=$row.Actual;$exit=if($null -ne $row.Mutation){66}else{0}
        Need ($a -is [pscustomobject] -and $a.Exit -is [int] -and $a.Exit -eq $exit -and
              $a.TimedOut -is [bool] -and -not $a.TimedOut -and $a.Stdout -is [string] -and
              $a.Stdout -ceq '' -and $a.Stderr -is [string]) 'terminal transport/exit'
        if($row.Model){
            $match=[regex]::Match($a.Stderr,'\AMODEL:CM4-MPU:CPUID=([0-9A-F]{8}):MPU_TYPE=([0-9A-F]{8}):NVIC_MASK=([0-9A-F]{8}):MVFR0=([0-9A-F]{8}):MPU_CTRL=([0-9A-F]{8})\nPASS:CM4-MPU:MODEL\n\z')
            Need $match.Success 'exact two-line model terminal'
            $v=@();for($j=1;$j -le 5;$j++){$v += [Convert]::ToUInt32($match.Groups[$j].Value,16)}
            Need (($v[0] -band 4279238640L) -eq 0x410FC240 -and $v[1] -eq 0x800 -and
                  $v[2] -eq 255 -and ($v[3] -band 0xFFF) -eq 0x21 -and $v[4] -eq 0) 'model CPU/MPU/FP facts'
            Facts $row.Observed ([ordered]@{CPUID=$v[0];MPU_TYPE=$v[1];NVIC_MASK=$v[2];MVFR0=$v[3];MPU_CTRL=$v[4]})
        }elseif($null -ne $row.Mutation){
            $m=[array]::IndexOf($mutations,$row.Mutation)
            Need ($m -ge 0) 'unknown control mutation'
            $match=[regex]::Match($a.Stderr,'\AREASON:CM4-MPU-FP:CODE=([0-9A-F]{8}):WORKER=([0-9A-F]{8}):PHASE=([0-9A-F]{8})\nFAIL:CM4-MPU-FP\n\z')
            Need $match.Success 'exact two-line mismatch terminal'
            $code=[Convert]::ToUInt32($match.Groups[1].Value,16)
            $worker=[Convert]::ToUInt32($match.Groups[2].Value,16)
            $phase=[Convert]::ToUInt32($match.Groups[3].Value,16)
            Need ($code -eq $reasons[$m] -and $worker -eq 0 -and $phase -eq $phases[$m]) 'mutation reason/worker/phase causality'
            Facts $row.Observed ([ordered]@{Reason=$code;Worker=$worker;Phase=$phase})
        }else{
            $label=if($row.Consumer -ceq 'context'){'CONTEXT'}else{'FIBERV1'};$lazy=[int]$row.Lazy
            $pattern='\ACHECK:CM4-MPU-FP:API='+$label+':LAZY='+$lazy+':CALLS=00000017:SELF=00000001:CROSS=00000015:EXT0=00000008:EXT1=00000007:BASIC2=00000007:CHALLENGE=0000000F:POSTCONTROL=([0-9A-F]{8}):LSPACT=00000000\nRETURN:CM4-MPU-FP:CODE=00000052:IPSR=0000000B:PC=([0-9A-F]{8}):PSP=([0-9A-F]{8}):XPSR=([0-9A-F]{8})\nPASS:CM4-MPU-FP:'+$label+':LAZY='+$lazy+'\n\z'
            $match=[regex]::Match($a.Stderr,$pattern);Need $match.Success 'exact three-line positive terminal'
            $mask=[Convert]::ToUInt32($match.Groups[1].Value,16);$pc=[Convert]::ToUInt32($match.Groups[2].Value,16)
            $sp=[Convert]::ToUInt32($match.Groups[3].Value,16);$xpsr=[Convert]::ToUInt32($match.Groups[4].Value,16)
            $bytes=104;if($xpsr -band 0x200){$bytes+=4}
            Need ($mask -in @(2,0x20,0x22) -and (Word $row.Audit.ReturnPC) -and $pc -eq $row.Audit.ReturnPC -and
                  ($sp % 8) -eq 0 -and $sp -ge 0x20002200 -and $sp -le (0x20003000-$bytes) -and
                  ($xpsr -band 0x010001FF) -eq 0x01000000) 'post-CONTROL/per-ELF PC/complete extended frame'
            Facts $row.Observed ([ordered]@{PostControlMask=$mask;PostSaveLspact=0;ReturnPC=$pc;ReturnPSP=$sp;ReturnXPSR=$xpsr})
        }
    }
    $root=[IO.Path]::GetFullPath($BuildRoot).TrimEnd('\','/')
    Need (Test-Path -LiteralPath $root -PathType Container) 'missing evidence directory'
    NoLink $root
    $results=Join-Path $root 'results.json';$manifestPath=Join-Path $root 'artifacts.json'
    NoLink $results;NoLink $manifestPath
    $resultsHash=(Get-FileHash -LiteralPath $results -Algorithm SHA256).Hash
    $manifestHash=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    Need (SameJson $Receipt (ReadJson $results)) 'passed/persisted receipt mismatch'
    $manifest=ReadJson $manifestPath
    Need ($manifest -is [pscustomobject] -and $manifest.Artifacts -is [pscustomobject] -and
          (Sha $manifest.ResultsSha256) -and $manifest.ResultsSha256 -ceq $resultsHash) 'results manifest binding'
    $entries=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($entry in $manifest.Artifacts.PSObject.Properties){
        Need ((Sha $entry.Value) -and $entry.Name -cne 'artifacts.json' -and
              $entry.Name -notmatch '(^/|[\\:]|/$|//|(^|/)\.{1,2}(/|$))' -and
              -not $entries.ContainsKey($entry.Name)) 'artifact relative name/hash'
        $entries.Add($entry.Name,$entry.Value)
    }
    $actual=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $directories=[Collections.Generic.Queue[string]]::new();$directories.Enqueue($root)
    while($directories.Count){
        foreach($item in Get-ChildItem -LiteralPath $directories.Dequeue() -Force){
            NoLink $item.FullName
            if($item.PSIsContainer){$directories.Enqueue($item.FullName);continue}
            if($item.FullName -ceq $manifestPath){continue}
            $relative=$item.FullName.Substring($root.Length+1).Replace('\','/')
            Need ($actual.Add($relative) -and $entries.ContainsKey($relative) -and
                  (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -ceq $entries[$relative]) ('artifact bytes/inventory '+$relative)
        }
    }
    Need ($actual.SetEquals($entries.Keys)) 'missing manifest artifact'
    function BoundFile([object]$Path,[object]$Hash){
        Need ($Path -is [string] -and (Sha $Hash) -and [IO.Path]::IsPathRooted($Path)) 'bound file types'
        $full=[IO.Path]::GetFullPath($Path)
        Need ($full -ceq $Path -and $full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) 'canonical evidence path'
        $relative=$full.Substring($root.Length+1).Replace('\','/')
        Need ($entries.ContainsKey($relative) -and $entries[$relative] -ceq $Hash -and
              (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ceq $Hash) 'bound file bytes/manifest'
    }
    $elfs=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($row in $all+$Receipt.References){
        BoundFile $row.Elf $row.ElfSha256
        Need ($elfs.Add($row.Elf)) 'duplicate ELF identity'
    }
    Need ($elfs.Count -eq 61 -and $model.Elf -ceq [IO.Path]::GetFullPath((Join-Path $root 'model/runtime.elf'))) 'canonical model/61 ELF inventory'
    $binding=$Receipt.ModelArtifactBinding
    Need ($binding -is [pscustomobject] -and $binding.Verified -is [bool] -and $binding.Verified -and
          $binding.ArtifactRelative -ceq 'model/runtime.elf' -and $binding.Elf -ceq $model.Elf -and
          $binding.ElfSha256 -ceq $model.ElfSha256 -and $binding.ManifestEntrySha256 -ceq $model.ElfSha256) 'model artifact binding'
    for($i=0;$i -lt 32;$i++){
        $a=$Receipt.Associations[$i];$row=$Receipt.Rows[$i]
        $reference=$references[(RefKey $row.Optimization $row.LTO $row.Archive)]
        Need ((Key $a $row.Consumer $row.Lazy $row.Optimization $row.LTO $row.Archive) -and
              $a.Executed -is [bool] -and -not $a.Executed -and
              $a.NamedMechanismResults -is [int] -and $a.NamedMechanismResults -eq 3 -and
              $a.SubjectElf -ceq $row.Elf -and $a.SubjectSha256 -ceq $row.ElfSha256 -and
              $a.ReferenceElf -ceq $reference.Elf -and $a.ReferenceSha256 -ceq $reference.ElfSha256 -and
              $a.SubjectFp -is [pscustomobject] -and $a.ReferenceFp -is [pscustomobject] -and
              (SameJson $a.SubjectFp $row.Mechanism) -and (SameJson $a.ReferenceFp $reference.FpMechanisms)) 'reference association identity'
        BoundFile $a.Evidence $a.EvidenceSha256
    }
    Need ((Get-FileHash -LiteralPath $results -Algorithm SHA256).Hash -ceq $resultsHash -and
          (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -ceq $manifestHash) 'closing receipt/manifest drift'
}
