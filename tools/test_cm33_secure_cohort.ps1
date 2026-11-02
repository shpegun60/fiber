param(
    [string]$ArmGcc=$env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore=$env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture=Join-Path $PSScriptRoot 'fixtures\cm33_secure_cohort'
$secure=Join-Path $repo 'fiber\port\ARM_CM33\secure'
if(!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {throw 'Supply existing -ArmGcc'}
if(!$CmsisCore) {$CmsisCore=Join-Path $repo '..\..\..\Drivers\CMSIS\Include'}
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
$bin=Split-Path $ArmGcc
$gxx=Join-Path $bin 'arm-none-eabi-g++.exe'
$ar=Join-Path $bin 'arm-none-eabi-gcc-ar.exe'
$nm=Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$objdump=Join-Path $bin 'arm-none-eabi-objdump.exe'
$objcopy=Join-Path $bin 'arm-none-eabi-objcopy.exe'
$guard=Join-Path $secure 'fiber_secure_context_cohort_contract.ld'
foreach($path in @($gxx,$ar,$nm,$objdump,$objcopy,$guard,(Join-Path $secure 'fiber_secure_context_cohort.h'))) {
    if(!(Test-Path -LiteralPath $path -PathType Leaf)) {throw "Missing cohort dependency: $path"}
}
if(!$BuildRoot) {$BuildRoot=[IO.Path]::GetTempPath()}
$out=Join-Path $BuildRoot ('fiber-cm33-secure-cohort-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out -Force
$commands=Join-Path $out 'commands.jsonl'
$checks=New-Object System.Collections.Generic.List[object]
$retentionMutants=New-Object System.Collections.Generic.List[object]
$verdict='FAIL'
$provider='fiber_secure_context_pool_c33s_v1_cohort_provider'
$keyPrefix='fiber_secure_context_cohort_c33s_g1'
$queries=@('fiber_secure_gateway_v1_abi_version','fiber_secure_gateway_v1_context_port_id',
    'fiber_secure_gateway_v1_context_layout_version','fiber_secure_gateway_v1_context_feature_mask',
    'fiber_secure_context_gateway_v1_abi_version','fiber_secure_context_gateway_v1_stack_alignment',
    'fiber_secure_context_gateway_v1_max_stack_bytes','fiber_secure_context_gateway_v1_max_contexts')
$exports=$queries+@('fiber_secure_context_gateway_v1_initialize','fiber_secure_context_gateway_v1_allocate',
    'fiber_secure_context_gateway_v1_load','fiber_secure_context_gateway_v1_save')
$inputs=@($PSCommandPath,$ArmGcc,$gxx,$ar,$nm,$objdump,$objcopy,(Join-Path $repo 'mcu_core.h'),
    (Join-Path $repo 'basic_types.h'),(Join-Path $repo 'fiber\fiber_api_attributes.h'),
    (Join-Path $PSScriptRoot 'fixtures\cm33_secure_guards\main.h'))+
    @(Get-ChildItem $fixture,$secure -File -Recurse | Where-Object {$_.Extension -ne '.pyc'} | Select-Object -ExpandProperty FullName)+
    @(Get-ChildItem $CmsisCore -Filter '*.h' -File | Select-Object -ExpandProperty FullName)
function HashInputs {
    @($inputs | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
}
$before=HashInputs
$before | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII
function Recorded([string]$File,[string[]]$Arguments,[string]$Log,[switch]$AllowFailure) {
    $old=$ErrorActionPreference
    try {$ErrorActionPreference='Continue';$lines=@(& $File @Arguments 2>&1);$code=$LASTEXITCODE}
    finally {$ErrorActionPreference=$old}
    $text=($lines | ForEach-Object {"$_"}) -join "`n"
    $text | Set-Content -LiteralPath $Log -Encoding ASCII
    @{File=$File;Arguments=$Arguments;ExitCode=$code;Log=$Log} | ConvertTo-Json -Compress -Depth 5 |
        Add-Content -LiteralPath $commands -Encoding ASCII
    if($code -ne 0 -and !$AllowFailure) {throw "Command failed ($code): $Log`n$text"}
    [pscustomobject]@{Code=$code;Text=$text}
}
function Facts([uint32]$Count=3,[uint32]$Capacity=256) {
    @(
        @{Tag='p';Macro='FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_PORT_ID';Value=[Convert]::ToUInt32('43333353',16)},
        @{Tag='l';Macro='FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION';Value=131073},
        @{Tag='f';Macro='FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_FEATURE_MASK';Value=138},
        @{Tag='i';Macro='FIBER_ARM_CM33_SECURE_GATEWAY_ABI_VERSION';Value=1},
        @{Tag='c';Macro='FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_ABI_VERSION';Value=1},
        @{Tag='r';Macro='FIBER_ARM_CM33_SECURE_CONTEXT_RECORD_LAYOUT_REVISION';Value=1},
        @{Tag='n';Macro='FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT';Value=$Count},
        @{Tag='b';Macro='FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES';Value=$Capacity},
        @{Tag='a';Macro='FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES';Value=8},
        @{Tag='w';Macro='FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_WORDS';Value=2},
        @{Tag='s';Macro='FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_BYTES';Value=8},
        @{Tag='v';Macro='FIBER_ARM_CM33_SECURE_CONTEXT_STACK_SEAL_VALUE';Value=[Convert]::ToUInt32('FEF5EDA5',16)}
    )
}
function Key([object[]]$Values) {
    $key=$keyPrefix
    foreach($fact in $Values) {
        $value=[uint64]$fact.Value
        $key+='_'+$fact.Tag+'_'+[string]($value -shr 16)+'_'+[string]($value -band 65535)
    }
    $key
}
function Flags([object]$Mode,[object]$Variant) {
    $base+$Mode.Flags+@('-std=c11','-mcmse','-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_PORT_ARMV8M_MAINLINE=1',
        ('-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT='+$Variant.CountExpression),
        ('-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES='+$Variant.CapacityExpression),
        "-I$fixture","-I$secure","-I$repo","-I$CmsisCore")
}
function Link([string]$Name,[string[]]$Flags,[string[]]$Objects,[string]$ExpectedKey,
        [string]$MissingKey,[switch]$NoGeneration,[switch]$FullSurface,[switch]$NoCmse,
        [ValidateSet('undefined','generation','duplicate')][string]$NegativeKind='undefined',
        [uint32]$PoolBytes=0,[string]$OnlyQuery,[switch]$ExpectNoCohort) {
    $dir=Join-Path $out $Name
    $null=New-Item -ItemType Directory -Path $dir -Force
    $elf=Join-Path $dir 'image.elf'
    $import=Join-Path $dir 'import.o'
    $layout=Join-Path $fixture 'image.ld'
    if($OnlyQuery) {
        if($OnlyQuery -notin $queries -or $FullSurface -or $NoCmse) {throw 'Invalid isolated query link'}
        $discards=@($exports | Where-Object {$_ -ne $OnlyQuery} |
            ForEach-Object {"        *(.text.$_ .text.$_.*)"}) -join "`n"
        $template=Get-Content -LiteralPath (Join-Path $fixture 'query_only.ld.in') -Raw
        $selected=$template.Replace('@DISCARDED_NSC_SECTIONS@',$discards).
            Replace('@IMAGE_LAYOUT@',$layout.Replace('\','/'))
        $layout=Join-Path $dir 'query-only.ld'
        $selected | Set-Content -LiteralPath $layout -Encoding ASCII
    }
    if($ExpectNoCohort -and (!$OnlyQuery -or !$NoGeneration -or $ExpectedKey)) {throw 'Invalid no-retain control'}
    $args=$Flags+@('-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none',
        '-Wl,--section-start=.gnu.sgstubs=0x10008000',
        '-T',$layout,"-Wl,-Map,$dir/image.map")
    if(!$NoCmse) {$args+="-Wl,--cmse-implib,--out-implib=$import"}
    if(!$NoGeneration) {$args+=@('-T',$guard)}
    $result=Recorded $ArmGcc ($args+$Objects+@('-o',$elf)) (Join-Path $dir 'link.log') -AllowFailure
    if($MissingKey) {
        if($result.Code -eq 0 -or !$result.Text.Contains($MissingKey)) {throw "Wrong negative result: $Name"}
        if($NegativeKind -eq 'undefined' -and $result.Text -notmatch ('undefined reference to .'+[regex]::Escape($MissingKey))) {
            throw "Cohort mismatch did not fail on the exact undefined key: $Name"
        }
        if($NegativeKind -eq 'duplicate' -and $result.Text -notmatch '(multiple definition|already defined)') {
            throw "Duplicate key did not fail as a strong duplicate: $Name"
        }
        if($OnlyQuery -and $NegativeKind -eq 'undefined') {
            $undefined=@($result.Text -split "`n" | Where-Object {$_ -match 'undefined reference'})
            if(!$result.Text.Contains($OnlyQuery) -or $undefined.Count -eq 0 -or
                    @($undefined | Where-Object {!$_.Contains($MissingKey)}).Count -ne 0 -or
                    $result.Text.Contains('C33S Secure private cohort generation 1 missing')) {
                throw "Isolated query did not fail solely on its own exact key: $Name"
            }
        }
        if($OnlyQuery -and $NegativeKind -eq 'generation' -and
                $result.Text -match '(undefined reference|multiple definition|discarded section)') {
            throw "Removal mutant had an unrelated linker failure: $Name"
        }
    } else {
        if($result.Code -ne 0) {throw "Matching link failed: $Name`n$($result.Text)"}
        $symbols=(Recorded $nm @('-a','-S','-n',$elf) (Join-Path $dir 'symbols.txt')).Text
        $keys=@([regex]::Matches($symbols,'(?m)^\S+\s+\S+\s+R\s+(fiber_secure_context_cohort_c33s_g1\S*)\r?$') |
            ForEach-Object {$_.Groups[1].Value})
        if($OnlyQuery) {
            $imports=(Recorded $nm @('--defined-only',$import) (Join-Path $dir 'imports.txt')).Text
            $names=@([regex]::Matches($imports,'(?m)^\S+\s+\S\s+(\S+)\r?$') | ForEach-Object {$_.Groups[1].Value})
            if($names.Count -ne 1 -or $names[0] -ne $OnlyQuery) {throw "Sibling NSC root survived query isolation: $Name"}
            foreach($sibling in @($exports | Where-Object {$_ -ne $OnlyQuery})) {
                if($symbols -match ('(?m)^\S+\s+\S+\s+[Tt]\s+(?:__acle_se_)?'+[regex]::Escape($sibling)+'\r?$')) {
                    throw "Sibling body survived query isolation: $Name"
                }
            }
        }
        if($ExpectedKey -and ($keys.Count -ne 1 -or $keys[0] -ne $ExpectedKey)) {throw "Wrong exact key: $Name"}
        if($ExpectNoCohort -and ($keys.Count -ne 0 -or $symbols.Contains($provider))) {
            throw "Removed query retention was masked by another cohort anchor: $Name"
        }
        if($ExpectedKey -and $symbols -notmatch ('(?m)^\S+\s+0*1\s+R\s+'+[regex]::Escape($ExpectedKey)+'\r?$')) {
            throw "Exact provider must be one strong read-only byte: $Name"
        }
        if(!$NoGeneration -and $symbols -notmatch ('(?m)^\S+\s+\S+\s+T\s+'+[regex]::Escape($provider)+'\r?$')) {
            throw "Ordinary caller did not extract real C provider: $Name"
        }
        $null=Recorded $objdump @('-drwC',$elf) (Join-Path $dir 'disassembly.txt')
        if($PoolBytes) {
            $sections=(Recorded $objdump @('-h',$elf) (Join-Path $dir 'sections.txt')).Text
            $poolSection=[regex]::Match($sections,'(?m)^\s*\d+\s+\.fiber_secure_context_pool\s+([0-9a-fA-F]+)\s')
            if(!$poolSection.Success -or [Convert]::ToUInt32($poolSection.Groups[1].Value,16) -ne $PoolBytes) {
                throw "Independent pool-byte geometry failed: $Name"
            }
        }
        if($FullSurface) {
            $imports=(Recorded $nm @('--defined-only',$import) (Join-Path $dir 'imports.txt')).Text
            $names=@([regex]::Matches($imports,'(?m)^\S+\s+\S\s+(\S+)\r?$') | ForEach-Object {$_.Groups[1].Value} | Sort-Object)
            if(Compare-Object @($exports | Sort-Object) $names) {throw "Changed twelve-entry NSC surface: $Name"}
        }
    }
    $checks.Add([pscustomobject]@{Name=$Name;ExpectedKey=$ExpectedKey;Missing=$MissingKey;ExitCode=$result.Code;
        OnlyQuery=$OnlyQuery;ExpectNoCohort=[bool]$ExpectNoCohort;Directory=$dir})
}
function QueryBodyFingerprint([string]$Object,[string]$Query,[string]$Prefix) {
    $raw=$Prefix+'.bin'
    $section='.text.'+$Query
    $null=Recorded $objcopy @('-O','binary',('--only-section='+$section),$Object,$raw) ($Prefix+'-bytes.log')
    if((Get-Item -LiteralPath $raw).Length -eq 0) {throw "Missing native query bytes: $Query"}
    $text=(Recorded $objdump @('-r','-j',$section,$Object) ($Prefix+'-relocations.txt')).Text
    $relocations=@([regex]::Matches($text,'(?m)^([0-9a-fA-F]+)\s+(R_ARM_\S+)\s+(\S+)\r?$') |
        ForEach-Object {$_.Groups[1].Value+' '+$_.Groups[2].Value+' '+$_.Groups[3].Value})
    $shape=@([regex]::Matches($text,'(?m)^([0-9a-fA-F]+)\s+(R_ARM_\S+)\s+(\S+)\r?$') |
        ForEach-Object {$_.Groups[2].Value+' '+$_.Groups[3].Value} | Sort-Object)
    $literal=@(('R_ARM_THM_CALL '+$provider),('R_ARM_ABS32 '+(Key (Facts)))) | Sort-Object
    $immediate=@(('R_ARM_THM_CALL '+$provider),('R_ARM_THM_MOVW_ABS_NC '+(Key (Facts))),
        ('R_ARM_THM_MOVT_ABS '+(Key (Facts)))) | Sort-Object
    if(($shape -join "`n") -cne ($literal -join "`n") -and
            ($shape -join "`n") -cne ($immediate -join "`n")) {
        throw "Native query lost its exact call/key relocations: $Query"
    }
    [pscustomobject]@{CodeSha256=(Get-FileHash -LiteralPath $raw -Algorithm SHA256).Hash;
        Relocations=($relocations -join "`n")}
}
function TestQueryAddressForms([object]$Mode,[object]$Source) {
    $query='fiber_secure_context_gateway_v1_abi_version'
    foreach($form in @('movw-movt','abs32')) {
        $dir=Join-Path $out ($Mode.Name+'-address-'+$form)
        $copy=Join-Path $dir 'fiber\port\ARM_CM33\secure'
        $null=New-Item -ItemType Directory -Path $copy -Force
        Get-ChildItem -LiteralPath $secure -File | Where-Object {$_.Extension -in @('.c','.h','.ld')} |
            ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $copy $_.Name)}
        Copy-Item -LiteralPath (Join-Path $repo 'fiber\fiber_api_attributes.h') -Destination (Join-Path $dir 'fiber\fiber_api_attributes.h')
        $header=Join-Path $copy 'fiber_secure_context_cohort.h'
        $text=(Get-Content -LiteralPath $header -Raw).Replace("`r`n","`n")
        $pair='"movw %[cohort_byte], #:lower16:" FIBER_C33S_PRIVATE_COHORT_KEY "\n\t" \' + "`n`t`t" +
            '"movt %[cohort_byte], #:upper16:" FIBER_C33S_PRIVATE_COHORT_KEY "\n\t"'
        if([regex]::Matches($text,[regex]::Escape($pair)).Count -ne 1) {throw 'C33S actual address-materialization anchor changed'}
        if($form -eq 'abs32') {$text=$text.Replace($pair,'"ldr %[cohort_byte], =" FIBER_C33S_PRIVATE_COHORT_KEY "\n\t"')}
        $text | Set-Content -LiteralPath $header -Encoding ASCII -NoNewline
        foreach($unit in @('fiber_secure_gateway','fiber_secure_context_gateway')) {
            $obj=Join-Path $dir ($unit+'.o')
            $null=Recorded $ArmGcc ($Source.Flags+@('-save-temps=obj','-MMD','-c',(Join-Path $copy ($unit+'.c')),'-o',$obj)) (Join-Path $dir ($unit+'.log'))
            foreach($name in @($queries | Where-Object {
                if($unit -eq 'fiber_secure_gateway') {$_ -like 'fiber_secure_gateway_*'}
                else {$_ -like 'fiber_secure_context_gateway_*'}
            })) {
                $null=QueryBodyFingerprint $obj $name (Join-Path $dir $name)
                $checks.Add([pscustomobject]@{Name=($Mode.Name+'-'+$form+'-'+$name);Kind='compiled exact address positive'})
            }
        }
        $sourcePath=Join-Path $copy 'fiber_secure_context_gateway.c'
        $originalContextText=Get-Content -LiteralPath $sourcePath -Raw
        foreach($negative in @('wrong-key','extra-provider-call','unexpected-query-helper')) {
            $sourceText=$originalContextText
            $sourceText | Set-Content -LiteralPath $sourcePath -Encoding ASCII -NoNewline
            if($negative -eq 'wrong-key') {
                $anchor='"fiber_secure_context_cohort_c33s_g1"'
                if([regex]::Matches($text,[regex]::Escape($anchor)).Count -ne 1) {throw 'C33S wrong-key control anchor'}
                $text.Replace($anchor,'"fiber_secure_context_cohort_c33s_g1_wrong"') |
                    Set-Content -LiteralPath $header -Encoding ASCII -NoNewline
            } else {
                $text | Set-Content -LiteralPath $header -Encoding ASCII -NoNewline
                $pattern='(?m)^uint32_t '+[regex]::Escape($query)+'\(void\)\r?\n\{[^{}]*^\}'
                $functions=[regex]::Matches($sourceText,$pattern)
                if($functions.Count -ne 1) {throw 'C33S extra-provider query boundary'}
                $old=$functions[0].Value
                $marker='FIBER_C33S_PRIVATE_COHORT_RETAIN();'
                if([regex]::Matches($old,[regex]::Escape($marker)).Count -ne 1) {throw 'C33S extra-provider RETAIN anchor'}
                $extra=if($negative -eq 'extra-provider-call') {"`n`t"+$provider+'();'}
                    else {"`n`textern void fiber_c33s_query_unexpected_helper(void);`n`tfiber_c33s_query_unexpected_helper();"}
                $changed=$old.Replace($marker,$marker+$extra)
                $sourceText.Replace($old,$changed) | Set-Content -LiteralPath $sourcePath -Encoding ASCII -NoNewline
            }
            $obj=Join-Path $dir ($negative+'.o')
            $null=Recorded $ArmGcc ($Source.Flags+@('-save-temps=obj','-MMD','-c',$sourcePath,'-o',$obj)) (Join-Path $dir ($negative+'.log'))
            try {
                $null=QueryBodyFingerprint $obj $query (Join-Path $dir $negative)
                throw ('C33S address mutant survived: '+$negative)
            } catch {
                if($_.Exception.Message -cne ('Native query lost its exact call/key relocations: '+$query)) {throw}
            }
            $checks.Add([pscustomobject]@{Name=($Mode.Name+'-'+$form+'-'+$negative);Kind='compiled exact address rejection'})
        }
    }
}
function TestQueryRetention([object]$Mode,[object]$Source,[object]$Foreign) {
    foreach($q in 0..($queries.Count-1)) {
        $query=$queries[$q]
        $name=$Mode.Name+'-retain-query-'+$q
        $dir=Join-Path $out $name
        $null=New-Item -ItemType Directory -Path $dir
        $unit=if($q -lt 4) {'identity'} else {'context'}
        $file=if($q -lt 4) {'fiber_secure_gateway.c'} else {'fiber_secure_context_gateway.c'}
        $originalPath=Join-Path $secure $file
        $original=Get-Content -LiteralPath $originalPath -Raw
        # These immutable definitions have no nested block. Refuse a changed
        # shape rather than editing a sibling or reconstructing a fake query.
        $pattern='(?m)^uint32_t '+[regex]::Escape($query)+'\(void\)\r?\n\{[^{}]*^\}'
        $functions=[regex]::Matches($original,$pattern)
        if($functions.Count -ne 1) {throw "Changed query mutation boundary: $query"}
        $function=$functions[0]
        $marker='FIBER_C33S_PRIVATE_COHORT_RETAIN();'
        if([regex]::Matches($function.Value,[regex]::Escape($marker)).Count -ne 1) {
            throw "Expected exactly one query-owned RETAIN: $query"
        }
        $changedFunction=$function.Value.Replace($marker,'/* mutation: only this query RETAIN removed */')
        $changed=$original.Substring(0,$function.Index)+$changedFunction+$original.Substring($function.Index+$function.Length)
        $copy=Join-Path $dir 'production.c'
        $mutant=Join-Path $dir 'removed-retain.c'
        $original | Set-Content -LiteralPath $copy -Encoding ASCII -NoNewline
        $changed | Set-Content -LiteralPath $mutant -Encoding ASCII -NoNewline
        $flags=$Source.Flags+@(('-DCOHORT_QUERY='+$query),'-include',(Join-Path $fixture 'select_query.h'))
        $objects=@{}
        foreach($kind in @('production','removed-retain')) {
            $sourcePath=if($kind -eq 'production') {$copy} else {$mutant}
            $object=Join-Path $dir ($kind+'.o')
            $null=Recorded $ArmGcc ($flags+@('-save-temps=obj','-MMD','-c',$sourcePath,'-o',$object)) (Join-Path $dir ($kind+'.log'))
            $objects[$kind]=$object
        }
        $fingerprint=$null
        if($Mode.Name -notmatch 'lto') {
            $reference=QueryBodyFingerprint $Source.Objects[$unit] $query (Join-Path $dir 'original-query')
            $fingerprint=QueryBodyFingerprint $objects.production $query (Join-Path $dir 'isolated-query')
            if($reference.CodeSha256 -ne $fingerprint.CodeSha256 -or $reference.Relocations -ne $fingerprint.Relocations) {
                throw "Fixture NSC projection changed selected production bytes/relocations: $query"
            }
        }
        $archives=@{}
        foreach($kind in @('matching','foreign','removed-retain')) {
            $parts=@()
            foreach($part in @('identity','context','pool')) {
                if($part -eq $unit) {$parts+=$objects[$(if($kind -eq 'removed-retain') {'removed-retain'} else {'production'})]}
                elseif($part -eq 'pool' -and $kind -ne 'matching') {$parts+=$Foreign.Objects.pool}
                else {$parts+=$Source.Objects[$part]}
            }
            $archive=Join-Path $dir ($kind+'.a')
            $null=Recorded $ar (@('rcs',$archive)+$parts) (Join-Path $dir ($kind+'-archive.log'))
            $archives[$kind]=$archive
        }
        $caller=Join-Path $Source.Directory ("query-$q-c.o")
        Link ($name+'-matching') $Source.Flags @($caller,$archives.matching) $Source.Key '' -OnlyQuery $query
        Link ($name+'-foreign') $Source.Flags @($caller,$archives.foreign) '' $Source.Key -OnlyQuery $query
        Link ($name+'-removed-control') $Source.Flags @($caller,$archives['removed-retain']) '' '' -OnlyQuery $query -NoGeneration -ExpectNoCohort
        $rejectedName=$name+'-removed-rejected'
        try {
            # A discarded sibling can cause archive extraction before GC, so
            # DEFINED alone need not fail. Reuse strict matching admission:
            # successful link, exactly one NSC, then missing live exact key.
            Link $rejectedName $Source.Flags @($caller,$archives['removed-retain']) $Source.Key '' -OnlyQuery $query
            throw "Query RETAIN-removal mutant survived admission: $query"
        } catch {
            $expected='Wrong exact key: '+$rejectedName
            if($_.Exception.Message -cne $expected) {throw}
            $checks.Add([pscustomobject]@{Name=$rejectedName;ExpectedKey=$Source.Key;Missing='';ExitCode=0;
                OnlyQuery=$query;ExpectedAdmissionFailure=$expected;Directory=(Join-Path $out $rejectedName)})
        }
        $evidence=[pscustomobject]@{Mode=$Mode.Name;Query=$query;OriginalPath=$originalPath;
            OriginalSha256=(Get-FileHash -LiteralPath $originalPath -Algorithm SHA256).Hash;
            CopiedSha256=(Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash;
            MutantSha256=(Get-FileHash -LiteralPath $mutant -Algorithm SHA256).Hash;
            Before=$function.Value;After=$changedFunction;NativeBodyFingerprint=$fingerprint;
            MatchingKey=$Source.Key;ForeignKey=$Foreign.Key;Directory=$dir;
            Rejection='matching admission: successful archive/GC link and one NSC query, but its own live exact key is missing'}
        if($evidence.OriginalSha256 -ne $evidence.CopiedSha256) {throw "Production copy changed: $query"}
        $evidence | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $dir 'mutation.json') -Encoding ASCII
        $retentionMutants.Add($evidence)
    }
}
try {
    Write-Host "C33S private cohort evidence: $out"
    $null=Recorded $ArmGcc @('--version') (Join-Path $out 'compiler.txt')
    $base=@('-mcpu=cortex-m33','-mthumb','-mfloat-abi=soft','-mgeneral-regs-only','-ffreestanding','-fno-builtin',
        '-fno-common','-ffunction-sections','-fdata-sections','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
        '-fno-instrument-functions','-fno-stack-protector','-fno-profile-arcs','-fno-test-coverage','-fno-sanitize=all',
        '-fno-profile','-fno-stack-check','-fno-sanitize-coverage=trace-pc','-Wall','-Wextra','-Werror','-Wundef')
    $modes=@(@{Name='o2';Flags=@('-O2')},@{Name='os';Flags=@('-Os')},
        @{Name='o2-lto';Flags=@('-O2','-flto')},@{Name='os-lto';Flags=@('-Os','-flto')})
    $variants=@(
        @{Name='a';Count=3;Capacity=256;CountExpression='3';CapacityExpression='256'},
        @{Name='b';Count=2;Capacity=400;CountExpression='2';CapacityExpression='400'},
        @{Name='count';Count=2;Capacity=256;CountExpression='2';CapacityExpression='256'},
        @{Name='capacity';Count=3;Capacity=264;CountExpression='3';CapacityExpression='264'},
        @{Name='expression';Count=3;Capacity=256;CountExpression='(1u + 2u)';CapacityExpression='(1u << 8)'}
    )
    $groups=@{}
    foreach($mode in $modes) {
        foreach($variant in $variants) {
            $dir=Join-Path $out ($mode.Name+'-'+$variant.Name)
            $null=New-Item -ItemType Directory -Path $dir
            $flags=Flags $mode $variant
            $objects=@{}
            foreach($unit in @(@{Name='identity';File='fiber_secure_gateway.c'},
                    @{Name='context';File='fiber_secure_context_gateway.c'},@{Name='pool';File='fiber_secure_context_pool.c'})) {
                $object=Join-Path $dir ($unit.Name+'.o')
                $null=Recorded $ArmGcc ($flags+@('-save-temps=obj','-MMD','-c',(Join-Path $secure $unit.File),'-o',$object)) (Join-Path $dir ($unit.Name+'.log'))
                $objects[$unit.Name]=$object
            }
            $archive=Join-Path $dir 'companion.a'
            $null=Recorded $ar (@('rcs',$archive)+@($objects.identity,$objects.context,$objects.pool)) (Join-Path $dir 'archive.log')
            $all=Join-Path $dir 'all.o'
            $null=Recorded $ArmGcc ($flags+@('-c',(Join-Path $fixture 'all.c'),'-o',$all)) (Join-Path $dir 'all.log')
            $group=@{Name=$variant.Name;Objects=$objects;Archive=$archive;All=$all;Flags=$flags;Key=(Key (Facts $variant.Count $variant.Capacity));Directory=$dir}
            $groups[$mode.Name+'.'+$variant.Name]=$group
            Link ($mode.Name+'-'+$variant.Name+'-complete') $flags @($all,$archive) $group.Key '' -FullSurface -PoolBytes ($variant.Count*(24+$variant.Capacity+8)+8)
        }
        $a=$groups[$mode.Name+'.a'];$b=$groups[$mode.Name+'.b'];$e=$groups[$mode.Name+'.expression']
        if($mode.Name -notmatch 'lto') {TestQueryAddressForms $mode $a}
        foreach($variant in @($a,$b)) {
            for($q=0;$q -lt $queries.Count;++$q) {
                foreach($language in @('c','c++')) {
                    $compiler=if($language -eq 'c') {$ArmGcc} else {$gxx}
                    $flags=@($variant.Flags | Where-Object {$_ -ne '-std=c11'})
                    if($language -eq 'c++') {$flags+=@('-x','c++','-std=c++17','-fno-exceptions','-fno-rtti')} else {$flags+='-std=c11'}
                    $object=Join-Path $variant.Directory ("query-$q-$language.o")
                    $null=Recorded $compiler ($flags+@(('-DCOHORT_QUERY='+$queries[$q]),'-c',(Join-Path $fixture 'query.c'),'-o',$object)) (Join-Path $variant.Directory ("query-$q-$language.log"))
                    Link ($mode.Name+'-'+$variant.Name+"-query-$q-$language") $variant.Flags @($object,$variant.Archive) $variant.Key ''
                }
            }
        }
        foreach($direction in @(@{Source=$a;Foreign=$b;Name='ab'},@{Source=$b;Foreign=$a;Name='ba'})) {
            $s=$direction.Source;$f=$direction.Foreign
            foreach($unit in @('identity','context','pool')) {
                $objects=@($s.All)
                foreach($part in @('identity','context','pool')) {$objects+=if($part -eq $unit){$f.Objects[$part]}else{$s.Objects[$part]}}
                $missing=if($unit -eq 'pool') {$s.Key} else {$f.Key}
                Link ($mode.Name+'-stale-'+$unit+'-'+$direction.Name) $s.Flags $objects '' $missing
            }
        }
        TestQueryRetention $mode $a $b
        foreach($name in @('count','capacity')) {
            $f=$groups[$mode.Name+'.'+$name]
            Link ($mode.Name+'-mismatch-'+$name) $a.Flags @($a.All,$a.Objects.identity,$a.Objects.context,$f.Objects.pool) '' $a.Key
        }
        Link ($mode.Name+'-equivalent-expressions') $a.Flags @($a.All,$e.Objects.identity,$e.Objects.context,$a.Objects.pool) $a.Key '' -FullSurface
        $old=Join-Path $a.Directory 'old12.o'
        $null=Recorded $ArmGcc ($a.Flags+@('-c',(Join-Path $fixture 'old12.c'),'-o',$old)) (Join-Path $a.Directory 'old12.log')
        Link ($mode.Name+'-preguard-control') $a.Flags @($a.All,$old) '' '' -NoGeneration -FullSurface
        Link ($mode.Name+'-preguard-rejected') $a.Flags @($a.All,$old) '' 'C33S Secure private cohort generation 1 missing' -NegativeKind generation
        $missing=Join-Path $a.Directory 'missing-data.o'
        $null=Recorded $ArmGcc ($a.Flags+@('-c',(Join-Path $fixture 'missing_data.c'),'-o',$missing)) (Join-Path $a.Directory 'missing-data.log')
        Link ($mode.Name+'-missing-data-provider') $a.Flags @((Join-Path $a.Directory 'query-1-c.o'),$a.Objects.identity,$missing) '' $a.Key

        # Post-include substitutions test key encoding, not accepted CPU/record
        # manifests: production layout assertions have already run unchanged.
        $baseline=Facts
        $encodingCases=@(@{Name='base';Facts=$baseline;Override=''})
        foreach($fact in $baseline) {
            foreach($kind in @('high','all-ones')) {
                $value=if($kind -eq 'high') {[uint32]([uint64]$fact.Value -bxor [uint64]65536)} else {[uint32]::MaxValue}
                $values=Facts
                ($values | Where-Object {$_.Tag -eq $fact.Tag}).Value=$value
                $encodingCases+=@{Name=$fact.Tag+'-'+$kind;Facts=$values;
                    Override=("#undef "+$fact.Macro+"`n#define "+$fact.Macro+' 0x'+$value.ToString('X8')+"u`n")}
            }
        }
        foreach($encoding in $encodingCases) {
            $name=$mode.Name+'-encoding-'+$encoding.Name
            $source=Join-Path $a.Directory ($name+'.c')
            @('#include "fiber_secure_context_cohort.h"',$encoding.Override,
                ('void '+$provider+'(void) {}'),
                'FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY',
                'void cohort_consumer(void) { FIBER_C33S_PRIVATE_COHORT_DEFINE(); FIBER_C33S_PRIVATE_COHORT_RETAIN(); }') |
                Set-Content -LiteralPath $source -Encoding ASCII
            $object=Join-Path $a.Directory ($name+'.o')
            $null=Recorded $ArmGcc ($a.Flags+@('-c',$source,'-o',$object)) (Join-Path $a.Directory ($name+'.log'))
            Link $name $a.Flags @($object) (Key $encoding.Facts) '' -NoGeneration -NoCmse
        }
        $duplicateSource=Join-Path $a.Directory 'duplicate-key.c'
        @('#include "fiber_secure_context_cohort.h"',
            'FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY',
            'void first_key(void) { FIBER_C33S_PRIVATE_COHORT_DEFINE(); }',
            'FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY',
            'void second_key(void) { FIBER_C33S_PRIVATE_COHORT_DEFINE(); }',
            'void cohort_consumer(void) { first_key(); second_key(); }') |
            Set-Content -LiteralPath $duplicateSource -Encoding ASCII
        $duplicateObject=Join-Path $a.Directory 'duplicate-key.o'
        $dup=Recorded $ArmGcc ($a.Flags+@('-c',$duplicateSource,'-o',$duplicateObject)) (Join-Path $a.Directory 'duplicate-key.log') -AllowFailure
        if($dup.Code -eq 0) {
            Link ($mode.Name+'-duplicate-key') $a.Flags @($duplicateObject) '' $a.Key -NoGeneration -NoCmse -NegativeKind duplicate
        } elseif($dup.Text.Contains($a.Key) -and $dup.Text -match 'already defined') {
            $checks.Add([pscustomobject]@{Name=$mode.Name+'-duplicate-key';ExpectedKey='';Missing=$a.Key;ExitCode=$dup.Code;Directory=$a.Directory})
        } else {throw 'Duplicate key failed for an unrelated reason'}
        Write-Host "PASS private cohort $($mode.Name): actual objects, expression normalization, query archives and stale links"
    }
    foreach($optimization in @('o2','os')) {
        $plain=$groups[$optimization+'.a'];$lto=$groups[$optimization+'-lto.a']
        foreach($split in @(@{Name='lto-gateway';Gateway=$lto;Pool=$plain},@{Name='lto-pool';Gateway=$plain;Pool=$lto})) {
            $archive=Join-Path $out ($optimization+'-'+$split.Name+'.a')
            $null=Recorded $ar @('rcs',$archive,$split.Gateway.Objects.identity,$split.Gateway.Objects.context,$split.Pool.Objects.pool) (Join-Path $out ($optimization+'-'+$split.Name+'-archive.log'))
            Link ($optimization+'-'+$split.Name) $lto.Flags @($lto.All,$archive) $lto.Key '' -FullSurface
            for($q=0;$q -lt $queries.Count;++$q) {
                foreach($language in @('c','c++')) {
                    $query=Join-Path $lto.Directory ("query-$q-$language.o")
                    Link ($optimization+'-'+$split.Name+"-query-$q-$language") $lto.Flags @($query,$archive) $lto.Key ''
                }
            }
        }
    }
    $after=HashInputs
    $after | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    if(Compare-Object $before $after -Property Path,Hash) {throw 'Cohort qualification inputs changed; rerun required'}
    if($retentionMutants.Count -ne 32 -or $checks.Count -ne 540) {throw 'Changed cohort retention proof inventory'}
    $verdict='PASS'
} finally {
    @{Verdict=$verdict;Checks=$checks.ToArray();QueryRetentionMutants=$retentionMutants.ToArray();
        Hardware='NOT_RUN';Execution='LINK_ONLY';ExternalCapacityExpectation=$false} |
        ConvertTo-Json -Depth 8 | Set-Content (Join-Path $out 'results.json') -Encoding ASCII
    Get-ChildItem -LiteralPath $out -File -Recurse | Where-Object {$_.Name -ne 'sha256.csv'} | Get-FileHash -Algorithm SHA256 |
        Select-Object Path,Hash | Export-Csv (Join-Path $out 'sha256.csv') -NoTypeInformation -Encoding ASCII
}
Write-Host "PASS C33S private cohort: $($checks.Count) checks, $($retentionMutants.Count) compiled query RETAIN-removal mutants; evidence: $out"
