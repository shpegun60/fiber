function ConstructorArchiveAdmission([string]$Marker) {
    $v1='fiber_internal_runtime_port_abi_v1_anchor'
    $v2='fiber_internal_runtime_port_abi_v2_anchor'
    $v2Archive=Join-Path $initDir 'libv2-common.a'
    Archive $v2Archive $badCommon
    $definitions=Defined $v2Archive
    # The LTO plugin classifies an unmaterialized const provider as D.
    Check "$name/init-only-real-v2-common-archive" ($definitions -match ('(?m)^[0-9a-f]+\s+[RD]\s+'+$v2+'\r?$') -and
        $definitions -notmatch ('\b'+$v1+'\b')) $definitions
    $badElf=Join-Path $initDir 'archive-missing-v1.elf'
    $bad=Link $badElf (@($initObjects)+@($expectation,'-Wl,--start-group',$v2Archive,$portArchive,'-Wl,--end-group')) $flags
    UndefinedFailure "$name/init-only-archive-missing-v1" $bad $v1
    $missing=@([regex]::Matches($bad.Text,'undefined reference to [^A-Za-z_]*([A-Za-z_][A-Za-z0-9_]*)') |
        ForEach-Object {$_.Groups[1].Value} | Sort-Object -Unique)
    Check "$name/init-only-archive-exact-missing-v1" ($missing.Count -eq 1 -and $missing[0] -ceq $v1 -and
        $bad.Text -match 'fiber_port_context_init' -and !(Test-Path -LiteralPath $badElf)) $bad.Text
    # Same real archives, changing only the constructor's cold anchor read.
    $unretainedArchive=Join-Path $initDir 'libunretained-port.a'
    Archive $unretainedArchive @($unretained,$portObjects[1])
    $controlDir3=Join-Path $initDir 'archive-removed-read-control'
    $null=New-Item -ItemType Directory -Path $controlDir3
    $elf=Join-Path $controlDir3 'secure.elf'
    $result=Link $elf (@($initObjects)+@($expectation,'-Wl,--start-group',$v2Archive,$unretainedArchive,'-Wl,--end-group')) $flags
    Check "$name/init-only-archive-removed-read-control-links" ($result.Code -eq 0) $result.Text
    $symbols=Need $nm @('-n','-S',$elf) ($elf+'.symbols.txt')
    $undefined=Need $nm @('-u',$elf) ($elf+'.undefined.txt')
    $null=Need $objdump @('-drwC',$elf) ($elf+'.disassembly.txt')
    Check "$name/init-only-archive-control-no-start-handlers-or-v1" ([string]::IsNullOrWhiteSpace($undefined) -and
        $symbols -notmatch ('\b'+$v1+'\b') -and
        $symbols -notmatch '(?m)\b(fiber_start|fiber_port_runtime_start_first|fiber_port_start_first_context)\r?$' -and
        $symbols -notmatch '(?m)^[0-9a-f]+\s+[0-9a-f]+\s+T\s+(SVC_Handler|PendSV_Handler)\r?$') $symbols
    $null=Execute "$name/archive-removed-constructor-read-control" $elf $Marker 'CompiledControl'
}
function PortableDefaultAdmission {
    $portableName="$mode/portable-default"
    $portableDir=Join-Path $dir 'portable-default'
    $null=New-Item -ItemType Directory -Path $portableDir
    $portableSource=Join-Path $repo 'tools/fixtures/portable_application.c'
    $source=[IO.File]::ReadAllText($portableSource)
    $includes=[regex]::Matches($source,'(?m)^\s*#\s*include\s*([<"][^>"]+[>"])')
    Check "$portableName/unchanged-feature-blind-source" ($includes.Count -eq 1 -and
        $includes[0].Groups[1].Value -ceq '"fiber/fiber_core.h"' -and
        $source -notmatch '(?m)^\s*#\s*(if|ifdef|ifndef|elif)\b' -and
        $source -notmatch '\b(FIBER_PORT_|fiber_port_)') $portableSource
    $portableFlags=@($flags | Where-Object {$_ -notmatch '^-DFIBER_(SCHEDULER_BASEPRI|REWIND_MSP|VALIDATE_ADDRESS_MAP_ON_SWITCH)='})
    $overrides=@($portableFlags | Where-Object {$_ -match '^-DFIBER_' -and
        $_ -notmatch '^-DFIBER_PORT_(BUILD_SELECTED|ARMV8M_MAINLINE|ARMV81M_MAINLINE)=1$'})
    Check "$portableName/no-policy-overrides" ($overrides.Count -eq 0) $portableFlags
    # The exact public translation unit gets no fixture/CMSIS include directory.
    $publicFlags=@($portableFlags | Where-Object {$_ -notin @("-I$fixture","-I$CmsisCore")})
    $application=Join-Path $portableDir 'portable-application.o'
    Compile $portableSource $application $publicFlags
    $dependencies=[IO.File]::ReadAllText([IO.Path]::ChangeExtension($application,'.d'))
    Check "$portableName/public-only-dependencies" ($dependencies -match 'fiber_core\.h' -and
        $dependencies -match 'fiber_port_types\.h' -and
        $dependencies -notmatch '(fiber_port_(private|boot|mpu_abi|secure_context_abi|tfm_abi|runtime_abi|context_cohort)\.h|fiber_portmacro\.h|fiber_runtime_(port_abi|state|context_configuration_abi)\.h|core_cm[0-9]+\.h|[/\\]main\.h)') $dependencies
    $portablePort=@()
    foreach($unit in @('fiber_port_boot.c','fiber_port.c')) {
        $o=Join-Path $portableDir ($unit.Replace('.c','.o'))
        Compile (Join-Path $port $unit) $o $portableFlags
        $portablePort+=$o
    }
    $definitions=Defined $portablePort[1]
    $m=[regex]::Matches($definitions,'(?m)^[0-9a-f]+\s+[RD]\s+(fiber_port_context_cohort_\S+)\r?$')
    Check "$portableName/exact-real-default-cohort" ($m.Count -eq 1) $definitions
    $cohort=$m[0].Groups[1].Value
    $m=[regex]::Matches($definitions,'(?m)^[0-9a-f]+\s+[RD]\s+(fiber_port_storage_cohort_\S+)\r?$')
    Check "$portableName/exact-real-storage-provider" ($m.Count -eq 1) $definitions
    $storageCohort=$m[0].Groups[1].Value
    $u=Need $gccnm @('-u',$application) ($application+'.undefined.txt')
    $actual=@([regex]::Matches($u,'(?m)^\s*U\s+(\S+)\r?$') | ForEach-Object {$_.Groups[1].Value} | Sort-Object -Unique)
    $expected=@('fiber_init','fiber_current','fiber_schedule','fiber_start','fiber_scheduler_set_pick_next',$storageCohort)
    Check "$portableName/exact-five-public-imports-and-storage-cohort" ($actual.Count -eq 6 -and
        @(Compare-Object ($expected | Sort-Object) $actual).Count -eq 0) $u
    $portableCommon=@();$portablePublicObjects=@()
    $portableCommonFlags=@($portableFlags | Where-Object {$_ -notin @("-I$fixture","-I$port","-I$CmsisCore")})
    foreach($source in $runtimeSources) {
        $unit=$source.Substring($repo.Length+1).Replace('\','_').Replace('/','_')
        $o=Join-Path $portableDir ($unit.Replace('.c','.o'))
        Compile $source $o $portableCommonFlags
        $portableCommon+=$o
        if($source -cin $runtimePublicSources){$portablePublicObjects+=$o}
    }
    foreach($public in @('fiber_init','fiber_current','fiber_schedule','fiber_start','fiber_scheduler_set_pick_next')) {
        $owners=@($portableCommon | Where-Object {(Defined $_) -match ('(?m)^[0-9a-f]+\s+T\s+'+[regex]::Escape($public)+'\r?$')})
        Check "$portableName/exact-common-public-owner-$public" ($owners.Count -eq 1 -and $owners[0] -cin $portablePublicObjects) $owners
    }
    $portableExpectation=Join-Path $portableDir 'expectation.o'
    Compile (Join-Path $repo 'fiber/port/fiber_port_context_cohort_expectation.c') $portableExpectation $portableFlags
    $support=@()
    foreach($unit in @('startup.S','portable_environment.c','portable_policy.c')) {
        $o=Join-Path $portableDir ($unit.Replace('.','-'))
        $o+='.o'
        Compile (Join-Path $fixture $unit) $o ($portableFlags+@('-DEXEC_WEAK_STARTUP=1'))
        $support+=$o
    }
    $portableCommonArchive=Join-Path $portableDir 'libcommon.a'
    $portablePortArchive=Join-Path $portableDir 'libport.a'
    Archive $portableCommonArchive $portableCommon
    Archive $portablePortArchive $portablePort
    $defaultBasepri=if($priorityBits -eq 8){2}else{1 -shl (8-$priorityBits)}
    $policy=[uint32[]]@($defaultBasepri,1,0,1,1,0,$ExpectedRuntimeSelectable)
    foreach($linkMode in @('direct','archive')) {
        $elf=Join-Path $portableDir ($linkMode+'.elf')
        $members=@($support)+@($application,$portableExpectation)
        if($linkMode -ceq 'direct') {$members+=$portableCommon+$portablePort}
        else {$members+=@('-Wl,--start-group',$portableCommonArchive,$portablePortArchive,'-Wl,--end-group')}
        $result=Link $elf $members $portableFlags (Join-Path $fixture 'portable.ld')
        Check "$portableName/$linkMode-link" ($result.Code -eq 0) $result.Text
        Inspect "$portableName/$linkMode" $elf -Portable
        $attr=[IO.File]::ReadAllText($elf+'.attributes.txt')
        $section=[regex]::Matches($attr,'(?m)^\s*\[\s*\d+\]\s+\.portable_policy\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\s')
        Check "$portableName/$linkMode-policy-section" ($section.Count -eq 1) $elf
        $offset=[Convert]::ToInt32($section[0].Groups[1].Value,16)
        $length=[Convert]::ToInt32($section[0].Groups[2].Value,16)
        $bytes=[IO.File]::ReadAllBytes($elf)
        Check "$portableName/$linkMode-policy-span" ($length -eq 28 -and $offset -ge 0 -and $offset+$length -le $bytes.Length) $elf
        $observed=@(for($i=0;$i -lt 7;++$i){[BitConverter]::ToUInt32($bytes,$offset+4*$i)})
        Check "$portableName/$linkMode-generated-safe-defaults" (($observed -join ',') -ceq ($policy -join ',')) $observed
        $runs.Add([pscustomobject]@{Name="$portableName/$linkMode";Executed=$false;Kind='PortableDefaultLinkOnly';ELF=$elf;
            Reason='Unchanged portable application, real default-policy providers; link/generated-code proof only'})
    }
    @{Source=$portableSource;SourceSHA256=(Get-FileHash -LiteralPath $portableSource -Algorithm SHA256).Hash;
        Flags=$portableFlags;PublicFlags=$publicFlags;PrivateCohort=$cohort;StorageCohort=$storageCohort;
        Policy=$policy;Executed=$false;Optimization=$optimization;LTO=[bool]$lto} |
        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $portableDir 'portable-default.json') -Encoding ASCII
}
