function Test-CompilerSensitiveBody([string]$Text,[string]$Hook,[string[]]$ColdFunctions) {
    $cold='\b(?:'+(($ColdFunctions | ForEach-Object {[regex]::Escape($_)}) -join '|')+')\b'
    return ($Text -notmatch $Hook -and $Text -notmatch $cold)
}
function CompilerAdversarial {
    $families=@(
        @{Name='instrument';Enable=@('-finstrument-functions');Pattern='__cyg_profile_func_(enter|exit)'},
        @{Name='ssp';Enable=@('-fstack-protector-all');Pattern='__stack_chk_(guard|fail)'},
        @{Name='coverage';Enable=@('-fprofile-arcs','-ftest-coverage');Pattern='__gcov'},
        @{Name='ubsan';Enable=@('-fsanitize=undefined');Pattern='__ubsan_'},
        @{Name='trace-pc';Enable=@('-fsanitize-coverage=trace-pc');Pattern='__sanitizer_cov_trace_pc'},
        @{Name='pg';Enable=@('-pg');Pattern='(?:__gnu_mcount_nc|_mcount|\bmcount\b)'})
    $hook='(__cyg_profile_|__stack_chk_|__gcov|__ubsan_|__sanitizer_cov_|__gnu_mcount_nc|_mcount|\bmcount\b)'
    $exclusions=@('-fno-instrument-functions','-fno-stack-protector','-fno-profile-arcs','-fno-test-coverage',
        '-fno-profile','-fno-stack-check','-fno-sanitize=all','-fno-sanitize-coverage=trace-pc')
    $neutralBase=@($base | Where-Object {$_ -notin $exclusions})
    $label=if($port -match 'CM33_'){'C3SO'}else{'C5SO'}
    $architecture=if($label -eq 'C3SO'){'-DFIBER_PORT_ARMV8M_MAINLINE=1'}else{'-DFIBER_PORT_ARMV81M_MAINLINE=1'}
    # These real common wrappers deliberately have no canonical sensitive
    # declaration. Their raw hooks are inventoried, not relabeled as protected.
    $ordinaryExports=@('fiber_init','fiber_scheduler_set_pick_next')
    $ordinary=$ordinaryExports+@('fiber_internal_scheduler_store_pick_next')
    $portExpected=@('fiber_addr_plausible_code','fiber_addr_plausible_ram',
        'fiber_internal_runtime_current_context_slot','fiber_internal_runtime_port_abi_v1_anchor',
        'fiber_internal_runtime_publish_current_context','fiber_internal_runtime_require_current_context',
        'fiber_internal_runtime_select_scheduler_candidate','fiber_internal_task_return','fiber_panic','memcpy','memset')
    $commonSensitive=@('fiber_current','fiber_start','fiber_schedule','fiber_internal_task_return',
        'fiber_internal_runtime_load_current_context','fiber_internal_scheduler_is_configured',
        'fiber_internal_runtime_select_scheduler_candidate','fiber_internal_runtime_publish_current_context',
        'fiber_internal_runtime_require_current_context','fiber_internal_runtime_close_context_configuration',
        'fiber_internal_runtime_context_configuration_is_open','fiber_panic')
    $inventory=New-Object System.Collections.Generic.List[object]
    foreach($optimization in @('-O2','-Os')) {
        foreach($lto in @(0,1)) {
            foreach($r9Mode in @('reserved','ordinary')) {
                $reserved=if($r9Mode -eq 'reserved'){1}else{0}
                $mode="compiler-$($optimization.Substring(1))-lto$lto-$r9Mode"
                $dir=Join-Path $out $mode;$null=New-Item -ItemType Directory -Path $dir
                Write-Host "$label $mode (raw attributes; no compiler counterflags)"
                $flags=$neutralBase+@($optimization,'-DFIBER_PORT_BUILD_SELECTED=1',$architecture,
                    '-DFIBER_SCHEDULER_BASEPRI=128','-DFIBER_REWIND_MSP=1','-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1',
                    "-DEXEC_NVIC_PRIO_BITS=$priorityBits","-DEXEC_EXPECT_RUNTIME_SELECTABLE=$ExpectedRuntimeSelectable","-DEXEC_RESERVED_R9=$reserved",
                    "-I$fixture","-I$port","-I$repo","-I$repo/fiber","-I$repo/fiber/port","-I$CmsisCore")
                if($reserved){$flags+='-ffixed-r9'}else{$flags+=@('-frename-registers','-fno-omit-frame-pointer')}
                if($lto){$flags+=@('-flto','-ffat-lto-objects')}
                $units=@(
                    @{Name='boot';Source=(Join-Path $port 'fiber_port_boot.c');Common=$false},
                    @{Name='runtime';Source=(Join-Path $port 'fiber_port.c');Common=$false},
                    @{Name='core';Source=(Join-Path $repo 'fiber/fiber_core.c');Common=$true},
                    @{Name='state';Source=(Join-Path $repo 'fiber/fiber_runtime_state.c');Common=$true},
                    @{Name='panic';Source=(Join-Path $repo 'fiber/fiber_panic.c');Common=$true})
                $baselineObjects=@()
                foreach($unit in $units) {
                    $f=if($unit.Common){@($flags | Where-Object {$_ -notin @("-I$fixture","-I$port","-I$CmsisCore")})}else{$flags}
                    $o=Join-Path $dir ($unit.Name+'.o');Compile $unit.Source $o $f;$baselineObjects+=$o
                }
                $nativeFlags=$flags+@('-nostdlib','-nostartfiles','-Wl,-r')
                if($lto){$nativeFlags+='-flinker-output=nolto-rel'}
                $baselineGroup=Join-Path $dir 'baseline-group.o'
                $null=Need $ArmGcc ($nativeFlags+$baselineObjects+@('-o',$baselineGroup)) ($baselineGroup+'.link.log')
                $baselineU=Need $nm @('-u',$baselineGroup) ($baselineGroup+'.undefined.txt')
                $expected=@([regex]::Matches($baselineU,'(?m)^\s*U\s+(\S+)\r?$') | ForEach-Object {$_.Groups[1].Value} | Sort-Object)
                $integration=@('fiber_addr_plausible_code','fiber_addr_plausible_ram','memcpy','memset')
                Check "$mode/exact-baseline-integration-dependencies" (@(Compare-Object $integration $expected).Count -eq 0 -and $baselineU -notmatch $hook) $baselineU
                $portGroup=Join-Path $dir 'baseline-port-only-group.o'
                $null=Need $ArmGcc ($nativeFlags+@($baselineObjects[0],$baselineObjects[1],'-o',$portGroup)) ($portGroup+'.link.log')
                $portU=Need $nm @('-u',$portGroup) ($portGroup+'.undefined.txt')
                $actualPort=@([regex]::Matches($portU,'(?m)^\s*U\s+(\S+)\r?$') | ForEach-Object {$_.Groups[1].Value} | Sort-Object)
                Check "$mode/exact-baseline-port-reverse-imports" (@(Compare-Object ($portExpected|Sort-Object) $actualPort).Count -eq 0) $portU
                foreach($family in $families) {
                    $name=$mode+'/'+$family.Name;$familyDir=Join-Path $dir $family.Name;$null=New-Item -ItemType Directory -Path $familyDir
                    $rawFlags=$flags+$family.Enable
                    Check "$name/no-counterflags" (@($rawFlags | Where-Object {$_ -in $exclusions}).Count -eq 0) $rawFlags
                    $rawProbe=Join-Path $familyDir 'raw-probe.o'
                    Compile (Join-Path $fixture 'compiler_probe.c') $rawProbe $rawFlags
                    $native=Join-Path $familyDir 'raw-native-probe.o'
                    $null=Need $ArmGcc ($nativeFlags+$family.Enable+@($rawProbe,'-o',$native)) ($native+'.link.log')
                    $u=Need $nm @('-u',$native) ($native+'.undefined.txt')
                    $probeDump=Need $objdump @('-drwC',$native) ($native+'.disassembly.txt')
                    Check "$name/unprotected-probe-really-instrumented" (($u+$probeDump) -match $family.Pattern) $u
                    $rawObjects=@()
                    foreach($unit in $units) {
                        $f=if($unit.Common){@($rawFlags | Where-Object {$_ -notin @("-I$fixture","-I$port","-I$CmsisCore")})}else{$rawFlags}
                        $o=Join-Path $familyDir ('raw-'+$unit.Name+'.o');Compile $unit.Source $o $f;$rawObjects+=$o
                    }
                    # Native LTO output proves the actual sensitive common code
                    # as well as every port body, not fat-object fallback bytes.
                    $rawGroup=Join-Path $familyDir 'raw-all-group.o'
                    $null=Need $ArmGcc ($nativeFlags+$family.Enable+$rawObjects+@('-o',$rawGroup)) ($rawGroup+'.link.log')
                    $null=Need $nm @('-u',$rawGroup) ($rawGroup+'.undefined.txt')
                    $dump=Need $objdump @('-drwC',$rawGroup) ($rawGroup+'.disassembly.txt')
                    $seen=@{};$coldSeen=@{}
                    foreach($body in [regex]::Matches($dump,'(?ms)^[0-9a-f]+ <([^>]+)>:\r?\n(.*?)(?=^[0-9a-f]+ <|^Disassembly of section|\z)')) {
                        $function=$body.Groups[1].Value;$text=$body.Groups[2].Value
                        $protected=($function -match '^(fiber_port_|fiber_addr_plausible_|SVC_Handler$|PendSV_Handler$)' -or $function -in $commonSensitive)
                        if($protected) {
                            $seen[$function]=$true
                            Check "$name/protected-body-and-no-cold-edge-$function" (Test-CompilerSensitiveBody $text $hook $ordinary) ($rawGroup+':'+$function)
                        }
                        if($function -in $ordinaryExports) {
                            $coldSeen[$function]=$text
                        }
                        if($text -match $hook) {
                            if($function -match '^fiber_') {
                                Check "$name/raw-hooks-only-frozen-cold-common-$function" ($function -in $ordinary) ($rawGroup+':'+$function)
                            }
                            $inventory.Add([pscustomobject]@{Mode=$mode;Family=$family.Name;Function=$function;Protected=$protected;
                                DeclaredOrdinaryCommon=($function -in $ordinary);Group=$rawGroup})
                        }
                    }
                    foreach($function in $commonSensitive) {Check "$name/real-sensitive-common-body-$function" ($seen.ContainsKey($function)) $rawGroup}
                    foreach($function in $ordinaryExports) {
                        Check "$name/real-ordinary-cold-export-$function" ($coldSeen.ContainsKey($function)) $rawGroup
                        if($family.Name -ne 'ubsan') {
                            Check "$name/raw-hooks-confined-to-ordinary-cold-export-$function" ($coldSeen[$function] -match $family.Pattern) $rawGroup
                        }
                    }
                    # No common cold functions are defined in this group.
                    # Keep its full reverse/import surface exact; never allow
                    # unresolved port helpers or arbitrary compiler callbacks.
                    $rawPortGroup=Join-Path $familyDir 'raw-port-only-group.o'
                    $null=Need $ArmGcc ($nativeFlags+$family.Enable+@($rawObjects[0],$rawObjects[1],'-o',$rawPortGroup)) ($rawPortGroup+'.link.log')
                    $portU=Need $nm @('-u',$rawPortGroup) ($rawPortGroup+'.undefined.txt')
                    $portDump=Need $objdump @('-drwC',$rawPortGroup) ($rawPortGroup+'.disassembly.txt')
                    $actualPort=@([regex]::Matches($portU,'(?m)^\s*U\s+(\S+)\r?$') | ForEach-Object {$_.Groups[1].Value} | Sort-Object)
                    Check "$name/raw-port-exact-reverse-imports-and-no-hooks" (@(Compare-Object ($portExpected|Sort-Object) $actualPort).Count -eq 0 -and
                        $portDump -notmatch $hook) $portU

                    # The executable uses raw protected port objects and real
                    # neutral common objects. Neutral means no enable OR disable
                    # flags; unprotected common wrappers are not a false claim.
                    $executionObjects=@($rawObjects[0],$rawObjects[1]) + @($baselineObjects | Select-Object -Skip 2)
                    $executionGroup=Join-Path $familyDir 'raw-port-neutral-common-group.o'
                    $null=Need $ArmGcc ($nativeFlags+$executionObjects+@('-o',$executionGroup)) ($executionGroup+'.link.log')
                    $u=Need $nm @('-u',$executionGroup) ($executionGroup+'.undefined.txt')
                    $d=Need $objdump @('-drwC',$executionGroup) ($executionGroup+'.disassembly.txt')
                    $actual=@([regex]::Matches($u,'(?m)^\s*U\s+(\S+)\r?$') | ForEach-Object {$_.Groups[1].Value} | Sort-Object)
                    Check "$name/raw-port-exact-runtime-dependencies" (@(Compare-Object $expected $actual).Count -eq 0 -and $d -notmatch $hook) $u
                    $null=Need $readelf @('-hASsW',$executionGroup) ($executionGroup+'.attributes.txt')
                    $cohortText=Defined $rawObjects[1]
                    $m=[regex]::Matches($cohortText,'(?m)^[0-9a-f]+\s+[RD]\s+(fiber_port_context_cohort_\S+)\r?$')
                    Check "$name/single-production-cohort" ($m.Count -eq 1) $cohortText;$cohort=$m[0].Groups[1].Value
                    $m=[regex]::Matches($cohortText,'(?m)^[0-9a-f]+\s+[RD]\s+(fiber_port_storage_cohort_\S+)\r?$')
                    Check "$name/single-production-storage-provider" ($m.Count -eq 1) $cohortText;$storageCohort=$m[0].Groups[1].Value
                    $expectation=Join-Path $familyDir 'expectation.o';Compile (Join-Path $repo 'fiber/port/fiber_port_context_cohort_expectation.c') $expectation $flags
                    $caseFlags=$flags+@('-DEXEC_CASE=0','-DEXEC_WEAK_STARTUP=1');$fixtures=@()
                    foreach($unit in @('startup.S','construct.S','tasks.S','application.c','environment.c','oracle.c')) {
                        $o=Join-Path $familyDir ($unit.Replace('.','-')+'.o');Compile (Join-Path $fixture $unit) $o $caseFlags;$fixtures+=$o
                    }
                    $elf=Join-Path $familyDir 'secure.elf'
                    # Repeating enable options here would instrument neutral
                    # common LTO IR and change the explicit execution boundary.
                    $result=Link $elf (@($fixtures)+@($expectation)+$executionObjects) $flags
                    Check "$name/raw-protected-port-runtime-link" ($result.Code -eq 0) $result.Text;Inspect "$name/raw" $elf
                    $log=Execute "$name/raw" $elf ("PASS:"+$label+"-FULL-RUNTIME") 'AttributesOnlyPortProduction'
                    FullTrace "$name/raw" $elf $log $reserved
                    $compilerCases.Add([pscustomobject]@{Mode=$mode;Family=$family.Name;Enable=$family.Enable;RequiredCounterflags=@();
                        RawAdmission=$true;RawAllGroup=$rawGroup;RawPortGroup=$rawPortGroup;PortExpectedUndefined=$portExpected;
                        RawPortNeutralCommonGroup=$executionGroup;ELF=$elf;
                        PortFlags=$rawFlags;CommonExecutionFlags=$flags;HarnessFlags=$caseFlags;RawPortRuntimeExecuted=$true;
                        CommonRawGeneratedSensitiveBodiesChecked=$commonSensitive;UnprotectedCommonWrappers=$ordinary})
                }
                # Current-source single attribute removals must acquire actual
                # hooks. The controls are compiled, never linked to fake hooks.
                $controlDir=Join-Path $dir 'attribute-controls';$null=New-Item -ItemType Directory -Path $controlDir
                $bootText=[IO.File]::ReadAllText((Join-Path $port 'fiber_port_boot.c'))
                $macroText=[IO.File]::ReadAllText((Join-Path $port 'fiber_portmacro.h'))
                foreach($target in @('fiber_port_hash32_accum','fiber_port_read_r9','fiber_port_control_read','fiber_port_exception_priority_read')) {
                    $isHash=$target -eq 'fiber_port_hash32_accum'
                    $text=if($isHash){$bootText}else{$macroText}
                    $attribute=if($isHash){'FIBER_API_ATTR_SENSITIVE'}else{'FIBER_API_ATTR_INLINE_SENSITIVE'}
                    $pattern='(?m)^([^\r\n]*?)'+$attribute+'([^\r\n]*\r?\nuint32_t '+$target+'\()'
                    Check "$mode/control-exact-source-anchor-$target" ([regex]::Matches($text,$pattern).Count -eq 1) $target
                    $mutated=[regex]::Replace($text,$pattern,'$1$2')
                    $c=Join-Path $controlDir ($target+'.c')
                    $f=$flags+@('-finstrument-functions')
                    if($isHash) {
                        [IO.File]::WriteAllText($c,$mutated)
                    } else {
                        $h=Join-Path $controlDir ($target+'.h')
                        $mutated=[regex]::Replace($mutated,'(?m)^(\s*#\s*include\s*)"([^"]+)"',{
                            param($m) $m.Groups[1].Value+'"'+[IO.Path]::GetFullPath((Join-Path $port $m.Groups[2].Value)).Replace('\','/')+'"'
                        })
                        [IO.File]::WriteAllText($h,$mutated)
                        $source=if($target -eq 'fiber_port_read_r9'){$bootText}else{[IO.File]::ReadAllText((Join-Path $port 'fiber_port.c'))}
                        [IO.File]::WriteAllText($c,('#include "'+$h.Replace('\','/')+'"'+[Environment]::NewLine+$source))
                    }
                    $o=Join-Path $controlDir ($target+'.o');Compile $c $o $f
                    $native=Join-Path $controlDir ($target+'-native.o')
                    $null=Need $ArmGcc ($nativeFlags+@('-finstrument-functions',$o,'-o',$native)) ($native+'.link.log')
                    $u=Need $nm @('-u',$native) ($native+'.undefined.txt')
                    $d=Need $objdump @('-drwC',$native) ($native+'.disassembly.txt')
                    Check "$mode/attribute-removal-rejected-$target" (($u+$d) -match '__cyg_profile_func_(enter|exit)') $native
                }
                # Keep noIPA/noinline and every other canonical attribute;
                # remove only no_profile_instrument_function. Coverage data
                # names are __gcov0.*, not just __gcov_* runtime calls.
                $pattern='(?m)^static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY(\r?\nuint32_t fiber_port_hash32_accum\()'
                Check "$mode/coverage-control-exact-source-anchor" ([regex]::Matches($bootText,$pattern).Count -eq 1) $pattern
                $exceptProfile='static FIBER_API_NOINLINE FIBER_API_NOIPA FIBER_API_NOCLONE FIBER_API_NOICF FIBER_API_USED '+
                    'FIBER_API_NOINSTR FIBER_API_NOSSP FIBER_API_NOSAN FIBER_API_NOCOVERAGE FIBER_GENERAL_REGS_ONLY'
                $c=Join-Path $controlDir 'hash-without-no-profile.c'
                [IO.File]::WriteAllText($c,[regex]::Replace($bootText,$pattern,($exceptProfile+'$1')))
                $o=Join-Path $controlDir 'hash-without-no-profile.o'
                Compile $c $o ($flags+@('-fprofile-arcs','-ftest-coverage'))
                $native=Join-Path $controlDir 'hash-without-no-profile-native.o'
                $null=Need $ArmGcc ($nativeFlags+@('-fprofile-arcs','-ftest-coverage',$o,'-o',$native)) ($native+'.link.log')
                $d=Need $objdump @('-drwC',$native) ($native+'.disassembly.txt')
                $body=[regex]::Match($d,'(?ms)^[0-9a-f]+ <fiber_port_hash32_accum>:\r?\n(.*?)(?=^[0-9a-f]+ <|^Disassembly of section|\z)')
                Check "$mode/coverage-attribute-removal-rejected-in-hot-helper-body" ($body.Success -and $body.Value -match '__gcov0[.]fiber_port_hash32_accum') $native
                # Poison one real sensitive common function with a cold
                # registration call. The exact normal-body predicate must
                # reject its native output, even though raw cold hooks are
                # legitimate elsewhere in the same relocatable group.
                $core=[IO.File]::ReadAllText((Join-Path $repo 'fiber/fiber_core.c'))
                $needle='return fiber_internal_runtime_load_current_context();'
                Check "$mode/cold-edge-control-exact-source-anchor" ([regex]::Matches($core,[regex]::Escape($needle)).Count -eq 1) $needle
                $c=Join-Path $controlDir 'sensitive-cold-edge.c'
                [IO.File]::WriteAllText($c,$core.Replace($needle,('fiber_scheduler_set_pick_next(0, 0);'+[Environment]::NewLine+$needle)))
                $f=@($flags | Where-Object {$_ -notin @("-I$fixture","-I$port","-I$CmsisCore")})+@('-finstrument-functions')
                $o=Join-Path $controlDir 'sensitive-cold-edge.o';Compile $c $o $f
                $native=Join-Path $controlDir 'sensitive-cold-edge-native.o'
                $null=Need $ArmGcc ($nativeFlags+@('-finstrument-functions',$baselineObjects[0],$baselineObjects[1],$o,$baselineObjects[3],$baselineObjects[4],'-o',$native)) ($native+'.link.log')
                $d=Need $objdump @('-drwC',$native) ($native+'.disassembly.txt')
                $body=[regex]::Match($d,'(?ms)^[0-9a-f]+ <fiber_current>:\r?\n(.*?)(?=^[0-9a-f]+ <|^Disassembly of section|\z)')
                Check "$mode/compiled-sensitive-cold-edge-control-rejected" ($body.Success -and
                    !(Test-CompilerSensitiveBody $body.Groups[1].Value $hook $ordinary)) $native

            }
        }
    }
    $compilerCases.ToArray() | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $out 'compiler-adversarial-cases.json') -Encoding ASCII
    $inventory.ToArray() | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $out 'raw-outside-sensitive-functions.json') -Encoding ASCII
    Check 'compiler/adversarial-exact-48-raw-port-cases' ($compilerCases.Count -eq 48 -and
        @($compilerCases | Where-Object {!$_.RawAdmission -or !$_.RawPortRuntimeExecuted -or $_.RequiredCounterflags.Count}).Count -eq 0) $compilerCases.Count
}
