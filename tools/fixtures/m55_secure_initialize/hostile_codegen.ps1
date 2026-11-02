# Loaded by the owning focused runner, sharing its recorded-tool/parser helpers.
function AssertC55SPureCohortProvider([string]$Symbols,[string]$Disassembly,[string]$Name) {
    $symbol=[regex]::Matches($Symbols,'(?m)^([0-9a-f]+) ([0-9a-f]+) [tT] '+[regex]::Escape($Name)+'\r?$')
    if($symbol.Count -ne 1) {throw "Missing exact sized cohort provider: $Name"}
    $begin=[Convert]::ToUInt32($symbol[0].Groups[1].Value,16)
    $end=[uint64]$begin+[Convert]::ToUInt32($symbol[0].Groups[2].Value,16)
    if($end -le $begin) {throw "Empty cohort provider: $Name"}
    $cursor=[uint64]$begin
    $returns=0
    $body=Get-ExactDisassemblyFunction $Disassembly $Name
    foreach($line in ($body -split "`n")) {
        $raw=[regex]::Match($line,'^\s*([0-9a-f]+):\s+(.*)$')
        if(!$raw.Success) {continue}
        $address=[Convert]::ToUInt32($raw.Groups[1].Value,16)
        if($address -ge $end) {continue} # Linker padding is not part of the ELF symbol.
        if($address -ne $cursor) {throw "Noncontiguous cohort provider bytes: $Name"}
        $instruction=[regex]::Match($raw.Groups[2].Value,
            '^((?:[0-9a-f]{4}(?:[0-9a-f]{4})?\s+)+)([a-z][a-z0-9.]*)(?:\s+([^\r\n]*))?$')
        if(!$instruction.Success) {throw "Undecoded cohort provider bytes: $Name / $line"}
        $bytes=$instruction.Groups[1].Value -replace '\s',''
        $opcode=$instruction.Groups[2].Value
        $operands=$instruction.Groups[3].Value.Trim()
        $isReturn=$bytes -eq '4770' -and $opcode -eq 'bx' -and $operands -eq 'lr'
        $isNop=($bytes -eq 'bf00' -or $bytes -eq 'f3af8000') -and $opcode -match '^nop(?:\.[wn])?$' -and !$operands
        if(!$isReturn -and !$isNop) {throw "Effectful cohort provider instruction: $Name / $line"}
        if($isReturn) {++$returns}
        $cursor+=$bytes.Length/2
        if($cursor -gt $end) {throw "Instruction exceeds cohort provider symbol: $Name"}
    }
    if($cursor -ne $end -or $returns -ne 1) {throw "Incomplete cohort provider byte coverage: $Name"}
}

function TestC55SHostile([string[]]$Flags,[string]$Directory,[string]$ReferenceDisassembly,[string[]]$Exports) {
    $null=New-Item -ItemType Directory -Path $Directory
    $adversarial=@('-finstrument-functions','-fstack-protector-all','-fprofile-arcs',
        '-ftest-coverage','-fsanitize=undefined','-fsanitize-coverage=trace-pc')
    # Last occurrence wins. No disabling option follows these hostile settings.
    $hostile=$Flags+$adversarial
    $hostile | Set-Content (Join-Path $Directory 'effective-command-flags.txt') -Encoding ASCII
    $negative=Join-Path $fixture 'contaminated.c'
    $settings=(Recorded $ArmGcc ($hostile+@('-Q','--help=common','-c',$negative,
        '-o',(Join-Path $Directory 'effective-options.o'))) (Join-Path $Directory 'effective-options.txt')).Text
    foreach ($option in @('finstrument-functions','fstack-protector-all','fprofile-arcs','ftest-coverage')) {
        if ($settings -notmatch ('(?m)^\s*-'+$option+'\s+\[enabled\]')) { throw "Hostile option not effective: $option" }
    }
    if ($settings -notmatch '(?m)^\s*-fsanitize-coverage=\s+trace-pc') {
        throw 'Hostile sanitizer coverage not effective'
    }
    # GCC 14's -Q prints an empty fsanitize= value even when active. The actual
    # unannotated control below must acquire __ubsan_* references in every mode.
    # Non-LTO materialized contaminated control proves every detector category
    # really fires. Production below retains its actual requested LTO setting.
    $control=Join-Path $Directory 'contaminated.o'
    $null=Recorded $ArmGcc ($hostile+@('-fno-lto','-c',$negative,'-o',$control)) (Join-Path $Directory 'contaminated-compile.log')
    $controlDis=(Recorded $objdump @('-drwC',$control) (Join-Path $Directory 'contaminated.dis')).Text
    $categories=@('__cyg_profile_func_','__stack_chk_','__gcov','__ubsan_','__sanitizer_cov')
    foreach ($pattern in $categories) {
        if ($controlDis -notmatch $pattern) { throw "Contaminated detector control missed $pattern" }
    }
    $forbidden='__cyg_profile_func_|__stack_chk_|__gcov|__ubsan_|__asan_|__tsan_|__sanitizer_cov|__gnu_mcount_nc|\bmcount\b|__morestack|__chkstk|__aeabi_|\bmem(?:set|cpy|move)\b'
    $private=@('fiber_secure_context_gateway_fail_closed','fiber_secure_context_pool_boot_initialize',
        'fiber_secure_context_pool_allocate','fiber_secure_context_pool_lookup_owned','fiber_secure_context_pool_fail_closed',
        'fiber_secure_context_pool_require_ready','fiber_secure_context_pool_record_is_free',
        'fiber_secure_context_pool_write_stack_seal','fiber_secure_context_pool_stack_seal_is_valid',
        'fiber_secure_context_pool_record_is_valid','fiber_secure_context_pool_c55s_v1_cohort_provider')
    $functions=@($Exports | ForEach-Object {'__acle_se_'+$_})+$private
    $requiredAttributes=@('noinline','noipa','noclone','no_icf','used','no_instrument_function',
        'no_stack_protector','no_profile_instrument_function','no_sanitize_coverage')
    $preprocessed=''
    $objects=@()
    foreach ($name in @('fiber_secure_gateway','fiber_secure_context_gateway','fiber_secure_context_pool')) {
        $object=Join-Path $Directory ($name+'.o')
        $null=Recorded $ArmGcc ($hostile+@('-save-temps=obj','-MMD','-c',(Join-Path $secure ($name+'.c')),
            '-o',$object)) (Join-Path $Directory ($name+'-compile.log'))
        $preprocessed+=(Get-Content (Join-Path $Directory ($name+'.i')) -Raw)+"`n"
        $objects+=$object
    }
    foreach ($name in ($Exports+$private)) {
        $attributeMatches=@([regex]::Matches($preprocessed,'(?m)^(?<attrs>[^\r\n]*__attribute__[^\r\n]*)\r?\n[^\r\n]*\b'+[regex]::Escape($name)+'\s*\('))
        $qualified=$false
        foreach ($match in $attributeMatches) {
            $attributes=$match.Groups['attrs'].Value
            $missing=@($requiredAttributes | Where-Object {$attributes -notmatch ('__attribute__\(\('+$_+'\)\)')})
            if (!$missing.Count -and $attributes -match 'no_sanitize\("address",\s*"undefined",\s*"thread"\)' -and
                    $attributes -match 'target\("general-regs-only"\)' -and
                    ($Exports -notcontains $name -or $attributes -match 'cmse_nonsecure_entry')) { $qualified=$true }
        }
        if (!$qualified) { throw "Missing complete canonical expanded attributes: $name" }
    }
    $elf=Join-Path $Directory 'complete.elf'
    $import=Join-Path $Directory 'complete-import.o'
    $roots=@(($Exports+@('fiber_secure_context_pool_boot_initialize','fiber_secure_context_pool_allocate',
        'fiber_secure_context_pool_lookup_owned')) | ForEach-Object {"-Wl,-u,$_"})
    $null=Recorded $ArmGcc ($hostile+@('-nostdlib','-nostartfiles','-Wl,--entry=0','-Wl,--gc-sections',
        '-Wl,--no-undefined','-Wl,--build-id=none','-Wl,--section-start=.gnu.sgstubs=0x10008000',
        '-T',(Join-Path $fixture 'hostile.ld'),"-Wl,-Map,$Directory/complete.map",
        '-T',(Join-Path $secure 'fiber_secure_context_cohort_contract.ld'),
        "-Wl,--cmse-implib,--out-implib=$import")+$roots+$objects+@('-o',$elf)) (Join-Path $Directory 'complete-link.log')
    AssertImports $import $Exports (Join-Path $Directory 'complete-import.nm')
    $unresolved=(Recorded $nm @('-u',$elf) (Join-Path $Directory 'undefined.nm')).Text
    if ($unresolved.Trim()) { throw 'Complete hostile group acquired external dependencies' }
    $symbols=(Recorded $nm @('-a','-S','-n',$elf) (Join-Path $Directory 'complete.nm')).Text
    $dis=(Recorded $objdump @('-drwC',$elf) (Join-Path $Directory 'complete.dis')).Text
    # Compile, but never execute, undecoded/data/gap counterexamples. The same
    # byte-complete validator must reject each within the exact ELF extent.
    $providerControls=Join-Path $Directory 'cohort-provider-controls.o'
    $null=Recorded $ArmGcc @('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-c',
        (Join-Path $fixture 'cohort_provider_controls.S'),'-o',$providerControls) (Join-Path $Directory 'cohort-provider-controls.log')
    $controlSymbols=(Recorded $nm @('-a','-S','-n',$providerControls) (Join-Path $Directory 'cohort-provider-controls.nm')).Text
    $controlCode=(Recorded $objdump @('-drwC',$providerControls) (Join-Path $Directory 'cohort-provider-controls.dis')).Text
    AssertC55SPureCohortProvider $controlSymbols $controlCode 'cohort_provider_control_valid'
    $providerRejections=@()
    foreach($name in @('udf','undefined','m55_undefined_stc','data','zero_gap','store')) {
        $rejected=$false
        try {AssertC55SPureCohortProvider $controlSymbols $controlCode ('cohort_provider_control_'+$name)}
        catch {$rejected=$true;$providerRejections+=@{Name=$name;Diagnostic=$_.Exception.Message}}
        if(!$rejected) {throw "Impure compiled cohort provider accepted: $name"}
    }
    $providerRejections | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Directory 'cohort-provider-control-rejections.json') -Encoding ASCII
    if (($symbols+"`n"+$dis) -match $forbidden) { throw 'Hostile complete group acquired compiler support/counters' }
    $writable=@([regex]::Matches($symbols,'(?m)^([0-9a-f]+) ([0-9a-f]+) [bBdDgGsScC] (\S+)\r?$'))
    $allowed=@{'fiber_secure_context_pool_image'=480;'fiber_secure_context_pool_state'=4;'fiber_secure_context_gateway_state'=4}
    if ($writable.Count -ne $allowed.Count) { throw 'Unexpected hostile writable symbol count' }
    foreach ($item in $writable) {
        $name=$item.Groups[3].Value
        if (!$allowed.ContainsKey($name) -or [Convert]::ToUInt32($item.Groups[2].Value,16) -ne $allowed[$name]) {
            throw "Unexpected hostile writable storage: $name"
        }
    }
    $securityForms=@('vstr FPCXTNS, [sp, #-4]!','vldr FPCXTNS, [sp], #4','vscclrm {s0-s15, VPR}')
    $referenceForms=@(Get-Instructions (Get-ExactDisassemblyFunction $ReferenceDisassembly '__acle_se_SecureContext_Init') |
        ForEach-Object {$_.Opcode+' '+$_.Operands})
    $securityEvidence=@()
    $addresses=@()
    foreach ($name in $functions) {
        $address=Get-ExactSymbolAddress $symbols $name
        if ($symbols -notmatch ('(?m)^[0-9a-f]+ (?:[0-9a-f]+ )?[tT] '+[regex]::Escape($name)+'\r?$')) {
            throw "Hostile sensitive symbol is not executable: $name"
        }
        if ($addresses -contains $address) { throw "Hostile sensitive identity was folded: $name" }
        $addresses+=$address
        $body=Get-ExactDisassemblyFunction $dis $name
        $code=@(Get-Instructions $body)
        if($name -eq 'fiber_secure_context_pool_c55s_v1_cohort_provider') {
            AssertC55SPureCohortProvider $symbols $dis $name
        }
        $saves=$restores=0
        for ($index=0;$index -lt $code.Count;++$index) {
            $instruction=$code[$index]
            $form=$instruction.Opcode+' '+$instruction.Operands
            if ($instruction.Opcode -match '^v' -or $instruction.Operands -match '(?i)(?:^|[\s,{])[sdq]\d+(?:[-,}\s]|$)') {
                if ($name -notmatch '^__acle_se_' -or $securityForms -notcontains $form -or $referenceForms -notcontains $form) {
                    throw "Ordinary FP/MVE or unqualified security instruction: $name / $form"
                }
                $securityEvidence+=@{Function=$name;Instruction=$instruction.Text;Reference='actual pinned SecureContext_Init'}
                if ($instruction.Opcode -eq 'vstr') { ++$saves }
                if ($instruction.Opcode -eq 'vldr') {
                    ++$restores
                    if ($index -lt 2 -or $code[$index-1].Opcode -ne 'clrm' -or $code[$index-2].Opcode -ne 'vscclrm') {
                        throw 'CMSE context restore is outside the exact register-clearing return sequence'
                    }
                }
                if ($instruction.Opcode -eq 'vscclrm') {
                    $next=$index+1
                    if ($next -ge $code.Count -or $code[$next].Opcode -ne 'clrm') { throw 'CMSE clear lacks integer-register clear' }
                    ++$next
                    if ($next -lt $code.Count -and $code[$next].Opcode -eq 'vldr') { ++$next }
                    if ($next -ge $code.Count -or $code[$next].Opcode -ne 'bxns' -or $code[$next].Operands -ne 'lr') {
                        throw 'CMSE clear/restore is not followed by exact BXNS LR'
                    }
                }
            }
            if ($instruction.Opcode -match '^blx' -or
                ($instruction.Opcode -match '^bx(?:ns)?$' -and $instruction.Operands -ne 'lr')) {
                throw "Unexpected indirect hostile call: $name / $($instruction.Text)"
            }
            if ($instruction.Opcode -match '^b' -and $instruction.Operands -match '^[0-9a-f]+ <([^>+]+)(?:\+[^>]+)?>$') {
                if (($functions+$Exports) -notcontains $Matches[1]) { throw "Unexpected hostile call/branch target $($Matches[1])" }
            }
        }
        if ($saves -ne $restores -or $saves -gt 1) { throw "Unbalanced/noncanonical FPCXTNS save/restore: $name" }
    }
    AssertM55CallerProof $dis 'fiber_secure_context_gateway_c55s_v1_initialize' (Join-Path $Directory 'entry-caller-proof.txt')
    @{Verdict='PASS';Functions=$functions;CanonicalExpandedAttributes=$true;EffectiveHostileFlags=$adversarial;
        ExternalDependencies=@();WritableBytes=488;CMSESecurityInstructions=$securityEvidence;
        OrdinaryFPOrMVE=$false;PureCohortProvider=$true;ProviderByteCoverage='exact sized ELF extent';
        ProviderCompiledControls=@{Positive=1;Rejected=$providerRejections};RuntimeExecution=$false;
        ContaminationControl='materialized non-LTO object, all five dependency categories present'} |
        ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Directory 'codegen-receipt.json') -Encoding ASCII
    Write-Host "PASS hostile complete C55S group: $Directory"
}
