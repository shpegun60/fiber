param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture = Join-Path $PSScriptRoot 'fixtures\cm33_secure_isa'
$secure = Join-Path $repo 'fiber\port\ARM_CM33\secure'
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {throw 'Supply existing -ArmGcc'}
if (!$CmsisCore) {$CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include'}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$bin = Split-Path $ArmGcc
$readelf = Join-Path $bin 'arm-none-eabi-readelf.exe'
$objdump = Join-Path $bin 'arm-none-eabi-objdump.exe'
$nm = Join-Path $bin 'arm-none-eabi-gcc-nm.exe'
$generation = Join-Path $secure 'fiber_secure_context_cohort_contract.ld'
foreach ($path in @($readelf, $objdump, $nm, $generation, (Join-Path $CmsisCore 'core_cm33.h'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {throw "Missing ISA test dependency: $path"}
}
if (!$BuildRoot) {$BuildRoot = [IO.Path]::GetTempPath()}
$out = Join-Path $BuildRoot ('fiber-cm33-secure-isa-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out -Force
$commands = Join-Path $out 'commands.jsonl'
$checks = New-Object System.Collections.Generic.List[object]
$failures = New-Object System.Collections.Generic.List[string]
$verdict = 'FAIL'
$exports = @(
    'fiber_secure_gateway_v1_abi_version', 'fiber_secure_gateway_v1_context_port_id',
    'fiber_secure_gateway_v1_context_layout_version', 'fiber_secure_gateway_v1_context_feature_mask',
    'fiber_secure_context_gateway_v1_abi_version', 'fiber_secure_context_gateway_v1_stack_alignment',
    'fiber_secure_context_gateway_v1_max_stack_bytes', 'fiber_secure_context_gateway_v1_max_contexts',
    'fiber_secure_context_gateway_v1_initialize', 'fiber_secure_context_gateway_v1_allocate',
    'fiber_secure_context_gateway_v1_load', 'fiber_secure_context_gateway_v1_save'
)
$inputs = @($PSCommandPath, $ArmGcc, $readelf, $objdump, $nm,
    (Join-Path $repo 'mcu_core.h'), (Join-Path $repo 'basic_types.h'),
    (Join-Path $repo 'fiber\fiber_api_attributes.h')) +
    @(Get-ChildItem $fixture, $secure -File -Recurse | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem $CmsisCore -Filter '*.h' -File -Recurse | Select-Object -ExpandProperty FullName)
function HashInputs {
    @($inputs | Sort-Object -Unique | ForEach-Object {
        Get-FileHash -LiteralPath $_ -Algorithm SHA256
    } | Select-Object Path, Hash)
}
function Recorded([string]$File, [string[]]$Arguments, [string]$Log) {
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $File @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally {$ErrorActionPreference = $old}
    $text = ($lines | ForEach-Object {"$_"}) -join "`n"
    $text | Set-Content -LiteralPath $Log -Encoding ASCII
    @{File = $File; Arguments = $Arguments; ExitCode = $code; Log = $Log} |
        ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath $commands -Encoding ASCII
    [pscustomobject]@{Code = $code; Text = $text}
}
function RequireCommand([string]$File, [string[]]$Arguments, [string]$Log) {
    $result = Recorded $File $Arguments $Log
    if ($result.Code -ne 0) {throw "Command failed ($($result.Code)): $Log`n$($result.Text)"}
    $result.Text
}
function Check([string]$Name, [bool]$Condition, [object]$Evidence) {
    $checks.Add([pscustomobject]@{Name = $Name; Passed = $Condition; Evidence = $Evidence})
    if (!$Condition) {$failures.Add($Name)}
}
function IsaVerdict([string]$Header, [string]$Attributes) {
    # Exact attribute values, not CPU-name substrings or lexicographic versions.
    $required = @(
        @{Text = $Header; Label = 'Class'; Values = @('ELF32')},
        @{Text = $Header; Label = 'Data'; Values = @("2's complement, little endian")},
        @{Text = $Header; Label = 'Machine'; Values = @('ARM')},
        @{Text = $Attributes; Label = 'Tag_CPU_arch_profile'; Values = @('Microcontroller')},
        @{Text = $Attributes; Label = 'Tag_CPU_arch'; Values = @(
            'v6-M', 'v6S-M', 'v7', 'v7E-M', 'v8-M.baseline', 'v8-M.mainline')}
    )
    $arch = ''
    foreach ($field in $required) {
        $matches = [regex]::Matches($field.Text,
            ('(?m)^[ \t]*' + [regex]::Escape($field.Label) + ':[ \t]*([^\r\n]*)\r?$'))
        if ($matches.Count -ne 1) {
            return [pscustomobject]@{Accepted = $false; Arch = $arch; Reason = "missing/duplicate $($field.Label)"}
        }
        $value = $matches[0].Groups[1].Value.Trim()
        if ($field.Label -eq 'Tag_CPU_arch') {$arch = $value}
        if ($value -cnotin $field.Values) {
            return [pscustomobject]@{Accepted = $false; Arch = $arch; Reason = "unsupported $($field.Label): $value"}
        }
    }
    $arm = [regex]::Matches($Attributes, '(?m)^[ \t]*Tag_ARM_ISA_use:[ \t]*([^\r\n]*)\r?$')
    if ($arm.Count -gt 1 -or ($arm.Count -eq 1 -and $arm[0].Groups[1].Value.Trim() -cne 'No')) {
        return [pscustomobject]@{Accepted = $false; Arch = $arch; Reason = 'ARM-state instruction attribute'}
    }
    [pscustomobject]@{Accepted = $true; Arch = $arch; Reason = 'known M-profile ISA at or below ARMv8-M Mainline'}
}
function Flags([object]$Mode, [string]$Cpu = 'cortex-m33', [switch]$PoolOnly) {
    $flags = @("-mcpu=$Cpu", '-mthumb', '-mfloat-abi=soft', '-mgeneral-regs-only', '-mcmse') +
        $Mode.Flags + $base + @('-std=c11', '-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3',
        '-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=256', "-I$secure", "-I$repo")
    if (!$PoolOnly) {$flags += @("-I$fixture", "-I$CmsisCore")}
    $flags
}
function InspectObject([string]$Name, [string]$Object, [bool]$ExpectAccepted, [string]$ExpectedArch) {
    $dir = Split-Path $Object
    $stem = [IO.Path]::GetFileNameWithoutExtension($Object)
    $header = RequireCommand $readelf @('-hW', $Object) (Join-Path $dir ($stem + '-header.txt'))
    $attributes = RequireCommand $readelf @('-AW', $Object) (Join-Path $dir ($stem + '-attributes.txt'))
    $decision = IsaVerdict $header $attributes
    $decision | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dir ($stem + '-isa.json')) -Encoding ASCII
    Check "$Name/input-ISA-ceiling" ($decision.Accepted -eq $ExpectAccepted) $decision
    Check "$Name/input-exact-architecture" ($decision.Arch -ceq $ExpectedArch) $attributes
    $decision
}
function Admission([string]$Name, [object[]]$Inputs, [object]$Image, [bool]$ExpectAccepted) {
    if (!$Inputs.Count) {throw 'Admission must inspect actual input objects'}
    $rejected = @($Inputs | Where-Object {!$_.Accepted})
    $accepted = $rejected.Count -eq 0 -and $Image.IsaAccepted
    Check "$Name/input-AND-final-admission" ($accepted -eq $ExpectAccepted) @{
        Inputs = $Inputs; FinalAccepted = $Image.IsaAccepted; Admitted = $accepted}
}
function InspectImage([string]$Name, [string]$Elf, [string]$Import, [bool]$ExpectAccepted,
        [string]$ExpectedArch) {
    $dir = Split-Path $Elf
    $header = RequireCommand $readelf @('-hW', $Elf) (Join-Path $dir 'elf-header.txt')
    $attributes = RequireCommand $readelf @('-AW', $Elf) (Join-Path $dir 'elf-attributes.txt')
    $decision = IsaVerdict $header $attributes
    $decision | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dir 'isa-decision.json') -Encoding ASCII
    Check "$Name/attribute-ISA-ceiling" ($decision.Accepted -eq ($ExpectedArch -ceq 'v8-M.mainline')) $decision
    Check "$Name/exact-merged-architecture" ($decision.Arch -ceq $ExpectedArch) $attributes
    $symbols = RequireCommand $nm @('-a', '-S', $Elf) (Join-Path $dir 'symbols.txt')
    $undefined = RequireCommand $nm @('-u', $Elf) (Join-Path $dir 'undefined.txt')
    Check "$Name/no-undefined-symbols" ([string]::IsNullOrWhiteSpace($undefined)) $undefined
    $imports = RequireCommand $nm @('--defined-only', $Import) (Join-Path $dir 'imports.txt')
    $names = @([regex]::Matches($imports, '(?m)^\S+\s+\S\s+(\S+)\r?$') |
        ForEach-Object {$_.Groups[1].Value} | Sort-Object)
    Check "$Name/exact-twelve-NSC-imports" ($names.Count -eq 12 -and
        @(Compare-Object @($exports | Sort-Object) $names).Count -eq 0) $names
    $keys = @([regex]::Matches($symbols,
        '(?m)^\S+\s+0*1\s+R\s+(fiber_secure_context_cohort_c33s_g1\S*)\r?$'))
    Check "$Name/private-provider-retained" ($keys.Count -eq 1 -and
        $symbols -match '(?m)^\S+\s+\S+\s+T\s+fiber_secure_context_pool_c33s_v1_cohort_provider\r?$') $symbols
    $assembly = RequireCommand $objdump @('-drwC', $Elf) (Join-Path $dir 'disassembly.txt')
    $lob = @([regex]::Matches($assembly,
        '(?m)^\s*[0-9a-f]+:\s+[0-9a-f]{4}\s+[0-9a-f]{4}\s+(?:dls|le)\s[^\r\n]*'))
    $accepted = $decision.Accepted -and $lob.Count -eq 0
    Check "$Name/attribute-plus-observed-LOB-ceiling" ($accepted -eq $ExpectAccepted) @{
        Attributes = $decision; ObservedLOB = @($lob | ForEach-Object {$_.Value}); Accepted = $accepted}
    [pscustomobject]@{Header = $header; Attributes = $attributes; Assembly = $assembly; IsaAccepted = $accepted}
}
function LinkImage([string]$Name, [string[]]$Flags, [string[]]$Objects, [bool]$ExpectAccepted,
        [string]$ExpectedArch) {
    if (!$ExpectedArch) {$ExpectedArch = if ($ExpectAccepted) {'v8-M.mainline'} else {'v8.1-M.mainline'}}
    $dir = Join-Path $out $Name
    $null = New-Item -ItemType Directory -Path $dir
    $elf = Join-Path $dir 'image.elf'
    $import = Join-Path $dir 'import.o'
    $args = $Flags + @('-save-temps=obj', '-nostdlib', '-nostartfiles', '-Wl,--gc-sections', '-Wl,--no-undefined',
        '-Wl,--build-id=none', '-Wl,--section-start=.gnu.sgstubs=0x10008000',
        "-Wl,--cmse-implib,--out-implib=$import", "-Wl,-Map,$dir/image.map",
        '-T', (Join-Path $fixture 'image.ld'), '-T', $generation) + $Objects + @('-o', $elf)
    $null = RequireCommand $ArmGcc $args (Join-Path $dir 'link.log')
    InspectImage $Name $elf $import $ExpectAccepted $ExpectedArch
}
function ErrorPayloads([string]$Text) {
    @([regex]::Matches($Text,
        '(?m)^.*?:\d+(?::\d+)?: (?:fatal error|error|Error): ([^\r\n]*)\r?$') |
        ForEach-Object {$_.Groups[1].Value})
}
function ParserControls([string]$Header, [string]$Attributes) {
    $controls = @(
        @{Name = 'missing-architecture'; Text = ($Attributes -replace '(?m)^.*Tag_CPU_arch:.*\r?\n?', ''); Why = 'missing/duplicate Tag_CPU_arch'},
        @{Name = 'duplicate-architecture'; Text = ($Attributes + "`n  Tag_CPU_arch: v8-M.mainline"); Why = 'missing/duplicate Tag_CPU_arch'},
        @{Name = 'higher-arch-with-m33-name'; Text = ($Attributes.Replace('Tag_CPU_arch: v8-M.mainline', 'Tag_CPU_arch: v8.1-M.mainline') + "`n  Tag_CPU_name: cortex-m33"); Why = 'unsupported Tag_CPU_arch: v8.1-M.mainline'},
        @{Name = 'architecture-suffix'; Text = $Attributes.Replace('Tag_CPU_arch: v8-M.mainline', 'Tag_CPU_arch: v8-M.mainline-hostile'); Why = 'unsupported Tag_CPU_arch: v8-M.mainline-hostile'},
        @{Name = 'unknown-future-architecture'; Text = $Attributes.Replace('Tag_CPU_arch: v8-M.mainline', 'Tag_CPU_arch: v9-M.mainline'); Why = 'unsupported Tag_CPU_arch: v9-M.mainline'},
        @{Name = 'missing-profile'; Text = ($Attributes -replace '(?m)^.*Tag_CPU_arch_profile:.*\r?\n?', ''); Why = 'missing/duplicate Tag_CPU_arch_profile'},
        @{Name = 'wrong-profile'; Text = $Attributes.Replace('Tag_CPU_arch_profile: Microcontroller', 'Tag_CPU_arch_profile: Application'); Why = 'unsupported Tag_CPU_arch_profile: Application'},
        @{Name = 'ARM-state'; Text = ($Attributes + "`n  Tag_ARM_ISA_use: Yes"); Why = 'ARM-state instruction attribute'},
        @{Name = 'empty-attributes'; Text = ''; Why = 'missing/duplicate Tag_CPU_arch_profile'}
    )
    foreach ($control in $controls) {
        $control.Text | Set-Content -LiteralPath (Join-Path $out ('parser-' + $control.Name + '.txt')) -Encoding ASCII
        $decision = IsaVerdict $Header $control.Text
        Check ('parser/' + $control.Name) (!$decision.Accepted -and $decision.Reason -ceq $control.Why) $decision
    }
    foreach ($control in @(
        @{Name = 'wrong-machine'; Text = $Header.Replace('ARM', 'AArch64'); Why = 'unsupported Machine: AArch64'},
        @{Name = 'duplicate-class'; Text = ($Header + "`n  Class: ELF32"); Why = 'missing/duplicate Class'},
        @{Name = 'empty-header'; Text = ''; Why = 'missing/duplicate Class'}
    )) {
        $decision = IsaVerdict $control.Text $Attributes
        Check ('parser/' + $control.Name) (!$decision.Accepted -and $decision.Reason -ceq $control.Why) $decision
    }
}
$before = HashInputs
$before | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'inputs-before.json') -Encoding ASCII
try {
    Write-Host "CM33 Secure ISA evidence: $out"
    $null = RequireCommand $ArmGcc @('--version') (Join-Path $out 'compiler.txt')
    $null = RequireCommand $readelf @('--version') (Join-Path $out 'readelf.txt')
    $base = @('-ffreestanding', '-fno-builtin', '-fno-common', '-ffunction-sections', '-fdata-sections',
        '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-fno-instrument-functions',
        '-fno-stack-protector', '-fno-profile-arcs', '-fno-test-coverage', '-fno-sanitize=all',
        '-fno-profile', '-fno-stack-check', '-fno-sanitize-coverage=trace-pc',
        '-Wall', '-Wextra', '-Werror', '-Wundef')
    $modes = @(
        @{Name = 'o2'; Flags = @('-O2')}, @{Name = 'os'; Flags = @('-Os')},
        @{Name = 'o2-lto'; Flags = @('-O2', '-flto')}, @{Name = 'os-lto'; Flags = @('-Os', '-flto')}
    )
    $parserTested = $false
    foreach ($mode in $modes) {
        $dir = Join-Path $out $mode.Name
        $null = New-Item -ItemType Directory -Path $dir
        $flags = Flags $mode
        $objects = @()
        $inputDecisions = @()
        foreach ($unit in @(
            @{Name = 'identity'; File = 'fiber_secure_gateway.c'},
            @{Name = 'context'; File = 'fiber_secure_context_gateway.c'},
            @{Name = 'pool'; File = 'fiber_secure_context_pool.c'}
        )) {
            $object = Join-Path $dir ($unit.Name + '.o')
            $compileFlags = if ($unit.Name -eq 'pool') {Flags $mode -PoolOnly} else {$flags}
            $compileArgs = $compileFlags + @('-save-temps=obj', '-MD', '-MF',
                (Join-Path $dir ($unit.Name + '.d')), '-c', (Join-Path $secure $unit.File), '-o', $object)
            $null = RequireCommand $ArmGcc $compileArgs (Join-Path $dir ($unit.Name + '.log'))
            $objects += $object
            $inputDecisions += InspectObject ($mode.Name + '/' + $unit.Name) $object $true 'v8-M.mainline'
            if ($unit.Name -eq 'pool') {
                $dependencies = [IO.File]::ReadAllText((Join-Path $dir 'pool.d'))
                Check ($mode.Name + '/pool-no-CMSIS-dependency') ($dependencies -notmatch '(?i)(CMSIS|core_cm33|main\.h)') $dependencies
            }
        }
        $consumer = Join-Path $dir 'consumer.o'
        $null = RequireCommand $ArmGcc ($flags + @('-save-temps=obj', '-MD', '-c',
            (Join-Path $fixture 'consumer.c'), '-o', $consumer)) (Join-Path $dir 'consumer.log')
        $consumerDecision = InspectObject ($mode.Name + '/consumer') $consumer $true 'v8-M.mainline'
        $positive = LinkImage ($mode.Name + '-m33') $flags (@($consumer) + $objects) $true
        Admission ($mode.Name + '-m33') ($inputDecisions + @($consumerDecision)) $positive $true
        if (!$parserTested) {ParserControls $positive.Header $positive.Attributes; $parserTested = $true}
        $helperConsumer = Join-Path $dir 'helper-consumer.o'
        $null = RequireCommand $ArmGcc ($flags + @('-DCM33_ISA_WITH_HELPER=1', '-save-temps=obj', '-MD',
            '-c', (Join-Path $fixture 'consumer.c'), '-o', $helperConsumer)) (Join-Path $dir 'helper-consumer.log')
        $helperConsumerDecision = InspectObject ($mode.Name + '/helper-consumer') $helperConsumer $true 'v8-M.mainline'
        foreach ($cpu in @('cortex-m3', 'cortex-m55')) {
            $helper = Join-Path $dir ($cpu + '-helper.o')
            # Native helper intentionally survives a normal or LTO parent link unchanged.
            $helperFlags = @("-mcpu=$cpu", '-mthumb', '-mfloat-abi=soft', '-mgeneral-regs-only',
                '-fno-lto', $mode.Flags[0], '-std=c11') + $base
            $null = RequireCommand $ArmGcc ($helperFlags + @('-save-temps=obj', '-MD', '-c',
                (Join-Path $fixture 'memory_helper.c'), '-o', $helper)) (Join-Path $dir ($cpu + '-helper.log'))
            $helperArch = if ($cpu -eq 'cortex-m3') {'v7'} else {'v8.1-M.mainline'}
            $helperDecision = InspectObject ($mode.Name + '/' + $cpu + '-helper') $helper ($cpu -eq 'cortex-m3') $helperArch
            $image = LinkImage ($mode.Name + '-' + $cpu + '-helper') $flags (@($helperConsumer) + $objects + @($helper)) ($cpu -eq 'cortex-m3')
            Admission ($mode.Name + '-' + $cpu + '-helper') ($inputDecisions + @($helperConsumerDecision, $helperDecision)) $image ($cpu -eq 'cortex-m3')
            $body = RequireCommand $objdump @('-d', '--disassemble=cm33_isa_memory_helper',
                (Join-Path $out ($mode.Name + '-' + $cpu + '-helper\image.elf'))) (Join-Path $dir ($cpu + '-helper-final.txt'))
            Check ($mode.Name + '/' + $cpu + '/helper-retained') ($body -match '(?m)^\s*[0-9a-f]+ <cm33_isa_memory_helper>:\r?$') $body
            $hasDls = $body -match '(?m)^\s*[0-9a-f]+:\s+[0-9a-f]{4}\s+[0-9a-f]{4}\s+dls\s'
            $hasLe = $body -match '(?m)^\s*[0-9a-f]+:\s+[0-9a-f]{4}\s+[0-9a-f]{4}\s+le\s'
            if ($cpu -eq 'cortex-m55') {
                Check ($mode.Name + '/actual-M55-dls-le-counterexample') ($hasDls -and $hasLe) $body
            } else {
                Check ($mode.Name + '/compatible-lower-ISA-helper') (!$hasDls -and !$hasLe) $body
            }
        }
        # Mechanism probes are isolated fixtures, not alternative production guards.
        foreach ($kind in @('SOURCE', 'FUNCTION')) {
            $probe = Join-Path $dir ($kind + '-ceiling-helper.o')
            $probeFlags = @('-mcpu=cortex-m55', '-mthumb', '-mfloat-abi=soft', '-mgeneral-regs-only',
                '-fno-lto', $mode.Flags[0], '-std=c11', "-DCM33_ISA_${kind}_CEILING=1") + $base
            $probeResult = Recorded $ArmGcc ($probeFlags + @('-save-temps=obj', '-MD', '-c',
                (Join-Path $fixture 'memory_helper.c'), '-o', $probe)) (Join-Path $dir ($kind + '-ceiling.log'))
            if ($kind -eq 'SOURCE') {
                $errors = @(ErrorPayloads $probeResult.Text)
                $unexpected = @($errors | Where-Object {
                    $_ -cnotmatch '^selected processor does not support `(?:dls|le) [^'']+'' in Thumb mode$'
                })
                Check ($mode.Name + '/prototype-native-source-ceiling') ($probeResult.Code -ne 0 -and
                    $errors.Count -ge 2 -and $unexpected.Count -eq 0 -and
                    ($errors -join "`n") -cmatch 'support `dls ' -and
                    ($errors -join "`n") -cmatch 'support `le ' -and !(Test-Path -LiteralPath $probe)) $errors
                $m33Probe = Join-Path $dir 'SOURCE-ceiling-m33.o'
                $m33Flags = @($probeFlags | ForEach-Object {if ($_ -ceq '-mcpu=cortex-m55') {'-mcpu=cortex-m33'} else {$_}})
                $null = RequireCommand $ArmGcc ($m33Flags + @('-save-temps=obj', '-MD', '-c',
                    (Join-Path $fixture 'memory_helper.c'), '-o', $m33Probe)) (Join-Path $dir 'SOURCE-ceiling-m33.log')
                Check ($mode.Name + '/prototype-native-source-ceiling-m33-control') (Test-Path -LiteralPath $m33Probe) $m33Probe
            } else {
                Check ($mode.Name + '/prototype-function-target-compiles') ($probeResult.Code -eq 0) $probeResult.Text
                if ($probeResult.Code -eq 0) {
                    $functionImage = LinkImage ($mode.Name + '-function-ceiling') $flags (@($helperConsumer) + $objects + @($probe)) $false
                    Check ($mode.Name + '/prototype-function-target-removes-observed-LOB') (
                        $functionImage.Assembly -cnotmatch '(?m)^\s*[0-9a-f]+:\s+[0-9a-f]{4}\s+[0-9a-f]{4}\s+(?:dls|le)\s') $functionImage.Attributes
                }
            }
        }
        if ($mode.Flags -contains '-flto') {
            foreach ($kind in @('plain', 'SOURCE')) {
                $probe = Join-Path $dir ($kind + '-lto-helper.o')
                $probeFlags = @('-mcpu=cortex-m55', '-mthumb', '-mfloat-abi=soft', '-mgeneral-regs-only',
                    '-std=c11') + $mode.Flags + $base
                if ($kind -eq 'SOURCE') {$probeFlags += '-DCM33_ISA_SOURCE_CEILING=1'}
                $null = RequireCommand $ArmGcc ($probeFlags + @('-save-temps=obj', '-MD', '-c',
                    (Join-Path $fixture 'memory_helper.c'), '-o', $probe)) (Join-Path $dir ($kind + '-lto-helper.log'))
                $probeDecision = InspectObject ($mode.Name + '/' + $kind + '-lto-helper') $probe $false 'v8.1-M.mainline'
                $probeName = $mode.Name + '-' + $kind + '-LTO-attribute-loss'
                $probeImage = LinkImage $probeName $flags (@($helperConsumer) + $objects + @($probe)) $false 'v8-M.mainline'
                Admission $probeName ($inputDecisions + @($helperConsumerDecision, $probeDecision)) $probeImage $false
                $probeBody = RequireCommand $objdump @('-d', '--disassemble=cm33_isa_memory_helper',
                    (Join-Path $out ($probeName + '\image.elf'))) (Join-Path $dir ($kind + '-lto-helper-final.txt'))
                Check ($mode.Name + '/' + $kind + '/actual-LTO-attribute-loss-counterexample') (
                    $probeBody -cmatch '(?m)^\s*[0-9a-f]+ <cm33_isa_memory_helper>:\r?$' -and
                    $probeBody -cmatch '(?m)^\s*[0-9a-f]+:\s+[0-9a-f]{4}\s+[0-9a-f]{4}\s+dls\s' -and
                    $probeBody -cmatch '(?m)^\s*[0-9a-f]+:\s+[0-9a-f]{4}\s+[0-9a-f]{4}\s+le\s') $probeImage.Attributes
            }
        }
        $wrong = Join-Path $dir 'wrong-m55-pool.o'
        $null = RequireCommand $ArmGcc ((Flags $mode 'cortex-m55' -PoolOnly) + @('-save-temps=obj',
            '-MD', '-c', (Join-Path $secure 'fiber_secure_context_pool.c'), '-o', $wrong)) (Join-Path $dir 'wrong-m55-pool.log')
        $wrongDecision = InspectObject ($mode.Name + '/wrong-M55-pool') $wrong $false 'v8.1-M.mainline'
        $wrongInputs = @($consumer, $objects[0], $objects[1], $wrong)
        $lto = $mode.Flags -contains '-flto'
        $wrongArch = if ($lto) {'v8-M.mainline'} else {'v8.1-M.mainline'}
        # The LTO output can look compatible; reject the original higher-ISA pool input too.
        $wrongImage = LinkImage ($mode.Name + '-wrong-M55-pool') $flags $wrongInputs $lto $wrongArch
        Check ($mode.Name + '/scoped-pool-target-removes-observed-LOB') (
            $wrongImage.Assembly -cnotmatch '(?m)^\s*[0-9a-f]+:\s+[0-9a-f]{4}\s+[0-9a-f]{4}\s+(?:dls|le)\s') $wrongImage.Attributes
        Admission ($mode.Name + '-wrong-M55-pool') @($consumerDecision, $inputDecisions[0], $inputDecisions[1], $wrongDecision) $wrongImage $false
        foreach ($cpu in @('cortex-m33', 'cortex-m55')) {
            $macroLog = Join-Path $dir ($cpu + '-macros.txt')
            $macros = RequireCommand $ArmGcc ((Flags $mode $cpu -PoolOnly) + @('-dM', '-E',
                (Join-Path $fixture 'memory_helper.c'))) $macroLog
            Check ($mode.Name + '/' + $cpu + '/normal-flags-macro-truth') (
                $macros -cmatch '(?m)^#define __ARM_ARCH_8M_MAIN__ 1\r?$' -and
                $macros -cmatch '(?m)^#define __ARM_FEATURE_CMSE 3\r?$' -and
                $macros -cmatch '(?m)^#define __SOFTFP__ 1\r?$' -and
                $macros -cnotmatch '(?m)^#define (?:__ARM_FP|__ARM_FEATURE_MVE|__ARM_ARCH_8_1M_MAIN__|__ARM_FEATURE_LOB|__ARM_PCS_VFP)\s') $macroLog
        }
    }
    if ($failures.Count -ne 0) {throw ("ISA regression failures: " + ($failures -join ', '))}
    $verdict = 'PASS'
} finally {
    $after = HashInputs
    $after | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'inputs-after.json') -Encoding ASCII
    $beforeLines = @($before | ForEach-Object {$_.Path + '=' + $_.Hash})
    $afterLines = @($after | ForEach-Object {$_.Path + '=' + $_.Hash})
    $drift = @(Compare-Object $beforeLines $afterLines)
    if ($drift.Count -ne 0) {$verdict = 'FAIL'; $failures.Add('input-drift')}
    $checks.ToArray() | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $out 'checks.json') -Encoding ASCII
    @{Verdict = $verdict; Checks = $checks.Count; Failures = $failures.ToArray();
        Admission = 'all inspected input objects AND final ELF'; Drift = $drift; Evidence = $out;
        ExecutedFirmware = $false; ISAAttributeRule = 'exact known M-profile <= ARMv8-M Mainline';
        ObservedOpcodeVeto = 'encoded dls/le in final objdump; not exhaustive opcode validation'} |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $out 'receipt.json') -Encoding ASCII
    Get-ChildItem -LiteralPath $out -File -Recurse | Where-Object {$_.Name -ne 'artifact-hashes.json'} |
        ForEach-Object {Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256} |
        Select-Object Path, Hash | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $out 'artifact-hashes.json') -Encoding ASCII
    if ($drift.Count -ne 0) {throw "Inputs changed during ISA test: $out"}
}
Write-Host "PASS: CM33 Secure ISA ($($checks.Count) checks); evidence $out"
