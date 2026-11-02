param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosRoot = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$BuildRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) { throw 'Supply existing -ArmGcc' }
if (!$CmsisCore) { $CmsisCore = Join-Path $repo '..\..\..\Drivers\CMSIS\Include' }
if (!$FreeRtosRoot) { $FreeRtosRoot = Join-Path $repo '..\..\..\..\_reference\FreeRTOS-Kernel' }
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
$FreeRtosRoot = (Resolve-Path -LiteralPath $FreeRtosRoot).Path
$port = Join-Path $repo 'fiber\port\ARM_CM55_SECURE_ONLY\secure'
$fixture = Join-Path $PSScriptRoot 'fixtures\cm55_secure_only'
$reference = Join-Path $FreeRtosRoot 'portable\GCC\ARM_CM55_NTZ\non_secure'
$bin = Split-Path $ArmGcc
$nm = Join-Path $bin 'arm-none-eabi-nm.exe'
$objdump = Join-Path $bin 'arm-none-eabi-objdump.exe'
$objcopy = Join-Path $bin 'arm-none-eabi-objcopy.exe'
$readelf = Join-Path $bin 'arm-none-eabi-readelf.exe'
$gxx = Join-Path $bin 'arm-none-eabi-g++.exe'
foreach ($path in @($nm,$objdump,$objcopy,$readelf,$gxx,(Join-Path $CmsisCore 'core_cm55.h'))) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing test dependency: $path" }
}
if (!$BuildRoot) { $BuildRoot = [IO.Path]::GetTempPath() }
$out = Join-Path $BuildRoot ('cm55-secure-only-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out
$checks = New-Object System.Collections.Generic.List[object]
$commands = Join-Path $out 'commands.jsonl'
$verdict = 'FAIL'
function Recorded([string]$Program,[string[]]$Arguments,[string]$Log) {
    $prior = $ErrorActionPreference
    try { $ErrorActionPreference='Continue'; $lines=@(& $Program @Arguments 2>&1); $code=$LASTEXITCODE }
    finally { $ErrorActionPreference=$prior }
    $text = ($lines | ForEach-Object { "$_" }) -join "`n"
    $text | Set-Content -LiteralPath $Log -Encoding ASCII
    @{Program=$Program;Arguments=$Arguments;ExitCode=$code;Log=$Log} |
        ConvertTo-Json -Depth 5 -Compress | Add-Content -LiteralPath $commands -Encoding ASCII
    [pscustomobject]@{Code=$code;Text=$text}
}
function Run([string]$Program,[string[]]$Arguments,[string]$Log) {
    $result = Recorded $Program $Arguments $Log
    if ($result.Code -ne 0) { throw "Command failed: $Log`n$($result.Text)" }
    $result.Text
}
function Check([string]$Name,[bool]$Passed,[object]$Evidence) {
    $checks.Add([pscustomobject]@{Name=$Name;Passed=$Passed;Evidence=$Evidence})
    if (!$Passed) { throw "C5SO construction/manifest gate failed: $Name" }
}
function Dump-Words([string]$Object,[string]$Section,[string]$Output) {
    $null = Run $objcopy @('--dump-section',($Section+'='+$Output),$Object) ($Output+'.log')
    $bytes = [IO.File]::ReadAllBytes($Output)
    if ($bytes.Length % 4) { throw "Malformed word table: $Output" }
    @(for ($i=0; $i -lt $bytes.Length; $i+=4) { [BitConverter]::ToUInt32($bytes,$i) })
}
function Function-Text([string]$Disassembly,[string]$Name) {
    $match = [regex]::Match($Disassembly, '(?ms)^[0-9a-f]+ <'+[regex]::Escape($Name)+'>:\r?\n(?<body>.*?)(?=^Disassembly of section|\z)')
    if (!$match.Success) { throw "Missing actual generated function: $Name" }
    $match.Groups['body'].Value.ToLowerInvariant()
}
function Check-OrderedSubset([string]$Name,[string]$Body,[string[]]$Patterns) {
    $cursor = 0
    foreach ($pattern in $Patterns) {
        $regex = New-Object Text.RegularExpressions.Regex($pattern)
        $matches = $regex.Matches($Body)
        Check ($Name+'/'+$pattern) ($matches.Count -eq 1 -and $matches[0].Index -ge $cursor) $matches.Count
        $cursor = $matches[0].Index+$matches[0].Length
    }
}
$inputs = @($PSCommandPath,$ArmGcc,$nm,$objdump,$objcopy,$readelf,$gxx,
    (Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h')) +
    @(Get-ChildItem -LiteralPath $fixture -Recurse -File | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath $port -File | Where-Object {$_.Extension -in '.c','.h'} | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath (Join-Path $repo 'fiber') -File -Filter '*.h' | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath (Join-Path $repo 'fiber\port') -File -Filter '*.h' | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath $CmsisCore -Recurse -File -Filter '*.h' | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath (Join-Path $FreeRtosRoot 'include') -File -Filter '*.h' | Select-Object -ExpandProperty FullName) +
    @(Get-ChildItem -LiteralPath $reference -File | Where-Object {$_.Extension -in '.c','.h'} | Select-Object -ExpandProperty FullName)
$before = @($inputs | Sort-Object -Unique | ForEach-Object { Get-FileHash -LiteralPath $_ } | Select-Object Path,Hash)
$before | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'inputs-before.json') -Encoding ASCII
try {
    $head = Run 'git.exe' @('-C',$FreeRtosRoot,'rev-parse','HEAD') (Join-Path $out 'reference-head.log')
    Check 'reference/pinned-head' ($head.Trim() -ceq 'a50edad08b29052631aa469d4df6e6ec7ff68878') $head
    $status = Run 'git.exe' @('-C',$FreeRtosRoot,'status','--porcelain=v1','--untracked-files=all','--ignored') (Join-Path $out 'reference-status.log')
    Check 'reference/clean-worktree' ([string]::IsNullOrWhiteSpace($status)) $status
    $null = Run $ArmGcc @('--version') (Join-Path $out 'compiler.log')
    $base = @('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-mcmse','-std=c11','-g0',
        '-ffreestanding','-fno-builtin','-fno-common','-ffunction-sections','-fdata-sections',
        '-fno-unwind-tables','-fno-asynchronous-unwind-tables',"-I$fixture","-I$CmsisCore")
    $own = @('-Wall','-Wextra','-Werror','-Wundef','-DFIBER_PORT_BUILD_SELECTED=1',
        '-DFIBER_PORT_ARMV81M_MAINLINE=1','-DFIBER_SCHEDULER_BASEPRI=128',"-I$port","-I$repo")
    $refFlags = @("-I$reference",('-I'+(Join-Path $FreeRtosRoot 'include')))
    $forward = @('fiber_port_context_init','fiber_port_runtime_memory_barrier','fiber_port_panic_wait',
        'fiber_port_require_scheduler_configuration_environment','fiber_port_runtime_prepare_start',
        'fiber_port_runtime_select_first','fiber_port_runtime_start_first','fiber_port_runtime_schedule')
    $expectedU = @('fiber_addr_plausible_code','fiber_addr_plausible_ram',
        'fiber_internal_runtime_current_context_slot','fiber_internal_runtime_port_abi_v1_anchor',
        'fiber_internal_runtime_publish_current_context','fiber_internal_runtime_require_current_context',
        'fiber_internal_runtime_select_scheduler_candidate','fiber_internal_task_return','fiber_panic','memcpy')
    foreach ($language in 'c','c++') {
        $compiler = if ($language -ceq 'c') {$ArmGcc} else {$gxx}
        $standard = if ($language -ceq 'c') {'-std=c11'} else {'-std=c++17'}
        $object = Join-Path $out ('public-'+$language.Replace('+','p')+'.o')
        $null = Run $compiler @('-mcpu=cortex-m55','-mthumb','-mfloat-abi=soft','-mcmse',
            '-x',$language,$standard,'-Wall','-Wextra','-Werror','-DFIBER_PORT_BUILD_SELECTED=1',
            '-DFIBER_PORT_ARMV81M_MAINLINE=1',"-I$port","-I$repo",'-c',
            (Join-Path $fixture 'public.c'),'-o',$object) ($object+'.log')
        $publicSymbols = Run $nm @('-u',$object) ($object+'.undefined')
        Check ('public/'+$language+'/caller-storage-identity') (
            $publicSymbols.Contains('fiber_port_storage_cohort_arm_cm55_secure_only_v1_r0')) $publicSymbols
    }
    foreach ($opt in 'O2','Os') {
        $dir = Join-Path $out $opt
        $null = New-Item -ItemType Directory -Path $dir
        $objects = @()
        foreach ($unit in 'fiber_port','fiber_port_boot') {
            $object = Join-Path $dir ($unit+'.o')
            $null = Run $ArmGcc ($base + $own + @(('-'+$opt),'-save-temps=obj','-MD','-c',
                (Join-Path $port ($unit+'.c')),'-o',$object)) (Join-Path $dir ($unit+'.log'))
            $null = Run $objdump @('-drwC',$object) ($object+'.dis')
            $null = Run $readelf @('-A',$object) ($object+'.attributes')
            $objects += $object
        }
        $group = Join-Path $dir 'port-group.o'
        $null = Run $ArmGcc (@('-r','-nostdlib')+$objects+@('-o',$group)) (Join-Path $dir 'group.log')
        $symbols = Run $nm @('-g',$group) ($group+'.nm')
        foreach ($symbol in $forward + @('SVC_Handler','PendSV_Handler')) {
            Check ($opt+'/definition/'+$symbol) ([regex]::Matches($symbols,"(?m)^\S+ T $symbol`r?$").Count -eq 1) $group
        }
        $definedForward = @([regex]::Matches($symbols,'(?m)^\S+ T (fiber_port_(?:context_init|runtime_\w+|panic_wait|require_scheduler_configuration_environment))\r?$') |
            ForEach-Object {$_.Groups[1].Value} | Where-Object {$_ -ne 'fiber_port_runtime_prepare'})
        Check ($opt+'/exact-forward-surface') (!(Compare-Object ($forward|Sort-Object) ($definedForward|Sort-Object))) $definedForward
        $undefined = Run $nm @('-u',$group) ($group+'.undefined')
        $actualU = @([regex]::Matches($undefined,'(?m)^\s+U (\S+)\r?$') | ForEach-Object {$_.Groups[1].Value})
        Check ($opt+'/exact-reverse-integration-surface') (!(Compare-Object ($expectedU|Sort-Object) ($actualU|Sort-Object))) $actualU
        $geo = Join-Path $dir 'geometry.o'
        $null = Run $ArmGcc ($base+$own+@(('-'+$opt),'-c',(Join-Path $fixture 'geometry.c'),'-o',$geo)) ($geo+'.log')
        $words = Dump-Words $geo '.rodata.c5so_geometry' ($geo+'.bin')
        $expected = [uint32[]]@(76,72,0,4,0x4335534f,0x10001,2,10,72,76,4294967293,4294967289,1,0,0,0,0)
        Check ($opt+'/numeric-secure-layout') (($words -join ',') -ceq ($expected -join ',')) $words
        foreach ($unit in 'port','portasm') {
            $object = Join-Path $dir ('reference-'+$unit+'.o')
            $null = Run $ArmGcc ($base+$refFlags+@(('-'+$opt),'-save-temps=obj','-MD','-c',
                (Join-Path $reference ($unit+'.c')),'-o',$object)) ($object+'.log')
            $null = Run $objdump @('-drwC',$object) ($object+'.dis')
            $null = Run $readelf @('-A',$object) ($object+'.attributes')
        }
        $refGeo = Join-Path $dir 'reference-geometry.o'
        $null = Run $ArmGcc ($base+$refFlags+@(('-'+$opt),'-c',
            (Join-Path $fixture 'reference_geometry.c'),'-o',$refGeo)) ($refGeo+'.log')
        $refWords = Dump-Words $refGeo '.rodata.c5so_reference_geometry' ($refGeo+'.bin')
        Check ($opt+'/actual-reference-tuple') (($refWords -join ',') -ceq '8,1,0,0,0,0,0,0') $refWords
        $macros = Run $ArmGcc ($base+$refFlags+@(('-'+$opt),'-dM','-E',(Join-Path $reference 'port.c'))) (Join-Path $dir 'reference-macros.txt')
        Check ($opt+'/actual-reference-secure-exc-return') ($macros -match '(?m)^#define portINITIAL_EXC_RETURN \( 0xfffffffd \)\r?$') $macros.Length
        $fiberDisassembly = Get-Content -LiteralPath (Join-Path $dir 'fiber_port.o.dis') -Raw
        $referenceDisassembly = Get-Content -LiteralPath (Join-Path $dir 'reference-portasm.o.dis') -Raw
        $registers = '\{r2, r3, r4, r5, r6, r7, r8, r9, sl, fp\}'
        $pendSvTransfers = @('mrs\s+r0, psp',('stmdb(?:\.w)?\s+r0!, '+$registers),
            'str\s+r0, \[r1, #0\]',('ldmia(?:\.w)?\s+r0!, '+$registers),
            'msr\s+psplim, r2','msr\s+psp, r0','bx\s+r3')
        Check-OrderedSubset ($opt+'/fiber/PendSV-transfer-subset') (Function-Text $fiberDisassembly 'PendSV_Handler') $pendSvTransfers
        Check-OrderedSubset ($opt+'/reference/PendSV-transfer-subset') (Function-Text $referenceDisassembly 'PendSV_Handler') $pendSvTransfers
        Check-OrderedSubset ($opt+'/fiber/first-restore-subset') (Function-Text $fiberDisassembly 'SVC_Handler') @(
            ('ldmia(?:\.w)?\s+r0!, '+$registers),'msr\s+psplim, r2','msr\s+psp, r0','bx\s+r3')
        Check-OrderedSubset ($opt+'/reference/first-restore-subset') (Function-Text $referenceDisassembly 'vRestoreContextOfFirstTask') @(
            'ldmia(?:\.w)?\s+r0!, \{r1, r2\}','msr\s+psplim, r1','adds\s+r0, #32','msr\s+psp, r0','bx\s+r2')
    }
    $negativeCases = @(
        @{Name='nonsecure';Flags=@();Remove='-mcmse';Diagnostic='requires a Secure CMSE level 3 build'},
        @{Name='nonsecure-bank-0';Flags=@('-DFIBER_TZ_NS=0');Remove='';Diagnostic='cannot target the Non-secure register bank'},
        @{Name='nonsecure-bank-1';Flags=@('-DFIBER_TZ_NS=1');Remove='';Diagnostic='cannot target the Non-secure register bank'},
        @{Name='fp';Flags=@('-mfpu=fpv5-sp-d16','-mfloat-abi=hard');Remove='';Diagnostic='does not permit an FP register ABI'},
        @{Name='mve';Flags=@('-D__ARM_FEATURE_MVE=1');Remove='';Diagnostic='does not permit MVE'},
        @{Name='pac';Flags=@('-D__ARM_FEATURE_PAC=1');Remove='';Diagnostic='does not permit PAC'},
        @{Name='pac-default';Flags=@('-D__ARM_FEATURE_PAC_DEFAULT=1');Remove='';Diagnostic='does not permit PAC'},
        @{Name='pauth';Flags=@('-D__ARM_FEATURE_PAUTH=1');Remove='';Diagnostic='does not permit PAC'},
        @{Name='pauth-default';Flags=@('-D__ARM_FEATURE_PAUTH_DEFAULT=1');Remove='';Diagnostic='does not permit PAC'},
        @{Name='bti';Flags=@('-D__ARM_FEATURE_BTI=1');Remove='';Diagnostic='does not permit BTI'},
        @{Name='wrong-device';Flags=@('-DFIBER_TEST_CM33_DEVICE=1');Remove='';Diagnostic='manifest requires CMSIS __CORTEX_M == 55'},
        @{Name='missing-vtor';Flags=@('-D__VTOR_PRESENT=0');Remove='';Diagnostic='requires __VTOR_PRESENT == 1'},
        @{Name='priority-zero';Flags=@('-D__NVIC_PRIO_BITS=0');Remove='';Diagnostic='requires 1..8 implemented NVIC priority bits'},
        @{Name='priority-nine';Flags=@('-D__NVIC_PRIO_BITS=9');Remove='';Diagnostic='requires 1..8 implemented NVIC priority bits'},
        @{Name='runtime-override';Flags=@('-DFIBER_PORT_RUNTIME_SELECTABLE=1');Remove='';Diagnostic='runtime-selectable state must not be predefined'}
    )
    foreach ($macro in 'CM4_MPU','CM33_MPU','CM33F_MPU','CM55_MPU','CM55F_MPU','CM55_MVEF_MPU','MPU') {
        foreach ($value in 0,8,16) {
            $negativeCases += @{Name=('mpu-'+$macro+'-'+$value);Flags=@('-DFIBER_PORT_'+$macro+'_TOTAL_REGIONS='+$value);
                Remove='';Diagnostic='is non-MPU; select a separate MPU profile'}
        }
    }
    foreach ($case in $negativeCases) {
        $flags = @($base | Where-Object {$_ -cne $case.Remove}) + $own + $case.Flags
        $result = Recorded $ArmGcc ($flags+@('-fsyntax-only',(Join-Path $fixture 'geometry.c'))) (Join-Path $out ($case.Name+'.log'))
        Check ('negative/'+$case.Name) ($result.Code -ne 0 -and $result.Text.Contains($case.Diagnostic)) $result.Code
    }
    $after = @($before | ForEach-Object {Get-FileHash -LiteralPath $_.Path} | Select-Object Path,Hash)
    $after | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'inputs-after.json') -Encoding ASCII
    Check 'inputs/no-drift' (!(Compare-Object $before $after -Property Path,Hash)) $before.Count
    $verdict = 'PASS'
} finally {
    [pscustomobject]@{Status=$verdict;Checks=$checks.Count;Cases=$checks.ToArray();Inputs=$before.Count;
        Scope='Staged C5SO actual-reference compilation, numeric geometry, exact symbols, ordered transfer subsets and manifest negatives; not closed whole-body parity, final ELF/LTO or execution'} |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'results.json') -Encoding ASCII
    @(Get-ChildItem -LiteralPath $out -Recurse -File | Where-Object {$_.Name -ne 'artifacts.json'} |
        ForEach-Object {Get-FileHash -LiteralPath $_.FullName} | Select-Object Path,Hash) |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'artifacts.json') -Encoding ASCII
    Write-Host "C5SO staged manifest result: $verdict; $out"
}
