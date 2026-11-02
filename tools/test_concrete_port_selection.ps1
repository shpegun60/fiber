param([string]$ArmGcc=$env:ARM_NONE_EABI_GCC, [string]$BuildRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
$cxx=Join-Path (Split-Path $ArmGcc) 'arm-none-eabi-g++.exe'
if (!(Test-Path -LiteralPath $cxx -PathType Leaf)) { throw 'Missing ARM C++ compiler' }
if (!$BuildRoot) { $BuildRoot=[IO.Path]::GetTempPath() }
$out=Join-Path $BuildRoot ('concrete-selection-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out -Force
$public=Join-Path $out 'public.c'
$detection=Join-Path $out 'detection.c'
[IO.File]::WriteAllText($public, "#include `"fiber/fiber_core.h`"`nFiberContext context;`n")
[IO.File]::WriteAllText($detection, "#include `"fiber/port/fiber_port_select.h`"`ntypedef char detected[(FIBER_EXPECT_ARCH == 1) ? 1 : -1];`n")
$inputs=@($PSCommandPath,$ArmGcc,$cxx)+@(Get-ChildItem (Join-Path $repo 'fiber') -Recurse -File -Filter '*.h' |
    Select-Object -ExpandProperty FullName)
$before=@($inputs | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_} |
    Select-Object Path,Hash)
$before | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII
$cases=New-Object System.Collections.Generic.List[object]
function Compile([string]$Name,[string]$Language,[string]$Source,[string[]]$Flags,[string]$Diagnostic) {
    $compiler=if($Language -eq 'c'){$ArmGcc}else{$cxx}
    $standard=if($Language -eq 'c'){'c11'}else{'c++17'}
    $args=@('-x',$(if($Language -eq 'c'){'c'}else{'c++'}),('-std='+$standard),
        '-mthumb','-mfloat-abi=soft','-ffreestanding','-Werror','-fsyntax-only','-I',$repo)+$Flags+@($Source)
    $old=$ErrorActionPreference
    try {$ErrorActionPreference='Continue';$lines=@(& $compiler @args 2>&1 | ForEach-Object {"$_"});$code=$LASTEXITCODE}
    finally {$ErrorActionPreference=$old}
    $text=$lines -join "`n"
    $log=Join-Path $out ($Name+'-'+$Language+'.log')
    [IO.File]::WriteAllText($log,$text)
    [ordered]@{Compiler=$compiler;Arguments=$args;ExitCode=$code;Log=$log} |
        ConvertTo-Json -Depth 4 -Compress | Add-Content (Join-Path $out 'commands.jsonl') -Encoding ASCII
    if ($Diagnostic) {
        if ($code -eq 0 -or !$text.Contains($Diagnostic)) {throw "Selection negative failed: $Name/$Language`n$text"}
    } elseif ($code -ne 0) {throw "Selection positive failed: $Name/$Language`n$text"}
    $cases.Add([pscustomobject]@{Name=$Name;Language=$Language;Rejected=[bool]$Diagnostic;ExitCode=$code})
}
$classic=@(
    @{Name='m0';Cpu='cortex-m0';Core=0}, @{Name='m0plus';Cpu='cortex-m0plus';Core=0},
    @{Name='m3';Cpu='cortex-m3';Core=3}, @{Name='m4';Cpu='cortex-m4';Core=4},
    @{Name='m7';Cpu='cortex-m7';Core=7})
$v8=@(
    @{Name='m23';Cpu='cortex-m23';Core=23;Arch='ARMV8M_BASELINE';Port='ARM_CM23_NTZ'},
    @{Name='m33';Cpu='cortex-m33';Core=33;Arch='ARMV8M_MAINLINE';Port='ARM_CM33_NTZ'},
    @{Name='m55';Cpu='cortex-m55';Core=55;Arch='ARMV81M_MAINLINE';Port='ARM_CM55_NTZ'})
$retired=@('FIBER_TRANSITIONAL_V8M_RUN_NONSECURE','FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK',
    'FIBER_ALLOW_UNVALIDATED_ARMV8M_BASELINE_RUNTIME','FIBER_ALLOW_UNVALIDATED_ARMV8M_MAINLINE_RUNTIME',
    'FIBER_ALLOW_UNVALIDATED_ARMV81M_RUNTIME','FIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME',
    'FIBER_ALLOW_UNVALIDATED_MVE_RUNTIME','FIBER_ALLOW_UNVALIDATED_PACBTI_RUNTIME','FIBER_TZ_NS')
foreach ($language in @('c','cxx')) {
    foreach ($item in $classic) {
        Compile $item.Name $language $public @(('-mcpu='+$item.Cpu),('-D__CORTEX_M='+$item.Core)) $null
    }
    foreach ($item in $v8) {
        $flags=@(('-mcpu='+$item.Cpu),('-D__CORTEX_M='+$item.Core))
        $diagnostic='ARMv8-M requires a concrete build-selected port'
        Compile ($item.Name+'-auto') $language $public $flags $diagnostic
        Compile ($item.Name+'-explicit') $language $public ($flags+@('-DFIBER_PORT_PROFILE=FIBER_PORT_PROFILE_'+$item.Arch)) $diagnostic
        Compile ($item.Name+'-forced') $language $public ($flags+@('-DFIBER_FORCE_PORT_'+$item.Arch+'=1')) $diagnostic
        Compile ($item.Name+'-detection') $language $detection ($flags+@('-DFIBER_EXPECT_ARCH=FIBER_PORT_'+$item.Arch)) $null
        $selected=$flags+@('-DFIBER_PORT_BUILD_SELECTED=1',('-DFIBER_PORT_'+$item.Arch+'=1'),
            '-I',(Join-Path $repo ('fiber/port/'+$item.Port+'/non_secure')))
        Compile ($item.Name+'-selected') $language $public $selected $null
    }
    foreach ($macro in $retired) {
        $diagnostic=if($macro.StartsWith('FIBER_TRANSITIONAL')){'transitional v8-M settings are retired'}
            elseif($macro -eq 'FIBER_TZ_NS'){'retired FIBER_TZ_NS'}else{'unvalidated runtime opt-ins are retired'}
        foreach ($value in @(0,1)) {
            Compile ($macro+'-'+$value) $language $public @('-mcpu=cortex-m0','-D__CORTEX_M=0',('-D'+$macro+'='+$value)) $diagnostic
        }
    }
}
foreach ($input in $before) {
    if ((Get-FileHash -LiteralPath $input.Path).Hash -cne $input.Hash) {throw "Selection input drift: $($input.Path)"}
}
[ordered]@{Status='PASS';CompilerCases=$cases.Count;Cases=$cases.ToArray();InputDrift=0;
    Scope='C/C++ public storage selection and retired configuration diagnostics; no runtime or board claim'} |
    ConvertTo-Json -Depth 5 | Set-Content (Join-Path $out 'results.json') -Encoding ASCII
Write-Host "PASS concrete selection: $($cases.Count) C/C++ compiler cases; $out"
