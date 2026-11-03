param(
    [string]$ArmGcc=$env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore=$env:CMSIS_CORE_INCLUDE,
    [string]$BuildRoot
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixture=Join-Path $PSScriptRoot 'fixtures\mpu_start_policy'
if(!$ArmGcc -or !(Test-Path -LiteralPath $ArmGcc -PathType Leaf)) {throw 'Supply existing -ArmGcc'}
if(!$CmsisCore) {$CmsisCore=Join-Path $repo '..\..\..\Drivers\CMSIS\Include'}
$ArmGcc=(Resolve-Path -LiteralPath $ArmGcc).Path
$CmsisCore=(Resolve-Path -LiteralPath $CmsisCore).Path
if(!$BuildRoot) {$BuildRoot=[IO.Path]::GetTempPath()}
$out=Join-Path $BuildRoot ('fiber-mpu-start-policy-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $out -Force
$checks=New-Object System.Collections.Generic.List[object]
$verdict='FAIL'
$profiles=@(
    @{Name='ARM_CM0_MPU';Core=0;Fp=0;Arch=@('-mcpu=cortex-m0plus');Role='ARMV6M';Regions=@(0);Abi=@('soft');Vtor=@(0,1)},
    @{Name='ARM_CM3_MPU';Core=3;Fp=0;Arch=@('-mcpu=cortex-m3');Role='ARMV7M';Regions=@(0);Abi=@('soft');Vtor=@(1)},
    @{Name='ARM_CM4_MPU';Core=4;Fp=1;Arch=@('-mcpu=cortex-m4','-mfpu=fpv4-sp-d16');Role='ARMV7EM';Regions=@(8,16);Abi=@('hard','softfp');Vtor=@(1)},
    @{Name='ARM_CM4_MPU';Core=7;Fp=1;Arch=@('-mcpu=cortex-m7','-mfpu=fpv5-d16');Role='ARMV7EM';Regions=@(8,16);Abi=@('hard','softfp');Vtor=@(1)},
    @{Name='ARM_CM33_MPU';Core=33;Fp=0;Arch=@('-mcpu=cortex-m33');Role='ARMV8M_MAINLINE';Regions=@(8,16);Abi=@('soft');Vtor=@(1)},
    @{Name='ARM_CM55_MPU';Core=55;Fp=0;Arch=@('-mcpu=cortex-m55');Role='ARMV81M_MAINLINE';Regions=@(8,16);Abi=@('soft');Vtor=@(1)},
    @{Name='ARM_CM55F_MPU';Core=55;Fp=1;Arch=@('-march=armv8.1-m.main+fp');Role='ARMV81M_MAINLINE';Regions=@(8,16);Abi=@('hard','softfp');Vtor=@(1)},
    @{Name='ARM_CM55_MVEF_MPU';Core=55;Fp=1;Arch=@('-march=armv8.1-m.main+mve.fp');Role='ARMV81M_MAINLINE';Regions=@(8,16);Abi=@('hard','softfp');Vtor=@(1)},
    @{Name='ARM_CM33F_MPU';Core=33;Fp=1;Arch=@('-mcpu=cortex-m33','-mfpu=fpv5-sp-d16');Role='ARMV8M_MAINLINE';Regions=@(8,16);Abi=@('hard','softfp');Vtor=@(1)}
)
foreach($profile in $profiles) {
    $relative=$profile.Name
    if($profile.Core -ge 33) {$relative+='\non_secure'}
    $profile.Directory=Join-Path $repo ('fiber\port\'+$relative)
}
$inputs=@($PSCommandPath,$ArmGcc,(Join-Path $repo 'mcu_core.h'),(Join-Path $repo 'basic_types.h'))+
    @(Get-ChildItem $fixture,(Join-Path $repo 'fiber'),(Join-Path $repo 'fiber\port'),$CmsisCore -File | Where-Object {$_.Extension -in @('.h','.c')} | Select-Object -ExpandProperty FullName)
$inputs+=@(Get-ChildItem -LiteralPath (Join-Path $repo 'context') -File -Filter '*.h' |
    Select-Object -ExpandProperty FullName)
foreach($directory in @($profiles.Directory | Sort-Object -Unique)) {
    foreach($name in @('fiber_portmacro.h','fiber_port_types.h','fiber_port_boot_types.h')) {
        $path=Join-Path $directory $name
        if(Test-Path -LiteralPath $path) {$inputs+=$path}
    }
}
function HashInputs {
    @($inputs | Sort-Object -Unique | ForEach-Object {Get-FileHash -LiteralPath $_ -Algorithm SHA256} | Select-Object Path,Hash)
}
$before=HashInputs
$before | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-before.json') -Encoding ASCII
function Compile([string[]]$Flags,[string]$Object,[string]$Diagnostic) {
    $saved=$ErrorActionPreference
    try {$ErrorActionPreference='Continue';$lines=@(& $ArmGcc @Flags '-c' (Join-Path $fixture 'probe.c') '-o' $Object 2>&1);$code=$LASTEXITCODE}
    finally {$ErrorActionPreference=$saved}
    $text=($lines | ForEach-Object {"$_"}) -join "`n"
    $text | Set-Content ($Object+'.log') -Encoding ASCII
    @{File=$ArmGcc;Arguments=$Flags+@('-c',(Join-Path $fixture 'probe.c'),'-o',$Object);ExitCode=$code} |
        ConvertTo-Json -Compress -Depth 5 | Add-Content (Join-Path $out 'commands.jsonl') -Encoding ASCII
    if($Diagnostic) {
        if($code -eq 0 -or !$text.Contains($Diagnostic)) {throw "Unsupported preserve-MSP policy was not rejected: $Object"}
    } elseif($code -ne 0) {throw "Supported protected start policy failed: $Object`n$text"}
}
try {
    Write-Host "MPU start-policy evidence: $out"
    & $ArmGcc --version | Set-Content (Join-Path $out 'compiler.txt') -Encoding ASCII
    if($LASTEXITCODE -ne 0) {throw 'Cannot identify compiler'}
    foreach($p in $profiles) {foreach($r in $p.Regions) {foreach($abi in $p.Abi) {foreach($vtor in $p.Vtor) {foreach($opt in @('O2','Os')) {
        $name=$p.Name+'-c'+$p.Core+'-r'+$r+'-'+$abi+'-v'+$vtor+'-'+$opt
        $flags=@('-mthumb','-std=c11',('-'+$opt),'-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-Wundef')+
            $p.Arch+@(('-mfloat-abi='+$abi),'-DFIBER_PORT_BUILD_SELECTED=1',('-DFIBER_PORT_'+$p.Role+'=1'),
            ('-DREWIND_CORE='+$p.Core),('-DREWIND_FP='+$p.Fp),('-DREWIND_VTOR='+$vtor),
            "-I$fixture",('-I'+$p.Directory),"-I$repo","-I$CmsisCore")
        if($r) {$flags+=('-DFIBER_PORT_'+$p.Name.Substring(4)+'_TOTAL_REGIONS='+$r)}
        $default=Join-Path $out ($name+'-default.o')
        $explicit=Join-Path $out ($name+'-one.o')
        Compile $flags $default ''
        Compile ($flags+'-DFIBER_REWIND_MSP=1') $explicit ''
        if((Get-FileHash $default).Hash -ne (Get-FileHash $explicit).Hash) {throw "Default differs from explicit rewind: $name"}
        $diagnostic='[fiber]: '+$p.Name+' requires FIBER_REWIND_MSP=1 for protected first start'
        Compile ($flags+'-DFIBER_REWIND_MSP=0') (Join-Path $out ($name+'-zero.o')) $diagnostic
        $checks.Add(@{Name=$name;DefaultAndOneIdentical=$true;ZeroRejectedFor=$diagnostic})
    }}}}}
    $after=HashInputs
    $after | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'inputs-after.json') -Encoding ASCII
    if(Compare-Object $before $after -Property Path,Hash) {throw 'Start-policy inputs changed during qualification'}
    if($checks.Count -ne 54) {throw 'Unexpected start-policy configuration count'}
    $verdict='PASS'
} finally {
    @{Verdict=$verdict;Configurations=$checks.ToArray();CompileInvocations=3*$checks.Count;Hardware='NOT_RUN';Execution='COMPILE_ONLY'} |
        ConvertTo-Json -Depth 6 | Set-Content (Join-Path $out 'results.json') -Encoding ASCII
    Get-ChildItem $out -Recurse -File | Where-Object {$_.Name -ne 'sha256.csv'} | Get-FileHash -Algorithm SHA256 |
        Select-Object Path,Hash | Export-Csv (Join-Path $out 'sha256.csv') -NoTypeInformation -Encoding ASCII
}
Write-Host "PASS protected MPU start policy: $($checks.Count) configurations; evidence: $out"
