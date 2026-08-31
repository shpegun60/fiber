param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosKernel = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$BuildRoot,
    [ValidateSet("-O2", "-Os")]
    [string]$Optimization = "-O2",
    [switch]$KeepBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ExpectedFreeRtosCommit = "a50edad08b29052631aa469d4df6e6ec7ff68878"

function Find-ArmGcc {
    if (-not [string]::IsNullOrWhiteSpace($ArmGcc)) {
        if (Test-Path -LiteralPath $ArmGcc) {
            return (Resolve-Path -LiteralPath $ArmGcc).Path
        }
        throw "ARM_NONE_EABI_GCC points to a missing file: $ArmGcc"
    }

    $command = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    foreach ($root in @("C:\ST", "C:\Program Files", "C:\Program Files (x86)")) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }
        $found = Get-ChildItem -LiteralPath $root -Recurse `
            -Filter arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }

    throw "arm-none-eabi-gcc.exe not found"
}

function Test-CmsisPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    foreach ($header in @(
            "cmsis_compiler.h", "core_cm0.h", "core_cm0plus.h", "core_cm23.h",
            "core_cm3.h", "core_cm4.h", "core_cm7.h", "core_cm33.h")) {
        if (-not (Test-Path -LiteralPath (Join-Path $Path $header))) {
            return $false
        }
    }
    return $true
}

function Find-CmsisCore {
    if (Test-CmsisPath $CmsisCore) {
        return (Resolve-Path -LiteralPath $CmsisCore).Path
    }

    $workspace = Join-Path $env:USERPROFILE "Documents\my_workspace"
    foreach ($candidate in @(
            (Join-Path $RepoRoot "..\..\..\Drivers\CMSIS\Include"),
            (Join-Path $workspace "gnu\gnu-tools-for-stm32\linkdb\tests\tmp_external\STM32_Embedded_CPP\Targets\Nucleo_F446RE\Drivers\CMSIS\Include"),
            (Join-Path $workspace "gnu\gnu-tools-for-stm32\linkdb\tests\tmp_external\STM32_FreeRTOS-Kernel\Drivers\CMSIS\Core\Include"))) {
        if (Test-CmsisPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "CMSIS core headers not found"
}

function Find-FreeRtosKernel {
    if (-not [string]::IsNullOrWhiteSpace($FreeRtosKernel)) {
        if (Test-Path -LiteralPath (Join-Path $FreeRtosKernel "portable\GCC")) {
            return (Resolve-Path -LiteralPath $FreeRtosKernel).Path
        }
        throw "FREERTOS_KERNEL_REFERENCE is not a FreeRTOS Kernel checkout: $FreeRtosKernel"
    }

    foreach ($candidate in @(
            (Join-Path $RepoRoot "..\..\..\..\_reference\FreeRTOS-Kernel"),
            (Join-Path $RepoRoot "_reference\FreeRTOS-Kernel"))) {
        if (Test-Path -LiteralPath (Join-Path $candidate "portable\GCC")) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "Pinned local FreeRTOS Kernel checkout not found"
}

function Get-DisassemblyFunctionBody {
    param(
        [string]$Disassembly,
        [string]$Symbol,
        [string]$Path
    )

    $pattern = '(?ms)^[0-9a-fA-F]+\s+<' + [regex]::Escape($Symbol) +
            '>:\r?\n(?<body>.*?)(?=^[0-9a-fA-F]+\s+<[^>]+>:\r?\n|\z)'
    $match = [regex]::Match($Disassembly, $pattern)
    if (-not $match.Success) {
        throw "Assembly parity cannot find $Symbol in $Path"
    }
    return $match.Groups['body'].Value
}

function Assert-OrderedPatterns {
    param(
        [string]$Body,
        [string[]]$Patterns,
        [string]$Label
    )

    $cursor = 0
    foreach ($pattern in $Patterns) {
        $match = [regex]::Match($Body.Substring($cursor), $pattern,
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $match.Success) {
            throw "$Label lost ordered generated instruction: $pattern`n$Body"
        }
        $cursor += $match.Index + $match.Length
    }
}

function Assert-AbsentPatterns {
    param(
        [string]$Body,
        [string[]]$Patterns,
        [string]$Label
    )

    foreach ($pattern in $Patterns) {
        if ([regex]::IsMatch($Body, $pattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            throw "$Label contains forbidden generated instruction: $pattern`n$Body"
        }
    }
}

function Write-CmsisMainHeader {
    param(
        [string]$Directory,
        [string]$CoreHeader,
        [int]$VtorPresent,
        [int]$MpuPresent,
        [int]$FpuPresent,
        [int]$FpuUsed,
        [int]$DspPresent
    )

    $content = @"
#ifndef MAIN_H_
#define MAIN_H_
#define __MPU_PRESENT ${MpuPresent}U
#define __VTOR_PRESENT ${VtorPresent}U
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT ${FpuPresent}U
#define __FPU_USED ${FpuUsed}U
#define __DSP_PRESENT ${DspPresent}U
#define __SAUREGION_PRESENT 0U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
#define __DTCM_PRESENT 0U
#define __ITCM_PRESENT 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14,
    HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12,
    BusFault_IRQn = -11,
    UsageFault_IRQn = -10,
    SecureFault_IRQn = -9,
    SVCall_IRQn = -5,
    DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2,
    SysTick_IRQn = -1,
    DummyDevice_IRQn = 0
} IRQn_Type;
#include "$CoreHeader"
#endif
"@
    Set-Content -LiteralPath (Join-Path $Directory "main.h") `
        -Value $content -Encoding ASCII
}

function Invoke-Compile {
    param(
        [string]$Compiler,
        [string[]]$Arguments,
        [string]$Label
    )

    & $Compiler @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label compile failed"
    }
}

function Get-ObjectDisassembly {
    param(
        [string]$Objdump,
        [string]$ObjectPath
    )

    $result = (& $Objdump -dr $ObjectPath) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed: $ObjectPath"
    }
    return $result
}

function Assert-ReferenceIdentity {
    param(
        [string]$KernelRoot,
        [hashtable]$ExpectedFiles
    )

    $commit = ((& git -C $KernelRoot rev-parse HEAD) -join "").Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot read pinned FreeRTOS commit"
    }
    if ($commit -ne $ExpectedFreeRtosCommit) {
        throw "FreeRTOS reference drifted: expected $ExpectedFreeRtosCommit, got $commit"
    }

    foreach ($relativePath in $ExpectedFiles.Keys) {
        $path = Join-Path $KernelRoot $relativePath
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Pinned FreeRTOS artifact is missing: $relativePath"
        }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if ($actual -ne $ExpectedFiles[$relativePath]) {
            throw "Pinned FreeRTOS artifact drifted: $relativePath`nExpected: $($ExpectedFiles[$relativePath])`nActual:   $actual"
        }
    }
}

function Assert-ProductionPortCoverage {
    param(
        [string]$RepositoryRoot,
        [object[]]$PortDefinitions,
        [string[]]$StagedRuntimeProfiles
    )

    $portRoot = Join-Path $RepositoryRoot "fiber\port"
    $actualProfiles = @(Get-ChildItem -LiteralPath $portRoot -Recurse `
            -Filter "fiber_port.c" -File |
        ForEach-Object {
            $_.DirectoryName.Substring($RepositoryRoot.Length + 1)
        } |
        Sort-Object -Unique)
    $coveredProfiles = @($PortDefinitions | Where-Object {
            ($null -eq $_.PSObject.Properties["Auxiliary"]) -and
            (($null -eq $_.PSObject.Properties["Staged"]) -or
             ($_.Staged -eq 0))
        } | ForEach-Object { $_.ProfileDir } |
        Sort-Object -Unique)
    $stagedDefinitionProfiles = @($PortDefinitions | Where-Object {
            ($null -ne $_.PSObject.Properties["Staged"]) -and
            ($_.Staged -ne 0)
        } | ForEach-Object { $_.ProfileDir } |
        Sort-Object -Unique)
    $stagedProfiles = @($StagedRuntimeProfiles | Sort-Object -Unique)
    $stagedCoveredOverlap = @($stagedProfiles | Where-Object {
        $coveredProfiles -contains $_
    })
    if ($stagedCoveredOverlap.Count -ne 0) {
        throw "A staged runtime profile must not also claim complete generated parity: $($stagedCoveredOverlap -join ', ')"
    }
    if (Compare-Object -ReferenceObject $stagedProfiles `
            -DifferenceObject $stagedDefinitionProfiles) {
        throw "Staged generated-assembly definitions and inventory must match exactly"
    }

    foreach ($profile in $stagedProfiles) {
        if ($actualProfiles -notcontains $profile) {
            throw "Staged runtime profile has no fiber_port.c: $profile"
        }

        $record = Join-Path (Join-Path $RepositoryRoot $profile) `
            "FREERTOS_PARITY.md"
        if (-not (Test-Path -LiteralPath $record)) {
            throw "Staged runtime profile has no FreeRTOS parity record: $profile"
        }

        $macro = Join-Path (Join-Path $RepositoryRoot $profile) `
            "fiber_portmacro.h"
        if (-not (Test-Path -LiteralPath $macro)) {
            throw "Staged runtime profile has no selected port macro header: $profile"
        }
        $macroText = Get-Content -LiteralPath $macro -Raw
        if ($macroText -notmatch '(?m)^\s*#define\s+FIBER_PORT_RUNTIME_SELECTABLE\s+0\s*$') {
            throw "Staged runtime profile must remain non-selectable until complete parity: $profile"
        }
    }

    $knownProfiles = @($coveredProfiles + $stagedProfiles | Sort-Object -Unique)
    $coverageDifference = @(Compare-Object -ReferenceObject $actualProfiles `
        -DifferenceObject $knownProfiles)
    if ($coverageDifference.Count -ne 0) {
        $details = ($coverageDifference | ForEach-Object {
            "$($_.SideIndicator) $($_.InputObject)"
        }) -join "`n"
        throw "Generated assembly parity production-port inventory drifted:`n$details"
    }

    foreach ($profile in $coveredProfiles) {
        $record = Join-Path (Join-Path $RepositoryRoot $profile) `
            "FREERTOS_PARITY.md"
        if (-not (Test-Path -LiteralPath $record)) {
            throw "Production port has no FreeRTOS parity record: $profile"
        }
    }
}

function Assert-MechanismParity {
    param(
        [string]$PortName,
        [string]$Mechanism,
        [string]$ReferenceDisassembly,
        [string]$ReferenceSymbol,
        [string[]]$ReferencePatterns,
        [string]$ReferencePath,
        [string]$FiberDisassembly,
        [string]$FiberSymbol,
        [string[]]$FiberPatterns,
        [string]$FiberPath,
        [string[]]$DifferenceIds,
        [string]$Ledger
    )

    $referenceBody = Get-DisassemblyFunctionBody `
        -Disassembly $ReferenceDisassembly -Symbol $ReferenceSymbol `
        -Path $ReferencePath
    $fiberBody = Get-DisassemblyFunctionBody `
        -Disassembly $FiberDisassembly -Symbol $FiberSymbol -Path $FiberPath

    Assert-OrderedPatterns -Body $referenceBody -Patterns $ReferencePatterns `
        -Label "$PortName FreeRTOS $Mechanism"
    Assert-OrderedPatterns -Body $fiberBody -Patterns $FiberPatterns `
        -Label "$PortName Fiber $Mechanism"

    if (($null -eq $DifferenceIds) -or ($DifferenceIds.Count -eq 0)) {
        throw "$PortName $Mechanism has no explicit difference rationale"
    }
    foreach ($differenceId in $DifferenceIds) {
        if ($Ledger.IndexOf($differenceId,
                [System.StringComparison]::Ordinal) -lt 0) {
            throw "$PortName $Mechanism references undocumented difference: $differenceId"
        }
    }

    Write-Host ("PASS {0,-14} {1,-18} {2} -> {3}" -f `
        $PortName, $Mechanism, $ReferenceSymbol, $FiberSymbol)
}

$expectedReferenceFiles = @{
    "portable\GCC\ARM_CM0\port.c" = "44A9D18193BF606BB8B6CC2B3341C207981C473D666A0C7075038E4FC18E1DF9"
    "portable\GCC\ARM_CM0\portasm.c" = "1696254D07EBE24CD635067B0449E8C156E948967D07CA2B0E09B0D577C55395"
    "portable\GCC\ARM_CM0\portasm.h" = "403910894BD2A6F588AFA3998584AE27D3336F6A7AE0F32FCE20DD2D0FF9B5C9"
    "portable\GCC\ARM_CM0\portmacro.h" = "80593EEB9E1A6F89A913E9AAE19427B820B4090D7BA8CE81A265B5E823986B42"
    "portable\GCC\ARM_CM3\port.c" = "0580691C59032249C53D572CF25A207C50417F0EF2BA0FC3A1588C6CB050C645"
    "portable\GCC\ARM_CM3\portmacro.h" = "7E736EACB99D77167528350526C178D85B2E6DB9775E906D80CC37005B9EB495"
    "portable\GCC\ARM_CM4F\port.c" = "1D26914A131EC8AE2E15F67EEB5D349C1CF8CB90CB432FFE6473773F06B35054"
    "portable\GCC\ARM_CM4F\portmacro.h" = "F2C7DAFBDC35335B74A5428C82E0585225B43227AC4E584332B36CAE0A2E3047"
    "portable\GCC\ARM_CM7\r0p1\port.c" = "13C9DE33A6856EF44522AB7B785C1196FF5739579DAB0FD2144E231E7393A32C"
    "portable\GCC\ARM_CM7\r0p1\portmacro.h" = "859485FB0ECCF94CB357C95E562427411F406CE2385078EDFFB8A9D3C70B8205"
    "portable\GCC\ARM_CM23_NTZ\non_secure\port.c" = "BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A"
    "portable\GCC\ARM_CM23_NTZ\non_secure\portasm.c" = "E15BDECFD24AB85165B69E3496E6FA644E5FF9C36EFBB3FFE6975FD5D7C9806C"
    "portable\GCC\ARM_CM23_NTZ\non_secure\portasm.h" = "185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C"
    "portable\GCC\ARM_CM23_NTZ\non_secure\portmacro.h" = "23709D8EE3DE532A8394EAD05414FCF4FB4B37C94B5288ACF1FB1B829AA3F50E"
    "portable\GCC\ARM_CM23_NTZ\non_secure\portmacrocommon.h" = "324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2"
    "portable\GCC\ARM_CM33_NTZ\non_secure\port.c" = "BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A"
    "portable\GCC\ARM_CM33_NTZ\non_secure\portasm.c" = "DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5"
    "portable\GCC\ARM_CM33_NTZ\non_secure\portasm.h" = "185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C"
    "portable\GCC\ARM_CM33_NTZ\non_secure\portmacro.h" = "F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B"
    "portable\GCC\ARM_CM33_NTZ\non_secure\portmacrocommon.h" = "324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2"
    "portable\GCC\ARM_CM55_NTZ\non_secure\port.c" = "BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A"
    "portable\GCC\ARM_CM55_NTZ\non_secure\portasm.c" = "DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5"
    "portable\GCC\ARM_CM55_NTZ\non_secure\portasm.h" = "185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C"
    "portable\GCC\ARM_CM55_NTZ\non_secure\portmacro.h" = "B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420"
    "portable\GCC\ARM_CM55_NTZ\non_secure\portmacrocommon.h" = "324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2"
    "portable\ThirdParty\GCC\ARM_TFM\README.md" = "43EAC6335CBC2B3B90FA53817B844774B5DCCDC8D477308C2E83128F83B4EE0A"
    "portable\ThirdParty\GCC\ARM_TFM\os_wrapper_freertos.c" = "9A6242DB2128A3220495C6739078959CF56D56649F1FFB2634C6430603938901"
    "portable\GCC\ARM_CM33\non_secure\port.c" = "BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A"
    "portable\GCC\ARM_CM33\non_secure\portasm.c" = "6F39F5CB7A24766DF3FA025E41E0E502301550136151B5E2EABDFA9AC4E42D60"
    "portable\GCC\ARM_CM33\secure\secure_context.c" = "E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72"
    "portable\GCC\ARM_CM33\secure\secure_context_port.c" = "B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E"
    "portable\GCC\ARM_CM33\secure\secure_init.c" = "1B8444698089651C6415D48A2B6716BA6C6DC32F71C51B679F5A8A9A3968DE55"
    "portable\GCC\ARM_CM33\secure\secure_init.h" = "7704E518DFAAE39170274B7DD924B1A214FFFB12DC37C050E7D3457B5AA0E149"
    "portable\GCC\ARM_CM3_MPU\port.c" = "B94311759D4B807017F56669BDE818215215076A20C301A10D3C9DAE3D736676"
    "portable\GCC\ARM_CM3_MPU\portmacro.h" = "FF720AEDBE44344752224173B3BBA316D675AD47C44103BBC8CAB984B0A98A68"
    "portable\GCC\ARM_CM4_MPU\port.c" = "CC9B731BC23E52A91D7D37B5DDA16D7B501CFB4D3B3A3C8229C355C66662BF59"
    "portable\GCC\ARM_CM4_MPU\portmacro.h" = "FA624BD1CAFAD461C86D1858E5AA9328EDEFE71D0E19A328746F85A52E7C35AD"
}

$ports = @(
    [pscustomobject]@{
        Name = "ARM_CM0"; CpuArgs = @("-mcpu=cortex-m0")
        CoreHeader = "core_cm0.h"; Vtor = 0; Mpu = 0; Fpu = 0; Dsp = 0
        ProfileDir = "fiber\port\ARM_CM0"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV6M=1")
        ReferenceDir = "portable\GCC\ARM_CM0"; ReferenceSource = "portasm.c"
        ReferenceDefines = @()
    },
    [pscustomobject]@{
        Name = "ARM_CM0PLUS"; CpuArgs = @("-mcpu=cortex-m0plus")
        CoreHeader = "core_cm0plus.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 0
        ProfileDir = "fiber\port\ARM_CM0"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV6M=1")
        ReferenceDir = "portable\GCC\ARM_CM0"; ReferenceSource = "portasm.c"
        ReferenceDefines = @()
    },
    [pscustomobject]@{
        Name = "ARM_CM0_MPU"; CpuArgs = @("-mcpu=cortex-m0plus")
        CoreHeader = "core_cm0plus.h"; Vtor = 1; Mpu = 1; Fpu = 0; Dsp = 0
        ProfileDir = "fiber\port\ARM_CM0_MPU"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV6M=1")
        ReferenceDir = "portable\GCC\ARM_CM0"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
    },
    [pscustomobject]@{
        Name = "ARM_CM3"; CpuArgs = @("-mcpu=cortex-m3")
        CoreHeader = "core_cm3.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 0
        ProfileDir = "fiber\port\ARM_CM3"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV7M=1")
        ReferenceDir = "portable\GCC\ARM_CM3"; ReferenceSource = "port.c"
        ReferenceDefines = @()
    },
    [pscustomobject]@{
        Name = "ARM_CM4"; CpuArgs = @("-mcpu=cortex-m4", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard")
        CoreHeader = "core_cm4.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM4"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV7EM=1")
        ReferenceDir = "portable\GCC\ARM_CM4F"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1")
    },
    [pscustomobject]@{
        Name = "ARM_CM7_R0P1"; CpuArgs = @("-mcpu=cortex-m7", "-mfpu=fpv5-d16", "-mfloat-abi=hard")
        CoreHeader = "core_cm7.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM7\r0p1"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV7EM=1")
        ReferenceDir = "portable\GCC\ARM_CM7\r0p1"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1")
    },
    [pscustomobject]@{
        Name = "ARM_CM23_NTZ"; CpuArgs = @("-mcpu=cortex-m23")
        CoreHeader = "core_cm23.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 0
        ProfileDir = "fiber\port\ARM_CM23_NTZ\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_BASELINE=1")
        ReferenceDir = "portable\GCC\ARM_CM23_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @()
    },
    [pscustomobject]@{
        Name = "ARM_CM33_NTZ"; CpuArgs = @("-mcpu=cortex-m33")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33_NTZ\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM33_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @()
    },
    [pscustomobject]@{
        Name = "ARM_CM55_NTZ"; CpuArgs = @("-mcpu=cortex-m55", "-mfloat-abi=soft")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_NTZ\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @()
    },
    # ARM_CM55_MPU is a complete build-selected protected runtime. It remains
    # outside the global auto-selector, like the other MPU profiles.
    [pscustomobject]@{
        Name = "ARM_CM55_MPU_8"; CpuArgs = @("-mcpu=cortex-m55", "-mfloat-abi=soft")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MPU\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
    },
    [pscustomobject]@{
        Name = "ARM_CM55_MPU_16"; CpuArgs = @("-mcpu=cortex-m55", "-mfloat-abi=soft")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MPU\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_NTZ_CONSTRUCTION"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_NTZ\non_secure"; FiberSource = "fiber_port_boot.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1")
    },
    # Slices 1-3 keep the protected scalar-FP constructor, first-start SVC,
    # and later FP-aware PendSV as independently audited objects. The forward
    # runtime facade remains deliberately absent.
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_CONSTRUCTION"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_boot.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_CONSTRUCTION_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_boot.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    # MVE-FP MPU uses the same protected basic constructor as scalar FP, but
    # its compiler facts and exact C55W cohort are deliberately separate.
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_CONSTRUCTION"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_boot.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_CONSTRUCTION_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_boot.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    # The protected scalar-FP SVC object restores only the basic first image.
    # The later extended FP save/restore belongs exclusively to its PendSV
    # slice, so this remains an independently audited auxiliary object.
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_SVC_8"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_SVC_16"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_SVC_8_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_SVC_16_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
        Auxiliary = 1
    },
    # MVE-FP changes the compiler and exact C55W cohort, not the FreeRTOS
    # protected basic first restore. PendSV remains a later independent slice.
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_SVC_8"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_SVC_16"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_SVC_8_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_SVC_16_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_PENDSV_8"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_pendsv.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_PENDSV_16"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_pendsv.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_PENDSV_8_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_pendsv.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_MPU_PENDSV_16_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_MPU\non_secure"; FiberSource = "fiber_port_pendsv.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55F_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
        Auxiliary = 1
    },
    # MVE-FP uses the same protected 54-word backing store and conditional
    # s16-s31 / copied low-FP backbone as scalar FP. Its separate C55W cohort
    # requires +mve.fp and proves that neither implementation adds VPR state.
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_PENDSV_8"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_pendsv.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_PENDSV_16"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_pendsv.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_PENDSV_8_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_pendsv.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_MPU_PENDSV_16_SOFTFP"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=softfp")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_MPU\non_secure"; FiberSource = "fiber_port_pendsv.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1", "-DFIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
        Auxiliary = 1
    },
    # Construction and SVC remain independently audited auxiliary objects;
    # the complete MVE-FP runtime below owns the selected PendSV mechanics.
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_NTZ_CONSTRUCTION"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_NTZ\non_secure"; FiberSource = "fiber_port_boot.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1")
        Auxiliary = 1
    },
    # The MVE-FP SVC object owns only first start; PendSV stays in its own
    # source file so both exception transfer paths remain independently auditable.
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_NTZ_SVC"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_NTZ\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55_MVEF_NTZ_PENDSV"
        CpuArgs = @("-march=armv8.1-m.main+mve.fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55_MVEF_NTZ\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_MVE=1")
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_NTZ_SVC"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_NTZ\non_secure"; FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1")
    },
    [pscustomobject]@{
        Name = "ARM_CM55F_NTZ_PENDSV"
        CpuArgs = @("-march=armv8.1-m.main+fp", "-mfloat-abi=hard")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55F_NTZ\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM55_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1")
    },
    [pscustomobject]@{
        Name = "ARM_CM33_TFM"; CpuArgs = @("-mcpu=cortex-m33")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33_TFM\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM33_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @()
    },
    [pscustomobject]@{
        Name = "ARM_CM33_SECURE_CONTEXT_CONSTRUCTION"
        CpuArgs = @("-mcpu=cortex-m33")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 1; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM33\non_secure"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1")
        ReferenceExtraIncludes = @("portable\GCC\ARM_CM33\secure")
    },
    [pscustomobject]@{
        Name = "ARM_CM33_SECURE_CONTEXT_ALLOCATOR"
        CpuArgs = @("-mcpu=cortex-m33", "-mcmse")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33\secure"
        FiberSource = "fiber_secure_context_gateway.c"
        FiberDefines = @(
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3u",
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=256u")
        ReferenceDir = "portable\GCC\ARM_CM33\secure"
        ReferenceSource = "secure_context.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM33_SECURE_CONTEXT_DEPRIORITIZE"
        CpuArgs = @("-mcpu=cortex-m33", "-mcmse")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33\secure"
        FiberSource = "fiber_secure_context_gateway.c"
        FiberDefines = @(
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3u",
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=256u")
        ReferenceDir = "portable\GCC\ARM_CM33\secure"
        ReferenceSource = "secure_init.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM33_SECURE_CONTEXT_INITIALIZE"
        CpuArgs = @("-mcpu=cortex-m33", "-mcmse")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33\secure"
        FiberSource = "fiber_secure_context_gateway.c"
        FiberDefines = @(
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3u",
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=256u")
        ReferenceDir = "portable\GCC\ARM_CM33\secure"
        ReferenceSource = "secure_context.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM33_SECURE_CONTEXT_LOAD"
        CpuArgs = @("-mcpu=cortex-m33", "-mcmse")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33\secure"
        FiberSource = "fiber_secure_context_gateway.c"
        FiberDefines = @(
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3u",
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=256u")
        ReferenceDir = "portable\GCC\ARM_CM33\secure"
        ReferenceSource = "secure_context_port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM33_SECURE_CONTEXT_SAVE"
        CpuArgs = @("-mcpu=cortex-m33", "-mcmse")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33\secure"
        FiberSource = "fiber_secure_context_gateway.c"
        FiberDefines = @(
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3u",
            "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=256u")
        ReferenceDir = "portable\GCC\ARM_CM33\secure"
        ReferenceSource = "secure_context_port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM33_SECURE_CONTEXT_SVC"
        CpuArgs = @("-mcpu=cortex-m33")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33\non_secure"
        FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM33\non_secure"
        ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1")
        ReferenceExtraIncludes = @("portable\GCC\ARM_CM33\secure")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM33_SECURE_CONTEXT_PENDSV"
        CpuArgs = @("-mcpu=cortex-m33")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33\non_secure"
        FiberSource = "fiber_port_svc.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM33\non_secure"
        ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1")
        ReferenceExtraIncludes = @("portable\GCC\ARM_CM33\secure")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM33_MPU_8"; CpuArgs = @("-mcpu=cortex-m33")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 1; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33_MPU\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM33_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
    },
    [pscustomobject]@{
        Name = "ARM_CM33_MPU_16"; CpuArgs = @("-mcpu=cortex-m33")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 1; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33_MPU\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1", "-DFIBER_PORT_CM33_MPU_TOTAL_REGIONS=16")
        ReferenceDir = "portable\GCC\ARM_CM33_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=16")
    },
    [pscustomobject]@{
        Name = "ARM_CM33F_NTZ_CONSTRUCTION"
        CpuArgs = @("-mcpu=cortex-m33", "-mfpu=fpv5-sp-d16", "-mfloat-abi=hard")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33F_NTZ\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM33_NTZ\non_secure"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1")
    },
    [pscustomobject]@{
        Name = "ARM_CM33F_NTZ_SVC"
        CpuArgs = @("-mcpu=cortex-m33", "-mfpu=fpv5-sp-d16", "-mfloat-abi=hard")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33F_NTZ\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM33_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1")
    },
    [pscustomobject]@{
        Name = "ARM_CM33F_NTZ_PENDSV"
        CpuArgs = @("-mcpu=cortex-m33", "-mfpu=fpv5-sp-d16", "-mfloat-abi=hard")
        CoreHeader = "core_cm33.h"; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM33F_NTZ\non_secure"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1")
        ReferenceDir = "portable\GCC\ARM_CM33_NTZ\non_secure"; ReferenceSource = "portasm.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1")
    },
    [pscustomobject]@{
        Name = "ARM_CM3_MPU"; CpuArgs = @("-mcpu=cortex-m3")
        CoreHeader = "core_cm3.h"; Vtor = 1; Mpu = 1; Fpu = 0; Dsp = 0
        ProfileDir = "fiber\port\ARM_CM3_MPU"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV7M=1")
        ReferenceDir = "portable\GCC\ARM_CM3_MPU"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
    },
    [pscustomobject]@{
        Name = "ARM_CM4_MPU"; CpuArgs = @("-mcpu=cortex-m4", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard")
        CoreHeader = "core_cm4.h"; Vtor = 1; Mpu = 1; Fpu = 1; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM4_MPU"; FiberSource = "fiber_port.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV7EM=1", "-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=8")
        ReferenceDir = "portable\GCC\ARM_CM4_MPU"; ReferenceSource = "port.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1", "-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1", "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8")
    }
)

$stagedRuntimeProfiles = @()

Assert-ProductionPortCoverage -RepositoryRoot $RepoRoot `
    -PortDefinitions $ports -StagedRuntimeProfiles $stagedRuntimeProfiles

$compiler = Find-ArmGcc
$toolDir = Split-Path -Parent $compiler
$objdump = Join-Path $toolDir "arm-none-eabi-objdump.exe"
if (-not (Test-Path -LiteralPath $objdump)) {
    throw "arm-none-eabi-objdump.exe not found next to compiler"
}
$cmsis = Find-CmsisCore
$kernel = Find-FreeRtosKernel
$configDir = Join-Path $RepoRoot "tools\fixtures\freertos_asm_parity"
$ledgerPath = Join-Path $RepoRoot "FREERTOS_ASM_PARITY.md"
if (-not (Test-Path -LiteralPath $ledgerPath)) {
    throw "Generated assembly parity ledger is missing: $ledgerPath"
}
$ledger = Get-Content -LiteralPath $ledgerPath -Raw

$ownsBuildRoot = [string]::IsNullOrWhiteSpace($BuildRoot)
if ($ownsBuildRoot) {
    $BuildRoot = Join-Path ([IO.Path]::GetTempPath()) `
        ("fiber-freertos-asm-parity-" + [Guid]::NewGuid().ToString("N"))
}
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null

try {
    Assert-ReferenceIdentity -KernelRoot $kernel `
        -ExpectedFiles $expectedReferenceFiles

    Write-Host "Parity optimization: $Optimization"

    $compiled = @{}
    foreach ($port in $ports) {
        $portBuild = Join-Path $BuildRoot $port.Name
        New-Item -ItemType Directory -Path $portBuild -Force | Out-Null
        Write-CmsisMainHeader -Directory $portBuild `
            -CoreHeader $port.CoreHeader -VtorPresent $port.Vtor `
            -MpuPresent $port.Mpu `
            -FpuPresent $port.Fpu -FpuUsed $port.Fpu `
            -DspPresent $port.Dsp

        $profileDir = Join-Path $RepoRoot $port.ProfileDir
        $fiberPath = Join-Path $profileDir $port.FiberSource
        $fiberObject = Join-Path $portBuild "fiber-port.o"
        $fiberArgs = @($port.CpuArgs) + @(
            "-mthumb", "-std=gnu11", $Optimization, "-g0",
            "-ffreestanding", "-fno-builtin", "-fno-common",
            "-ffunction-sections", "-fdata-sections",
            "-Wall", "-Wextra", "-Wundef", "-Werror=undef",
            "-Werror=implicit-function-declaration", "-Werror=return-type"
        ) + @($port.FiberDefines) + @(
            "-I$portBuild", "-I$profileDir",
            "-I$(Join-Path $RepoRoot 'fiber\port')",
            "-I$(Join-Path $RepoRoot 'fiber')", "-I$RepoRoot", "-I$cmsis",
            "-c", $fiberPath, "-o", $fiberObject
        )
        Invoke-Compile -Compiler $compiler -Arguments $fiberArgs `
            -Label "$($port.Name) Fiber"

        $referenceDir = Join-Path $kernel $port.ReferenceDir
        $referencePath = Join-Path $referenceDir $port.ReferenceSource
        $referenceObject = Join-Path $portBuild "freertos-port.o"
        $referenceExtraIncludes = @()
        if ($null -ne $port.PSObject.Properties["ReferenceExtraIncludes"]) {
            $referenceExtraIncludes = @($port.ReferenceExtraIncludes |
                ForEach-Object { "-I$(Join-Path $kernel $_)" })
        }
        $referenceArgs = @($port.CpuArgs) + @(
            "-mthumb", "-std=gnu11", $Optimization, "-g0",
            "-ffreestanding", "-fno-builtin", "-fno-common",
            "-ffunction-sections", "-fdata-sections"
        ) + @($port.ReferenceDefines) + $referenceExtraIncludes + @(
            "-I$configDir", "-I$(Join-Path $kernel 'include')",
            "-I$referenceDir", "-c", $referencePath,
            "-o", $referenceObject
        )
        Invoke-Compile -Compiler $compiler -Arguments $referenceArgs `
            -Label "$($port.Name) FreeRTOS"

        $compiled[$port.Name] = [pscustomobject]@{
            FiberPath = $fiberObject
            Fiber = Get-ObjectDisassembly -Objdump $objdump `
                -ObjectPath $fiberObject
            ReferencePath = $referenceObject
            Reference = Get-ObjectDisassembly -Objdump $objdump `
                -ObjectPath $referenceObject
        }
    }

    # ARMv6-M keeps the same staged high-register frame as the reference.
    foreach ($armv6Port in @("ARM_CM0", "ARM_CM0PLUS")) {
    $pair = $compiled[$armv6Port]
    Assert-MechanismParity -PortName $armv6Port -Mechanism "first-start" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bcpsie\s+i\b', '\bdsb\b', '\bisb\b', '\bsvc\s+\d+\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('\bcpsid\s+i\b', '\bmsr\s+CONTROL\b', '\bmsr\s+MSP\b', '\bcpsie\s+i\b', '\bdsb\b', '\bisb\b', '\bsvc\s+70\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armv6Port -Mechanism "first-restore" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bldmia\s+r0!,\s*\{r2\}', '\bmsr\s+CONTROL', '\badds\s+r0,\s*#32', '\bmsr\s+PSP', '\bisb\b', '\bbx\s+r2\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @('fiber_port_context_validate_restore', '\badds\s+r0,\s*#20', '\bldmia\s+r0!,\s*\{r4[^\r\n]*r7\}', '\bmsr\s+PSP', '\bsubs\s+r0,\s*#36', '\bldmia\s+r0!,\s*\{r3[^\r\n]*r7\}', '\bbx\s+lr\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-CM0-STAGED-FRAME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armv6Port -Mechanism "PendSV" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @('\bmrs\s+r0,\s*PSP', '\bsubs\s+r0,\s*#36', '\bstmia\s+r0!,\s*\{r3[^\r\n]*r7\}', '\bstmia\s+r0!,\s*\{r4[^\r\n]*r7\}', '\bcpsid\s+i', 'vTaskSwitchContext', '\bcpsie\s+i', '\badds\s+r0,\s*#20', '\bldmia\s+r0!', '\bmsr\s+PSP', '\bsubs\s+r0,\s*#36', '\bldmia\s+r0!', '\bbx\s+r3') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bmrs\s+r0,\s*PSP', 'fiber_port_context_validate_save_current', '\bsubs\s+r0,\s*#36', '\bstmia\s+r0!,\s*\{r3[^\r\n]*r7\}', '\bstmia\s+r0!,\s*\{r4[^\r\n]*r7\}', '\bmrs\s+r3,\s*PRIMASK', '\bcpsid\s+i', 'fiber_port_scheduler_pick_next_from_pendsv', '\bmsr\s+PRIMASK,\s*r3', '\badds\s+r0,\s*#20', '\bldmia\s+r0!', '\bmsr\s+PSP', '\bsubs\s+r0,\s*#36', '\bldmia\s+r0!', '\bbx\s+lr') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE") `
        -Ledger $ledger
    }

    # ARM_CM0_MPU retains the FreeRTOS protected-context model: the complete
    # hardware frame is copied into privileged context storage, MPU state is
    # replaced under PRIMASK, then the frame is copied back to the selected PSP.
    $pair = $compiled["ARM_CM0_MPU"]
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "first-start" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bcpsie\s+i\b', '\bdsb\b', '\bisb\b', '\bsvc\s+\d+\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('\bcpsid\s+i\b', '\bcpsie\s+i\b', '\bdsb\b',
            '\bisb\b', '\bsvc\s+70\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE",
            "FAP-MPU-FIRST-ACTIVATION-SPLIT") `
        -Ledger $ledger
    $cm0MpuStart = Get-DisassemblyFunctionBody -Disassembly $pair.Fiber `
        -Symbol "fiber_port_start_first_context" -Path $pair.FiberPath
    Assert-AbsentPatterns -Body $cm0MpuStart -Patterns @('\bmsr\s+MSP\b',
        'fiber_port_runtime_prepare_start') `
        -Label "ARM_CM0_MPU Fiber first-start"
    $cm0MpuPrepare = Get-DisassemblyFunctionBody -Disassembly $pair.Fiber `
        -Symbol "fiber_port_runtime_prepare_start" -Path $pair.FiberPath
    Assert-OrderedPatterns -Body $cm0MpuPrepare -Patterns @(
        'fiber_port_mpu_load_linker_layout',
        'fiber_port_mpu_linker_layout_check',
        'fiber_port_validate_exception_vectors',
        'fiber_port_configure_exception_priorities') `
        -Label "ARM_CM0_MPU Fiber forward start preparation"
    $cm0MpuSelectFirst = Get-DisassemblyFunctionBody -Disassembly $pair.Fiber `
        -Symbol "fiber_port_runtime_select_first" -Path $pair.FiberPath
    Assert-OrderedPatterns -Body $cm0MpuSelectFirst -Patterns @(
        'fiber_port_primask_save_disable',
        'fiber_internal_runtime_select_scheduler_candidate',
        'fiber_port_context_validate_initial_restore',
        'fiber_port_primask_restore') `
        -Label "ARM_CM0_MPU Fiber first-selection envelope"

    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "first-restore-special" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_special_regs_first_task" `
        -ReferencePatterns @('\bsubs\s+r1,\s*#12\b',
            '\bldmia\s+r1!,\s*\{r2,\s*r3,\s*r4\}',
            '\bmsr\s+PSP', '\bmsr\s+CONTROL', '\bmov\s+lr,\s*r4\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bcpsid\s+i\b', '\bsubs\s+r1,\s*#12\b',
            '\bldmia\s+r1!,\s*\{r2,\s*r3,\s*r4\}',
            '\bmsr\s+PSP', '\bmsr\s+CONTROL', '\bmov\s+lr,\s*r5\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-MPU-FIRST-ACTIVATION-SPLIT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "first-restore-general" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_general_regs_first_task" `
        -ReferencePatterns @('\bsubs\s+r1,\s*#32\b',
            '\bldmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r2!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bldmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r2!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bsubs\s+r1,\s*#48\b',
            '\bmov\s+r8,\s*r4\b', '\bmov\s+r9,\s*r5\b',
            '\bmov\s+(r10|sl),\s*r6\b', '\bmov\s+(r11|fp),\s*r7\b',
            '\bsubs\s+r1,\s*#16\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bsubs\s+r1,\s*#32\b',
            '\bldmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r2!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bldmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r2!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bsubs\s+r1,\s*#48\b',
            '\bmov\s+r8,\s*r4\b', '\bmov\s+r9,\s*r5\b',
            '\bmov\s+(r10|sl),\s*r6\b', '\bmov\s+(r11|fp),\s*r7\b',
            '\bsubs\s+r1,\s*#16\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-MPU-FIRST-ACTIVATION-SPLIT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "first-restore-complete" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_context_done_first_task" `
        -ReferencePatterns @('\bstr\s+r1,\s*\[r0,\s*#0\]', '\bbx\s+lr\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bstr\s+r1,\s*\[r0,\s*#0\]', '\bcpsie\s+i\b',
            '\bbx\s+lr\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-MPU-FIRST-ACTIVATION-SPLIT") `
        -Ledger $ledger

    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "PendSV-entry" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @('\bldr\s+r2', '\bldr\s+r0,\s*\[r2,\s*#0\]',
            '\bldr\s+r1,\s*\[r0,\s*#0\]', '\bmrs\s+r2,\s*PSP') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bmrs\s+r0,\s*PSP',
            'fiber_port_pendsv_validate_save_current') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "PendSV-save" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "save_general_regs" `
        -ReferencePatterns @('\bstmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bmov\s+r4,\s*r8\b', '\bmov\s+r5,\s*r9\b',
            '\bmov\s+r6,\s*(r10|sl)\b', '\bmov\s+r7,\s*(r11|fp)\b',
            '\bstmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bldmia\s+r2!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bstmia\s+r3!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bmov\s+r4,\s*r8\b', '\bmov\s+r5,\s*r9\b',
            '\bmov\s+r6,\s*(r10|sl)\b', '\bmov\s+r7,\s*(r11|fp)\b',
            '\bstmia\s+r3!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bldmia\s+r0!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r3!,\s*\{r4,\s*r5,\s*r6,\s*r7\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM0-STAGED-FRAME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "PendSV-save-special" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "save_special_regs" `
        -ReferencePatterns @('\bmrs\s+r2,\s*PSP', '\bmrs\s+r3,\s*CONTROL',
            '\bmov\s+r4,\s*lr\b',
            '\bstmia\s+r1!,\s*\{r2,\s*r3,\s*r4\}',
            '\bstr\s+r1,\s*\[r0,\s*#0\]') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bmrs\s+r0,\s*PSP', '\bmrs\s+r2,\s*CONTROL',
            '\bmov\s+r4,\s*lr\b',
            '\bstmia\s+r3!,\s*\{r0,\s*r2,\s*r4\}',
            '\bstr\s+r3,\s*\[r1,\s*#0\]') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "PendSV-scheduler" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "select_next_task" `
        -ReferencePatterns @('\bcpsid\s+i\b', 'vTaskSwitchContext',
            '\bcpsie\s+i\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bcpsid\s+i\b',
            'fiber_port_scheduler_pick_next_from_pendsv',
            'fiber_port_mpu_switch_to_context') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE",
            "FAP-MPU-ATOMIC-SWITCH") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "PendSV-MPU-replace" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "program_mpu" `
        -ReferencePatterns @('\bdmb\b', '\bstr\s+r2,\s*\[r1,\s*#0\]',
            '\bldmia\s+r0!,\s*\{r3,\s*r4\}', '\bstr\s+r3,\s*\[r1,\s*#0\]',
            '\bstr\s+r4,\s*\[r2,\s*#0\]', '\bdsb\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_mpu_switch_to_context" `
        -FiberPatterns @('fiber_port_context_validate_restore', '\bdmb\b',
            'fiber_port_mpu_write_region', '\bstr\s+r6,\s*\[r5,\s*#0\]',
            '\bdsb\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-MPU-ATOMIC-SWITCH") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "PendSV-restore-special" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_special_regs" `
        -ReferencePatterns @('\bsubs\s+r1,\s*#12\b',
            '\bldmia\s+r1!,\s*\{r2,\s*r3,\s*r4\}',
            '\bmsr\s+PSP', '\bmsr\s+CONTROL', '\bmov\s+lr,\s*r4\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bsubs\s+r1,\s*#12\b',
            '\bldmia\s+r1!,\s*\{r0,\s*r3,\s*r4\}',
            '\bmsr\s+PSP', '\bmsr\s+CONTROL', '\bmov\s+lr,\s*r5\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "PendSV-restore-general" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_general_regs" `
        -ReferencePatterns @('\bsubs\s+r1,\s*#32\b',
            '\bldmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r2!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bldmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r2!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bsubs\s+r1,\s*#48\b',
            '\bmov\s+r8,\s*r4\b', '\bmov\s+r9,\s*r5\b',
            '\bmov\s+(r10|sl),\s*r6\b', '\bmov\s+(r11|fp),\s*r7\b',
            '\bsubs\s+r1,\s*#16\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bsubs\s+r1,\s*#32\b',
            '\bldmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r0!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bldmia\s+r1!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bstmia\s+r0!,\s*\{r4,\s*r5,\s*r6,\s*r7\}',
            '\bsubs\s+r1,\s*#48\b',
            '\bmov\s+r8,\s*r4\b', '\bmov\s+r9,\s*r5\b',
            '\bmov\s+(r10|sl),\s*r6\b', '\bmov\s+(r11|fp),\s*r7\b',
            '\bsubs\s+r1,\s*#16\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM0-STAGED-FRAME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM0_MPU" -Mechanism "PendSV-complete" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_context_done" `
        -ReferencePatterns @('\bstr\s+r1,\s*\[r0,\s*#0\]', '\bbx\s+lr\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bstr\s+r1,\s*\[r2,\s*#0\]', '\bcpsie\s+i\b',
            '\bbx\s+lr\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-MPU-ATOMIC-SWITCH") `
        -Ledger $ledger


    # ARM_CM55_MPU is the complete build-selected protected runtime for both
    # supported MPU geometries. Its SVC/PendSV mechanics remain direct parity
    # checks; archive/cohort proof lives in the compile matrix.
    foreach ($armCm55MpuName in @(
            "ARM_CM55_MPU_8",
            "ARM_CM55_MPU_16")) {
    $pair = $compiled[$armCm55MpuName]
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "first-start" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f',
            '\bdsb\b', '\bisb\b', '\bsvc\s+\d+\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('fiber_port_prepare_first_start', '\bcpsid\s+i',
            '\bmsr\s+MSP', '\bcpsie\s+f', '\bcpsie\s+i', '\bdsb\b',
            '\bisb\b', '\bsvc\s+70\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE",
            "FAP-M55MPU-PENDSV") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "MPU-activation" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bbic(?:\.w)?\s+r2,\s*r2,\s*#1',
            '\bstr\s+r2,\s*\[r1,\s*#0\]', '\badds\s+r0,\s*#4',
            '\bldr\s+r1,\s*\[r0,\s*#0\]', '\bstr\s+r1,\s*\[r2,\s*#0\]',
            '\bmovs\s+r3,\s*#4', '\bstr\s+r3,\s*\[r1,\s*#0\]',
            '\bldmia(?:\.w)?\s+r0!', '\bstmia(?:\.w)?\s+r2',
            '\borr(?:\.w)?\s+r2,\s*r2,\s*#1', '\bdsb\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bmov\s+lr,\s*r1', '\bpush\s+\{r0,\s*lr\}',
            '\bbic(?:\.w)?\s+r2,\s*r2,\s*#1',
            '\bstr\s+r2,\s*\[r1,\s*#0\]', '\badds\s+r0,\s*#4',
            '\bldr\s+r1,\s*\[r0,\s*#0\]', '\bstr\s+r1,\s*\[r2,\s*#0\]',
            '\bmovs\s+r3,\s*#4', '\bstr\s+r3,\s*\[r1,\s*#0\]',
            '\bldmia(?:\.w)?\s+r0!', '\bstmia(?:\.w)?\s+r2',
            '\borr(?:\.w)?\s+r2,\s*r2,\s*#5',
            'fiber_port_mpu_validate_active_initial_context', '\bdsb\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-FIRST-ACTIVATION-SPLIT", "FAP-M55MPU-PENDSV") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "first-restore-special" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_special_regs_first_task" `
        -ReferencePatterns @('\bldmdb\s+r1!,\s*\{r2,\s*r3,\s*r4,\s*lr\}',
            '\bmsr\s+PSP', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bldmdb\s+r1!,\s*\{r2,\s*r3,\s*r4,\s*lr\}',
            '\bmsr\s+PSP', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-M55MPU-PENDSV") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "first-restore-general" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_general_regs_first_task" `
        -ReferencePatterns @('\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bstmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bstmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-M55MPU-PENDSV") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "first-restore-complete" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_context_done_first_task" `
        -ReferencePatterns @('\bstr\s+r1,\s*\[r0,\s*#0\]',
            '\bmsr\s+BASEPRI', '\bbx\s+lr\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bstr\s+r1,\s*\[r0,\s*#0\]',
            '\bmsr\s+BASEPRI', '\bcpsie\s+i', '\bbx\s+lr\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-M55MPU-PENDSV") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "PendSV-save" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "save_general_regs" `
        -ReferencePatterns @('(?i)\bstmia(?:\.w)?\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bldmia(?:\.w)?\s+r2,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bmrs\s+r0,\s*psp',
            'fiber_port_pendsv_validate_save_current',
            '(?i)\bstmia(?:\.w)?\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bldmia(?:\.w)?\s+r0,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-M55MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "PendSV-save-special" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "save_special_regs" `
        -ReferencePatterns @('(?i)\bmrs\s+r3,\s*psplim', '(?i)\bmrs\s+r4,\s*control',
            '(?i)\bstmia(?:\.w)?\s+r1!,\s*\{r2[^\r\n]*lr\}',
            '(?i)\bstr\s+r1,\s*\[r0') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bmrs\s+r3,\s*psplim', '(?i)\bmrs\s+r4,\s*control',
            '(?i)\bstmia(?:\.w)?\s+r1!,\s*\{r0[^\r\n]*lr\}',
            '(?i)\bstr\s+r1,\s*\[r2') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-M55MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "PendSV-MPU-replace" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "program_mpu" `
        -ReferencePatterns @('(?i)\bdmb\b', '(?i)\bbic(?:\.w)?\s+r2',
            '(?i)\badds\s+r0,\s*#4', '(?i)\bmovs\s+r3,\s*#4',
            '(?i)\bldmia(?:\.w)?\s+r0!', '(?i)\bstmia(?:\.w)?\s+r2',
            '(?i)\borr(?:\.w)?\s+r2', '(?i)\bdsb\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_mpu_switch_to_context" `
        -FiberPatterns @('fiber_port_context_validate_restore', '(?i)\bdsb\b',
            '(?i)\bstr\b', '(?i)\bisb\b',
            'fiber_port_mpu_validate_active_context') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-MPU-ATOMIC-SWITCH",
            "FAP-M55MPU-PENDSV-C-SWITCH") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "PendSV-restore" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_special_regs" `
        -ReferencePatterns @('(?i)\bldmdb\s+r1!,\s*\{r2,\s*r3,\s*r4,\s*lr\}',
            '(?i)\bmsr\s+psp', '(?i)\bmsr\s+psplim', '(?i)\bmsr\s+control') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bldmdb\s+r1!,\s*\{r0,\s*r3,\s*r4,\s*lr\}',
            '(?i)\bmsr\s+psp', '(?i)\bmsr\s+psplim', '(?i)\bmsr\s+control') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-M55MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "PendSV-restore-general" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_general_regs" `
        -ReferencePatterns @('(?i)\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bstmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bstmia(?:\.w)?\s+r0!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-M55MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm55MpuName -Mechanism "PendSV-restore-complete" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_context_done" `
        -ReferencePatterns @('(?i)\bstr\s+r1,\s*\[r0', '(?i)\bbx\s+lr\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bstr\s+r1,\s*\[r2', '(?i)\bcpsie\s+i',
            '(?i)\bbx\s+lr\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-M55MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    }

    # ARM_CM33_MPU now exposes the frozen forward ABI. Its protected SVC/PendSV
    # sequence remains pinned against the same 8- and 16-region references.
    foreach ($armCm33MpuName in @(
            "ARM_CM33_MPU_8",
            "ARM_CM33_MPU_16")) {
    $pair = $compiled[$armCm33MpuName]
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "first-start" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f',
            '\bdsb\b', '\bisb\b', '\bsvc\s+\d+\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('fiber_port_prepare_first_start', '\bcpsid\s+i',
            '\bmsr\s+MSP', '\bcpsie\s+f', '\bcpsie\s+i', '\bdsb\b',
            '\bisb\b', '\bsvc\s+70\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE",
            "FAP-CM33-MPU-RUNTIME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "MPU-activation" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bbic(?:\.w)?\s+r2,\s*r2,\s*#1',
            '\bstr\s+r2,\s*\[r1,\s*#0\]', '\badds\s+r0,\s*#4',
            '\bldr\s+r1,\s*\[r0,\s*#0\]', '\bstr\s+r1,\s*\[r2,\s*#0\]',
            '\bmovs\s+r3,\s*#4', '\bstr\s+r3,\s*\[r1,\s*#0\]',
            '\bldmia(?:\.w)?\s+r0!', '\bstmia(?:\.w)?\s+r2',
            '\borr(?:\.w)?\s+r2,\s*r2,\s*#1', '\bdsb\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bmov\s+lr,\s*r1', '\bpush\s+\{r0,\s*lr\}',
            '\bbic(?:\.w)?\s+r2,\s*r2,\s*#1',
            '\bstr\s+r2,\s*\[r1,\s*#0\]', '\badds\s+r0,\s*#4',
            '\bldr\s+r1,\s*\[r0,\s*#0\]', '\bstr\s+r1,\s*\[r2,\s*#0\]',
            '\bmovs\s+r3,\s*#4', '\bstr\s+r3,\s*\[r1,\s*#0\]',
            '\bldmia(?:\.w)?\s+r0!', '\bstmia(?:\.w)?\s+r2',
            '\borr(?:\.w)?\s+r2,\s*r2,\s*#5',
            'fiber_port_mpu_validate_active_initial_context', '\bdsb\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-FIRST-ACTIVATION-SPLIT", "FAP-CM33-MPU-RUNTIME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "first-restore-special" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_special_regs_first_task" `
        -ReferencePatterns @('\bldmdb\s+r1!,\s*\{r2,\s*r3,\s*r4,\s*lr\}',
            '\bmsr\s+PSP', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bldmdb\s+r1!,\s*\{r2,\s*r3,\s*r4,\s*lr\}',
            '\bmsr\s+PSP', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM33-MPU-RUNTIME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "first-restore-general" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_general_regs_first_task" `
        -ReferencePatterns @('\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bstmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bstmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM33-MPU-RUNTIME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "first-restore-complete" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_context_done_first_task" `
        -ReferencePatterns @('\bstr\s+r1,\s*\[r0,\s*#0\]',
            '\bmsr\s+BASEPRI', '\bbx\s+lr\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bstr\s+r1,\s*\[r0,\s*#0\]',
            '\bmsr\s+BASEPRI', '\bcpsie\s+i', '\bbx\s+lr\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM33-MPU-RUNTIME") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "PendSV-save" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "save_general_regs" `
        -ReferencePatterns @('(?i)\bstmia(?:\.w)?\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bldmia(?:\.w)?\s+r2,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bmrs\s+r0,\s*psp',
            'fiber_port_pendsv_validate_save_current',
            '(?i)\bstmia(?:\.w)?\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bldmia(?:\.w)?\s+r0,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM33-MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "PendSV-save-special" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "save_special_regs" `
        -ReferencePatterns @('(?i)\bmrs\s+r3,\s*psplim', '(?i)\bmrs\s+r4,\s*control',
            '(?i)\bstmia(?:\.w)?\s+r1!,\s*\{r2[^\r\n]*lr\}',
            '(?i)\bstr\s+r1,\s*\[r0') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bmrs\s+r3,\s*psplim', '(?i)\bmrs\s+r4,\s*control',
            '(?i)\bstmia(?:\.w)?\s+r1!,\s*\{r0[^\r\n]*lr\}',
            '(?i)\bstr\s+r1,\s*\[r2') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM33-MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "PendSV-MPU-replace" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "program_mpu" `
        -ReferencePatterns @('(?i)\bdmb\b', '(?i)\bbic(?:\.w)?\s+r2',
            '(?i)\badds\s+r0,\s*#4', '(?i)\bmovs\s+r3,\s*#4',
            '(?i)\bldmia(?:\.w)?\s+r0!', '(?i)\bstmia(?:\.w)?\s+r2',
            '(?i)\borr(?:\.w)?\s+r2', '(?i)\bdsb\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_mpu_switch_to_context" `
        -FiberPatterns @('fiber_port_context_validate_restore', '(?i)\bdsb\b',
            '(?i)\bstr\b', '(?i)\bisb\b',
            'fiber_port_mpu_validate_active_context') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-MPU-ATOMIC-SWITCH",
            "FAP-CM33-MPU-PENDSV-C-SWITCH",
            "FAP-CM33-MPU-CURRENT-SLOT-APERTURE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "PendSV-restore" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_special_regs" `
        -ReferencePatterns @('(?i)\bldmdb\s+r1!,\s*\{r2,\s*r3,\s*r4,\s*lr\}',
            '(?i)\bmsr\s+psp', '(?i)\bmsr\s+psplim', '(?i)\bmsr\s+control') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bldmdb\s+r1!,\s*\{r0,\s*r3,\s*r4,\s*lr\}',
            '(?i)\bmsr\s+psp', '(?i)\bmsr\s+psplim', '(?i)\bmsr\s+control') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM33-MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "PendSV-restore-general" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_general_regs" `
        -ReferencePatterns @('(?i)\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bstmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bstmia(?:\.w)?\s+r0!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '(?i)\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM33-MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    Assert-MechanismParity -PortName $armCm33MpuName -Mechanism "PendSV-restore-complete" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_context_done" `
        -ReferencePatterns @('(?i)\bstr\s+r1,\s*\[r0', '(?i)\bbx\s+lr\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('(?i)\bstr\s+r1,\s*\[r2', '(?i)\bcpsie\s+i',
            '(?i)\bbx\s+lr\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", "FAP-CM33-MPU-PENDSV-PREFLIGHT") `
        -Ledger $ledger
    }

    # ARMv7-M uses BASEPRI in both implementations. Fiber additionally carries
    # EXC_RETURN per context instead of manufacturing FD in the SVC handler.
    $pair = $compiled["ARM_CM3"]
    Assert-MechanismParity -PortName "ARM_CM3" -Mechanism "first-start" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "prvPortStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f', '\bdsb\b', '\bisb\b', '\bsvc\s+0') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('\bcpsid\s+i', '\bmsr\s+CONTROL', '\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f', '\bdsb\b', '\bisb\b', '\bsvc\s+70') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM3" -Mechanism "first-restore" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vPortSVCHandler" `
        -ReferencePatterns @('\bldmia(\.w)?\s+r0!,\s*\{r4[^\r\n]*fp\}', '\bmsr\s+PSP', '\bmsr\s+BASEPRI', '\borr(\.w)?\s+lr,\s*lr,\s*#13', '\bbx\s+lr') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @('\bmsr\s+BASEPRI', 'fiber_port_context_validate_restore', '\bldmia(\.w)?\s+r0!,\s*\{r4[^\r\n]*lr\}', '\bmsr\s+PSP', '\bbx\s+lr') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-CM3-EXC-RETURN") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM3" -Mechanism "PendSV" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "xPortPendSVHandler" `
        -ReferencePatterns @('\bmrs\s+r0,\s*PSP', '\bstmdb\s+r0!,\s*\{r4[^\r\n]*fp\}', '\bstr\s+r0', '\bmsr\s+BASEPRI', 'vTaskSwitchContext', '\bmsr\s+BASEPRI', '\bldmia(\.w)?\s+r0!,\s*\{r4[^\r\n]*fp\}', '\bmsr\s+PSP', '\bisb\b', '\bbx\s+lr') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bmrs\s+r0,\s*PSP', 'fiber_port_context_validate_save_current', '\bstmdb\s+r0!,\s*\{r4[^\r\n]*lr\}', '\bstr\s+r0', '\bmsr\s+BASEPRI', 'fiber_port_scheduler_pick_next_from_pendsv', '\bmsr\s+BASEPRI', '\bldmia(\.w)?\s+r0!,\s*\{r4[^\r\n]*lr\}', '\bmsr\s+PSP', '\bisb\b', '\bbx\s+lr') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-CM3-EXC-RETURN") `
        -Ledger $ledger

    foreach ($floatingPort in @(
            [pscustomobject]@{ Name = "ARM_CM4"; Errata = $false },
            [pscustomobject]@{ Name = "ARM_CM7_R0P1"; Errata = $true })) {
        $pair = $compiled[$floatingPort.Name]
        Assert-MechanismParity -PortName $floatingPort.Name `
            -Mechanism "first-start" -ReferenceDisassembly $pair.Reference `
            -ReferenceSymbol "prvPortStartFirstTask" `
            -ReferencePatterns @('\bmsr\s+MSP', '\bmsr\s+CONTROL', '\bcpsie\s+i', '\bcpsie\s+f', '\bdsb\b', '\bisb\b', '\bsvc\s+0') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "fiber_port_start_first_context" `
            -FiberPatterns @('\bcpsid\s+i', '\bmsr\s+CONTROL', '\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f', '\bdsb\b', '\bisb\b', '\bsvc\s+70') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE") `
            -Ledger $ledger
        Assert-MechanismParity -PortName $floatingPort.Name `
            -Mechanism "first-restore" -ReferenceDisassembly $pair.Reference `
            -ReferenceSymbol "vPortSVCHandler" `
            -ReferencePatterns @('\bldmia(\.w)?\s+r0!,\s*\{r4[^\r\n]*lr\}', '\bmsr\s+PSP', '\bmsr\s+BASEPRI', '\bbx\s+lr') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "SVC_Handler" `
            -FiberPatterns @('\bmsr\s+BASEPRI', 'fiber_port_context_validate_restore', '\bldmia(\.w)?\s+r0!,\s*\{r4[^\r\n]*lr\}', '\bmsr\s+PSP', '\bbx\s+lr') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-FP-VALIDATION") `
            -Ledger $ledger
        $referencePendSvPatterns = @(
            '\bmrs\s+r0,\s*PSP', '\btst(\.w)?\s+lr,\s*#16',
            '\bvstmdb(eq)?\s+r0!,\s*\{s16-s31\}',
            '\bstmdb\s+r0!,\s*\{r4[^\r\n]*lr\}', '\bstr\s+r0')
        if ($floatingPort.Errata) {
            $referencePendSvPatterns += @('\bcpsid\s+i', '\bmsr\s+BASEPRI', '\bcpsie\s+i')
        } else {
            $referencePendSvPatterns += @('\bmsr\s+BASEPRI')
        }
        $referencePendSvPatterns += @(
            'vTaskSwitchContext', '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r4[^\r\n]*lr\}',
            '\btst(\.w)?\s+lr,\s*#16',
            '\bvldmia(eq)?\s+r0!,\s*\{s16-s31\}',
            '\bmsr\s+PSP', '\bisb\b', '\bbx\s+lr')
        $fiberPendSvPatterns = @(
            '\bmrs\s+r0,\s*PSP', 'fiber_port_context_validate_save_current',
            '\btst(\.w)?\s+lr,\s*#16',
            '\bvstmdb(eq)?\s+r0!,\s*\{s16-s31\}',
            '\bstmdb\s+r0!,\s*\{r4[^\r\n]*lr\}', '\bstr\s+r0')
        if ($floatingPort.Errata) {
            $fiberPendSvPatterns += @('\bmrs\s+(ip|r12),\s*PRIMASK', '\bcpsid\s+i', '\bmsr\s+BASEPRI', '\bmsr\s+PRIMASK,\s*(ip|r12)')
        } else {
            $fiberPendSvPatterns += @('\bmsr\s+BASEPRI')
        }
        $fiberPendSvPatterns += @(
            'fiber_port_scheduler_pick_next_from_pendsv', '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r4[^\r\n]*lr\}',
            '\btst(\.w)?\s+lr,\s*#16',
            '\bvldmia(eq)?\s+r0!,\s*\{s16-s31\}',
            '\bmsr\s+PSP', '\bisb\b', '\bbx\s+lr')
        $differences = @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-FP-VALIDATION")
        if ($floatingPort.Errata) {
            $differences += "FAP-CM7-ERRATA-PRIMASK"
        }
        Assert-MechanismParity -PortName $floatingPort.Name `
            -Mechanism "PendSV-FP" -ReferenceDisassembly $pair.Reference `
            -ReferenceSymbol "xPortPendSVHandler" `
            -ReferencePatterns $referencePendSvPatterns `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "PendSV_Handler" -FiberPatterns $fiberPendSvPatterns `
            -FiberPath $pair.FiberPath -DifferenceIds $differences `
            -Ledger $ledger
    }

    # ARMv8-M Baseline NTZ keeps a reserved PSPLIM word but never accesses the
    # register. The generated save/restore geometry must remain ten words.
    $pair = $compiled["ARM_CM23_NTZ"]
    Assert-MechanismParity -PortName "ARM_CM23_NTZ" `
        -Mechanism "first-start" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bdsb\b', '\bisb\b', '\bsvc\s+\d+') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('\bcpsid\s+i', '\bmsr\s+CONTROL', '\bmsr\s+MSP', '\bcpsie\s+i', '\bdsb\b', '\bisb\b', '\bsvc\s+70') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM23_NTZ" `
        -Mechanism "first-restore" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bldmia\s+r0!,\s*\{r1,\s*r2\}', '\bmsr\s+CONTROL', '\badds\s+r0,\s*#32', '\bmsr\s+PSP', '\bisb\b', '\bbx\s+r2') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @('fiber_port_context_validate_restore', '\badds\s+r0,\s*#24', '\bmsr\s+PSP', '\bsubs\s+r0,\s*#36', '\bbx\s+lr') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-M23-PSPLIM-PLACEHOLDER") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM23_NTZ" `
        -Mechanism "PendSV" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @('\bmrs\s+r0,\s*PSP', '\bsubs\s+r0,\s*#40', '\bstmia\s+r0!,\s*\{r2[^\r\n]*r7\}', '\bstmia\s+r0!,\s*\{r4[^\r\n]*r7\}', '\bcpsid\s+i', 'vTaskSwitchContext', '\bcpsie\s+i', '\badds\s+r0,\s*#24', '\bmsr\s+PSP', '\bsubs\s+r0,\s*#40', '\bbx\s+r3') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bmrs\s+r0,\s*PSP', 'fiber_port_context_validate_save_current', '\bsubs\s+r0,\s*#40', '\bstmia\s+r0!,\s*\{r2[^\r\n]*r7\}', '\bstmia\s+r0!,\s*\{r4[^\r\n]*r7\}', '\bcpsid\s+i', 'fiber_port_scheduler_pick_next_from_pendsv', '\bcpsie\s+i', '\badds\s+r0,\s*#24', '\bmsr\s+PSP', '\bsubs\s+r0,\s*#36', '\bbx\s+lr') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-M23-PSPLIM-PLACEHOLDER") `
        -Ledger $ledger
    $cm23ReferencePendSv = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Reference -Symbol "PendSV_Handler" `
        -Path $pair.ReferencePath
    $cm23FiberPendSv = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Fiber -Symbol "PendSV_Handler" -Path $pair.FiberPath
    Assert-AbsentPatterns -Body $cm23ReferencePendSv -Patterns @('\bPSPLIM\b') `
        -Label "ARM_CM23_NTZ FreeRTOS PendSV"
    Assert-AbsentPatterns -Body $cm23FiberPendSv -Patterns @('\bPSPLIM\b') `
        -Label "ARM_CM23_NTZ Fiber PendSV"

    # CM33 retains the FreeRTOS ten-word Mainline frame and adds exact
    # provenance, bounds, CPU-state, and PSPLIM readback validation.
    $pair = $compiled["ARM_CM33_NTZ"]
    Assert-MechanismParity -PortName "ARM_CM33_NTZ" `
        -Mechanism "first-start" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f', '\bdsb\b', '\bisb\b', '\bsvc\s+\d+') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('\bcpsid\s+i', '\bmsr\s+CONTROL', '\bmsr\s+MSP', '\bcpsie\s+f', '\bcpsie\s+i', '\bdsb\b', '\bisb\b', '\bsvc\s+70') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE") `
        -Ledger $ledger

    # TF-M does not supply a different context-switch port. Its pinned
    # ThirdParty profile copies the corresponding NTZ CPU port and adds only
    # the TF-M Non-secure interface mutex adapter. Prove the C3TF CPU mechanics
    # against the same reference independently so the profiles cannot drift.
    $pair = $compiled["ARM_CM33_TFM"]
    Assert-MechanismParity -PortName "ARM_CM33_TFM" `
        -Mechanism "first-start" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f', '\bdsb\b', '\bisb\b', '\bsvc\s+\d+') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('\bcpsid\s+i', '\bmsr\s+CONTROL', '\bmsr\s+MSP', '\bcpsie\s+f', '\bcpsie\s+i', '\bdsb\b', '\bisb\b', '\bsvc\s+70') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33_TFM" `
        -Mechanism "first-restore" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bldmia\s+r0!,\s*\{r1,\s*r2\}', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL', '\badds\s+r0,\s*#32', '\bmsr\s+PSP', '\bmsr\s+BASEPRI', '\bbx\s+r2') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @('\bmsr\s+BASEPRI', 'fiber_port_context_validate_restore', '\bldmia(\.w)?\s+r0!,\s*\{r2,\s*r3[^\r\n]*fp\}', '\bmsr\s+PSPLIM', '\bmrs\s+[^,]+,\s*PSPLIM', '\bmsr\s+CONTROL', '\bmsr\s+PSP', '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M33-FULL-FIRST-RESTORE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33_TFM" `
        -Mechanism "PendSV" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @(
            '\bmrs\s+r0,\s*PSP',
            '\bmrs\s+r2,\s*PSPLIM',
            '\bmov\s+r3,\s*lr',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'vTaskSwitchContext',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmsr\s+PSP,\s*r0',
            '\bbx\s+r3') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r0,\s*PSP',
            'fiber_port_context_validate_save_current',
            '\bmrs\s+r3,\s*PSPLIM',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'fiber_port_scheduler_pick_next_from_pendsv',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmrs\s+r1,\s*PSPLIM',
            '\bmsr\s+PSP,\s*r0',
            '\bmrs\s+r1,\s*PSP',
            '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M33-PSPLIM-READBACK") `
        -Ledger $ledger
    $pair = $compiled["ARM_CM33_NTZ"]
    Assert-MechanismParity -PortName "ARM_CM33_NTZ" `
        -Mechanism "first-restore" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bldmia\s+r0!,\s*\{r1,\s*r2\}', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL', '\badds\s+r0,\s*#32', '\bmsr\s+PSP', '\bmsr\s+BASEPRI', '\bbx\s+r2') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @('\bmsr\s+BASEPRI', 'fiber_port_context_validate_restore', '\bldmia(\.w)?\s+r0!,\s*\{r2,\s*r3[^\r\n]*fp\}', '\bmsr\s+PSPLIM', '\bmrs\s+[^,]+,\s*PSPLIM', '\bmsr\s+CONTROL', '\bmsr\s+PSP', '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M33-FULL-FIRST-RESTORE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33_NTZ" `
        -Mechanism "PendSV" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @(
            '\bmrs\s+r0,\s*PSP',
            '\bmrs\s+r2,\s*PSPLIM',
            '\bmov\s+r3,\s*lr',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'vTaskSwitchContext',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmsr\s+PSP,\s*r0',
            '\bbx\s+r3') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r0,\s*PSP',
            'fiber_port_context_validate_save_current',
            '\bmrs\s+r3,\s*PSPLIM',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'fiber_port_scheduler_pick_next_from_pendsv',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmrs\s+r1,\s*PSPLIM',
            '\bmsr\s+PSP,\s*r0',
            '\bmrs\s+r1,\s*PSP',
            '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M33-PSPLIM-READBACK") `
        -Ledger $ledger

    # The Cortex-M55 NTZ baseline is deliberately compiled with FPU and MVE
    # disabled. Its scalar frame remains ten words, while its profile identity
    # prevents it from being confused with the later M55F/MVE cohorts.
    $pair = $compiled["ARM_CM55_NTZ"]
    Assert-MechanismParity -PortName "ARM_CM55_NTZ" `
        -Mechanism "first-start" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f', '\bdsb\b', '\bisb\b', '\bsvc\s+\d+') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('\bcpsid\s+i', '\bmsr\s+CONTROL', '\bmsr\s+MSP', '\bcpsie\s+f', '\bcpsie\s+i', '\bdsb\b', '\bisb\b', '\bsvc\s+70') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM55_NTZ" `
        -Mechanism "first-restore" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bldmia\s+r0!,\s*\{r1,\s*r2\}', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL', '\badds\s+r0,\s*#32', '\bmsr\s+PSP', '\bmsr\s+BASEPRI', '\bbx\s+r2') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @('\bmsr\s+BASEPRI', 'fiber_port_context_validate_restore', '\bldmia(\.w)?\s+r0!,\s*\{r2,\s*r3[^\r\n]*fp\}', '\bmsr\s+PSPLIM', '\bmrs\s+[^,]+,\s*PSPLIM', '\bmsr\s+CONTROL', '\bmsr\s+PSP', '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M55-FULL-FIRST-RESTORE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM55_NTZ" `
        -Mechanism "PendSV" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @(
            '\bmrs\s+r0,\s*PSP',
            '\bmrs\s+r2,\s*PSPLIM',
            '\bmov\s+r3,\s*lr',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'vTaskSwitchContext',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmsr\s+PSP,\s*r0',
            '\bbx\s+r3') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r0,\s*PSP',
            'fiber_port_context_validate_save_current',
            '\bmrs\s+r3,\s*PSPLIM',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'fiber_port_scheduler_pick_next_from_pendsv',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmrs\s+r1,\s*PSPLIM',
            '\bmsr\s+PSP,\s*r0',
            '\bmrs\s+r1,\s*PSP',
            '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M55-PSPLIM-READBACK") `
        -Ledger $ledger

    # ARM_CM55F_NTZ is the exact scalar-FP/no-MVE sibling of the scalar M55
    # cohort. Its construction remains basic, while SVC and PendSV gain the
    # selected FP policy and conditional s16-s31 transfer.
    $pair = $compiled["ARM_CM55F_NTZ_CONSTRUCTION"]
    Assert-MechanismParity -PortName "ARM_CM55F_NTZ" `
        -Mechanism "initial-construction" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "pxPortInitialiseStack" `
        -ReferencePatterns @('#-?(?:72|0x48)\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_init_context_frame" `
        -FiberPatterns @('#-?(?:72|0x48)\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-M55F-CONSTRUCTION") `
        -Ledger $ledger
    $cm55fReferenceConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Reference -Symbol "pxPortInitialiseStack" `
        -Path $pair.ReferencePath
    $cm55fFiberConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Fiber -Symbol "fiber_port_init_context_frame" `
        -Path $pair.FiberPath
    Assert-AbsentPatterns -Body $cm55fReferenceConstruction `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b') `
        -Label "ARM_CM55F_NTZ FreeRTOS initial construction"
    Assert-AbsentPatterns -Body $cm55fFiberConstruction `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b') `
        -Label "ARM_CM55F_NTZ Fiber initial construction"

    # The MPU plus scalar-FP profile begins with the FreeRTOS protected basic
    # image. The constructor is paired under both supported scalar-FP calling
    # conventions; the later extended FP copy/restore has its own PendSV proof.
    foreach ($cm55fMpuConstructionName in @(
            "ARM_CM55F_MPU_CONSTRUCTION",
            "ARM_CM55F_MPU_CONSTRUCTION_SOFTFP")) {
    $pair = $compiled[$cm55fMpuConstructionName]
    Assert-MechanismParity -PortName $cm55fMpuConstructionName `
        -Mechanism "MPU-FPU-initial-construction" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "pxPortInitialiseStack" `
        -ReferencePatterns @('\bsub(?:s|\.w)?\s+\w+(?:,\s*\w+)?,\s*#32\b',
            '\bstr(?:\.w)?\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_context_init" `
        -FiberPatterns @('fiber_port_mpu_encode_exact_region',
            '\bsub(?:s|\.w)?\s+\w+(?:,\s*\w+)?,\s*#32\b', '#54\b',
            'fiber_port_context_compute_seal') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-M55FMPU-CONSTRUCTION") `
        -Ledger $ledger
    $cm55fMpuReferenceConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Reference -Symbol "pxPortInitialiseStack" `
        -Path $pair.ReferencePath
    $cm55fMpuFiberConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Fiber -Symbol "fiber_port_context_init" `
        -Path $pair.FiberPath
    Assert-AbsentPatterns -Body $cm55fMpuReferenceConstruction `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b', '\b(?:vpr|mve)\b') `
        -Label "$cm55fMpuConstructionName FreeRTOS initial construction"
    Assert-AbsentPatterns -Body $cm55fMpuFiberConstruction `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b', '\b(?:vpr|mve)\b') `
        -Label "$cm55fMpuConstructionName Fiber initial construction"
    }

    # FreeRTOS uses the same 54-word protected basic image when both FPU and
    # MVE are enabled. MVE changes the later conditional FP save contract, not
    # construction, and must not create a VPR software slot here.
    foreach ($cm55MvefMpuConstructionName in @(
            "ARM_CM55_MVEF_MPU_CONSTRUCTION",
            "ARM_CM55_MVEF_MPU_CONSTRUCTION_SOFTFP")) {
    $pair = $compiled[$cm55MvefMpuConstructionName]
    Assert-MechanismParity -PortName $cm55MvefMpuConstructionName `
        -Mechanism "MPU-MVE-FP-initial-construction" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "pxPortInitialiseStack" `
        -ReferencePatterns @('\bsub(?:s|\.w)?\s+\w+(?:,\s*\w+)?,\s*#32\b',
            '\bstr(?:\.w)?\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_context_init" `
        -FiberPatterns @('fiber_port_mpu_encode_exact_region',
            '\bsub(?:s|\.w)?\s+\w+(?:,\s*\w+)?,\s*#32\b', '#54\b',
            'fiber_port_context_compute_seal') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-M55MVE-MPU-CONSTRUCTION") `
        -Ledger $ledger
    $cm55MvefMpuReferenceConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Reference -Symbol "pxPortInitialiseStack" `
        -Path $pair.ReferencePath
    $cm55MvefMpuFiberConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Fiber -Symbol "fiber_port_context_init" `
        -Path $pair.FiberPath
    # GCC may vectorize FreeRTOS's static initialization into transient q-register
    # stores under +mve.fp. That is not a saved-context operation. The invariant
    # is that neither implementation owns VPR state or a VPR software slot.
    Assert-AbsentPatterns -Body $cm55MvefMpuReferenceConstruction `
        -Patterns @('\b(?:vmsr|vmrs)\b[^\r\n]*\bvpr\b', '\bmsr\s+vpr\b') `
        -Label "$cm55MvefMpuConstructionName FreeRTOS initial VPR state"
    Assert-AbsentPatterns -Body $cm55MvefMpuFiberConstruction `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b',
            '\b(?:vmsr|vmrs)\b[^\r\n]*\bvpr\b', '\bmsr\s+vpr\b') `
        -Label "$cm55MvefMpuConstructionName Fiber general-register construction"
    }

    # With MPU and scalar-FP or MVE-FP enabled, FreeRTOS still restores only
    # the basic protected image on first entry. Its high-FP state first exists
    # after a later extended PendSV save, so neither side may emit VFP, MVE, or
    # VPR state transfer here.
    foreach ($cm55MpuSvcProfile in @(
            [pscustomobject]@{ Name = "ARM_CM55F_MPU_SVC_8"; DifferenceId = "FAP-M55FMPU-SVC" },
            [pscustomobject]@{ Name = "ARM_CM55F_MPU_SVC_16"; DifferenceId = "FAP-M55FMPU-SVC" },
            [pscustomobject]@{ Name = "ARM_CM55F_MPU_SVC_8_SOFTFP"; DifferenceId = "FAP-M55FMPU-SVC" },
            [pscustomobject]@{ Name = "ARM_CM55F_MPU_SVC_16_SOFTFP"; DifferenceId = "FAP-M55FMPU-SVC" },
            [pscustomobject]@{ Name = "ARM_CM55_MVEF_MPU_SVC_8"; DifferenceId = "FAP-M55MVE-MPU-SVC" },
            [pscustomobject]@{ Name = "ARM_CM55_MVEF_MPU_SVC_16"; DifferenceId = "FAP-M55MVE-MPU-SVC" },
            [pscustomobject]@{ Name = "ARM_CM55_MVEF_MPU_SVC_8_SOFTFP"; DifferenceId = "FAP-M55MVE-MPU-SVC" },
            [pscustomobject]@{ Name = "ARM_CM55_MVEF_MPU_SVC_16_SOFTFP"; DifferenceId = "FAP-M55MVE-MPU-SVC" })) {
    $cm55fMpuSvcName = $cm55MpuSvcProfile.Name
    $cm55MpuSvcDifferenceId = $cm55MpuSvcProfile.DifferenceId
    $pair = $compiled[$cm55fMpuSvcName]
    Assert-MechanismParity -PortName $cm55fMpuSvcName -Mechanism "first-start" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f',
            '\bdsb\b', '\bisb\b', '\bsvc\s+\d+\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('fiber_port_prepare_first_start', '\bcpsid\s+i',
            '\bmsr\s+MSP', '\bcpsie\s+f', '\bcpsie\s+i', '\bdsb\b',
            '\bisb\b', '\bsvc\s+70\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE",
            $cm55MpuSvcDifferenceId) `
        -Ledger $ledger
    Assert-MechanismParity -PortName $cm55fMpuSvcName -Mechanism "MPU-activation" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bbic(?:\.w)?\s+r2,\s*r2,\s*#1',
            '\bstr\s+r2,\s*\[r1,\s*#0\]', '\badds\s+r0,\s*#4',
            '\bldr\s+r1,\s*\[r0,\s*#0\]', '\bstr\s+r1,\s*\[r2,\s*#0\]',
            '\bmovs\s+r3,\s*#4', '\bstr\s+r3,\s*\[r1,\s*#0\]',
            '\bldmia(?:\.w)?\s+r0!', '\bstmia(?:\.w)?\s+r2',
            '\borr(?:\.w)?\s+r2,\s*r2,\s*#1', '\bdsb\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bmov\s+lr,\s*r1', '\bpush\s+\{r0,\s*lr\}',
            '\bbic(?:\.w)?\s+r2,\s*r2,\s*#1',
            '\bstr\s+r2,\s*\[r1,\s*#0\]', '\badds\s+r0,\s*#4',
            '\bldr\s+r1,\s*\[r0,\s*#0\]', '\bstr\s+r1,\s*\[r2,\s*#0\]',
            '\bmovs\s+r3,\s*#4', '\bstr\s+r3,\s*\[r1,\s*#0\]',
            '\bldmia(?:\.w)?\s+r0!', '\bstmia(?:\.w)?\s+r2',
            '\borr(?:\.w)?\s+r2,\s*r2,\s*#5',
            'fiber_port_mpu_validate_active_initial_context', '\bdsb\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-FIRST-ACTIVATION-SPLIT", $cm55MpuSvcDifferenceId) `
        -Ledger $ledger
    Assert-MechanismParity -PortName $cm55fMpuSvcName -Mechanism "first-restore-special" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_special_regs_first_task" `
        -ReferencePatterns @('\bldmdb\s+r1!,\s*\{r2,\s*r3,\s*r4,\s*lr\}',
            '\bmsr\s+PSP', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bldmdb\s+r1!,\s*\{r2,\s*r3,\s*r4,\s*lr\}',
            '\bmsr\s+PSP', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", $cm55MpuSvcDifferenceId) `
        -Ledger $ledger
    Assert-MechanismParity -PortName $cm55fMpuSvcName -Mechanism "first-restore-general" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_general_regs_first_task" `
        -ReferencePatterns @('\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bstmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bstmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*(r11|fp)\}',
            '\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", $cm55MpuSvcDifferenceId) `
        -Ledger $ledger
    Assert-MechanismParity -PortName $cm55fMpuSvcName -Mechanism "first-restore-complete" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_context_done_first_task" `
        -ReferencePatterns @('\bstr\s+r1,\s*\[r0,\s*#0\]',
            '\bmsr\s+BASEPRI', '\bbx\s+lr\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_restore_first_context_from_svc" `
        -FiberPatterns @('\bstr\s+r1,\s*\[r0,\s*#0\]',
            '\bmsr\s+BASEPRI', '\bcpsie\s+i', '\bbx\s+lr\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE",
            "FAP-MPU-PROTECTED-FRAME", $cm55MpuSvcDifferenceId) `
        -Ledger $ledger
    $cm55fMpuReferenceFirstRestore = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Reference -Symbol "vRestoreContextOfFirstTask" `
        -Path $pair.ReferencePath
    $cm55fMpuFiberFirstRestore = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Fiber -Symbol "fiber_port_restore_first_context_from_svc" `
        -Path $pair.FiberPath
    Assert-AbsentPatterns -Body $cm55fMpuReferenceFirstRestore `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b', '\b(?:vpr|mve)\b') `
        -Label "$cm55fMpuSvcName FreeRTOS first restore"
    Assert-AbsentPatterns -Body $cm55fMpuFiberFirstRestore `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b', '\b(?:vpr|mve)\b') `
        -Label "$cm55fMpuSvcName Fiber first restore"
    }

    foreach ($cm55MpuPendSvProfile in @(
            [pscustomobject]@{ Name = "ARM_CM55F_MPU_PENDSV_8"; DifferenceId = "FAP-M55FMPU-PENDSV" },
            [pscustomobject]@{ Name = "ARM_CM55F_MPU_PENDSV_16"; DifferenceId = "FAP-M55FMPU-PENDSV" },
            [pscustomobject]@{ Name = "ARM_CM55F_MPU_PENDSV_8_SOFTFP"; DifferenceId = "FAP-M55FMPU-PENDSV" },
            [pscustomobject]@{ Name = "ARM_CM55F_MPU_PENDSV_16_SOFTFP"; DifferenceId = "FAP-M55FMPU-PENDSV" },
            [pscustomobject]@{ Name = "ARM_CM55_MVEF_MPU_PENDSV_8"; DifferenceId = "FAP-M55MVE-MPU-PENDSV" },
            [pscustomobject]@{ Name = "ARM_CM55_MVEF_MPU_PENDSV_16"; DifferenceId = "FAP-M55MVE-MPU-PENDSV" },
            [pscustomobject]@{ Name = "ARM_CM55_MVEF_MPU_PENDSV_8_SOFTFP"; DifferenceId = "FAP-M55MVE-MPU-PENDSV" },
            [pscustomobject]@{ Name = "ARM_CM55_MVEF_MPU_PENDSV_16_SOFTFP"; DifferenceId = "FAP-M55MVE-MPU-PENDSV" })) {
        $cm55fMpuPendSvName = $cm55MpuPendSvProfile.Name
        $cm55MpuPendSvDifferenceId = $cm55MpuPendSvProfile.DifferenceId
        $pair = $compiled[$cm55fMpuPendSvName]
        Assert-MechanismParity -PortName $cm55fMpuPendSvName -Mechanism "PendSV-entry" `
            -ReferenceDisassembly $pair.Reference -ReferenceSymbol "PendSV_Handler" `
            -ReferencePatterns @('\bldr\s+r2,\s*\[pc', '\bldr\s+r0,\s*\[r2',
                '\bldr\s+r1,\s*\[r0', '\bmrs\s+r2,\s*PSP') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "PendSV_Handler" `
            -FiberPatterns @('\bmrs\s+r3,\s*IPSR', '\bcmp\s+r3,\s*#14',
                '\bmrs\s+r0,\s*PSP',
                'fiber_port_pendsv_validate_save_current') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-PROVENANCE", $cm55MpuPendSvDifferenceId) `
            -Ledger $ledger
        Assert-MechanismParity -PortName $cm55fMpuPendSvName -Mechanism "PendSV-save-FP" `
            -ReferenceDisassembly $pair.Reference -ReferenceSymbol "save_general_regs" `
            -ReferencePatterns @('\badd(?:s|\.w)?\s+r2(?:,\s*r2)?,\s*#(?:32|0x20)',
                '\btst(?:\.w)?\s+lr,\s*#16',
                '\bvstmia\w*\s+r1!,\s*\{s16-s31\}',
                '\bvldmia\w*\s+r2,\s*\{s0-s16\}',
                '\bvstmia\w*\s+r1!,\s*\{s0-s16\}',
                '\bstmia(?:\.w)?\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
                '\bldmia(?:\.w)?\s+r2,\s*\{r4[^\r\n]*(r11|fp)\}') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "PendSV_Handler" `
            -FiberPatterns @('\badd(?:s|\.w)?\s+r0(?:,\s*r0)?,\s*#(?:32|0x20)',
                '\btst(?:\.w)?\s+lr,\s*#16',
                '\bvstmia\w*\s+r1!,\s*\{s16-s31\}',
                '\bvldmia\w*\s+r0,\s*\{s0-s16\}',
                '\bvstmia\w*\s+r1!,\s*\{s0-s16\}',
                '\bstmia(?:\.w)?\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
                '\bldmia(?:\.w)?\s+r0,\s*\{r4[^\r\n]*(r11|fp)\}') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-MPU-PROTECTED-FRAME",
                $cm55MpuPendSvDifferenceId) `
            -Ledger $ledger
        Assert-MechanismParity -PortName $cm55fMpuPendSvName -Mechanism "PendSV-save-special" `
            -ReferenceDisassembly $pair.Reference -ReferenceSymbol "save_special_regs" `
            -ReferencePatterns @('\bmrs\s+r3,\s*PSPLIM', '\bmrs\s+r4,\s*CONTROL',
                '\bstmia(?:\.w)?\s+r1!,\s*\{r2[^\r\n]*lr\}',
                '\bstr\s+r1,\s*\[r0') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "PendSV_Handler" `
            -FiberPatterns @('\bmrs\s+r3,\s*PSPLIM', '\bmrs\s+r4,\s*CONTROL',
                '\bstmia(?:\.w)?\s+r1!,\s*\{r0[^\r\n]*lr\}',
                '\bstr\s+r1,\s*\[r2') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-MPU-PROTECTED-FRAME",
                $cm55MpuPendSvDifferenceId) `
            -Ledger $ledger
        Assert-MechanismParity -PortName $cm55fMpuPendSvName -Mechanism "PendSV-scheduler" `
            -ReferenceDisassembly $pair.Reference -ReferenceSymbol "select_next_task" `
            -ReferencePatterns @('\bmsr\s+BASEPRI', 'vTaskSwitchContext',
                '\bmov(?:s|\.w)?\s+r0,\s*#0', '\bmsr\s+BASEPRI') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "PendSV_Handler" `
            -FiberPatterns @('\bmsr\s+BASEPRI',
                'fiber_port_scheduler_pick_next_from_pendsv', '\bcpsid\s+i') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-MASK-RESTORE",
                $cm55MpuPendSvDifferenceId) `
            -Ledger $ledger
        Assert-MechanismParity -PortName $cm55fMpuPendSvName -Mechanism "PendSV-MPU-replace" `
            -ReferenceDisassembly $pair.Reference -ReferenceSymbol "program_mpu" `
            -ReferencePatterns @('\bdmb\b', '\bbic(?:\.w)?\s+r2',
                '\badds\s+r0,\s*#4', '\bmovs\s+r3,\s*#4',
                '\bldmia(?:\.w)?\s+r0!', '\bstmia(?:\.w)?\s+r2',
                '\borr(?:\.w)?\s+r2', '\bdsb\b') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "fiber_port_mpu_switch_to_context" `
            -FiberPatterns @('fiber_port_context_validate_restore', '\bdsb\b',
                '\bstr\b', '\bisb\b', 'fiber_port_mpu_validate_active_context') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-MPU-ATOMIC-SWITCH", $cm55MpuPendSvDifferenceId) `
            -Ledger $ledger
        Assert-MechanismParity -PortName $cm55fMpuPendSvName -Mechanism "PendSV-restore-FP" `
            -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_special_regs" `
            -ReferencePatterns @('\bldmdb\s+r1!,\s*\{r2[^\r\n]*lr\}',
                '\bmsr\s+PSP', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "PendSV_Handler" `
            -FiberPatterns @('\bldmdb\s+r1!,\s*\{r0,\s*r3,\s*r4,\s*lr\}',
                '\bmsr\s+PSP', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL',
                '\bldmdb\s+r1!,\s*\{r4[^\r\n]*(r11|fp)\}',
                '\bstmia(?:\.w)?\s+r0!,\s*\{r4[^\r\n]*(r11|fp)\}',
                '\bvldmdb\w*\s+r1!,\s*\{s0-s16\}',
                '\bvstmia\w*\s+r0!,\s*\{s0-s16\}',
                '\bvldmdb\w*\s+r1!,\s*\{s16-s31\}') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-MPU-PROTECTED-FRAME",
                $cm55MpuPendSvDifferenceId) `
            -Ledger $ledger
        Assert-MechanismParity -PortName $cm55fMpuPendSvName -Mechanism "PendSV-complete" `
            -ReferenceDisassembly $pair.Reference -ReferenceSymbol "restore_context_done" `
            -ReferencePatterns @('\bstr\s+r1,\s*\[r0', '\bbx\s+lr\b') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "PendSV_Handler" `
            -FiberPatterns @('\bstr\s+r1,\s*\[r2', '\bcpsie\s+i', '\bbx\s+lr\b') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE",
                $cm55MpuPendSvDifferenceId) `
            -Ledger $ledger
        $referenceSave = Get-DisassemblyFunctionBody -Disassembly $pair.Reference `
            -Symbol "save_general_regs" -Path $pair.ReferencePath
        $fiberPendSv = Get-DisassemblyFunctionBody -Disassembly $pair.Fiber `
            -Symbol "PendSV_Handler" -Path $pair.FiberPath
        Assert-AbsentPatterns -Body $referenceSave -Patterns @('\b(?:vpr|mve)\b') `
        -Label "$cm55fMpuPendSvName FreeRTOS protected FP/MVE PendSV VPR state"
        Assert-AbsentPatterns -Body $fiberPendSv -Patterns @('\b(?:vpr|mve)\b') `
        -Label "$cm55fMpuPendSvName Fiber protected FP/MVE PendSV VPR state"
    }

    # MVE-FP uses the same pinned non-MPU basic initial frame as scalar FP.
    # MVE changes the later conditional high-register save contract, not this
    # general-registers-only constructor.
    $pair = $compiled["ARM_CM55_MVEF_NTZ_CONSTRUCTION"]
    Assert-MechanismParity -PortName "ARM_CM55_MVEF_NTZ" `
        -Mechanism "initial-construction" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "pxPortInitialiseStack" `
        -ReferencePatterns @('#-?(?:72|0x48)\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_init_context_frame" `
        -FiberPatterns @('#-?(?:72|0x48)\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-M55MVE-CONSTRUCTION") `
        -Ledger $ledger
    $cm55MveReferenceConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Reference -Symbol "pxPortInitialiseStack" `
        -Path $pair.ReferencePath
    $cm55MveFiberConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Fiber -Symbol "fiber_port_init_context_frame" `
        -Path $pair.FiberPath
    Assert-AbsentPatterns -Body $cm55MveReferenceConstruction `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b') `
        -Label "ARM_CM55_MVEF_NTZ FreeRTOS initial construction"
    Assert-AbsentPatterns -Body $cm55MveFiberConstruction `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b') `
        -Label "ARM_CM55_MVEF_NTZ Fiber initial construction"

    # MVE-FP keeps the same integer-only initial SVC transfer as scalar FP.
    # MVE changes only the later conditional s16-s31 PendSV mechanism.
    $pair = $compiled["ARM_CM55_MVEF_NTZ_SVC"]
    Assert-MechanismParity -PortName "ARM_CM55_MVEF_NTZ" `
        -Mechanism "first-start" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f', '\bdsb\b', '\bisb\b', '\bsvc\s+\d+') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('\bcpsid\s+i', '\bmsr\s+CONTROL', '\bmsr\s+MSP', '\bmsr\s+BASEPRI', '\bcpsie\s+f', '\bcpsie\s+i', '\bdsb\b', '\bisb\b', '\bsvc\s+70') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-M55MVE-SVC") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM55_MVEF_NTZ" `
        -Mechanism "first-restore" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bldmia\s+r0!,\s*\{r1,\s*r2\}', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL', '\badds\s+r0,\s*#32', '\bmsr\s+PSP', '\bmsr\s+BASEPRI', '\bbx\s+r2') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @('\bmsr\s+BASEPRI', 'fiber_port_context_validate_restore', '\bldmia(\.w)?\s+r0!,\s*\{r2,\s*r3[^\r\n]*fp\}', '\bmsr\s+PSPLIM', '\bmrs\s+[^,]+,\s*PSPLIM', '\bmsr\s+CONTROL', '\bmsr\s+PSP', '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M55MVE-SVC") `
        -Ledger $ledger

    # The pinned non-MPU MVE branch deliberately uses the same conditional
    # s16-s31 backbone as scalar FP. Its MVE-specific invariant is negative:
    # neither FreeRTOS nor Fiber owns a VPR software-frame slot here.
    $pair = $compiled["ARM_CM55_MVEF_NTZ_PENDSV"]
    Assert-MechanismParity -PortName "ARM_CM55_MVEF_NTZ" `
        -Mechanism "MVE-FP PendSV" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @(
            '\bmrs\s+r0,\s*PSP',
            '\btst(?:\.w)?\s+lr,\s*#16',
            '\bvstmdb\w*\s+r0!,\s*\{s16-s31\}',
            '\bmrs\s+r2,\s*PSPLIM',
            '\bmov\s+r3,\s*lr',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'vTaskSwitchContext',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\btst(?:\.w)?\s+r3,\s*#16',
            '\bvldmia\w*\s+r0!,\s*\{s16-s31\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmsr\s+PSP,\s*r0',
            '\bbx\s+r3') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r0,\s*PSP',
            'fiber_port_context_validate_save_current',
            '\btst(?:\.w)?\s+lr,\s*#16',
            '\bvstmdb\w*\s+r0!,\s*\{s16-s31\}',
            '\bmrs\s+r3,\s*PSPLIM',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'fiber_port_scheduler_pick_next_from_pendsv',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\btst(?:\.w)?\s+r3,\s*#16',
            '\bvldmia\w*\s+r0!,\s*\{s16-s31\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmrs\s+r1,\s*PSPLIM',
            '\bmsr\s+PSP,\s*r0',
            '\bmrs\s+r1,\s*PSP',
            '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M55MVE-PENDSV") `
        -Ledger $ledger
    $cm55MveReferencePendSv = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Reference -Symbol "PendSV_Handler" `
        -Path $pair.ReferencePath
    $cm55MveFiberPendSv = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Fiber -Symbol "PendSV_Handler" `
        -Path $pair.FiberPath
    Assert-AbsentPatterns -Body $cm55MveReferencePendSv -Patterns @('\bvpr\b') `
        -Label "ARM_CM55_MVEF_NTZ FreeRTOS non-MPU PendSV VPR slot"
    Assert-AbsentPatterns -Body $cm55MveFiberPendSv -Patterns @('\bvpr\b') `
        -Label "ARM_CM55_MVEF_NTZ Fiber non-MPU PendSV VPR slot"

    $pair = $compiled["ARM_CM55F_NTZ_SVC"]
    Assert-MechanismParity -PortName "ARM_CM55F_NTZ" `
        -Mechanism "first-start" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @('\bmsr\s+MSP', '\bcpsie\s+i', '\bcpsie\s+f', '\bdsb\b', '\bisb\b', '\bsvc\s+\d+') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @('\bcpsid\s+i', '\bmsr\s+CONTROL', '\bmsr\s+MSP', '\bmsr\s+BASEPRI', '\bcpsie\s+f', '\bcpsie\s+i', '\bdsb\b', '\bisb\b', '\bsvc\s+70') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-M55F-SVC-START") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM55F_NTZ" `
        -Mechanism "first-restore" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @('\bldmia\s+r0!,\s*\{r1,\s*r2\}', '\bmsr\s+PSPLIM', '\bmsr\s+CONTROL', '\badds\s+r0,\s*#32', '\bmsr\s+PSP', '\bmsr\s+BASEPRI', '\bbx\s+r2') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @('\bmsr\s+BASEPRI', 'fiber_port_context_validate_restore', '\bldmia(\.w)?\s+r0!,\s*\{r2,\s*r3[^\r\n]*fp\}', '\bmsr\s+PSPLIM', '\bmrs\s+[^,]+,\s*PSPLIM', '\bmsr\s+CONTROL', '\bmsr\s+PSP', '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M55F-SVC-START") `
        -Ledger $ledger

    $pair = $compiled["ARM_CM55F_NTZ_PENDSV"]
    Assert-MechanismParity -PortName "ARM_CM55F_NTZ" `
        -Mechanism "FP PendSV" -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @(
            '\bmrs\s+r0,\s*PSP',
            '\btst(?:\.w)?\s+lr,\s*#16',
            '\bvstmdb\w*\s+r0!,\s*\{s16-s31\}',
            '\bmrs\s+r2,\s*PSPLIM',
            '\bmov\s+r3,\s*lr',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'vTaskSwitchContext',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\btst(?:\.w)?\s+r3,\s*#16',
            '\bvldmia\w*\s+r0!,\s*\{s16-s31\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmsr\s+PSP,\s*r0',
            '\bbx\s+r3') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r0,\s*PSP',
            'fiber_port_context_validate_save_current',
            '\btst(?:\.w)?\s+lr,\s*#16',
            '\bvstmdb\w*\s+r0!,\s*\{s16-s31\}',
            '\bmrs\s+r3,\s*PSPLIM',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'fiber_port_scheduler_pick_next_from_pendsv',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\btst(?:\.w)?\s+r3,\s*#16',
            '\bvldmia\w*\s+r0!,\s*\{s16-s31\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmrs\s+r1,\s*PSPLIM',
            '\bmsr\s+PSP,\s*r0',
            '\bmrs\s+r1,\s*PSP',
            '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M55F-FP-PENDSV") `
        -Ledger $ledger

    # FPU enablement does not change the initial FreeRTOS stack image. This
    # mechanism proves construction only; SVC and PendSV have separate proofs.
    $pair = $compiled["ARM_CM33F_NTZ_CONSTRUCTION"]
    Assert-MechanismParity -PortName "ARM_CM33F_NTZ" `
        -Mechanism "initial-construction" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "pxPortInitialiseStack" `
        -ReferencePatterns @('#-?(?:72|0x48)\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_init_context_frame" `
        -FiberPatterns @('#-?(?:72|0x48)\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33F-CONSTRUCTION") `
        -Ledger $ledger
    $cm33fReferenceConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Reference -Symbol "pxPortInitialiseStack" `
        -Path $pair.ReferencePath
    $cm33fFiberConstruction = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Fiber -Symbol "fiber_port_init_context_frame" `
        -Path $pair.FiberPath
    Assert-AbsentPatterns -Body $cm33fReferenceConstruction `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b') `
        -Label "ARM_CM33F_NTZ FreeRTOS initial construction"
    Assert-AbsentPatterns -Body $cm33fFiberConstruction `
        -Patterns @('\bv(?:stm|ldm|push|pop|mov|ldr|str)\w*\b') `
        -Label "ARM_CM33F_NTZ Fiber initial construction"

    # The selected TrustZone profile retains the exact FreeRTOS
    # non-MPU/no-FPU 19-word initial image. Separate mechanisms prove Secure
    # save/load, first start, and the complete PendSV switch choreography.
    $pair = $compiled["ARM_CM33_SECURE_CONTEXT_CONSTRUCTION"]
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "initial-construction" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "pxPortInitialiseStack" `
        -ReferencePatterns @('#-?(?:76|0x4c)\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_init_context_frame" `
        -FiberPatterns @('#-?(?:76|0x4c)\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-CONSTRUCTION") `
        -Ledger $ledger

    $pair = $compiled["ARM_CM33_SECURE_CONTEXT_ALLOCATOR"]
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "allocation-gate" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "SecureContext_AllocateContext" `
        -ReferencePatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\bmrs\s+[^,]+,\s*PSPLIM',
            '\b(?:bl|b\.w)\s+[^\r\n]*pvPortMalloc') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_secure_context_gateway_v1_allocate" `
        -FiberPatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\bcmp\s+[^,]+,\s*#11\b',
            '\bmrs\s+[^,]+,\s*PSPLIM',
            '\b(?:bl|b\.w)\s+[^\r\n]*fiber_secure_context_pool_allocate') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-ALLOCATOR") `
        -Ledger $ledger

    $pair = $compiled["ARM_CM33_SECURE_CONTEXT_DEPRIORITIZE"]
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "secure-exception-priority" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "SecureInit_DePrioritizeNSExceptions" `
        -ReferencePatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\b(?:cbz|cmp)\b',
            '\bldr(?:\.w)?\b',
            '\bstr(?:\.w)?\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_secure_context_gateway_v1_initialize" `
        -FiberPatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\bcmp\s+[^,]+,\s*#11\b',
            '\bldr(?:\.w)?\b',
            '\bstr(?:\.w)?\b',
            '\bdsb\b',
            '\bisb\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-INITIALIZE") `
        -Ledger $ledger

    $pair = $compiled["ARM_CM33_SECURE_CONTEXT_INITIALIZE"]
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "secure-context-init" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "SecureContext_Init" `
        -ReferencePatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\bmsr\s+PSPLIM',
            '\bmsr\s+PSP',
            '\bmsr\s+CONTROL') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_secure_context_gateway_v1_initialize" `
        -FiberPatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\bmsr\s+PSPLIM',
            '\bmsr\s+PSP',
            'fiber_secure_context_pool_boot_initialize',
            '\bmsr\s+CONTROL') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-INITIALIZE") `
        -Ledger $ledger

    $pair = $compiled["ARM_CM33_SECURE_CONTEXT_LOAD"]
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "secure-context-load" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "SecureContext_LoadContextAsm" `
        -ReferencePatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\bldmia(?:\.w)?\b',
            '\bmsr\s+PSPLIM',
            '\bmsr\s+PSP') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_secure_context_gateway_v1_load" `
        -FiberPatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\bcmp(?:\.w)?\s+[^,]+,\s*#11\b',
            'fiber_secure_context_pool_lookup_owned',
            '\bmsr\s+PSPLIM',
            '\bmrs\s+[^,]+,\s*PSPLIM',
            '\bmsr\s+PSP',
            '\bmrs\s+[^,]+,\s*PSP') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-LOAD") `
        -Ledger $ledger

    $pair = $compiled["ARM_CM33_SECURE_CONTEXT_SAVE"]
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "secure-context-save" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "SecureContext_SaveContextAsm" `
        -ReferencePatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\bmrs\s+[^,]+,\s*PSP',
            '\bstr(?:\.w)?\s+[^,]+,\s*\[[^\]]+\]',
            '\bmsr\s+PSPLIM',
            '\bmsr\s+PSP') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_secure_context_gateway_v1_save" `
        -FiberPatterns @(
            '\bmrs\s+[^,]+,\s*IPSR',
            '\bcmp(?:\.w)?\s+[^,]+,\s*#14\b',
            'fiber_secure_context_pool_lookup_owned',
            '\bmrs\s+[^,]+,\s*PSP',
            '\bstr(?:\.w)?\s+[^,]+,\s*\[[^\]]+\]',
            '\bmsr\s+PSPLIM',
            '\bmrs\s+[^,]+,\s*PSPLIM',
            '\bmsr\s+PSP',
            '\bmrs\s+[^,]+,\s*PSP') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-SAVE") `
        -Ledger $ledger

    $pair = $compiled["ARM_CM33_SECURE_CONTEXT_SVC"]
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "first-start-trigger" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @(
            '\bmsr\s+MSP',
            '\bcpsie\s+i',
            '\bcpsie\s+f',
            '\bsvc\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @(
            '\bcpsid\s+i',
            '\bmsr\s+CONTROL',
            '\bmsr\s+MSP',
            '\bmsr\s+BASEPRI',
            '\bcpsie\s+f',
            '\bcpsie\s+i',
            '\bsvc\s+70\b') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-FIRST-START") `
        -Ledger $ledger

    $pair = $compiled["ARM_CM33_SECURE_CONTEXT_PENDSV"]
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "PendSV-entry" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @(
            '\bldr\s+r0',
            '\bldr\s+r1',
            '\bmrs\s+r2,\s*PSP') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r3,\s*IPSR',
            '\bcmp\s+r3,\s*#14',
            '\bmrs\s+r0,\s*PSP',
            '\bldr\s+r1,\s*\[pc',
            '\bldr\s+r1,\s*\[r1',
            'fiber_port_context_validate_save_current') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "PendSV-secure-save" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "save_s_context" `
        -ReferencePatterns @('SecureContext_SaveContext') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('fiber_port_secure_context_save_current_from_pendsv') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-SAVE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "PendSV-save-general" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "save_general_regs" `
        -ReferencePatterns @('\bstmdb\s+r2!,\s*\{r4[^\r\n]*fp\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bstmdb\s+r0!,\s*\{r4[^\r\n]*fp\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-LAZY-ALLOCATE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "PendSV-save-special" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "save_special_regs" `
        -ReferencePatterns @(
            '\bmrs\s+r3,\s*PSPLIM',
            '\bstmdb\s+r2!,\s*\{r0[^\r\n]*lr\}',
            '\bstr\s+r2') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r3,\s*PSPLIM',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*lr\}',
            '\bstr\s+r0') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-LAZY-ALLOCATE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "PendSV-scheduler" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "select_next_task" `
        -ReferencePatterns @(
            '\bmsr\s+BASEPRI',
            'vTaskSwitchContext',
            '\bmov(?:\.w)?\s+r0,\s*#0',
            '\bmsr\s+BASEPRI') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmsr\s+BASEPRI',
            'fiber_port_scheduler_pick_next_from_pendsv',
            '\bmsr\s+BASEPRI') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @(
            "FAP-COMMON-SCHEDULER",
            "FAP-COMMON-MASK-RESTORE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "PendSV-restore-special" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "restore_special_regs" `
        -ReferencePatterns @(
            '\bldmia(?:\.w)?\s+r2!,\s*\{r0[^\r\n]*lr\}',
            '\bmsr\s+PSPLIM') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            'fiber_port_secure_context_prepare_next_from_pendsv',
            '\bldmia(?:\.w)?\s+r2!,\s*\{r0[^\r\n]*lr\}',
            '\bmsr\s+PSPLIM',
            '\bmrs\s+(?:r12|ip),\s*PSPLIM') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @(
            "FAP-M33-PSPLIM-READBACK",
            "FAP-CM33-SECURE-CONTEXT-LAZY-ALLOCATE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "PendSV-secure-load" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "restore_s_context" `
        -ReferencePatterns @('SecureContext_LoadContext') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('fiber_port_secure_context_load_next_from_pendsv') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-LAZY-ALLOCATE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "PendSV-restore-general" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "restore_general_regs" `
        -ReferencePatterns @('\bldmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*fp\}') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @('\bldmia(?:\.w)?\s+r2!,\s*\{r4[^\r\n]*fp\}') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-LAZY-ALLOCATE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "PendSV-complete" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "restore_context_done" `
        -ReferencePatterns @('\bmsr\s+PSP,\s*r2', '\bbx\s+lr') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmsr\s+PSP,\s*r2',
            '\bmrs\s+r1,\s*PSP',
            '\bbx\s+lr') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-PROVENANCE") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33 SecureContext" `
        -Mechanism "first-context-restore" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vRestoreContextOfFirstTask" `
        -ReferencePatterns @(
            '\bldmia?(?:\.w)?\s+r0!,\s*\{r1[^\r\n]*r3\}',
            '\bmsr\s+PSPLIM',
            '\bmsr\s+CONTROL',
            '\bmsr\s+PSP',
            '\bbx\s+r3') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r3,\s*IPSR',
            '\bcmp\s+r3,\s*#11\b',
            'fiber_port_secure_context_prepare_first_start',
            '\bldmia(?:\.w)?\s+r0!,\s*\{r1[^\r\n]*fp\}',
            '\bmsr\s+PSPLIM',
            '\bmsr\s+CONTROL',
            '\bmsr\s+PSP',
            '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33-SECURE-CONTEXT-FIRST-START") `
        -Ledger $ledger

    $pair = $compiled["ARM_CM33F_NTZ_SVC"]
    Assert-MechanismParity -PortName "ARM_CM33F_NTZ" `
        -Mechanism "first-start" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "vStartFirstTask" `
        -ReferencePatterns @(
            '\bldr\s+r0,\s*\[r0(?:,\s*#0)?\]',
            '\bmsr\s+MSP,\s*r0',
            '\bcpsie\s+i',
            '\bcpsie\s+f',
            '\bsvc\b') `
        -ReferencePath $pair.ReferencePath `
        -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_port_start_first_context" `
        -FiberPatterns @(
            '\bcpsid\s+i',
            '\bmsr\s+CONTROL,\s*r3',
            '\bmsr\s+MSP,\s*r0',
            '\bmsr\s+BASEPRI,\s*r0',
            '\bcpsie\s+f',
            '\bcpsie\s+i',
            '\bsvc\s+70') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33F-SVC-START") `
        -Ledger $ledger
    Assert-MechanismParity -PortName "ARM_CM33F_NTZ" `
        -Mechanism "first-restore" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "SVC_Handler" `
        -ReferencePatterns @(
            '\btst(?:\.w)?\s+lr,\s*#4',
            '\bmrseq\s+r0,\s*MSP',
            '\bmrsne\s+r0,\s*PSP',
            '\bbx\s+r1') `
        -ReferencePath $pair.ReferencePath `
        -FiberDisassembly $pair.Fiber `
        -FiberSymbol "SVC_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r3,\s*IPSR',
            '\bcmp\s+r3,\s*#11',
            '\bmvn(?:\.w)?\s+r3,\s*#71',
            '\bmsr\s+BASEPRI,\s*r0',
            'fiber_port_context_validate_restore',
            '\bldmia(?:\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmsr\s+CONTROL,\s*r1',
            '\bmsr\s+PSP,\s*r0',
            '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-CM33F-SVC-START") `
        -Ledger $ledger
    $pair = $compiled["ARM_CM33F_NTZ_PENDSV"]
    Assert-MechanismParity -PortName "ARM_CM33F_NTZ" `
        -Mechanism "FP-aware-PendSV" `
        -ReferenceDisassembly $pair.Reference `
        -ReferenceSymbol "PendSV_Handler" `
        -ReferencePatterns @(
            '\bmrs\s+r0,\s*PSP',
            '\btst(?:\.w)?\s+lr,\s*#(?:0x10|16)',
            '\bvstm(?:db)?(?:eq)?\s+r0!,\s*\{s16-s31\}',
            '\bmrs\s+r2,\s*PSPLIM',
            '\bmov\s+r3,\s*lr',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'vTaskSwitchContext',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\btst(?:\.w)?\s+r3,\s*#(?:0x10|16)',
            '\bvldmia(?:eq)?\s+r0!,\s*\{s16-s31\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmsr\s+PSP,\s*r0',
            '\bbx\s+r3') `
        -ReferencePath $pair.ReferencePath `
        -FiberDisassembly $pair.Fiber `
        -FiberSymbol "PendSV_Handler" `
        -FiberPatterns @(
            '\bmrs\s+r0,\s*PSP',
            'fiber_port_context_validate_save_current',
            '\btst(?:\.w)?\s+lr,\s*#(?:0x10|16)',
            '\bvstmdb\s+r0!,\s*\{s16-s31\}',
            '\bmrs\s+r3,\s*PSPLIM',
            '\bstmdb\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\bstr\s+r0',
            '\bmsr\s+BASEPRI',
            'fiber_port_scheduler_pick_next_from_pendsv',
            '\bmsr\s+BASEPRI',
            '\bldmia(\.w)?\s+r0!,\s*\{r2[^\r\n]*fp\}',
            '\btst(?:\.w)?\s+r3,\s*#(?:0x10|16)',
            '\bvldmia\s+r0!,\s*\{s16-s31\}',
            '\bmsr\s+PSPLIM,\s*r2',
            '\bmrs\s+r1,\s*PSPLIM',
            '\bmsr\s+PSP,\s*r0',
            '\bmrs\s+r1,\s*PSP',
            '\bbx\s+r3') `
        -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-M33-PSPLIM-READBACK", "FAP-CM33F-FP-PENDSV") `
        -Ledger $ledger

    # MPU ports deliberately retain the FreeRTOS protected-context model:
    # hardware frames are copied to privileged context storage and MPU state is
    # replaced before returning to unprivileged Thread mode.
    foreach ($mpuPort in @(
            [pscustomobject]@{ Name = "ARM_CM3_MPU"; HasFp = $false },
            [pscustomobject]@{ Name = "ARM_CM4_MPU"; HasFp = $true })) {
        $pair = $compiled[$mpuPort.Name]
        Assert-MechanismParity -PortName $mpuPort.Name `
            -Mechanism "SVC-dispatch" -ReferenceDisassembly $pair.Reference `
            -ReferenceSymbol "vPortSVCHandler" `
            -ReferencePatterns @('\btst(\.w)?\s+lr,\s*#4', '\bmrs(eq)?\s+r0,\s*MSP', '\bmrs(ne)?\s+r0,\s*PSP', '\bldr\s+r[12],\s*\[r0,\s*#24\]', '\bldrb(\.w)?\s+r[12]', 'vSVCHandler_C') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "SVC_Handler" `
            -FiberPatterns @('\btst(\.w)?\s+lr,\s*#4', '\bmrs(eq)?\s+r0,\s*MSP', '\bmrs(ne)?\s+r0,\s*PSP', 'fiber_port_svc_dispatch') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-MPU-SVC-NAMESPACE") `
            -Ledger $ledger
        Assert-MechanismParity -PortName $mpuPort.Name `
            -Mechanism "first-restore" -ReferenceDisassembly $pair.Reference `
            -ReferenceSymbol "prvRestoreContextOfFirstTask" `
            -ReferencePatterns @('\bmsr\s+MSP', '\bdmb\b', '\bldmia(\.w)?\s+r2!', '\bstmia(\.w)?\s+r0', '\bdsb\b', '\bldmdb\s+r1!', '\bmsr\s+PSP', '\bstmia(\.w)?\s+r0', '\bldmdb\s+r1!', '\bmsr\s+CONTROL', '\bmsr\s+BASEPRI', '\bbx\s+lr') `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "fiber_port_restore_first_context_from_svc" `
            -FiberPatterns @('\bmsr\s+MSP', '\bldmdb\s+r1!', '\bmsr\s+PSP', '\bstmia(\.w)?\s+r0', '\bldmdb\s+r1!', '\bmsr\s+CONTROL', '\bmsr\s+BASEPRI', '\bbx\s+lr') `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-PROVENANCE", "FAP-MPU-PROTECTED-FRAME", "FAP-MPU-FIRST-ACTIVATION-SPLIT") `
            -Ledger $ledger

        $fiberSvcDispatch = Get-DisassemblyFunctionBody `
            -Disassembly $pair.Fiber -Symbol "fiber_port_svc_dispatch" `
            -Path $pair.FiberPath
        Assert-OrderedPatterns -Body $fiberSvcDispatch `
            -Patterns @('fiber_port_mpu_activate_first_context',
                'fiber_port_restore_first_context_from_svc') `
            -Label "$($mpuPort.Name) Fiber first MPU activation split"

        $referencePendSv = @(
            '\bmrs\s+r3,\s*CONTROL', '\bmrs\s+r0,\s*PSP')
        $fiberPendSv = @(
            '\bmrs\s+r0,\s*PSP',
            'fiber_port_pendsv_validate_save_current',
            '\bmrs\s+r[23],\s*CONTROL')
        if ($mpuPort.HasFp) {
            $referencePendSv += @('\bvstmia(eq)?\s+r1!,\s*\{s16-s31\}', '\bvldmia(eq)?\s+r0,\s*\{s0-s16\}', '\bvstmia(eq)?\s+r1!,\s*\{s0-s16\}')
            $fiberPendSv += @('\bvstmia(eq)?\s+r1!,\s*\{s16-s31\}', '\bvldmia(eq)?\s+r0,\s*\{s0-s16\}', '\bvstmia(eq)?\s+r1!,\s*\{s0-s16\}')
        }
        $referencePendSv += @(
            '\bstmia(\.w)?\s+r1!,\s*\{r3[^\r\n]*lr\}',
            '\bldmia(\.w)?\s+r0,\s*\{r4[^\r\n]*fp\}',
            '\bstmia(\.w)?\s+r1!,\s*\{r0[^\r\n]*fp\}',
            '\bmsr\s+BASEPRI', 'vTaskSwitchContext', '\bmsr\s+BASEPRI',
            '\bdmb\b', '\bldmia(\.w)?\s+r2!', '\bstmia(\.w)?\s+r0',
            '\bldmdb\s+r1!', '\bmsr\s+PSP', '\bstmia(\.w)?\s+r0',
            '\bldmdb\s+r1!', '\bmsr\s+CONTROL')
        $fiberPendSv += @(
            '\bstmia(\.w)?\s+r[13]!,\s*\{r[23][^\r\n]*lr\}',
            '\bldmia(\.w)?\s+r0,\s*\{r4[^\r\n]*fp\}',
            '\bstmia(\.w)?\s+r[13]!,\s*\{r0[^\r\n]*fp\}',
            '\bmsr\s+BASEPRI', 'fiber_port_scheduler_pick_next_from_pendsv',
            '\bcpsid\s+i', 'fiber_port_mpu_switch_to_context',
            '\bmsr\s+BASEPRI', '\bldmdb\s+r1!', '\bmsr\s+PSP',
            '\bstmia(\.w)?\s+r0', '\bldmdb\s+r1!', '\bmsr\s+CONTROL')
        if ($mpuPort.HasFp) {
            $referencePendSv += @('\bvldmdb(eq)?\s+r1!,\s*\{s0-s16\}', '\bvstmia(eq)?\s+r0!,\s*\{s0-s16\}', '\bvldmdb(eq)?\s+r1!,\s*\{s16-s31\}')
            $fiberPendSv += @('\bvldmdb(eq)?\s+r1!,\s*\{s0-s16\}', '\bvstmia(eq)?\s+r0!,\s*\{s0-s16\}', '\bvldmdb(eq)?\s+r1!,\s*\{s16-s31\}')
        }
        $referencePendSv += '\bbx\s+lr'
        $fiberPendSv += @('\bcpsie\s+i', '\bbx\s+lr')
        Assert-MechanismParity -PortName $mpuPort.Name `
            -Mechanism "PendSV-MPU" -ReferenceDisassembly $pair.Reference `
            -ReferenceSymbol "xPortPendSVHandler" `
            -ReferencePatterns $referencePendSv `
            -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
            -FiberSymbol "PendSV_Handler" -FiberPatterns $fiberPendSv `
            -FiberPath $pair.FiberPath `
            -DifferenceIds @("FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-MPU-PROTECTED-FRAME", "FAP-MPU-ATOMIC-SWITCH") `
            -Ledger $ledger
    }

    Write-Host "FREERTOS_ASM_PARITY_PASS ($Optimization)"
    if ($KeepBuild -or (-not $ownsBuildRoot)) {
        Write-Host "Parity build retained: $BuildRoot"
    }
}
finally {
    if ($ownsBuildRoot -and (-not $KeepBuild) -and
            (Test-Path -LiteralPath $BuildRoot)) {
        Remove-Item -LiteralPath $BuildRoot -Recurse -Force
    }
}
