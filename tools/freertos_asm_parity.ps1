param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosKernel = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$BuildRoot,
    [ValidateSet("-O2", "-Os")]
    [string]$Optimization = "-O2",
    [switch]$ReferenceIdentityOnly,
    [switch]$Cm33fRunningOnly,
    [switch]$Cm55TfmOnly,
    [switch]$Cm33fTfmOnly,
    [switch]$Cm33SecureContextOnly,
    [switch]$Cm33SecureOnly,
    [switch]$Cm55SecureOnly,
    [switch]$Cm0Only,
    [switch]$Cm3Only,
    [switch]$KeepBuild,
    [string]$Python = "python",
    [string]$PythonModules = $env:FIBER_CLASSIC_AUDIT_PYTHONPATH
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ExpectedFreeRtosCommit = "a50edad08b29052631aa469d4df6e6ec7ff68878"
$ClassicOnly = $Cm0Only -or $Cm3Only
$ClassicName = if ($Cm3Only) { 'CM3' } else { 'CM0' }
$ClassicEvidence = "$ClassicName-FOCUSED"

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

function Get-BackwardLoopContaining {
    param([string]$Body, [string]$OperationPattern, [string]$Label)

    # Inspect real branch addresses, including M55 low-overhead LE loops. A
    # byte-access fingerprint outside the loop is not evidence of a full scrub.
    $instructions = @([regex]::Matches($Body,
        '(?m)^[ \t]*(?<address>[0-9a-f]+):[ \t]+[0-9a-f]{4}(?:[ \t]+[0-9a-f]{4})?[ \t]+(?<opcode>[a-z][a-z0-9.]+)[ \t]*(?<operands>[^\r\n]*)$') |
        ForEach-Object {
            [pscustomobject]@{
                Address = [Convert]::ToUInt32($_.Groups['address'].Value, 16)
                Opcode = $_.Groups['opcode'].Value
                Operands = $_.Groups['operands'].Value
                Text = $_.Value
            }
        })
    foreach ($instruction in $instructions) {
        if ($instruction.Opcode -notmatch '^(?:b(?:ne|eq|cc|cs|hi|ls)?(?:\.[nw])?|le)$') {
            continue
        }
        $target = [regex]::Match($instruction.Operands,
            '^(?:lr,\s*)?(?<address>[0-9a-f]+)\s+<')
        if (-not $target.Success) { continue }
        $address = [Convert]::ToUInt32($target.Groups['address'].Value, 16)
        if ($address -ge $instruction.Address) { continue }
        $loopInstructions = @($instructions | Where-Object {
            ($_.Address -ge $address) -and
            ($_.Address -le $instruction.Address)
        })
        # Size optimization may place the common trap before the scrub. A
        # backward branch to that noreturn call is an exit, not a loop edge.
        if (($loopInstructions[0].Opcode -match '^bl') -and
                ($loopInstructions[0].Operands -match '<fiber_secure_context_pool_fail_closed>')) {
            continue
        }
        $loop = ($loopInstructions | ForEach-Object { $_.Text }) -join "`n"
        if ([regex]::IsMatch($loop, $OperationPattern)) {
            return [pscustomobject]@{
                Start = $address; End = $instruction.Address; Body = $loop
            }
        }
    }
    throw "$Label lost a backward loop containing $OperationPattern`n$Body"
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

    if ((Get-Variable -Name ClassicOnly -ValueOnly -ErrorAction SilentlyContinue) -eq $true) {
        ConvertTo-Json -InputObject (@($Compiler) + $Arguments) -Compress |
            Add-Content -LiteralPath (Join-Path $BuildRoot "$ClassicEvidence/commands.jsonl") -Encoding ASCII
    }
    & $Compiler @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label compile failed"
    }
}

function Add-BoundCallRelocationTargets {
    param([string]$Disassembly)

    # In a function-sections object, a BL placeholder can name the enclosing
    # function. Only the immediately following relocation at the same byte
    # offset establishes its real target. Replace only that operand's symbolic
    # target; leave the instruction bytes and authoritative relocation intact.
    # Never attach the relocation to an unrelated predecessor.
    $pattern = '(?m)^(?<prefix>[ \t]*(?<address>[0-9a-fA-F]+):[ \t]+' +
        '[0-9a-fA-F]{4}(?:[ \t]+[0-9a-fA-F]{4})?[ \t]+' +
        '(?<opcode>bl(?:\.w)?|b\.w)[ \t]+)' +
        '(?<destination>[0-9a-fA-F]+)[ \t]+<[^>]+>[^\r\n]*' +
        '(?<newline>\r?\n)(?<relocation>[ \t]*(?<relAddress>[0-9a-fA-F]+):[ \t]+' +
        '(?<kind>R_ARM_THM_CALL|R_ARM_THM_JUMP24)[ \t]+' +
        '(?<target>[A-Za-z_.$][A-Za-z0-9_.$]*(?:[+-]0x[0-9a-fA-F]+)?)[ \t]*\r?$)'
    return [regex]::Replace($Disassembly, $pattern, {
        param($match)
        $sameOffset = [Convert]::ToUInt64($match.Groups['address'].Value, 16) -eq
            [Convert]::ToUInt64($match.Groups['relAddress'].Value, 16)
        $sameOpcode = (($match.Groups['kind'].Value -eq 'R_ARM_THM_CALL') -and
                ($match.Groups['opcode'].Value -match '^bl')) -or
            (($match.Groups['kind'].Value -eq 'R_ARM_THM_JUMP24') -and
                ($match.Groups['opcode'].Value -eq 'b.w'))
        if (-not ($sameOffset -and $sameOpcode)) { return $match.Value }
        return $match.Groups['prefix'].Value + $match.Groups['destination'].Value +
            ' <' + $match.Groups['target'].Value + '>' + $match.Groups['newline'].Value +
            $match.Groups['relocation'].Value
    })
}

function Get-ObjectDisassembly {
    param(
        [string]$Objdump,
        [string]$ObjectPath
    )

    if ((Get-Variable -Name ClassicOnly -ValueOnly -ErrorAction SilentlyContinue) -eq $true) {
        ConvertTo-Json -InputObject @($Objdump, '-dr', $ObjectPath) -Compress |
            Add-Content -LiteralPath (Join-Path $BuildRoot "$ClassicEvidence/commands.jsonl") -Encoding ASCII
    }
    $result = (& $Objdump -dr $ObjectPath) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed: $ObjectPath"
    }
    return Add-BoundCallRelocationTargets -Disassembly $result
}

function Assert-ReferenceIdentity {
    param(
        [string]$KernelRoot,
        [hashtable]$ExpectedFiles
    )

    $commit = ((& git --no-optional-locks -C $KernelRoot rev-parse HEAD) -join "").Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot read pinned FreeRTOS commit"
    }
    if ($commit -ne $ExpectedFreeRtosCommit) {
        throw "FreeRTOS reference drifted: expected $ExpectedFreeRtosCommit, got $commit"
    }

    # Reject additions too: an untracked or ignored header beside a pinned
    # source can shadow the intended dependency without changing HEAD. Disable
    # optional index refresh writes; validation must never mutate the reference.
    $status = @(& git --no-optional-locks -c core.fsmonitor=false -C $KernelRoot `
        status --porcelain=v1 --untracked-files=all --ignored=matching)
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot inspect pinned FreeRTOS worktree"
    }
    if ($status.Count -ne 0) {
        throw "Pinned FreeRTOS worktree is not clean (tracked/untracked/ignored):`n$($status -join "`n")"
    }

    # Hash every tracked regular file, not just the historical SHA256 subset.
    # This also catches consumed-header changes hidden by assume-unchanged,
    # skip-worktree, or cached file metadata. Git applies the pinned checkout's
    # text normalization, so a normal Windows CRLF checkout remains valid.
    # hash-object without -w is read-only. The two non-consumed third-party
    # submodule entries are not regular files and are not compiled by this tool.
    $tree = @(& git --no-optional-locks -C $KernelRoot ls-tree -r HEAD)
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot enumerate pinned FreeRTOS tree"
    }
    $tracked = @($tree | ForEach-Object {
        if ($_ -match '^100(?:644|755) blob (?<hash>[0-9a-f]{40})\t(?<path>.+)$') {
            [pscustomobject]@{ Hash = $Matches['hash']; Path = $Matches['path'] }
        } elseif ($_ -notmatch '^160000 commit [0-9a-f]{40}\t') {
            throw "Unsupported pinned FreeRTOS tree entry: $_"
        }
    })
    if ($tracked.Count -eq 0) {
        throw "Pinned FreeRTOS tree contains no regular files"
    }
    $actualHashes = @($tracked | ForEach-Object { $_.Path } |
        & git --no-optional-locks -C $KernelRoot hash-object --stdin-paths)
    if (($LASTEXITCODE -ne 0) -or ($actualHashes.Count -ne $tracked.Count)) {
        throw "Cannot hash all pinned FreeRTOS files"
    }
    for ($index = 0; $index -lt $tracked.Count; ++$index) {
        if ($actualHashes[$index] -ne $tracked[$index].Hash) {
            throw "Pinned FreeRTOS tracked content drifted: $($tracked[$index].Path)"
        }
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
        $definitions = @($PortDefinitions | Where-Object {
            $_.ProfileDir -eq $profile -and ($null -ne $_.PSObject.Properties['Staged']) -and $_.Staged -eq 1
        })
        $metadataFlag = 0
        if ($definitions.Count -ne 1) { throw "Staged profile must have one exact definition: $profile" }
        if ($null -ne $definitions[0].PSObject.Properties['PendingSelectableMetadata']) {
            if ($definitions[0].PendingSelectableMetadata -ne 1) { throw "Invalid pending selectable metadata: $profile" }
            $metadataFlag = 1
        }
        if ($macroText -notmatch ('(?m)^\s*#define\s+FIBER_PORT_RUNTIME_SELECTABLE\s+'+$metadataFlag+'\s*$')) {
            throw "Staged runtime profile metadata must remain exactly $metadataFlag until qualification: $profile"
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
    if ((Get-Variable -Name ClassicOnly -ValueOnly -ErrorAction SilentlyContinue) -eq $true) {
        $script:cm0Mechanisms += [ordered]@{Port=$PortName; Mechanism=$Mechanism;
            ReferenceSymbol=$ReferenceSymbol; FiberSymbol=$FiberSymbol;
            ReferencePatterns=$ReferencePatterns; FiberPatterns=$FiberPatterns; DifferenceIds=$DifferenceIds}
    }
}

function Assert-Cm3Mechanisms {
    param([object]$Pair, [string]$Ledger)
    # ARMv7-M uses BASEPRI in both implementations. Fiber additionally carries
    # EXC_RETURN per context instead of manufacturing FD in the SVC handler.
    $pair = $Pair
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
}

function Start-ClassicFocusedEvidence {
    $directory = Join-Path $BuildRoot $ClassicEvidence
    if (@(Get-ChildItem -LiteralPath $BuildRoot -Force).Count) { throw "$ClassicName focused proof requires an empty BuildRoot" }
    $rationale = if ($Cm3Only) { 'FAP-CM3-LOCAL-LITERAL-POOLS' } else { 'FAP-CM0-THUMB1-VECTOR' }
    if ($ledger.IndexOf($rationale, [StringComparison]::Ordinal) -lt 0) { throw "$ClassicName focused rationale missing" }
    if (Test-Path -LiteralPath $directory) { throw "$ClassicName evidence exists; choose a fresh BuildRoot: $directory" }
    New-Item -ItemType Directory -Path $directory | Out-Null
    $paths = @($PSCommandPath, $ledgerPath, $compiler, $objdump, (Join-Path $toolDir 'arm-none-eabi-readelf.exe'))
    foreach ($tool in @('cc1', 'as')) {
        $path = (& $compiler "-print-prog-name=$tool") -join ''
        if ($LASTEXITCODE -ne 0) { throw "Cannot locate compiler $tool" }
        $paths += (Resolve-Path -LiteralPath $path.Trim()).Path
    }
    $include = (& $compiler '-print-file-name=include') -join ''
    if ($LASTEXITCODE -ne 0) { throw 'Cannot locate compiler headers' }
    foreach ($root in @($include.Trim(), (Join-Path (Split-Path $toolDir) 'arm-none-eabi/include'))) {
        $paths += @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.h' -File | Select-Object -ExpandProperty FullName)
    }
    $profileRoots = if ($Cm3Only) { @('ARM_CM3') } else { @('ARM_CM0', 'ARM_CM0_MPU') }
    $roots = @($RepoRoot, (Join-Path $RepoRoot 'context'),
        (Join-Path $RepoRoot 'fiber'), (Join-Path $RepoRoot 'fiber/port'),
        (Join-Path $kernel "portable/GCC/ARM_$ClassicName"), (Join-Path $kernel 'include'), $cmsis, $configDir)
    $roots += @($profileRoots | ForEach-Object { Join-Path $RepoRoot "fiber/port/$_" })
    foreach ($root in $roots) {
        $paths += @(Get-ChildItem -LiteralPath $root -File | Where-Object {
            $_.Extension -in @('.c', '.h', '.ld', '.md') -and
                ($root -ne $RepoRoot -or $_.Name -in @('mcu_core.h', 'basic_types.h', 'FREERTOS_ASM_PARITY.md'))
        } | Select-Object -ExpandProperty FullName)
    }
    $script:cm0SourceInputs = @($paths | Sort-Object -Unique | ForEach-Object {
        [ordered]@{Path=$_; Sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
    })
    $script:cm0Inputs = @($script:cm0SourceInputs | ForEach-Object {
        if ([IO.Path]::GetExtension($_.Path) -ne '.md') { $_; return }
        $target = Join-Path $directory ('doc-' + [Guid]::NewGuid().ToString('N') + '-' + [IO.Path]::GetFileName($_.Path))
        Copy-Item -LiteralPath $_.Path -Destination $target
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $_.Sha256) { throw "$ClassicName documentation snapshot drift" }
        [ordered]@{Path=$target; Sha256=$_.Sha256; SourcePath=$_.Path; Role='DocumentationSnapshot'}
    })
    $script:cm0Mechanisms = @()
    ConvertTo-Json -Depth 8 -InputObject $script:cm0Inputs |
        Set-Content -LiteralPath (Join-Path $directory 'inputs.before.json') -Encoding ASCII
}

function Complete-ClassicFocusedEvidence {
    $directory = Join-Path $BuildRoot $ClassicEvidence
    $configurations = if ($Cm3Only) { 1 } else { 3 }
    $objectCount = 2 * $configurations
    $mechanismCount = if ($Cm3Only) { 3 } else { 18 }
    $known = @{}
    foreach ($entry in $script:cm0SourceInputs) { $known[[IO.Path]::GetFullPath($entry.Path)] = $entry.Sha256 }
    $dependencies = @()
    $dependencyFiles = @(Get-ChildItem -LiteralPath $BuildRoot -Recurse -Filter '*.d' -File)
    if ($dependencyFiles.Count -ne $objectCount) { throw "$ClassicName compile dependency inventory changed" }
    $prefix = [IO.Path]::GetFullPath($BuildRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    foreach ($file in $dependencyFiles) {
        $text = (Get-Content -LiteralPath $file.FullName -Raw).Replace("\`r`n", ' ').Replace("\`n", ' ')
        $colon = $text.IndexOf(': ', [StringComparison]::Ordinal)
        if ($colon -lt 0) { throw "Malformed $ClassicName dependency output: $($file.FullName)" }
        foreach ($token in [regex]::Matches($text.Substring($colon+2), '(?:\\ |[^\s])+')) {
            $name = $token.Value.Replace('\ ', ' ')
            $path = (Resolve-Path -LiteralPath $name).Path
            $generated = $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
            if (-not $generated -and -not $known.ContainsKey($path)) { throw "Unhashed $ClassicName compile dependency: $path" }
            $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            if (-not $generated -and $hash -ne $known[$path]) { throw "$ClassicName dependency changed: $path" }
            $dependencies += [ordered]@{DependencyFile=$file.FullName; Path=$path; Sha256=$hash; Generated=$generated}
        }
    }
    ConvertTo-Json -Depth 6 -InputObject $dependencies | Set-Content -LiteralPath (Join-Path $directory 'dependencies.json') -Encoding ASCII
    $drift = @((@($script:cm0SourceInputs) + @($script:cm0Inputs)) | Where-Object {
        -not (Test-Path -LiteralPath $_.Path) -or (Get-FileHash -LiteralPath $_.Path -Algorithm SHA256).Hash -ne $_.Sha256
    })
    ConvertTo-Json -Depth 6 -InputObject $drift | Set-Content -LiteralPath (Join-Path $directory 'inputs.drift.json') -Encoding ASCII
    if ($drift.Count) { throw "$ClassicName source/tool inputs changed; no qualification" }
    if ($script:cm0Mechanisms.Count -ne $mechanismCount) { throw "$ClassicName focused mechanism inventory changed" }
    [ordered]@{Status='PASS'; Optimization=$Optimization; Configurations=$configurations; CompiledObjects=$objectCount;
        Mechanisms=$script:cm0Mechanisms; SourceDrift=0; RuntimeProfileAdded=$false;
        Scope='Existing ordered mechanism checks only; not closed whole-provider, hostile-pressure or CPU execution proof'} |
        ConvertTo-Json -Depth 9 | Set-Content -LiteralPath (Join-Path $directory 'result.json') -Encoding ASCII
    $artifacts = @(Get-ChildItem -LiteralPath $BuildRoot -Recurse -File | ForEach-Object {
        [ordered]@{Path=$_.FullName; Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    [ordered]@{Status='PASS'; ReferenceCommit=$ExpectedFreeRtosCommit; Inputs=$script:cm0Inputs; Artifacts=$artifacts} |
        ConvertTo-Json -Depth 9 | Set-Content -LiteralPath (Join-Path $directory 'artifacts.json') -Encoding ASCII
    Write-Host "${ClassicName}_FOCUSED_PARITY_PASS ($Optimization; $configurations configurations, $objectCount objects, $mechanismCount mechanisms; narrow ordered checks only)"
}

function Get-C55SGatewayFunctionSpan {
    param([string]$Source, [string]$Name)
    $start = [regex]::Match($Source, '(?m)^uint32_t ' + [regex]::Escape($Name) + '\(')
    if (-not $start.Success) { throw "C55S gateway function anchor changed: $Name" }
    $next = [regex]::Match($Source.Substring($start.Index + $start.Length),
        '(?m)^uint32_t fiber_secure_context_gateway_c55s_v1_\w+\(')
    $end = $Source.Length
    if ($next.Success) { $end = $start.Index + $start.Length + $next.Index }
    return [pscustomobject]@{Start=$start.Index; Length=$end-$start.Index;
        Text=$Source.Substring($start.Index, $end-$start.Index)}
}

function Test-C55SInitMechanisms {
    param([object]$PriorityPair, [object]$CpuPair)

    $assertInputs = {
        foreach ($pair in @($PriorityPair, $CpuPair)) {
            foreach ($inputFile in $pair.InitSourceHashes) {
                if ((Get-FileHash -LiteralPath $inputFile.Path -Algorithm SHA256).Hash -ne $inputFile.Sha256) {
                    throw "C55SINIT input changed during qualification: $($inputFile.Path)"
                }
            }
        }
    }
    & $assertInputs
    foreach ($id in @("FAP-C55SINIT-PRIORITY", "FAP-C55SINIT-CPU", "FAP-C55SINIT-GATES", "FAP-CMSE-M55", "FAP-C55S-PRIVATE-COHORT")) {
        if ($ledger.IndexOf($id, [StringComparison]::Ordinal) -lt 0) {
            throw "C55SINIT missing intentional-difference ledger entry: $id"
        }
    }
    $directory = Join-Path $BuildRoot "C55SINIT"
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $profile = Join-Path $RepoRoot "fiber\port\ARM_CM55\secure"
    $source = Join-Path $profile "fiber_secure_context_gateway.c"
    $commandsPath = Join-Path $directory "commands.jsonl"
    $runCommand = {
        param([string]$Program, [string[]]$Arguments)
        ConvertTo-Json -InputObject (@($Program) + $Arguments) -Compress |
            Add-Content -LiteralPath $commandsPath -Encoding ASCII
        & $Program @Arguments
        if ($LASTEXITCODE -ne 0) { throw "C55SINIT command failed: $Program" }
    }
    $linker = Join-Path $directory "body.ld"
    @'
SECTIONS {
 .fiber_c55s_private_cohort 0x0802F000 : { *(.rodata.fiber_c55s_private_cohort) }
 .text 0x08000000 : { *(.text*) *(.rodata*) }
 .ARM.extab : { *(.ARM.extab*) }
 .ARM.exidx : { *(.ARM.exidx*) }
 .gnu.sgstubs 0x08030000 : ALIGN(32) { *(.gnu.sgstubs*) }
 .data 0x30000000 : { *(.data*) }
 .bss 0x30001000 (NOLOAD) : { *(.bss*) *(COMMON) }
 .fiber_secure_context_pool 0x30002000 (NOLOAD) : { *(.fiber_secure_context_pool) }
 /DISCARD/ : { *(.comment*) *(.note*) }
}
'@ | Set-Content -LiteralPath $linker -Encoding ASCII
    $stub = Join-Path $directory "pool_boundary.c"
    @'
#include <stdint.h>
#include "fiber/fiber_api_attributes.h"
/* Explicit boundary stub: pool lifecycle is qualified by C55SPOOL, not here. */
volatile uint32_t c55sinit_pool_result = 1u;
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_boot_initialize(void)
{
    return c55sinit_pool_result;
}
'@ | Set-Content -LiteralPath $stub -Encoding ASCII
    $stubObject = Join-Path $directory "pool_boundary.o"
    & $runCommand $compiler @("-mcpu=cortex-m55", "-mthumb", "-mcmse", "-mfloat-abi=soft",
        "-std=gnu11", $Optimization, "-ffreestanding", "-fno-builtin", "-ffunction-sections",
        "-fdata-sections", "-I$RepoRoot", "-c", $stub, "-o", $stubObject)
    $boundaryProvider = Join-Path $directory 'cohort_boundary_provider.c'
    @'
#include "fiber_secure_context_cohort.h"
/* Fixture-only provider for modeled pool boundaries, not archive extraction
 * or production pool qualification. Use the actual selected header/key ABI. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_secure_context_pool_c55s_v1_cohort_provider(void)
{
    FIBER_C55S_PRIVATE_COHORT_DEFINE();
}
'@ | Set-Content $boundaryProvider -Encoding ASCII
    $boundaryProviderObject = Join-Path $directory 'cohort-boundary-provider.o'
    $providerArguments = @($PriorityPair.FiberArguments)
    for ($i=0; $i -lt $providerArguments.Count; ++$i) {
        if ($providerArguments[$i] -eq $source) { $providerArguments[$i] = $boundaryProvider }
        if ($providerArguments[$i] -eq '-o') { $providerArguments[$i+1] = $boundaryProviderObject }
    }
    & $runCommand $compiler $providerArguments
    $linkBody = {
        param([string]$Object, [string]$Name, [string]$Entry, [switch]$WithPool, [string]$PoolObject)
        if ($Entry -eq 'fiber_secure_context_gateway_c55s_v1_initialize') {
            $isolated = Join-Path $directory "$Name-init-only.o"
            $strip = @('allocate', 'load', 'save') | ForEach-Object {
                "--remove-section=.text.fiber_secure_context_gateway_c55s_v1_$_"
            }
            & $runCommand (Join-Path (Split-Path $compiler) 'arm-none-eabi-objcopy.exe') `
                ($strip + @('--strip-symbol=fiber_secure_context_pool_allocate',
                    '--strip-symbol=fiber_secure_context_pool_lookup_owned', $Object, $isolated))
            $Object = $isolated
        }
        $elf = Join-Path $directory "$Name.elf"
        $arguments = @("-mcpu=cortex-m55", "-mthumb", "-mcmse", "-mfloat-abi=soft", "-nostdlib",
            "-Wl,--gc-sections", "-Wl,-e,__acle_se_$Entry", "-Wl,-T,$linker",
            "-Wl,--section-start=.gnu.sgstubs=0x08030000",
            "-Wl,-Map,$(Join-Path $directory "$Name.map")", $Object)
        if ($Entry -eq 'fiber_secure_context_gateway_c55s_v1_initialize') {
            $arguments += "-Wl,-T,$(Join-Path $profile 'fiber_secure_context_cohort_contract.ld')"
            $arguments += @('initialize','abi_version','stack_alignment','max_stack_bytes','max_contexts') |
                ForEach-Object { "-Wl,--undefined=__acle_se_fiber_secure_context_gateway_c55s_v1_$_" }
        }
        if ($WithPool) { $arguments += @($stubObject,$boundaryProviderObject) }
        if ($PoolObject) { $arguments += $PoolObject }
        & $runCommand $compiler ($arguments + @("-o", $elf))
        Get-ObjectDisassembly -Objdump $objdump -ObjectPath $elf |
            Set-Content -LiteralPath "$elf.disasm" -Encoding ASCII
        return $elf
    }
    $fiberElf = & $linkBody $PriorityPair.FiberPath "fiber" "fiber_secure_context_gateway_c55s_v1_initialize" -WithPool
    $priorityElf = & $linkBody $PriorityPair.ReferencePath "reference-priority" "SecureInit_DePrioritizeNSExceptions"
    # CMSE exports are linker roots even under GC. Remove unrelated entry
    # sections, not their dependencies via fake malloc/save/load providers.
    $isolatedReference = Join-Path $directory "reference-init-only.o"
    $objcopy = Join-Path (Split-Path $compiler) "arm-none-eabi-objcopy.exe"
    $remove = @("SecureContext_AllocateContext", "SecureContext_FreeContext", "SecureContext_LoadContext", "SecureContext_SaveContext")
    $copyArgs = @($remove | ForEach-Object { "--remove-section=.text.$_" })
    & $runCommand $objcopy ($copyArgs + @($CpuPair.ReferencePath, $isolatedReference))
    $cpuElf = & $linkBody $isolatedReference "reference-cpu" "SecureContext_Init"
    $hostileObject = Join-Path $directory "hostile.o"
    $hostileArguments = @($PriorityPair.FiberArguments)
    for ($index = 0; $index -lt $hostileArguments.Count; ++$index) {
        if ($hostileArguments[$index] -eq '-o') { $hostileArguments[$index + 1] = $hostileObject }
    }
    $hostileArguments += @("-finstrument-functions", "-fstack-protector-all",
        "-fprofile-arcs", "-ftest-coverage", "-fsanitize=undefined")
    & $runCommand $compiler $hostileArguments
    Get-ObjectDisassembly -Objdump $objdump -ObjectPath $hostileObject |
        Set-Content -LiteralPath "$hostileObject.disasm" -Encoding ASCII
    $hostileElf = & $linkBody $hostileObject "hostile" "fiber_secure_context_gateway_c55s_v1_initialize" -WithPool
    # A separate static link covers the real transitive initializer callgraph.
    # It is not executed on Unicorn's M33 engine (M55 loop/CPU semantics differ).
    $realPools = @{}
    $realLinks = @{}
    foreach ($variant in @('normal', 'hostile')) {
        $realPools[$variant] = Join-Path $directory "actual-pool-$variant.o"
        $poolArguments = @($PriorityPair.FiberArguments)
        for ($index = 0; $index -lt $poolArguments.Count; ++$index) {
            if ($poolArguments[$index] -eq $source) {
                $poolArguments[$index] = Join-Path $profile 'fiber_secure_context_pool.c'
            }
            if ($poolArguments[$index] -eq '-o') { $poolArguments[$index + 1] = $realPools[$variant] }
        }
        if ($variant -eq 'hostile') {
            $poolArguments += @('-finstrument-functions', '-fstack-protector-all',
                '-fprofile-arcs', '-ftest-coverage', '-fsanitize=undefined')
        }
        & $runCommand $compiler $poolArguments
        $gatewayObject = $PriorityPair.FiberPath
        if ($variant -eq 'hostile') { $gatewayObject = $hostileObject }
        $realLinks[$variant] = & $linkBody $gatewayObject "actual-callgraph-$variant" `
            "fiber_secure_context_gateway_c55s_v1_initialize" -PoolObject $realPools[$variant]
    }

    # Each mutant is compiled from a mechanically altered production source.
    # No production file is modified, and no handwritten replacement init is used.
    $mutations = @(
        @{Name="origin"; Find='__builtin_arm_cmse_nonsecure_caller\(\) == 0'; Replacement='0u'},
        @{Name="svc11"; Find='FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER'; Replacement='14u'},
        @{Name="bfhfnmins"; Find='\(aircr_before & fiber_secure_contextAIRCR_BFHFNMINS_MASK\) != 0u'; Replacement='0u'},
        @{Name="aircr-preservation"; Find='aircr_before & ~\(fiber_secure_contextAIRCR_VECTKEY_MASK'; Replacement='aircr_before & ~(0x80u | fiber_secure_contextAIRCR_VECTKEY_MASK'},
        @{Name="aircr-readback"; Find='(?s)if \(\(\(aircr_after & fiber_secure_contextAIRCR_PRIS_MASK\).*?\n\t\}'; Replacement='/* deliberate missing AIRCR readback guard */'},
        @{Name="psplim-readback"; Find='stack_limit != 0u'; Replacement='0u'},
        @{Name="psp-readback"; Find='stack_pointer != 0u'; Replacement='0u'},
        @{Name="control-readback"; Find='control_after != 2u'; Replacement='0u'},
        @{Name="pool-success"; Find='fiber_secure_context_pool_boot_initialize\(\) != 1u'; Replacement='fiber_secure_context_pool_boot_initialize() == 0xFFFFFFFFu'},
        @{Name="initial-latch-readback"; Find='fiber_secure_context_gateway_state !=\s*fiber_secure_contextGATEWAY_INITIALIZING'; Replacement='0u'},
        @{Name="ready-latch-readback"; Find='fiber_secure_context_gateway_state !=\s*fiber_secure_contextGATEWAY_READY'; Replacement='0u'},
        @{Name="stack-order"; Find='msr psplim, %0\\n\\tmsr psp, %0'; Replacement='msr psp, %0\n\tmsr psplim, %0'},
        @{Name="control-two"; Find='"r" \(2u\)'; Replacement='"r" (3u)'},
        @{Name="barriers"; Find='fiber_secure_contextBARRIERS\(\);'; Replacement=''; Multiple=$true},
        # VMOV s0,r0 encoding deliberately bypasses the soft-float assembler
        # rejection. The code-generation guard must inspect the emitted opcode.
        @{Name="fp-data"; Find='uint32_t aircr_after;'; Replacement='uint32_t aircr_after; __asm volatile (".inst.w 0xee000a10" ::: "memory");'}
    )
    $original = (Get-Content -LiteralPath $source -Raw).Replace("`r`n", "`n")
    $initSpan = Get-C55SGatewayFunctionSpan -Source $original -Name 'fiber_secure_context_gateway_c55s_v1_initialize'
    $mutants = @()
    foreach ($mutation in $mutations) {
        $matches = [regex]::Matches($initSpan.Text, $mutation.Find)
        if ($matches.Count -eq 0 -or
                ((-not $mutation.ContainsKey('Multiple')) -and ($matches.Count -ne 1))) {
            throw "C55SINIT mutant anchor changed: $($mutation.Name)"
        }
        $changed = $original.Substring(0, $initSpan.Start) +
            [regex]::Replace($initSpan.Text, $mutation.Find, $mutation.Replacement) +
            $original.Substring($initSpan.Start + $initSpan.Length)
        $mutantSource = Join-Path $directory ("mutant-" + $mutation.Name + ".c")
        Set-Content -LiteralPath $mutantSource -Value $changed -Encoding ASCII
        $object = Join-Path $directory ("mutant-" + $mutation.Name + ".o")
        $arguments = @($PriorityPair.FiberArguments)
        for ($index = 0; $index -lt $arguments.Count; ++$index) {
            if ($arguments[$index] -eq $source) { $arguments[$index] = $mutantSource }
            if ($arguments[$index] -eq '-o') { $arguments[$index + 1] = $object }
        }
        & $runCommand $compiler $arguments
        $elf = & $linkBody $object ("mutant-" + $mutation.Name) "fiber_secure_context_gateway_c55s_v1_initialize" -WithPool
        $mutants += [ordered]@{Name=$mutation.Name; Elf=$elf; Source=$mutantSource}
    }
    $manifest = Join-Path $directory "inputs.json"
    [ordered]@{Fiber=$fiberElf; Priority=$priorityElf; Cpu=$cpuElf; Hostile=$hostileObject; HostileElf=$hostileElf;
        ActualPools=$realPools; ActualLinks=$realLinks;
        FiberIsolated=(Join-Path $directory 'fiber-init-only.o');
        HostileIsolated=(Join-Path $directory 'hostile-init-only.o');
        BoundaryProvider=$boundaryProviderObject;
        Object=$PriorityPair.FiberPath; ReferenceOriginal=$CpuPair.ReferencePath; ReferenceIsolated=$isolatedReference;
        Mutants=$mutants; Optimization=$Optimization} |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding ASCII
    $proof = Join-Path $directory "trace_init.py"
    @'
"""Generated ARM integer/control mechanism traces, not M55/CMSE architecture.

Unicorn M33 runs ordinary emitted instructions. Explicit hooks supply banked
CPU-register/PPB readbacks and account for compiler CMSE hygiene. SG, exception
entry/return, CONTROL effects, FP context state and MPU enforcement are NOT
qualified here; the independent M55 QEMU runner owns architectural execution.
"""
import sys
if sys.flags.optimize or not __debug__:
    raise SystemExit('C55SINIT requires Python optimization disabled')
import importlib.metadata as metadata
for package, expected in (('unicorn', '2.1.4'), ('pyelftools', '0.33')):
    if metadata.version(package) != expected:
        raise SystemExit('C55SINIT requires ' + package + '==' + expected)
import json, re, struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS,
                     UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                     UC_HOOK_MEM_INVALID, UC_MEM_WRITE)
from unicorn import arm_const as arm

class ProofFailure(RuntimeError):
    def __init__(self, code, detail=''):
        self.code=code
        super().__init__(code + (': ' + detail if detail else ''))

def check(condition, message, detail=''):
    if not condition:
        raise ProofFailure(message,detail)

def hygiene(op,args):
    return ((op == 'vstr' and args == 'FPCXTNS, [sp, #-4]!') or
            (op == 'vldr' and args == 'FPCXTNS, [sp], #4') or
            (op == 'vscclrm' and args == '{s0-s15, VPR}'))

def body_name(name):
    return '__acle_se_' + name

COHORT_HELPER='fiber_secure_context_pool_c55s_v1_cohort_provider'
# Independent numeric oracle for this maintained N=3, S=256 probe. The key
# schema has twelve uint32 facts, each encoded as two decimal halfwords.
COHORT_FACTS=(('p',0x43353553),('l',0x00010001),('f',0x8A),('i',1),('c',1),
              ('r',1),('n',3),('b',256),('a',8),('w',2),('s',8),('v',0xFEF5EDA5))
COHORT_KEY='fiber_secure_context_cohort_c55s_g1'+''.join(
    '_'+tag+'_'+str(value>>16)+'_'+str(value&0xFFFF) for tag,value in COHORT_FACTS)
COHORT_IMPORTS={COHORT_HELPER,COHORT_KEY}

class Image:
    def __init__(self, path):
        self.path = Path(path)
        with self.path.open('rb') as stream:
            elf = ELFFile(stream)
            self.symbols = {s.name: dict(value=s['st_value'], size=s['st_size'],
                kind=s['st_info']['type'], bind=s['st_info']['bind'], section=s['st_shndx'])
                for s in elf.get_section_by_name('.symtab').iter_symbols()}
            self.loads = [(s['p_vaddr'], s.data()) for s in elf.iter_segments()
                          if s['p_type'] == 'PT_LOAD' and s['p_filesz']]
        self.instructions = {}
        self.encoding = {}
        disassembly = Path(str(path) + '.disasm').read_text()
        for match in re.finditer(r'(?m)^[ \t]*([0-9a-f]+):[ \t]+((?:[0-9a-f]{4}[ \t]+){1,2})([a-z][a-z0-9.]*)[ \t]*([^\r\n]*)', disassembly):
            address, encoded, opcode, operands = match.groups()
            self.instructions[int(address,16)] = (len(encoded.split())*2, opcode, operands.split('@')[0].strip())
            self.encoding[int(address,16)] = tuple(int(word,16) for word in encoded.split())

    def address(self, name):
        return self.symbols[name]['value'] & ~1

def dependencies(path):
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        return {s.name for s in elf.get_section_by_name('.symtab').iter_symbols()
                if s.name and s['st_shndx'] == 'SHN_UNDEF' and s['st_info']['bind'] != 'STB_LOCAL'}

def static_callgraph(path,whole_pool=False):
    image=Image(path)
    calls=0
    # GNU ld gives __acle_se_ aliases zero size. Objdump -d's executable
    # sections include every retained body/helper, not only sized symbols.
    for address,(_,op,args) in image.instructions.items():
        check(not op.startswith('v') or hygiene(op,args),'static FP data instruction',op+' '+args)
        check(op not in ('blx','blxns'),'static indirect helper call',args)
        if op in ('bl','bl.w'):
            target=int(args.split()[0],16)
            permitted={image.address('fiber_secure_context_pool_boot_initialize')}
            permitted.add(image.address(COHORT_HELPER))
            if 'fiber_secure_context_gateway_fail_closed' in image.symbols:
                permitted.add(image.address('fiber_secure_context_gateway_fail_closed'))
            if whole_pool:
                permitted.update(s['value'] & ~1 for name,s in image.symbols.items()
                    if name.startswith('fiber_secure_context_') and s['kind'] == 'STT_FUNC')
            check(target in permitted,'static unexpected helper call',args)
            calls+=1
    check(calls > 0,'static pool call missing')
    return calls

def cmse_template(image,name,value_return):
    start=image.address(body_name(name))
    end=min(s['value'] & ~1 for s in image.symbols.values()
            if s['kind'] == 'STT_FUNC' and (s['value'] & ~1) > start)
    body=[(a,op,args) for a,(_,op,args) in sorted(image.instructions.items()) if start <= a < end]
    selected=[(a,op,args) for a,op,args in body if op.startswith('v') or op in ('clrm','bxns')]
    check(selected and selected[0][1:] == ('vstr','FPCXTNS, [sp, #-4]!'),'CMSE template prologue changed')
    mask=0x900E if value_return else 0x900F
    clear='{r1, r2, r3, ip, APSR}' if value_return else '{r0, r1, r2, r3, ip, APSR}'
    expected=[('vstr','FPCXTNS, [sp, #-4]!',(0xED6D,0xCF81)),
              ('vscclrm','{s0-s15, VPR}',(0xEC9F,0x0A10)),
              ('clrm',clear,(0xE89F,mask)),
              ('vldr','FPCXTNS, [sp], #4',(0xECFD,0xCF81)),
              ('bxns','lr',(0x4774,))]
    actual=[(op,args,image.encoding[a]) for a,op,args in selected[:5]]
    check(actual == expected,'CMSE template sequence changed',name)
    tail=[a for a,_,_ in selected[1:5]]
    check(all(tail[i]+image.instructions[tail[i]][0] == tail[i+1] for i in range(3)),
          'CMSE template epilogue not contiguous')
    extra=[(op,args,image.encoding[a]) for a,op,args in selected[5:]]
    if selected[0][0] != start:
        # GCC -O2 shrink-wraps FPCXTNS save/restore past the immediate Secure
        # caller rejection. That exact no-save path still scrubs and BXNS-returns.
        check(value_return and len(body) >= 3 and body[0][1:] == ('tst.w','lr, #1') and
              image.encoding[start] == (0xF01E,0x0F01) and
              body[1][0] == start+4 and body[1][1] == 'bne.n' and
              selected[0][0] == start+6 and extra == expected[1:3]+expected[4:],
              'CMSE origin rejection shrink-wrap changed')
        reject=int(body[1][2].split()[0],16)
        check(image.instructions.get(reject) == (2,'movs','r0, #0') and
              image.encoding[reject] == (0x2000,) and selected[5][0] == reject+2,
              'CMSE origin rejection target changed')
        short=[a for a,_,_ in selected[5:]]
        check(all(short[i]+image.instructions[short[i]][0] == short[i+1] for i in range(2)),
              'CMSE origin rejection scrub not contiguous')
    else:
        check(not extra,'CMSE unexpected security epilogue')
    return dict(Canonical=actual,PrologueOffset=selected[0][0]-start,OriginRejectEpilogue=extra)

def check_cmse_templates(inputs):
    priority=cmse_template(Image(inputs['Priority']),'SecureInit_DePrioritizeNSExceptions',False)
    context=cmse_template(Image(inputs['Cpu']),'SecureContext_Init',False)
    check(priority == context,'pinned CM55 security templates disagree')
    measured={}
    for label,path in [('Fiber',inputs['Fiber']),('Hostile',inputs['HostileElf'])]+[
            ('ActualPool-'+label,path) for label,path in inputs['ActualLinks'].items()]:
        actual=cmse_template(Image(path),INIT,True)
        # The only security-template difference is retaining the u32 result in
        # r0. Compare the remaining opcode/operand/encoding tuples directly.
        actual_core=actual['Canonical']
        pinned_core=priority['Canonical']
        check(actual_core[:2]+actual_core[3:] == pinned_core[:2]+pinned_core[3:],
              'Fiber/pinned CMSE template mismatch',label)
        measured[label]=actual
    # Decoded-instruction classifier controls, distinct from compiled C guard
    # mutants. Removing or weakening security cleanup must not pass as "no FP".
    controls={}
    for control in ('missing-prologue','missing-scrub','wrong-fp-bank','clear-result'):
        image=Image(inputs['Fiber'])
        start=image.address(body_name(INIT))
        end=min(s['value'] & ~1 for s in image.symbols.values()
                if s['kind'] == 'STT_FUNC' and (s['value'] & ~1) > start)
        targets={}
        for address,(_,op,_) in sorted(image.instructions.items()):
            if start <= address < end and op in ('vstr','vscclrm','vldr','clrm'):
                targets.setdefault(op,address)
        if control == 'missing-prologue':
            image.instructions[targets['vstr']]=(4,'nop.w','')
        elif control == 'missing-scrub':
            image.instructions[targets['vscclrm']]=(4,'nop.w','')
        elif control == 'wrong-fp-bank':
            image.instructions[targets['vldr']]=(4,'vldr','FPCXTS, [sp], #4')
        else:
            image.instructions[targets['clrm']]=(4,'clrm','{r0, r1, r2, r3, ip, APSR}')
        expected='CMSE template prologue changed' if control == 'missing-prologue' else 'CMSE template sequence changed'
        try:
            cmse_template(image,INIT,True)
        except ProofFailure as exc:
            check(exc.code == expected,'CMSE classifier control rejected for unintended reason',control+': '+str(exc))
            controls[control]=exc.code
        else:
            raise RuntimeError('CMSE classifier control survived: '+control)
    return dict(PinnedPriority=priority,PinnedContext=context,Fiber=measured,ClassifierControls=controls)

def reference_identity(original,isolated,name='SecureContext_Init'):
    images=[]
    for path in (original,isolated):
        with Path(path).open('rb') as stream:
            elf=ELFFile(stream)
            section=elf.get_section_by_name('.text.'+name)
            check(section is not None,'missing actual pinned init section')
            reloc=elf.get_section_by_name('.rel.text.'+name)
            relocations=[]
            if reloc is not None:
                symbols=elf.get_section(reloc['sh_link'])
                relocations=[(r['r_offset'],r['r_info_type'],symbols.get_symbol(r['r_info_sym']).name)
                    for r in reloc.iter_relocations()]
            images.append((section.data(),relocations))
    check(images[0] == images[1],'isolated reference init bytes/relocations changed')

def function_relocations(path,name):
    with Path(path).open('rb') as stream:
        elf=ELFFile(stream)
        check(elf.get_section_by_name('.text.'+name) is not None,'missing cohort consumer function',name)
        reloc=elf.get_section_by_name('.rel.text.'+name)
        if reloc is None: return []
        symbols=elf.get_section(reloc['sh_link'])
        return [(r['r_info_type'],symbols.get_symbol(r['r_info_sym']).name) for r in reloc.iter_relocations()]

def cohort_definition(path):
    image=Image(path)
    keys={name for name in image.symbols if name.startswith('fiber_secure_context_cohort_c55s_g1_')}
    check(keys=={COHORT_KEY},'private cohort key differs from numeric oracle',str(keys))
    key,helper=image.symbols[COHORT_KEY],image.symbols[COHORT_HELPER]
    check(key['kind']=='STT_OBJECT' and key['bind']=='STB_GLOBAL' and key['size']==1,'private cohort key provider identity')
    check(helper['kind']=='STT_FUNC' and helper['bind']=='STB_GLOBAL','private cohort C provider identity')
    check(body_name(COHORT_HELPER) not in image.symbols,'private cohort helper became NSC')
    with Path(path).open('rb') as stream:
        elf=ELFFile(stream)
        section=elf.get_section(key['section'])
        offset=key['value']-section['sh_addr']
        check(section['sh_flags']&2 and not section['sh_flags']&5 and section.data()[offset:offset+1]==b'\x01',
              'private cohort key not one read-only allocated byte')
    start=image.address(COHORT_HELPER)
    instructions=[(op,args) for a,(_,op,args) in image.instructions.items() if start<=a<start+helper['size']]
    check(instructions==[('bx','lr')],'private cohort provider acquired runtime operations',str(instructions))
    return COHORT_KEY

AIRCR, INITIALIZING, READY = 0xE000ED0C, 0x53434742, 0x53434752
REGS = {f'r{i}':getattr(arm,f'UC_ARM_REG_R{i}') for i in range(13)}
REGS.update(sp=arm.UC_ARM_REG_SP, lr=arm.UC_ARM_REG_LR, ip=arm.UC_ARM_REG_R12)
COUNTS = {'calls':0, 'mutants':0, 'hygiene_instructions':0}

class Machine:
    stop = 0x0803FFF0
    def __init__(self, path, ipsr=11, nonsecure=True, aircr=0xFA050080, fault=None, pool=1):
        self.image, self.ipsr, self.nonsecure = Image(path), ipsr, nonsecure
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_M33)
        for address, size in ((0x08000000,0x40000),(0x30000000,0x20000),(0xE000E000,0x2000)):
            self.uc.mem_map(address,size)
        for address, data in self.image.loads:
            self.uc.mem_write(address,data)
        self.cpu = dict(PSPLIM=0x30018000,PSP=0x30019000,CONTROL=0)
        self.aircr, self.fault, self.pending, self.trace = aircr, fault, [], []
        self.state = self.image.symbols.get('fiber_secure_context_gateway_state',{}).get('value',0)
        self.record = self.image.symbols.get('xSecureContexts',{}).get('value',0)
        self.pool = self.image.symbols.get('fiber_secure_context_pool_boot_initialize',{}).get('value',0) & ~1
        self.cohort_provider=self.image.symbols.get(COHORT_HELPER,{}).get('value',0) & ~1
        self.cohort_key=self.image.symbols.get(COHORT_KEY,{}).get('value',0)
        self.put(AIRCR,aircr)
        if 'c55sinit_pool_result' in self.image.symbols:
            self.put(self.image.address('c55sinit_pool_result'),pool)
        self.uc.hook_add(UC_HOOK_CODE,self.code)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,self.memory)
        self.uc.hook_add(UC_HOOK_MEM_INVALID,self.invalid)

    def put(self,address,value):
        self.uc.mem_write(address,struct.pack('<I',value & 0xFFFFFFFF))
    def get(self,address):
        return struct.unpack('<I',self.uc.mem_read(address,4))[0]
    def invalid(self,uc,kind,address,size,value,data):
        raise RuntimeError(f'invalid generated-code access {address:#x}')
    def skip(self,address,size):
        self.uc.reg_write(arm.UC_ARM_REG_PC,(address+size)|1)
    def code(self,uc,address,size,data):
        for target,value in self.pending:
            self.put(target,value)
        self.pending=[]
        if address == self.pool and self.pool:
            self.trace.append(('pool',))
        if address == self.cohort_provider and self.cohort_provider:
            self.trace.append(('cohort-provider',))
        if address == self.stop:
            self.returned=True
            uc.emu_stop()
            return
        check(address in self.image.instructions,f'unknown instruction at {address:#x}')
        length,op,args=self.image.instructions[address]
        if op == 'udf':
            symbol=self.image.symbols.get('fiber_secure_context_gateway_fail_closed',{})
            start=symbol.get('value',0) & ~1
            check(start <= address < start+symbol.get('size',0),'unexpected UDF location')
            check(self.fault in ('INITIALIZING','READY'),'unexpected fail-closed trap')
            self.trapped=True
            uc.emu_stop()
        elif op == 'mrs':
            dest,register=[x.strip() for x in args.split(',')]
            value=self.ipsr if register == 'IPSR' else self.cpu.get(register)
            check(value is not None,'unexpected banked register read '+register)
            if self.fault == register:
                value=0 if register == 'CONTROL' else 8
            self.trace.append(('read',register,value))
            uc.reg_write(REGS[dest],value)
            self.skip(address,length)
        elif op == 'msr':
            register,src=[x.strip() for x in args.split(',')]
            check(register in self.cpu,'unexpected banked register write '+register)
            value=uc.reg_read(REGS[src])
            self.cpu[register]=value
            self.trace.append(('write',register,value))
            self.skip(address,length)
        elif op in ('dsb','isb'):
            self.trace.append((op,))
        elif op.startswith('v'):
            # Only these exact compiler-generated NSC hygiene forms may be
            # modeled. Never permit FP arithmetic, user FP state or helper FP.
            check(hygiene(op,args), 'FP data instruction '+op+' '+args)
            sp=uc.reg_read(arm.UC_ARM_REG_SP)
            if op == 'vstr':
                uc.reg_write(arm.UC_ARM_REG_SP,sp-4)
                self.put(sp-4,0)
            elif op == 'vldr':
                uc.reg_write(arm.UC_ARM_REG_SP,sp+4)
            COUNTS['hygiene_instructions']+=1
            self.skip(address,length)
        elif op == 'clrm':
            check(args in ('{r0, r1, r2, r3, ip, APSR}','{r1, r2, r3, ip, APSR}'),
                  'unexpected CMSE register-clear form',args)
            self.skip(address,length)
        elif op == 'bxns':
            check(args == 'lr','unexpected NSC return operand')
            self.returned=True
            uc.emu_stop()
        elif op in ('sg','blx','blxns'):
            raise RuntimeError('unexpected SG/indirect call in C-body trace')

    def memory(self,uc,kind,address,size,value,data):
        if address == self.cohort_key and self.cohort_key:
            check(kind != UC_MEM_WRITE and size==1,'private cohort key access changed')
            self.trace.append(('cohort-read',bytes(uc.mem_read(address,1))[0]))
        elif address == AIRCR:
            check(size == 4,'nonword AIRCR access')
            if kind == UC_MEM_WRITE:
                self.trace.append(('aircr-write',value))
                self.aircr=0xFA050000 | (value & 0xFFFF)
                if self.fault == 'AIRCR-PRIS': self.aircr &= ~0x4000
                if self.fault == 'AIRCR-preserve': self.aircr ^= 0x80
                self.pending.append((address,self.aircr))
            else:
                self.trace.append(('aircr-read',self.get(address)))
        elif address >= 0xE0000000:
            raise RuntimeError(f'unexpected PPB access {address:#x}')
        elif address == self.state and self.state:
            if kind == UC_MEM_WRITE:
                self.trace.append(('state-write',value))
            else:
                value=self.get(address)
                self.trace.append(('state-read',value))
                if (self.fault == 'INITIALIZING' and value == INITIALIZING) or (self.fault == 'READY' and value == READY):
                    self.put(address,0)
                    self.pending.append((address,value))
        elif self.record and self.record <= address < self.record+48 and kind == UC_MEM_WRITE:
            self.trace.append(('record-write',address-self.record,size,value))

    def call(self,name):
        COUNTS['calls']+=1
        self.trace=[]
        self.returned=self.trapped=False
        self.uc.reg_write(arm.UC_ARM_REG_CONTROL,0)
        self.uc.reg_write(arm.UC_ARM_REG_MSP,0x3001F000)
        self.uc.reg_write(arm.UC_ARM_REG_SP,0x3001F000)
        preserved={REGS[f'r{i}']:0xCA110000+i for i in range(4,12)}
        for register,value in preserved.items():
            self.uc.reg_write(register,value)
        self.uc.reg_write(arm.UC_ARM_REG_LR,self.stop | (0 if self.nonsecure else 1))
        try:
            self.uc.emu_start(self.image.address(body_name(name))|1,self.stop+2,count=100000)
        except UcError as exc:
            pc=self.uc.reg_read(arm.UC_ARM_REG_PC)
            raise RuntimeError(f'generated instruction unsupported at {pc:#x}: '+str(exc)) from exc
        check(self.returned or self.trapped,'generated C body did not finish')
        if self.returned:
            check(self.uc.reg_read(arm.UC_ARM_REG_SP) == 0x3001F000,'generated C body lost stack balance')
            check(all(self.uc.reg_read(r) == v for r,v in preserved.items()),'generated C body lost callee registers')
        return self.uc.reg_read(arm.UC_ARM_REG_R0)

def ordered(trace,events):
    cursor=0
    for event in events:
        while cursor < len(trace) and trace[cursor] != event:
            cursor+=1
        check(cursor < len(trace),'missing ordered generated event '+str(event),str(trace))
        cursor+=1

INIT='fiber_secure_context_gateway_c55s_v1_initialize'
def effects(trace):
    return [x for x in trace if x[0] in ('state-write','aircr-write','write','pool','record-write')]

def cohort_events(trace):
    return [x for x in trace if x[0] in ('cohort-provider','cohort-read')]

def rejected_before_cohort(machine,diagnostic):
    check(machine.call(INIT) == 0 and not effects(machine.trace),diagnostic)
    check(not cohort_events(machine.trace),'rejected init reached private cohort',diagnostic)

def check_fiber(path):
    for low in [0,0x80,0xFFFF & ~0x2000] + [1<<i for i in range(16) if i != 13]:
        m=Machine(path,aircr=0xFA050000|low)
        result=m.call(INIT)
        check(result == 1 and not m.trapped,'valid init rejected')
        expected=0x05FA0000 | low | 0x4000
        check(effects(m.trace) == [('state-write',INITIALIZING),('aircr-write',expected),
            ('write','PSPLIM',0),('write','PSP',0),('pool',),('write','CONTROL',2),('state-write',READY)],
            'numeric write preservation/order mismatch',str(effects(m.trace)))
        ordered(m.trace,[('state-write',INITIALIZING),('dsb',),('isb',),('state-read',INITIALIZING),
            ('aircr-write',expected),('dsb',),('isb',),('aircr-read',0xFA050000|(low|0x4000)),
            ('write','PSPLIM',0),('write','PSP',0),('dsb',),('isb',),('read','PSPLIM',0),('read','PSP',0),
            ('pool',),('write','CONTROL',2),('isb',),('read','CONTROL',2),
            ('state-write',READY),('dsb',),('isb',),('state-read',READY)])
        ordered(m.trace,[('cohort-provider',),('cohort-read',1),('state-write',INITIALIZING)])
        rejected_before_cohort(m,'repeat init made effects')
    for exception in (0,1,3,14,15,16):
        m=Machine(path,ipsr=exception)
        rejected_before_cohort(m,'invalid SVC origin accepted')
    m=Machine(path,nonsecure=False)
    rejected_before_cohort(m,'Secure-origin call accepted')
    for marker in (INITIALIZING,READY,1,0xFFFFFFFF):
        m=Machine(path)
        m.put(m.state,marker)
        rejected_before_cohort(m,'existing marker accepted')
    m=Machine(path,aircr=0xFA052080)
    rejected_before_cohort(m,'A26 BFHFNMINS precommit rejection lost')
    for fault in ('AIRCR-PRIS','AIRCR-preserve','PSPLIM','PSP','CONTROL','INITIALIZING','READY'):
        m=Machine(path,fault=fault)
        result=m.call(INIT)
        check((m.trapped if fault in ('INITIALIZING','READY') else result == 0 and not m.trapped),
              'readback fault accepted '+fault)
        if not m.trapped:
            check(m.get(m.state) == INITIALIZING,'failure lost sticky commitment')
            rejected_before_cohort(m,'failure retry made effects')
    for pool in (0,2,0xFFFFFFFF):
        m=Machine(path,pool=pool)
        check(m.call(INIT) == 0 and m.get(m.state) == INITIALIZING,'pool failure accepted')
        check(not any(x[0] == 'write' and x[1] == 'CONTROL' for x in m.trace),'pool failure wrote CONTROL')

def check_reference(priority,cpu):
    for low in [0,0x80] + [1<<i for i in range(16) if i != 13]:
        m=Machine(priority,aircr=0xFA050000|low)
        m.call('SecureInit_DePrioritizeNSExceptions')
        check([x for x in m.trace if x[0] == 'aircr-write'] == [('aircr-write',0x05FA0000|low|0x4000)],
            'pinned priority preservation/key mechanism changed')
    m=Machine(priority,ipsr=0)
    m.call('SecureInit_DePrioritizeNSExceptions')
    check(not effects(m.trace),'pinned priority Thread gate changed')
    m=Machine(cpu)
    record=m.image.address('xSecureContexts')
    m.uc.mem_write(record,b'\xA5'*48)
    m.call('SecureContext_Init')
    check([x for x in m.trace if x[0] == 'write'] == [('write','PSPLIM',0),('write','PSP',0),('write','CONTROL',2)],
          'pinned stack/control order or values changed')
    check(bytes(m.uc.mem_read(record,48)) == b'\0'*48,'pinned three-record clear changed')
    clears=[(i,event) for i,event in enumerate(m.trace) if event[0] == 'record-write']
    check(sorted(offset for _,(_,start,size,_) in clears for offset in range(start,start+size)) == list(range(48))
          and all(event[3] == 0 for _,event in clears),'pinned record clear write coverage changed')
    check(m.trace.index(('write','PSP',0)) < min(i for i,_ in clears) <= max(i for i,_ in clears)
          < m.trace.index(('write','CONTROL',2)),'pinned memory/CPU initialization order changed')
    m.call('SecureContext_Init')
    check(not effects(m.trace),'pinned one-shot marker lost')
    m=Machine(cpu,ipsr=0)
    m.call('SecureContext_Init')
    check(not effects(m.trace),'pinned init Thread gate changed')

def main():
    manifest=Path(sys.argv[1])
    inputs=json.loads(manifest.read_text(encoding='utf-8-sig'))
    reference_identity(inputs['ReferenceOriginal'],inputs['ReferenceIsolated'])
    reference_identity(inputs['Object'],inputs['FiberIsolated'],INIT)
    reference_identity(inputs['Hostile'],inputs['HostileIsolated'],INIT)
    reference_identity(inputs['BoundaryProvider'],inputs['ActualPools']['normal'],COHORT_HELPER)
    reference_identity(inputs['BoundaryProvider'],inputs['ActualPools']['hostile'],COHORT_HELPER)
    check(dependencies(inputs['Object']) == {'fiber_secure_context_pool_boot_initialize',
        'fiber_secure_context_pool_allocate','fiber_secure_context_pool_lookup_owned'}|COHORT_IMPORTS,'C55SINIT hidden helper dependency')
    check(dependencies(inputs['FiberIsolated']) == {'fiber_secure_context_pool_boot_initialize'}|COHORT_IMPORTS,
          'C55SINIT isolated initializer helper dependency')
    check(dependencies(inputs['Hostile']) == dependencies(inputs['Object']),'C55SINIT canonical sensitive callgraph instrumentation leak')
    callgraph={name:static_callgraph(inputs[name]) for name in ('Fiber','HostileElf')}
    for variant,path in inputs['ActualPools'].items():
        check(not dependencies(path),'actual pool helper/instrumentation dependency',variant)
        callgraph['ActualPool-'+variant]=static_callgraph(inputs['ActualLinks'][variant],whole_pool=True)
        cohort_definition(inputs['ActualLinks'][variant])
    cohort_definition(inputs['Fiber'])
    for name in (INIT,'fiber_secure_context_gateway_c55s_v1_abi_version',
                 'fiber_secure_context_gateway_c55s_v1_stack_alignment',
                 'fiber_secure_context_gateway_c55s_v1_max_stack_bytes','fiber_secure_context_gateway_c55s_v1_max_contexts'):
        for path in (inputs['Object'],inputs['FiberIsolated'],inputs['Hostile'],inputs['HostileIsolated']):
            relocations=function_relocations(path,name)
            check(relocations.count((10,COHORT_HELPER))==1 and relocations.count((2,COHORT_KEY))==1,
                  'missing exact private cohort call/key relocations',name)
    cmse=check_cmse_templates(inputs)
    check_reference(inputs['Priority'],inputs['Cpu'])
    check_fiber(inputs['Fiber'])
    expected_kills={
        'origin':'Secure-origin call accepted', 'svc11':'valid init rejected',
        'bfhfnmins':'A26 BFHFNMINS precommit rejection lost',
        'aircr-preservation':'numeric write preservation/order mismatch',
        'aircr-readback':'readback fault accepted AIRCR-PRIS',
        'psplim-readback':'readback fault accepted PSPLIM',
        'psp-readback':'readback fault accepted PSP',
        'control-readback':'readback fault accepted CONTROL',
        'pool-success':'pool failure accepted',
        'initial-latch-readback':"missing ordered generated event ('state-read', 1396918082)",
        'ready-latch-readback':"missing ordered generated event ('state-read', 1396918098)",
        'stack-order':'numeric write preservation/order mismatch',
        'control-two':'valid init rejected',
        'barriers':"missing ordered generated event ('dsb',)",
        'fp-data':'FP data instruction vmov s0, r0'}
    check({m['Name'] for m in inputs['Mutants']} == set(expected_kills),'mutant inventory changed')
    killed=[]
    for mutant in inputs['Mutants']:
        try:
            check_fiber(mutant['Elf'])
        except ProofFailure as exc:
            check(exc.code == expected_kills[mutant['Name']],
                  'mutant rejected for unintended reason',mutant['Name']+': '+str(exc))
            killed.append(dict(Name=mutant['Name'],Diagnostic=str(exc)))
        else:
            raise RuntimeError('C55SINIT guard mutant survived: '+mutant['Name'])
    COUNTS['mutants']=len(killed)
    result=dict(COUNTS,Optimization=inputs['Optimization'],Killed=killed,StaticCallgraphCalls=callgraph,CMSE=cmse,
        PrivateCohort=dict(Key=COHORT_KEY,Facts=COHORT_FACTS,BoundaryProvider=inputs['BoundaryProvider'],
                           ActualProviders=inputs['ActualPools'],ColdConsumers=5),
        Scope='Actual emitted ordinary ARM instructions with explicit banked-register, AIRCR and CMSE-hygiene hooks; not M55 architectural CPU/SG/FP qualification. Pool boundary stub, not pool-memory proof.')
    (manifest.parent/'trace-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS C55SINIT generated mechanisms: '+str(COUNTS['calls'])+' traces, '+str(len(killed))+
          ' compiled mutants killed, '+str(len(cmse['ClassifierControls']))+' CMSE classifier controls')

if __name__ == '__main__':
    main()
'@ | Set-Content -LiteralPath $proof -Encoding ASCII
    $oldPath = $env:PYTHONPATH
    try {
        $modules = $PythonModules
        if (-not $modules) {
            $cached = Join-Path ([IO.Path]::GetTempPath()) "fiber-classic-audit-python"
            if (Test-Path -LiteralPath $cached) { $modules = $cached }
        }
        if ($modules) { $env:PYTHONPATH = $modules + [IO.Path]::PathSeparator + $oldPath }
        & $runCommand $Python @($proof, $manifest)
    }
    finally { $env:PYTHONPATH = $oldPath }
    & $assertInputs
    [ordered]@{Optimization=$Optimization; Sources=$PriorityPair.InitSourceHashes;
        Compiler=[ordered]@{Path=$compiler; Sha256=(Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash};
        Artifacts=@(Get-ChildItem -LiteralPath @($directory, (Split-Path $PriorityPair.FiberPath),
            (Split-Path $CpuPair.ReferencePath)) -File | Where-Object { $_.Name -ne 'artifacts.json' } | ForEach-Object {
            [ordered]@{Path=$_.FullName; Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
        })} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $directory "artifacts.json") -Encoding ASCII
}

function Test-C55STransferMechanisms {
    param([object]$Pair)
    $initDirectory = Join-Path $BuildRoot 'C55SINIT'
    $upstreamPath = Join-Path $initDirectory 'artifacts.json'
    $upstream = Get-Content $upstreamPath -Raw | ConvertFrom-Json
    $assertInputs = {
        foreach ($inputFile in @($Pair.InitSourceHashes)+@($upstream.Artifacts)) {
            if ((Get-FileHash -LiteralPath $inputFile.Path -Algorithm SHA256).Hash -ne $inputFile.Sha256) {
                throw "C55STRANSFER input changed during qualification: $($inputFile.Path)"
            }
        }
    }
    & $assertInputs
    foreach ($id in @('FAP-C55STRANSFER-ALLOCATE','FAP-C55STRANSFER-LOAD',
            'FAP-C55STRANSFER-SAVE','FAP-C55STRANSFER-GATES','FAP-CMSE-M55')) {
        if ($ledger.IndexOf($id, [StringComparison]::Ordinal) -lt 0) { throw "Missing ledger ID: $id" }
    }
    $directory = Join-Path $BuildRoot 'C55STRANSFER'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $profile = Join-Path $RepoRoot 'fiber\port\ARM_CM55\secure'
    $source = Join-Path $profile 'fiber_secure_context_gateway.c'
    $run = {
        param([string]$Program, [string[]]$Arguments)
        ConvertTo-Json -InputObject (@($Program)+$Arguments) -Compress |
            Add-Content (Join-Path $directory 'commands.jsonl') -Encoding ASCII
        & $Program @Arguments
        if ($LASTEXITCODE -ne 0) { throw "C55STRANSFER command failed: $Program" }
    }
    $compileFiber = {
        param([string]$SourcePath, [string]$Name, [switch]$Hostile)
        $object = Join-Path $directory "$Name.o"
        $arguments = @($Pair.FiberArguments)
        for ($i=0; $i -lt $arguments.Count; ++$i) {
            if ($arguments[$i] -eq $source) { $arguments[$i] = $SourcePath }
            if ($arguments[$i] -eq '-o') { $arguments[$i+1] = $object }
        }
        if ($Hostile) { $arguments += @('-finstrument-functions','-fstack-protector-all',
            '-fprofile-arcs','-ftest-coverage','-fsanitize=undefined') }
        & $run $compiler $arguments
        Get-ObjectDisassembly -Objdump $objdump -ObjectPath $object |
            Set-Content "$object.disasm" -Encoding ASCII
        return $object
    }
    $link = {
        param([string[]]$Objects, [string]$Name, [string]$Entry, [switch]$WithIdentity)
        $elf = Join-Path $directory "$Name.elf"
        $cohortArguments = @()
        if ($Entry.StartsWith('fiber_secure_')) {
            $cohortArguments += "-Wl,-T,$(Join-Path $profile 'fiber_secure_context_cohort_contract.ld')"
            # Explicit NSC roots, never an artificial root for the private
            # provider/key. Direct-object links do not prove archive extraction.
            $roots = @('initialize','abi_version','stack_alignment','max_stack_bytes',
                'max_contexts','allocate','load','save') | ForEach-Object { 'fiber_secure_context_gateway_c55s_v1_'+$_ }
            if ($WithIdentity) {
                $roots += @('abi_version','context_port_id','context_layout_version','context_feature_mask') |
                    ForEach-Object { 'fiber_secure_gateway_c55s_v1_'+$_ }
            }
            $cohortArguments += $roots | ForEach-Object { "-Wl,--undefined=__acle_se_$_" }
        }
        & $run $compiler (@('-mcpu=cortex-m55','-mthumb','-mcmse','-mfloat-abi=soft',
            '-nostdlib','-Wl,--gc-sections',"-Wl,-e,__acle_se_$Entry",
            "-Wl,-T,$(Join-Path $initDirectory 'body.ld')",'-Wl,--section-start=.gnu.sgstubs=0x08030000',
            "-Wl,-Map,$(Join-Path $directory "$Name.map")")+$cohortArguments+$Objects+@('-o',$elf))
        Get-ObjectDisassembly -Objdump $objdump -ObjectPath $elf |
            Set-Content "$elf.disasm" -Encoding ASCII
        return $elf
    }
    # Explicit gateway boundary fixture, not an alternative pool implementation.
    # The actual pool is linked/scanned separately and has its own behavior suite.
    $boundary = Join-Path $directory 'pool_boundary.c'
    @'
#include "fiber_secure_context_pool.h"
FiberSecureContextRecord c55stransfer_records[3];
volatile uint32_t c55stransfer_alloc_result = 2u;
volatile uint32_t c55stransfer_lookup_fail_at;
volatile uint32_t c55stransfer_lookup_calls;
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_boot_initialize(void) { return 1u; }
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberSecureContextHandle fiber_secure_context_pool_allocate(uint32_t bytes, uintptr_t owner)
{ (void)bytes; (void)owner; return c55stransfer_alloc_result; }
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberSecureContextRecord *fiber_secure_context_pool_lookup_owned(FiberSecureContextHandle handle, uintptr_t owner)
{
    ++c55stransfer_lookup_calls;
    if (c55stransfer_lookup_calls == c55stransfer_lookup_fail_at || handle == 0u || handle > 3u || owner == 0u)
        return 0;
    FiberSecureContextRecord *record = &c55stransfer_records[handle-1u];
    return record->owner_token == owner ? record : 0;
}
'@ | Set-Content $boundary -Encoding ASCII
    $boundaryObject = & $compileFiber $boundary 'pool-boundary'
    $cohortBoundaryObject = Join-Path $initDirectory 'cohort-boundary-provider.o'
    $fiberElf = & $link @($Pair.FiberPath,$boundaryObject,$cohortBoundaryObject) 'fiber' 'fiber_secure_context_gateway_c55s_v1_allocate'
    $actual = @{}
    $identities = @{}
    foreach ($variant in @('normal','hostile')) {
        $gateway = $Pair.FiberPath
        $pool = Join-Path $initDirectory "actual-pool-$variant.o"
        if ($variant -eq 'hostile') { $gateway = Join-Path $initDirectory 'hostile.o' }
        $identity = & $compileFiber (Join-Path $profile 'fiber_secure_gateway.c') "identity-$variant" -Hostile:($variant -eq 'hostile')
        $identities[$variant] = $identity
        $actual[$variant] = & $link @($gateway,$pool,$identity) "actual-$variant" 'fiber_secure_context_gateway_c55s_v1_allocate' -WithIdentity
    }
    $referencePort = Join-Path $directory 'reference-port.o'
    $referenceArguments = @($Pair.ReferenceArguments)
    for ($i=0; $i -lt $referenceArguments.Count; ++$i) {
        if ($referenceArguments[$i] -eq '-c') {
            $referenceArguments[$i+1] = Join-Path $kernel 'portable\GCC\ARM_CM55\secure\secure_context_port.c'
        }
        if ($referenceArguments[$i] -eq '-o') { $referenceArguments[$i+1] = $referencePort }
    }
    & $run $compiler $referenceArguments
    Get-ObjectDisassembly -Objdump $objdump -ObjectPath $referencePort |
        Set-Content "$referencePort.disasm" -Encoding ASCII
    $referenceObject = Join-Path $directory 'reference-without-free.o'
    & $run (Join-Path (Split-Path $compiler) 'arm-none-eabi-objcopy.exe') @(
        '--remove-section=.text.SecureContext_FreeContext',$Pair.ReferencePath,$referenceObject)
    $heap = Join-Path $directory 'reference_heap_boundary.c'
    @'
#include <stdint.h>
#include <stddef.h>
/* Actual pinned allocation runs; only its allocator result is controlled. */
volatile uintptr_t c55stransfer_heap_result = 0x30008000u;
void *pvPortMalloc(size_t bytes) { (void)bytes; return (void *)c55stransfer_heap_result; }
'@ | Set-Content $heap -Encoding ASCII
    $heapObject = & $compileFiber $heap 'reference-heap-boundary'
    $referenceElf = & $link @($referenceObject,$referencePort,$heapObject) 'reference' 'SecureContext_AllocateContext'
    $original = (Get-Content $source -Raw).Replace("`r`n","`n")
    $mutations = @()
    foreach ($operation in @('allocate','load','save')) {
        $mutations += @{Name="$operation-origin"; Operation=$operation; Find='__builtin_arm_cmse_nonsecure_caller\(\) == 0'; Replacement='0u'}
        $mutations += @{Name="$operation-ready"; Operation=$operation; Find='fiber_secure_context_gateway_state !=\s*fiber_secure_contextGATEWAY_READY'; Replacement='0u'}
        $mutations += @{Name="$operation-control"; Operation=$operation; Find='control != 2u'; Replacement='0u'}
        $mutations += @{Name="$operation-handler"; Operation=$operation; Find='FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER'; Replacement='15u'}
    }
    $mutations += @(
        @{Name='allocate-limit'; Operation='allocate'; Find='stack_limit != 0u'; Replacement='0u'},
        @{Name='allocate-pointer'; Operation='allocate'; Find='stack_pointer != 0u'; Replacement='0u'},
        @{Name='load-limit-admission'; Operation='load'; Find='stack_limit != 0u'; Replacement='0u'},
        @{Name='load-pointer-admission'; Operation='load'; Find='stack_pointer != 0u'; Replacement='0u'},
        @{Name='load-owner'; Operation='load'; Find='owner_token == 0u'; Replacement='0u'},
        @{Name='load-lookup'; Operation='load'; Find='\(FiberSecureContextHandle\)handle, owner_token'; Replacement='(FiberSecureContextHandle)handle, 0u'},
        @{Name='load-limit-readback'; Operation='load'; Find='limit_after != stack_limit'; Replacement='0u'; Multiple=$true},
        @{Name='load-pointer-readback'; Operation='load'; Find='pointer_after != stack_pointer'; Replacement='0u'},
        @{Name='save-owner'; Operation='save'; Find='owner_token == 0u'; Replacement='0u'},
        @{Name='save-limit-admission'; Operation='save'; Find='stack_limit != record->stack_limit'; Replacement='0u'},
        @{Name='save-align'; Operation='save'; Find='(?s)\(stack_pointer &\s*\(FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT - 1u\)\) !=\s*0u'; Replacement='0u'},
        @{Name='save-lower'; Operation='save'; Find='stack_pointer < record->stack_limit'; Replacement='0u'},
        @{Name='save-upper'; Operation='save'; Find='stack_pointer > record->stack_top'; Replacement='0u'},
        @{Name='save-lookup-readback'; Operation='save'; Find='(?s)fiber_secure_context_pool_lookup_owned\(\s*\(FiberSecureContextHandle\)handle, owner_token\) != record'; Replacement='0u'},
        @{Name='save-publication-readback'; Operation='save'; Find='(?s)\(\(volatile FiberSecureContextRecord \*\)record\)->current_stack_pointer !=\s*stack_pointer'; Replacement='0u'},
        @{Name='save-limit-readback'; Operation='save'; Find='limit_after != 0u'; Replacement='0u'; Multiple=$true},
        @{Name='save-pointer-readback'; Operation='save'; Find='pointer_after != 0u'; Replacement='0u'},
        @{Name='load-barriers'; Operation='load'; Find='fiber_secure_contextBARRIERS\(\);'; Replacement=''; Multiple=$true},
        @{Name='save-barriers'; Operation='save'; Find='fiber_secure_contextBARRIERS\(\);'; Replacement=''; Multiple=$true},
        @{Name='load-order'; Operation='load'; Remove='__asm volatile \("msr psp, %0" :: "r" \(stack_pointer\) : "memory"\);';
          Find='__asm volatile \("msr psplim, %0" :: "r" \(stack_limit\) : "memory"\);';
          Replacement='__asm volatile ("msr psp, %0" :: "r" (stack_pointer) : "memory"); __asm volatile ("msr psplim, %0" :: "r" (stack_limit) : "memory");'},
        @{Name='save-order'; Operation='save'; Remove='__asm volatile \("msr psplim, %0" :: "r" \(0u\) : "memory"\);';
          Find='\(\(volatile FiberSecureContextRecord \*\)record\)->current_stack_pointer =';
          Replacement='__asm volatile ("msr psplim, %0" :: "r" (0u) : "memory"); ((volatile FiberSecureContextRecord *)record)->current_stack_pointer ='},
        @{Name='save-publication'; Operation='save'; Find='(?s)\(\(volatile FiberSecureContextRecord \*\)record\)->current_stack_pointer =\s*stack_pointer;'; Replacement='/* removed PSP publication */'},
        @{Name='allocate-control-write'; Operation='allocate'; Find='uint32_t control;';
          Replacement='uint32_t control; __asm volatile ("msr control, %0" :: "r" (2u) : "memory");'},
        @{Name='allocate-fp-data'; Operation='allocate'; Find='uint32_t control;'; Replacement='uint32_t control; __asm volatile (".inst.w 0xee000a10" ::: "memory");'}
    )
    $mutants = @()
    foreach ($mutation in $mutations) {
        $span = Get-C55SGatewayFunctionSpan $original ('fiber_secure_context_gateway_c55s_v1_'+$mutation.Operation)
        $functionText = $span.Text
        if ($mutation.ContainsKey('Remove')) {
            if ([regex]::Matches($functionText,$mutation.Remove).Count -ne 1) {
                throw "C55STRANSFER movement anchor changed: $($mutation.Name)"
            }
            $functionText = [regex]::Replace($functionText,$mutation.Remove,'')
        }
        $matches = [regex]::Matches($functionText,$mutation.Find)
        if ($matches.Count -eq 0 -or (-not $mutation.ContainsKey('Multiple') -and $matches.Count -ne 1)) {
            throw "C55STRANSFER mutant anchor changed: $($mutation.Name)"
        }
        $changed = $original.Substring(0,$span.Start)+[regex]::Replace($functionText,$mutation.Find,$mutation.Replacement)+
            $original.Substring($span.Start+$span.Length)
        $mutantSource = Join-Path $directory ("mutant-"+$mutation.Name+'.c')
        Set-Content $mutantSource $changed -Encoding ASCII
        $object = & $compileFiber $mutantSource ("mutant-"+$mutation.Name)
        $elf = & $link @($object,$boundaryObject,$cohortBoundaryObject) ("mutant-"+$mutation.Name) 'fiber_secure_context_gateway_c55s_v1_allocate'
        $mutants += [ordered]@{Name=$mutation.Name;Operation=$mutation.Operation;Elf=$elf}
    }
    $manifest = Join-Path $directory 'inputs.json'
    [ordered]@{Fiber=$fiberElf;Actual=$actual;IdentityObjects=$identities;BoundaryProvider=$cohortBoundaryObject;
        Reference=$referenceElf;ReferenceOriginal=$Pair.ReferencePath;
        ReferenceIsolated=$referenceObject;ReferencePort=$referencePort;GatewayObject=$Pair.FiberPath;
        HostileObject=(Join-Path $initDirectory 'hostile.o');Mutants=$mutants;Optimization=$Optimization;
        InitProof=(Join-Path $initDirectory 'trace_init.py')} |
        ConvertTo-Json -Depth 6 | Set-Content $manifest -Encoding ASCII
    $proof = Join-Path $directory 'trace_transfer.py'
    @'
"""Actual ARM C bodies; explicit CPU/CMSE and pool/heap boundary doubles.
Not physical M55 execution, real pool lifecycle or an NS runtime provider.
"""
import sys
if sys.flags.optimize or not __debug__:
    raise SystemExit('C55STRANSFER requires Python optimization disabled')
import importlib.util, json, struct
from pathlib import Path
inputs=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig'))
spec=importlib.util.spec_from_file_location('c55s_init_proof',inputs['InitProof'])
base=importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
check,Failure,arm=base.check,base.ProofFailure,base.arm
PREFIX='fiber_secure_context_gateway_c55s_v1_'
OWNER,LIMIT,TOP,PSP=0x11223344,0x30008000,0x30008100,0x30008080
RESULTS={'cases':0}

def body(image,name):
    start=image.address(base.body_name(name))
    end=min(s['value'] & ~1 for s in image.symbols.values()
        if s['kind'] == 'STT_FUNC' and (s['value'] & ~1) > start)
    return [(a,length,op,args) for a,(length,op,args) in sorted(image.instructions.items()) if start <= a < end]

def full_template(value_return=True):
    clear='{r1, r2, r3, ip, APSR}' if value_return else '{r0, r1, r2, r3, ip, APSR}'
    return [('vstr','FPCXTNS, [sp, #-4]!',(0xED6D,0xCF81)),
        ('vscclrm','{s0-s15, VPR}',(0xEC9F,0x0A10)),
        ('clrm',clear,(0xE89F,0x900E if value_return else 0x900F)),
        ('vldr','FPCXTNS, [sp], #4',(0xECFD,0xCF81)),('bxns','lr',(0x4774,))]

def static_template(image,name,value_return=True):
    instructions=body(image,name)
    selected=[(a,op,args) for a,_,op,args in instructions if op.startswith('v') or op in ('clrm','bxns')]
    actual=[(op,args,image.encoding[a]) for a,op,args in selected]
    full=full_template(value_return)
    short=full[1:3]+full[4:]
    check(actual in (full,full+short,short+full),'transfer CMSE template changed',name)
    tails=([selected[:3],selected[4:8]] if actual==short+full else
           [selected[1:5]]+([selected[5:]] if len(selected)>5 else []))
    for tail in tails:
        check(all(tail[i][0]+image.instructions[tail[i][0]][0] == tail[i+1][0] for i in range(len(tail)-1)),
              'transfer CMSE epilogue is not contiguous',name)
    check(not any(op == 'msr' and args.split(',')[0].strip() == 'CONTROL' for _,_,op,args in instructions),
          'transfer wrote CONTROL',name)
    return actual

class Machine(base.Machine):
    def __init__(self,path,operation='load',fault=None,**kwargs):
        super().__init__(path,**kwargs)
        self.operation,self.transfer_fault=operation,fault
        self.cpu=dict(CONTROL=2,PSPLIM=LIMIT if operation=='save' else 0,PSP=PSP if operation=='save' else 0)
        if self.state: self.put(self.state,base.READY)
        self.records=self.image.symbols.get('c55stransfer_records',{}).get('value',0)
        self.published=0
        if self.records:
            check(self.image.symbols['c55stransfer_records']['size'] == 72,'boundary record geometry changed')
            for i in range(3):
                self.uc.mem_write(self.records+24*i,struct.pack('<6I',TOP,LIMIT,TOP,OWNER,256,0xA110CA7E))
        self.boundaries={}
        for symbol,event in [('fiber_secure_context_pool_allocate','allocate'),
                ('fiber_secure_context_pool_lookup_owned','lookup'),('pvPortMalloc','heap')]:
            if symbol in self.image.symbols: self.boundaries[self.image.address(symbol)]=event
        self.security=[]

    def code(self,uc,address,size,data):
        if address in self.boundaries:
            event=self.boundaries[address]
            self.trace.append((event,uc.reg_read(arm.UC_ARM_REG_R0),uc.reg_read(arm.UC_ARM_REG_R1)))
        decoded=self.image.instructions.get(address)
        if decoded:
            _,op,args=decoded
            if op.startswith('v') or op in ('clrm','bxns'):
                self.security.append((op,args,self.image.encoding[address]))
            if op == 'mrs':
                register=args.split(',')[1].strip()
                writes=[e for e in self.trace if e[0] == 'write']
                fault=self.transfer_fault
                corrupt=((fault=='limit-first' and register=='PSPLIM' and len(writes)==1) or
                         (fault=='limit-final' and register=='PSPLIM' and len(writes)==2) or
                         (fault=='pointer-final' and register=='PSP' and len(writes)==2))
                if corrupt:
                    old=self.cpu[register]
                    self.cpu[register]=old^8
                    super().code(uc,address,size,data)
                    self.cpu[register]=old
                    return
        super().code(uc,address,size,data)

    def memory(self,uc,kind,address,size,value,data):
        if self.records and self.records <= address < self.records+72 and (address-self.records)%24 == 0:
            if kind == base.UC_MEM_WRITE:
                self.published=address
                self.trace.append(('publish',address,value))
            else:
                visible=self.get(address)
                if self.transfer_fault == 'saved-read' and address == self.published:
                    self.put(address,visible^8)
                    self.pending.append((address,visible))
                    visible^=8
                self.trace.append(('saved-read',address,visible))
        super().memory(uc,kind,address,size,value,data)

    def invoke(self,operation,args):
        self.security=[]
        for i,value in enumerate(args): self.uc.reg_write(base.REGS['r'+str(i)],value)
        name=PREFIX+operation if self.records else 'SecureContext_'+operation.title()+'Context'
        result=self.call(name)
        expected=full_template(self.records != 0 or operation=='allocate')
        check(self.security in (expected,expected[1:3]+expected[4:]),'executed transfer CMSE template changed',name)
        return result

def effects(trace):
    return [e for e in trace if e[0] in ('allocate','lookup','write','publish','heap','record-write')]

def case(path,operation,name,expected=0,cpu=None,handle=2,owner=OWNER,marker=base.READY,
         ipsr=None,nonsecure=True,fault=None,pool_result=2,lookup_fail=0,expected_effects=None,order=None):
    RESULTS['cases']+=1
    m=Machine(path,operation,fault=fault,ipsr=(14 if operation=='save' else 11) if ipsr is None else ipsr,nonsecure=nonsecure)
    if cpu: m.cpu.update(cpu)
    m.put(m.state,marker)
    m.put(m.image.address('c55stransfer_alloc_result'),pool_result)
    m.put(m.image.address('c55stransfer_lookup_fail_at'),lookup_fail)
    args=(64,owner) if operation=='allocate' else (handle,owner)
    result=m.invoke(operation,args)
    code=operation+':'+name
    check(result==expected,code,str(m.trace))
    if expected_effects is not None:
        expected_events=expected_effects(m) if callable(expected_effects) else expected_effects
        check(effects(m.trace)==expected_events,code+'-effects',str(m.trace))
    if order is not None:
        try: base.ordered(m.trace,order(m))
        except Failure as exc: raise Failure(code+'-order',str(exc)) from exc
    return m

def expected_load(m): return [('lookup',2,OWNER),('write','PSPLIM',LIMIT),('write','PSP',TOP)]
def expected_save(m): return [('lookup',2,OWNER),('publish',m.records+24,PSP),('lookup',2,OWNER),
                              ('write','PSPLIM',0),('write','PSP',0)]
def load_order(m): return [('lookup',2,OWNER),('write','PSPLIM',LIMIT),('dsb',),('isb',),('read','PSPLIM',LIMIT),
                          ('write','PSP',TOP),('dsb',),('isb',),('read','PSP',TOP),('read','PSPLIM',LIMIT)]
def save_order(m): return [('publish',m.records+24,PSP),('dsb',),('isb',),('lookup',2,OWNER),
                          ('saved-read',m.records+24,PSP),('write','PSPLIM',0),('dsb',),('isb',),('read','PSPLIM',0),
                          ('write','PSP',0),('dsb',),('isb',),('read','PSP',0),('read','PSPLIM',0)]

def check_fiber(path,operation):
    for exception in ((14,) if operation=='save' else (11,14)):
        case(path,operation,'valid-'+str(exception),expected=2 if operation=='allocate' else 1,ipsr=exception,
            expected_effects=([('allocate',64,OWNER)] if operation=='allocate' else expected_load if operation=='load' else expected_save),
            order=load_order if operation=='load' else save_order if operation=='save' else None)
    case(path,operation,'secure-origin',nonsecure=False,expected_effects=[])
    for exception in (0,1,3,15,16)+( (11,) if operation=='save' else ()):
        case(path,operation,'handler-'+str(exception),ipsr=exception,expected_effects=[])
    for marker in (0,base.INITIALIZING,1,0xFFFFFFFF):
        case(path,operation,'state-'+str(marker),marker=marker,expected_effects=[])
    for control in (0,1,3,6,7,0x80000002):
        case(path,operation,'control-'+str(control),cpu={'CONTROL':control},expected_effects=[])
    if operation=='allocate':
        case(path,operation,'loaded-limit',cpu={'PSPLIM':LIMIT},expected_effects=[])
        case(path,operation,'loaded-pointer',cpu={'PSP':PSP},expected_effects=[])
        for result in (0,1,3,0xFFFFFFFF):
            case(path,operation,'pool-result-'+str(result),expected=result,pool_result=result,
                 expected_effects=[('allocate',64,OWNER)])
        return
    case(path,operation,'zero-owner',handle=0,owner=0,cpu={'PSP':0,'PSPLIM':0},expected_effects=[])
    case(path,operation,'zero-handle',expected=1,handle=0,cpu={'PSP':0,'PSPLIM':0},expected_effects=[])
    for handle,owner in ((4,OWNER),(0xFFFFFFFF,OWNER),(1,OWNER+1)):
        case(path,operation,'ownership-'+str(handle),handle=handle,owner=owner,
             expected_effects=[('lookup',handle,owner)])
    if operation=='load':
        case(path,operation,'loaded-limit',cpu={'PSPLIM':LIMIT},expected_effects=[])
        case(path,operation,'loaded-pointer',cpu={'PSP':PSP},expected_effects=[])
        for fault in ('limit-first','limit-final','pointer-final'):
            case(path,operation,fault,fault=fault,expected_effects=([('lookup',2,OWNER),('write','PSPLIM',LIMIT)] if
                fault=='limit-first' else expected_load))
    else:
        for name,cpu in [('wrong-limit',{'PSPLIM':LIMIT+8}),('unaligned',{'PSP':PSP+1}),
                         ('lower-bound',{'PSP':LIMIT-8}),('upper-bound',{'PSP':TOP+8})]:
            case(path,operation,name,cpu=cpu,expected_effects=[('lookup',2,OWNER)])
        for pointer in (LIMIT,TOP):
            m=case(path,operation,'inclusive-'+str(pointer),expected=1,cpu={'PSP':pointer})
            check(m.get(m.records+24)==pointer,'inclusive save publication changed')
        case(path,operation,'zero-handle-loaded',handle=0,expected_effects=[])
        for fault in ('limit-first','limit-final','pointer-final','saved-read'):
            expected=lambda m: expected_save(m)[:3] if fault=='saved-read' else (
                expected_save(m)[:4] if fault=='limit-first' else expected_save(m))
            m=case(path,operation,fault,fault=fault,expected_effects=expected)
            if fault=='saved-read': check(not any(e[0]=='write' for e in m.trace),'saved-read failure cleared CPU state')
        m=case(path,operation,'lookup-readback',lookup_fail=2,expected_effects=lambda m: expected_save(m)[:3])
        check(not any(e[0]=='write' for e in m.trace),'lookup revalidation failure cleared CPU state')

def round_trip(path):
    m=Machine(path,'allocate',ipsr=14)
    RESULTS['cases']+=7
    check(m.invoke('allocate',(64,OWNER))==2,'round-trip allocation forwarding changed')
    check(m.invoke('load',(2,OWNER))==1 and m.cpu==dict(CONTROL=2,PSPLIM=LIMIT,PSP=TOP),'round-trip load changed')
    check(m.invoke('load',(2,OWNER))==0 and not effects(m.trace),'loaded stack admitted another load')
    m.cpu['PSP']=PSP  # Explicit modeled Secure Thread stack movement, not CPU execution.
    check(m.invoke('save',(2,OWNER))==1 and m.get(m.records+24)==PSP,'round-trip save changed')
    check(m.invoke('load',(2,OWNER))==1 and m.cpu['PSP']==PSP,'saved PSP was not reloaded')
    check(m.invoke('save',(2,OWNER))==1 and m.cpu['PSPLIM']==0 and m.cpu['PSP']==0,'round-trip second clear changed')
    check(m.invoke('save',(0,OWNER))==1 and not effects(m.trace),'unloaded zero-handle no-op changed')

def reference_checks(path):
    m=Machine(path,'allocate')
    record=m.image.address('xSecureContexts')
    for index in range(3):
        m.put(m.image.address('c55stransfer_heap_result'),LIMIT+index*0x100)
        owner=OWNER+index
        check(m.invoke('allocate',(64,owner))==index+1,'pinned allocation index-plus-one changed')
        check([e[:2] for e in m.trace if e[0]=='heap']==[('heap',72)],'pinned allocation/seal byte count changed')
        check(struct.unpack('<4I',m.uc.mem_read(record+16*index,16))==
              (LIMIT+index*0x100+64,LIMIT+index*0x100,LIMIT+index*0x100+64,owner),'pinned four-word publication changed')
        check(bytes(m.uc.mem_read(LIMIT+index*0x100+64,8))==struct.pack('<2I',0xFEF5EDA5,0xFEF5EDA5),
              'pinned seal representation changed')
        check(m.invoke('allocate',(64,owner))==0 and not effects(m.trace),'pinned duplicate owner accepted')
    check(m.invoke('allocate',(64,OWNER+3))==0 and not effects(m.trace),'pinned exhaustion changed')
    for name,args,cpu,heap in [('thread',(64,OWNER),{'IPSR':0},LIMIT),('loaded',(64,OWNER),{'PSPLIM':LIMIT},LIMIT),
                             ('overflow',(0xFFFFFFF8,OWNER),{},LIMIT),('heap-null',(64,OWNER),{},0)]:
        n=Machine(path,'allocate',ipsr=cpu.pop('IPSR',11))
        n.cpu.update(cpu)
        n.put(n.image.address('c55stransfer_heap_result'),heap)
        check(n.invoke('allocate',args)==0,'pinned allocation negative changed',name)
        check(not any(e[0]=='write' for e in n.trace),'pinned allocation wrote CPU state')
    for operation in ('load','save'):
        for exception in (0,11,14):
            n=Machine(path,operation,ipsr=exception)
            n.uc.mem_write(n.image.address('xSecureContexts'),struct.pack('<4I',PSP,LIMIT,TOP,OWNER))
            n.invoke(operation,(1,OWNER))
            if exception==0:
                check(not effects(n.trace),'pinned assembly Thread gate changed',operation)
            elif operation=='load':
                check(effects(n.trace)==[('write','PSPLIM',LIMIT),('write','PSP',PSP)],'pinned load order changed')
            else:
                check(effects(n.trace)==[('record-write',0,4,PSP),('write','PSPLIM',0),('write','PSP',0)],
                      'pinned save publication/clear order changed')
        for handle,owner in ((0,OWNER),(4,OWNER),(0xFFFFFFFF,OWNER),(1,OWNER+1)):
            n=Machine(path,operation)
            n.uc.mem_write(n.image.address('xSecureContexts'),struct.pack('<4I',PSP,LIMIT,TOP,OWNER))
            n.invoke(operation,(handle,owner))
            check(not effects(n.trace),'pinned handle/owner rejection changed',operation)

def query_checks(path,identity_object):
    # Execute the real provider and eight real cold entries, not the modeled
    # allocator. Numeric results and tuple oracle do not come from the headers.
    values={'fiber_secure_gateway_c55s_v1_abi_version':1,
            'fiber_secure_gateway_c55s_v1_context_port_id':0x43353553,
            'fiber_secure_gateway_c55s_v1_context_layout_version':0x00010001,
            'fiber_secure_gateway_c55s_v1_context_feature_mask':0x8A,
            PREFIX+'abi_version':1,PREFIX+'stack_alignment':8,
            PREFIX+'max_stack_bytes':256,PREFIX+'max_contexts':3}
    result={}
    for name,value in values.items():
        if name.startswith('fiber_secure_gateway_'):
            relocations=base.function_relocations(identity_object,name)
            check(relocations.count((10,base.COHORT_HELPER))==1 and
                  relocations.count((2,base.COHORT_KEY))==1,
                  'identity missing exact private cohort call/key relocations',name)
        m=base.Machine(path,ipsr=0)
        before=bytes(m.uc.mem_read(0x30000000,0x18000))
        cpu=dict(m.cpu)
        check(m.call(name)==value,'actual query result differs from numeric oracle',name)
        check(m.trace==[('cohort-provider',),('cohort-read',1)],'query acquired state/CPU/pool effects',name)
        check(m.cpu==cpu and bytes(m.uc.mem_read(0x30000000,0x18000))==before,
              'query changed CPU/pool/BSS',name)
        result[name]=dict(Value=value,Trace=m.trace,CMSE=base.cmse_template(m.image,name,True))
    return result

def main():
    for operation in ('Allocate','Load','Save'):
        base.reference_identity(inputs['ReferenceOriginal'],inputs['ReferenceIsolated'],'SecureContext_'+operation+'Context')
    expected={'fiber_secure_context_pool_boot_initialize','fiber_secure_context_pool_allocate',
              'fiber_secure_context_pool_lookup_owned'}|base.COHORT_IMPORTS
    check(base.dependencies(inputs['GatewayObject'])==expected,'gateway dependency contract changed')
    check(base.dependencies(inputs['HostileObject'])==expected,'gateway hostile instrumentation dependency')
    for path in (inputs['GatewayObject'],inputs['HostileObject']):
        for operation in ('allocate','load','save'):
            relocations=base.function_relocations(path,PREFIX+operation)
            check(not any(target==base.COHORT_HELPER or target.startswith('fiber_secure_context_cohort_')
                          for _,target in relocations),'hot transfer acquired private cohort dependency',operation)
    templates={}
    queries={}
    for variant,path in inputs['Actual'].items():
        image=base.Image(path)
        entries={name for name in image.symbols if name.startswith('__acle_se_')}
        check(len(entries)==12,'C55S NSC export count changed',variant)
        base.static_callgraph(path,whole_pool=True)
        base.cohort_definition(path)
        identity=inputs['IdentityObjects'][variant]
        check(base.dependencies(identity)==base.COHORT_IMPORTS,'identity dependency contract changed',variant)
        queries[variant]=query_checks(path,identity)
        templates[variant]={operation:static_template(image,PREFIX+operation) for operation in ('allocate','load','save')}
    reference=base.Image(inputs['Reference'])
    templates['reference']={operation:static_template(reference,'SecureContext_'+operation.title()+'Context',operation=='allocate')
        for operation in ('allocate','load','save')}
    for name in ('SecureContext_LoadContextAsm','SecureContext_SaveContextAsm'):
        start=reference.address(name)
        size=reference.symbols[name]['size']
        instructions=[v for a,v in reference.instructions.items() if start<=a<start+size]
        check(not any(op.startswith('v') or (op=='msr' and args.split(',')[0].strip()=='CONTROL') for _,op,args in instructions),
              'pinned no-MPU/no-FP helper branch changed',name)
    reference_checks(inputs['Reference'])
    for operation in ('allocate','load','save'): check_fiber(inputs['Fiber'],operation)
    round_trip(inputs['Fiber'])
    expected_kills={}
    for op in ('allocate','load','save'):
        expected_kills.update({op+'-origin':op+':secure-origin',op+'-ready':op+':state-0',op+'-control':op+':control-0',
                              op+'-handler':op+':valid-14'})
    expected_kills.update({'allocate-limit':'allocate:loaded-limit','allocate-pointer':'allocate:loaded-pointer',
        'load-limit-admission':'load:loaded-limit','load-pointer-admission':'load:loaded-pointer','load-owner':'load:zero-owner',
        'load-lookup':'load:valid-11','load-limit-readback':'load:limit-first','load-pointer-readback':'load:pointer-final',
        'save-owner':'save:zero-owner','save-limit-admission':'save:wrong-limit','save-align':'save:unaligned',
        'save-lower':'save:lower-bound','save-upper':'save:upper-bound','save-lookup-readback':'save:valid-14-effects',
        'save-publication-readback':'save:valid-14-order','save-limit-readback':'save:limit-first',
        'save-pointer-readback':'save:pointer-final','load-barriers':'load:valid-11-order','save-barriers':'save:valid-14-order',
        'load-order':'load:valid-11-effects','save-order':'save:valid-14-effects','save-publication':'save:valid-14',
        'allocate-control-write':'allocate:valid-11-effects',
        'allocate-fp-data':'FP data instruction vmov s0, r0'})
    check({m['Name'] for m in inputs['Mutants']}==set(expected_kills),'transfer mutant inventory changed')
    killed=[]
    for mutant in inputs['Mutants']:
        try: check_fiber(mutant['Elf'],mutant['Operation'])
        except Failure as exc:
            check(exc.code==expected_kills[mutant['Name']],'transfer mutant rejected for unintended reason',mutant['Name']+': '+str(exc))
            killed.append(dict(Name=mutant['Name'],Diagnostic=str(exc)))
        else: raise RuntimeError('transfer mutant survived: '+mutant['Name'])
    result=dict(RESULTS,ArmCalls=base.COUNTS['calls'],CompiledMutants=len(killed),Killed=killed,CMSE=templates,
        PrivateCohort=dict(Key=base.COHORT_KEY,Facts=base.COHORT_FACTS,Queries=queries,
                           QueryCalls=sum(len(value) for value in queries.values()),ColdConsumers=9),
        Optimization=inputs['Optimization'],Scope=__doc__)
    (Path(sys.argv[1]).parent/'trace-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS C55STRANSFER: '+str(RESULTS['cases'])+' gateway cases, '+str(base.COUNTS['calls'])+
          ' ARM calls, '+str(len(killed))+' compiled mutants killed; 16 actual query calls, normal/hostile 12-export callgraphs')

if __name__=='__main__': main()
'@ | Set-Content $proof -Encoding ASCII
    $oldPath = $env:PYTHONPATH
    try {
        $modules = $PythonModules
        if (-not $modules) { $modules = Join-Path ([IO.Path]::GetTempPath()) 'fiber-classic-audit-python' }
        $env:PYTHONPATH = $modules+[IO.Path]::PathSeparator+$oldPath
        & $run $Python @($proof,$manifest)
    }
    finally { $env:PYTHONPATH = $oldPath }
    & $assertInputs
    [ordered]@{Optimization=$Optimization;Sources=$Pair.InitSourceHashes;
        ReferenceCommit=$ExpectedFreeRtosCommit;
        Compiler=[ordered]@{Path=$compiler;Sha256=(Get-FileHash $compiler -Algorithm SHA256).Hash};
        UpstreamReceipt=[ordered]@{Path=$upstreamPath;Sha256=(Get-FileHash $upstreamPath -Algorithm SHA256).Hash};
        Artifacts=@(Get-ChildItem $directory -File | Where-Object {$_.Name -ne 'artifacts.json'} | ForEach-Object {
            [ordered]@{Path=$_.FullName;Sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash}
        })} | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $directory 'artifacts.json') -Encoding ASCII
}

function Test-C33SCohortMechanisms {
    param([object]$Pair,[object]$PriorityPair)
    if ($ledger.IndexOf('FAP-C33S-PRIVATE-COHORT',[StringComparison]::Ordinal) -lt 0) {
        throw 'Missing ledger ID: FAP-C33S-PRIVATE-COHORT'
    }
    $upstreamPath = Join-Path $BuildRoot 'C55SINIT\artifacts.json'
    $upstream = Get-Content -LiteralPath $upstreamPath -Raw | ConvertFrom-Json
    $assertInputs = {
        foreach ($inputFile in @($Pair.InitSourceHashes)+@($PriorityPair.InitSourceHashes)+
                @($upstream.Sources)+@($upstream.Artifacts)) {
            if ((Get-FileHash -LiteralPath $inputFile.Path -Algorithm SHA256).Hash -ne $inputFile.Sha256) {
                throw "C33SCOHORT input changed during qualification: $($inputFile.Path)"
            }
        }
    }
    & $assertInputs
    $directory = Join-Path $BuildRoot 'C33SCOHORT'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $profile = Join-Path $RepoRoot 'fiber\port\ARM_CM33\secure'
    $source = Join-Path $profile 'fiber_secure_context_gateway.c'
    $run = {
        param([string]$Program,[string[]]$Arguments)
        ConvertTo-Json -InputObject (@($Program)+$Arguments) -Compress |
            Add-Content (Join-Path $directory 'commands.jsonl') -Encoding ASCII
        & $Program @Arguments
        if ($LASTEXITCODE -ne 0) { throw "C33SCOHORT command failed: $Program" }
    }
    $compile = {
        param([string]$SourcePath,[string]$Name,[switch]$SupportedHostile)
        $object = Join-Path $directory "$Name.o"
        $arguments = @($Pair.FiberArguments)
        for ($i=0; $i -lt $arguments.Count; ++$i) {
            if ($arguments[$i] -eq $source) { $arguments[$i] = $SourcePath }
            if ($arguments[$i] -eq '-o') { $arguments[$i+1] = $object }
        }
        if ($SupportedHostile) {
            # CM33 uses CMSIS/CMSE inline wrappers. Its supported image contract
            # requires these counterflags; this is not an attributes-alone test.
            $arguments += @('-finstrument-functions','-fstack-protector-all','-fprofile-arcs',
                '-ftest-coverage','-fsanitize=undefined','-fno-instrument-functions',
                '-fno-stack-protector','-fno-profile-arcs','-fno-test-coverage','-fno-sanitize=all')
        }
        if ($arguments -notcontains '-mcmse') { throw 'C33S private pool requires -mcmse' }
        & $run $compiler $arguments
        Get-ObjectDisassembly -Objdump $objdump -ObjectPath $object |
            Set-Content "$object.disasm" -Encoding ASCII
        return $object
    }
    $contextNames = @('abi_version','stack_alignment','max_stack_bytes','max_contexts',
        'initialize','allocate','load','save') | ForEach-Object { 'fiber_secure_context_gateway_v1_'+$_ }
    $identityNames = @('abi_version','context_port_id','context_layout_version','context_feature_mask') |
        ForEach-Object { 'fiber_secure_gateway_v1_'+$_ }
    $exports = @($contextNames)+@($identityNames)
    $linker = Join-Path $directory 'body.ld'
    @'
ENTRY(fiber_secure_context_gateway_v1_initialize)
SECTIONS {
 .text 0x08000000 : { *(.text*) }
 .rodata : { *(.rodata*) }
 .gnu.sgstubs 0x08030000 : { *(.gnu.sgstubs*) }
 .data 0x30000000 : { *(.data*) }
 .bss 0x30001000 (NOLOAD) : { *(.bss*) *(COMMON) }
 .fiber_secure_context_pool 0x30002000 (NOLOAD) : { *(.fiber_secure_context_pool) }
 /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) }
}
'@ | Set-Content $linker -Encoding ASCII
    $link = {
        param([string[]]$Objects,[string]$Name,[string]$Entry,[switch]$Fiber)
        $elf = Join-Path $directory "$Name.elf"
        $arguments = @('-mcpu=cortex-m33','-mthumb','-mcmse','-mfloat-abi=soft','-nostdlib',
            '-Wl,--gc-sections',"-Wl,-e,__acle_se_$Entry","-Wl,-T,$linker",
            '-Wl,--section-start=.gnu.sgstubs=0x08030000',"-Wl,-Map,$directory/$Name.map")
        if ($Fiber) {
            $arguments += "-Wl,-T,$(Join-Path $profile 'fiber_secure_context_cohort_contract.ld')"
            # Root actual NSC entries, never the private helper/key. These are
            # direct-object mechanism links, not archive/LTO extraction proof.
            $arguments += $exports | ForEach-Object { "-Wl,--undefined=__acle_se_$_" }
        }
        & $run $compiler ($arguments+$Objects+@('-o',$elf))
        Get-ObjectDisassembly -Objdump $objdump -ObjectPath $elf |
            Set-Content "$elf.disasm" -Encoding ASCII
        return $elf
    }
    $variants = @{}
    foreach ($variant in @('normal','supported-hostile')) {
        $objects = @{}
        foreach ($unit in @('gateway','identity','pool')) {
            $file = switch ($unit) {
                'gateway' { 'fiber_secure_context_gateway.c' }
                'identity' { 'fiber_secure_gateway.c' }
                'pool' { 'fiber_secure_context_pool.c' }
            }
            $objects[$unit] = & $compile (Join-Path $profile $file) "$variant-$unit" -SupportedHostile:($variant -ne 'normal')
        }
        $elf = & $link @($objects.gateway,$objects.identity,$objects.pool) $variant 'fiber_secure_context_gateway_v1_initialize' -Fiber
        $variants[$variant] = [ordered]@{Objects=$objects;Elf=$elf}
    }
    # C33S fixture-only source copies: test one legacy mechanism at a time.
    # The production files and all twelve facts remain untouched.
    $copySecure = {
        param([string]$Name,[switch]$Literal)
        $root = Join-Path $directory $Name
        $copy = Join-Path $root 'fiber\port\ARM_CM33\secure'
        New-Item -ItemType Directory -Path $copy -Force | Out-Null
        Get-ChildItem -LiteralPath $profile -File | Where-Object { $_.Extension -in @('.c','.h','.ld') } |
            ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $copy $_.Name) }
        Copy-Item -LiteralPath (Join-Path $RepoRoot 'fiber\fiber_api_attributes.h') -Destination (Join-Path $root 'fiber\fiber_api_attributes.h')
        if ($Literal) {
            $header = Join-Path $copy 'fiber_secure_context_cohort.h'
            $text = (Get-Content -LiteralPath $header -Raw).Replace("`r`n","`n")
            $pair = '"movw %[cohort_byte], #:lower16:" FIBER_C33S_PRIVATE_COHORT_KEY "\n\t" \' + "`n`t`t" +
                '"movt %[cohort_byte], #:upper16:" FIBER_C33S_PRIVATE_COHORT_KEY "\n\t"'
            if ([regex]::Matches($text,[regex]::Escape($pair)).Count -ne 1) { throw 'C33S materialization control anchor changed' }
            $text.Replace($pair,'"ldr %[cohort_byte], =" FIBER_C33S_PRIVATE_COHORT_KEY "\n\t"') |
                Set-Content -LiteralPath $header -Encoding ASCII -NoNewline
        }
        return $copy
    }
    foreach ($variant in @('literal-abs32','cmsis-caller')) {
        $copy = & $copySecure ('source-'+$variant) -Literal:($variant -eq 'literal-abs32')
        if ($variant -eq 'cmsis-caller') {
            $gateway = Join-Path $copy 'fiber_secure_context_gateway.c'
            $text = Get-Content -LiteralPath $gateway -Raw
            if ([regex]::Matches($text,'__builtin_arm_cmse_nonsecure_caller\(\)').Count -ne 4) { throw 'C33S copied caller anchor changed' }
            $text.Replace('__builtin_arm_cmse_nonsecure_caller()','cmse_nonsecure_caller()') |
                Set-Content -LiteralPath $gateway -Encoding ASCII -NoNewline
        }
        $objects = @{}
        foreach ($unit in @('gateway','identity','pool')) {
            $file = switch ($unit) {
                'gateway' { 'fiber_secure_context_gateway.c' }
                'identity' { 'fiber_secure_gateway.c' }
                'pool' { 'fiber_secure_context_pool.c' }
            }
            $objects[$unit] = & $compile (Join-Path $copy $file) "$variant-$unit"
        }
        $elf = & $link @($objects.gateway,$objects.identity,$objects.pool) $variant 'fiber_secure_context_gateway_v1_initialize' -Fiber
        $variants[$variant] = [ordered]@{Objects=$objects;Elf=$elf}
    }
    $isolatedReference = Join-Path $directory 'reference-init-only.o'
    $remove = @('SecureContext_AllocateContext','SecureContext_FreeContext','SecureContext_LoadContext','SecureContext_SaveContext') |
        ForEach-Object { '--remove-section=.text.'+$_ }
    & $run (Join-Path (Split-Path $compiler) 'arm-none-eabi-objcopy.exe') ($remove+@($Pair.ReferencePath,$isolatedReference))
    $referenceCpu = & $link @($isolatedReference) 'reference-cpu' 'SecureContext_Init'
    $referencePriority = & $link @($PriorityPair.ReferencePath) 'reference-priority' 'SecureInit_DePrioritizeNSExceptions'
    $original = (Get-Content -LiteralPath $source -Raw).Replace("`r`n","`n")
    $start = $original.IndexOf('uint32_t fiber_secure_context_gateway_v1_initialize(void)',[StringComparison]::Ordinal)
    $end = $original.IndexOf('uint32_t fiber_secure_context_gateway_v1_allocate(',[StringComparison]::Ordinal)
    if ($start -lt 0 -or $end -le $start) { throw 'C33S initializer mutation span changed' }
    $body = $original.Substring($start,$end-$start)
    $retain = 'FIBER_C33S_PRIVATE_COHORT_RETAIN();'
    if ([regex]::Matches($body,[regex]::Escape($retain)).Count -ne 1) { throw 'C33S initializer RETAIN anchor changed' }
    $mutants = @()
    foreach ($name in @('missing-retain','helper-only','before-preflight','after-commit')) {
        $changed = $body.Replace($retain,'')
        switch ($name) {
            'helper-only' { $changed = $body.Replace($retain,'fiber_secure_context_pool_c33s_v1_cohort_provider();') }
            'before-preflight' {
                $anchor = 'aircr_before = fiber_secure_contextSCB_AIRCR;'
                if ([regex]::Matches($changed,[regex]::Escape($anchor)).Count -ne 1) { throw 'C33S preflight anchor changed' }
                $changed = $changed.Replace($anchor,$anchor+"`n`t"+$retain)
            }
            'after-commit' {
                $pattern = 'fiber_secure_context_gateway_state =\s*fiber_secure_contextGATEWAY_INITIALIZING;'
                if ([regex]::Matches($changed,$pattern).Count -ne 1) { throw 'C33S commit anchor changed' }
                $changed = [regex]::Replace($changed,$pattern,{param($m) $m.Value+"`n`t"+$retain})
            }
        }
        $path = Join-Path $directory "mutant-$name.c"
        ($original.Substring(0,$start)+$changed+$original.Substring($end)) | Set-Content $path -Encoding ASCII
        $object = & $compile $path "mutant-$name"
        $elf = & $link @($object,$variants.normal.Objects.identity,$variants.normal.Objects.pool) "mutant-$name" 'fiber_secure_context_gateway_v1_initialize' -Fiber
        $mutants += [ordered]@{Name=$name;Object=$object;Elf=$elf}
    }
    foreach ($name in @('stale-layout-key','unexpected-helper')) {
        $copy = $original
        if ($name -eq 'stale-layout-key') {
            $anchor = '#include "fiber_secure_context_cohort.h"'
            if ([regex]::Matches($copy,[regex]::Escape($anchor)).Count -ne 1) { throw 'C33S stale-key include anchor changed' }
            $copy = $copy.Replace($anchor,$anchor+"`n#undef FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION`n"+
                '#define FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION 0x00010001u')
        } else {
            $changed = $body.Replace($retain,$retain+"`n`textern void fiber_c33s_cohort_unexpected_helper(void);`n"+
                "`tfiber_c33s_cohort_unexpected_helper();")
            $copy = $original.Substring(0,$start)+$changed+$original.Substring($end)
        }
        $path = Join-Path $directory "mutant-$name.c"
        $copy | Set-Content $path -Encoding ASCII
        $object = & $compile $path "mutant-$name"
        # Deliberately unresolved object controls: exact dependency admission
        # must reject these before a provider could hide the mismatch at link.
        $mutants += [ordered]@{Name=$name;Object=$object}
    }
    foreach ($form in @('movw-movt','abs32')) {
        foreach ($fault in @('wrong-key','extra-provider-call','unexpected-query-helper')) {
            $name = "$form-$fault"
            $copy = & $copySecure ('source-mutant-'+$name) -Literal:($form -eq 'abs32')
            $header = Join-Path $copy 'fiber_secure_context_cohort.h'
            if ($fault -eq 'wrong-key') {
                $text = Get-Content -LiteralPath $header -Raw
                $anchor = '"fiber_secure_context_cohort_c33s_g1"'
                if ([regex]::Matches($text,[regex]::Escape($anchor)).Count -ne 1) { throw 'C33S wrong-key control anchor changed' }
                $text.Replace($anchor,'"fiber_secure_context_cohort_c33s_g1_wrong"') |
                    Set-Content -LiteralPath $header -Encoding ASCII -NoNewline
            } else {
                $gateway = Join-Path $copy 'fiber_secure_context_gateway.c'
                $text = Get-Content -LiteralPath $gateway -Raw
                $pattern = '(?m)^uint32_t fiber_secure_context_gateway_v1_abi_version\(void\)\r?\n\{[^{}]*^\}'
                $matches = [regex]::Matches($text,$pattern)
                if ($matches.Count -ne 1 -or [regex]::Matches($matches[0].Value,[regex]::Escape($retain)).Count -ne 1) {
                    throw 'C33S extra-provider control anchor changed'
                }
                $extra = if ($fault -eq 'extra-provider-call') {
                    "`n`tfiber_secure_context_pool_c33s_v1_cohort_provider();"
                } else {
                    "`n`textern void fiber_c33s_query_unexpected_helper(void);`n`tfiber_c33s_query_unexpected_helper();"
                }
                $text.Replace($matches[0].Value,$matches[0].Value.Replace($retain,$retain+$extra)) |
                    Set-Content -LiteralPath $gateway -Encoding ASCII -NoNewline
            }
            $object = & $compile (Join-Path $copy 'fiber_secure_context_gateway.c') ('mutant-'+$name)
            $mutants += [ordered]@{Name=$name;Object=$object}
        }
    }
    foreach ($fault in @('missing-high-half','wrong-high-half','mixed-materialization')) {
        $copy = & $copySecure ('source-mutant-'+$fault)
        $header = Join-Path $copy 'fiber_secure_context_cohort.h'
        $text = Get-Content -LiteralPath $header -Raw
        $high = '"movt %[cohort_byte], #:upper16:" FIBER_C33S_PRIVATE_COHORT_KEY "\n\t"'
        if ([regex]::Matches($text,[regex]::Escape($high)).Count -ne 1) { throw 'C33S high-half control anchor changed' }
        $replacement = if ($fault -eq 'missing-high-half') { '""' } elseif ($fault -eq 'wrong-high-half') {
            $high.Replace('FIBER_C33S_PRIVATE_COHORT_KEY','FIBER_C33S_PRIVATE_COHORT_KEY "_wrong_high"')
        } else {
            $high+' "ldr %[cohort_byte], =" FIBER_C33S_PRIVATE_COHORT_KEY "\n\t"'
        }
        $text.Replace($high,$replacement) | Set-Content -LiteralPath $header -Encoding ASCII -NoNewline
        $object = & $compile (Join-Path $copy 'fiber_secure_context_gateway.c') ('mutant-'+$fault)
        $mutants += [ordered]@{Name=$fault;Object=$object}
    }
    $manifest = Join-Path $directory 'inputs.json'
    [ordered]@{Variants=$variants;Mutants=$mutants;Optimization=$Optimization;Exports=$exports;
        OriginalObject=$Pair.FiberPath;ReferenceOriginal=$Pair.ReferencePath;ReferenceIsolated=$isolatedReference;
        ReferenceCpu=$referenceCpu;ReferencePriority=$referencePriority;
        InitProof=(Join-Path $BuildRoot 'C55SINIT\trace_init.py')} |
        ConvertTo-Json -Depth 7 | Set-Content $manifest -Encoding ASCII
    $proof = Join-Path $directory 'trace_cohort.py'
    @'
"""Actual CM33 C bodies and real pool; explicit CPU/AIRCR/CMSE-return doubles.
Not physical SG/exception/CONTROL qualification, archive/LTO or pool-fault proof.
"""
import sys
if sys.flags.optimize or not __debug__:
    raise SystemExit('C33SCOHORT requires Python optimization disabled')
import importlib.util, json, struct
from pathlib import Path
inputs=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig'))
spec=importlib.util.spec_from_file_location('c33s_generic_arm_support',inputs['InitProof'])
base=importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
check,Failure,arm=base.check,base.ProofFailure,base.arm
HELPER='fiber_secure_context_pool_c33s_v1_cohort_provider'
FACTS=(('p',0x43333353),('l',0x00020001),('f',0x8A),('i',1),('c',1),('r',1),
       ('n',3),('b',256),('a',8),('w',2),('s',8),('v',0xFEF5EDA5))
KEY='fiber_secure_context_cohort_c33s_g1'+''.join('_'+tag+'_'+str(v>>16)+'_'+str(v&65535) for tag,v in FACTS)
STALE_KEY='fiber_secure_context_cohort_c33s_g1'+''.join('_'+tag+'_'+str(v>>16)+'_'+str(v&65535)
    for tag,v in ((tag,0x00010001 if tag=='l' else v) for tag,v in FACTS))
COHORT={HELPER,KEY}
INIT='fiber_secure_context_gateway_v1_initialize'
CAPACITY=['fiber_secure_context_gateway_v1_'+n for n in ('abi_version','stack_alignment','max_stack_bytes','max_contexts')]
IDENTITY=['fiber_secure_gateway_v1_'+n for n in ('abi_version','context_port_id','context_layout_version','context_feature_mask')]
GATEWAY={'fiber_secure_context_pool_boot_initialize','fiber_secure_context_pool_allocate','fiber_secure_context_pool_lookup_owned'}|COHORT
PRIVATE={HELPER,'fiber_secure_context_pool_boot_initialize','fiber_secure_context_pool_allocate','fiber_secure_context_pool_lookup_owned',
         'fiber_secure_context_pool_fail_closed','fiber_secure_context_pool_clear_record','fiber_secure_context_pool_clear_stack',
         'fiber_secure_context_pool_record_is_free','fiber_secure_context_pool_write_stack_seal',
         'fiber_secure_context_pool_stack_seal_is_valid','fiber_secure_context_pool_record_is_valid',
         'fiber_secure_context_gateway_is_runtime_exception'}

def retained(path,name):
    rel=base.function_relocations(path,name)
    binding=sorted((t,n) for t,n in rel if n==HELPER or n.startswith('fiber_secure_context_cohort_'))
    literal=sorted([(10,HELPER),(2,KEY)])
    immediate=sorted([(10,HELPER),(47,KEY),(48,KEY)])
    check(binding in (literal,immediate),'missing exact C33S call/key relocations',name)
    if name!=INIT:
        check(sorted(rel)==binding,'unexpected C33S query relocations',name)

def gateway_dependencies(path):
    actual=base.dependencies(path)
    check(actual==GATEWAY,'C33S gateway exact dependencies changed',str(sorted(actual^GATEWAY)))

def dependency_facts(path):
    return dict(Undefined=sorted(base.dependencies(path)),Consumers={name:base.function_relocations(path,name)
        for name in [INIT]+CAPACITY})

def definitions(path):
    image=base.Image(path)
    check({n for n in image.symbols if n.startswith('__acle_se_')}=={'__acle_se_'+n for n in inputs['Exports']},
          'C33S twelve-entry surface changed')
    check({n for n in image.symbols if n.startswith('fiber_secure_context_cohort_')}=={KEY},'C33S numeric cohort key mismatch')
    key,helper=image.symbols[KEY],image.symbols[HELPER]
    check(key['kind']=='STT_OBJECT' and key['bind']=='STB_GLOBAL' and key['size']==1,'C33S key not one strong byte')
    check(helper['kind']=='STT_FUNC' and helper['bind']=='STB_GLOBAL' and '__acle_se_'+HELPER not in image.symbols,
          'C33S ordinary C provider changed')
    with Path(path).open('rb') as stream:
        elf=base.ELFFile(stream)
        section=elf.get_section(key['section'])
        offset=key['value']-section['sh_addr']
        check(section['sh_flags']&2 and not section['sh_flags']&5 and section.data()[offset:offset+1]==b'\x01',
              'C33S key not allocated read-only value one')
        pool=elf.get_section_by_name('.fiber_secure_context_pool')
        check(pool['sh_type']=='SHT_NOBITS' and pool['sh_size']==872,'C33S retained pool geometry changed')
    start=image.address(HELPER)
    code=[(op,args) for a,(_,op,args) in sorted(image.instructions.items()) if start<=a<start+helper['size']]
    check(code and code[0]==('bx','lr') and all(op=='nop' for op,_ in code[1:]),'C33S provider acquired runtime work',str(code))
    allowed={s['value']&~1 for n,s in image.symbols.items() if n in PRIVATE and s['kind']=='STT_FUNC'}
    calls=0
    for _,op,args in image.instructions.values():
        check(not op.startswith('v'),'C33S unexpected FP/MVE instruction',op+' '+args)
        check(op not in ('blx','blxns'),'C33S indirect helper call')
        if op in ('bl','bl.w'):
            check(int(args.split()[0],16) in allowed,'C33S unexpected direct helper',args)
            calls+=1
    check(calls>=9,'C33S retained C calls missing')
    return calls

class Machine(base.Machine):
    def __init__(self,path,control_read=None,**kwargs):
        super().__init__(path,**kwargs)
        self.cohort_provider=self.image.symbols.get(HELPER,{}).get('value',0)&~1
        self.cohort_key=self.image.symbols.get(KEY,{}).get('value',0)
        self.control_read=control_read
    def code(self,uc,address,size,data):
        decoded=self.image.instructions.get(address)
        if decoded:
            length,op,args=decoded
            if op=='msr' and args=='CPSR_fs, lr':
                check(self.image.encoding[address]==(0xF38E,0x8C00),'C33S CMSE flags encoding changed')
                # Compiler return hygiene only, not a banked CONTROL write.
                self.trace.append(('cmse-flags',))
                self.skip(address,length)
                return
            if op=='mrs' and args.split(',')[1].strip()=='CONTROL' and self.control_read is not None:
                uc.reg_write(base.REGS[args.split(',')[0].strip()],self.control_read)
                self.trace.append(('read','CONTROL',self.control_read))
                self.skip(address,length)
                return
        super().code(uc,address,size,data)

def rejected(machine,name):
    check(machine.call(INIT)==0 and not base.effects(machine.trace),'C33S init preflight rejection lost',name)
    check(not base.cohort_events(machine.trace),'C33S rejected preflight reached cohort',name)

def init_checks(path):
    for low in (0,0x80,0xDFFF):
        for control in (2,6,0x80000002):
            m=Machine(path,aircr=0xFA050000|low,control_read=control)
            check(m.call(INIT)==1,'C33S valid masked-CONTROL init rejected')
            write=0x05FA0000|low|0x4000
            check(base.effects(m.trace)==[('state-write',base.INITIALIZING),('aircr-write',write),
                ('write','PSPLIM',0),('write','PSP',0),('pool',),('write','CONTROL',2),('state-write',base.READY)],
                'C33S init write/order changed',str(m.trace))
            check(base.cohort_events(m.trace)==[('cohort-provider',),('cohort-read',1)],'C33S init cohort event count changed')
            try:
                base.ordered(m.trace,[('aircr-read',0xFA050000|low),('cohort-provider',),('cohort-read',1),
                    ('state-write',base.INITIALIZING),('dsb',),('isb',),('state-read',base.INITIALIZING),
                    ('aircr-write',write),('dsb',),('isb',),('aircr-read',0xFA050000|(low|0x4000)),
                    ('write','PSPLIM',0),('write','PSP',0),('dsb',),('isb',),('read','PSPLIM',0),('read','PSP',0),
                    ('pool',),('write','CONTROL',2),('isb',),('read','CONTROL',control),
                    ('state-write',base.READY),('dsb',),('isb',),('state-read',base.READY)])
            except Failure as exc: raise Failure('C33S cohort/precommit order changed',str(exc)) from exc
            rejected(m,'repeat')
    for ipsr in (0,1,3,14,15,16): rejected(Machine(path,ipsr=ipsr),'IPSR-'+str(ipsr))
    rejected(Machine(path,nonsecure=False),'Secure caller')
    rejected(Machine(path,aircr=0xFA052080),'BFHFNMINS')
    for marker in (base.INITIALIZING,base.READY,1,0xFFFFFFFF):
        m=Machine(path)
        m.put(m.state,marker)
        rejected(m,'marker-'+str(marker))
    for control in (0,1,3,0xFFFFFFFF):
        m=Machine(path,control_read=control)
        check(m.call(INIT)==0 and m.get(m.state)==base.INITIALIZING,'C33S masked CONTROL failure changed')
        rejected(m,'partial failure retry')

def query_checks(path):
    for name,value in zip(IDENTITY+CAPACITY,(1,0x43333353,0x00020001,0x8A,1,8,256,3)):
        m=Machine(path,ipsr=0)
        before=bytes(m.uc.mem_read(0x30000000,0x18000))
        cpu=dict(m.cpu)
        check(m.call(name)==value,'C33S query numeric result changed',name)
        check(m.trace==[('cohort-provider',),('cohort-read',1),('cmse-flags',)],'C33S query acquired extra effects',name)
        check(m.cpu==cpu and bytes(m.uc.mem_read(0x30000000,0x18000))==before,'C33S query changed CPU/pool/BSS',name)

def reference_checks():
    base.reference_identity(inputs['ReferenceOriginal'],inputs['ReferenceIsolated'])
    for low in (0,0x80,0xDFFF):
        m=Machine(inputs['ReferencePriority'],aircr=0xFA050000|low)
        m.call('SecureInit_DePrioritizeNSExceptions')
        check([e for e in m.trace if e[0]=='aircr-write']==[('aircr-write',0x05FA0000|low|0x4000)],'pinned CM33 priority changed')
    m=Machine(inputs['ReferenceCpu'])
    # This existing reference profile retains the pinned default eight records,
    # unlike Fiber's explicitly selected three. Only CPU/clear order is paired.
    record=m.image.address('xSecureContexts')
    check(m.image.symbols['xSecureContexts']['size']==128,'pinned CM33 default record geometry changed')
    m.uc.mem_write(record,b'\xA5'*128)
    m.call('SecureContext_Init')
    check([e for e in m.trace if e[0]=='write']==[('write','PSPLIM',0),('write','PSP',0),('write','CONTROL',2)],
          'pinned CM33 scalar init order changed')
    check(bytes(m.uc.mem_read(record,128))==b'\0'*128,'pinned CM33 record clear changed')

def main():
    calls={}
    facts={variant:dependency_facts(item['Objects']['gateway']) for variant,item in inputs['Variants'].items()}
    facts['original-pinned-pair']=dependency_facts(inputs['OriginalObject'])
    (Path(sys.argv[1]).parent/'dependency-facts.json').write_text(json.dumps(facts,indent=2)+'\n')
    for variant,item in inputs['Variants'].items():
        objects=item['Objects']
        gateway_dependencies(objects['gateway'])
        check(base.dependencies(objects['identity'])==COHORT,'C33S identity exact dependencies changed',variant)
        check(not base.dependencies(objects['pool']),'C33S pool acquired helper dependency',variant)
        for name in [INIT]+CAPACITY: retained(objects['gateway'],name)
        for name in IDENTITY: retained(objects['identity'],name)
        for op in ('allocate','load','save'):
            rel=base.function_relocations(objects['gateway'],'fiber_secure_context_gateway_v1_'+op)
            check(not any(n==HELPER or n.startswith('fiber_secure_context_cohort_') for _,n in rel),'C33S hot transfer acquired cohort',op)
        calls[variant]=definitions(item['Elf'])
        query_checks(item['Elf'])
        init_checks(item['Elf'])
    gateway_dependencies(inputs['OriginalObject'])
    reference_checks()
    expected={'missing-retain':'missing exact C33S call/key relocations','helper-only':'missing exact C33S call/key relocations',
              'before-preflight':'C33S rejected preflight reached cohort','after-commit':'C33S cohort/precommit order changed',
              'stale-layout-key':'C33S gateway exact dependencies changed','unexpected-helper':'C33S gateway exact dependencies changed'}
    for form in ('movw-movt','abs32'):
        for fault in ('wrong-key','extra-provider-call','unexpected-query-helper'):
            expected[form+'-'+fault]=('unexpected C33S query relocations' if fault=='unexpected-query-helper'
                                     else 'missing exact C33S call/key relocations')
    expected.update({'missing-high-half':'missing exact C33S call/key relocations',
                     'wrong-high-half':'missing exact C33S call/key relocations',
                     'mixed-materialization':'missing exact C33S call/key relocations'})
    check({m['Name'] for m in inputs['Mutants']}==set(expected),'C33S mutant inventory changed')
    killed=[]
    for mutant in inputs['Mutants']:
        if mutant['Name']=='stale-layout-key':
            check(base.dependencies(mutant['Object'])==(GATEWAY-{KEY})|{STALE_KEY},'C33S stale-key negative shape changed')
            rel=base.function_relocations(mutant['Object'],INIT)
            check(sorted((t,n) for t,n in rel if n==HELPER or n.startswith('fiber_secure_context_cohort_'))
                  in (sorted([(10,HELPER),(2,STALE_KEY)]),sorted([(10,HELPER),(47,STALE_KEY),(48,STALE_KEY)])),
                  'C33S stale-key negative callsite changed')
        elif mutant['Name']=='unexpected-helper':
            check(base.dependencies(mutant['Object'])==GATEWAY|{'fiber_c33s_cohort_unexpected_helper'},
                  'C33S extra-helper negative shape changed')
            check(base.function_relocations(mutant['Object'],INIT).count((10,'fiber_c33s_cohort_unexpected_helper'))==1,
                  'C33S extra-helper negative callsite changed')
        try:
            if mutant['Name'] in ('missing-retain','helper-only'): retained(mutant['Object'],INIT)
            elif mutant['Name'] in ('missing-high-half','wrong-high-half','mixed-materialization') or mutant['Name'].startswith(('movw-movt-','abs32-')):
                retained(mutant['Object'],CAPACITY[0])
            elif mutant['Name'] in ('stale-layout-key','unexpected-helper'): gateway_dependencies(mutant['Object'])
            else: init_checks(mutant['Elf'])
        except Failure as exc:
            check(exc.code==expected[mutant['Name']],'C33S mutant failed for unintended reason',mutant['Name']+': '+str(exc))
            killed.append(dict(Name=mutant['Name'],Diagnostic=str(exc)))
        else: raise RuntimeError('C33S cohort mutant survived: '+mutant['Name'])
    result=dict(Optimization=inputs['Optimization'],ArmCalls=base.COUNTS['calls'],ActualQueryCalls=8*len(inputs['Variants']),
        ColdConsumers=9,Key=KEY,Facts=FACTS,StaticCalls=calls,CompiledMutants=len(killed),Killed=killed,Scope=__doc__)
    (Path(sys.argv[1]).parent/'trace-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS C33SCOHORT: 9 cold edges, '+str(result['ActualQueryCalls'])+' real query calls, '+str(base.COUNTS['calls'])+
          ' ARM calls, '+str(len(killed))+' compiled mutants; actual pinned CM33 init, void pool, masked CONTROL')

if __name__=='__main__': main()
'@ | Set-Content $proof -Encoding ASCII
    $oldPath = $env:PYTHONPATH
    try {
        $modules = $PythonModules
        if (-not $modules) { $modules = Join-Path ([IO.Path]::GetTempPath()) 'fiber-classic-audit-python' }
        $env:PYTHONPATH = $modules+[IO.Path]::PathSeparator+$oldPath
        & $run $Python @($proof,$manifest)
    } finally { $env:PYTHONPATH = $oldPath }
    & $assertInputs
    $evidenceDirectories = @($directory)+@('ALLOCATOR','DEPRIORITIZE','INITIALIZE','LOAD','SAVE' |
        ForEach-Object { Join-Path $BuildRoot ('ARM_CM33_SECURE_CONTEXT_'+$_) })
    [ordered]@{Optimization=$Optimization;Sources=$Pair.InitSourceHashes;ReferenceCommit=$ExpectedFreeRtosCommit;
        Compiler=[ordered]@{Path=$compiler;Sha256=(Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash};
        UpstreamReceipt=[ordered]@{Path=$upstreamPath;Sha256=(Get-FileHash -LiteralPath $upstreamPath -Algorithm SHA256).Hash};
        Artifacts=@(Get-ChildItem -LiteralPath $evidenceDirectories -File -Recurse |
            Where-Object {$_.Name -ne 'artifacts.json'} | ForEach-Object {
                [ordered]@{Path=$_.FullName;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
            })} | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $directory 'artifacts.json') -Encoding ASCII
}

function Assert-Cm33fMpuRunningParity {
    $directory = Join-Path $BuildRoot 'C3FP-RUNNING'
    if (Test-Path -LiteralPath $directory) {
        throw "C3FP running evidence already exists; use a fresh -BuildRoot: $directory"
    }
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $fixture = Join-Path $RepoRoot 'tools\fixtures\cm33f_mpu_running_parity'
    $profile = Join-Path $RepoRoot 'fiber\port\ARM_CM33F_MPU\non_secure'
    $source = Join-Path $profile 'fiber_port_pendsv.c'
    $referenceDir = Join-Path $kernel 'portable\GCC\ARM_CM33_NTZ\non_secure'
    $referenceSource = Join-Path $referenceDir 'portasm.c'
    $checker = Join-Path $fixture 'check.py'
    foreach ($path in @($source, $referenceSource, $checker, (Join-Path $fixture 'mutants.ps1'))) {
        if (-not (Test-Path -LiteralPath $path)) { throw "Missing C3FP running parity input: $path" }
    }
    foreach ($id in @('FAP-C3FP-RUNNING-TRANSFER', 'FAP-C3FP-RUNNING-HARDENING', 'FAP-C3FP-RUNNING-STAGED')) {
        if ($ledger -notmatch [regex]::Escape($id)) { throw "C3FP running difference missing from ledger: $id" }
    }
    . (Join-Path $fixture 'mutants.ps1')
    $commands = Join-Path $directory 'commands.log'
    function Invoke-C3fpProof {
        param([string]$Program, [string[]]$Arguments, [string]$Log, [switch]$AllowFailure)
        Add-Content -LiteralPath $commands -Encoding ASCII -Value (ConvertTo-Json -Compress -InputObject (@($Program)+$Arguments))
        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $lines = @(& $Program @Arguments 2>&1 | ForEach-Object { "$_" })
            $code = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $saved }
        $output = $lines -join "`n"
        if ($Log) { Set-Content -LiteralPath $Log -Value $output -Encoding ASCII }
        if ($output) { Add-Content -LiteralPath $commands -Value $output -Encoding ASCII }
        if ($code -ne 0 -and -not $AllowFailure) {
            throw "C3FP running command failed ($code); $commands`n$(($lines | Select-Object -Last 8) -join "`n")"
        }
        return [pscustomobject]@{ExitCode=$code; Output=$output}
    }
    function Write-C3fpJson {
        param([string]$Path, [object]$Value)
        ConvertTo-Json -Depth 12 -InputObject $Value | Set-Content -LiteralPath $Path -Encoding ASCII
    }
    function Test-C3fpExactRejection {
        param([object]$Result, [string]$Expected)
        return $Result.ExitCode -eq 1 -and $Result.Output -ceq $Expected
    }
    function Test-C3fpCodeRejection {
        param([object]$Result, [string]$Code)
        return $Result.ExitCode -eq 1 -and $Result.Output -cmatch ('^REJECT:'+ [regex]::Escape($Code) +':[^\r\n]+$')
    }
    $readelf = Join-Path $toolDir 'arm-none-eabi-readelf.exe'
    $paths = @($PSCommandPath, $ledgerPath, $compiler, $objdump, $readelf)
    foreach ($tool in @('cc1', 'as')) {
        $query = Invoke-C3fpProof $compiler @("-print-prog-name=$tool")
        $paths += (Resolve-Path -LiteralPath $query.Output.Trim()).Path
    }
    $query = Invoke-C3fpProof $compiler @('-print-file-name=include')
    $compilerHeaders = (Resolve-Path -LiteralPath $query.Output.Trim()).Path
    foreach ($root in @($compilerHeaders, (Join-Path (Split-Path $toolDir) 'arm-none-eabi\include'))) {
        $paths += @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.h' -File | Select-Object -ExpandProperty FullName)
    }
    foreach ($root in @($RepoRoot, (Join-Path $RepoRoot 'context'),
            (Join-Path $RepoRoot 'fiber'), (Join-Path $RepoRoot 'fiber\port'),
            $profile, $referenceDir, (Join-Path $kernel 'include'), $cmsis, $configDir, $fixture)) {
        $paths += @(Get-ChildItem -LiteralPath $root -File | Where-Object {
            $_.Extension -in @('.h', '.c', '.ld', '.py', '.ps1', '.md')
        } | Select-Object -ExpandProperty FullName)
    }
    $sourceInputs = @($paths | Sort-Object -Unique | ForEach-Object {
        [pscustomobject]@{Path=$_; Sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
    })
    $documentationDirectory = Join-Path $directory 'documentation'
    New-Item -ItemType Directory -Path $documentationDirectory | Out-Null
    $documentation = @()
    $inputs = @($sourceInputs | ForEach-Object {
        if ([IO.Path]::GetExtension($_.Path) -ne '.md') { $_; return }
        # Documentation is historical evidence, not a live code dependency.
        # Keep its origin, but make the receipt hash the exact retained bytes.
        $snapshot = Join-Path $documentationDirectory ('{0:D3}-{1}' -f $documentation.Count, [IO.Path]::GetFileName($_.Path))
        Copy-Item -LiteralPath $_.Path -Destination $snapshot
        if ((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -ne $_.Sha256) {
            throw "C3FP documentation changed while snapshotting: $($_.Path)"
        }
        $record = [pscustomobject]@{Path=$snapshot; Sha256=$_.Sha256; SourcePath=$_.Path; Role='DocumentationSnapshot'}
        $documentation += $record
        $record
    })
    Write-C3fpJson (Join-Path $directory 'documentation.json') $documentation
    Write-C3fpJson (Join-Path $directory 'inputs.before.json') $inputs
    $runs, $mutantReceipts, $controls = @(), @(), @()
    $success = $false
    try {
        Invoke-C3fpProof $compiler @('--version') -Log (Join-Path $directory 'compiler.txt') | Out-Null
        Invoke-C3fpProof $Python @('-B', '-c', 'import sys; print(sys.executable); print(sys.version)') `
            -Log (Join-Path $directory 'python.txt') | Out-Null
        $fiberText = Get-Content -LiteralPath $source -Raw
        $svcText = Get-Content -LiteralPath (Join-Path $profile 'fiber_port_svc.c') -Raw
        $referenceText = Get-Content -LiteralPath $referenceSource -Raw
        foreach ($abi in @('hard', 'softfp')) {
            foreach ($regions in @(8, 16)) {
                $name = "$abi-r$regions"
                $root = Join-Path $directory $name
                New-Item -ItemType Directory -Path $root -Force | Out-Null
                Write-CmsisMainHeader $root 'core_cm33.h' 1 1 1 1 1
                $common = @('-mcpu=cortex-m33', '-mthumb', '-mfpu=fpv5-sp-d16', "-mfloat-abi=$abi",
                    '-std=gnu11', $Optimization, '-g0', '-ffreestanding', '-fno-builtin', '-fno-common',
                    '-ffunction-sections', '-fdata-sections', '-save-temps=obj', '-MMD')
                $fiberFlags = $common + @('-Wall', '-Wextra', '-Wundef', '-Werror',
                    '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_ARMV8M_MAINLINE=1',
                    '-DFIBER_SCHEDULER_BASEPRI=128',
                    "-DFIBER_PORT_CM33F_MPU_TOTAL_REGIONS=$regions", "-I$root", "-I$profile",
                    "-I$(Join-Path $RepoRoot 'fiber\port')", "-I$(Join-Path $RepoRoot 'fiber')", "-I$RepoRoot", "-I$cmsis")
                $referenceFlags = $common + @('-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1',
                    '-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1', "-DFIBER_FREERTOS_PARITY_MPU_REGIONS=$regions",
                    "-I$configDir", "-I$(Join-Path $kernel 'include')", "-I$referenceDir")
                $fiberObject = Join-Path $root 'pendsv.o'
                $referenceObject = Join-Path $root 'reference.o'
                Invoke-C3fpProof $compiler ($fiberFlags + @('-c', $source, '-o', $fiberObject)) | Out-Null
                Invoke-C3fpProof $compiler ($referenceFlags + @('-c', $referenceSource, '-o', $referenceObject)) | Out-Null
                foreach ($object in @($fiberObject, $referenceObject)) {
                    Invoke-C3fpProof $objdump @('-dr', $object) -Log ($object+'.dis') | Out-Null
                    Invoke-C3fpProof $readelf @('-A', '-h', '-S', '-s', '-r', '-W', $object) -Log ($object+'.elf.txt') | Out-Null
                }
                # Compile the evolving real SVC as well; its first-start proof
                # and the constructor row remain owned by their existing gate.
                $svcObject = Join-Path $root 'svc.o'
                Invoke-C3fpProof $compiler ($fiberFlags + @('-c', (Join-Path $profile 'fiber_port_svc.c'), '-o', $svcObject)) | Out-Null
                Invoke-C3fpProof $objdump @('-dr', $svcObject) -Log ($svcObject+'.dis') | Out-Null
                $manifest = [ordered]@{Fiber=$fiberObject; FiberDisassembly=($fiberObject+'.dis');
                    Reference=$referenceObject; ReferenceDisassembly=($referenceObject+'.dis');
                    Svc=$svcObject; SvcDisassembly=($svcObject+'.dis');
                    Regions=$regions; Receipt=(Join-Path $root 'result.json')}
                $manifestPath = Join-Path $root 'check.json'
                Write-C3fpJson $manifestPath $manifest
                $result = Invoke-C3fpProof $Python @('-B', $checker, $manifestPath) -Log (Join-Path $root 'check.log')
                $runs += [ordered]@{Name=$name; Manifest=$manifestPath; Result=$result.Output}
                foreach ($mutation in @(Get-Cm33fRunningMutants)) {
                    $isReference = $mutation.ContainsKey('Reference') -and $mutation.Reference
                    $isSvc = $mutation.ContainsKey('Svc') -and $mutation.Svc
                    $text = if ($isReference) { $referenceText } elseif ($isSvc) { $svcText } else { $fiberText }
                    if ($isSvc -and -not $mutation.ContainsKey('Code')) {
                        # Keep the cold first-start prefix outside running-SVC
                        # mutation anchors; its existing proof is unchanged.
                        $start = $text.IndexOf('void SVC_Handler(void)', [StringComparison]::Ordinal)
                        if ($start -lt 0) { throw 'C3FP running SVC mutation body missing' }
                        $prefix = $text.Substring(0, $start)
                        $changed = $prefix + (New-Cm33fRunningMutation $text.Substring($start) $mutation)
                    }
                    else { $changed = New-Cm33fRunningMutation $text $mutation }
                    $copy = Join-Path $root ("mutant-"+$mutation.Name+'.c')
                    Set-Content -LiteralPath $copy -Value $changed -Encoding ASCII
                    $object = Join-Path $root ("mutant-"+$mutation.Name+'.o')
                    $flags = if ($isReference) { $referenceFlags } else { $fiberFlags }
                    Invoke-C3fpProof $compiler ($flags + @('-c', $copy, '-o', $object)) | Out-Null
                    Invoke-C3fpProof $objdump @('-dr', $object) -Log ($object+'.dis') | Out-Null
                    $negative = [ordered]@{}
                    foreach ($key in $manifest.Keys) { $negative[$key] = $manifest[$key] }
                    $side = if ($isReference) { 'Reference' } elseif ($isSvc) { 'Svc' } else { 'Fiber' }
                    $negative[$side] = $object
                    $negative[$side+'Disassembly'] = $object+'.dis'
                    $negative.Receipt = $object+'.unexpected-pass.json'
                    $negativePath = $object+'.json'
                    Write-C3fpJson $negativePath $negative
                    $rejected = Invoke-C3fpProof $Python @('-B', $checker, $negativePath) -Log ($object+'.check.log') -AllowFailure
                    $expectedCode = if ($isReference) { 'REFERENCE' } elseif ($isSvc) { 'SVC' } else { 'PENDSV' }
                    if ($mutation.ContainsKey('Code')) { $expectedCode = $mutation.Code }
                    $allowed = if ($mutation.Name -in @('unknown-encoding', 'unknown-coprocessor')) { @('DECODE') } else { @($expectedCode) }
                    $valid = $false
                    foreach ($code in $allowed) {
                        if (Test-C3fpCodeRejection $rejected $code) { $valid = $true }
                    }
                    if (-not $valid) { throw "C3FP mutant $($mutation.Name) survived or failed for unintended reason: $($rejected.Output)" }
                    $mutantReceipts += [ordered]@{Configuration=$name; Name=$mutation.Name; Manifest=$negativePath; Diagnostic=$rejected.Output}
                }
                if ($controls.Count -eq 0) {
                    $diagnostic = 'REJECT:PYTHON:optimization is unsupported'
                    foreach ($flag in @('-O', '-OO')) {
                        $control = Invoke-C3fpProof $Python @('-B', $flag, $checker, $manifestPath) -AllowFailure
                        if (-not (Test-C3fpExactRejection $control $diagnostic)) { throw "C3FP Python $flag guard failed: $($control.Output)" }
                        $controls += $flag
                    }
                    $oldOptimize = $env:PYTHONOPTIMIZE
                    try {
                        $env:PYTHONOPTIMIZE = '1'
                        $control = Invoke-C3fpProof $Python @('-B', $checker, $manifestPath) -AllowFailure
                        if (-not (Test-C3fpExactRejection $control $diagnostic)) { throw 'C3FP Python environment guard failed' }
                        $controls += 'PYTHONOPTIMIZE=1'
                    }
                    finally { $env:PYTHONOPTIMIZE = $oldOptimize }
                    foreach ($level in @(1, 2)) {
                        $code = "from pathlib import Path; import sys; p=sys.argv[1]; exec(compile(Path(p).read_text(),p,'exec',optimize=$level),{'__name__':'compiled_import'})"
                        $control = Invoke-C3fpProof $Python @('-B', '-c', $code, $checker) -AllowFailure
                        if (-not (Test-C3fpExactRejection $control $diagnostic)) { throw 'C3FP compiled-import optimization guard failed' }
                        $controls += "compiled-import-$level"
                    }
                    $counterfeit = Invoke-C3fpProof $Python @('-B', '-c', "raise RuntimeError('$diagnostic')") -AllowFailure
                    if (Test-C3fpExactRejection $counterfeit $diagnostic) { throw 'C3FP diagnostic classifier accepted traceback counterfeit' }
                    $controls += 'RuntimeError-counterfeit-rejected'
                    $counterfeit = Invoke-C3fpProof $Python @('-B', '-c', "raise RuntimeError('REJECT:PENDSV:counterfeit')") -AllowFailure
                    if (Test-C3fpCodeRejection $counterfeit 'PENDSV') { throw 'C3FP mutant classifier accepted traceback counterfeit' }
                    $controls += 'mutant-RuntimeError-counterfeit-rejected'
                    $guardSource = Get-Content -LiteralPath $checker -Raw
                    $guardFrom = 'raise SystemExit("REJECT:PYTHON:optimization is unsupported")'
                    $guardTo = 'raise RuntimeError("REJECT:PYTHON:optimization is unsupported")'
                    if ([regex]::Matches($guardSource, [regex]::Escape($guardFrom)).Count -ne 1) { throw 'C3FP guard counterfeit anchor changed' }
                    $guardCopy = Join-Path $directory 'counterfeit-guard.py'
                    Set-Content -LiteralPath $guardCopy -Value $guardSource.Replace($guardFrom, $guardTo) -Encoding ASCII
                    $counterfeit = Invoke-C3fpProof $Python @('-B', '-O', $guardCopy, $manifestPath) -AllowFailure
                    if (Test-C3fpExactRejection $counterfeit $diagnostic) { throw 'C3FP classifier accepted SystemExit-to-RuntimeError counterfeit' }
                    $controls += 'actual-guard-RuntimeError-counterfeit-rejected'
                }
                Write-Host "PASS C3FP auxiliary running $Optimization $name (33 compiled mutants)"
            }
        }
        $success = $true
    }
    finally {
        # Live originals, including every document, remain frozen during the
        # run. Also verify that none of the retained snapshot bytes changed.
        $drift = @((@($sourceInputs) + @($documentation)) | Where-Object {
            -not (Test-Path -LiteralPath $_.Path) -or (Get-FileHash -LiteralPath $_.Path -Algorithm SHA256).Hash -ne $_.Sha256
        })
        Write-C3fpJson (Join-Path $directory 'inputs.drift.json') $drift
        Write-C3fpJson (Join-Path $directory 'status.json') ([ordered]@{Status= $(if ($success -and $drift.Count -eq 0) { 'PASS' } else { 'INCOMPLETE' });
            RuntimeProfileAdded=$false; Optimization=$Optimization; SourceDrift=$drift.Count;
            DocumentationSnapshotCount=$documentation.Count; Configurations=$runs; Mutants=$mutantReceipts; Controls=$controls})
        if ($drift.Count) { throw "C3FP running parity inputs changed during run; no qualification: $directory" }
    }
    $artifactPrefix = [IO.Path]::GetFullPath($directory).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $artifacts = @(Get-ChildItem -LiteralPath $directory -Recurse -File | Where-Object { $_.Name -ne 'artifacts.json' } | ForEach-Object {
        if (-not $_.FullName.StartsWith($artifactPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "C3FP artifact escaped its evidence directory: $($_.FullName)"
        }
        [ordered]@{Path=$_.FullName; Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    Write-C3fpJson (Join-Path $directory 'artifacts.json') ([ordered]@{Status='PASS'; ReferenceCommit=$ExpectedFreeRtosCommit;
        Optimization=$Optimization; RuntimeProfileAdded=$false; Inputs=$inputs; Artifacts=$artifacts})
    Write-Host "PASS C3FP auxiliary running parity: 4 configurations, $($mutantReceipts.Count) compiled mutants, $($controls.Count) harness controls; $directory"
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
    "portable\GCC\ARM_CM55\secure\secure_context.c" = "E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72"
    "portable\GCC\ARM_CM55\secure\secure_context_port.c" = "B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E"
    "portable\GCC\ARM_CM55\secure\secure_context.h" = "8209F4BAF60741E8ED5516AF9706FC4B5B2EE3CF16452EDB0C034B7DDDE443B4"
    "portable\GCC\ARM_CM55\secure\secure_heap.h" = "E58805B998EE73A9EB84627EBD2955787CDFD0CD968D1BC7D93423441BAB6C87"
    "portable\GCC\ARM_CM55\secure\secure_port_macros.h" = "5F2DF28DF3D445F08727CAF41F83ED6C67E0494E40AF5572B5E18F6416B2838D"
    "portable\GCC\ARM_CM55\secure\secure_init.c" = "1B8444698089651C6415D48A2B6716BA6C6DC32F71C51B679F5A8A9A3968DE55"
    "portable\GCC\ARM_CM55\secure\secure_init.h" = "7704E518DFAAE39170274B7DD924B1A214FFFB12DC37C050E7D3457B5AA0E149"
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
    # Auxiliary private memory mechanisms only: C55S stays staged. Compile the
    # actual M55 reference, not its currently identical M33 source. Both sides
    # use three records and strict aliasing; only Fiber has fixed stack storage.
    [pscustomobject]@{
        Name = "ARM_CM55_SECURE_CONTEXT_POOL"
        CpuArgs = @("-mcpu=cortex-m55", "-mcmse", "-mfloat-abi=soft",
            "-fstrict-aliasing", "-Wstrict-aliasing=2", "-Werror=strict-aliasing")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55\secure"
        FiberSource = "fiber_secure_context_pool.c"
        FiberDefines = @(
            "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3u",
            "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=256u")
        ReferenceDir = "portable\GCC\ARM_CM55\secure"
        ReferenceSource = "secure_context.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1",
            "-DsecureconfigMAX_SECURE_CONTEXTS=3u")
        Auxiliary = 1
    },
    # Auxiliary one-shot CPU/gateway initialization, independent of C55SPOOL.
    # Neither pair adds the deferred Non-secure scheduler runtime profile.
    [pscustomobject]@{
        Name = "ARM_CM55_SECURE_CONTEXT_INIT_PRIORITY"
        CpuArgs = @("-mcpu=cortex-m55", "-mcmse", "-mfloat-abi=soft", "-fstrict-aliasing")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55\secure"; FiberSource = "fiber_secure_context_gateway.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1",
            "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3u", "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=256u")
        ReferenceDir = "portable\GCC\ARM_CM55\secure"; ReferenceSource = "secure_init.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1", "-DsecureconfigMAX_SECURE_CONTEXTS=3u")
        Auxiliary = 1
    },
    [pscustomobject]@{
        Name = "ARM_CM55_SECURE_CONTEXT_INIT_CPU"
        CpuArgs = @("-mcpu=cortex-m55", "-mcmse", "-mfloat-abi=soft", "-fstrict-aliasing")
        CoreHeader = "core_cm55.h"; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
        ProfileDir = "fiber\port\ARM_CM55\secure"; FiberSource = "fiber_secure_context_gateway.c"
        FiberDefines = @("-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1",
            "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3u", "-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=256u")
        ReferenceDir = "portable\GCC\ARM_CM55\secure"; ReferenceSource = "secure_context.c"
        ReferenceDefines = @("-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1", "-DsecureconfigMAX_SECURE_CONTEXTS=3u")
        Auxiliary = 1
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

$ports += [pscustomobject]@{
    Name = 'ARM_CM55_TFM'; Staged = 1; PendingSelectableMetadata = 1
    CpuArgs = @('-mcpu=cortex-m55', '-mfloat-abi=soft')
    CoreHeader = 'core_cm55.h'; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
    ProfileDir = 'fiber\port\ARM_CM55_TFM\non_secure'; FiberSource = 'fiber_port.c'
    FiberDefines = @('-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_ARMV81M_MAINLINE=1')
    ReferenceDir = 'portable\GCC\ARM_CM55_NTZ\non_secure'; ReferenceSource = 'portasm.c'
    ReferenceDefines = @()
}
# Exact staged-zero inventory. Independent C3FT closed proof runs below;
# neither this definition nor that source/object gate promotes the profile.
$ports += [pscustomobject]@{
    Name = 'ARM_CM33F_TFM'; Staged = 1
    CpuArgs = @('-mcpu=cortex-m33', '-mfpu=fpv5-sp-d16', '-mfloat-abi=hard')
    CoreHeader = 'core_cm33.h'; Vtor = 1; Mpu = 0; Fpu = 1; Dsp = 1
    ProfileDir = 'fiber\port\ARM_CM33F_TFM\non_secure'; FiberSource = 'fiber_port.c'
    FiberDefines = @('-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_ARMV8M_MAINLINE=1')
    ReferenceDir = 'portable\GCC\ARM_CM33_NTZ\non_secure'; ReferenceSource = 'portasm.c'
    ReferenceDefines = @('-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1')
}
# The closed-body C3SO gate does not promote this staged definition. Consumer
# and runtime integration qualification remain separate obligations.
$ports += [pscustomobject]@{
    Name = 'ARM_CM33_SECURE_ONLY'; Staged = 1
    CpuArgs = @('-mcpu=cortex-m33', '-mcmse', '-mfloat-abi=soft')
    CoreHeader = 'core_cm33.h'; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
    ProfileDir = 'fiber\port\ARM_CM33_SECURE_ONLY\secure'; FiberSource = 'fiber_port.c'
    FiberDefines = @('-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_ARMV8M_MAINLINE=1')
    ReferenceDir = 'portable\GCC\ARM_CM33_NTZ\non_secure'; ReferenceSource = 'portasm.c'
    ReferenceDefines = @('-DFIBER_FREERTOS_PARITY_SECURE_ONLY=1',
        '-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=0', '-DFIBER_FREERTOS_PARITY_ENABLE_FPU=0',
        '-DFIBER_FREERTOS_PARITY_ENABLE_MPU=0')
}
# Inventory/compile only until the separate C5SO closed-body gate is qualified.
$ports += [pscustomobject]@{
    Name = 'ARM_CM55_SECURE_ONLY'; Staged = 1
    CpuArgs = @('-mcpu=cortex-m55', '-mcmse', '-mfloat-abi=soft')
    CoreHeader = 'core_cm55.h'; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
    ProfileDir = 'fiber\port\ARM_CM55_SECURE_ONLY\secure'; FiberSource = 'fiber_port.c'
    FiberDefines = @('-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_ARMV81M_MAINLINE=1')
    ReferenceDir = 'portable\GCC\ARM_CM55_NTZ\non_secure'; ReferenceSource = 'portasm.c'
    ReferenceDefines = @('-DFIBER_FREERTOS_PARITY_SECURE_ONLY=1',
        '-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=0', '-DFIBER_FREERTOS_PARITY_ENABLE_FPU=0',
        '-DFIBER_FREERTOS_PARITY_ENABLE_MPU=0')
}
# New C55S adapters are staged inventory, not qualified by old component receipts.
$ports += [pscustomobject]@{
    Name = 'ARM_CM55_SECURE_CONTEXT_RUNTIME'; Staged = 1
    CpuArgs = @('-mcpu=cortex-m55', '-mfloat-abi=soft')
    CoreHeader = 'core_cm55.h'; Vtor = 1; Mpu = 0; Fpu = 0; Dsp = 1
    ProfileDir = 'fiber\port\ARM_CM55\non_secure'; FiberSource = 'fiber_port.c'
    FiberDefines = @('-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_ARMV81M_MAINLINE=1')
    ReferenceDir = 'portable\GCC\ARM_CM55\non_secure'; ReferenceSource = 'portasm.c'
    ReferenceDefines = @('-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1')
    ReferenceExtraIncludes = @('portable\GCC\ARM_CM55\secure')
}
$stagedRuntimeProfiles = @('fiber\port\ARM_CM55_TFM\non_secure',
    'fiber\port\ARM_CM33F_TFM\non_secure',
    'fiber\port\ARM_CM33_SECURE_ONLY\secure', 'fiber\port\ARM_CM55_SECURE_ONLY\secure',
    'fiber\port\ARM_CM55\non_secure')

Assert-ProductionPortCoverage -RepositoryRoot $RepoRoot `
    -PortDefinitions $ports -StagedRuntimeProfiles $stagedRuntimeProfiles

$kernel = Find-FreeRtosKernel
Assert-ReferenceIdentity -KernelRoot $kernel -ExpectedFiles $expectedReferenceFiles
if ($ReferenceIdentityOnly) {
    Write-Host "PASS pinned FreeRTOS reference identity (all tracked files; no extra files)"
    return
}

$compiler = Find-ArmGcc
$toolDir = Split-Path -Parent $compiler
$objdump = Join-Path $toolDir "arm-none-eabi-objdump.exe"
if (-not (Test-Path -LiteralPath $objdump)) {
    throw "arm-none-eabi-objdump.exe not found next to compiler"
}
$cmsis = Find-CmsisCore
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
if (@(@($Cm33fRunningOnly, $Cm55TfmOnly, $Cm33fTfmOnly, $Cm33SecureContextOnly, $Cm33SecureOnly, $Cm55SecureOnly, $Cm0Only, $Cm3Only) | Where-Object { $_ }).Count -gt 1) {
    throw 'Choose only one focused parity group'
}
if ($Cm33fRunningOnly -or $Cm55TfmOnly -or $Cm33fTfmOnly -or $Cm33SecureContextOnly -or $Cm33SecureOnly -or $Cm55SecureOnly -or $ClassicOnly) { $KeepBuild = $true }

try {
    Write-Host "Parity optimization: $Optimization"

    foreach ($mode in @('A30', 'C3SO', 'C5SO')) {
        if ($ClassicOnly -or $Cm33fRunningOnly -or $Cm55TfmOnly -or $Cm33fTfmOnly -or
                ($Cm33SecureContextOnly -and $mode -ne 'A30') -or
                ($Cm33SecureOnly -and $mode -ne 'C3SO') -or
                ($Cm55SecureOnly -and $mode -ne 'C5SO')) { continue }
        $originIds = if ($mode -eq 'A30') {
            @('FAP-C33S-DUAL-ORIGIN','FAP-C33S-RESTORE-ADMISSION','FAP-C33S-PSP-PRESERVATION','FAP-C33S-CLOSED-PROOF')
        } elseif ($mode -eq 'C3SO') {
            @('FAP-C3SO-CPU','FAP-C3SO-CONSTRUCTION','FAP-C3SO-START','FAP-C3SO-HARDENING','FAP-C3SO-STAGED')
        } else {
            @('FAP-C5SO-CPU','FAP-C5SO-CONSTRUCTION','FAP-C5SO-START','FAP-C5SO-HARDENING','FAP-C5SO-STAGED')
        }
        foreach ($id in $originIds) {
            if ($ledger.IndexOf($id,[StringComparison]::Ordinal) -lt 0) { throw "Missing parity difference: $id" }
        }
        $originBuild = Join-Path $BuildRoot $mode
        if (Test-Path -LiteralPath $originBuild) { throw "Evidence already exists; choose a fresh -BuildRoot: $originBuild" }
        New-Item -ItemType Directory -Path $originBuild | Out-Null
        $originCore = if ($mode -eq 'C5SO') { 'core_cm55.h' } else { 'core_cm33.h' }
        Write-CmsisMainHeader $originBuild $originCore 1 0 0 0 1
        & $Python -B (Join-Path $RepoRoot 'tools\fixtures\cm33_secure_parity\run.py') `
            --repo $RepoRoot --arm-gcc $compiler --cmsis $cmsis --reference $kernel `
            --build $originBuild --optimization=$Optimization --mode $mode
        if ($LASTEXITCODE -ne 0) { throw "$mode closed parity failed; evidence retained: $originBuild" }
    }
    if ($Cm33SecureContextOnly -or $Cm33SecureOnly -or $Cm55SecureOnly) {
        Write-Host "SCALAR_SECURE_FOCUSED_PARITY_PASS ($Optimization; no profile promotion)"
        return
    }

    if (-not $ClassicOnly -and -not $Cm33fRunningOnly -and -not $Cm55TfmOnly) {
        foreach ($id in @('FAP-C3FT-CPU','FAP-C3FT-CONSTRUCTOR','FAP-C3FT-FPU-EAGER',
                'FAP-C3FT-HARDENING','FAP-C3FT-INITIALIZE','FAP-C3FT-WRAPPER','FAP-C3FT-STAGED')) {
            if ($ledger.IndexOf($id,[StringComparison]::Ordinal) -lt 0) { throw "C3FT difference missing: $id" }
        }
        foreach ($floatAbi in @('hard','softfp')) {
            $tfmFpBuild = Join-Path $BuildRoot "C3FT-$floatAbi"
            if (Test-Path -LiteralPath $tfmFpBuild) { throw "C3FT evidence exists; choose a fresh BuildRoot: $tfmFpBuild" }
            & $Python -B (Join-Path $RepoRoot 'tools/fixtures/cm33f_tfm_parity/run.py') `
                --repo $RepoRoot --arm-gcc $compiler --cmsis $cmsis --reference $kernel `
                --build $tfmFpBuild --optimization=$Optimization --float-abi $floatAbi
            if ($LASTEXITCODE -ne 0) { throw "C3FT actual-source parity failed; evidence retained: $tfmFpBuild" }
        }
        if ($Cm33fTfmOnly) {
            Write-Host "C3FT_PARITY_PASS ($Optimization; hard/softfp, staged metadata zero, no profile promotion)"
            return
        }
    }

    if (-not $ClassicOnly -and -not $Cm55TfmOnly) { Assert-Cm33fMpuRunningParity }
    if ($Cm33fRunningOnly) {
        Write-Host "C3FP_RUNNING_PARITY_PASS ($Optimization; auxiliary only)"
        return
    }

    if (-not $ClassicOnly) {
    $tfmBuild = Join-Path $BuildRoot 'C5TF'
    foreach ($id in @('FAP-C5TF-CPU', 'FAP-C5TF-CONSTRUCTOR', 'FAP-C5TF-HARDENING',
            'FAP-C5TF-INITIALIZE', 'FAP-C5TF-WRAPPER', 'FAP-C5TF-STAGED')) {
        if ($ledger -notmatch [regex]::Escape($id)) { throw "C5TF difference missing from parity ledger: $id" }
    }
    if (Test-Path -LiteralPath $tfmBuild) { throw "C5TF evidence already exists; choose a fresh -BuildRoot: $tfmBuild" }
    New-Item -ItemType Directory -Path $tfmBuild | Out-Null
    Write-CmsisMainHeader $tfmBuild 'core_cm55.h' 1 0 0 0 1
    & $Python -B (Join-Path $RepoRoot 'tools\fixtures\cm55_tfm_parity\run.py') `
        --repo $RepoRoot --arm-gcc $compiler --cmsis $cmsis --reference $kernel `
        --build $tfmBuild --optimization=$Optimization
    if ($LASTEXITCODE -ne 0) { throw "C5TF actual-source parity failed; evidence retained: $tfmBuild" }
    if ($Cm55TfmOnly) {
        Write-Host "C5TF_PARITY_PASS ($Optimization; metadata one, no profile promotion by this gate)"
        return
    }
    }

    $compiled = @{}
    if ($ClassicOnly) { Start-ClassicFocusedEvidence }
    $compilePorts = @($ports | Where-Object {
        (-not $ClassicOnly) -or ($Cm3Only -and $_.Name -eq 'ARM_CM3') -or
        ($Cm0Only -and $_.Name -in @('ARM_CM0', 'ARM_CM0PLUS', 'ARM_CM0_MPU'))
    })
    foreach ($port in $compilePorts) {
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
        $captureC33 = $port.Name -in @('ARM_CM33_SECURE_CONTEXT_ALLOCATOR','ARM_CM33_SECURE_CONTEXT_DEPRIORITIZE',
            'ARM_CM33_SECURE_CONTEXT_INITIALIZE','ARM_CM33_SECURE_CONTEXT_LOAD','ARM_CM33_SECURE_CONTEXT_SAVE')
        if ($ClassicOnly -or $port.Name -like "ARM_CM55_SECURE_CONTEXT_INIT_*" -or $captureC33) {
            $fiberArgs += @("-save-temps=obj", "-MMD")
        }
        $initSourceHashes = @()
        if ($port.Name -like "ARM_CM55_SECURE_CONTEXT_INIT_*" -or $captureC33) {
            $initInputs = @((Join-Path $RepoRoot "fiber\fiber_api_attributes.h"),
                (Join-Path $RepoRoot "tools\freertos_asm_parity.ps1"), $ledgerPath) +
                @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'context') -Filter '*.h' -File | Select-Object -ExpandProperty FullName) +
                @(Get-ChildItem -LiteralPath $profileDir -File | Where-Object { $_.Extension -in @('.c', '.h', '.ld') } | Select-Object -ExpandProperty FullName) +
                @(Get-ChildItem -LiteralPath $configDir -Filter '*.h' -File | Select-Object -ExpandProperty FullName) +
                @(Get-ChildItem -LiteralPath (Join-Path $kernel $port.ReferenceDir) -File |
                    Where-Object { $_.Extension -in @('.c', '.h') } | Select-Object -ExpandProperty FullName)
            if ($captureC33) {
                $initInputs += @((Join-Path $RepoRoot 'mcu_core.h'),(Join-Path $RepoRoot 'basic_types.h'))+
                    @(Get-ChildItem -LiteralPath $cmsis -Filter '*.h' -File | Select-Object -ExpandProperty FullName)
            }
            $initSourceHashes = @($initInputs | ForEach-Object {
                [pscustomobject]@{Path=$_; Sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
            })
        }
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
        if ($ClassicOnly -or $port.Name -like "ARM_CM55_SECURE_CONTEXT_INIT_*" -or $captureC33) {
            $referenceArgs += @("-save-temps=obj", "-MMD")
        }
        Invoke-Compile -Compiler $compiler -Arguments $referenceArgs `
            -Label "$($port.Name) FreeRTOS"

        $compiled[$port.Name] = [pscustomobject]@{
            FiberPath = $fiberObject
            Fiber = Get-ObjectDisassembly -Objdump $objdump `
                -ObjectPath $fiberObject
            ReferencePath = $referenceObject
            Reference = Get-ObjectDisassembly -Objdump $objdump `
                -ObjectPath $referenceObject
            FiberArguments = $fiberArgs
            ReferenceArguments = $referenceArgs
            InitSourceHashes = $initSourceHashes
        }
        if ($ClassicOnly) {
            foreach ($entry in @(@($fiberObject, $compiled[$port.Name].Fiber), @($referenceObject, $compiled[$port.Name].Reference))) {
                Set-Content -LiteralPath ($entry[0]+'.dis') -Value $entry[1] -Encoding ASCII
                $readelf = Join-Path $toolDir 'arm-none-eabi-readelf.exe'
                ConvertTo-Json -InputObject @($readelf, '-A', '-h', '-S', '-s', '-r', '-W', $entry[0]) -Compress |
                    Add-Content -LiteralPath (Join-Path $BuildRoot "$ClassicEvidence/commands.jsonl") -Encoding ASCII
                $details = (& $readelf -A -h -S -s -r -W $entry[0]) -join "`n"
                if ($LASTEXITCODE -ne 0) { throw "$ClassicName readelf failed" }
                $architecture = if ($Cm3Only) { '(?m)^\s*Tag_CPU_arch: v7\r?$' } else { 'Tag_CPU_arch: v6S?-M' }
                $thumb = if ($Cm3Only) { 'Tag_THUMB_ISA_use: Thumb-2' } else { 'Tag_THUMB_ISA_use: Thumb-1' }
                if ($details -notmatch $architecture -or $details -notmatch $thumb -or
                    ($Cm3Only -and $details -notmatch 'Tag_CPU_arch_profile: Microcontroller') -or
                    $details -match 'Tag_(FP_arch|MVE_arch|Advanced_SIMD_arch|ABI_VFP_args|PAC_extension|BTI_extension):') {
                    throw "$ClassicName object has unexpected CPU/FP/ABI attributes"
                }
                Set-Content -LiteralPath ($entry[0]+'.elf.txt') -Value $details -Encoding ASCII
            }
        }
        if ($port.Name -like "ARM_CM55_SECURE_CONTEXT_INIT_*" -or $captureC33) {
            Set-Content -LiteralPath (Join-Path $portBuild "fiber-port.disasm") `
                -Value $compiled[$port.Name].Fiber -Encoding ASCII
            Set-Content -LiteralPath (Join-Path $portBuild "freertos-port.disasm") `
                -Value $compiled[$port.Name].Reference -Encoding ASCII
            $evidenceName = if ($captureC33) { 'c33s-evidence.json' } else { 'c55sinit-evidence.json' }
            [ordered]@{
                ReferenceCommit = $ExpectedFreeRtosCommit
                Optimization = $Optimization
                RuntimeProfileAdded = $false
                Compiler = $compiler
                FiberSource = $fiberPath
                FiberSourceSha256 = (Get-FileHash -LiteralPath $fiberPath -Algorithm SHA256).Hash
                FiberArguments = $fiberArgs
                ReferenceSource = $referencePath
                ReferenceSourceSha256 = (Get-FileHash -LiteralPath $referencePath -Algorithm SHA256).Hash
                ReferenceArguments = $referenceArgs
                Inputs = $initSourceHashes
            } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath `
                (Join-Path $portBuild $evidenceName) -Encoding ASCII
        }
        if ($port.Name -eq "ARM_CM55_SECURE_CONTEXT_POOL") {
            Set-Content -LiteralPath (Join-Path $portBuild "fiber-port.disasm") `
                -Value $compiled[$port.Name].Fiber -Encoding ASCII
            Set-Content -LiteralPath (Join-Path $portBuild "freertos-port.disasm") `
                -Value $compiled[$port.Name].Reference -Encoding ASCII
            [ordered]@{
                ReferenceCommit = $ExpectedFreeRtosCommit
                Optimization = $Optimization
                RuntimeProfileAdded = $false
                Compiler = $compiler
                FiberSource = $fiberPath
                FiberSourceSha256 = (Get-FileHash -LiteralPath $fiberPath -Algorithm SHA256).Hash
                FiberArguments = $fiberArgs
                ReferenceSource = $referencePath
                ReferenceSourceSha256 = (Get-FileHash -LiteralPath $referencePath -Algorithm SHA256).Hash
                ReferenceArguments = $referenceArgs
            } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath `
                (Join-Path $portBuild "c55spool-evidence.json") -Encoding ASCII
        }
    }

    if ($Cm3Only) {
        Assert-Cm3Mechanisms -Pair $compiled['ARM_CM3'] -Ledger $ledger
        Complete-ClassicFocusedEvidence
        return
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


    if ($Cm0Only) { Complete-ClassicFocusedEvidence; return }

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

    Assert-Cm3Mechanisms -Pair $compiled["ARM_CM3"] -Ledger $ledger

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

    # C55SPOOL is an auxiliary memory-mechanism pair, not a runtime profile.
    # Signatures follow the reference scan/handle/owner contract and Fiber's
    # documented static-storage adaptation; CPU initialization is not paired.
    $pair = $compiled["ARM_CM55_SECURE_CONTEXT_POOL"]
    $poolForbidden = @(
        '\b(?:mrs|msr|cpsid|cpsie|svc|sg|bxns|blxns)\b',
        '(?m)^\s*[0-9a-f]+:\s+(?:[0-9a-f]{4}\s+){1,2}v[a-z][a-z0-9.]*\b',
        '\bblx\b', '\bbx\s+(?!lr\b)',
        '\b(?:pvPortMalloc|vPortFree|malloc|calloc|realloc|free|memset|memcpy|memmove|__aeabi_\w*|__cmse_\w*)\b',
        '__acle_se_', 'SecureContext_(?:Load|Save)ContextAsm')
    Assert-AbsentPatterns -Body $pair.Fiber -Patterns $poolForbidden `
        -Label "C55SPOOL complete private call graph: no CPU/NSC/FP/heap/libc"
    foreach ($call in [regex]::Matches($pair.Fiber,
            'R_ARM_THM_(?:CALL|JUMP24)\s+(?<target>[A-Za-z_.$][A-Za-z0-9_.$]*)')) {
        $null = Get-DisassemblyFunctionBody -Disassembly $pair.Fiber `
            -Symbol $call.Groups['target'].Value -Path $pair.FiberPath
    }

    $poolInitPatterns = @(
        '\bldr(?:\.w)?\s+[^\r\n]+',
        '\b(?:beq(?:\.[nw])?|cbz)\b',
        '\b(?:cbz|cbnz|bne(?:\.[nw])?)\b',
        '\bstr(?:\.w)?\s+[^\r\n]+',
        '\bstrb(?:\.w)?\b',
        '\b(?:le|bne(?:\.[nw])?)\b',
        '\bldrb(?:\.w)?\b',
        '\b(?:cbnz|bne(?:\.[nw])?)\b',
        '\bldr(?:\.w)?\b', '\bcmp(?:\.w)?\b',
        '\bbne(?:\.[nw])?\b', '\bstr(?:\.w)?\b',
        '\bldr(?:\.w)?\b', '\bcmp(?:\.w)?\b',
        '\bbne(?:\.[nw])?\b', '\bmovs?\s+r0,\s*#1\b')
    Assert-MechanismParity -PortName "C55SPOOL" -Mechanism "one-shot-memory-init" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "SecureContext_Init" `
        -ReferencePatterns @(
            '\bmrs\s+[^,]+,\s*IPSR', '\bcbnz\b',
            '\bstr(?:\.w)?\b', '\bmsr\s+PSPLIM', '\bmsr\s+PSP',
            '\bstr(?:d|\.w)?\b',
            '\bmsr\s+CONTROL') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_secure_context_pool_boot_initialize" `
        -FiberPatterns $poolInitPatterns -FiberPath $pair.FiberPath `
        -DifferenceIds @("FAP-C55SPOOL-INIT") -Ledger $ledger

    $referenceInit = Get-DisassemblyFunctionBody -Disassembly $pair.Reference `
        -Symbol "SecureContext_Init" -Path $pair.ReferencePath
    if ([regex]::Matches($referenceInit, '\bstrd\b').Count -eq 2) {
        Assert-OrderedPatterns -Body $referenceInit -Patterns @(
            '\badds?(?:\.w)?\s+[^,]+,\s*[^,]+,\s*#48\b', '\bstrd\b') `
            -Label "C55SPOOL FreeRTOS three-record loop end"
        $clear = Get-BackwardLoopContaining -Body $referenceInit `
            -OperationPattern '\bstrd\b' -Label "C55SPOOL FreeRTOS 48-byte record clear"
        if ([regex]::Matches($clear.Body, '\bstrd\b').Count -ne 2) {
            throw "C55SPOOL FreeRTOS record-clear loop must clear four words per record"
        }
    } else {
        # The size-optimized reference may unroll three four-word records.
        $clearPatterns = @('\bstrd\s+[^\r\n]*\[[^\],]+(?:,\s*#0)?\]')
        $clearPatterns += @(8, 16, 24, 32, 40 | ForEach-Object {
            '\bstrd\s+[^\r\n]*\[[^\]]+,\s*#' + $_ + '\]'
        })
        Assert-OrderedPatterns -Body $referenceInit -Patterns $clearPatterns `
            -Label "C55SPOOL FreeRTOS unrolled 48-byte record clear"
    }
    $poolInit = Get-DisassemblyFunctionBody -Disassembly $pair.Fiber `
        -Symbol "fiber_secure_context_pool_boot_initialize" -Path $pair.FiberPath
    if ([regex]::Matches($poolInit, '#864\b').Count -ne 2) {
        throw "C55SPOOL scrub and readback must each cover the full 864-byte image"
    }
    $scrub = Get-BackwardLoopContaining -Body $poolInit `
        -OperationPattern '\bstrb(?:\.w)?\b' -Label "C55SPOOL volatile scrub"
    $readback = Get-BackwardLoopContaining -Body $poolInit `
        -OperationPattern '\bldrb(?:\.w)?\b' -Label "C55SPOOL volatile readback"
    if ($scrub.End -ge $readback.Start) {
        throw "C55SPOOL must finish the scrub loop before its readback loop"
    }
    Assert-OrderedPatterns -Body $readback.Body `
        -Patterns @('\bldrb(?:\.w)?\b', '\b(?:cbnz|bne(?:\.[nw])?)\b') `
        -Label "C55SPOOL readback rejects nonzero bytes inside the loop"
    Assert-OrderedPatterns -Body $poolInit -Patterns @(
        'fiber_secure_context_pool_fail_closed', '0x53435042\b') `
        -Label "C55SPOOL one-way marker and readback failure target"

    Assert-MechanismParity -PortName "C55SPOOL" -Mechanism "bounded-allocation" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "SecureContext_AllocateContext" `
        -ReferencePatterns @(
            '\bmrs\s+[^,]+,\s*IPSR', '\bmrs\s+[^,]+,\s*PSPLIM',
            '\bcmp(?:\.w)?\s+[^,]+,\s*#3\b', 'pvPortMalloc',
            '\bstr(?:\.w)?\b', '\bstr(?:\.w)?\b', '0xfef5eda5\b') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_secure_context_pool_allocate" `
        -FiberPatterns @(
            'fiber_secure_context_pool_require_ready',
            '\bcmp(?:\.w)?\s+[^,]+,\s*#(?:255|256)\b',
            '\b(?:ands?(?:\.w)?[^\r\n]*#7|lsls[^\r\n]*#29)\b',
            'fiber_secure_context_pool_record_is_free',
            '\bcmp(?:\.w)?\s+[^,]+,\s*#3\b',
            'fiber_secure_context_pool_write_stack_seal',
            '\bstr(?:d|\.w)?\b',
            '\bstr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#20\]',
            'fiber_secure_context_pool_record_is_valid',
            'fiber_secure_context_pool_require_ready',
            '\badds?(?:\.w)?\s+r0,\s*[^\r\n]*#1\b') `
        -FiberPath $pair.FiberPath -DifferenceIds @("FAP-C55SPOOL-ALLOCATE") `
        -Ledger $ledger

    $referenceAllocate = Get-DisassemblyFunctionBody -Disassembly $pair.Reference `
        -Symbol "SecureContext_AllocateContext" -Path $pair.ReferencePath
    $poolAllocate = Get-DisassemblyFunctionBody -Disassembly $pair.Fiber `
        -Symbol "fiber_secure_context_pool_allocate" -Path $pair.FiberPath
    foreach ($allocation in @(
            [pscustomobject]@{ Body = $referenceAllocate; Label = "FreeRTOS" },
            [pscustomobject]@{ Body = $poolAllocate; Label = "Fiber" })) {
        $null = Get-BackwardLoopContaining -Body $allocation.Body `
            -OperationPattern '\bldr(?:\.w)?\b' `
            -Label "C55SPOOL $($allocation.Label) bounded record scan"
        Assert-OrderedPatterns -Body $allocation.Body -Patterns @(
            '\bldr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#12\]', '\bcmp\b') `
            -Label "C55SPOOL $($allocation.Label) compares opaque owner tokens"
        Assert-OrderedPatterns -Body $allocation.Body -Patterns @(
            '\badds?(?:\.w)?\s+r0,\s*[^\r\n]*#1\b') `
            -Label "C55SPOOL $($allocation.Label) index-plus-one handle"
    }
    foreach ($seal in @(
            [pscustomobject]@{ Symbol = "fiber_secure_context_pool_write_stack_seal"; Op = '\bstrb(?:\.w)?\b' },
            [pscustomobject]@{ Symbol = "fiber_secure_context_pool_stack_seal_is_valid"; Op = '\bldrb(?:\.w)?\b' })) {
        $body = Get-DisassemblyFunctionBody -Disassembly $pair.Fiber `
            -Symbol $seal.Symbol -Path $pair.FiberPath
        Assert-OrderedPatterns -Body $body -Patterns @(
            '#(?:7|8)\b', $seal.Op, '0xfef5eda5\b') `
            -Label "C55SPOOL $($seal.Symbol) eight-byte native seal"
        $null = Get-BackwardLoopContaining -Body $body -OperationPattern $seal.Op `
            -Label "C55SPOOL $($seal.Symbol) strict-alias-safe character loop"
        $wordAccess = [regex]::Replace($body, $seal.Op, 'ldr')
        $rejected = $false
        try {
            $null = Get-BackwardLoopContaining -Body $wordAccess `
                -OperationPattern $seal.Op -Label "C55SPOOL word-access seal mutant"
        } catch { $rejected = $true }
        if (-not $rejected) { throw "C55SPOOL accepted a non-byte seal-access mutant" }
    }

    Assert-MechanismParity -PortName "C55SPOOL" -Mechanism "owned-handle-lookup" `
        -ReferenceDisassembly $pair.Reference -ReferenceSymbol "SecureContext_LoadContext" `
        -ReferencePatterns @(
            '\bsubs?(?:\.w)?\s+[^\r\n]*#1\b',
            '\bcmp(?:\.w)?\s+[^,]+,\s*#2\b', '\bmrs\s+[^,]+,\s*PSPLIM',
            '\bldr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#12\]',
            '\bcmp\b', 'SecureContext_LoadContextAsm') `
        -ReferencePath $pair.ReferencePath -FiberDisassembly $pair.Fiber `
        -FiberSymbol "fiber_secure_context_pool_lookup_owned" `
        -FiberPatterns @(
            'fiber_secure_context_pool_require_ready',
            '\bsubs?(?:\.w)?\s+[^\r\n]*#1\b',
            '\bcmp(?:\.w)?\s+[^,]+,\s*#2\b',
            '\bldr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#20\]',
            'fiber_secure_context_pool_record_is_valid',
            '\bldr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#12\]', '\bcmp\b') `
        -FiberPath $pair.FiberPath -DifferenceIds @("FAP-C55SPOOL-LOOKUP") `
        -Ledger $ledger
    $recordValidation = Get-DisassemblyFunctionBody -Disassembly $pair.Fiber `
        -Symbol "fiber_secure_context_pool_record_is_valid" -Path $pair.FiberPath
    Assert-OrderedPatterns -Body $recordValidation -Patterns @(
        '\bcmp(?:\.w)?\s+[^,]+,\s*#2\b',
        '\bldr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#20\]',
        '\bldr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#12\]',
        '\bldr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#16\]',
        '\bcmp(?:\.w)?\s+[^,]+,\s*#(?:255|256)\b',
        '\bldr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#4\]',
        '\bcmp\b', '\bldr(?:\.w)?\s+[^\r\n]*\[[^\]]+,\s*#8\]',
        '\bcmp\b', 'fiber_secure_context_pool_stack_seal_is_valid') `
        -Label "C55SPOOL checked record geometry precedes seal reads"

    $poolSymbols = (& $objdump -t $pair.FiberPath) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "C55SPOOL symbol-table inspection failed" }
    Assert-OrderedPatterns -Body $poolSymbols -Patterns @(
        '(?m)^.*\sO\s+\.bss\.fiber_secure_context_pool_state\s+00000004\s+fiber_secure_context_pool_state\s*$',
        '(?m)^.*\sO\s+\.fiber_secure_context_pool\s+00000360\s+fiber_secure_context_pool_image\s*$') `
        -Label "C55SPOOL 864-byte retained image and separate four-byte BSS marker"

    # Exercise the guards against mutations of the actual generated object text.
    # A removed readback or a word-access replacement must not keep passing.
    $rejected = $false
    try {
        $null = Get-BackwardLoopContaining `
            -Body ([regex]::Replace($poolInit, '\bldrb(?:\.w)?\b', 'ldr')) `
            -OperationPattern '\bldrb(?:\.w)?\b' -Label "C55SPOOL readback mutant"
    } catch { $rejected = $true }
    if (-not $rejected) { throw "C55SPOOL accepted the missing byte-readback mutant" }
    $rejected = $false
    try {
        $backEdge = ($readback.Body -split "`n")[-1]
        $null = Get-BackwardLoopContaining -Body ($poolInit.Replace($backEdge, '')) `
            -OperationPattern '\bldrb(?:\.w)?\b' -Label "C55SPOOL readback-loop mutant"
    } catch { $rejected = $true }
    if (-not $rejected) { throw "C55SPOOL accepted readback without its loop back edge" }
    $rejected = $false
    try {
        Assert-AbsentPatterns -Body ($pair.Fiber + "`nmsr CONTROL, r0`n") `
            -Patterns $poolForbidden -Label "C55SPOOL CPU-write mutant"
    } catch { $rejected = $true }
    if (-not $rejected) { throw "C55SPOOL accepted a private CPU-write mutant" }
    Write-Host "PASS C55SPOOL auxiliary storage, byte loops, no-CPU/no-heap, and negative guards"

    Test-C55SInitMechanisms -PriorityPair $compiled["ARM_CM55_SECURE_CONTEXT_INIT_PRIORITY"] `
        -CpuPair $compiled["ARM_CM55_SECURE_CONTEXT_INIT_CPU"]
    Test-C55STransferMechanisms -Pair $compiled["ARM_CM55_SECURE_CONTEXT_INIT_CPU"]
    Test-C33SCohortMechanisms -Pair $compiled['ARM_CM33_SECURE_CONTEXT_INITIALIZE'] `
        -PriorityPair $compiled['ARM_CM33_SECURE_CONTEXT_DEPRIORITIZE']

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
    # A17 makes this reachable helper a canonical no-IPA boundary. Inspect its
    # gate separately rather than requiring the compiler to inline it into each
    # NSC entry. The entries below must still call it before accessing the pool.
    $runtimeExceptionGate = Get-DisassemblyFunctionBody `
        -Disassembly $pair.Fiber `
        -Symbol "fiber_secure_context_gateway_is_runtime_exception" `
        -Path $pair.FiberPath
    Assert-OrderedPatterns -Body $runtimeExceptionGate -Patterns @(
        '\bmrs\s+[^,]+,\s*IPSR',
        '\bcmp\s+[^,]+,\s*#11\b',
        '\b(?:cmp|sub)[a-z]*(?:\.w)?\s+[^\r\n]*#14\b') `
        -Label "ARM_CM33 SecureContext runtime exception gate"
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
            '\bbl\s+[^\r\n]*fiber_secure_context_gateway_is_runtime_exception',
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
            '\bbl\s+[^\r\n]*fiber_secure_context_gateway_is_runtime_exception',
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
