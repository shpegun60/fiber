function Test-CodegenMutants {
    param([string]$Directory, [string[]]$Flags, [string[]]$Objects, [string]$Provider,
        [int]$Regions, [string]$Source, [string]$SvcObject, [string]$Linker, [string]$Contract)
    $text = Get-Content -LiteralPath $Source -Raw
    $mutations = @(
        @{Name="wrong-psp-register"; From="msr   psp, r2"; To="msr   psp, r3"; Code="RESTORE"},
        @{Name="wrong-control-readback"; From="cmp   r5, #3"; To="cmp   r5, #0"; Code="RESTORE"},
        @{Name="wrong-final-exc-return"; From="mvn   r5, #67"; To="mvn   r5, #71"; Code="RESTORE"},
        @{Name="wrong-region-transfer"; From="stmia r2, {r4-r11}"; To="stmia r2, {r4-r10,r12}"; Code="RESTORE"},
        @{Name="wrong-cursor-publication"; From="str   r1, [r0, #0]"; To="str   r2, [r0, #0]"; Code="RESTORE"},
        @{Name="wrong-entry-origin"; From="mvn   r3, #71"; To="mvn   r3, #67"; Code="ORIGIN"; HandlerOnly=$true},
        @{Name="wrong-yield-service"; From='fiber_portSTRINGIFY(fiber_portSVC_YIELD)';
          To='fiber_portSTRINGIFY(fiber_portSVC_START)'; Code="STAGED"},
        @{Name="wrong-return-service"; From='fiber_portSTRINGIFY(fiber_portSVC_RETURN)';
          To='fiber_portSTRINGIFY(fiber_portSVC_YIELD)'; Code="STAGED"},
        @{Name="ordinary-fp-injection"; From="mrs   r5, control"; To='vmov  s0, r0 \n" "mrs   r5, control'; Code="FP"},
        @{Name="unknown-live-stc"; From="mov   lr, r1"; To='.inst.w 0xED810000 \n" "mov   lr, r1'; Code="DECODE"},
        @{Name="unknown-live-ffffffff"; From="mov   lr, r1"; To='.inst.w 0xFFFFFFFF \n" "mov   lr, r1'; Code="DECODE"},
        @{Name="instrumentation-attribute-removal"; From='#include "fiber_port_private.h"';
          To="#define FIBER_API_NOINSTR`n" + '#include "fiber_port_private.h"'; Code="INSTRUMENTATION"; Instrument=$true}
    )
    $receipts = @()
    foreach ($mutation in $mutations) {
        $dir = Join-Path $Directory ("mutant-" + $mutation.Name)
        New-Item -ItemType Directory -Path $dir | Out-Null
        $prefix = ""
        $body = $text
        if ($mutation.ContainsKey("HandlerOnly")) {
            $index = $text.IndexOf("void SVC_Handler(void)", [StringComparison]::Ordinal)
            if ($index -lt 0) { throw "Handler mutation anchor is missing" }
            $prefix = $text.Substring(0, $index)
            $body = $text.Substring($index)
        }
        $count = [regex]::Matches($body, [regex]::Escape($mutation.From)).Count
        $expectedCount = if ($mutation.Name -eq "wrong-region-transfer") { 3 } else { 1 }
        if ($count -ne $expectedCount) { throw "Mutation anchor changed: $($mutation.Name)/$count" }
        $copy = Join-Path $dir "mutated-svc.c"
        Set-Content -LiteralPath $copy -Encoding ASCII -Value ($prefix + $body.Replace($mutation.From, $mutation.To))
        $object = Join-Path $dir "mutated-svc.o"
        $extra = @()
        $providers = @($Provider)
        if ($mutation.ContainsKey("Instrument")) {
            $extra += "-finstrument-functions"
            $compilerProviders = Join-Path $dir "forbidden-compiler-providers.o"
            Invoke-Proof $ArmGcc ($Flags + @("-c", (Join-Path $fixture "compiler_providers.c"), "-o", $compilerProviders)) | Out-Null
            $providers += $compilerProviders
        }
        Invoke-Proof $ArmGcc ($Flags + $extra + @("-save-temps=obj", "-MMD", "-c", $copy, "-o", $object)) | Out-Null
        $elf = Join-Path $dir "mutated.elf"
        Invoke-Proof $ArmGcc ($Flags + @("-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings",
            "-Wl,-T,$Linker", "-Wl,-T,$Contract", "-Wl,-Map,$elf.map") +
            @($Objects | Where-Object { $_ -ne $SvcObject }) + @($object) +
            $providers + @("-o", $elf)) | Out-Null
        Save-ElfEvidence $elf
        Test-Oracle $elf $Regions -ExpectedRejection $mutation.Code | Out-Null
        $receipts += [pscustomobject]@{Name=$mutation.Name; Regions=$Regions; Directory=$dir; Rejection=$mutation.Code}
    }
    $duplicateObject = Join-Path $Directory "duplicate-svc.o"
    Invoke-Proof $ArmGcc ($Flags + @("-c", (Join-Path $fixture "duplicate.c"), "-o", $duplicateObject)) | Out-Null
    $duplicate = Invoke-Proof $ArmGcc ($Flags + @("-nostdlib", "-Wl,--gc-sections",
        "-Wl,-T,$Linker", "-Wl,-T,$Contract") + $Objects + @($Provider, $duplicateObject, "-o", (Join-Path $Directory "duplicate.elf"))) `
        -Log (Join-Path $Directory "duplicate.log") -AllowFailure
    if ($duplicate.ExitCode -eq 0 -or $duplicate.Output -notmatch 'multiple definition.*SVC_Handler') {
        throw "Duplicate strong SVC negative failed for the wrong reason: $($duplicate.Output)"
    }
    $receipts += [pscustomobject]@{Name="duplicate-strong-SVC"; Regions=$Regions; Directory=$Directory; Rejection="link:multiple definition SVC_Handler"}
    $duplicatePendSv = Join-Path $Directory "duplicate-pendsv.o"
    Invoke-Proof $ArmGcc ($Flags + @("-DDUPLICATE_PENDSV=1", "-c", (Join-Path $fixture "duplicate.c"),
        "-o", $duplicatePendSv)) | Out-Null
    $duplicate = Invoke-Proof $ArmGcc ($Flags + @("-nostdlib", "-Wl,--gc-sections",
        "-Wl,-T,$Linker", "-Wl,-T,$Contract") + $Objects + @($Provider, $duplicatePendSv,
        "-o", (Join-Path $Directory "duplicate-pendsv.elf"))) `
        -Log (Join-Path $Directory "duplicate-pendsv.log") -AllowFailure
    if ($duplicate.ExitCode -eq 0 -or $duplicate.Output -notmatch 'multiple definition.*PendSV_Handler') {
        throw "Duplicate strong PendSV negative failed for the wrong reason: $($duplicate.Output)"
    }
    $receipts += [pscustomobject]@{Name="duplicate-strong-PendSV"; Regions=$Regions; Directory=$Directory; Rejection="link:multiple definition PendSV_Handler"}
    $ambiguousObject = Join-Path $Directory "ambiguous-local-SVC.o"
    Invoke-Proof $ArmGcc ($Flags + @("-c", (Join-Path $fixture "ambiguous.S"), "-o", $ambiguousObject)) | Out-Null
    $ambiguousElf = Join-Path $Directory "ambiguous-local-SVC.elf"
    Invoke-Proof $ArmGcc ($Flags + @("-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings",
        "-Wl,-T,$Linker", "-Wl,-T,$Contract") + $Objects + @($Provider, $ambiguousObject, "-o", $ambiguousElf)) | Out-Null
    Save-ElfEvidence $ambiguousElf
    Test-Oracle $ambiguousElf $Regions -ExpectedRejection "SYMBOL" | Out-Null
    $receipts += [pscustomobject]@{Name="ambiguous-local-SVC"; Regions=$Regions; Directory=$Directory; Rejection="SYMBOL"}
    return $receipts
}
