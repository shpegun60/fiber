param(
    [string]$ArmGcc = $env:ARM_NONE_EABI_GCC,
    [string]$CmsisCore = $env:CMSIS_CORE_INCLUDE,
    [string]$FreeRtosKernel = $env:FREERTOS_KERNEL_REFERENCE,
    [string]$BuildRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($ArmGcc)) {
    $command = Get-Command arm-none-eabi-gcc.exe -ErrorAction SilentlyContinue
    if ($command) { $ArmGcc = $command.Source }
}
if ([string]::IsNullOrWhiteSpace($ArmGcc) -or -not (Test-Path -LiteralPath $ArmGcc)) {
    throw "Owner regressions require -ArmGcc or ARM_NONE_EABI_GCC"
}
$ArmGcc = (Resolve-Path -LiteralPath $ArmGcc).Path
if ([string]::IsNullOrWhiteSpace($CmsisCore)) {
    $CmsisCore = Join-Path $RepositoryRoot "..\..\..\Drivers\CMSIS\Include"
}
if (-not (Test-Path -LiteralPath (Join-Path $CmsisCore "core_cm33.h"))) {
    throw "Owner regressions require -CmsisCore with core_cm33.h"
}
$CmsisCore = (Resolve-Path -LiteralPath $CmsisCore).Path
if ([string]::IsNullOrWhiteSpace($FreeRtosKernel)) {
    $FreeRtosKernel = Join-Path $RepositoryRoot "..\..\..\..\_reference\FreeRTOS-Kernel"
}
$FreeRtosKernel = (Resolve-Path -LiteralPath $FreeRtosKernel).Path
if ([string]::IsNullOrWhiteSpace($BuildRoot)) { $BuildRoot = [IO.Path]::GetTempPath() }
$work = Join-Path $BuildRoot ("owner-guards-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$work = (Resolve-Path -LiteralPath $work).Path
$toolDir = Split-Path -Parent $ArmGcc
$nm = Join-Path $toolDir "arm-none-eabi-nm.exe"
$objdump = Join-Path $toolDir "arm-none-eabi-objdump.exe"
foreach ($tool in @($nm, $objdump)) {
    if (-not (Test-Path -LiteralPath $tool)) { throw "Missing ARM tool: $tool" }
}

function Invoke-OwnerTool {
    param([string]$Tool, [string[]]$Arguments)
    $output = @(& $Tool @Arguments)
    if ($LASTEXITCODE -ne 0) { throw "$Tool failed: $($Arguments -join ' ')" }
    return $output
}

function Assert-OwnerReferenceRejected {
    param([string]$Path, [string]$Reason)
    $message = ""
    try {
        & (Join-Path $PSScriptRoot "freertos_asm_parity.ps1") `
            -FreeRtosKernel $Path -ReferenceIdentityOnly
    } catch { $message = $_.Exception.Message }
    if ($message -notmatch 'Pinned FreeRTOS (worktree is not clean|tracked content drifted)') {
        throw "Reference negative did not fail on the intended guard ($Reason): $message"
    }
    Write-Host "PASS A19 rejected $Reason"
}

# Qualify the exact production normalizer and ordered matcher, not a copied
# implementation. Import function definitions only; do not run parity here.
$tokens = $null
$parseErrors = $null
$parityAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot "freertos_asm_parity.ps1"), [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) { throw "Cannot parse parity tool" }
foreach ($functionName in @("Add-BoundCallRelocationTargets",
        "Get-DisassemblyFunctionBody", "Assert-OrderedPatterns",
        "Assert-AbsentPatterns", "Get-ObjectDisassembly", "Assert-MechanismParity")) {
    $definition = $parityAst.Find({ param($node)
        ($node -is [Management.Automation.Language.FunctionDefinitionAst]) -and
            ($node.Name -eq $functionName)
    }, $true)
    if ($null -eq $definition) { throw "Missing parity function $functionName" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$boundCall = "  20:`tf7ff fffe `tbl`t0 <enclosing_gateway>`n`t`t20: R_ARM_THM_CALL fiber_owner_callee"
$boundJump = "  20:`tf7ff bffe `tb.w`t0 <enclosing_gateway>`n`t`t20: R_ARM_THM_JUMP24 fiber_owner_callee"
foreach ($positive in @($boundCall, $boundJump)) {
    $normalized = Add-BoundCallRelocationTargets $positive
    Assert-OrderedPatterns -Body $normalized `
        -Patterns @('\b(?:bl|b\.w)\s+[^\r\n]*<fiber_owner_callee>') `
        -Label "A17 same-instruction relocation"
    if ($normalized -match 'enclosing_gateway') {
        throw "A17 normalizer retained a misleading placeholder target"
    }
}
foreach ($negative in @(
        $boundCall.Replace('20: R_ARM', '24: R_ARM'),
        $boundCall.Replace('R_ARM_THM_CALL', 'R_ARM_THM_JUMP24'),
        $boundCall.Replace("`tbl`t", "`tbne`t"),
        $boundCall.Replace("`n", "`n  24: bf00 nop`n"))) {
    if ((Add-BoundCallRelocationTargets $negative) -ne $negative) {
        throw "A17 normalizer accepted an unbound/wrong-opcode relocation"
    }
}
Write-Host "PASS A17 bound-call relocation positives and offset/opcode/intervening-instruction negatives"

$indexPath = ((Invoke-OwnerTool "git" @(
    "--no-optional-locks", "-C", $FreeRtosKernel,
    "rev-parse", "--path-format=absolute", "--git-path", "index")) -join "").Trim()
$indexBefore = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash
& (Join-Path $PSScriptRoot "freertos_asm_parity.ps1") `
    -FreeRtosKernel $FreeRtosKernel -ReferenceIdentityOnly
if ((Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash -ne $indexBefore) {
    throw "Reference validation mutated the live reference index"
}

# Compile the actual reference allocator's dependency list before creating the
# negative fixture. This documents that the edited headers are consumed inputs.
$secureReference = Join-Path $FreeRtosKernel "portable\GCC\ARM_CM33\secure"
$dependencies = Join-Path $work "reference-secure-context.d"
$null = Invoke-OwnerTool $ArmGcc @(
    "-mcpu=cortex-m33", "-mthumb", "-mcmse", "-mfloat-abi=soft",
    "-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1",
    "-I$(Join-Path $PSScriptRoot 'fixtures\freertos_asm_parity')",
    "-I$(Join-Path $FreeRtosKernel 'include')", "-I$secureReference",
    "-MM", "-MF", $dependencies, "-MT", "reference-secure-context.o",
    (Join-Path $secureReference "secure_context.c")
)
$dependencyText = Get-Content -LiteralPath $dependencies -Raw
foreach ($header in @("secure_context.h", "secure_heap.h", "secure_port_macros.h")) {
    if ($dependencyText -notmatch [regex]::Escape($header)) {
        throw "A19 fixture no longer consumes $header"
    }
}
$referenceTempRoot = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).Path
$referenceCopy = Join-Path $referenceTempRoot ("fref-" + [Guid]::NewGuid().ToString("N"))
$referencePaths = @(Invoke-OwnerTool "git" @("--no-optional-locks", "-C",
    $FreeRtosKernel, "ls-tree", "-r", "--name-only", "HEAD"))
$maxReferencePath = $referenceCopy.Length + 1 +
    ($referencePaths | Measure-Object -Property Length -Maximum).Maximum
if ($maxReferencePath -ge 260) {
    throw "Reference fixture would exceed MAX_PATH ($maxReferencePath); use a shorter TEMP directory"
}
$referenceTree = Join-Path $work "reference-pinned-tree.txt"
Invoke-OwnerTool "git" @("--no-optional-locks", "-C", $FreeRtosKernel,
    "ls-tree", "-r", "HEAD") |
    Set-Content -LiteralPath $referenceTree -Encoding ASCII
$referenceEvidencePath = Join-Path $work "reference-fixture.json"
$referenceEvidence = [ordered]@{
    SourceRoot = $FreeRtosKernel
    Commit = "a50edad08b29052631aa469d4df6e6ec7ff68878"
    TreeListingSha256 = (Get-FileHash -LiteralPath $referenceTree -Algorithm SHA256).Hash
    FixturePath = $referenceCopy
    MaxWorktreePathCharacters = $maxReferencePath
    CleanCheckoutValidated = $false
    FixtureHeaderSha256 = $null
    CleanupCompleted = $false
    LiveIndexSha256Before = $indexBefore
    LiveIndexSha256After = $null
}
$referenceEvidence | ConvertTo-Json | Set-Content -LiteralPath $referenceEvidencePath -Encoding ASCII
Write-Host "A19 short temporary reference: $referenceCopy (maximum path $maxReferencePath characters)"
try {
    # Shared object storage is read-only; all fixture worktree/index writes stay
    # in a short temp-root sibling, never under a potentially nested BuildRoot.
    # No checkout/reset/update-index touches the live pin.
    New-Item -ItemType Directory -Path $referenceCopy | Out-Null
    $null = Invoke-OwnerTool "git" @("clone", "--quiet", "--shared", "--no-checkout",
        "--", $FreeRtosKernel, $referenceCopy)
    $null = Invoke-OwnerTool "git" @("-C", $referenceCopy, "-c", "core.autocrlf=false",
        "checkout", "--quiet", "--detach", "a50edad08b29052631aa469d4df6e6ec7ff68878")
    & (Join-Path $PSScriptRoot "freertos_asm_parity.ps1") `
        -FreeRtosKernel $referenceCopy -ReferenceIdentityOnly
    $referenceEvidence.CleanCheckoutValidated = $true
    $relativeHeader = "portable/GCC/ARM_CM33/secure/secure_port_macros.h"
    $headerPath = Join-Path $referenceCopy $relativeHeader
    $headerBytes = [IO.File]::ReadAllBytes($headerPath)
    $referenceEvidence.FixtureHeaderSha256 =
        (Get-FileHash -LiteralPath $headerPath -Algorithm SHA256).Hash
    [IO.File]::AppendAllText($headerPath, "`n/* owner consumed-header negative */`n")
    Assert-OwnerReferenceRejected $referenceCopy "edited consumed Secure header at the pinned HEAD"
    $null = Invoke-OwnerTool "git" @("-C", $referenceCopy, "update-index",
        "--assume-unchanged", "--", $relativeHeader)
    Assert-OwnerReferenceRejected $referenceCopy "assume-unchanged consumed header"
    $null = Invoke-OwnerTool "git" @("-C", $referenceCopy, "update-index",
        "--no-assume-unchanged", "--", $relativeHeader)
    $null = Invoke-OwnerTool "git" @("-C", $referenceCopy, "update-index",
        "--skip-worktree", "--", $relativeHeader)
    Assert-OwnerReferenceRejected $referenceCopy "skip-worktree consumed header"
    $null = Invoke-OwnerTool "git" @("-C", $referenceCopy, "update-index",
        "--no-skip-worktree", "--", $relativeHeader)
    [IO.File]::WriteAllBytes($headerPath, $headerBytes)

    # stdint.h can shadow a toolchain header because the reference directory is
    # an -I path. Reject both ordinary and ignored untracked inputs.
    $shadow = Join-Path $referenceCopy "portable\GCC\ARM_CM33\secure\stdint.h"
    [IO.File]::WriteAllText($shadow, "#error owner shadow header`n")
    Assert-OwnerReferenceRejected $referenceCopy "untracked shadow header"
    [IO.File]::AppendAllText((Join-Path $referenceCopy ".git\info\exclude"), "`nstdint.h`n")
    Assert-OwnerReferenceRejected $referenceCopy "ignored shadow header"
    Remove-Item -LiteralPath $shadow -Force
    & (Join-Path $PSScriptRoot "freertos_asm_parity.ps1") `
        -FreeRtosKernel $referenceCopy -ReferenceIdentityOnly
} finally {
    if (Test-Path -LiteralPath $referenceCopy) {
        $resolvedCopy = (Resolve-Path -LiteralPath $referenceCopy).Path
        if (($resolvedCopy -ne $referenceCopy) -or
                ((Split-Path -Parent $resolvedCopy) -ne
                    (Split-Path -Parent $referenceCopy)) -or
                ((Split-Path -Leaf $resolvedCopy) -notmatch '^fref-[0-9a-f]{32}$') -or
                ($resolvedCopy -eq $FreeRtosKernel)) {
            throw "Refusing cleanup outside the exact short reference fixture: $resolvedCopy"
        }
        Remove-Item -LiteralPath $resolvedCopy -Recurse -Force
    }
    $referenceEvidence.CleanupCompleted = -not (Test-Path -LiteralPath $referenceCopy)
    $referenceEvidence.LiveIndexSha256After =
        (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash
    $referenceEvidence | ConvertTo-Json |
        Set-Content -LiteralPath $referenceEvidencePath -Encoding ASCII
}
if ((Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash -ne $indexBefore) {
    throw "A19 tests mutated the live reference index"
}

# Evaluate only the matrix's real mode/argument assignments, never its body.
# Assert the effective optimization and let GCC independently verify its macro.
$tokens = $null
$parseErrors = $null
$matrixAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot "compile_matrix.ps1"), [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) { throw "Cannot parse central matrix" }
foreach ($functionName in @("Test-ArmCm55fMpuRuntimeIntegration",
        "Test-ArmCm55MvefMpuRuntimeIntegration")) {
    $function = $matrixAst.Find({ param($node)
        ($node -is [Management.Automation.Language.FunctionDefinitionAst]) -and
            ($node.Name -eq $functionName)
    }, $true)
    if ($null -eq $function) { throw "Missing matrix function $functionName" }
    $assignments = @{}
    foreach ($name in @("modes", "baseArgs")) {
        $assignment = @($function.FindAll({ param($node)
            ($node -is [Management.Automation.Language.AssignmentStatementAst]) -and
                ($node.Left.Extent.Text -eq ('$' + $name))
        }, $true))
        if ($assignment.Count -ne 1) { throw "Ambiguous matrix assignment $functionName/$name" }
        $assignments[$name] = $assignment[0].Right.Extent.Text
    }
    $modes = & ([scriptblock]::Create($assignments['modes']))
    $profileDir = $work
    $CmsisPath = $CmsisCore
    $probeDir = $work
    $warningArgs = @()
    $manifestDefines = @()
    foreach ($mode in $modes) {
        $ltoArgs = if ($mode.Lto) { @("-flto") } else { @() }
        $baseArgs = @(& ([scriptblock]::Create($assignments['baseArgs'])))
        $expected = if ($mode.Name -eq "softfp-os") { "-Os" } else { "-O2" }
        $effective = @($baseArgs | Where-Object { $_ -match '^-O' })
        if (($effective.Count -ne 1) -or ($effective[0] -ne $expected)) {
            throw "A18 matrix effective flags differ from mode: $functionName/$($mode.Name)"
        }
        $label = "$functionName-$($mode.Name)"
        $baseArgs | Set-Content -LiteralPath (Join-Path $work "$label.flags.txt") -Encoding ASCII
        $expectSize = if ($expected -eq "-Os") { 1 } else { 0 }
        $null = Invoke-OwnerTool $ArmGcc ($baseArgs + @(
            "-DFIBER_OWNER_EXPECT_SIZE=$expectSize", "-c",
            (Join-Path $PSScriptRoot "fixtures\owner_optimization_probe.c"),
            "-o", (Join-Path $work "$label.o")))
        Write-Host "PASS A18 effective $expected $label"
    }
}

$secureDir = Join-Path $RepositoryRoot "fiber\port\ARM_CM33\secure"
$secureSymbols = @(
    "fiber_secure_gateway_v1_abi_version", "fiber_secure_gateway_v1_context_port_id",
    "fiber_secure_gateway_v1_context_layout_version", "fiber_secure_gateway_v1_context_feature_mask",
    "fiber_secure_context_gateway_v1_abi_version", "fiber_secure_context_gateway_v1_stack_alignment",
    "fiber_secure_context_gateway_v1_max_stack_bytes", "fiber_secure_context_gateway_v1_max_contexts",
    "fiber_secure_context_gateway_v1_initialize", "fiber_secure_context_gateway_v1_allocate",
    "fiber_secure_context_gateway_v1_load", "fiber_secure_context_gateway_v1_save",
    "fiber_secure_context_gateway_is_runtime_exception",
    "fiber_secure_context_pool_boot_initialize", "fiber_secure_context_pool_allocate",
    "fiber_secure_context_pool_lookup_owned", "fiber_secure_context_pool_fail_closed",
    "fiber_secure_context_pool_clear_record", "fiber_secure_context_pool_clear_stack",
    "fiber_secure_context_pool_record_is_free", "fiber_secure_context_pool_write_stack_seal",
    "fiber_secure_context_pool_stack_seal_is_valid", "fiber_secure_context_pool_record_is_valid",
    "fiber_secure_context_pool_c33s_v1_cohort_provider"
)
$forbidden = '__cyg_profile_func_|__stack_chk_|__gcov|__ubsan_|__asan_|__tsan_|' +
    '__sanitizer_cov|__gnu_mcount_nc|\bmcount\b|__morestack|__chkstk|__aeabi_|\bmem(?:set|cpy|move)\b'
$adversarial = @("-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs",
    "-ftest-coverage", "-fsanitize=undefined", "-fsanitize-coverage=trace-pc",
    "-pg", "-fstack-check=generic")
$counterFlags = @("-fno-instrument-functions", "-fno-stack-protector",
    "-fno-profile-arcs", "-fno-test-coverage", "-fno-sanitize=all",
    "-fno-sanitize-coverage=trace-pc", "-fno-profile", "-fno-stack-check", "-mgeneral-regs-only")
$sources = @(
    (Join-Path $secureDir "fiber_secure_gateway.c"),
    (Join-Path $secureDir "fiber_secure_context_gateway.c"),
    (Join-Path $secureDir "fiber_secure_context_pool.c"),
    (Join-Path $PSScriptRoot "fixtures\arm_cm33_secure_gateway_secure_probe.c")
)
foreach ($mode in @(
        [pscustomobject]@{ Name = "o0"; Optimization = "-O0"; Lto = $false },
        [pscustomobject]@{ Name = "o2"; Optimization = "-O2"; Lto = $false },
        [pscustomobject]@{ Name = "os"; Optimization = "-Os"; Lto = $false },
        [pscustomobject]@{ Name = "o2-lto"; Optimization = "-O2"; Lto = $true },
        [pscustomobject]@{ Name = "os-lto"; Optimization = "-Os"; Lto = $true })) {
    $modeDir = Join-Path $work ("secure-" + $mode.Name)
    New-Item -ItemType Directory -Path $modeDir | Out-Null
    $ltoArgs = if ($mode.Lto) { @("-flto") } else { @() }
    $compileArgs = @("-mcpu=cortex-m33", "-mthumb", "-mcmse", "-mfloat-abi=soft",
        "-std=gnu11", $mode.Optimization, "-ffreestanding", "-fno-builtin", "-fno-common",
        "-ffunction-sections", "-fdata-sections", "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror",
        "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3u",
        "-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES=256u",
        "-I$(Join-Path $PSScriptRoot 'fixtures\owner_secure')", "-I$secureDir",
        "-I$RepositoryRoot", "-I$CmsisCore") + $ltoArgs + $adversarial + $counterFlags
    $compileArgs | Set-Content -LiteralPath (Join-Path $modeDir "flags.txt") -Encoding ASCII
    $objects = @()
    foreach ($source in $sources) {
        $object = Join-Path $modeDir (([IO.Path]::GetFileNameWithoutExtension($source)) + ".o")
        $null = Invoke-OwnerTool $ArmGcc ($compileArgs + @("-c", $source, "-o", $object))
        $objects += $object
        if (-not $mode.Lto) {
            $objectText = Add-BoundCallRelocationTargets (
                (Invoke-OwnerTool $objdump @("-dr", $object)) -join "`n")
            $objectText | Set-Content -LiteralPath ($object + ".dis") -Encoding ASCII
            if ($objectText -match $forbidden) { throw "A17 forbidden dependency in $object" }
            if ([IO.Path]::GetFileName($object) -eq "fiber_secure_context_gateway.o") {
                foreach ($gateway in @("allocate", "load")) {
                    $body = Get-DisassemblyFunctionBody -Disassembly $objectText `
                        -Symbol "fiber_secure_context_gateway_v1_$gateway" -Path $object
                    Assert-OrderedPatterns -Body $body -Patterns @(
                        '\bbl\s+[^\r\n]*fiber_secure_context_gateway_is_runtime_exception',
                        'fiber_secure_context_pool_') -Label "A17 real object gateway $gateway"
                }
            }
        }
    }
    $elf = Join-Path $modeDir "secure.elf"
    $import = Join-Path $modeDir "secure-import.o"
    $null = Invoke-OwnerTool $ArmGcc ($compileArgs + @("-nostdlib", "-Wl,--gc-sections",
        "-Wl,--cmse-implib", "-Wl,--out-implib,$import",
        "-Wl,-Map,$(Join-Path $modeDir 'secure.map')",
        "-Wl,-T,$(Join-Path $PSScriptRoot 'fixtures\arm_cm33_secure_gateway_secure.ld')",
        "-Wl,-T,$(Join-Path $secureDir 'fiber_secure_context_cohort_contract.ld')",
        '-Wl,--section-start=.gnu.sgstubs=0x0C010000') +
        $objects + @("-o", $elf))
    $undefined = @(Invoke-OwnerTool $nm @("-u", $elf))
    if ($undefined.Count -ne 0) { throw "A17 Secure ELF has unresolved dependencies: $undefined" }
    $symbols = (Invoke-OwnerTool $nm @("-a", $elf)) -join "`n"
    $disassembly = (Invoke-OwnerTool $objdump @("-d", $elf)) -join "`n"
    $symbols | Set-Content -LiteralPath (Join-Path $modeDir "secure.nm") -Encoding ASCII
    $disassembly | Set-Content -LiteralPath (Join-Path $modeDir "secure.dis") -Encoding ASCII
    foreach ($symbol in $secureSymbols) {
        if ($symbols -notmatch ('(?m)\b[tT]\s+' + [regex]::Escape($symbol) + '$')) {
            throw "A17 complete Secure companion lost sensitive function $symbol ($($mode.Name))"
        }
    }
    if (($symbols + "`n" + $disassembly) -match $forbidden) {
        throw "A17 final Secure ELF acquired forbidden compiler/runtime support ($($mode.Name))"
    }
    if ($disassembly -match '(?mi)\s(?:vldr|vstr|vldm|vstm|vmov|vpush|vpop|vadd|vsub|vmul|vdiv|vmsr|vmrs)\S*\s|\sblx\s+r\d+') {
        throw "A17 Secure companion has implicit FP/MVE or indirect calls ($($mode.Name))"
    }
    foreach ($call in [regex]::Matches($disassembly, '(?m)\sbl(?:\.w)?\s+[0-9a-f]+\s+<(?<target>[^>]+)>')) {
        $target = $call.Groups['target'].Value -replace '^__acle_se_', '' -replace '\+.*$', ''
        if ($secureSymbols -notcontains $target) {
            throw "A17 unexpected Secure call-graph edge to $target ($($mode.Name))"
        }
    }
    Write-Host "PASS A17 complete Secure companion/call graph $($mode.Name)"
}
# No unsupported-build runtime claim: this object is never linked or executed.
# It just establishes that the forbidden-dependency detector sees active flags.
$negativeObject = Join-Path $work "unannotated-negative.o"
$negativeArgs = @("-mcpu=cortex-m33", "-mthumb", "-mcmse", "-mfloat-abi=soft",
    "-O2", "-ffreestanding") + $adversarial + @("-c",
    (Join-Path $PSScriptRoot "fixtures\owner_sensitive_negative.c"), "-o", $negativeObject)
$null = Invoke-OwnerTool $ArmGcc $negativeArgs
$negativeDisassembly = (Invoke-OwnerTool $objdump @("-dr", $negativeObject)) -join "`n"
$negativeDisassembly | Set-Content -LiteralPath ($negativeObject + ".dis") -Encoding ASCII
if ($negativeDisassembly -notmatch $forbidden) {
    throw "A17 forbidden-dependency detector did not see the deliberately contaminated control"
}
Write-Host "PASS A17 forbidden-dependency detector contaminated-object control (not executed)"

# Replay the five actual production Secure parity assertions, including the
# relocated helper call, at O2 and Os. This is not the whole matrix/parity grid.
$parityTry = @($parityAst.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst]
})
if ($parityTry.Count -ne 1) { throw "Ambiguous production parity body" }
$statements = @($parityTry[0].Body.Statements)
$first = -1
$last = -1
for ($index = 0; $index -lt $statements.Count; ++$index) {
    if ($statements[$index].Extent.Text -eq '$pair = $compiled["ARM_CM33_SECURE_CONTEXT_ALLOCATOR"]') {
        $first = $index
    }
    if ($statements[$index].Extent.Text -eq '$pair = $compiled["ARM_CM33_SECURE_CONTEXT_SVC"]') {
        $last = $index
    }
}
if (($first -lt 0) -or ($last -le $first)) { throw "Cannot locate production Secure parity assertions" }
$ledger = Get-Content -LiteralPath (Join-Path $RepositoryRoot "FREERTOS_ASM_PARITY.md") -Raw
foreach ($optimization in @("-O2", "-Os")) {
    $modeDir = Join-Path $work ("secure-" + $optimization.Substring(1).ToLowerInvariant())
    $referenceObjects = @{}
    foreach ($source in @("secure_context.c", "secure_context_port.c", "secure_init.c")) {
        $object = Join-Path $modeDir ("reference-" + $source + ".o")
        $null = Invoke-OwnerTool $ArmGcc @(
            "-mcpu=cortex-m33", "-mthumb", "-mcmse", "-mfloat-abi=soft", "-std=gnu11",
            $optimization, "-ffreestanding", "-fno-builtin", "-fno-common",
            "-ffunction-sections", "-fdata-sections",
            "-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=1",
            "-I$(Join-Path $PSScriptRoot 'fixtures\freertos_asm_parity')",
            "-I$(Join-Path $FreeRtosKernel 'include')", "-I$secureReference",
            "-c", (Join-Path $secureReference $source), "-o", $object)
        $referenceObjects[$source] = $object
    }
    $compiled = @{}
    foreach ($case in @(
            [pscustomobject]@{ Name = "ALLOCATOR"; Source = "secure_context.c" },
            [pscustomobject]@{ Name = "DEPRIORITIZE"; Source = "secure_init.c" },
            [pscustomobject]@{ Name = "INITIALIZE"; Source = "secure_context.c" },
            [pscustomobject]@{ Name = "LOAD"; Source = "secure_context_port.c" },
            [pscustomobject]@{ Name = "SAVE"; Source = "secure_context_port.c" })) {
        $fiberObject = Join-Path $modeDir "fiber_secure_context_gateway.o"
        $referenceObject = $referenceObjects[$case.Source]
        $compiled["ARM_CM33_SECURE_CONTEXT_" + $case.Name] = [pscustomobject]@{
            FiberPath = $fiberObject
            Fiber = Get-ObjectDisassembly $objdump $fiberObject
            ReferencePath = $referenceObject
            Reference = Get-ObjectDisassembly $objdump $referenceObject
        }
    }
    for ($index = $first; $index -lt $last; ++$index) {
        . ([scriptblock]::Create($statements[$index].Extent.Text))
    }
    Write-Host "PASS production Secure parity assertions $optimization"
}
Write-Host "Owner evidence retained: $work"
Write-Host "PASS owner guards A17/A18/A19 (codegen/link/reference checks only; no target execution)"
