# CM7 FP Context Runtime

This is the separate Cortex-M7 adaptation of the maintained classic FP runtime
gate. The full captured receipt is recorded in
`PORT_ARCHITECTURE_AUDIT.md#post-context-cm7-fp-runtime`. Preparation compiles
and development runs alone are not a complete qualification. Acceptance is
specific to retained inputs/artifacts; the CM4F receipt does not qualify this
profile and later worktrees do not inherit PASS automatically.

## Exact Model And Backend

Use QEMU `mps2-an500`, explicit `-mcpu=cortex-m7 -mfpu=fpv5-d16` and hard-float
ABI, the real Context engine/state/panic providers, and the actual
`fiber/port/ARM_CM7/r0p1` backend. Fiber rows additionally use the real Fiber v1
consumer and optional configuration provider. Do not replace either directional
ABI, current slot, scheduler bridge, or production exception handlers.

The firmware reads and requires the model's exact CPU/FP identification:

```text
CPUID  = 0x411FC272 (Cortex-M7 r1p2)
MVFR0  = 0x10110221
MVFR1  = 0x12000011
MVFR2  = 0x00000040
```

The additional exact `MODEL:CM7F` terminal line must not be supplied by the host
or inferred from a manifest. The fixture manifest uses eight implemented priority
bits, PendSV `0xFF` and scheduler BASEPRI `0x80`. These are model facts, not H7/H7S
device-priority-width, cache, TCM, peripheral, board, interrupt-timing or erratum
effectiveness evidence. The selected r0p1 backend's PRIMASK-preserving sequence
is exercised on this r1p2 model; no affected r0p0/r0p1 silicon is present.

## Execution And Observation

Keep the same three-worker oracle as the CM4F gate: two distinct FP-active
workers and one general-register-only worker; self-selection and all directed
worker transfers; guards, current identities, stack geometry and continuation.
The C-call yield phase checks the AAPCS callee-saved register contract. The
separately reseeded assembly-only direct-PendSV phase observes all S0-S31,
FPSCR, GPRs and SP before another C call or restoring epilogue can hide damage.
S0-S31 bit-pattern preservation covers the D0-D15 storage bits, not double-
precision arithmetic accuracy or timing.

The live core hardware frame begins at PSP; low FP words begin at PSP+32 and
FPSCR is at PSP+96. Validation-policy map hooks observe FPCCR before the first
backend FP instruction in PendSV, without changing CPU state or calling a
Context/Fiber API.
Only exact report/arm stores and matched allocated stack slots are admitted by
the bounded generated-code checker. Unknown stores, PC writes, interior calls,
undecoded branch targets and reachable function/literal fallthrough reject.
Handler CONTROL is recorded separately from resumed Thread FPCA.

The required full grid is O2/Os x ordinary/final-linked LTO x direct/archive x
Context/Fiber x eager/lazy x primary hash/map 0/0 or validation 1/1: 64 positive
executions. Seven compiled production mutations across the 32 primary tuples
add 224 exact causal failures, for 288 total. Wrong panic, incidental fault,
timeout or compile failure is not an oracle success. Development smoke retains
`CompleteSuite=false` and cannot satisfy this full grid.

An explicit `-FullOptimizationGridFP` selects the separate seven-mode grid:
ordinary O0/Og/O2/Os/O3 plus O2/Os native final LTO. It has 112 positive and
392 compiled-causal target executions (504 total), fourteen link-only upstream
ELFs and 112 associations. Combining it with `-DevelopmentSmoke` instead runs
eleven executions/four associations with fourteen references and explicitly
`CompleteSuite=false`. The default 288/8/64 inventory and ordering are unchanged.
See the shared fixture's
[CPACR and option-oracle boundary](../classic_fp_context_runtime/README.md#opt-in-seven-mode-grid)
for the unchanged `Image`/observer checks and the separate 36 compiled controls.
Only actual-port full-grid O0 uses the new bounded spill/guard CPACR proof;
upstream and the other modes retain their existing bounded patterns. This is
not a global profile/ABI or whole-provider equivalence claim.

## Actual Upstream Comparison

The separate `reference/` fixture links the unmodified pinned
`portable/GCC/ARM_CM7/r0p1/port.c` and real upstream headers at
`a50edad08b29052631aa469d4df6e6ec7ff68878`. It supplies fail-stop unavailable-
kernel boundaries, not a working TCB or scheduler. The default eight upstream
final ELFs cover O2/Os x ordinary/LTO x direct/archive, paired with the 64
consumer rows. The opt-in grid uses fourteen reference ELFs and 112 associations.
They are not executed or complete FreeRTOS runtime tests.

Retain separate M7 BASEPRI checks. Upstream PendSV uses `cpsid i`, BASEPRI,
DSB/ISB, and unconditional `cpsie i`, then later clears BASEPRI to zero. The
Fiber backend intentionally preserves/restores incoming PRIMASK and the saved
scheduler BASEPRI. Eager initialization is another explicit difference from
upstream's always-lazy initialization. Ordered mechanisms, conditional FP
transfers, vectors, first SVC and bounded CPACR evidence are not byte equality,
closed whole-provider equivalence or a global all-optimization parity proof.

## Invocation And Evidence

```powershell
& tools/test_classic_cm7_fp_context_runtime.ps1 `
    -ArmGcc $env:ARM_NONE_EABI_GCC `
    -CmsisCore $env:CMSIS_CORE_INCLUDE `
    -FreeRtosRoot $env:FREERTOS_KERNEL_REFERENCE `
    -QemuRoot '/absolute/existing/qemu-prefix' `
    -WslDistro Ubuntu-24.04 `
    -BuildRoot 'C:\fresh-cm7-evidence'
```

Use an absent output path and already-installed explicit tools. No provisioning,
download, board programming or PASS reuse is performed. Preserve all failed
attempts. Source/dependency/tool/QEMU-library identities, object ownership,
actual final ELF bytes/disassembly, exact terminal outcomes and full artifact
hashes must remain stable through finalization. A shared checker refactor also
requires a fresh independent CM4F replay; its historical receipt stays intact.
Add `-FullOptimizationGridFP` to request the opt-in expansion, never to relabel
an old default or development receipt as the complete seven-mode qualification.
