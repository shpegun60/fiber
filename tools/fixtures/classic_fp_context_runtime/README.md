# Classic FP Context Runtime

The captured CM4F complete suite is accepted in
`PORT_ARCHITECTURE_AUDIT.md#post-context-cm4f-fp-runtime`. The matrix dispatches it
only with an explicit QEMU root. The accepted CM0 gate remains separate.
Acceptance describes the exact retained snapshot, not every later worktree.

## First Target

The first target is QEMU `mps2-an386`, Cortex-M4F with `fpv4-sp-d16` and hard-float
ABI. Actual CPUID, required MVFR0 capability fields, memory geometry and FP
behavior must be observed and checked; a machine name alone is insufficient.
MVFR1 is additionally recorded, not comprehensively validated. The QEMU
manifest uses eight priority bits, PendSV priority `0xFF` and scheduler BASEPRI
`0x80`; it is not an STM32G4 priority-width manifest. This is a CPU execution
fixture, not STM32G4 peripheral or board qualification. Softfp and subsequent
CM7/H7/H7S execution require separate applicable evidence. The subsequent
CM7/AN500 gate has its own fixture, entry point and captured receipt at
`PORT_ARCHITECTURE_AUDIT.md#post-context-cm7-fp-runtime`; it does not inherit
this CM4 receipt. A shared immutable Profile selects its inputs without copying
or weakening the bounded `Image` checker. Thirty-two synthetic discriminator
controls reject cross-profile terminals, capability flags, cohorts and mask
sequences; they are not additional firmware executions.

Use the real Context engine/state/panic providers and actual `ARM_CM4` backend.
The Fiber variant adds the real Fiber v1 consumer and configuration provider.
No fixture may replace a forward operation, reverse service, current slot or
production exception handler. Only reset/fault terminals, memory-map hooks and
the application policy belong to the fixture.

## Oracle Boundary

Three workers comprise two distinct FP-active contexts and one FP-inactive
context. Static storage, guards, arguments, current identities, self-selection,
bidirectional transfer, basic/extended frames and Thread/PSP continuation must
be checked. The inactive worker and its executed helper paths must avoid FP
instructions; inspecting FPSCR with an FP instruction would itself change the
state being tested.

Keep two separate assembly phases. The public-yield phase checks callee-saved
GPRs and S16-S31. It does not invent a C ABI promise that S0-S15 or FPSCR survive
an arbitrary C call. The direct-PendSV supplement reseeds FP payload/FPSCR and
checks all S0-S31, FPSCR, GPRs and stack state immediately after continuation,
before another C call or restoring epilogue can mask corruption.

Eager/lazy policy readback is not lazy-stacking execution evidence. Validation
map-hook builds may observe FPCCR, core integer state and PSP during the real
pre-save validator, before the production handler's first FP instruction. Such
an observer must not execute FP, call Context/Fiber APIs, or change CPU state.
It may update its own fixture report and defer semantic assertions. Distinguish
Handler CONTROL from resumed Thread CONTROL; do not infer one from the other.
The normal hash/map 0/0 path must remain separately exercised.

Three noipa/GRO capture helpers use constant worker indices. The generated-code
checker admits writes only within the exact fixture report/arm objects or
matched allocated stack slots; unknown indexed/writeback/store forms fail.
Calls require exact function entry, internal branches require decoded instruction
boundaries, and returns require incoming-LR/stack provenance. Reachable function
or literal-pool fallthrough rejects. This is a bounded fixture proof, not a
general pointer-range analyser or formal verification of the kernel.

## Required Proof

The required positive grid is Context/Fiber, O2/Os, ordinary/final-linked LTO,
direct/archive links, eager/lazy and primary 0/0 versus validation 1/1 policies.
This is 64 positive executions. Seven actual-production mutations across the
32 primary-policy tuples add 224 executions, for a literal total of 288. The
runner must enforce that grid and exact case/reason map, not derive completeness
only from whatever happened to execute. Development smoke runs nine executions
and must retain `CompleteSuite=false`.

### Opt-In Seven-Mode Grid

`-FullOptimizationGridFP` independently selects five ordinary modes
`O0/Og/O2/Os/O3` and native final-linked LTO at O2/Os only. It does not multiply
all five optimizations by LTO, change the default O2/Os grid, or expand the
central matrix's conditional dispatch. Each profile has 56 primary tuples:
two consumers, seven modes, direct/archive and eager/lazy. Primary/validation
positives produce 112 executions; seven primary-only production mutants add
392, for 504 target executions. Fourteen actual pinned upstream final ELFs
provide 112 positive/reference associations and remain link-only.

| Request | Target executions | Upstream ELFs | Associations | CompleteSuite |
| --- | --- | --- | --- | --- |
| Default | 288 | 8 | 64 | true |
| Default + DevelopmentSmoke | 9 | 8 | 2 | false |
| FullOptimizationGridFP | 504 | 14 | 112 | true |
| FullOptimizationGridFP + DevelopmentSmoke | 11 | 14 | 4 | false |

Literal tuple/option controls and both launchers distinguish these requests;
an incomplete development result cannot become a qualification receipt. Neither
the `Image` checker nor its 32 compiled observer controls changes for this mode.

Actual-port O0 CPACR code spills constants and uses register ORR, so this one
new tuple uses a separate bounded dataflow oracle. Every decoded normal exit
must follow an exact CPACR word read/OR/store or an exact already-full-mask
read guard. Constant/allocated-stack provenance, path intersection and flag
effects are tracked; reclaimed/call-crossing spills and nonconstant BIC RHS
cannot provide admission. Unsupported conditional calls fail closed. This is
not a general pointer, arbitrary callee or whole-provider semantic proof.
The other modes and upstream references retain their existing bounded
immediate mask/address/store patterns.

Thirty-six source-derived/assembly CPACR controls are separately compiled at
O0/O2: eight accepted positives and twenty-eight exact assigned rejections.
They cover wrong mask/address/width, unresolved stores, unrelated masks,
branch/IT skips, stale spills, conditional calls, missing normal exits and
inverted BIC guards. These are static checker controls, not extra target
executions or a changed production port. A successful full opt-in run still
does not establish non-FP profiles, softfp/MPU, all-configuration/global
FreeRTOS equivalence, hosted CI or board qualification.

Compile causal mutations of actual register save/restore and publication code.
Preserve frame geometry and required lazy-state materialization when isolating
a high-FP-store omission. A compile error, incidental frame panic, arbitrary
fault or timeout must not qualify a register-integrity control.

Retain exact inputs/dependencies, installed tool and resolved QEMU-library
identities, source/object roles, native final ELFs/disassembly, strong vectors,
public/profile expectations, prelink common-private ownership and strict
terminal outcomes. Preserve failed attempts and reject source/tool drift.
No automatic provisioning or board access is part of this gate.

The separate reference fixture links the actual pinned FreeRTOS CM4F port.
Reference boundary providers must fail-stop and remain explicitly link-only.
Upstream initialization selects lazy preservation; Fiber's eager policy is an
intentional documented difference, not a second upstream eager implementation.
Pair final ELFs at the selected optimization/LTO/link tuples without claiming
byte equality or execution of the complete FreeRTOS scheduler.

The default grid has eight distinct upstream final ELFs, not 64 upstream policy
modes; the opt-in grid has fourteen, not 112 upstream policy modes.
Each positive execution is associated with exactly one matching optimization,
LTO and link tuple. Ordered save/restore, conditional FP transfer, BASEPRI,
first-SVC and bounded CPACR evidence do not constitute closed-body equivalence.

## Invocation

Use existing explicit compiler, CMSIS, pinned reference and WSL QEMU inputs:

```powershell
& tools/test_classic_fp_context_runtime.ps1 `
    -ArmGcc $env:ARM_NONE_EABI_GCC `
    -CmsisCore $env:CMSIS_CORE_INCLUDE `
    -FreeRtosRoot $env:FREERTOS_KERNEL_REFERENCE `
    -QemuRoot '/absolute/existing/qemu-prefix' `
    -WslDistro Ubuntu-24.04 `
    -BuildRoot 'C:\fresh-cm4f-evidence'
```

The output directory must not already exist. The runner does not install tools,
download packages, program boards or reuse earlier PASS records. Add
`-DevelopmentSmoke` only for development; it cannot satisfy full qualification.
Add `-FullOptimizationGridFP` for the separate seven-mode grid described above;
the ordinary invocation and default matrix continue to select the original grid.
Preserve every failed or superseded output directory. Acceptance additionally
requires independent review of the captured inputs, complete receipt and
actual final-ELF evidence; successful execution alone does not certify a
checker whose scope or fail-closed behavior is still under repair.
