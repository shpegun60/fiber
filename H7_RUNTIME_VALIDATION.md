# STM32H7 Runtime Validation Checklist

This checklist is the hardware gate for claiming that the v2 scheduler-driven
ARMv7E-M path is validated on STM32H7 / Cortex-M7.

It was added after commit `775648c` because that checkpoint changed more than
feature policy gates. It integrated the pure scheduler-driven execution model,
removed the public direct target-switch path, moved ARMv7E-M switching behind
the port boundary, added handler-side scheduler critical sections, and enabled
runtime exception setup validation. Compile checks are necessary, but they do
not prove this execution model on hardware.

## Required Build State

Run the validation first with portable conservative defaults:

```c
#define FIBER_FPU_LAZY 0
#define FIBER_SWITCH_MASK_IRQS 1
#define FIBER_SWITCH_STRICT_BARRIERS 1
#define FIBER_STACK_CANARY 1
#define FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH 0
#define FIBER_VALIDATE_EXCEPTION_SETUP 1
```

Performance-mode runs may be recorded separately, but they must not replace the
conservative run.

Before a board run:

- `tools/compile_matrix.ps1` must pass.
- The STM32H7 application build must pass.
- `git diff --check` must pass.
- Source and docs changed by the validation commit must stay ASCII-only.
- Any behavior-changing first-start or PendSV change must get a fresh board run;
  earlier recorded results become historical until the new checkpoint passes.

## Startup Exception Setup

`fiber_pendsv_init_lowest_priority()` must complete without panic on the
validated STM32H7 build.

The runtime check must cover:

- PendSV priority reads back as the lowest priority.
- SVCall priority reads back as highest priority.
- PendSV vector routing matches the configured wrapper/direct mode.
- SVC vector routing matches the configured policy.
- the selected port scheduler BASEPRI threshold uses only implemented NVIC
  priority bits.
- `AIRCR.PRIGROUP` is compatible with the scheduler `BASEPRI` policy.
- affected Cortex-M7 r0p0/r0p1 CPUID values require
  `FIBER_CORTEX_M7_R0P1_ERRATA_837070=1`.

Expected setup panic codes when deliberately misconfigured:

- `'Y'`: PendSV vector mismatch.
- `'y'`: SVC vector mismatch.
- `'w'`: SVCall priority is not highest.
- `'Q'`: scheduler `BASEPRI` masks no implemented priority bits.
- `'q'`: scheduler `BASEPRI` contains unimplemented priority bits.
- `'g'`: priority grouping or priority threshold is incompatible.
- `'7'`: affected Cortex-M7 r0p0/r0p1 core without the errata gate.

## Scheduler Hook API

The board harness uses compile-time validation modes:

```c
#define FIBER_VALIDATION_MODE FIBER_VAL_NORMAL_RUN
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_NO_HOOK
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_NULL_HOOK
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_HOT_SWAP
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_PRIMASK
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_BASEPRI
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_NULL_FIRST
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_BAD_FIRST
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_NULL_NEXT
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_BAD_NEXT
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_FAULTMASK
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_CANARY
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_BAD_EXC_RETURN
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_SHORT_FRAME
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_BAD_BOOT
```

`fiber_live.validation_mode_seen` records the selected mode, and
`fiber_live.expected_panic_code` records the expected panic code for trap modes.

The current STM32H7 board harness lives in the embedding application tree, not
inside this repository:

```text
h7s_fiber_test/Boot/app_core/app_core.cpp
```

This repository documents the required validation modes and expected results.
The embedding application must keep its board harness in sync until a
standalone board-validation example is added to this repository.

Validate these cases from Thread mode:

- `fiber_scheduler_set_pick_next(valid_hook, user)` before start succeeds.
- `fiber_scheduler_set_pick_next(NULL, user)` traps with `'K'`.
- changing the hook after `fiber_start()` has seeded the current context traps
  with `'k'`.

The hook must be a bounded scheduler picker. It must not block, allocate, throw
C++ exceptions across the C ABI, call fiber scheduling APIs recursively, or
return `NULL`. Define it with `FIBER_SCHEDULER_HOOK_ATTR`; it must not execute
floating-point or MVE instructions because later calls execute inside PendSV
and the indirect function-pointer call cannot enforce the GCC target attribute.
Apply the same rule to the hook's complete call graph.

The first scheduler call comes from `fiber_start()` with `current == NULL`.
That call selects the first context. Idle and "no work" states must still be
represented by a real initialized `FiberContext`; returning `NULL` is always a
panic condition. The first hook call must run under the same port scheduler
critical-section policy used for PendSV scheduler calls.

## First Start

On ARMv7E-M, the default first-start path is SVC-based. The application must
provide a naked `SVC_Handler()` branch wrapper that reaches `fiber_svc()` while
preserving the original SVC handler LR/EXC_RETURN:

```c
FIBER_ATTR_NAKED_ASM
void SVC_Handler(void)
{
	__ASM volatile("b fiber_svc");
}
```

If the vector table points directly to `fiber_svc()` instead of an application
wrapper, define `FIBER_SVC_VECTOR_DIRECT=1`. `FIBER_VALIDATE_SVC_VECTOR`
defaults to active because SVC is the only first-start path.

The compile matrix covers both wrapper-vector and direct-vector configurations.
This is a build guard only. If a board uses direct vectoring to `fiber_pendsv()`
or `fiber_svc()`, record a separate hardware validation result for that wiring.

Validate these cases:

- `fiber_start()` without a configured scheduler hook traps with `'K'`.
- `fiber_start()` with a valid hook calls the hook with `current == NULL`,
  validates the returned context, seeds `fiber_current()`, and enters the first
  fiber.
- `fiber_start()` with a hook that returns `NULL` for the first context traps
  with `'N'`.
- `fiber_start()` with a hook that returns a context with `sp == NULL` for the
  first context traps with `'P'`.
- pre-start floating-point work does not leak `CONTROL.FPCA` into the first
  fiber when an FP context exists.
- stale pending PendSV is cleared by the start helper before interrupts are
  reopened for SVC.
- fault exceptions are enabled before SVC and `BASEPRI` is cleared inside the
  SVC handler before the first context is restored.
- first entry arrives through SVC exception return, not a direct function call.
- `fiber_port_start_first_context()` does not continue after the `svc`
  instruction. If it does, it traps with `'y'`.
- SVC entry from PSP or rejected first-start CPU state traps with `'l'`.
- an unaligned first-start SVC MSP frame traps with `'l'`.
- wrong SVC opcode or immediate value traps with `'u'`.
- failed PSP/CONTROL verification before first exception return traps with
  `'j'`.

## Scheduler Jump API

Validate these `fiber_schedule()` cases:

- normal Thread-mode scheduler jump succeeds.
- calling from Handler mode traps with `'i'`.
- calling while `PRIMASK != 0` traps with `'p'`.
- calling while `BASEPRI != 0` traps with `'b'` on BASEPRI-capable cores.
- calling while `FAULTMASK != 0` traps with `'f'` on FAULTMASK-capable cores.

No real scheduler jump may be silently delayed behind interrupt masks.

## PendSV Scheduler Result Validation

During PendSV, the port saves the runtime-owned current context, enters the
port scheduler critical section, calls
`fiber_internal_scheduler_pick_next_from_pendsv(current)`, validates the
returned context, and restores only that context.

Validate these scheduler result cases:

- valid returned context switches correctly.
- PendSV entered while Thread mode is not using PSP traps with `'j'`; this
  catches pre-start or foreign PendSV entry before any PSP context is saved.
- live PSP without enough space for the source software frame traps with `'d'`
  before PendSV writes below the current fiber stack base.
- returned `NULL` traps with `'N'`.
- returned context with `sp == NULL` traps with `'P'`.
- returned context with invalid saved-frame alignment traps with `'A'`.
- returned context with out-of-bounds saved stack pointer traps with `'U'` or a
  related stack-bound panic code.
- returned context with an `EXC_RETURN` value outside the exact selected-port
  encoding set traps with `'x'`.
- returned context with insufficient software, hardware, or extended-FP frame
  headroom traps with `'X'` before exception return.
- a damaged low-stack software canary traps with `'c'`, including on ports that
  also provide PSPLIM.
- returned context with an unsealed or corrupted boot record traps before PSP is
  restored.

The harness keeps first-start and later-PendSV result validation separate:

- `FIBER_VAL_TRAP_NULL_FIRST` traps on `pick_next(NULL, user)` with `'N'`.
- `FIBER_VAL_TRAP_BAD_FIRST` traps on `pick_next(NULL, user)` with `'P'`.
- `FIBER_VAL_TRAP_NULL_NEXT` lets first-start enter the first fiber, then traps
  on a later `pick_next(current, user)` with `'N'`.
- `FIBER_VAL_TRAP_BAD_NEXT` lets first-start enter the first fiber, then traps
  on a later `pick_next(current, user)` with `'P'`.
- `FIBER_VAL_TRAP_CANARY` damages the running fiber canary and traps with `'c'`
  when PendSV validates the just-saved current context.
- `FIBER_VAL_TRAP_BAD_EXC_RETURN` damages the next saved exception-return word
  and traps with `'x'` before restore.
- `FIBER_VAL_TRAP_SHORT_FRAME` moves the next saved SP too close to `stack_top`
  and traps with `'X'` before reading or restoring an incomplete frame.
- `FIBER_VAL_TRAP_BAD_BOOT` corrupts the next context's `avail` relationship
  and traps with `'a'` in the mandatory fast structural boot-record check.

## Long-Run H7 Stress

The validation application currently starts from `f2`, then the scheduler hook
selects:

```text
f2 -> f1 -> f3 -> f2
```

The long-run pass criteria are:

- `validation_flags == 0x000001FF`.
- `validation_failures == 0`.
- `last_panic_code == 0`.
- `fiber_current()` matches the running fiber in every entry.
- all three counters keep progressing for millions of switches.
- FP accumulators preserve the expected relationship:
  `fpu_acc2 == 2 * fpu_acc1`, `fpu_acc3 == 3 * fpu_acc1` within the exact test
  loop state.
- `fpu_sink` follows the last updated FP accumulator and stays finite.

Record the exact counter snapshot, settings, board, core revision, compiler
flags, and commit hash with each successful run.

## Current Partial Recorded Result: 2026-07-11

Commit:

```text
208be61157ee3f06ba4b4bfc3be700b37d78eea5
```

This run was recorded after:

- `739469a Harden SVC first-start dispatch checks`;
- `208be61 Document BASEPRI asm scratch register`.

Board/build:

- STM32H7S3 / Cortex-M7 application build;
- wrapper-vector SVC/PendSV wiring;
- debugger stopped the CPU with SIGINT during a normal PendSV switch.

Normal run snapshot:

```text
validation_flags     = 0x000001FF
validation_failures  = 0
last_panic_code      = 0
validation_mode_seen = 0
expected_panic_code  = 0
trigger_count        = 0
counter1             = 1246134
counter2             = 1246135
counter3             = 1246134
fpu_acc1             = 1246134
fpu_acc2             = 2492270
fpu_acc3             = 3738402
fpu_sink             = 2492270
```

The one-count skew between counters is acceptable for this snapshot because
the debugger stopped during `fiber_schedule()` / `fiber_pendsv()`, not at a
round boundary.

Status:

- `FIBER_VAL_NORMAL_RUN` passed on the board for this commit.
- Trap modes still need to be rerun after the SVC dispatch hardening before the
  H7 runtime-validation claim is fully restored for `208be61`.

This record is now historical for the later mandatory-restore-validation
hardening. The current code additionally changes exact `EXC_RETURN` checks,
software-canary checks, full live hardware-frame bounds, FPU register readback,
and exact CM7 source selection. Do not promote the current working state from
this older snapshot. Re-run normal mode and all listed trap modes, including
`CANARY`, `BAD_EXC_RETURN`, `SHORT_FRAME`, and `BAD_BOOT`.

## Superseded Recorded Result: 2026-07-11

This result predates the scheduler-selected first-context API. It is retained
only as an archived hardware observation for the SVC/PendSV fixes listed below.
It is not a validation claim for the current API and must not be used as a pass
record for new changes.

The STM32H7 board run passed the then-current scheduler-driven ARMv7E-M
validation set after the SVC first-start and PendSV source-save corrections.

Normal run:

```text
validation_flags    = 0x000001FF
validation_failures = 0
last_panic_code     = 0
counter1            = counter2 = counter3 = 18832997 or higher in observed runs
fpu_acc2            = 2 * fpu_acc1
fpu_acc3            = 3 * fpu_acc1
```

Trap modes also passed under the then-current harness, but those mode names and
startup semantics are superseded by the current first/next split. Do not treat
that archived trap set as a pass record for the current API.

Two SVC migration defects were found and fixed before this pass:

- the SVC handler must not set `CONTROL.SPSEL` from Handler mode; the first
  Thread-mode PSP entry is selected by the restored `EXC_RETURN` value;
- PendSV must prove that the interrupted Thread context used PSP by checking
  the active `LR`/`EXC_RETURN` bit 2, not by reading `CONTROL.SPSEL`.

Other active/fallback switch paths were audited for the same class of defect:

- ARMv7E-M SVC start now uses `EXC_RETURN` for Thread PSP selection and verifies
  FPCA only as a separate hygiene check;
- ARMv7E-M PendSV checks active `LR`/`EXC_RETURN` bit 2 before saving the source
  context;
- ARMv6-M and non-ARMv7E-M transitional PendSV paths were audited for the same
  source-stack proof and now have compile-covered SVC first-start paths, but
  they remain unsupported until profile-specific hardware validation is
  recorded.

## Performance Mode

After the conservative run passes, STM32H7 performance mode may be tested with:

```c
#define FIBER_FPU_LAZY 1
#define FIBER_SWITCH_MASK_IRQS 0
#define FIBER_SWITCH_STRICT_BARRIERS 0
```

Performance-mode success is target-specific evidence for STM32H7. It does not
change the portable defaults and does not validate M0/M23/M33/M55/MVE paths.

## Claim Rule

After any behavior-affecting change to `fiber_core.c`, `fiber_runtime_state.c`,
the selected `ARM_CM7/r0p1` sources, exception setup validation, feature policy
gates, stack layout, scheduler hook semantics, or startup code, the STM32H7
validation label must be downgraded until this checklist passes again on
hardware.
