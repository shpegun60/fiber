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
#define FIBER_VALIDATE_SCHEDULED_CONTEXT 1
#define FIBER_VALIDATE_EXCEPTION_SETUP 1
```

Performance-mode runs may be recorded separately, but they must not replace the
conservative run.

Before a board run:

- `tools/compile_matrix.ps1` must pass.
- The STM32H7 application build must pass.
- `git diff --check` must pass.
- Source and docs changed by the validation commit must stay ASCII-only.

## Startup Exception Setup

`fiber_pendsv_init_lowest_priority()` must complete without panic on the
validated STM32H7 build.

The runtime check must cover:

- PendSV priority reads back as the lowest priority.
- PendSV vector routing matches the configured wrapper/direct mode.
- SVC vector routing matches the configured policy.
- `FIBER_SCHEDULER_BASEPRI` uses only implemented NVIC priority bits.
- `AIRCR.PRIGROUP` is compatible with the scheduler `BASEPRI` policy.
- affected Cortex-M7 r0p0/r0p1 CPUID values require
  `FIBER_CORTEX_M7_R0P1_ERRATA_837070=1`.

Expected setup panic codes when deliberately misconfigured:

- `'Y'`: PendSV vector mismatch.
- `'y'`: SVC vector mismatch.
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
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_NULL_NEXT
#define FIBER_VALIDATION_MODE FIBER_VAL_TRAP_BAD_CONTEXT
```

`fiber_live.validation_mode_seen` records the selected mode, and
`fiber_live.expected_panic_code` records the expected panic code for trap modes.

Validate these cases from Thread mode:

- `fiber_scheduler_set_pick_next(valid_hook, user)` before start succeeds.
- `fiber_scheduler_set_pick_next(NULL, user)` traps with `'K'`.
- changing the hook after `fiber_start()` has seeded the current context traps
  with `'k'`.

The hook must be a bounded scheduler picker. It must not block, allocate, throw
C++ exceptions across the C ABI, call fiber scheduling APIs recursively, or
return `NULL`.

## First Start

Validate these cases:

- `fiber_start(ctx)` without a configured scheduler hook traps with `'K'`.
- `fiber_start(ctx)` with a valid hook seeds `fiber_current()` and enters the
  first fiber.
- pre-start floating-point work does not leak `CONTROL.FPCA` into the first
  fiber when an FP context exists.

## Scheduler Jump API

Validate these `fiber_schedule()` cases:

- normal Thread-mode scheduler jump succeeds.
- calling from Handler mode traps with `'i'`.
- calling while `PRIMASK != 0` traps with `'p'`.
- calling while `BASEPRI != 0` traps with `'b'` on BASEPRI-capable cores.

No real scheduler jump may be silently delayed behind interrupt masks.

## PendSV Scheduler Result Validation

During PendSV, the port saves the runtime-owned current context, enters the
port scheduler critical section, calls
`fiber_internal_scheduler_pick_next_from_pendsv(current)`, validates the
returned context, and restores only that context.

Validate these scheduler result cases:

- valid returned context switches correctly.
- returned `NULL` traps with `'N'`.
- returned context with `sp == NULL` traps with `'P'`.
- returned context with invalid saved-frame alignment traps with `'A'`.
- returned context with out-of-bounds saved stack pointer traps with `'U'` or a
  related stack-bound panic code.
- returned context with invalid `EXC_RETURN` signature or wrong Thread/PSP bits
  traps with `'X'` or `'x'`.
- returned context with insufficient software, hardware, or extended-FP frame
  headroom traps before exception return.
- returned context with an unsealed or corrupted boot record traps before PSP is
  restored.

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

After any behavior-affecting change to `fiber_core.c`, `fiber_port_state.c`,
`fiber_port_armv7em.c`, exception setup validation, feature policy gates, stack
layout, scheduler hook semantics, or startup code, the STM32H7 validation label
must be downgraded until this checklist passes again on hardware.
