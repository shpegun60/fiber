# Fiber Decision Log

## 2026-07-10: v8-M Feature Policy Gates

The v2 runtime now has explicit policy gates for Cortex-M profiles whose
FreeRTOS ports carry extra context state that the current generic fiber context
does not save yet:

- `fiber_feature_policy.h` defines `FIBER_HAS_EXTENDED_FP_CONTEXT`,
  `FIBER_USE_PSPLIM_REGISTER`, `FIBER_HAS_PAC`, and `FIBER_HAS_BTI`.
- MVE-FP follows the extended FP save/restore model. MVE without scalar FP is
  rejected by runtime policy validation because the current assembly does not
  implement an MVE-only register save path.
- PSPLIM register access is no longer implied only by the architecture family.
  `FIBER_USE_PSPLIM_REGISTER` is the actual access gate, keeping M23/security
  variants from accidentally writing an unsupported or wrong-bank PSPLIM.
- ARMv8-M Baseline, ARMv8-M Mainline, ARMv8.1-M, TrustZone/Non-secure bank
  targeting, MVE, and PAC/BTI runtime use all require explicit
  `FIBER_ALLOW_UNVALIDATED_*` opt-in until the matching FreeRTOS-style context
  layout and hardware validation exist.

New policy panic codes:

- `'2'`: ARMv8-M Baseline runtime attempted without explicit unvalidated opt-in.
- `'3'`: ARMv8-M Mainline runtime attempted without explicit unvalidated opt-in.
- `'8'`: ARMv8.1-M runtime attempted without explicit unvalidated opt-in.
- `'v'`: MVE is present without scalar FP support for the current save/restore
  path.
- `'V'`: MVE runtime attempted without explicit unvalidated opt-in.
- `'z'`: TrustZone/Non-secure policy runtime attempted without explicit
  unvalidated opt-in.
- `'J'`: PAC/BTI-capable runtime attempted without explicit unvalidated opt-in.

This does not claim FreeRTOS parity for M23/M33/M55. It closes the dangerous
silent-success path: compile-only support can continue, but unsupported runtime
features now fail early and explicitly.

## 2026-07-10: FreeRTOS-Level Exception Setup Hardening

The v2 runtime now checks exception setup before the first fiber starts:

- `fiber_exception_runtime_check()` is called by
  `fiber_pendsv_init_lowest_priority()` and again by `fiber_start()`.
- PendSV priority must read back as the lowest priority.
- PendSV and SVC vector entries must point at the expected handler symbols.
- The default PendSV model expects an application `PendSV_Handler()` wrapper.
  That wrapper must branch to `fiber_pendsv()` without clobbering
  LR/EXC_RETURN. A normal C wrapper that emits `bl fiber_pendsv` is invalid.
  Direct vectoring to `fiber_pendsv()` is supported with
  `FIBER_PENDSV_VECTOR_DIRECT=1`.
- `FIBER_SCHEDULER_BASEPRI` is validated against the hardware-implemented NVIC
  priority bits using a FreeRTOS-style write/readback probe.
- `AIRCR.PRIGROUP` is validated with the same FreeRTOS-style rule used by the
  Cortex-M ports: scheduler `BASEPRI` assumes priority bits are not split into
  an unsafe subpriority configuration.
- Cortex-M7 r0p0/r0p1 CPUID values trap unless
  `FIBER_CORTEX_M7_R0P1_ERRATA_837070=1` is enabled.

New panic codes:

- `'Y'`: PendSV vector entry mismatch.
- `'y'`: SVC vector entry mismatch.
- `'Q'`: scheduler BASEPRI masks no implemented priority bits.
- `'q'`: scheduler BASEPRI contains unimplemented priority bits.
- `'g'`: priority grouping or 8-bit priority threshold is incompatible with
  the scheduler BASEPRI policy.
- `'7'`: affected Cortex-M7 r0p0/r0p1 core without the BASEPRI errata gate.

Portable defaults are conservative again:

- `FIBER_FPU_LAZY = 0`;
- `FIBER_SWITCH_MASK_IRQS = 1`;
- `FIBER_SWITCH_STRICT_BARRIERS = 1`.

The previously validated H7 performance mode remains an opt-in target policy,
not the portable default.

## 2026-07-10: Pure Scheduler Port ABI Checkpoint

The v2 core no longer exposes a direct target-switch API:

- `fiber_switch(from, to)` and `fiber_yield_to(to)` were removed from the public
  API.
- `fiber_internal_port_switch_from_slot` and
  `fiber_internal_port_switch_to_slot` were removed from port state.
- PendSV no longer receives a preselected target from Thread mode.
- Every port path derives the source from the runtime-owned current context,
  calls the scheduler bridge, and restores only the returned context.
- The validation application now provides its own scheduler hook to reproduce
  the previous f2 -> f1 -> f3 -> f2 execution order.

This keeps the context-switch core policy-free. Sleep, wait, wake, round-robin
order, idle selection, and future yield APIs belong to the scheduler layer, not
to the CPU port.

## 2026-07-10: ARMv7E-M Scheduler-Driven PendSV Checkpoint

The ARMv7E-M port now has a scheduler-driven PendSV path:

- `fiber_scheduler_set_pick_next()` installs a stable C scheduler hook.
- Scheduler hook installation is a Thread-mode, pre-start operation. Passing a
  `NULL` hook panics with `'K'`; changing the hook after the current context is
  seeded panics with `'k'`.
- `fiber_schedule()` requests a scheduler-driven PendSV switch without
  publishing a target slot.
- ARMv7E-M PendSV saves the runtime-owned current context, enters the
  handler-side scheduler critical section, calls
  `fiber_internal_scheduler_pick_next_from_pendsv()`, and restores the returned
  context.
- The scheduler bridge validates current context, configured hook, returned
  context, sealed boot state, saved stack pointer alignment (`ctx->sp % 8 == 4`
  for the saved 36-byte software frame), stack bounds, software-frame plus
  hardware exception-frame headroom, EXC_RETURN signature and Thread/PSP bits,
  and FP extended-frame headroom before restore.
- A missing hook panics with `'K'`; a `NULL` returned context panics with `'N'`;
  a missing saved stack pointer panics with `'P'`; an invalid restore frame can
  panic with `'A'`, `'U'`, `'T'`, `'X'`, or `'x'`; a corrupt boot seal uses the
  existing boot-check panic codes such as `'m'`, `'v'`, `'g'`, `'G'`, `'s'`, and
  `'h'`.
- The previous legacy/manual target-slot path has been removed.

The ARMv7E-M scheduler path follows the FreeRTOS handler critical-section model:

- `FIBER_SCHEDULER_BASEPRI` defaults to the highest non-zero hardware priority
  threshold derived from `__NVIC_PRIO_BITS`.
- Startup validates the active `AIRCR.PRIGROUP` against the FreeRTOS
  preemption-priority-only assumption for BASEPRI-protected scheduler sections.
- PendSV snapshots previous `BASEPRI`, writes scheduler `BASEPRI`, calls the
  bridge, restores previous `BASEPRI`, then restores the selected context.
- `BASEPRI` is not saved as part of `FiberContext`.
- Ports without `BASEPRI` wrap the handler-side scheduler bridge with a saved
  `PRIMASK` critical section, matching the FreeRTOS Cortex-M0 PendSV model.
- `FIBER_CORTEX_M7_R0P1_ERRATA_837070=1` enables the FreeRTOS-style
  `cpsid i` / `msr BASEPRI` / `cpsie i` workaround for affected Cortex-M7 r0p1
  parts.
- The compile matrix now builds Cortex-M7 and Cortex-M7F with that errata gate
  enabled, but real r0p1 hardware validation is still required before claiming
  FreeRTOS CM7/r0p1 parity.

## 2026-07-10: v2 Scheduler Hook State Checkpoint

Commit `cf610cc` prepares the v2 scheduler-driven port boundary:

- `fiber_port_state.h` now owns the internal scheduler hook state:
  current context, pick-next function pointer, and user context pointer.
- The port state layer provides a stable C bridge for future PendSV/SVC
  scheduler selection.
- The bridge validates the hook and returned context before restore.
- The public scheduler API is intentionally not exposed yet. `fiber_core.h`
  still exposes the low-level/current API only, because the ARMv7E-M PendSV path
  has not migrated to scheduler-driven selection yet.

The same checkpoint also changes the validated ARMv7E-M `FiberContext.sp`
invariant:

- `FiberContext.sp` now follows the FreeRTOS `pxTopOfStack` model.
- A non-running context stores the last saved software-frame pointer.
- While a fiber is running, the live stack pointer is CPU PSP.
- The port updates `ctx->sp` when saving a context as the switch source.
- The port no longer moves the target `ctx->sp` forward after restore.

This invariant is cleaner and better aligned with FreeRTOS, but it is a
behavior-affecting change in the STM32H7/Cortex-M7 validated path. Compile
checks and H7 build passed for this checkpoint, but the H7 runtime validation
must be repeated before this v2 path carries the previous H7 runtime-validated
claim.

## 2026-07-04: Context Switch Hardening

The earlier direct-switch implementation was treated as a FreeRTOS-style
cooperative PendSV switcher for STM32 Cortex-M projects.

Validated baseline for STM32H7 / Cortex-M7:

- Save and restore `r4-r11`.
- Preserve `LR` as the `EXC_RETURN` value.
- Run tasks on PSP.
- Request switching through PendSV.
- Keep PendSV at the lowest interrupt priority.
- Save and restore `s16-s31` only when `EXC_RETURN` reports an extended FP frame.
- Use eager FP stacking by default with `FIBER_FPU_LAZY = 0`.

Observed STM32H7 hardware validation:

- A normal runtime run reached `validation_flags = 0x000001FF` with
  `validation_failures = 0` and `last_panic_code = 0`.
- A long run exceeded 8 million visits per fiber while FP accumulators kept the
  expected 1x/2x/3x relationship.
- Forced real switch while `PRIMASK != 0` trapped with panic code `'p'`.
- Forced real switch while `BASEPRI != 0` trapped with panic code `'b'`.
- A performance-mode H7 run with `FIBER_FPU_LAZY = 1`,
  `FIBER_SWITCH_MASK_IRQS = 0`, and `FIBER_SWITCH_STRICT_BARRIERS = 0`
  exceeded 18 million visits per fiber with `validation_flags = 0x000001FF`,
  `validation_failures = 0`, `last_panic_code = 0`, and the expected FP
  accumulator relationship.

Hardening decisions:

- The synthetic exception frame stores `PC` with bit 0 clear. Thumb state comes
  from `xPSR.T`, matching the FreeRTOS initial stack pattern.
- The initial `EXC_RETURN` is configurable through `FIBER_INITIAL_EXC_RETURN`.
  The default stays `0xFFFFFFFDu` for M3/M4/M7 and secure-only style builds.
- ARMv8-M Non-secure projects can set `FIBER_RUN_NONSECURE = 1` to select
  `0xFFFFFFBCu`, or override `FIBER_INITIAL_EXC_RETURN` directly.
- `fiber_schedule()` rejects real scheduler jumps when `PRIMASK` is already set,
  because a pending PendSV delayed past a critical section is unsafe.
- On cores with BASEPRI, `fiber_schedule()` also rejects scheduler jumps when
  `BASEPRI` is already set.
- The direct boot trampoline clears `CONTROL.FPCA` before entering the first
  fiber when an FPU context exists.
- The direct boot trampoline remains the default start path. A future optional
  SVC-based first-fiber start path may be added to match the FreeRTOS first-task
  model more closely, where the first context is entered by exception return
  instead of a direct branch. It should be gated by a dedicated option and kept
  separate from the validated STM32H7/M7 trampoline path until hardware tests
  prove the SVC path.
- The preferred low-level runtime API is `fiber_start()` plus
  `fiber_schedule()`. Higher-level yield/sleep/wait APIs should update scheduler
  state and then call `fiber_schedule()`.
- `fiber_start()` seeds the runtime-owned current context, and the scheduler
  bridge updates it to the selected context during every scheduler-driven
  switch. This mirrors the FreeRTOS `pxCurrentTCB` ownership model without
  exposing direct target selection to the core API.
- The scheduler-driven ARMv7E-M branch writes `BASEPRI` around the scheduler
  bridge and has an explicit Cortex-M7 r0p1 errata gate.
- The validated H7 performance mode is an opt-in policy, not the portable safety
  default. Keep conservative defaults for broad bring-up unless a target has
  hardware validation for the faster settings.

Known limits:

- STM32H7 / Cortex-M7 is the primary validated target.
- ARMv8-M Non-secure needs explicit `FIBER_RUN_NONSECURE` or an explicit
  `FIBER_INITIAL_EXC_RETURN`.
- Cortex-M23 PSPLIM behavior is intentionally not enabled by the generic
  baseline path. FreeRTOS has context slots for PSPLIM, but its Non-secure M23
  port does not program a non-secure PSPLIM register.
- Cortex-M55 / MVE needs validation. If MVE code can use the extended FP
  register file, the build must ensure `FIBER_HAS_FPU` covers that context or
  force saving with `FIBER_FORCE_SAVE_FPU = 1`.
- `fiber_boot(&ctx->boot)` remains available for advanced/manual integrations,
  but it cannot seed current ownership before the first switch because a
  `FiberBoot` record does not point back to its owning `FiberContext`.
- `tools/compile_matrix.ps1` provides the compile-only sanity matrix. It does
  not replace hardware tests, but it must stay green before widening support
  claims beyond STM32H7/Cortex-M7.
