# Fiber Decision Log

## 2026-07-04: Context Switch Hardening

The current implementation is treated as a FreeRTOS-style cooperative PendSV
switcher for STM32 Cortex-M projects.

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

Hardening decisions:

- The synthetic exception frame stores `PC` with bit 0 clear. Thumb state comes
  from `xPSR.T`, matching the FreeRTOS initial stack pattern.
- The initial `EXC_RETURN` is configurable through `FIBER_INITIAL_EXC_RETURN`.
  The default stays `0xFFFFFFFDu` for M3/M4/M7 and secure-only style builds.
- ARMv8-M Non-secure projects can set `FIBER_RUN_NONSECURE = 1` to select
  `0xFFFFFFBCu`, or override `FIBER_INITIAL_EXC_RETURN` directly.
- `fiber_switch()` rejects real switches when `PRIMASK` is already set, because
  a pending PendSV delayed past a critical section is unsafe for this API.
- On cores with BASEPRI, `fiber_switch()` also rejects real switches when
  `BASEPRI` is already set.
- The direct boot trampoline clears `CONTROL.FPCA` before entering the first
  fiber when an FPU context exists.
- The direct boot trampoline remains the default start path. A future optional
  SVC-based first-fiber start path may be added to match the FreeRTOS first-task
  model more closely, where the first context is entered by exception return
  instead of a direct branch. It should be gated by a dedicated option and kept
  separate from the validated STM32H7/M7 trampoline path until hardware tests
  prove the SVC path.
- The preferred runtime API is `fiber_start()` plus `fiber_yield_to()`.
  `fiber_start()` seeds the runtime-owned current context, and PendSV updates it
  to the target context during every real switch. This mirrors the FreeRTOS
  `pxCurrentTCB` ownership model while keeping `fiber_switch(from, to)` as an
  advanced/manual API.
- `FIBER_VALIDATE_CURRENT = 1` rejects real switches whose `from` argument does
  not match the runtime-owned current context once that context is known.
- The current PendSV path does not write `BASEPRI`. Therefore the FreeRTOS
  Cortex-M7 r0p1 errata workaround around `BASEPRI` writes in PendSV is not
  required by the current implementation. If a future scheduler or critical
  section writes `BASEPRI` from PendSV, the FreeRTOS-style r0p1 workaround must
  be added before claiming support for affected Cortex-M7 revisions.

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
