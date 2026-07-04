# FreeRTOS-Style Cortex-M Support Plan

## Goal

Make `fiber` match the FreeRTOS Cortex-M CPU-port behavior where it matters for
a cooperative STM32 fiber library:

- correct PSP based exception return;
- correct callee-saved core register handling;
- correct `EXC_RETURN` handling;
- correct high FP register handling;
- correct PendSV priority and trigger rules;
- correct v8-M stack-limit handling where supported;
- clear and honest support boundaries per Cortex-M core family.

This is not a plan to clone the FreeRTOS scheduler. The target is FreeRTOS-like
CPU context-switch robustness without tasks, priorities, tick scheduling, queues,
MPU task management, or the FreeRTOS API surface.

## Current Baseline

Validated primary target:

- STM32H7 / Cortex-M7.

Implemented and aligned with the FreeRTOS non-MPU PendSV pattern:

- `r4-r11` are saved and restored.
- `LR` is preserved as `EXC_RETURN`.
- PSP is used for fiber stacks.
- PendSV performs the actual switch.
- PendSV is configured at the lowest priority.
- `s16-s31` are saved and restored only when `EXC_RETURN` reports an extended
  FP frame.
- `FIBER_FPU_LAZY = 0` keeps FP stacking deterministic by default.
- The initial stacked `PC` has bit 0 clear; Thumb state comes from `xPSR.T`.
- `FIBER_INITIAL_EXC_RETURN` is configurable.
- The first direct fiber boot clears `CONTROL.FPCA` when an FP context exists.
- `fiber_switch()` rejects calls from Handler mode.
- `fiber_switch()` rejects real switches while `PRIMASK` is already set.
- `fiber_switch()` rejects real switches while `BASEPRI` is already set on cores
  that implement BASEPRI.

Closed hardening items from the FreeRTOS comparison:

- stacked `PC` bit 0 handling is fixed;
- hard-coded initial `0xFFFFFFFDu` is replaced by `FIBER_INITIAL_EXC_RETURN`;
- `CONTROL.FPCA` is cleared before the first direct fiber entry when needed;
- real switches are rejected when `PRIMASK` would defer PendSV;
- real switches are rejected when `BASEPRI` would defer PendSV;
- source comments no longer claim full "all STM32" validation;
- M0/M0+ MSP rewind behavior is documented as platform-dependent;
- M23 and M55/MVE are documented as not yet validated.

## Support Matrix

| Core family | Current state | Target state |
| --- | --- | --- |
| Cortex-M0/M0+ | Baseline path is FreeRTOS-like, not hardware validated | Validate, document MSP rewind policy |
| Cortex-M3 | Mainline path works with universal `r4-r11,lr` frame | Compile and smoke-test |
| Cortex-M4F | FPU-aware path matches FreeRTOS pattern | Compile and FP stress-test |
| Cortex-M7F | Primary validated path for STM32H7 | Keep validated |
| Cortex-M23 | Not validated; generic baseline path does not implement active PSPLIM | Decide support or explicitly exclude |
| Cortex-M33 | Mainline PSPLIM is restored from `boot.stack_base` | Validate non-MPU and Non-secure configs |
| Cortex-M55/MVE | Not validated | Add MVE/PAC/BTI policy before claiming support |

## Priority Roadmap

### P0: Next Validation

1. Add a compile-only matrix for representative Cortex-M targets.

   Minimum set:

   - Cortex-M0 or M0+
   - Cortex-M3
   - Cortex-M4F
   - Cortex-M7F
   - Cortex-M23
   - Cortex-M33

2. Add a focused STM32H7 runtime stress test for delayed-switch hazards.

   Required cases:

   - normal `fiber_switch()`;
   - no-op `fiber_switch(from, NULL)`;
   - no-op `fiber_switch(from, from)`;
   - real switch with `PRIMASK != 0` must trap;
   - real switch with `BASEPRI != 0` must trap on BASEPRI-capable cores.

3. Keep source support claims aligned with README, DECISIONS.md, and this plan
   before every release.

### P1: FreeRTOS Port Parity Decisions

1. Decide Cortex-M23 support.

   Options:

   - implement a v8-M Baseline path with a PSPLIM slot similar to FreeRTOS NTZ;
   - or mark M23 as not supported until hardware/toolchain validation exists.

   Current policy: M23 is not a validated target. FreeRTOS has a PSPLIM slot in
   the CM23 NTZ context layout, but it also gates actual PSPLIM register access
   through target/security configuration because Non-secure Cortex-M23 does not
   have a Non-secure PSPLIM register. Do not enable generic M23 PSPLIM behavior
   just because the slot exists.

   Future direction: copying the FreeRTOS-style M23 layout is useful if `fiber`
   wants to claim ARMv8-M Baseline/Mainline parity. That work should be done as
   a dedicated ARMv8-M portability pass after the compile-only matrix exists,
   not as part of STM32H7/M7 hardening. The implementation should separate:

   - a context slot for PSPLIM;
   - a compile-time `FIBER_USE_PSPLIM_REGISTER` gate;
   - M23 Non-secure behavior, where PSPLIM register access must stay disabled;
   - M23 Secure-only behavior, which needs separate validation;
   - M33/M55 Mainline behavior, where PSPLIM register access is expected.

2. Validate ARMv8-M Non-secure behavior.

   Required checks:

   - `FIBER_INITIAL_EXC_RETURN = 0xFFFFFFBCu` path;
   - PSPLIM symbol selection;
   - CPACR/NSACR behavior for FP access;
   - vector table and PendSV wiring in the current security domain.

3. Add an explicit MVE policy for Cortex-M55 class targets.

   Required checks:

   - whether the toolchain exposes MVE use through existing FP macros;
   - whether `FIBER_HAS_FPU` must become a broader extended-context flag;
   - whether PAC/BTI state needs an explicit unsupported note or implementation.

### P2: API Safety

1. Add current-fiber tracking.

   Problem: the public API currently trusts the caller to pass the real source
   context:

   ```c
   fiber_switch(&from, &to);
   ```

   FreeRTOS avoids this by owning `pxCurrentTCB`. The fiber equivalent should be:

   ```c
   FiberContext *fiber_current(void);
   void fiber_yield_to(FiberContext *to);
   ```

   The advanced `fiber_switch(from, to)` API can remain, but normal users should
   not need to pass `from`.

2. Add optional vector wiring verification.

   Rationale: FreeRTOS validates critical handler wiring in its startup path.
   `fiber` should provide an optional check that `PendSV_Handler` reaches
   `fiber_pendsv()`, where the platform makes that observable.

3. Consider moving PendSV assembly into a dedicated assembly source.

   Rationale: naked C plus inline assembly works, but a dedicated assembly file
   can make architecture-specific variants clearer once M23/M33/M55 support is
   expanded.

## Definition of Done

The library can claim FreeRTOS-style STM32 Cortex-M CPU-port support only when:

- each claimed core family has an explicit support status;
- the claimed core families compile with representative GCC target flags;
- the STM32H7/M7 path remains hardware validated;
- M23, M33 Non-secure, and M55/MVE are either implemented and validated or
  explicitly excluded;
- docs and source comments use the same support claims;
- context-switch safety checks reject delayed-switch cases caused by interrupt
  masks.
