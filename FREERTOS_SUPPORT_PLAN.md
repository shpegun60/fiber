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
- The ARMv7E-M first-fiber start uses SVC by default and enters the first fiber
  by exception return. The direct boot trampoline remains available as a
  fallback for ports without SVC first-start support.
- `fiber_schedule()` rejects calls from Handler mode.
- `fiber_schedule()` rejects scheduler jumps while `PRIMASK` is already set.
- `fiber_schedule()` rejects scheduler jumps while `BASEPRI` is already set on cores
  that implement BASEPRI.
- `fiber_schedule()` rejects scheduler jumps while `FAULTMASK` is already set on
  cores that implement FAULTMASK.

Closed hardening items from the FreeRTOS comparison:

- stacked `PC` bit 0 handling is fixed;
- hard-coded initial `0xFFFFFFFDu` is replaced by `FIBER_INITIAL_EXC_RETURN`;
- `CONTROL.FPCA` is cleared before the first fiber entry when needed;
- real switches are rejected when `PRIMASK` would defer PendSV;
- real switches are rejected when `BASEPRI` would defer PendSV;
- real switches are rejected when `FAULTMASK` would defer PendSV;
- STM32H7 hardware validation covered a normal long-running switch loop,
  pre-boot FP use, current-fiber tracking, and forced delayed-switch traps for
  `PRIMASK` (`'p'`) and `BASEPRI` (`'b'`);
- STM32H7 performance-mode validation also covered
  `FIBER_FPU_LAZY = 1`, `FIBER_SWITCH_MASK_IRQS = 0`, and
  `FIBER_SWITCH_STRICT_BARRIERS = 0` for a long-running switch loop;
- current-fiber ownership is implemented through `fiber_start()`,
  `fiber_current()`, `fiber_schedule()`, and the scheduler bridge;
- startup mask cleanup no longer emits `FAULTMASK` on baseline cores that do
  not implement it;
- obsolete archived `fiber/old` source was removed so audits and validation
  only cover the active runtime implementation;
- runtime exception setup validation checks PendSV priority, PendSV/SVC vector
  routing, SVCall priority for SVC first-start, BASEPRI priority-bit policy,
  FreeRTOS-style `AIRCR.PRIGROUP` compatibility, and Cortex-M7 r0p0/r0p1 errata
  gating;
- ARMv7E-M SVC first-start validates privileged Thread/MSP setup, MSP read-back,
  pending-PendSV cleanup, SVC provenance, SVC immediate value,
  restore-context integrity, fault exception enable, BASEPRI cleanup, PSP setup,
  and `CONTROL.SPSEL`/`CONTROL.FPCA` state before exception return;
- handler-side scheduler calls use the FreeRTOS critical-section pattern:
  `BASEPRI` on BASEPRI-capable ports and saved `PRIMASK` on BASEPRI-less ports;
- portable defaults are back to conservative settings:
  `FIBER_FPU_LAZY = 0`, `FIBER_SWITCH_MASK_IRQS = 1`, and
  `FIBER_SWITCH_STRICT_BARRIERS = 1`;
- source comments no longer claim full "all STM32" validation;
- M0/M0+ MSP rewind behavior is documented as platform-dependent;
- M23, M33, M55/MVE, TrustZone/Non-secure, and PAC/BTI runtime use is now
  explicitly policy-gated until FreeRTOS-style context layout and hardware
  validation exist.

## Support Matrix

| Core family | Current state | Target state |
| --- | --- | --- |
| Cortex-M0/M0+ | Dedicated `port/armv6m` Thumb-1 path uses the FreeRTOS CM0 software-frame order and PRIMASK around the scheduler bridge, compile-only | Validate on hardware, document MSP rewind policy |
| Cortex-M3 | Mainline path works with universal `r4-r11,lr` frame | Compile and smoke-test |
| Cortex-M4F | FPU-aware path matches FreeRTOS pattern | Compile and FP stress-test |
| Cortex-M7F | Primary validated path for STM32H7 | Keep validated |
| Cortex-M23 | Compile-covered; runtime-gated by default; generic baseline path has no PSPLIM slot | Add FreeRTOS-style PSPLIM slot/security policy or keep excluded |
| Cortex-M33 | Compile-covered; runtime-gated by default; simple PSPLIM register policy exists | Add FreeRTOS-style CONTROL/PSPLIM/security-domain context layout and validate |
| Cortex-M55/MVE | Compile-covered; runtime-gated by default; MVE-FP maps to extended FP context, MVE-only is rejected | Add MVE/PAC/BTI context policy and hardware validation |

## Priority Roadmap

### P0: Next Validation

0. Repeat STM32H7 runtime validation after `775648c`.

   `cf610cc` changed the ARMv7E-M/H7 `FiberContext.sp` invariant to the
   FreeRTOS `pxTopOfStack` model. Commit `775648c` then integrated the larger
   scheduler-driven v2 execution model: direct target switching is removed,
   PendSV asks the scheduler bridge for the next context, handler-side scheduler
   calls use the port critical-section policy, and runtime exception setup plus
   unvalidated feature policies are enforced.

   This is architecturally cleaner, but it is behavior-affecting. The later
   ARMv7E-M SVC first-start checkpoint is also behavior-affecting because the
   first fiber is entered by SVC exception return instead of a direct branch.
   The v2 path must repeat `H7_RUNTIME_VALIDATION.md` before carrying the
   previous H7 runtime-validated claim.

1. Add a compile-only matrix for representative Cortex-M targets.

   Tooling:

   ```powershell
   .\tools\compile_matrix.ps1
   ```

   Current compile-only set:

   - Cortex-M0 or M0+
   - Cortex-M3
   - Cortex-M4 without FPU
   - Cortex-M4F
   - Cortex-M7 without FPU
   - Cortex-M7F
   - Cortex-M23
   - Cortex-M33 without FPU
   - Cortex-M33F
   - Cortex-M55 without FPU
   - Cortex-M55F
   - Cortex-M55 MVE-FP
   - ARMv8-M/ARMv8.1-M `FIBER_RUN_NONSECURE=1` compile mode
   - ARMv8-M/ARMv8.1-M Secure-to-Non-secure bank compile mode with
     `FIBER_TZ_NS=1` and `-mcmse`

   Each target must prove that `FIBER_HAS_BASEPRI` and the PSPLIM/FPU feature
   macros are defined before they are used. This is a compile sanity check only;
   it does not promote M23/M33/M55/MVE to validated runtime targets.

2. Keep expanding the focused STM32H7 runtime stress tests.

   The canonical checklist is `H7_RUNTIME_VALIDATION.md`. That file is the
   gate for promoting the v2 ARMv7E-M path back to H7 runtime-validated after
   behavior-affecting changes.

   Already covered manually on hardware:

   - normal scheduler-driven `fiber_schedule()`;
   - scheduler jump with `PRIMASK != 0` must trap;
   - scheduler jump with `BASEPRI != 0` must trap on BASEPRI-capable cores;
   - scheduler jump with `FAULTMASK != 0` must trap on FAULTMASK-capable cores.

   Remaining useful cases:

   - `fiber_schedule()` from Handler mode must trap;
   - invalid `AIRCR.PRIGROUP` for the scheduler `BASEPRI` policy must trap with
     `'g'`;
   - missing scheduler hook must trap with `'K'`;
   - scheduler hook returning `NULL` must trap with `'N'`;
   - changing the scheduler hook after the current context is seeded must trap
     with `'k'`;
   - scheduler hook returning an uninitialized or corrupted context must trap
     before PendSV restores PSP;
   - scheduler hook returning a context with a bad EXC_RETURN or insufficient
     restore-frame headroom must trap before exception return;
   - package the manual checks into a repeatable board validation mode.

3. Keep the FPU startup hygiene stress test active.

   Already covered manually on hardware:

   - execute floating-point code before `fiber_start()`;
   - enter the first fiber;
   - verify that clearing `CONTROL.FPCA` prevents pre-fiber FP active state from
     leaking into the fiber runtime;
   - run the existing FP switch stress afterward.

4. Keep performance-mode validation separate from portable defaults.

   The H7 path has passed a long run with:

   ```c
   #define FIBER_FPU_LAZY 1
   #define FIBER_SWITCH_MASK_IRQS 0
   #define FIBER_SWITCH_STRICT_BARRIERS 0
   ```

   Treat these as validated H7 performance settings, not as proof that every
   Cortex-M target should use them by default. New core families should first
   pass conservative settings, then opt-in performance settings.

5. Keep source support claims aligned with README, DECISIONS.md, and this plan
   before every release.

### P1: FreeRTOS Port Parity Decisions

1. Keep Cortex-M7 r0p1 errata policy explicit.

   FreeRTOS wraps `BASEPRI` writes in PendSV on Cortex-M7 r0p1 because of ARM
   errata 837070. The ARMv7E-M scheduler-driven `fiber` PendSV path now writes
   `BASEPRI` around the scheduler bridge, then restores the previous value
   before restoring the selected context.

   `FIBER_CORTEX_M7_R0P1_ERRATA_837070=1` enables the FreeRTOS-style workaround
   around the `BASEPRI` raise operation. The compile matrix builds Cortex-M7 and
   Cortex-M7F with this gate enabled. Runtime startup checks CPUID and traps if
   an affected r0p0/r0p1 core runs without the workaround. Real affected M7
   hardware validation is still required before claiming parity with the
   FreeRTOS CM7/r0p1 port.

2. Finish Cortex-M23 support or keep it explicitly excluded.

   Options:

   - implement a v8-M Baseline path with a PSPLIM slot similar to FreeRTOS NTZ;
   - or mark M23 as not supported until hardware/toolchain validation exists.

   Current policy: M23 is compile-covered but runtime-gated by default.
   FreeRTOS has a PSPLIM slot in the CM23 NTZ context layout, but it also gates
   actual PSPLIM register access through target/security configuration because
   Non-secure Cortex-M23 does not have a Non-secure PSPLIM register. The fiber
   baseline path still has no PSPLIM slot, and `FIBER_USE_PSPLIM_REGISTER`
   remains disabled unless a future port explicitly implements that layout.

   Future direction: copying the FreeRTOS-style M23 layout is useful if `fiber`
   wants to claim ARMv8-M Baseline/Mainline parity. That work should be done as
   a dedicated ARMv8-M portability pass after the compile-only matrix exists,
   not as part of STM32H7/M7 hardening. The implementation should separate:

   - a context slot for PSPLIM;
   - a compile-time `FIBER_USE_PSPLIM_REGISTER` gate;
   - M23 Non-secure behavior, where PSPLIM register access must stay disabled;
   - M23 Secure-only behavior, which needs separate validation;
   - M33/M55 Mainline behavior, where PSPLIM register access is expected.

3. Implement and validate ARMv8-M Non-secure behavior.

   Required checks:

   - `FIBER_INITIAL_EXC_RETURN = 0xFFFFFFBCu` path;
   - PSPLIM symbol selection;
   - CPACR/NSACR behavior for FP access;
   - vector table and PendSV wiring in the current security domain.
   - context slots for `CONTROL`, `PSPLIM`, and security-domain state when
     matching a FreeRTOS CM33/CM55-style port.

   Current policy: Non-secure and Secure-to-Non-secure bank builds remain
   compile-covered, but runtime use requires
   `FIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME=1`.

4. Complete MVE/PAC/BTI policy for Cortex-M55 class targets.

   Required checks:

   - MVE-FP uses the current extended FP save/restore model;
   - MVE without scalar FP is rejected by runtime policy validation;
   - PAC/BTI context support is compile-blocked until save/restore is
     implemented;
   - hardware validation is still required before enabling MVE runtime by
     default.

### P2: API Safety

1. Keep current-fiber tracking on the preferred API path.

   The preferred low-level API now mirrors the FreeRTOS `pxCurrentTCB`
   ownership model:

   ```c
   FiberContext *fiber_current(void);
   void fiber_schedule(void);
   void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                      void *user);
   FIBER_NORETURN void fiber_start(FiberContext *ctx);
   ```

   `fiber_start()` seeds the first current context. PendSV saves that context,
   asks the scheduler bridge for the next context, and restores only the
   returned context. The core API does not accept `from` or `to` from Thread
   mode.

   On ARMv7E-M, the current first-start path uses SVC. Other ports may still use
   the direct trampoline fallback. PendSV must still verify that Thread mode is
   already using PSP before saving a source context. A pre-start or foreign
   PendSV now traps with `'j'` instead of publishing a bogus saved stack
   pointer.

   The port also checks live PSP source-save headroom before writing the
   software frame. If the save would cross the current fiber stack base, it
   traps with `'d'` before modifying memory. This is stricter than the small
   FreeRTOS PendSV snippets, which rely on the broader RTOS stack-checking
   infrastructure.

   `fiber_boot(&ctx->boot)` remains available for low-level/manual start
   experiments, but it cannot seed current ownership before the first switch
   because a `FiberBoot` record does not point back to its owning
   `FiberContext`.

2. Keep vector wiring verification active.

   Rationale: FreeRTOS validates critical handler wiring in its startup path.
   `fiber_exception_runtime_check()` now verifies that the active vector table
   routes PendSV and SVC to the expected handler symbols. The default PendSV
   model expects an application wrapper `PendSV_Handler()` that branches to
   `fiber_pendsv()` without clobbering LR/EXC_RETURN. A normal C wrapper that
   emits `bl fiber_pendsv` is invalid because `fiber_pendsv()` needs the
   hardware `EXC_RETURN` in LR. Projects that vector directly to
   `fiber_pendsv()` must set `FIBER_PENDSV_VECTOR_DIRECT=1`. The SVC first-start
   path has the same rule: default validation expects an `SVC_Handler()` wrapper,
   and direct vectoring to `fiber_svc()` requires `FIBER_SVC_VECTOR_DIRECT=1`.
   `FIBER_VALIDATE_SVC_VECTOR` defaults to enabled only when
   `FIBER_START_USE_SVC=1`.

   This proves vector-table routing. The ARMv7E-M SVC first-start path adds a
   separate dispatch check by decoding the SVC immediate in `fiber_svc()` and
   trapping with `'u'` when the immediate does not match
   `FIBER_SVC_START_NUMBER`.

3. Keep the ARMv7E-M SVC-based first-fiber start path validated separately.

   FreeRTOS starts the first task through an SVC handler and enters the task by
   exception return. The ARMv7E-M `fiber` default now does the same high-level
   thing behind `FIBER_START_USE_SVC=1`, while adding extra local checks:
   privileged Thread/MSP setup, optional MSP rewind and read-back, pending
   PendSV cleanup before interrupts reopen, SVC immediate validation,
   seeded-current validation, fault exception enable, BASEPRI cleanup, PSP
   setup, `CONTROL.SPSEL`, and `CONTROL.FPCA` verification.

   The direct trampoline remains available as a fallback and A/B validation
   path for ports that do not implement SVC start. The SVC and direct paths must
   keep separate validation records.

4. Consider moving PendSV assembly into a dedicated assembly source.

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
