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
a common FreeRTOS-style MPU task-management API, or the FreeRTOS API surface.
Selected MPU ports may still own optional pre-start region/privilege
configuration and an SVC yield path for unprivileged fibers.

The policy for using FreeRTOS `portable/` as a reference, rather than as a
compiled backend, is documented in `V2_FREERTOS_PORT_REFERENCE_POLICY.md`.

The required common-core boundary before production ports are added in bulk is
defined in `V2_OPAQUE_CONTEXT_CONTRACT.md`. `fiber_api_types.h` exposes only
the forward declaration and callbacks, while each selected port owns its
complete `FiberContext`, `FiberPortBoot` record, boot/hash implementation, and
CPU state. The current physical `sp + FiberPortBoot` shape is transitional, but
common runtime sources now operate through the callable port ABI and do not
access that layout.

## Current Baseline

Primary target, pending a fresh hardware run after the current hardening diff:

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
- initial `EXC_RETURN` is selected-port-owned. The concrete CM7 value is fixed
  at `0xFFFFFFFDu`; only transitional v8-M bring-up still accepts an input.
- First-fiber start uses SVC and enters the first fiber by exception return.
  The direct boot trampoline has been removed; each selected port must provide
  an SVC first-start symbol.
- The current validated privileged CM7 request path rejects Handler mode and
  rejects scheduler jumps while PRIMASK, BASEPRI, or FAULTMASK is nonzero.
- `fiber_schedule()` delegates its environment checks and PendSV request through
  the selected-port ABI. The selected CM7 port preserves the historical
  `IPSR -> current -> PRIMASK -> BASEPRI -> FAULTMASK -> PENDSVSET` sequence.
  A fresh H7 board run is still required after this source-boundary change.
- Future unprivileged MPU paths use a validated yield SVC and enforce zero mask
  state as a selected-port restore invariant instead of reading privileged mask
  registers from common Thread-mode code.

Closed hardening items from the FreeRTOS comparison:

- stacked `PC` bit 0 handling is fixed;
- each selected port publishes its initial `EXC_RETURN`; the concrete CM7 port
  rejects attempts to override its fixed `0xFFFFFFFDu` ABI;
- `CONTROL.FPCA` is cleared before the first fiber entry when needed;
- real switches are rejected when `PRIMASK` would defer PendSV;
- real switches are rejected when `BASEPRI` would defer PendSV;
- real switches are rejected when `FAULTMASK` would defer PendSV;
- STM32H7 hardware validation covered a normal long-running switch loop,
  pre-boot FP use, current-fiber tracking, and forced delayed-switch traps for
  `PRIMASK` (`'p'`) and `BASEPRI` (`'b'`);
- STM32H7 validation also covered `FIBER_FPU_LAZY = 1` in a long-running
  switch loop; switch barriers are now mandatory and have no disable knob;
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
  pending-PendSV cleanup, SVC provenance, SVC MSP-frame alignment, SVC opcode
  and immediate value,
  restore-context integrity, fault exception enable, BASEPRI cleanup, PSP setup,
  and `CONTROL.FPCA` state before exception return. Thread PSP selection is
  performed by the `EXC_RETURN` value, matching the FreeRTOS first-task start
  model;
- handler-side scheduler calls use the FreeRTOS critical-section pattern:
  `BASEPRI` on BASEPRI-capable ports and saved `PRIMASK` on BASEPRI-less ports;
- initial software-frame sizing, saved-SP modulo validation, and saved
  `EXC_RETURN` word selection now come from selected port traits instead of a
  common hard-coded 36-byte assumption;
- each current selected port now owns `fiber_port_types.h`,
  `fiber_port_boot_types.h`, `fiber_port_boot.h`, and `fiber_port_boot.c`;
  `fiber_port_selected.h` is the sole selector and its selected
  `fiber_portmacro.h` includes that contract. `fiber_types.h` remains a
  source-compatible facade. The physical `sp + FiberPortBoot` layout is
  transitional, while common sources already use the opaque callable ABI;
- build-selected portmacro workflow exists for the first FreeRTOS-referenced
  Cortex-M7 source group:
  `fiber/port/ARM_CM7/r0p1/fiber_portmacro.h` and `fiber_port.c`. The
  matrix compiles this source group for Cortex-M7/Cortex-M7F build-selected
  modes with its port-owned errata workaround always enabled;
- scheduled context restore uses mandatory selected-port boot-record checks by
  default; the full selected-port boot-record hash is still checked during
  init/start and is opt-in for every switch through
  `FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=1`;
- portable FPU policy defaults to `FIBER_FPU_LAZY = 0`; PendSV publication and
  context-boundary DSB/ISB serialization are mandatory selected-port behavior;
- source comments no longer claim full "all STM32" validation;
- M0/M0+ MSP rewind behavior is documented as platform-dependent;
- M23, M33, M55/MVE, TrustZone/Non-secure, and PAC/BTI runtime use is now
  explicitly policy-gated until FreeRTOS-style context layout and hardware
  validation exist.

## Support Matrix

| Core family | Current state | Target state |
| --- | --- | --- |
| Cortex-M0/M0+ | Concrete `port/ARM_CM0` SVC/PendSV/frame code is compile/link-covered | Validate on hardware and document MSP rewind policy |
| Cortex-M3 | Concrete `port/ARM_CM3` SVC/PendSV/frame code is compile/link-covered | Validate on hardware |
| Cortex-M4F | Concrete `port/ARM_CM4` source group is compile/link-covered and FPU-aware | Run M4F hardware FP stress validation |
| Cortex-M7F | STM32H7 embedding build selects the concrete FreeRTOS-referenced `ARM_CM7/r0p1` source group; compile matrix requires one complete port ABI definition set | Re-run H7 normal and all trap modes after current hardening; validate r0p0/r0p1 on affected hardware |
| Cortex-M23 | Transitional SVC/PendSV/frame code exists and is compile-covered, but PSPLIM/security policy is not FreeRTOS-level | Add PSPLIM slot/security policy, or keep excluded from runtime support |
| Cortex-M33 | Transitional SVC/PendSV/frame code exists and is compile-covered, but CONTROL/PSPLIM/security policy is not FreeRTOS-level | Add FreeRTOS-style CONTROL/PSPLIM/security-domain context layout and validate |
| Cortex-M55/MVE | Transitional SVC/PendSV/frame code exists and is compile-covered, but MVE/PAC/BTI policy is not FreeRTOS-level | Add MVE/PAC/BTI context policy and hardware validation |

## Priority Roadmap

### P0: Next Validation

0. Keep STM32H7 runtime validation current after behavior changes.

   `cf610cc` changed the ARMv7E-M/H7 `FiberContext.sp` invariant to the
   FreeRTOS `pxTopOfStack` model. Commit `775648c` then integrated the larger
   scheduler-driven v2 execution model: direct target switching is removed,
   PendSV asks the scheduler bridge for the next context, handler-side scheduler
   calls use the port critical-section policy, and runtime exception setup plus
   unvalidated feature policies are enforced.

   This is architecturally cleaner, but it is behavior-affecting. The later
   ARMv7E-M SVC first-start checkpoint is also behavior-affecting because the
   first fiber is entered by SVC exception return instead of a direct branch.

   The 2026-07-11 STM32H7 run passed the active H7 validation set after two SVC
   migration fixes:

   - SVC first-start must select Thread PSP through `EXC_RETURN`, not by
     writing `CONTROL.SPSEL` from Handler mode;
   - PendSV must validate the interrupted stack source through active
     `LR`/`EXC_RETURN` bit 2, not by reading `CONTROL.SPSEL`.

   Repeat `H7_RUNTIME_VALIDATION.md` after every behavior-affecting change to
   startup, PendSV, scheduler bridge state, saved stack layout, exception setup,
   interrupt-mask policy, or selected-port traits.

1. Maintain a compile/link matrix for representative Cortex-M targets.

   Tooling:

   ```powershell
   .\tools\compile_matrix.ps1
   ```

   Current matrix set:

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
   - ARMv8-M/ARMv8.1-M
     `FIBER_TRANSITIONAL_V8M_RUN_NONSECURE=1` compile mode
   - ARMv8-M/ARMv8.1-M Secure-to-Non-secure bank compile mode with
     `FIBER_TZ_NS=1` and `-mcmse`
   - PendSV direct-vector mode with `FIBER_PENDSV_VECTOR_DIRECT=1`
   - ARMv7E-M PendSV+SVC direct-vector mode with
     `FIBER_PENDSV_VECTOR_DIRECT=1` and `FIBER_SVC_VECTOR_DIRECT=1`
   - build-selected portmacro mode with `FIBER_PORT_BUILD_SELECTED=1`
   - Cortex-M7/Cortex-M7F build-selected source group
     `fiber/port/ARM_CM7/r0p1/fiber_port.c`, including the port-owned errata
     workaround

   Every selected profile must compile in wrapper and direct-vector SVC/PendSV
   modes. Each mode is then relocatably linked and inspected with `nm`; every
   mandatory port ABI symbol must have exactly one global definition. Passing
   the matrix is compile/link coverage only; runtime support still requires
   profile-specific hardware validation.

2. Keep expanding the focused STM32H7 runtime stress tests.

   The canonical checklist is `H7_RUNTIME_VALIDATION.md`. That file is the
   gate for promoting the v2 ARMv7E-M path back to H7 runtime-validated after
   behavior-affecting changes.

   Already covered manually on hardware:

   - normal scheduler-driven `fiber_schedule()`;
   - missing scheduler hook traps with `'K'`;
   - `NULL` scheduler hook traps with `'K'`;
   - changing the scheduler hook after the current context is seeded traps with
     `'k'`;
   - scheduler jump with `PRIMASK != 0` must trap;
   - scheduler jump with `BASEPRI != 0` must trap on BASEPRI-capable cores;
   - scheduler jump with `FAULTMASK != 0` must trap on FAULTMASK-capable cores.
   - scheduler hook returning `NULL` traps with `'N'`;
   - scheduler hook returning a context with `sp == NULL` traps with `'P'`.

   Remaining useful cases:

   - `fiber_schedule()` from Handler mode must trap;
   - invalid `AIRCR.PRIGROUP` for the scheduler `BASEPRI` policy must trap with
     `'g'`;
   - scheduler hook returning an uninitialized or corrupted context must trap
     before PendSV restores PSP;
   - scheduler hook mutation of PRIMASK, FAULTMASK, or BASEPRI must trap for
     both first selection and PendSV selection;
   - damaged software canary must trap with `'c'`;
   - scheduler hook returning a context with an exact-encoding-invalid
     EXC_RETURN must trap with `'x'`;
   - insufficient restore-frame headroom must trap with `'X'`;
   - package the manual checks into a repeatable board validation mode.

3. Keep the FPU startup hygiene stress test active.

   Already covered manually on hardware:

   - execute floating-point code before `fiber_start()`;
   - enter the first fiber;
   - verify that clearing `CONTROL.FPCA` prevents pre-fiber FP active state from
     leaking into the fiber runtime;
   - run the existing FP switch stress afterward.

4. Keep lazy-FPU validation separate from portable defaults.

   The H7 path has passed a long run with:

   ```c
   #define FIBER_FPU_LAZY 1
   ```

   Treat this as target-specific evidence, not proof that every Cortex-M target
   should use lazy stacking. Mandatory barriers are not part of performance
   tuning. New core families should first pass eager FP policy, then lazy FP.

5. Keep source support claims aligned with README, DECISIONS.md, and this plan
   before every release.

### P1: FreeRTOS Port Parity Decisions

1. Finish the FreeRTOS-style port ownership split.

   The public type-only phase of `V2_OPAQUE_CONTEXT_CONTRACT.md` is complete:
   each selected port exports `fiber_port_types.h`, and the selected facade
   completes `FiberContext` for application allocation. Continue with an
   internal type-only ABI header for private scheduler CPU-state tokens and a
   callable ABI that accepts opaque context pointers. Common runtime files must
   then stop including the selected complete context type or containing
   architecture-specific switch assembly.

   Move out of common code:

   - transitional fallback `fiber_port_init_context_frame()`;
   - transitional fallback `fiber_pendsv()`;
   - direct startup trampoline mechanics;
   - SVC first-start mechanics;
   - CONTROL/PSP/MSP programming;
   - PendSV/SVC priority setup and vector routing validation;
   - BASEPRI/PRIMASK scheduler critical-section assembly;
   - Cortex-M7 r0p0/r0p1 errata policy;
   - PSPLIM/FPU/MVE/PAC/BTI policy decisions that depend on the selected
     architecture profile.

   Keep in common code:

   - public cooperative API semantics;
   - scheduler hook storage and current-context ownership policy;
   - CPU-neutral immutable metadata helpers that do not reveal where the
     selected port embeds that metadata;
   - portable diagnostics and app-provided RAM/code plausibility hooks.

   Keep in the selected port:

   - the complete `FiberContext` layout and any port-specific boot data;
   - context construction, final sealing, and restore validation;
   - saved-SP, EXC_RETURN, CONTROL, PSPLIM, MPU, security, PAC, FP, and MVE
     storage as required by that profile;
   - runtime MSP preparation and first-context SVC transfer.

   The common metadata hash is not the final context proof. Every production
   port owns an immutable seal over its layout/configuration identity and
   validates mutable saved state separately before restore. The structural move
   must preserve current scheduler critical-section placement; callback-wrapper
   redesign is a separate behavior change.

   A transitional fallback may exist only under an explicitly transitional
   directory such as `port/transitional_v8m`. A port cannot be claimed as
   FreeRTOS-level while it depends on transitional PendSV or frame layout.

   The `fiber/port` helper-root convention is reserved for reusable helper code, not
   selected-port fallback behavior.

2. Keep Cortex-M7 r0p1 errata policy explicit.

   FreeRTOS wraps `BASEPRI` writes in PendSV on Cortex-M7 r0p1 because of ARM
   errata 837070. The ARMv7E-M scheduler-driven `fiber` PendSV path now writes
   `BASEPRI` around the scheduler bridge, then restores the previous value
   before restoring the selected context.

   The concrete `ARM_CM7/r0p1` port always enables the FreeRTOS-style workaround
   around handler-side `BASEPRI` writes. Unlike the FreeRTOS minimum sequence,
   the fiber helper preserves and restores the previous `PRIMASK` instead of
   unconditionally re-enabling IRQs; this keeps SVC/start critical sections
   closed while still serializing the `BASEPRI` write. The compile matrix builds
   Cortex-M7 and Cortex-M7F through this concrete source group. Runtime startup
   checks CPUID and the immutable port trait. Real
   affected M7 hardware validation is still required before claiming parity with
   the FreeRTOS CM7/r0p1 port.

3. Finish Cortex-M23 support or keep it explicitly excluded.

   Options:

   - implement a v8-M Baseline path with a PSPLIM slot similar to FreeRTOS NTZ;
   - or mark M23 as not supported until hardware/toolchain validation exists.

   Current policy: M23 has compile-covered SVC first-start mechanics, but it is
   not runtime-supported until it has PSPLIM/security context policy.
   FreeRTOS has a PSPLIM slot in the CM23 NTZ context layout, but it also gates
   actual PSPLIM register access through target/security configuration because
   Non-secure Cortex-M23 does not have a Non-secure PSPLIM register. The fiber
   baseline path still has no PSPLIM slot, and
   `FIBER_PORT_USES_PSPLIM_REGISTER`
   remains disabled unless a future port explicitly implements that layout.

   Future direction: copying the FreeRTOS-style M23 layout is useful if `fiber`
   wants to claim ARMv8-M Baseline/Mainline parity. That work should be done as
   a dedicated ARMv8-M portability pass after the unsupported-port gate exists,
   not as part of STM32H7/M7 hardening. The implementation should separate:

   - a context slot for PSPLIM;
   - a compile-time `FIBER_PORT_USES_PSPLIM_REGISTER` trait;
   - M23 Non-secure behavior, where PSPLIM register access must stay disabled;
   - M23 Secure-only behavior, which needs separate validation;
   - M33/M55 Mainline behavior, where PSPLIM register access is expected.

4. Implement and validate ARMv8-M Non-secure behavior.

   Required checks:

   - a port-owned `FIBER_PORT_INITIAL_EXC_RETURN = 0xFFFFFFBCu` path;
   - PSPLIM symbol selection;
   - CPACR/NSACR behavior for FP access;
   - vector table and PendSV wiring in the current security domain.
   - context slots for `CONTROL`, `PSPLIM`, and security-domain state when
     matching a FreeRTOS CM33/CM55-style port.

   Current policy: Non-secure and Secure-to-Non-secure bank builds remain
   unsupported until their selected ports provide the required security-domain
   context state.

5. Complete MVE/PAC/BTI policy for Cortex-M55 class targets.

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
   FIBER_NORETURN void fiber_start(void);
   ```

   `fiber_start()` calls the configured scheduler hook with `current == NULL`,
   validates the returned first context, and seeds it as the current context.
   PendSV later saves that context, asks the scheduler bridge for the next
   context, and restores only the returned context. The core API does not
   accept `from` or `to` from Thread mode.

   Each selected port uses SVC for first start. Ports no longer have a direct
   trampoline fallback. PendSV must still verify from the
   active `EXC_RETURN` value that the interrupted Thread context used PSP before
   saving a source context. A pre-start or foreign PendSV now traps with `'j'`
   instead of publishing a bogus saved stack pointer.

   The port also checks live PSP source-save headroom before writing the
   software frame. If the save would cross the current fiber stack base, it
   traps with `'d'` before modifying memory. This is stricter than the small
   FreeRTOS PendSV snippets, which rely on the broader RTOS stack-checking
   infrastructure.

   There is no v2 public API for starting from a caller-provided port boot
   record. Ports without hardware validation are not runtime-supported.

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
   SVC vector validation is mandatory because SVC is mandatory for first
   start.

   This proves vector-table routing. The ARMv7E-M SVC first-start path adds a
   separate dispatch check by validating MSP-frame alignment and decoding the
   SVC opcode plus immediate in `fiber_svc()`. It traps with `'u'` when the
   instruction is not the configured `SVC #FIBER_SVC_START_NUMBER`.

3. Keep the ARMv7E-M SVC-based first-fiber start path validated separately.

   FreeRTOS starts the first task through an SVC handler and enters the task by
   exception return. The ARMv7E-M `fiber` path now does the same high-level
   thing, while adding extra local checks:
   privileged Thread/MSP setup, optional MSP rewind and read-back, pending
   PendSV cleanup before interrupts reopen, SVC immediate validation,
   seeded-current validation, fault exception enable, BASEPRI cleanup, SVC
   MSP-frame alignment, SVC opcode/immediate validation, PSP setup, and
   `CONTROL.FPCA` verification. The SVC handler does not set
   `CONTROL.SPSEL` from Handler mode; the first Thread-mode PSP entry is
   selected by `EXC_RETURN`, as in the FreeRTOS first-task start path.

   The direct trampoline is no longer available. New ports must add an SVC
   first-start path before they can become runtime-supported.

4. Consider moving PendSV assembly into a dedicated assembly source.

   Rationale: naked C plus inline assembly works, but a dedicated assembly file
   can make architecture-specific variants clearer once M23/M33/M55 support is
   expanded.

## Definition of Done

The library can claim FreeRTOS-style STM32 Cortex-M CPU-port support only when:

- each claimed core family has an explicit support status;
- each claimed core family has a concrete selected port header/source pair that
  exports the full port interface;
- common runtime files contain no architecture-specific PendSV, SVC, direct
  trampoline, or synthetic-frame fallback for claimed ports;
- the claimed core families compile with representative GCC target flags;
- the STM32H7/M7 path remains hardware validated;
- M23, M33 Non-secure, and M55/MVE are either implemented and validated or
  explicitly excluded;
- docs and source comments use the same support claims;
- context-switch safety checks reject delayed-switch cases caused by interrupt
  masks.
