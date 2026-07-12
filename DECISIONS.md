# Fiber Decision Log

## 2026-07-12: Remove target Directory

The `fiber/target` source directory was removed.

The remaining target-level files moved out of `fiber/target`:

```text
fiber/target/fiber_panic.c    -> fiber/fiber_panic.c
fiber/target/fiber_panic.h    -> fiber/fiber_panic.h
fiber/target/fiber_settings.h -> fiber/port/fiber_settings.h
```

`fiber_panic` is a runtime-level fallback hook, not CPU-port policy.
`fiber_settings.h` is now a port-root configuration header because selected
ports consume those defaults while exporting the CPU contract.

## 2026-07-12: Remove fiber_target.h Facade

`fiber/target/fiber_target.h` was removed. The selected-port facade is now:

```text
fiber/port/fiber_port_selected.h
```

Public runtime headers include `port/fiber_port_selected.h` directly. The
selected port provides the CPU contract through its `fiber_portmacro.h`; the
facade then applies common post-port checks, stack alignment helpers,
exception-frame headroom constants, and feature-policy gates.

Important ownership rule:

```text
selected port owns CPU facts and low-level mechanics;
fiber_port_selected.h validates and exports the selected contract;
fiber_target.h must not be recreated as a CPU-policy layer.
```

`FIBER_SVC_START_NUMBER` is also port-owned now. Each selected
`fiber_portmacro.h` provides the default and checks that the value fits the
8-bit SVC immediate field.

## 2026-07-12: Move Exception Setup Into Selected Ports

PendSV/SVC exception setup is no longer owned by `fiber/target/fiber_irq.c`
and `fiber/target/fiber_irq.h`. It is also no longer a shared root
`fiber/port/fiber_port_exception.*` implementation.

Each concrete port source group now owns its exception setup file:

```text
fiber/port/armv6m/fiber_port_exception.c
fiber/port/armv7m/fiber_port_exception.c
fiber/port/armv7em/fiber_port_exception.c
fiber/port/transitional_v8m/fiber_port_exception.c
fiber/port/ARM_CM7/r0p1/fiber_port_exception.c
```

The selected-port exception setup owns:

- PendSV priority programming and read-back validation;
- SVCall priority programming and read-back validation;
- direct/wrapper vector routing validation for SVC and PendSV;
- pending PendSV cleanup before first start;
- implemented NVIC priority-bit probing;
- scheduler BASEPRI threshold validation;
- AIRCR.PRIGROUP validation for BASEPRI ports;
- Cortex-M7 r0p0/r0p1 errata policy validation.

The public API names remain stable for now:

```c
void fiber_pendsv_init_lowest_priority(void);
void fiber_exception_runtime_check(void);
```

This is an ownership move, not a behavior change. The implementation consumes
selected-port traits and helpers, including `fiber_port_vectors_base_ptr()` and
`FIBER_PORT_SCHEDULER_BASEPRI`.

`fiber_port_exception.c` includes the selector guard first, then consumes the
selected CPU/platform contract through `fiber_portmacro.h`. It must not include
`fiber_target.h`, `fiber_compiler.h`, `fiber_panic.h`, FPU/PSPLIM/VTOR helpers,
or unvalidated feature-policy headers directly. If exception setup needs a CPU
fact, validation knob, compiler helper, CMSIS view, or diagnostic contract, the
selected port must expose it from `fiber_portmacro.h`.

## 2026-07-12: Move VTOR/Vector Policy Into Selected Ports

VTOR and vector-table access are no longer owned by
`fiber/target/fiber_vtor.h`. That target helper was removed.

The selected port now owns:

- whether the CPU/profile exposes `SCB->VTOR`;
- whether vector-table access targets the current bank or the Non-secure bank;
- the fallback vector base for profiles without VTOR;
- vector-table base masking/alignment before reads and writes;
- the initial MSP read used by boot/MSP rewind policy.

Common runtime code now calls:

```c
uintptr_t fiber_port_vectors_base_addr(void);
const uint32_t *fiber_port_vectors_base_ptr(void);
uint32_t fiber_port_read_initial_msp(void);
void fiber_port_set_vectors_base_addr(uintptr_t base);
```

Ports without VTOR expose an explicit `0x00000000` vector-base fallback.
ARMv7-M, ARMv7E-M, ARM_CM7/r0p1, and v8-M mainline-capable ports read/write
the selected VTOR bank inside their own port header.

## 2026-07-12: Move PSPLIM Policy Into Selected Ports

PSPLIM register policy is no longer owned by `fiber/target/fiber_pslim.h`.
That target helper was removed.

The selected port now owns:

- whether the CPU/security state has a PSPLIM register;
- whether this selected runtime is allowed to write that register;
- whether the saved context layout has a PSPLIM slot;
- whether PSPLIM access targets the current security bank or the Non-secure
  bank;
- the C API used by common startup code:
  `fiber_port_psplim_read()`, `fiber_port_psplim_write()`, and
  `fiber_port_psplim_config()`;
- the asm restore macro used by port code: `FBR_ASM_MSR_PSPLIM()`.

Ports without PSPLIM expose explicit disabled/no-op definitions. The
transitional v8-M port owns the temporary `psplim` / `psplim_ns` bank selection
until concrete v8-M production ports replace it.

Common runtime code only consumes `FIBER_USE_PSPLIM_REGISTER` and the selected
port API; it no longer includes a target-wide PSPLIM helper.

## 2026-07-12: Move FPU Policy Into Selected Ports

FPU capability detection and FP-context policy are no longer owned by
`fiber/target/fiber_fpu.h`.

The selected port now owns:

- whether the toolchain is building FP instructions;
- whether the silicon exposes an FPU;
- whether CMSIS reports `__FPU_USED`;
- whether the port supports scalar FPU use;
- whether the port saves/restores extended FP context;
- whether first start must clear or validate `CONTROL.FPCA`;
- how early FPU enable is applied through `fiber_port_fpu_enable_early()`.

The root `fiber_fpu.h` / `fiber_fpu.c` pair was removed. Common runtime code
now calls the selected-port API `fiber_port_fpu_enable_early()`. Ports without
FPU provide a no-op implementation; FPU-capable ports own CPACR/FPCCR setup,
lazy/eager policy application, barriers, and read-back checks.

This matches the v2 direction: selected ports export the CPU interface, while
common runtime code only consumes that interface.

## 2026-07-11: H7 Normal Run After SVC Dispatch Hardening

The STM32H7 / Cortex-M7 board passed `FIBER_VAL_NORMAL_RUN` after the current
SVC dispatch hardening checkpoint:

```text
208be61157ee3f06ba4b4bfc3be700b37d78eea5
```

Observed snapshot:

- `validation_flags = 0x000001FF`;
- `validation_failures = 0`;
- `last_panic_code = 0`;
- `validation_mode_seen = 0`;
- counters reached `1246134`, `1246135`, and `1246134`;
- FP accumulator relationships remained valid.

The debugger stopped the CPU during `fiber_schedule()` / `fiber_pendsv()`, so
the one-count counter skew is expected for that snapshot.

This is a normal-run validation record only. The H7 runtime-validation claim for
this exact checkpoint remains partial until the trap modes in
`H7_RUNTIME_VALIDATION.md` are rerun after the SVC dispatch hardening.

## 2026-07-11: SVC-Only First Start

The direct boot trampoline path was removed.

Current runtime startup has one path:

- `fiber_start()` asks the scheduler hook for the first context with
  `current == NULL`;
- the returned context is validated and seeded as the runtime-owned current
  context;
- the selected port enters the first fiber through SVC and exception return.

The old non-SVC start selector was deleted. There is no direct-start
configuration path left in the runtime.

This intentionally narrows the active support claim:

- ARMv7E-M remains the active runtime-supported port;
- ARMv6-M, ARMv7-M, and transitional v8-M now have compile-covered SVC
  first-start symbols, but they are not runtime-supported until hardware
  validation is recorded for each profile;
- the compile matrix now builds SVC wrapper and direct-vector modes for every
  selected profile instead of keeping a fallback-start fence.

This is behavior-affecting. The STM32H7 validation label must stay downgraded
until the SVC-only build passes `H7_RUNTIME_VALIDATION.md` again on hardware.

## 2026-07-11: Scheduler-Selected First Context

`fiber_start()` no longer accepts a direct first `FiberContext`.

The first context is now selected through the same scheduler ownership model as
later switches:

- application code installs a scheduler hook before start;
- `fiber_start()` requires the hook and a clear current-context slot;
- `fiber_start()` calls the hook once with `current == NULL`;
- the returned first context must be non-NULL, initialized, sealed, aligned, and
  valid for restore;
- only after that validation does the runtime seed the current context and enter
  the selected port first-start path.

This keeps direct task selection out of the core API. It mirrors the FreeRTOS
ownership idea that the scheduler owns the current task pointer, while keeping
the runtime cooperative and user-scheduler-driven.

This is behavior-affecting. The previous H7 validation result remains
historical until the normal and trap modes are rerun with this API shape.

The H7 validation harness splits first-start scheduler result traps from later
PendSV scheduler result traps:

- `FIBER_VAL_TRAP_NULL_FIRST` and `FIBER_VAL_TRAP_BAD_FIRST` exercise
  `pick_next(NULL, user)`;
- `FIBER_VAL_TRAP_NULL_NEXT` and `FIBER_VAL_TRAP_BAD_NEXT` exercise
  `pick_next(current, user)` after the first fiber has already entered.

## 2026-07-11: Start Real Port Common Helpers

The `fiber/port` helper-root convention is now reserved for reusable helper
code such as compiler, diagnostics, and static-assert ABI headers.

PRIMASK save/restore is intentionally not a root helper. The selected port owns
its local PRIMASK implementation and exposes only the generic
`fiber_port_switch_mask_enter()` / `fiber_port_switch_mask_exit()` contract to
common runtime code.

## 2026-07-12: Move BASEPRI Policy Into Selected Ports

`fiber/target/fiber_basepri.h` is removed. BASEPRI is no longer a target-wide
helper or selector-inferred CPU policy.

Each selected port now owns:

- whether BASEPRI exists;
- the scheduler BASEPRI threshold;
- C read/write helpers exposed as `fiber_port_basepri_read()` and
  `fiber_port_basepri_write()`;
- naked-asm scheduler critical-section snippets;
- Cortex-M7 r0p0/r0p1 errata handling when applicable.

Ports without BASEPRI provide no-op BASEPRI helpers and use saved PRIMASK for
the scheduler bridge. Common runtime code may only call the selected-port API.

## 2026-07-11: Rename Transitional v8-M Fallback

The temporary v8-M fallback directory was moved out of the `fiber/port` helper
root into `port/transitional_v8m`.

This is intentionally a naming-only boundary cleanup:

- `transitional_v8m` is not a real shared helper layer;
- it remains compile-covered and runtime-gated;
- it must be split into concrete v8-M ports before any FreeRTOS-level runtime
  support claim is made;
- the future `fiber/port` helper-root convention is reserved for reusable
  helper code, not selected-port fallback behavior.

## 2026-07-11: Transitional v8-M Port Split

Architecture fallback code for v8-M profiles that are not concrete v2 ports yet
lives in `fiber/port/transitional_v8m`.

This is a boundary cleanup:

- `fiber_core.c` no longer owns PendSV assembly or synthetic software-frame
  construction for any selected port;
- `fiber_core.c` also delegates switch-publication masking to the selected
  port boundary;
- `fiber/port/fiber_port_selected.h` includes
  `transitional_v8m/fiber_port_transitional_v8m.h` only for profiles that do
  not yet have a concrete selected port header;
- `port/transitional_v8m` remains transitional and runtime-gated. It is not a
  FreeRTOS-level support claim for v8-M Baseline/Mainline or ARMv8.1-M.

The validated ARMv7E-M/H7 path remains in `port/armv7em` and is not changed by
this cleanup.

## 2026-07-11: ARMv7-M Port Split Checkpoint

The Cortex-M3 / ARMv7-M path now lives in
`fiber/port/armv7m/fiber_port_armv7m.c`.

This is a focused port-layout step:

- ARMv7-M uses the mainline software frame order `[r4..r11][LR]`;
- the scheduler bridge is protected with the BASEPRI policy used by mainline
  Cortex-M ports;
- ARMv7-M has no high-FP, PSPLIM, MVE, PAC, or BTI handling in this port;
- `fiber_core.c` no longer defines `fiber_pendsv()` or
  `fiber_port_init_context_frame()` for ARMv7-M;
- the remaining transitional fallback is now limited to runtime-gated v8-M
  transitional profiles.

This does not create a runtime validation claim for STM32F1/Cortex-M3 class
targets. ARMv7-M remains compile-only until hardware tests exist.

## 2026-07-11: Direct-Vector Compile Coverage

After the H7 SVC/PendSV validation checkpoint, the next step is intentionally a
stabilization change, not a port refactor. The compile matrix now covers:

- wrapper vector mode with `FIBER_PENDSV_WIRED=1`;
- wrapper SVC mode on ARMv7E-M with `FIBER_SVC_WIRED=1`;
- PendSV direct-vector mode with `FIBER_PENDSV_VECTOR_DIRECT=1`;
- ARMv7E-M PendSV+SVC direct-vector mode with
  `FIBER_PENDSV_VECTOR_DIRECT=1` and `FIBER_SVC_VECTOR_DIRECT=1`.

This does not change the validated H7 wrapper-vector runtime path. Direct-vector
mode is compile-covered only until a board run records that exact wiring.

## 2026-07-11: H7 SVC/PendSV Runtime Validation Pass

The STM32H7 / Cortex-M7 v2 ARMv7E-M path passed the current scheduler-driven
hardware validation set after the SVC first-start and PendSV source-save
corrections.

Observed normal run:

- `validation_flags = 0x000001FF`;
- `validation_failures = 0`;
- `last_panic_code = 0`;
- all three counters progressed equally into multi-million switch counts;
- FP accumulator relationships stayed valid.

Observed trap runs:

- no scheduler hook trapped with `'K'`;
- `NULL` scheduler hook trapped with `'K'`;
- scheduler hook hot-swap after start trapped with `'k'`;
- `fiber_schedule()` under `PRIMASK` trapped with `'p'`;
- `fiber_schedule()` under `BASEPRI` trapped with `'b'`;
- scheduler hook returning `NULL` trapped with `'N'`;
- scheduler hook returning a context with `sp == NULL` trapped with `'P'`;
- `fiber_schedule()` under `FAULTMASK` trapped with `'f'`.

Two defects were found during the SVC migration and are now documented as
port-contract rules:

- SVC first-start must not rely on writing `CONTROL.SPSEL` from Handler mode.
  Thread-mode PSP selection comes from `EXC_RETURN`, matching the FreeRTOS
  first-task start model.
- PendSV must validate the active interrupted stack by inspecting
  `LR`/`EXC_RETURN` bit 2. `CONTROL.SPSEL` is not a sufficient proof inside
  Handler mode after an exception-entry path.

The same defect class was checked in the other current switch implementations:

- ARMv6-M and transitional v8-M PendSV paths were audited for the same
  source-stack proof. After the SVC-only first-start decision, those profiles
  are no longer runtime-startable until they grow their own SVC start path.

This restores the H7 runtime-validation claim for the active ARMv7E-M SVC
start plus scheduler-driven PendSV path. It does not validate M0/M23/M33/M55
hardware or ARMv8-M security/MVE/PAC/BTI behavior.

## 2026-07-10: ARMv7E-M SVC First-Start Checkpoint

The ARMv7E-M port now starts the first fiber through SVC by default:

- That checkpoint predates the current scheduler-selected first-context API and
  the later SVC-only first-start decision.
  The current API selects the first context through the scheduler hook before
  entering the port first-start helper.
- The first-start helper forces privileged Thread/MSP state, clears FPCA by
  clearing `CONTROL`, optionally rewinds MSP through the sealed boot plan,
  verifies MSP read-back, clears any pending PendSV while interrupts are still
  masked, enables IRQ and fault exceptions, executes
  `svc #FIBER_SVC_START_NUMBER`, and panics with `'y'` if SVC returns to the
  helper.
- `fiber_svc()` rejects SVC entry from PSP or an unaligned SVC MSP frame with
  `'l'`, validates the SVC opcode and immediate, traps with `'u'` on mismatch,
  clears `BASEPRI` like the
  FreeRTOS SVC first-task handler, validates the seeded current context,
  restores the synthetic software frame, sets PSP, verifies `CONTROL.FPCA` when
  configured, and enters the first fiber by exception return. The SVC handler
  does not set `CONTROL.SPSEL` from Handler mode; Thread PSP selection comes
  from `EXC_RETURN`, matching the FreeRTOS first-task start pattern.
- `fiber_pendsv_init_lowest_priority()` sets SVCall to the highest priority
  when SVC first-start is enabled, and runtime validation traps with `'w'` if
  SVCall does not read back as highest priority.
- The direct boot trampoline existed at this checkpoint, but it has since been
  removed by the SVC-only first-start decision.
- The STM32H7 application must wire `SVC_Handler()` as a naked branch to
  `fiber_svc()`. That wrapper lives in the embedding application tree, outside
  this repository.

This brings the ARMv7E-M first-start model closer to FreeRTOS while keeping the
runtime cooperative. It is behavior-affecting and must pass
`H7_RUNTIME_VALIDATION.md` before the v2 H7 path regains the previous hardware
validation claim.

## 2026-07-10: ARMv6-M Port Split Checkpoint

The Cortex-M0/M0+ Thumb-1 PendSV path now lives in
`fiber/port/armv6m/fiber_port_armv6m.c`.

This is a mechanical port-layout step:

- ARMv6-M uses the FreeRTOS Cortex-M0 non-MPU software frame order:
  `[LR][r4][r5][r6][r7][r8][r9][r10][r11]`.
- The saved stack pointer is published only after the full software frame is
  stored. This is stricter than the FreeRTOS CM0 ordering, which writes the TCB
  top-of-stack slot before completing the staged high-register stores.
- ARMv6-M still uses saved `PRIMASK` around the scheduler bridge because the
  profile has no `BASEPRI`.
- `fiber_core.c` no longer defines `fiber_pendsv()` when `FIBER_PORT_ARMV6M`
  is selected.
- ARMv8-M Baseline/Mainline fallback code still remains in `fiber_core.c` until
  those dedicated port files are split.
- This does not create a runtime validation claim for STM32F0/G0/C0/L0/U0
  class targets. ARMv6-M remains compile-only until hardware tests exist.

## 2026-07-10: H7 Validation Gate After 775648c

Commit `775648c` is a behavior-affecting v2 checkpoint. It is larger than a
feature-policy-only change: it carries the scheduler-driven execution model,
the pure scheduler port ABI, ARMv7E-M PendSV selection through the scheduler
bridge, handler-side critical sections, exception setup validation, and
unvalidated v8-M/MVE/TrustZone/PAC/BTI runtime gates.

Compile matrix and STM32H7 build success are necessary, but they do not preserve
the older H7 runtime-validated claim by themselves. The v2 ARMv7E-M path must
pass `H7_RUNTIME_VALIDATION.md` on hardware before this branch claims the same
runtime validation level as the previous H7 path.

## 2026-07-10: v8-M Feature Policy Gates

The v2 runtime now has explicit policy gates for Cortex-M profiles whose
FreeRTOS ports carry extra context state that the current generic fiber context
does not save yet:

- `fiber/port/fiber_feature_policy.h` defines `FIBER_HAS_EXTENDED_FP_CONTEXT`,
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
- The default ARMv7E-M SVC model expects an application `SVC_Handler()` wrapper
  that branches to `fiber_svc()` without clobbering LR/EXC_RETURN. Direct
  vectoring to `fiber_svc()` is supported with `FIBER_SVC_VECTOR_DIRECT=1`.
  `FIBER_VALIDATE_SVC_VECTOR` defaults to active because SVC is mandatory for
  first start.
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
- PendSV refuses to save a source context unless Thread mode is already using
  PSP. A spurious PendSV before the first PSP context is active traps with panic
  code `'j'` instead of overwriting `ctx->sp` with a pre-start stack state.
- PendSV also checks live PSP source-save headroom before writing the software
  frame. If the core or high-FP save would cross the current fiber stack base,
  it traps with panic code `'d'` before modifying memory below the stack.
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
- `FIBER_CORTEX_M7_R0P1_ERRATA_837070=1` enables a FreeRTOS-style errata 837070
  guard around handler-side `BASEPRI` writes on affected Cortex-M7 r0p1 parts.
  The fiber helper is stricter than the FreeRTOS minimum: it preserves and
  restores the previous `PRIMASK` instead of unconditionally re-enabling IRQs.
- The compile matrix now builds Cortex-M7 and Cortex-M7F with that errata gate
  enabled, but real r0p1 hardware validation is still required before claiming
  FreeRTOS CM7/r0p1 parity.

## 2026-07-10: v2 Scheduler Hook State Checkpoint

Commit `cf610cc` prepares the v2 scheduler-driven port boundary:

- `fiber_runtime_state.h` now owns the internal scheduler hook state:
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
- On cores with FAULTMASK, `fiber_schedule()` also rejects scheduler jumps when
  `FAULTMASK` is already set.
- The first-start path clears `CONTROL.FPCA` before entering the first fiber
  when an FPU context exists. On the current ARMv7E-M v2 path this happens
  through SVC first-start.
- The preferred low-level runtime API is `fiber_start()` plus
  `fiber_schedule()`. Higher-level yield/sleep/wait APIs should update scheduler
  state and then call `fiber_schedule()`.
- `fiber_start()` asks the scheduler hook for the first context with
  `current == NULL`, seeds that validated context as runtime-owned current, and
  the scheduler bridge updates it during every scheduler-driven switch. This
  mirrors the FreeRTOS `pxCurrentTCB` ownership model without exposing direct
  target selection to the core API.
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
- There is no v2 public API for starting from a caller-provided `FiberBoot`
  record. Ports without hardware validation are not runtime-supported.
- `tools/compile_matrix.ps1` provides the compile-only sanity matrix. It does
  not replace hardware tests, but it must stay green before widening support
  claims beyond STM32H7/Cortex-M7.
