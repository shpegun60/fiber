# Fiber Decision Log

## 2026-07-13: Move Privileged Schedule Requests Behind Selected Ports

`fiber_schedule()` remains the public cooperative trigger, but it no longer
reads CPU special registers or writes PendSV state itself. It invokes the
selected-port ABI in two steps:

- `fiber_port_require_schedule_environment()` validates the port-owned
  Thread-mode and interrupt-mask rules;
- `fiber_port_request_schedule()` performs the selected request mechanism.

The common runtime retains current-context lifecycle ownership through
`fiber_internal_require_schedule_current()`. Direct privileged ports call that
guard after the IPSR check and before PRIMASK, BASEPRI, and FAULTMASK checks, so
the CM7 failure order remains `i -> G -> p -> b -> f -> PENDSVSET`.

The compile matrix now proves exactly one definition of both selected-port ABI
symbols and rejects CPU-specific access in the body of `fiber_schedule()`.
This is a source-boundary and generated-assembly checkpoint, not a renewed H7
hardware-runtime claim; normal and trap validation must be repeated on board.

## 2026-07-13: Close Opaque-Port Portability Gaps

A contract-level source audit against local FreeRTOS commit `a50edad`, covering
classic, MPU, v8-M, NTZ, TF-M, and MVE/PAC port groups, confirms that the
selected-port-owned opaque context can represent every STM32-relevant Cortex-M
profile without adding CPU layout to the common core. This does not replace the
required line-by-line parity ledger for each implemented port.

The contract is tightened before structural migration:

- `fiber_context_metadata_types.h` is the public type-only metadata layer;
  `internal/fiber_context_metadata.h` contains helper declarations;
- `fiber_port_context_init()` owns context alignment, extent-overflow, and
  context/stack overlap checks and performs them before its first write;
- `fiber_pendsv_init_lowest_priority()` is explicitly transitional diagnostic
  surface, not a sixth frozen public API function;
- `fiber_port_request_schedule()` is mechanism-neutral: privileged ports may
  pend PendSV directly, while unprivileged MPU ports must enter a validated
  port-owned SVC that pends PendSV from Handler mode;
- the existing CM7 Thread-mode register checks and direct PendSV publication
  now live behind the selected-port environment/request boundary; remaining
  common-runtime CPU access moves with the opaque-context transition;
- common scheduling code does not read CPU mask registers. Privileged ports
  validate them before direct PendSV publication; unprivileged ports validate
  safely observable state before SVC and the real mask state in Handler mode;
- every unprivileged restore guarantees zero PRIMASK and, where implemented,
  zero BASEPRI and FAULTMASK;
- selected-port configuration calls a common-owned lifecycle guard and never
  reads common scheduler/current globals directly;
- MPU ports must protect common runtime and context state from unprivileged
  writes and own CONTROL, PSPLIM, MPU, secure-context, PAC, and FP/MVE storage;
- Secure and TF-M integration is a matched companion component/artifact, not an
  additional cooperative scheduler port. It may live in a separate Secure
  target or be supplied by TF-M and never defines a second callable fiber runtime
  ABI in the same runtime image;
- separate Secure images expose a versioned gateway/service ABI and require a
  manifest or startup compatibility check because normal link relocations cannot
  validate two firmware images;
- every target tree includes the public type-only
  `fiber_context_metadata_types.h` layer;
- every configuration that changes context layout or saved-state meaning gets
  a distinct ABI identity and validation record.

This remains a documentation-only refinement. It proves that the architecture
can host the relevant FreeRTOS port families; it does not claim those ports are
implemented or hardware-validated.

## 2026-07-13: Define Opaque Selected-Port Context ABI

Before production ports are added in bulk, the common runtime will move to the
opaque selected-port context boundary defined in
`V2_OPAQUE_CONTEXT_CONTRACT.md`:

- the public API remains limited to `fiber_init()`, `fiber_current()`,
  `fiber_scheduler_set_pick_next()`, `fiber_start()`, and `fiber_schedule()`;
- application code receives the complete selected `FiberContext` type for
  static allocation but must treat all fields as private;
- common translation units see only `typedef struct FiberContext FiberContext`
  and must not dereference, size, align, or inspect the context;
- the selected port owns the complete context layout, construction, immutable
  port seal, dynamic restore validation, startup state, and SVC/PendSV transfer;
- common code owns scheduler semantics, callback storage, recursion and
  hot-swap policy, NULL handling, and current-context publication;
- CPU-neutral immutable metadata may be shared, but it is not a substitute for
  the selected port's final integrity seal;
- live saved-stack-pointer and FP/MVE state are validated dynamically and are
  not placed in an immutable hash by default;
- initial MSP rewind or validation is one port-runtime startup policy, not a
  permanent field required in every fiber context;
- selected internal type-only headers complete scheduler CPU-state tokens that
  common code may allocate and pass without inspecting;
- each context layout carries port identity, layout version, size, alignment,
  and feature identity, with a real link-time mismatch guard required before
  precompiled library objects are supported.

The first structural move must preserve the current scheduler critical-section
placement, frame layout, panic codes, assembly behavior, and temporary
per-context MSP behavior. Cleanup and ownership changes that affect behavior
remain separate commits with separate hardware validation.

This is a documentation-only decision. The current source still uses the
transitional shared `FiberContext`/`FiberBoot` layout, and no runtime support
claim changes at this checkpoint. This decision supersedes older architectural
statements that require one common-known context or boot-record layout for all
ports.

## 2026-07-12: Close Startup and Scheduler-Hook State Gaps

The runtime now fails closed around startup side effects and the user scheduler
callback:

- `fiber_start()` validates privileged Thread mode on MSP before any SCB/NVIC
  priority write;
- every port exception initializer independently enforces privileged Thread/MSP
  preconditions, so a direct internal call cannot bypass the common check;
- the concrete `ARM_CM7/r0p1` port always owns and enables errata 837070
  handling. The old `FIBER_CORTEX_M7_R0P1_ERRATA_837070` integration switch is
  a compile error;
- existing CFSR/HFSR/DFSR evidence is preserved by default. Clearing it is an
  explicit `FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START=1` application policy;
- enabling available configurable faults remains the explicit conservative
  default through `FIBER_ENABLE_CONFIGURABLE_FAULTS=1`;
- scheduler callbacks must preserve `PRIMASK`, `FAULTMASK`, `BASEPRI`, and
  `CONTROL`. The runtime snapshots and validates those registers around both
  first selection and PendSV selection;
- the H7 harness has separate first/next mask-mutation trap modes;
- the compile matrix now runs a complete Cortex-M7F eight-priority-bit build,
  relocatable link, and six-symbol selected-port ABI audit.

The settings-only matrix passes. These runtime changes still require a fresh H7
normal run and all documented trap modes before restoring the hardware claim.

## 2026-07-12: Canonicalize Port Policy and Exact Stack Geometry

The selected-port contract is now the single source of CPU facts across every
compile-covered profile:

- common runtime code consumes only `FIBER_PORT_*` traits;
- `FIBER_PORT_TRAITS_LEGACY_BRIDGE`, old `FIBER_HAS_*` aliases, and
  `FIBER_USE_PSPLIM_REGISTER` are compile errors;
- CPACR setup, FPCA cleanup, EXC_RETURN, stack alignment, vector-bank choice,
  canary encoding, PendSV publication, and context-boundary DSB/ISB barriers
  are mandatory port/runtime behavior rather than application tuning;
- FPU context support requires agreement between compiler FP generation and
  CMSIS silicon capability. The library does not synthesize `__FPU_USED` and
  has no force-save override;
- the initial synthetic frame is built directly down from `stack_top`. After
  SVC restore, PSP equals `stack_top`, so the old independent top guard is
  unnecessary;
- minimum usable stack is exactly the selected port's maximum saved context,
  including high FP registers and the architectural alignment word. CM7F uses
  208 bytes, or 240 bytes including the default low red zone;
- initial context bytes, high-FP software bytes, exception alignment padding,
  maximum saved-context bytes, and saved-SP alignment are explicit mandatory
  selected-port traits rather than common Cortex-M assumptions;
- global UNALIGN_TRP and DIV_0_TRP choices moved to
  `fiber_platform_policy.h` because they affect the complete application;
- obsolete settings fail explicitly instead of being ignored;
- the compile matrix now contains negative probes for every remaining boolean,
  every removed setting/alias, vector mode, SVC immediate, red-zone alignment,
  and BASEPRI priority encoding.

The full compile/link matrix and STM32H7 Debug build pass. This changes initial
PSP geometry and therefore requires a fresh H7 normal/trap hardware run before
the current code can inherit an old runtime-validation claim.

## 2026-07-12: Make CM7 Settings and Saved Frames Fail-Closed (Superseded)

The top-guard and configurable-reserve decisions in this entry were superseded
later on the same date by exact stack geometry and canonical port ownership.

A second line-by-line comparison against local FreeRTOS commit `a50edad`
tightened the concrete `ARM_CM7/r0p1` contract without changing its
`r4-r11`/`EXC_RETURN`/FP save and restore order:

- CPU facts are selected-port-owned. The CM7 initial `EXC_RETURN`, security
  domain, FPCA policy, FPU presence, and saved-frame layout cannot be changed
  into another architecture by application settings;
- optional startup-validation switches were removed from the production CM7
  contract. Vector routing, priority readback, implemented-priority probing,
  PRIGROUP compatibility, CPUID, and errata checks are mandatory;
- `fiber_start()` validates privileged Thread/MSP and mask state before
  configuring PendSV/SVCall priorities, matching FreeRTOS scheduler-start
  ownership without allowing an uncontrolled privileged-register fault;
- the default scheduler `BASEPRI` accounts for the unavoidable subpriority bit
  when all eight NVIC priority bits are implemented. Compile-time and runtime
  checks reject incompatible thresholds;
- suspended contexts require an exact selected-port `EXC_RETURN`, complete
  software/hardware/FP frame bounds, valid `xPSR.T`, Thread-mode stacked IPSR,
  an even stacked PC, and any `xPSR.STACKALIGN` word;
- this superseded checkpoint still used a separate hardware-frame top guard.
  The current contract removes that guard and derives the minimum directly from
  the selected port's exact maximum saved context plus the low red zone;
- `FIBER_EXC_LEVELS_ON_PSP` and `FIBER_BOOT_EXTRA_BYTES` were removed. Nested
  handlers use MSP, and applications choose an actual stack size above the
  architectural minimum for their own call depth and local objects;
- boot-record, canary, scheduler bridge, and panic helpers reachable from
  PendSV use the general-registers-only compiler contract;
- the compile matrix includes expected-failure probes for invalid settings and
  a positive eight-priority-bit default probe.

These changes invalidate the active H7 hardware claim until `NORMAL_RUN` and
all documented trap modes, including the saved-xPSR/PC/alignment modes, pass on
the board. Compile and link coverage is not a substitute for that run.

## 2026-07-12: Make Port ABI and Restore Validation Non-Optional

The paranoid FreeRTOS comparison found several cases where object-only compile
coverage could pass while the selected runtime port was incomplete or safety
checks could be compiled away. The v2 contract is tightened as follows:

- Cortex-M4/M4F selects the generic `armv7em` implementation; Cortex-M7 selects
  the concrete `ARM_CM7/r0p1` implementation. They no longer share an
  ambiguous source guard.
- the STM32H7 embedding build includes the concrete CM7 source group and
  excludes all non-selected port source directories;
- `tools/compile_matrix.ps1` performs a relocatable link for every mode and
  uses `nm` to require exactly one definition of each mandatory port ABI
  symbol. Compiling unrelated source objects is no longer considered proof of
  a complete selected port;
- restore-context and current-context ownership checks are mandatory.
  `FIBER_VALIDATE_SCHEDULED_CONTEXT` and `FIBER_VALIDATE_CURRENT` are obsolete
  and now produce compile errors if defined;
- every just-saved current context and every selected restore target is checked
  before the scheduler bridge permits restore;
- saved `EXC_RETURN` accepts only the exact basic/extended encodings exported
  by the selected port. Broad signature or Thread/PSP-bit checks are not enough;
- the low-stack canary is written and checked even when PSPLIM is available, so
  the two mechanisms remain independent defenses;
- the fast boot-record path checks pointer ordering, stack alignment, available
  size, entry state, and MSP policy before canary or saved-frame dereferences;
- PendSV verifies that the complete live hardware exception frame, including
  an extended FP frame when active, remains below the declared `stack_top`;
- FPU enable policy now validates CPACR and FPCCR readback instead of merely
  reading and discarding those registers;
- transitional v8-M unsupported-feature gates run regardless of optional
  exception wiring diagnostics. Disabling diagnostics cannot turn an
  unvalidated profile into runtime support;
- the first scheduler call happens after common FPU/platform bootstrap. Every
  scheduler hook must use `FIBER_SCHEDULER_HOOK_ATTR` and must not execute FP or
  MVE instructions, because later calls execute in PendSV.

These changes affect runtime validation behavior. The previous H7 record stays
historical until normal mode and all trap modes, including canary, exact
`EXC_RETURN`, and short-frame traps, pass on the board again.

The heuristic device-header selection in the embedding `mcu_core.h` is outside
this checkpoint and is intentionally unchanged.

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

Common runtime code only consumes `FIBER_PORT_USES_PSPLIM_REGISTER` and the
selected port API; it no longer includes a target-wide PSPLIM helper.

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
`fiber_port_scheduler_critical_enter()` /
`fiber_port_scheduler_critical_exit()` contract around the scheduler hook.
PendSV request publication itself is not wrapped in PRIMASK.

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

Historical note: at this checkpoint the H7 path still lived in
`port/armv7em`. The 2026-07-12 selected-port decision above supersedes that
layout: H7 now uses `port/ARM_CM7/r0p1`, while generic `armv7em` serves M4/M4F.

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

- `fiber/port/fiber_feature_policy.h` consumes the canonical
  `FIBER_PORT_HAS_EXTENDED_FP_CONTEXT`, `FIBER_PORT_USES_PSPLIM_REGISTER`,
  `FIBER_PORT_HAS_PAC`, and `FIBER_PORT_HAS_BTI` traits.
- MVE-FP follows the extended FP save/restore model. MVE without scalar FP is
  rejected by runtime policy validation because the current assembly does not
  implement an MVE-only register save path.
- PSPLIM register access is no longer implied only by the architecture family.
  `FIBER_PORT_USES_PSPLIM_REGISTER` is the actual access gate, keeping
  M23/security variants from accidentally writing an unsupported or wrong-bank
  PSPLIM.
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
  SVC vector validation is mandatory because SVC is mandatory for first start.
- `FIBER_SCHEDULER_BASEPRI` is validated against the hardware-implemented NVIC
  priority bits using a FreeRTOS-style write/readback probe.
- `AIRCR.PRIGROUP` is validated with the same FreeRTOS-style rule used by the
  Cortex-M ports: scheduler `BASEPRI` assumes priority bits are not split into
  an unsafe subpriority configuration.
- Cortex-M7 r0p0/r0p1 CPUID values are accepted only by the concrete port whose
  errata workaround is always enabled.

New panic codes:

- `'Y'`: PendSV vector entry mismatch.
- `'y'`: SVC vector entry mismatch.
- `'Q'`: scheduler BASEPRI masks no implemented priority bits.
- `'q'`: scheduler BASEPRI contains unimplemented priority bits.
- `'g'`: priority grouping or 8-bit priority threshold is incompatible with
  the scheduler BASEPRI policy.
- `'7'`: affected Cortex-M7 r0p0/r0p1 core without the BASEPRI errata gate.

At that checkpoint the portable defaults used conservative switch knobs. Those
knobs were later removed: PendSV publication is unmasked, matching FreeRTOS
yield, while the selected port always emits its required DSB/ISB barriers.

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
- The concrete `ARM_CM7/r0p1` port always emits a FreeRTOS-style errata 837070
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

Status: historical. The direct-switch API, configurable EXC_RETURN, force-FPU
mode, and switch mask/barrier knobs described below were removed by the v2
canonical selected-port contract. Keep the measurements as history only; use
the 2026-07-12 decisions and `FIBER_SETTINGS.md` for current behavior.

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
- The validated privileged CM7 request path rejects a real scheduler jump when
  `PRIMASK`, BASEPRI, or FAULTMASK is nonzero, because a pending PendSV delayed
  past a critical section is unsafe. This behavior is preserved by the selected
  port environment/request boundary; it is not a requirement for common code
  to read privileged registers.
- Future unprivileged MPU request paths enter a validated yield SVC instead.
  Handler mode validates the real mask state before publishing PendSV, and
  every unprivileged restore guarantees zero PRIMASK and, where implemented,
  zero BASEPRI and FAULTMASK.
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
- The old H7 performance-mode measurements remain historical evidence only.
  Lazy FP is the sole surviving performance policy; switch masking and barrier
  disable knobs no longer exist.

Known limits:

- STM32H7 / Cortex-M7 is the primary validation target and has the strongest
  historical hardware evidence; the latest behavior changes require a fresh
  checklist run.
- ARMv8-M Non-secure remains a transitional compile-only scenario selected by
  `FIBER_TRANSITIONAL_V8M_RUN_NONSECURE`; EXC_RETURN is selected-port-owned and
  cannot be overridden by common application settings.
- Cortex-M23 PSPLIM behavior is intentionally not enabled by the generic
  baseline path. FreeRTOS has context slots for PSPLIM, but its Non-secure M23
  port does not program a non-secure PSPLIM register.
- Cortex-M55 / MVE needs a concrete port-owned context layout and hardware
  validation. There is no force-save override; a production port must derive
  and implement every required FP/MVE context slot from compiler and CPU facts.
- There is no v2 public API for starting from a caller-provided `FiberBoot`
  record. Ports without hardware validation are not runtime-supported.
- `tools/compile_matrix.ps1` provides the compile-only sanity matrix. It does
  not replace hardware tests, but it must stay green before widening support
  claims beyond STM32H7/Cortex-M7.
