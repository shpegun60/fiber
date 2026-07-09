# Fiber v2 Port Contract

## Purpose

`v2` is the branch for turning `fiber` into a FreeRTOS-style cooperative
Cortex-M context-switch core.

The goal is to reuse the proven CPU-port discipline from FreeRTOS while keeping
the library small and explicit:

- manual cooperative yield only;
- no FreeRTOS scheduler policy;
- no queues, semaphores, timers, heap, or FreeRTOS API surface;
- no preemptive tick switching unless it is added later as a separate feature;
- context switch robustness at the same level as FreeRTOS ports where support is
  claimed.

This branch may change internal layout and port boundaries. `main` remains the
stable STM32H7/Cortex-M7 validated branch.

## Target Outcome

The long-term target is a stable, auditable, FreeRTOS-style cooperative
Cortex-M context-switch core for STM32 projects.

This means:

- use the same CPU-port discipline that makes FreeRTOS reliable on Cortex-M:
  explicit port selection, exact exception-frame ownership, PSP-based Thread
  mode execution, PendSV/SVC ownership, target-aware EXC_RETURN, FPU/MVE policy,
  PSPLIM/security-domain policy, and per-port validation evidence;
- keep the runtime cooperative: the user decides when to yield;
- keep the library much smaller than FreeRTOS by excluding scheduler policy,
  priorities, queues, semaphores, timers, event groups, streams, and heaps;
- keep safety defaults at least as conservative as v1 unless a target-specific
  validation record justifies faster settings;
- add stronger paranoid checks where they improve failure mode quality without
  hiding timing bugs, for example Thread-mode guards, current-context
  validation, interrupt-mask guards, strict publication ordering, and explicit
  unsupported-target failures;
- treat FreeRTOS as the reference for CPU-port behavior, not as an API surface
  to clone.

The desired end state is not "it compiles for many cores". The desired end state
is: every claimed STM32 Cortex-M profile has a selected port, documented CPU
contract, known limitations, and validation level that matches the claim.

## Design Rules

1. Split by ARM core and architectural feature profile, not by STM32 marketing
   series.
2. Keep common runtime state and public API outside architecture-specific
   assembly.
3. Keep each port responsible for its own exception return, saved register
   layout, stack-limit policy, FPU/MVE policy, and security-domain policy.
4. Keep unsupported feature profiles explicit. A port that compiles is not
   automatically validated.
5. Keep safety defaults conservative. Performance settings are opt-in per
   target after hardware validation.
6. Prefer readable, auditable C plus small, isolated assembly blocks.
7. Do not copy FreeRTOS source code silently. If code is copied or closely
   adapted, keep the required MIT license notice.
8. Select exactly one active port at compile time. Ambiguous, missing, or
   conflicting port selection must fail with a clear compile-time error.
9. Normalize every architecture feature gate to `0` or `1` before use. No
   `#if FIBER_HAS_*` expression may depend on an undefined macro.
10. Separate mechanical file moves from behavior changes. A refactor commit that
    only changes layout must keep the generated code path equivalent enough to
    pass the same compile matrix and the same H7 runtime validation checklist.
11. Never weaken `main` safety defaults as part of a portability refactor. Faster
    settings must stay target-local, documented, and validated before promotion.

## Non-Goals

`v2` is not a FreeRTOS clone.

The following are out of scope for the core port contract:

- FreeRTOS task API compatibility;
- priority scheduling;
- tick interrupt scheduling;
- queues;
- semaphores;
- event groups;
- stream buffers;
- software timers;
- heap implementations;
- MPU task isolation as a scheduler feature.

Some CPU features used by FreeRTOS ports, such as MPU, TrustZone, PSPLIM, MVE,
PAC, and BTI, may still affect context-switch correctness. Those features are
in scope only at the CPU context and exception-return layer.

## Proposed Layout

The final layout can evolve, but the target direction is:

```text
fiber/
  fiber_core.c
  fiber_core.h
  fiber_boot.c
  fiber_boot.h
  fiber_stack.c
  fiber_stack.h
  target/
    fiber_settings.h
    fiber_panic.c
    fiber_panic.h
    fiber_compiler.h
    fiber_diagnostics.h
  port/
    fiber_port.h
    fiber_port_state.c
    fiber_port_state.h
    armv6m/
      fiber_port_armv6m.c
    armv7m/
      fiber_port_armv7m.c
    armv7em/
      fiber_port_armv7em.c
    armv8m_baseline/
      fiber_port_armv8m_baseline.c
    armv8m_mainline/
      fiber_port_armv8m_mainline.c
    armv81m_mainline/
      fiber_port_armv81m_mainline.c
```

The current one-file implementation may be split gradually. Behavior should not
change during a pure file-layout split.

## Port Selection Contract

Port selection must be deterministic and auditable.

Required rules:

- support automatic selection from compiler-provided architecture macros for
  small-library convenience;
- support explicit production selection through `FIBER_PORT_PROFILE`, similar
  in purpose to FreeRTOS `FREERTOS_PORT`;
- verify explicit `FIBER_PORT_PROFILE` against compiler `__ARM_ARCH_*` macros
  when those macros are available;
- allow selection mismatch only behind a named opt-in escape hatch for
  nonstandard toolchains;
- reserve `FIBER_FORCE_PORT_*` for unusual toolchains and compatibility, and do
  not allow it to be mixed with `FIBER_PORT_PROFILE`;
- produce exactly one internal `FIBER_PORT_*` selection macro;
- fail the build if no supported port matches;
- fail the build if more than one port matches;
- derive normalized aggregate gates such as `FIBER_PORT_IS_BASELINE`,
  `FIBER_PORT_IS_MAINLINE`, and `FIBER_PORT_IS_V8M`;
- prefer ARMv8.1-M Mainline over ARMv8-M Mainline if a future toolchain exposes
  both architecture macros;
- treat enabled MVE as ARMv8.1-M Mainline selection input when the toolchain
  exposes MVE but still reports only `__ARM_ARCH_8M_MAIN__`;
- keep STM32 family names out of the low-level switch logic;
- expose a diagnostic `FIBER_PORT_NAME` for the selected internal port;
- keep all `FIBER_HAS_*`, `FIBER_USE_*`, and `FIBER_PORT_*` macros normalized to
  `0` or `1` in one target feature header before any port source uses them.

STM32 series mapping belongs in documentation and board integration examples.
CPU context switching belongs to the ARM profile port.

Explicit profile names currently cover architecture classes, not every exact
FreeRTOS port directory:

```c
FIBER_PORT_PROFILE_AUTO
FIBER_PORT_PROFILE_ARMV6M
FIBER_PORT_PROFILE_ARMV7M
FIBER_PORT_PROFILE_ARMV7EM
FIBER_PORT_PROFILE_ARMV8M_BASELINE
FIBER_PORT_PROFILE_ARMV8M_MAINLINE
FIBER_PORT_PROFILE_ARMV81M_MAINLINE
```

Future splits may add more specific profiles, for example a Cortex-M7 r0p1
profile or ARMv8-M Secure/Non-secure profiles, when the implementation needs a
separate source path rather than only a policy gate.

`FIBER_PORT_SELECTION_ALLOW_MISMATCH` exists only for unusual toolchains or
bring-up experiments where compiler architecture macros are missing or known to
be wrong. Normal production builds should leave it disabled. The older
`FIBER_PORT_PROFILE_ALLOW_MISMATCH` spelling is kept as a compatibility alias.

## Core Profiles

The port split is based on architectural behavior:

| Profile | Typical STM32 families | Main concerns |
| --- | --- | --- |
| ARMv6-M | STM32F0, STM32G0, STM32C0, STM32L0, STM32U0, STM32WB0 | Thumb-1 assembly, no BASEPRI, no FPU, no mainline registers |
| ARMv7-M | STM32F1, selected STM32F2 class parts | Mainline PendSV path, no FP high-register context |
| ARMv7E-M | STM32F3, STM32F4, STM32G4, STM32L4, STM32F7, STM32H7, STM32WB | Mainline path, optional FPU, M7 errata policy |
| ARMv8-M Baseline | Cortex-M23 based STM32 parts | Baseline path, security state, PSPLIM access gates |
| ARMv8-M Mainline | STM32L5, STM32U5, STM32H5, STM32WBA | TrustZone, Non-secure EXC_RETURN, PSPLIM, optional FPU |
| ARMv8.1-M Mainline | STM32N6 class targets | MVE, PAC, BTI, PSPLIM, extended context policy |

The table is a routing aid, not a validation claim.

## FreeRTOS Parity Backlog

The current v2 selection layer covers the main STM32 Cortex-M architecture
classes. That does not mean every FreeRTOS Cortex-M port scenario is implemented
or validated.

Current boundary:

```text
Port selection for STM32 Cortex-M classes:
  implemented for auto and explicit profile modes

Full FreeRTOS-level port behavior for every STM32 Cortex-M scenario:
  not complete yet
```

Backlog required before stronger parity claims:

| Area | Current v2 status | Required future work |
| --- | --- | --- |
| Cortex-M7 r0p1 | Documented policy only. Current PendSV does not write `BASEPRI`, so the FreeRTOS r0p1 workaround is not required by the current code path. | Add a dedicated CM7/r0p1 policy or source split if any future PendSV, SVC, or handler-side section writes `BASEPRI`. Validate on real Cortex-M7 hardware before claiming parity with the FreeRTOS CM7 port. |
| ARMv8-M Baseline / M23 | Selection and compile-only coverage exist. Full PSPLIM/security behavior is not FreeRTOS-level yet. | Define PSPLIM slot policy, PSPLIM register access gates, Secure/Non-secure ownership, and hardware validation for the claimed domain. |
| ARMv8-M Mainline / M33 | Selection and compile-only coverage exist. TrustZone, Non-secure, NTZ, and TFM variants are not split like FreeRTOS yet. | Split or explicitly gate Secure, Non-secure, NTZ, and TFM behavior. Validate EXC_RETURN, vector ownership, PSPLIM access, FP access, and SVC/PendSV domain routing. |
| ARMv8.1-M / M55 / MVE | Selection can detect MVE and route to the ARMv8.1-M profile. Full MVE/PAC/BTI policy is not implemented. | Define MVE extended-context policy, PAC/BTI policy where applicable, stack-frame implications, and validation beyond scalar FP stress tests. |
| Source layout | Selection gates exist, but the main implementation is still being split from a shared source path. | Move CPU-specific save/restore/start logic into exactly one selected port source path per profile, matching the FreeRTOS discipline where the build includes one concrete port. |
| Hardware evidence | H7/M7 is the strongest validated path. Other profiles are compile-only unless separately recorded. | Promote each profile only after board-level smoke/runtime/FPU/security/performance validation as appropriate. |

Do not describe a profile as FreeRTOS-level only because it passes the compile
matrix. Compile-only proves that selection and syntax are coherent; it does not
prove exception return, security-domain behavior, FPU/MVE context behavior, or
real interrupt-mask timing on hardware.

## Common Runtime Contract

The common runtime owns:

- public API;
- current-fiber ownership;
- switch publication state and ordering;
- switch preconditions;
- panic behavior;
- diagnostics;
- validation hooks;
- documentation-visible settings.

The common runtime does not own:

- physical exception frame layout;
- assembly save/restore sequences;
- security-domain register access;
- PSPLIM/MSPLIM register access;
- FPU/MVE lazy-stacking register policy;
- SVC instruction encoding or SVC handler dispatch.

The common API should keep this shape:

```c
FiberContext *fiber_current(void);
void fiber_yield_to(FiberContext *to);
FIBER_NORETURN void fiber_start(FiberContext *ctx);
void fiber_switch(FiberContext *from, FiberContext *to);
```

Preferred user code should call `fiber_start()` and `fiber_yield_to()`.
`fiber_switch(from, to)` remains the advanced/manual API.

Common switch preconditions:

- `fiber_switch()` is a Thread-mode API;
- `from != NULL` for a real switch;
- `to == NULL` is a no-op;
- `to == from` is a no-op;
- real switches require `PRIMASK == 0`;
- real switches require `BASEPRI == 0` on cores that implement BASEPRI;
- when current validation is active, manual `from` must match
  `fiber_current()`.

No-op switches should not trap only because interrupt masks are set. A call that
cannot cause a real PendSV switch may return after a compiler barrier.

`fiber_yield_to()` is the normal public path. New examples should avoid
`fiber_switch(from, to)` unless they are documenting advanced integration.

## Port ABI Contract

Each architecture port should provide a small ABI to the common layer:

```c
extern FiberContext *volatile fiber_internal_port_switch_from_slot;
extern FiberContext *volatile fiber_internal_port_switch_to_slot;
extern FiberContext *volatile fiber_internal_port_current_context;

void fiber_port_init(void);
void fiber_port_set_pendsv_lowest_priority(void);
void fiber_port_pend_switch(void);
FiberContext *fiber_port_load_current_context(void);
void fiber_port_seed_current_context(FiberContext *ctx);
void fiber_port_publish_switch_slots(FiberContext *from, FiberContext *to);
FIBER_NORETURN void fiber_port_start_first(FiberContext *to);
uint32_t *fiber_port_init_stack(FiberContext *ctx,
                                void *stack_begin,
                                void *stack_end,
                                FiberEntry entry,
                                void *arg);
void fiber_pendsv(void);
```

Exact names may change, but ownership should not:

- common code decides whether a switch is allowed;
- common code publishes `fiber_internal_port_switch_from_slot` and
  `fiber_internal_port_switch_to_slot`;
- common code owns the current-context policy;
- common code calls `fiber_port_pend_switch()` only after publication is
  complete;
- port code performs CPU-specific save, restore, and exception return;
- port code may update `fiber_internal_port_current_context` during the real
  restore path, but it must follow the common current-context policy;
- port code must not decide scheduler/runtime semantics;
- port code owns the physical stack frame layout;
- port code owns optional SVC first-start mechanics;
- port code owns feature gates that depend on architecture state.

The port ABI must hide architecture-specific storage from users. Shared PendSV
state such as `from`, `to`, and `current` must live in an internal port-state
module. It may be visible to port sources through an internal header, but it
must not become user-facing API.

Avoid a port-level function shaped like `fiber_port_request_switch(from, to)`
unless it is only a thin mechanical wrapper. Passing `from` and `to` to the port
as a semantic request makes it too easy for the port to start owning runtime
policy. The preferred boundary is: common validates and publishes state, then
the port only pends the architecture-specific switch mechanism.

Port entry points must document whether they are callable from Thread mode,
Handler mode, or both. Undefined call mode is not acceptable for start/switch
primitives.

## Stack Frame Contract

Every port must document and test its initial stack frame.

Required invariants:

- fiber stacks are at least 8-byte aligned at exception return;
- the synthetic frame sets `xPSR.T`;
- the synthetic stacked `PC` stores the entry address with bit 0 clear;
- Thumb state comes from `xPSR.T`, not from stacked `PC` bit 0;
- the initial `LR`/`EXC_RETURN` value is target-aware and configurable;
- stack growth direction is explicit;
- stack limit metadata is either implemented for the port or explicitly unused;
- invalid stack bounds trap before the first switch;
- no user entry runs on MSP unless a port explicitly documents that policy.

The layout used by `fiber_port_init_stack()` is part of the port ABI. Changing it
requires updating the port audit note and compile/runtime validation.

## PendSV Contract

All ports that use PendSV must preserve the FreeRTOS-style invariants:

- save and restore callee-saved core registers required by the ABI;
- preserve `LR` as the active `EXC_RETURN` value when needed;
- run fibers on PSP;
- keep PendSV at the lowest priority unless a port documents a stronger rule;
- update current-fiber ownership exactly once per real switch;
- keep publication of source and target contexts ordered before PendSV can read
  them;
- never allow a real cooperative switch to be silently delayed by interrupt
  masks.

PendSV must not call user code directly. It may only restore the selected
context and return through the architecture-defined exception-return path.

If a port uses SVC and PendSV together, their shared state ownership must be
documented. The first-start SVC path must not create a second current-context
owner beside PendSV/common state.

## Handler Wiring Contract

Vector ownership must be explicit.

Required rules:

- the application must know whether it provides `PendSV_Handler` and
  `SVC_Handler`, or whether the library provides weak/default handlers;
- a build must not silently override an application handler;
- if handler chaining is supported, the chaining rule must be documented;
- vector-table relocation and security-domain vector selection must be explicit
  for ARMv8-M targets;
- an optional validation hook should prove that the expected PendSV/SVC handler
  path is actually reached on hardware.

If another RTOS, bootloader, monitor, or debug framework owns SVC or PendSV,
`fiber` must require explicit integration instead of assuming ownership.

## First-Fiber Start Contract

`main` uses a direct boot trampoline. It is validated on STM32H7/Cortex-M7 and
must remain available for A/B testing.

`v2` may add an optional SVC first-start path:

```c
#define FIBER_START_USE_SVC 1
```

The SVC path should:

- enter the first fiber through exception return;
- centralize first-start CPU flag setup in handler mode;
- make vector wiring validation easier;
- stay optional until it has hardware validation;
- not remove the direct trampoline until both paths have comparable tests.

The SVC path is allowed to be more FreeRTOS-like, but it must stay cooperative.
It must not introduce tick scheduling or priority scheduling by accident.

The SVC path must also define:

- the SVC number or dispatch mechanism;
- whether it requires privileged Thread mode before start;
- how it sets or preserves `CONTROL.SPSEL`, `CONTROL.nPRIV`, and
  `CONTROL.FPCA`;
- how it selects Secure or Non-secure handler state on ARMv8-M;
- how it fails when SVC is already owned by another component.

The direct trampoline and SVC start paths must have separate validation results.
Passing one path does not validate the other.

## FPU and Extended Context Contract

For FPU-capable ports:

- save `s16-s31` only when the active `EXC_RETURN` reports an extended FP frame,
  unless a force-save setting is enabled;
- keep `FIBER_FPU_LAZY = 0` as the portable safety default;
- allow `FIBER_FPU_LAZY = 1` only as an opt-in performance setting after target
  validation;
- clear `CONTROL.FPCA` before starting the first fiber when an FP context exists;
- keep MVE targets explicit, because MVE may need broader extended-context
  handling than classic scalar FP tests reveal.

Each FPU/MVE port must state:

- whether compiler flags use soft, softfp, or hard FP ABI;
- whether the target exposes classic scalar FP, MVE, or both;
- whether `FIBER_HAS_FPU` means only scalar FP or all extended context;
- whether `FIBER_FORCE_SAVE_FPU` is required for the target;
- how FPCCR lazy-stacking bits are configured or intentionally left untouched;
- whether pre-start FP code is part of the validation case.

Do not infer MVE safety from a scalar double-accumulator test alone.

## ARMv8-M Security and PSPLIM Contract

ARMv8-M support must separate three ideas:

1. whether a context layout has a PSPLIM slot;
2. whether the current security domain exposes a PSPLIM register that this code
   may access;
3. whether the target has been validated in Secure, Non-secure, or secure-only
   mode.

Do not enable PSPLIM register access only because the architecture profile name
contains ARMv8-M.

Required gates:

- explicit `FIBER_INITIAL_EXC_RETURN` policy;
- explicit Non-secure EXC_RETURN policy;
- explicit PSPLIM register-access policy;
- explicit vector-domain policy for SVC and PendSV;
- explicit FP access policy for CPACR/NSACR when applicable.

ARMv8-M support claims must name the exact domain:

- Secure-only;
- Secure firmware starting Non-secure fibers;
- Non-secure application only;
- mixed Secure/Non-secure integration.

A port validated in one domain is not automatically validated in another.

## Cortex-M7 r0p1 Errata Policy

FreeRTOS has a Cortex-M7 r0p1 workaround around `BASEPRI` writes in PendSV for
ARM errata 837070.

FreeRTOS routes `GCC_ARM_CM7` to a dedicated `portable/GCC/ARM_CM7/r0p1` port
instead of treating Cortex-M7 as only a generic ARMv7E-M build.

The current `fiber` PendSV path does not write `BASEPRI`; it rejects
`BASEPRI != 0` before requesting a cooperative switch from Thread mode. Because
of that, the workaround is not required by the current implementation.

If any future port writes `BASEPRI` from PendSV, SVC, or a handler-side
scheduler section, the affected Cortex-M7 r0p1 workaround must be implemented
before claiming support for that path.

If that happens, the ARMv7E-M profile must either split into a dedicated
Cortex-M7/r0p1 source path or add an explicit r0p1 policy gate with compile and
hardware validation. A generic ARMv7E-M claim is not enough once PendSV starts
touching `BASEPRI`.

## FreeRTOS Sync Policy

FreeRTOS is used as a reference for CPU-port behavior, not as an API target.

For each port, keep a short audit note with:

- the FreeRTOS Kernel commit or release used for comparison;
- the FreeRTOS port files reviewed;
- the matching behavior copied conceptually;
- intentional differences;
- unsupported FreeRTOS CPU-port features;
- validation status.

If source code or close code structure is copied or adapted from FreeRTOS, keep
the required MIT notice in the relevant file or in `THIRD_PARTY_NOTICES.md`.
Purely independent code that follows the same ARM architectural rules does not
need to pretend it is copied code.

Renaming FreeRTOS identifiers or changing formatting does not make copied code
independent. When in doubt, treat close source-level adaptation as MIT-covered
third-party code and document it.

Do not copy FreeRTOS comments verbatim unless the relevant license notice is
kept. Prefer fresh comments that explain the local `fiber` contract.

## Regression Policy

Before a port refactor can be treated as equivalent to the previous H7 path:

- the compile matrix must pass;
- `git diff --check` must pass;
- source and docs must remain ASCII-only unless a file explicitly opts out;
- the STM32H7 runtime validation checklist must still pass;
- panic codes used by validation must remain documented;
- performance-mode results must not be used to justify changing portable
  defaults.

A file-layout-only split must pass the same validation level as the source path
before support claims are preserved. If the source H7 path was
`fpu-validated` or `performance-validated`, the moved H7 port must repeat that
validation before carrying the same claim.

Behavior-changing commits should be small enough that a failed board validation
can be traced to one decision.

## Validation Levels

Use these support labels consistently:

- `unsupported`: code is not intended to work for this profile;
- `compile-only`: representative compiler flags pass, no hardware claim;
- `smoke-tested`: boots and switches on real hardware with simple integer
  fibers;
- `runtime-validated`: stress test passes on real hardware, including current
  tracking and mask guards;
- `fpu-validated`: runtime validation includes FP save/restore and pre-boot FP
  hygiene;
- `security-validated`: ARMv8-M Secure/Non-secure behavior is validated in the
  claimed domain;
- `performance-validated`: opt-in faster settings are validated on the specific
  target.

A release claim must not use a stronger label than the weakest required test for
that feature profile.

Minimum evidence for stronger labels:

- `compile-only`: compile matrix entry, target flags, and warnings recorded;
- `smoke-tested`: board name, core, clock/config summary, and basic switch proof
  recorded;
- `runtime-validated`: long run counters, current tracking, no-op switch checks,
  PRIMASK/BASEPRI policy checks where applicable;
- `fpu-validated`: all runtime checks plus pre-start FP use and FP accumulator
  integrity;
- `security-validated`: exact Secure/Non-secure ownership and vector-domain
  setup recorded;
- `performance-validated`: exact settings, target, runtime duration or counter
  threshold, and failure state recorded.

## v2 Initial Milestones

1. Create this contract on the `v2` branch.
2. Add deterministic port-selection and feature-normalization headers.
3. Move the current STM32H7/Cortex-M7 implementation into an ARMv7E-M port
   boundary without changing behavior.
4. Add a common `fiber_port.h` boundary.
5. Keep the existing compile matrix green.
6. Add vector wiring validation hooks for PendSV and SVC where possible.
7. Add optional SVC first-start behind `FIBER_START_USE_SVC`.
8. Validate direct start and SVC start separately on STM32H7.
9. Split ARMv6-M baseline support from ARMv7-M/ARMv7E-M mainline support.
10. Add ARMv8-M Baseline/Mainline PSPLIM and security-domain policy.
11. Add ARMv8.1-M/MVE policy before claiming STM32N6-class support.
12. Keep `main` stable until a `v2` path passes the same STM32H7 validation.

## Implementation Strategy

Do not try to close every FreeRTOS parity gap in one step. The safe path is to
port the known-good H7/M7 behavior into the v2 architecture first, then expand
profile by profile.

Priority order:

```text
P0: ARMv7E-M / STM32H7-M7
  Move the current validated H7/M7 logic behind the port ABI.
  Keep behavior equivalent during the move.
  Re-run H7 runtime and FPU validation before claiming parity with v1/main.

P1: ARMv7-M / Cortex-M3
  Add or split a mainline non-FPU path.
  Require compile matrix plus smoke validation on real hardware before
  promoting beyond compile-only.

P2: ARMv6-M / Cortex-M0/M0+
  Isolate the Thumb-1 baseline save/restore path.
  Validate no BASEPRI/FPU assumptions.
  Record MSP rewind and VTOR caveats per target.

P3: ARMv8-M Baseline / Cortex-M23
  Define PSPLIM slot policy and register-access gates.
  Define Secure/Non-secure ownership before claiming FreeRTOS-level behavior.

P4: ARMv8-M Mainline / Cortex-M33
  Split or explicitly gate Secure, Non-secure, NTZ, and TFM behavior.
  Validate EXC_RETURN, vector ownership, PSPLIM, CONTROL, and FP access policy.

P5: ARMv8.1-M / Cortex-M55 / MVE
  Define MVE extended-context policy.
  Define PAC/BTI policy where applicable.
  Validate beyond scalar FP accumulator tests.
```

Each phase should leave the tree in a working state. Mechanical source moves,
new feature policy, and behavior changes should be separate commits whenever
possible.

## Definition of Done

`v2` can claim FreeRTOS-style cooperative STM32 Cortex-M port support only when:

- each claimed core profile has its own documented port behavior;
- representative compile profiles pass;
- claimed hardware profiles have real board validation;
- H7/M7 remains at least as validated as `main`;
- ARMv8-M claims distinguish Secure, Non-secure, and secure-only behavior;
- MVE/PAC/BTI claims are explicit for ARMv8.1-M targets;
- docs, source comments, and compile gates describe the same support level;
- exactly one port is selected for every supported compile target;
- unsupported compile targets fail clearly instead of building a wrong port;
- SVC/PendSV handler ownership is explicit;
- direct-start and SVC-start paths have separate validation records if both are
  enabled;
- any copied or closely adapted FreeRTOS code carries the required MIT notice.
