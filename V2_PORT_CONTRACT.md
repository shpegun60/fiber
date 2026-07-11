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
- keep the library much smaller than FreeRTOS by excluding FreeRTOS priority
  scheduler policy, queues, semaphores, timers, event groups, streams, and
  heaps;
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
    fiber_port_boot_record.h
    fiber_port_select.h
    fiber_port_selected.h
    fiber_port_types.h
    fiber_port_state.c
    fiber_port_state.h
    armv6m/
      fiber_port_armv6m.h
      fiber_port_armv6m.c
    armv7m/
      fiber_port_armv7m.h
      fiber_port_armv7m.c
    armv7em/
      fiber_port_armv7em.h
      fiber_port_armv7em.c
    armv8m_baseline/
      fiber_port_armv8m_baseline.h
      fiber_port_armv8m_baseline.c
    armv8m_mainline/
      fiber_port_armv8m_mainline.h
      fiber_port_armv8m_mainline.c
    armv81m_mainline/
      fiber_port_armv81m_mainline.h
      fiber_port_armv81m_mainline.c
```

The current one-file implementation may be split gradually. Behavior should not
change during a pure file-layout split.

## FreeRTOS-Style Port Ownership Model

The target architecture is a FreeRTOS-style port boundary:

- `fiber_core.c` owns public cooperative runtime semantics only;
- `fiber_core.c` must not own CPU exception-handler assembly;
- `fiber_core.c` must not own architecture-specific synthetic frame layout;
- `fiber_core.c` must not contain a fallback PendSV implementation once the
  v2 split is complete;
- `fiber_boot.c` owns portable boot-record construction and validation only;
- first-context CPU startup, SVC startup, direct trampoline startup, CONTROL
  writes, PSP/MSP programming, and exception-return mechanics are port-owned;
- exception setup such as PendSV/SVC priority, vector wiring validation,
  implemented-priority-bit probing, and M7 errata policy is port-owned;
- support helpers such as FPU, PSPLIM, VTOR, BASEPRI, and fault hygiene may be
  shared, but the selected port owns the policy for when and how they are used.

In the final v2 shape each concrete `port/arm*/fiber_port_*.h` exports the
selected port interface. The common runtime includes only
`fiber_port_selected.h` or `fiber_port.h`; it does not include concrete
architecture headers directly and does not branch into architecture-specific
implementation logic.

Temporary transitional fallback code is allowed only while splitting ports. It
must live under an explicitly transitional directory such as
`port/transitional_v8m`, be clearly marked, be compile-covered, and be tracked
as debt. A port cannot be claimed as FreeRTOS-level while it depends on a
transitional PendSV or frame builder.

The `port/common` name is reserved for reusable helper code, not selected-port
fallback behavior.

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
| Cortex-M7 r0p0/r0p1 | ARMv7E-M scheduler-driven PendSV has an explicit `FIBER_CORTEX_M7_R0P1_ERRATA_837070` gate around handler-side `BASEPRI` writes, the compile matrix builds that branch, and runtime startup traps if affected CPUID values run without the gate. Hardware validation is not recorded yet. | Validate on affected Cortex-M7 hardware before claiming parity with the FreeRTOS CM7 r0p1 port. Consider a dedicated CM7/r0p1 source split if the policy grows beyond the current guarded BASEPRI sequence. |
| ARMv8-M Baseline / M23 | Selection and compile-only coverage exist. Runtime is gated by default. The generic baseline path still has no FreeRTOS-style PSPLIM slot. | Implement a PSPLIM slot/security policy or keep M23 runtime excluded. Validate Secure/Non-secure ownership before claiming support. |
| ARMv8-M Mainline / M33 | Selection and compile-only coverage exist. Runtime is gated by default. Simple PSPLIM register access is separate from full FreeRTOS CONTROL/PSPLIM/security context. | Split or explicitly implement Secure, Non-secure, NTZ, and TFM behavior. Validate EXC_RETURN, vector ownership, PSPLIM access, FP access, CONTROL state, and SVC/PendSV domain routing. |
| ARMv8.1-M / M55 / MVE | Selection can detect MVE and route to the ARMv8.1-M profile. Runtime is gated by default. MVE-FP maps to extended FP context; MVE-only and PAC/BTI are not implemented. | Implement MVE-only and PAC/BTI policy where applicable, stack-frame implications, and validation beyond scalar FP stress tests. |
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
- software-frame size, saved-SP modulo, and EXC_RETURN word index;
- assembly save/restore sequences;
- security-domain register access;
- PSPLIM/MSPLIM register access;
- FPU/MVE lazy-stacking register policy;
- SVC instruction encoding or SVC handler dispatch.

The common API should keep this shape:

```c
FiberContext *fiber_current(void);
void fiber_yield(void);
void fiber_sleep_until(uint32_t tick);
void fiber_schedule(void);
FIBER_NORETURN void fiber_start(FiberContext *ctx);
```

Current low-level user code should call `fiber_start()` and `fiber_schedule()`.
The long-term v2 user path should be `fiber_start()`, `fiber_yield()`,
`fiber_sleep_until()`, and wait/wake APIs. Direct target selection from Thread
mode is not part of the core API.

The low-level primitive that enters the scheduler-driven PendSV path should not
own yield/sleep/wait policy. Its working name is `fiber_schedule()`; a name such
as `fiber_jump_scheduler()` is also acceptable if it makes the boundary clearer.
This primitive only requests entry into the scheduler/port path.

Common scheduler-jump preconditions:

- `fiber_schedule()` is a Thread-mode API;
- a runtime-owned current context must already be seeded;
- real scheduler jumps require `PRIMASK == 0`;
- real scheduler jumps require `BASEPRI == 0` on cores that implement BASEPRI;
- real scheduler jumps require `FAULTMASK == 0` on cores that implement
  FAULTMASK;
- the scheduler hook must return a real initialized `FiberContext`.

New examples should prefer `fiber_yield()` and sleep/wait APIs once those are
implemented. Low-level examples may call `fiber_schedule()` directly to show the
core scheduler jump.

User-facing scheduling APIs must update scheduler state before requesting the
core scheduler jump:

```text
fiber_yield()
  mark current task READY
  fiber_schedule()

fiber_sleep_until(tick)
  mark current task SLEEPING
  record wake_tick
  fiber_schedule()

fiber_wait(object, timeout)
  mark current task WAITING
  record wait object and timeout
  fiber_schedule()
```

The core scheduler jump does not know why scheduling was requested. It simply
enters PendSV/SVC so the scheduler hook can choose the next context.

## Scheduler Layering Contract

The scheduler-driven design must keep three layers separate:

```text
port/asm core
  save current CPU context
  enter scheduler critical section
  call the stable scheduler bridge
  restore the returned context

scheduler bridge
  call the configured pick-next hook
  validate the returned FiberContext
  panic on NULL or invalid context
  update runtime-owned current context

user scheduler policy
  own task states
  own ready/sleep/wait lists
  own ticks, deadlines, wait objects, events, and wake rules
  decide which real FiberContext runs next
```

The port/asm core must stay policy-free. It must not know whether scheduling was
requested because of `fiber_yield()`, `fiber_sleep_until()`, a wait timeout, an
event wake, or an ISR-side wake request.

The scheduler bridge is the only boundary between CPU context switching and
application scheduling policy. This keeps the core small and allows the
application to provide a C or C++ scheduler without rewriting architecture
assembly.

## Cooperative Round-Robin Scheduler Contract

The scheduler goal is a deterministic cooperative round-robin core, not a
FreeRTOS priority scheduler.

Required behavior:

- no priority scheduling;
- no preemptive tick switching;
- no tick time slicing;
- no automatic switch only because a periodic tick fired;
- switches occur only at explicit yield, block, wake/reschedule, start, or
  validation-defined points;
- scheduling order is stable task registration/list order;
- `fiber_yield()` means "give the CPU to the next runnable task in list order",
  not "give the CPU to the highest priority task";
- the picker starts after the current task and scans forward through the list;
- tasks that are not runnable are skipped;
- if no user task is runnable, the scheduler must run a documented idle task or
  return to the current task only if that is explicitly safe for the current
  state.

The minimum task states are:

```text
RUNNING
READY
SLEEPING
WAITING
SUSPENDED
```

State rules:

- `RUNNING` is the current task.
- `READY` is eligible for selection.
- `SLEEPING` is skipped until its wake tick has expired or it is explicitly
  woken.
- `WAITING` is skipped until its wait object is signaled or its timeout expires.
- `SUSPENDED` is skipped until an explicit resume/wake policy makes it ready.

Sleep and wake rules:

- `fiber_sleep_until(tick)` marks the current task `SLEEPING`, records
  `wake_tick`, and requests a reschedule.
- `fiber_sleep_for(delta)` is a convenience wrapper around
  `fiber_sleep_until(now + delta)` and must use wrap-safe tick math.
- When the picker reaches a sleeping task, it must compare the current tick with
  `wake_tick` using wrap-safe arithmetic. If the wake time has not arrived, the
  task stays sleeping and is skipped.
- If the wake time has arrived, the task becomes `READY` and may be selected in
  its normal list position.
- `fiber_wake(task)` may make a sleeping or waiting task `READY` before its
  timeout expires. Explicit wake wins over the recorded sleep timeout.
- Waking an already `READY` or `RUNNING` task must be harmless and documented as
  a no-op or diagnostic event.

Wait rules:

- A waiting task records the wait object and optional timeout.
- A signaled wait object makes matching waiting tasks `READY` according to the
  documented wake policy.
- If a waiting task also has a timeout, timeout expiry makes it `READY` with a
  timeout result.
- The scheduler must not select a task whose wait condition is still false and
  whose timeout has not expired.

Tick rules:

- The tick source is an input to the scheduler, not a preemption mechanism by
  itself.
- A tick update may move expired sleeping/waiting tasks to `READY`.
- A tick ISR may request PendSV if it makes a task ready, but it must not create
  preemptive time slicing by accident.
- The tick counter width and wrap behavior must be documented before timeouts
  are exposed as stable API.

This scheduler still uses the same port discipline as FreeRTOS: the scheduler
owns task state and ready/sleep/wait lists, while the port owns CPU context
save/restore. If the final design calls scheduler selection from PendSV or SVC,
that handler-side scheduler section must use the port's interrupt-priority
critical-section policy, including the Cortex-M7 r0p1 `BASEPRI` workaround when
that path writes `BASEPRI`.

Yield policy, time-based sleep, wait objects, timeout expiry, and wake decisions
belong to the scheduler layer. The port must not inspect ticks, sleep deadlines,
wait objects, task states, or event state. The port only saves the current
context, enters the scheduler critical section, asks the scheduler bridge for the
next `FiberContext`, validates that result, and restores it.

## Custom Scheduler Hook Contract

`fiber` should allow the scheduling policy to be supplied by the application.
This keeps the library focused on context switching while allowing a C or C++
application to implement its own ready/sleep/wait model.

The public shape should be similar to:

```c
typedef FiberContext *(*FiberSchedulerPickNextFn)(FiberContext *current,
                                                  void *user);

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                   void *user);
```

The exact names may change, but the boundary should not:

- architecture assembly saves the current CPU context;
- architecture assembly calls one stable C bridge, not an arbitrary user
  function pointer directly;
- the C bridge calls the configured scheduler hook;
- the hook returns the `FiberContext` to restore next;
- architecture assembly restores only the returned context.

In the scheduler-driven path, `from/to` publication slots are not part of the
PendSV ABI. The port does not receive a preselected target from Thread mode.
PendSV/SVC derives the source from the runtime-owned current context, saves it,
calls the scheduler bridge, and restores the returned context.

The normal scheduler-driven port state should be reduced to:

```c
FiberContext *volatile current_context;
FiberSchedulerPickNextFn pick_next;
void *pick_next_user;
```

Optional request/debug flags may be added, but the normal path must have one
source of truth for the next context: the scheduler hook result.

The expected scheduler-driven PendSV flow is:

```text
panic if Thread mode is not already using PSP
current = current_context
panic if live PSP cannot hold the source software frame
save current context
enter port scheduler critical section
next = fiber_internal_scheduler_pick_next_from_pendsv(current)
panic if next == NULL
panic if next is not a valid restore target
current_context = next
exit port scheduler critical section
restore next context
```

`fiber_port_state.h` should remain as the narrow internal scheduler/port
runtime-state header. Its normal scheduler-driven contents are the current
context, the stable scheduler bridge declaration, the pick-next function
pointer, and the user context pointer. Do not reintroduce `from/to` slots as a
competing switch mechanism.

The internal bridge should have a narrow shape, for example:

```c
FiberContext *fiber_internal_scheduler_pick_next_from_pendsv(FiberContext *current);
```

The bridge owns validation around the user hook:

- the hook must be configured before the scheduler starts;
- changing the hook while fibers are running is forbidden unless a future API
  defines a sealed, synchronized replacement protocol;
- hook installation must be rejected after the runtime-owned current context has
  been seeded;
- the default hook pointer is `NULL`;
- explicitly installing a `NULL` hook is invalid;
- a scheduler-driven PendSV/SVC path must panic if no hook is configured;
- the hook must return a non-NULL context for every real scheduler-driven
  switch;
- a `NULL` returned context must always panic;
- idle must be represented by a real initialized `FiberContext`, selected by
  the scheduler hook like any other runnable context;
- the returned context must be initialized, sealed, and eligible for restore;
- the bridge must validate the returned context before architecture assembly
  restores it: non-NULL `sp`, boot seal, stack bounds, saved-frame alignment
  (`sp % 8 == 4` for the current 36-byte software frame), software-frame
  plus hardware exception-frame headroom, EXC_RETURN signature and Thread/PSP
  bits, and any port-specific extended-frame headroom such as `s16-s31` plus
  the hardware FP extension frame;
- before saving a source context, PendSV must prove from the active
  `EXC_RETURN` value that the interrupted Thread context used PSP. If this is
  false, the handler must panic instead of saving an unrelated pre-start or
  foreign MSP stack state;
- before writing the source software frame, PendSV must prove that the live PSP
  is inside the current context bounds and has enough headroom for the core
  software frame plus any port-specific high-FP frame. If this is false, the
  handler must panic before modifying memory below `stack_base`;
- returning the current context is allowed only when the scheduler contract says
  staying on the current task is safe.

If the hook is called from PendSV or SVC, it is a Handler-mode scheduler hook,
not a normal application callback. The port must call it only inside a
port-defined scheduler critical section.

Critical-section requirements:

- on cores that implement `BASEPRI`, protect the scheduler bridge/hook with a
  `BASEPRI` threshold suitable for scheduler-aware ISRs;
- validate that the configured scheduler `BASEPRI` uses only hardware-implemented
  NVIC priority bits and still masks at least one implemented priority level;
- validate `AIRCR.PRIGROUP` so the scheduler `BASEPRI` policy is not undermined
  by an unexpected subpriority split, following the FreeRTOS Cortex-M port rule;
- do not save `BASEPRI` as part of `FiberContext`;
- restore the previous `BASEPRI` value after the scheduler bridge returns;
  no-return panic paths may stop before restore because execution does not
  continue;
- on Cortex-M7 r0p1, any handler-side `BASEPRI` write must use the documented
  errata 837070 workaround before that path can be considered supported;
- on cores without `BASEPRI`, protect the handler-side scheduler bridge with a
  saved `PRIMASK` critical section, matching the FreeRTOS Cortex-M0 discipline;
- ISR-side wake/tick APIs for no-BASEPRI ports still need an explicit API-level
  policy before they are exposed;
- ISRs above the configured scheduler priority threshold must not call
  scheduler-aware fiber APIs directly.

Hook restrictions:

- bounded execution time;
- no blocking;
- no `fiber_yield()`, `fiber_sleep_*()`, or wait API calls from inside the hook;
- no `malloc()`/`free()` or heap-dependent C++ allocation;
- no locks that can wait for another fiber;
- no `HAL_Delay()` or polling loops without a fixed short bound;
- no user callbacks;
- no throwing C++ exceptions across the C ABI boundary;
- no floating-point use unless the port explicitly documents and validates that
  Handler-mode FP use is safe for that profile;
- no direct edits to port-owned switch slots or CPU context frames.

The application may implement the scheduler in C++ by storing a pointer to a C++
object in the `user` argument and using an `extern "C"` or static thunk:

```c
static FiberContext *pick_next_thunk(FiberContext *current, void *user)
{
    return ((MyScheduler *)user)->pick_next(current);
}
```

The hook API must remain C-callable so that assembly and C ports do not depend
on C++ ABI details.

## Port ABI Contract

Each architecture port should provide a small ABI to the common layer:

```c
enum {
    FIBER_PORT_SOFTWARE_FRAME_WORDS = ...,
    FIBER_PORT_SOFTWARE_FRAME_BYTES = ...,
    FIBER_PORT_EXC_RETURN_WORD_INDEX = ...
};

extern FiberContext *volatile fiber_internal_port_current_context;
extern FiberSchedulerPickNextFn volatile fiber_internal_port_scheduler_pick_next;
extern void *volatile fiber_internal_port_scheduler_user;

void fiber_port_init(void);
void fiber_port_exception_setup(void);
void fiber_port_platform_bootstrap(void);
uintptr_t fiber_port_prepare_msp_for_start(const FiberBoot *boot);
void fiber_port_pend_switch(void);
FiberContext *fiber_port_load_current_context(void);
void fiber_port_seed_current_context(FiberContext *ctx);
void fiber_port_set_scheduler_pick_next(FiberSchedulerPickNextFn pick_next,
                                        void *user);
FiberContext *fiber_internal_scheduler_pick_next_from_pendsv(FiberContext *current);
FIBER_NORETURN void fiber_port_start_first_context(uintptr_t msp_top);
void fiber_port_init_context_frame(FiberContext *ctx);
void fiber_pendsv(void);
void fiber_svc(void);
```

Exact names may change, but ownership should not:

- `fiber_port_types.h` owns the shared type ABI: `entry_t`, `FiberBoot`,
  `FiberContext`, and the scheduler hook function type. It does not include
  `fiber_boot.h` or `fiber_core.h`, so ports can inspect offsets without
  depending on public runtime API headers;
- `fiber_port_boot_record.h` owns the `FiberBoot` integrity constants and hash
  helper used by both boot construction and port-side restore validation;
- scheduled restore validation uses a fast sealed-record check by default and
  must not recompute the full boot-record hash on every switch unless
  `FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=1` is explicitly selected;
- `fiber_port_select.h` owns strict compile-time profile selection only;
- `fiber_port_selected.h` includes the selected `arm*/fiber_port_*.h`
  interface and is the common-runtime entry point for port-owned frame
  constants and low-level handler declarations;
- each concrete `arm*/fiber_port_*.h` must declare its port interface and frame
  traits without including `fiber_boot.h` or `fiber_core.h`;
- common code decides whether a switch is allowed;
- common code seeds the current context and scheduler hook before a
  scheduler-driven switch can run;
- common code owns the current-context policy;
- common code calls `fiber_port_pend_switch()` only after the scheduler-visible
  request state is coherent;
- port code performs CPU-specific save, restore, and exception return;
- port code may update `fiber_internal_port_current_context` during the real
  restore path, but it must follow the common current-context policy;
- port code must not decide scheduler/runtime semantics;
- port code owns the physical stack frame layout;
- port code owns SVC first-start mechanics where that port implements them;
- port code owns direct trampoline first-start mechanics where that port keeps a
  non-SVC startup fallback;
- port code owns Thread/Handler mode preconditions that depend on CONTROL,
  IPSR, PSP, MSP, PRIMASK, BASEPRI, or FAULTMASK;
- port code owns PendSV/SVC priority programming and vector routing validation;
- port code owns BASEPRI/PRIMASK critical-section assembly used inside PendSV;
- port code owns Cortex-M7 r0p0/r0p1 errata policy when BASEPRI writes exist in
  the handler path;
- port code owns feature gates that depend on architecture state.

Common code may provide small helpers for hashing, range checks, alignment,
diagnostics, and user-facing API validation. Those helpers must not hide a CPU
context layout decision.

`FiberContext.sp` follows the FreeRTOS `pxTopOfStack` invariant: it points to
the last saved software frame for a context that is not currently running. While
a fiber is running, the live stack pointer is CPU PSP. A port must update
`ctx->sp` when saving that context as the source of a switch, and must not move
the target `ctx->sp` forward after restore.

The port ABI must hide architecture-specific storage from users.
Scheduler-driven state such as current context, pick-next hook, and hook user
data must live in an internal port-state module. It may be visible to port
sources through an internal header, but it must not become user-facing API.

Avoid a port-level function shaped like `fiber_port_request_switch(from, to)`.
Passing `from` and `to` to the port makes it too easy for the port to start
owning runtime policy. The required boundary is: common code requests a
scheduler jump, then the port enters the architecture-specific scheduler switch
path and restores only the context returned by the scheduler bridge.

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

The layout used by `fiber_port_init_context_frame()` is part of the port ABI.
Changing it requires updating the port audit note and compile/runtime
validation.

Common validation may use selected-port traits to prove stack bounds, saved-SP
alignment, and `EXC_RETURN` sanity. It must not hard-code a universal software
frame size such as 36 bytes. ARMv6-M and ARMv7E-M currently both use a 9-word
software frame, but ARMv8-M security, PSPLIM, MVE, PAC, or BTI support may need
different context slots. New ports must publish their own trait header before a
runtime support claim is made.

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
- prove that the interrupted Thread context used PSP from the active
  `LR`/`EXC_RETURN` bit 2 before saving the source context. Handler-mode reads
  of `CONTROL.SPSEL` are not a sufficient proof for SVC-started fibers.

PendSV must not call arbitrary user code directly. A scheduler-driven path may
call the configured pick-next hook only through the stable scheduler bridge and
only inside the port-defined scheduler critical section. After a context is
selected and validated, PendSV restores only that context and returns through
the architecture-defined exception-return path.

If a port uses SVC and PendSV together, their shared state ownership must be
documented. The first-start SVC path must not create a second current-context
owner beside PendSV/common state.

## Handler Wiring Contract

Vector ownership must be explicit.

Required rules:

- the application must know whether it provides `PendSV_Handler` and
  `SVC_Handler`, or whether the library provides weak/default handlers;
- a build must not silently override an application handler;
- a wrapper for a naked PendSV or SVC body must preserve LR/EXC_RETURN; a
  normal C wrapper that emits `bl fiber_pendsv` or `bl fiber_svc` is invalid
  because it overwrites LR with a function return address;
- direct vectoring to the naked handler body or a naked branch wrapper is the
  preferred wiring model;
- if handler chaining is supported, the chaining rule must be documented;
- vector-table relocation and security-domain vector selection must be explicit
  for ARMv8-M targets;
- validation should prove that the expected PendSV/SVC handler path is actually
  reached on hardware. Vector-table checks prove the first handler symbol, while
  SVC-start ports should also validate the SVC dispatch value in the handler.

If another RTOS, bootloader, monitor, or debug framework owns SVC or PendSV,
`fiber` must require explicit integration instead of assuming ownership.

## First-Fiber Start Contract

`main` used a direct boot trampoline as the validated STM32H7/Cortex-M7
first-start path. `v2` keeps the direct trampoline as a fallback/A-B path, but
ARMv7E-M now defaults to an SVC first-start path:

```c
#define FIBER_START_USE_SVC 1
```

The current ARMv7E-M SVC path:

- enters the first fiber through exception return;
- centralizes first-start CPU flag setup before and inside the handler path;
- requires privileged Thread/MSP state before issuing SVC;
- optionally rewinds MSP through the sealed boot plan and verifies MSP
  read-back;
- clears any pending PendSV while interrupts are still masked before issuing
  SVC;
- requires SVCall to run at highest priority when SVC first-start is enabled;
- uses `svc #FIBER_SVC_START_NUMBER` as the dispatch key;
- rejects SVC entry from PSP;
- validates the SVC immediate before restoring the first context;
- validates the seeded current `FiberContext` before PSP is restored;
- clears BASEPRI in the SVC handler before the first context is restored;
- sets PSP before exception return; Thread PSP selection comes from the
  `EXC_RETURN` value, not from writing `CONTROL.SPSEL` in Handler mode;
- clears and verifies `CONTROL.FPCA` when the target has an FP context and
  `FIBER_BOOT_CLEAR_FPCA` is enabled;
- panics if the SVC instruction returns to the start helper.

This is deliberately more paranoid than the minimum FreeRTOS first-task start.
It is still cooperative: it does not introduce tick scheduling or priority
scheduling by accident.

The SVC path must keep defining:

- the SVC number or dispatch mechanism;
- whether it requires privileged Thread mode before start;
- how it selects Thread PSP by `EXC_RETURN`, and how it sets or preserves
  `CONTROL.nPRIV` and `CONTROL.FPCA`;
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
- whether `FIBER_HAS_EXTENDED_FP_CONTEXT` is enabled for the target;
- whether `FIBER_FORCE_SAVE_FPU` is required for the target;
- how FPCCR lazy-stacking bits are configured or intentionally left untouched;
- whether pre-start FP code is part of the validation case.

Current v2 policy:

- `FIBER_HAS_EXTENDED_FP_CONTEXT` follows scalar FP support.
- MVE-FP is treated as an extended FP/MVE context candidate, but runtime use is
  gated until hardware validation.
- MVE without scalar FP is rejected by runtime policy validation because the
  current assembly does not implement a separate MVE-only save path.

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

Current v2 policy:

- `FIBER_USE_PSPLIM_REGISTER` is the actual PSPLIM access gate.
- ARMv8-M Baseline/Mainline, ARMv8.1-M, TrustZone/Non-secure bank targeting,
  MVE, and PAC/BTI runtime use is blocked by default unless the matching
  `FIBER_ALLOW_UNVALIDATED_*` opt-in is set for bring-up.
- The opt-in only allows experiments; it does not add the FreeRTOS-style
  CONTROL/PSPLIM/secure-context/PAC-key context slots.

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

The ARMv7E-M scheduler-driven PendSV path writes `BASEPRI` around the scheduler
bridge. The write is guarded by `FIBER_CORTEX_M7_R0P1_ERRATA_837070`; when that
gate is enabled, the port emits the FreeRTOS-style `cpsid i` / `msr BASEPRI` /
`cpsie i` workaround around the raise operation.

This gate is compile-covered by the matrix for Cortex-M7 and Cortex-M7F. Runtime
startup also checks CPUID and traps on affected Cortex-M7 r0p0/r0p1 cores when
the gate is not enabled. This is still not a hardware validation claim.
Affected Cortex-M7 r0p0/r0p1 hardware must pass runtime scheduler-switch
validation before parity with the FreeRTOS CM7/r0p1 port can be claimed.

If this policy grows beyond a guarded `BASEPRI` sequence, ARMv7E-M should split
into a dedicated Cortex-M7/r0p1 source path rather than hiding too much behavior
behind generic ARMv7E-M conditionals.

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

Changing the `FiberContext.sp` save/restore invariant is a behavior-changing
commit, even when the new invariant is more FreeRTOS-like. Such a change must
repeat the relevant board runtime validation before inheriting an earlier
runtime-validated support label.

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
- `security-compile-only`: ARMv8-M/ARMv8.1-M `FIBER_RUN_NONSECURE=1` and
  Secure-to-Non-secure bank aliases compile with the selected toolchain, without
  claiming runtime security-domain behavior;
- `smoke-tested`: board name, core, clock/config summary, and basic switch proof
  recorded;
- `runtime-validated`: long run counters, current tracking, scheduler hook
  result validation, and PRIMASK/BASEPRI policy checks where applicable;
- `fpu-validated`: all runtime checks plus pre-start FP use and FP accumulator
  integrity;
- `security-validated`: exact Secure/Non-secure ownership and vector-domain
  setup recorded;
- `performance-validated`: exact settings, target, runtime duration or counter
  threshold, and failure state recorded.

## v2 Initial Milestones

1. Create this contract on the `v2` branch.
2. Add deterministic port-selection and feature-normalization headers.
3. Add a common `fiber_port.h` boundary and internal port state.
4. Add an ARMv7E-M port file shell with no behavior change.
5. Move the current STM32H7/Cortex-M7 implementation into the ARMv7E-M port
   boundary without changing behavior.
6. Keep the existing compile matrix green.
7. Add vector wiring validation hooks for PendSV and SVC where possible. Done
   for active vector-table routing. ARMv7E-M SVC-start dispatch also validates
   the SVC immediate in the handler.
8. Add optional SVC first-start behind `FIBER_START_USE_SVC`. Done for
   ARMv7E-M as the default selected start path; other ports still use the
   direct fallback unless they implement their own SVC path.
9. Validate direct start and SVC start separately on STM32H7.
10. Split ARMv6-M and ARMv7-M support from the transitional fallback path.
    Done for Cortex-M0/M0+ and Cortex-M3 compile-only source layouts. Remaining
    transitional fallback code lives under `port/transitional_v8m`, not
    `fiber_core.c`. ARMv8-M Baseline remains a separate runtime-gated
    portability task.
11. Add conservative ARMv8-M/ARMv8.1-M feature policy gates. Done for compile
    selection, PSPLIM register access, MVE, TrustZone opt-in, and PAC/BTI
    rejection.
12. Add full ARMv8-M Baseline/Mainline PSPLIM and security-domain context
    layout before claiming runtime support.
13. Add full ARMv8.1-M/MVE/PAC/BTI context policy before claiming STM32N6-class
    support.
14. Keep `main` stable until a `v2` path passes the same STM32H7 validation.

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
  Keep the software frame in FreeRTOS CM0 non-MPU order:
  [LR][r4][r5][r6][r7][r8][r9][r10][r11].
  Publish the saved stack pointer only after the complete software frame is
  stored.
  Validate no BASEPRI/FPU assumptions.
  Record MSP rewind and VTOR caveats per target.

P3: ARMv8-M Baseline / Cortex-M23
  PSPLIM register-access gate exists.
  Define PSPLIM context slot policy.
  Define Secure/Non-secure ownership before claiming FreeRTOS-level behavior.

P4: ARMv8-M Mainline / Cortex-M33
  Runtime policy gates exist.
  Split or implement Secure, Non-secure, NTZ, and TFM behavior.
  Validate EXC_RETURN, vector ownership, PSPLIM, CONTROL, and FP access policy.

P5: ARMv8.1-M / Cortex-M55 / MVE
  Runtime policy gates exist.
  Define MVE-only save/restore if needed.
  Define PAC/BTI context save/restore where applicable.
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
