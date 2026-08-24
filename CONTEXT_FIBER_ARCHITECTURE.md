# Context and Fiber Architecture Contract

## Status

This document freezes the intended post-port-freeze separation between the
processor execution-context engine, the stackful Fiber lifecycle, and the
future C++ kernel. It is a design and migration contract, not a claim that the
separation is implemented in the current tree.

The active v2 five-function public API, eight-function forward port ABI,
reverse ABI v1, selected-port context layouts, strong handlers, and context
cohort guards remain unchanged while the remaining CPU ports and hardware
evidence are completed. This document does not rename a symbol, move a source
file, change a frame, or modify generated SVC/PendSV code.

The later extraction is a versioned architectural change. It must preserve the
validated CPU mechanics first and may remove old mixed `fiber_*` compatibility
names only in a separate, explicit bridge-burning change after the replacement
surface is complete.

## Motivation

The current C runtime deliberately became a small scheduler-neutral CPU
transfer engine. Its public name still combines two different concepts:

```text
execution context
  registers, stack, exception frame, CPU policy and transfer mechanics

fiber
  one stackful logical execution object with execution lifetime; scheduler
  state belongs to the owning Task/Kernel
```

Keeping those concepts in one permanent module would make the future C++
kernel depend on names and ownership rules that belong to the CPU engine. It
would also make a host context backend appear to be an STM32 fiber port, and it
would leave no clean place for lifecycle state shared by cooperative,
preemptive, fixed-priority, round-robin, EDF, and CBS policies.

The target separation follows the useful architectural boundary demonstrated
by Boost.Context and Boost.Fiber, but not their platform mechanics:

- Context owns execution-state transfer;
- Fiber consumes Context and owns stackful lifecycle identity;
- scheduler policy consumes Fiber/Task state and decides what runs;
- the selected Cortex-M Context backend remains exception-driven and retains
  the existing FreeRTOS-derived SVC/PendSV mechanics.

Boost.Context uses direct cooperative transfers in an application ABI. The
Cortex-M Context engine in this project must additionally support protected
handler-side dispatch, asynchronous reschedule requests, MPU, TrustZone, FPU,
MVE, PAC/BTI, PSPLIM, and architecture errata. The separation is adopted; the
Boost assembly model is not.

## Normative Layering

The target dependency direction is:

```text
selected Context port
  CPU frame construction, SVC/PendSV, masks, exceptions, FPU, MPU,
  TrustZone, PSPLIM, MVE, PAC/BTI and errata

portable C Context engine
  dispatcher registration, current-context ownership, one-shot start,
  Thread-mode yield request, future ISR reschedule boundary and panic policy

portable Fiber lifecycle
  stackful execution identity, context containment, execution lifetime and
  adaptation between Fiber selection and Context dispatch

C++ Task and Kernel
  ownership, ready/wait/sleep state transitions, time and scheduler policy

C++ synchronization
  mutex, event, semaphore, channel, timeout and ISR handoff

service adapters
  lwIP sys_arch, drivers, timers and application services
```

Dependencies point only downward. A lower layer must not include, call, or
inspect a higher layer.

## Context Engine Ownership

The Context engine owns all facts required to transfer CPU execution safely:

- the opaque selected execution-context type and its exact cohort identity;
- selected-port stack alignment, frame geometry and initial frame creation;
- the runtime current-context slot and publication ordering;
- one registered dispatcher callback and its user pointer;
- first selection using a null current-context input;
- one-shot startup preparation and first exception return;
- Thread-mode cooperative reschedule requests;
- the future validated ISR reschedule request boundary;
- SVC and PendSV handler ownership;
- scheduler/dispatcher critical envelopes used inside the handlers;
- special-register, vector, priority and exception-environment validation;
- context save/restore validation and terminal panic behavior;
- FPU, MPU, security-domain, PSPLIM, MVE, PAC/BTI and errata mechanics;
- exact generated-code, ABI, archive, vector and hardware proof obligations.

The Context engine does not own:

- Fiber, Task, queue or wait-object state;
- ready, sleep, timeout or blocked lists;
- priorities, deadlines, budgets, fairness or time-slice policy;
- mutexes, semaphores, channels or networking objects;
- knowledge of which Fiber or Task contains a context;
- application service policy.

## Context Consumer Surface

The semantic consumer surface is frozen by operation, not yet by final C
symbol spelling. The implementation slice that activates it must select one
collision-resistant prefix and version the resulting ABI. The required
operations are equivalent to:

```c
typedef struct CpuContext CpuContext;
typedef void (*ContextEntryFn)(void *arg);

typedef CpuContext *(*ContextDispatchFn)(
        CpuContext *current,
        void *user);

void context_init(CpuContext *context,
                  void *stack_begin,
                  void *stack_end,
                  ContextEntryFn entry,
                  void *arg);

void context_set_dispatcher(ContextDispatchFn dispatch, void *user);

CpuContext *context_current(void);

CONTEXT_NORETURN void context_start(void);

void context_yield(void);
```

The future preemptive extension adds one explicit ISR-safe reschedule request.
It is not simulated by allowing ISR callers to invoke the Thread-mode yield
function:

```c
void context_request_reschedule_from_isr(void);
```

The exact ISR signature may later carry a validated wake/reschedule token, but
it must remain CPU-neutral. Active ISR priority validation, mask rules, and the
architecture-specific PendSV request remain selected-port responsibilities.

The Context API contains no Task pointer, priority, deadline, queue, tick,
mutex, first-target argument, `from` argument, or direct `to` argument.

The initial Context contract is static-lifetime and single-core. It has no
destroy/reclaim operation and no cross-core or cross-host-thread context
migration. A later lifetime or SMP contract requires a separately versioned
surface and cannot be inferred from the opaque context type.

## Dispatcher Contract

The dispatcher is the only Context-to-consumer selection boundary.

```text
current == NULL
  first selection during context_start()

current != NULL
  normal selection after the complete outgoing context has been saved

return value
  one non-null initialized and restoreable context from the exact selected
  context cohort
```

The Context engine validates the returned context and publishes it as current
before the selected port restores it. The consumer never writes the current
slot and never publishes a target by direct memory access.

Dispatcher installation is one-shot for a running Context engine. It must be
complete before `context_start()`. A null dispatcher, replacement after first
selection begins, a null result, or an invalid result fails closed.

The initial dispatcher does not receive a CPU or scheduling reason enum. The
owning Task/Kernel applies `yield`, wake, timeout, tick, budget, and ISR state
transitions before requesting Context dispatch. `pick_next()` then observes
completed policy state and selects from it. Adding reason flags is a future
versioned ABI change permitted only by a demonstrated requirement.

First and later dispatch calls run inside the selected port's protected
dispatcher envelope. The callback and its complete call graph obey the
existing sensitive general-registers-only ABI. They must not execute FP, MVE,
or other context-sensitive instructions unless a future versioned Context ABI
explicitly saves that state before invoking the callback.

## No Direct Target-Switch Surface

There is no public or Fiber-facing operation equivalent to:

```c
context_switch(from, to);
context_resume(to);
context_start_with(first);
```

Such operations are useful for a purely cooperative Boost.Context-style
library, but they are not the safe scheduling boundary for this runtime. They
would permit callers to bypass dispatcher policy, current publication,
handler-side validation, MPU/security replacement, and the asynchronous
PendSV path.

Selected-port assembly necessarily restores a concrete target internally.
That operation remains private to the exact Context port and is reachable only
after the protected dispatcher returns a validated context.

## Fiber Ownership

A Fiber is the first consumer of the Context engine. It owns stackful execution
lifetime but no processor details or scheduler queues. Its conceptual state
includes:

```text
Fiber
  one CpuContext
  execution lifetime
  entry completion policy
  mapping used by the owning Task/Kernel
```

The initial execution-lifetime vocabulary is:

```text
EMPTY
INITIALIZED
STARTED
COMPLETED
FAILED
```

The exact state representation belongs to the Fiber implementation and is not
stored in a selected Context port. `READY`, `RUNNING`, `BLOCKED`, and
`SLEEPING` are Task/Kernel scheduling states, not duplicate Fiber states. A
minimal static embedded profile may initially reject entry-function return,
preserving the current panic behavior. A later controlled completion path
requires an explicit versioned lifecycle contract; it must not silently turn
the current task-return panic sink into a mutable scheduler callback.

Ordinary application code and scheduler policies do not inspect `CpuContext`.
The Fiber adapter alone maps a selected Fiber or Task to the contained context
returned through `ContextDispatchFn`.

## C++ Task and Scheduler Ownership

The C++ kernel owns policy-visible state:

```text
Task
  Fiber execution object
  NEW/READY/RUNNING/BLOCKED/SLEEPING/TERMINATED state
  priority or deadline properties
  optional quantum and budget
  wait and timer nodes
```

Scheduler policies operate on Task/Fiber identities, not raw context pointers.
An intended policy concept is equivalent to:

```cpp
struct SchedulerPolicy {
    void on_ready(Task&);
    void on_block(Task&);
    void on_yield(Task&);
    void on_tick(time_point);
    Task* pick_next(Task* current);
};
```

The exact C++ spelling is not frozen by this document. The ownership is frozen:
the policy owns queue ordering, while the Context engine owns CPU transfer.

The planned policy sequence remains:

```text
cooperative FIFO
fixed-priority FIFO
round-robin with per-task quantum
fixed-priority preemption
EDF
EDF with CBS budgets
fair scheduling only when a concrete requirement justifies it
```

Scheduling algorithms may be independently implemented from published
specifications and papers. Linux and RTEMS are behavioral and architectural
references, not source-code donors.

## Required Execution Flows

### First Start

```text
application constructs Fibers/Tasks
  -> Fiber installs its Context dispatcher adapter
  -> Context validates one-shot lifecycle state
  -> selected port prepares and validates CPU startup state
  -> Context invokes dispatch(NULL, user) under the protected envelope
  -> Fiber/Kernel returns the first Fiber's CpuContext
  -> Context validates and publishes it
  -> selected port enters SVC and exception-returns into the first context
```

Application code never passes a first context directly to `context_start()`.

### Cooperative Yield

```text
running Task updates policy-visible state if required
  -> Fiber requests context_yield()
  -> selected port validates Thread-mode/mask state and pends PendSV
  -> PendSV saves current CpuContext
  -> Context invokes the Fiber dispatcher adapter
  -> policy selects a Task
  -> adapter returns its CpuContext
  -> Context validates and publishes it
  -> selected port restores and exception-returns
```

### ISR Wake or Preemption

```text
ISR performs an ISR-safe kernel state transition
  -> kernel requests Context reschedule through the ISR API
  -> selected port validates ISR priority and pends PendSV
  -> PendSV performs the same save/dispatch/publish/restore path
```

SysTick, another ISR, and port assembly never contain scheduler policy.

## Optional Processor Features

Any feature that changes saved execution state remains below the Fiber layer:

- MPU and privilege state;
- SecureContext handles and Secure companion calls;
- TF-M integration required by the selected execution profile;
- PSPLIM and security-bank state;
- FPU and MVE state;
- PAC keys and BTI policy.

The exact Context port owns mandatory safe mechanics. Optional profile
configuration remains a separate selected-profile integration ABI. Fiber and
ordinary Task code remain feature-neutral.

Application operations such as secure storage, cryptography, filesystems, and
networking use application-level service abstractions. They are not Context or
Fiber operations.

## Adding A Processor Or Execution Profile

Adding processor support means implementing one complete Context backend. It
must not add a processor branch to Fiber, Task, SchedulerPolicy,
synchronization, or service-adapter code.

One backend supplies:

```text
selected public opaque context storage type
exact context/profile traits and cohort identity
context initialization and synthetic first frame
one-shot CPU startup preparation
first-context SVC or architecture-equivalent transfer
save/dispatch/publish/restore handler path
Thread-mode yield request
future validated ISR reschedule request
private FPU/MPU/security/errata mechanics required by the profile
panic, barrier and environment validation required by the Context ABI
```

One backend integration supplies:

```text
exact source/build selection
startup/vector ownership
linker placement required by the profile
ABI and cohort expectation object
normal, section-GC and LTO links
generated-code and reference-port comparison
negative configuration and stale-object tests
target hardware validation
```

For a classic privileged CPU profile, no optional feature API is needed. An
MPU, TrustZone, TF-M, MVE, PAC/BTI, or other extended profile supplies its
mandatory safe Context mechanics internally and exposes a separate optional
integration ABI only when the board must customize a safe default.

The acceptance rule is:

```text
new Context backend passes its contract
  -> existing Fiber implementation runs unchanged
  -> existing Task/Kernel implementations run unchanged
  -> existing scheduler policies run unchanged
```

An application written only against the portable Fiber, Task, synchronization,
time, and service-abstraction APIs is source-portable to every accepted Context
backend that provides the capabilities the application requires. This does not
make direct CMSIS, HAL, peripheral-register, linker-script, or board-driver code
portable; those dependencies remain below application services in board and
service-adapter layers.

If adding a processor requires editing scheduler policy, ready/wait state, or
portable Fiber lifecycle, the Context boundary is incomplete or the proposed
operation is not actually a processor concern.

## Host Context Backend

A future host backend may implement the Context consumer surface with
Boost.Context or an independently implemented host context mechanism:

```text
HOST_BOOST_CONTEXT Context backend
  -> portable Fiber lifecycle
  -> C++ Task/Kernel and scheduler policies
```

This backend is valuable for deterministic model tests, scheduler tests,
lifecycle tests, fuzzing, and sanitizers on Windows/Linux. It does not inherit
or claim Cortex-M properties:

- no SVC/PendSV vector proof;
- no interrupt-priority validation;
- no MPU, TrustZone, PSPLIM or M-profile errata proof;
- no claim that host cooperative dispatch proves asynchronous MCU preemption.

Backend capabilities must fail closed. A host backend that cannot provide the
ISR reschedule contract does not export a fake no-op implementation and cannot
be used as evidence for a preemptive target profile.

## Current v2 Mapping

The current source already provides most of the future Context engine:

```text
fiber_port_context_init
  future Context construction

fiber_internal_runtime_current_context_slot
  future Context-owned current slot

fiber_scheduler_set_pick_next
  future Context dispatcher registration used by the Fiber adapter

fiber_start
  future Context one-shot start

fiber_schedule
  future Context Thread-mode yield request

fiber_port_runtime_abi.h
  current Context-to-selected-port substrate

fiber_runtime_port_abi.h
  current selected-port-to-Context substrate
```

The current selected ports therefore become Context backends. Their frame
layouts, private helpers, strong handlers, parity ledgers, exact cohort guards,
and hardware proof requirements remain valid.

The mixed scheduler terminology in the current forward/reverse ABI is migration
debt, not a reason to change assembly. Future Context ABI names must be
CPU-neutral and consumer-neutral, for example `dispatcher` rather than
`scheduler candidate`.

The final physical directory names are not frozen by this document. Moving
`fiber/port` to a Context-owned path is a mechanical cleanup after the callable
boundary exists; it must not be combined with frame, handler, or dispatch
behavior changes.

## Forbidden Dependency Edges

The final architecture rejects all of the following:

```text
Context port -> Fiber lifecycle header
Context port -> C++ Task or SchedulerPolicy
Context engine -> ready/wait/timer queue
Fiber -> concrete ARM_CMxx private header
SchedulerPolicy -> CpuContext fields
application -> current-context slot
application -> direct context restore target
ISR -> Thread-mode context_yield()
host backend -> fake Cortex-M capability claim
```

The selected public Context type may be complete for static storage while
remaining private by contract, matching the current opaque selected-port type
model.

## Proof Separation

### Context Port Proof

- exact FreeRTOS source and generated-assembly parity ledger per Cortex-M
  profile;
- frame construction and save/restore geometry proofs;
- forward/reverse ABI and exact cohort mismatch links;
- strong handler, vector, archive extraction, GC and LTO proofs;
- compiler-attribute and forbidden-runtime-call audits;
- hardware SVC/PendSV, FPU, MPU/security and trap validation per profile.

### Context Common Proof

- incomplete selected context type in common translation units;
- exact dispatcher lifecycle and current-publication ownership;
- null, stale, cross-cohort and invalid-target negative tests;
- no direct target-switch API or port-private include;
- Thread and ISR request surfaces reject the wrong execution environment.

### Fiber Proof

- execution-lifetime transition model tests;
- one context per Fiber and exact context-to-Fiber mapping;
- no selected-port dependency;
- entry return and termination policy tests;
- identical behavior over host and Cortex-M Context backends where both claim
  the required capability.

### Scheduler and Kernel Proof

- deterministic model tests for ready/wait/sleep transitions;
- starvation, fairness, priority inversion and timeout tests appropriate to
  each policy;
- property/model tests for EDF ordering and CBS budget replenishment;
- ISR handoff and preemption tests on hardware;
- service-adapter tests independent of selected Context layout.

Host tests supplement but never replace selected-target assembly and hardware
evidence.

## Normative Port-Freeze And Extraction Order

The following order is mandatory. Port completion and architectural extraction
must not be combined into one behavior-changing step.

1. Complete every architecturally distinct STM32 execution profile required
   from the pinned local FreeRTOS reference. Do not duplicate GCC, IAR, or Arm
   Compiler ports when they implement the same processor-state mechanics. A
   compiler-specific implementation is separate only when its ABI or generated
   context mechanics are materially different.
2. For every selected profile, verify all applicable evidence:
   - initial and saved frame layout plus save/restore register order;
   - first-start SVC and PendSV dispatch;
   - FPU, MPU, TrustZone, PSPLIM, MVE, PAC/BTI, and architecture errata;
   - compile matrix at all required optimization levels and with LTO;
   - generated assembly against the matching pinned FreeRTOS port;
   - ELF, vector, directional ABI, exact-cohort, stale-object, and negative
     link tests;
   - hardware tests when a matching board is available.
3. Record a profile without a matching board only as
   `compile/assembly/ELF validated`. Never infer or publish a
   `hardware validated` claim from compile, disassembly, emulator, host, or ELF
   evidence.
4. Create a stable pre-extraction checkpoint only after all applicable software
   proofs pass and no known software gap remains in any required profile.
5. Only after that checkpoint, mechanically separate the validated runtime:

   ```text
   CPU/Context backend
       -> Fiber lifecycle
       -> C++ Task/Kernel
       -> scheduler policies
   ```

   This step moves ownership and names behind the Context interface. It must not
   redesign frame layout, save/restore order, exception mechanics, feature
   policy, or scheduler semantics at the same time.
6. After extraction, repeat the same generated-assembly, ELF/vector,
   ABI/cohort, negative-link, and available hardware tests against the
   pre-extraction checkpoint. The extracted baseline is accepted only when the
   evidence proves no unintended runtime behavior change.

## Mechanical Migration Sequence

The separation must not be implemented as one behavior-changing rename.

### Slice 0: Documentation Freeze

- add this contract;
- update the architecture index and decision log;
- make no source, ABI, frame, handler or generated-code change.

### Slice 1: Complete Existing Port Freeze

- finish every architecturally distinct STM32 Cortex-M execution profile needed
  from the pinned local FreeRTOS reference under its current v2 name;
- do not duplicate GCC, IAR, or Arm Compiler directories when they implement the
  same processor state contract; record and test a compiler-specific difference
  when it changes generated context mechanics;
- retain per-port FreeRTOS parity and compile/ELF proofs;
- complete outstanding hardware validation where boards exist.

#### Slice 1 Exit Gate

Every selected profile must have a reviewed parity ledger covering:

```text
initial and saved frame layout
save and restore register order
first-start SVC and PendSV dispatch
FPU, MPU, TrustZone, PSPLIM, MVE, PAC/BTI and errata when applicable
compile matrix at the required optimization levels and with LTO
generated assembly comparison against the pinned FreeRTOS reference
ELF, vector, directional ABI and exact-cohort positive and negative proofs
target hardware tests when a matching board is available
```

A profile without matching hardware may be recorded only as
`compile/assembly/ELF validated`; it must not receive a hardware-validation
claim. Slice 2 may begin only after all required profiles pass their applicable
software proofs, every unavailable hardware proof is explicitly recorded, and
the branch has a stable checkpoint with no known software gap in frame,
save/restore, exception, feature-state, ABI/cohort, or generated-code behavior.

### Slice 2: Introduce Internal Context Facade

- add the Context type and consumer declarations behind an internal build
  boundary;
- adapt them to the existing runtime without changing selected-port assembly;
- prove generated SVC/PendSV and frame bytes identical to the preceding
  checkpoint.

### Slice 3: Move Context Ownership

- move dispatcher storage, current publication and one-shot start ownership
  into the Context common module;
- version the new directional ABI and exact cohort anchors;
- retain negative stale-object/archive tests;
- keep the current public Fiber API as a temporary compatibility facade only.

### Slice 4: Add Fiber Lifecycle Consumer

- define Fiber identity and execution lifetime independently of selected ports;
- register one Fiber-to-Context dispatcher adapter;
- keep policy state outside CpuContext;
- prove the same Fiber tests on the host backend and at least one Cortex-M
  backend.

### Slice 5: Add C++ Task and Reference Policies

- add static cooperative FIFO first;
- add portable synchronization semantics before preemption;
- add the validated ISR boundary and fixed-priority preemption;
- add RR, EDF and CBS as independent policy slices.

### Slice 6: Remove Transitional Mixed Names

- remove old compatibility symbols only after all consumers use the separated
  layers;
- perform the removal as an explicit major ABI change;
- reject stale v2 archives through new version/cohort anchors;
- rerun complete compile, ELF, generated-code and hardware evidence.

## Reference Lineage

The architecture uses independent references for different responsibilities:

```text
FreeRTOS portable/
  Cortex-M exception, context frame and architecture mechanics

Boost.Context and Boost.Fiber
  separation of context transfer from fiber management and scheduler policy

RTEMS
  pluggable embedded scheduler interfaces, EDF and CBS behavior

Linux scheduler documentation
  scheduling classes, FIFO/RR semantics, EDF/CBS and policy experimentation

Zephyr and QXK
  cooperative/preemptive coexistence and dual-mode execution semantics
```

Reference URLs:

- https://www.boost.org/library/latest/context/
- https://www.boost.org/doc/libs/latest/libs/fiber/doc/html/fiber/custom.html
- https://docs.rtems.org/docs/main/c-user/scheduling-concepts/index.html
- https://docs.kernel.org/scheduler/sched-deadline.html
- https://docs.kernel.org/scheduler/sched-ext.html
- https://docs.zephyrproject.org/latest/kernel/services/scheduling/index.html

Algorithms and architecture are independently implemented for this project.
Linux scheduler source is not copied into the library.

## Frozen Decision

The current Cortex-M port work is retained. It becomes the backend of a
standardized Context engine rather than being rewritten into direct
Boost.Context-style jumps.

The future Fiber layer consumes only the Context consumer surface. The future
C++ kernel consumes only Fiber/Task lifecycle surfaces. Scheduler policy never
enters selected-port assembly, and processor details never enter scheduler
policy.
