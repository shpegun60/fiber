# V2 FreeRTOS Port Reference Policy

## Decision

FreeRTOS `portable/` code is the CPU-port reference for `fiber` v2, not the
default compiled backend.

The selected v2 direction is:

```text
_reference/FreeRTOS-Kernel/portable:
  reference implementation for Cortex-M CPU mechanics

fiber/port:
  fiber-owned cooperative runtime port implementation
```

This keeps the library small and explicit while still using FreeRTOS as the
baseline for proven Cortex-M context-switch behavior.

## Why FreeRTOS Portable Is Not a Drop-In Backend

FreeRTOS Cortex-M port sources are not standalone context-switch libraries.
They are part of the FreeRTOS kernel ABI.

Typical FreeRTOS port code expects:

```text
pxCurrentTCB
vTaskSwitchContext()
StackType_t
TaskFunction_t
FreeRTOSConfig.h
configASSERT()
configMAX_SYSCALL_INTERRUPT_PRIORITY
TCB layout where the first field is the saved top-of-stack pointer
FreeRTOS critical nesting and FromISR rules
optional SysTick/tick integration
```

For example, a FreeRTOS SVC first-start path reads `pxCurrentTCB`, treats the
first field of the current TCB as the task top-of-stack, restores the software
frame, programs PSP, and returns from the exception.

The FreeRTOS PendSV path saves PSP into the first field of the current TCB,
calls `vTaskSwitchContext()`, then reloads `pxCurrentTCB` and restores the next
task context.

That is a stable and proven design inside FreeRTOS, but it is not the same
runtime contract as `fiber`.

The `fiber` v2 runtime contract is:

```text
fiber_start()
  scheduler hook selects first FiberContext with current == NULL

fiber_schedule()
  pends the selected-port scheduler exception path

PendSV
  saves current FiberContext
  calls the fiber scheduler bridge
  validates the returned FiberContext
  restores the returned context
```

There is no FreeRTOS task API, no priority scheduler, no RTOS tick, no queues,
no semaphores, no timers, and no FreeRTOS TCB ownership.

## Considered Options

### Option A: Compile FreeRTOS Portable As Backend

This is technically possible, but it requires a compatibility layer that makes
`fiber` look enough like the FreeRTOS kernel for the port code to link and run.

Such a layer would need files and symbols like:

```text
fiber/port/freertos_compat/
  FreeRTOSConfig.h
  FreeRTOS.h
  task.h
  fiber_freertos_tcb.h
  fiber_freertos_scheduler_adapter.c

pxCurrentTCB
vTaskSwitchContext()
configASSERT()
StackType_t
BaseType_t
TaskFunction_t
TCB-compatible first-field saved stack pointer
tick and critical-section stubs if unused
```

A minimal compatibility TCB would look like:

```c
typedef struct FiberFreeRTOSTcb {
    StackType_t *pxTopOfStack;  /* must be first */
    FiberContext *fiber;
} FiberFreeRTOSTcb;

extern FiberFreeRTOSTcb * volatile pxCurrentTCB;
```

Then the adapter would update `pxCurrentTCB` from the fiber scheduler:

```c
void vTaskSwitchContext(void)
{
    pxCurrentTCB = fiber_scheduler_pick_next_compat(pxCurrentTCB);
}
```

This gives direct access to the tested FreeRTOS assembly skeleton, but the cost
is high:

- the library becomes a partial FreeRTOS kernel ABI emulator;
- the public architecture boundary becomes harder to explain;
- unused FreeRTOS concepts such as tick, critical nesting, and FromISR rules can
  leak into the design;
- `xPortStartScheduler()` pulls in more than first-task start, including
  priority checks, tick setup, VFP/lazy-FP setup, and static internal helpers;
- the direct start-first-task path may require patching or copying static
  FreeRTOS internals anyway.

Decision: do not use this option as the normal v2 architecture.

If this option is ever explored, it must live under an explicitly named
experimental directory such as `fiber/port/freertos_compat/`, must not replace
the native `fiber/port/*` implementation, and must carry the required FreeRTOS
MIT license notices for any copied or derived code.

### Option B: Reimplement Fiber Ports Against FreeRTOS CPU Contracts

This is the selected path.

The intent is to build native `fiber` ports in the same engineering style as
FreeRTOS ports:

```text
one selected CPU profile
explicit port-owned macros
explicit port-owned helper functions
small architecture-specific assembly blocks
clear config gates
clear unsupported-feature failures
per-port validation evidence
```

The implementation must be adapted to the `fiber` scheduler contract, not to the
FreeRTOS task scheduler contract. The selected port provides the CPU engine; the
user-owned scheduler decides which `FiberContext` runs next.

Use FreeRTOS as a reference for:

```text
initial synthetic exception frame layout
SVC first-start mechanics
PendSV save/restore order
PSP ownership
EXC_RETURN handling
BASEPRI scheduler critical-section discipline
implemented priority-bit validation
Cortex-M7 r0p0/r0p1 errata policy
v8-M PSPLIM/security-domain context policy
MVE/PAC/BTI port split decisions
```

But implement those concepts in the native `fiber` runtime contract:

```text
fiber_port_init_context_frame()
fiber_port_start_first_context()
fiber_svc()
fiber_pendsv()
fiber_internal_scheduler_pick_next_from_pendsv()
fiber_internal_validate_restore_context()
selected-port traits
```

Benefits:

- `fiber` keeps a clean cooperative API;
- the user-owned scheduler remains explicit;
- there is no `pxCurrentTCB` compatibility layer;
- the selected port can add stronger validation than FreeRTOS where useful;
- FreeRTOS parity can be checked per port without importing FreeRTOS scheduler
  policy.

Cost:

- every selected port must maintain a documented parity map against the relevant
  FreeRTOS reference files;
- copied or closely adapted substantial code still requires MIT notices;
- runtime support claims require hardware validation, not only compile coverage.

## FreeRTOS Port Audit Workflow

Every native `fiber` port must be developed from a FreeRTOS reference audit, not
from memory.

For each FreeRTOS reference port, inspect:

```text
port.c
portasm.c or equivalent assembly source
portasm.h
portmacro.h
portmacrocommon.h
secure/non_secure companion files when present
README or port notes when present
```

The audit must inventory every relevant CPU-port symbol:

```text
macros
inline helpers
public port functions
static port functions
exception handlers
assembly labels
global variables used by the port ABI
configuration macros consumed by the port
errata gates
priority and vector constants
FPU/MVE/PSPLIM/security/PAC/BTI policy gates
```

No relevant FreeRTOS CPU-port macro, function, label, or policy gate may vanish
silently. Each item must have exactly one decision:

```text
adopt:
  same role in fiber, implemented with native fiber names and contracts

adapt:
  same CPU purpose, changed to fit FiberContext and user scheduler hook

replace:
  FreeRTOS mechanism is replaced by a stronger or clearer fiber mechanism

exclude:
  not needed because it belongs to FreeRTOS scheduler, tick, task API,
  queues, semaphores, heap, MPU task management, or FromISR API surface

defer:
  needed for future parity, but not implemented in this checkpoint; must have
  a tracked TODO and must not be claimed as runtime-supported
```

An item may be excluded only with a reason. "Not copied" is not a reason.

The port audit must preserve the CPU behavior that matters even when symbol
names differ. For example, a FreeRTOS macro does not need to keep its FreeRTOS
name in `fiber`, but its role must be represented by a selected-port trait,
`port/common` helper, selected-port private macro, or an explicit exclusion.

Examples of FreeRTOS mechanisms that must be audited per relevant port:

```text
initial EXC_RETURN value
task/fiber return address
synthetic hardware exception frame fields
software frame register order
SVC immediate and first-start path
PendSV priority and pended-bit handling
PendSV save/restore order
BASEPRI or PRIMASK scheduler critical section
implemented NVIC priority bits
AIRCR.PRIGROUP validation
FPU enable and lazy/eager FP policy
high FP register save/restore
CONTROL.FPCA handling
PSPLIM register access and saved-context slot policy
TrustZone secure/non-secure state selection
MVE/PAC/BTI context policy
Cortex-M7 r0p0/r0p1 errata workarounds
SysTick/tick integration, usually excluded for fiber core
FreeRTOS task-list scheduling hooks, excluded and replaced by scheduler hook
```

## FreeRTOS-Style Source Layout Policy

The `fiber` port tree should follow the same organizational style as FreeRTOS
ports, but with native `fiber` names and the cooperative scheduler contract.

FreeRTOS port selection is mostly a build/include contract:

```text
FreeRTOS.h
  includes portable.h

portable.h
  includes portmacro.h from the selected port include path

FreeRTOS CMake or the user project
  selects exactly one portable source set with FREERTOS_PORT or equivalent
  for example port.c plus optional portasm.c

portmacro.h
  defines port-owned types, macros, and extern declarations
  may include portmacrocommon.h for shared ARMv8-M logic

port.c / portasm.c
  implement the selected CPU port functions and exception handlers
```

There is no runtime port registry. The "engine" is the selected `portmacro.h`
header plus exactly one selected port source group in the build.

The v2 `fiber` equivalent has two stages:

```text
development/convenience stage:
  fiber_port_select.h can auto-detect or use FIBER_PORT_PROFILE
  fiber_port_selected.h includes the selected role headers
  compile matrix checks all supported selector modes

FreeRTOS-like production stage:
  build defines FIBER_PORT_BUILD_SELECTED=1
  build defines exactly one FIBER_PORT_ARMV*=1
  build includes exactly one selected port source group
  fiber_port_select.h validates only during migration
```

The long-term target is that selected `fiber_portmacro.h` headers provide the
CPU interface directly, the build selects one source group, and
`fiber_port_select.h` can be removed from the production path without changing
the core runtime API.

FreeRTOS layout patterns observed in the local reference tree:

```text
GCC/ARM_CM3:
  portmacro.h
  port.c

GCC/ARM_CM4F:
  portmacro.h
  port.c

GCC/ARM_CM7/r0p1:
  portmacro.h
  port.c

GCC/ARM_CM0:
  portmacro.h
  portasm.h
  portasm.c
  port.c
  mpu_wrappers_v2_asm.c

GCC/ARM_CM23_NTZ/non_secure:
  portmacrocommon.h
  portmacro.h
  portasm.h
  portasm.c
  port.c
  mpu_wrappers_v2_asm.c

GCC/ARM_CM33/non_secure, ARM_CM55/non_secure, ARM_CM85/non_secure:
  portmacrocommon.h
  portmacro.h
  portasm.h
  portasm.c
  port.c
  mpu_wrappers_v2_asm.c

GCC/ARM_CM33/secure, ARM_CM55/secure, ARM_CM85/secure:
  secure_context.h
  secure_context.c
  secure_context_port.c
  secure_init.*
  secure_heap.*
  secure_port_macros.h
```

Native `fiber` mapping:

```text
FreeRTOS portmacro.h:
  fiber_portmacro.h
  selected-port traits and selected-port interface

FreeRTOS portmacrocommon.h:
  fiber_portmacrocommon.h or port/common helpers
  only for facts shared by several selected ports

FreeRTOS port.c:
  fiber_port.c
  C-side frame init, exception setup, validation, and start helpers

FreeRTOS portasm.h:
  fiber_portasm.h or private selected-port declarations

FreeRTOS portasm.c:
  fiber_portasm.c or a clearly named handler source
  SVC/PendSV naked assembly and low-level exception-return code

FreeRTOS secure_context.*:
  fiber_secure_context.* or selected v8-M secure-context files
  only when TrustZone secure context support is implemented

FreeRTOS mpu_wrappers*.c:
  fiber_mpu_wrappers*.c only if explicitly supported later
  not part of the core fiber CPU-port runtime by default
  exclude unless a future MPU task-isolation feature is explicitly added
```

Naming rule for new or mechanically renamed port role files:

```text
fiber_<FreeRTOS original role name>

portmacro.h       -> fiber_portmacro.h
portmacrocommon.h -> fiber_portmacrocommon.h
port.c            -> fiber_port.c
portasm.h         -> fiber_portasm.h
portasm.c         -> fiber_portasm.c
secure_context.h  -> fiber_secure_context.h
secure_context.c  -> fiber_secure_context.c
secure_context_port.c -> fiber_secure_context_port.c
```

The CPU profile belongs to the directory name, not necessarily to every file
name. Existing files such as `fiber_port_armv7em.c` are transitional names and
may be mechanically renamed later in a no-behavior-change commit.

Long-term target layout:

```text
fiber/port/
  fiber_port_select.h
  fiber_port_selected.h
  fiber_port_traits.h
  fiber_port_types.h
  fiber_port_state.h
  fiber_port_state.c
  common/
    fiber_port_primask.h
    fiber_port_basepri.h
    fiber_port_vtor.h
    fiber_port_exception.h
    fiber_port_exception.c
    fiber_port_fpu.h
    fiber_port_fpu.c
    fiber_port_psplim.h
  armv6m/
    fiber_portmacro.h
    fiber_port.c
    fiber_portasm.h
    fiber_portasm.c
  armv7m/
    fiber_portmacro.h
    fiber_port.c
    fiber_portasm.h
    fiber_portasm.c
  armv7em/
    fiber_portmacro.h
    fiber_port.c
    fiber_portasm.h
    fiber_portasm.c
  armv7em_m7_r0p1/
    optional split only if errata policy needs a separate source path
  armv8m_baseline/
    non_secure/
      fiber_portmacrocommon.h
      fiber_portmacro.h
      fiber_port.c
      fiber_portasm.h
      fiber_portasm.c
    secure/
      fiber_secure_context.h
      fiber_secure_context.c
      fiber_secure_context_port.c
  armv8m_mainline/
    non_secure/
      fiber_portmacrocommon.h
      fiber_portmacro.h
      fiber_port.c
      fiber_portasm.h
      fiber_portasm.c
    secure/
      fiber_secure_context.h
      fiber_secure_context.c
      fiber_secure_context_port.c
  armv81m_mainline/
    non_secure/
      fiber_portmacrocommon.h
      fiber_portmacro.h
      fiber_port.c
      fiber_portasm.h
      fiber_portasm.c
    secure/
      fiber_secure_context.h
      fiber_secure_context.c
      fiber_secure_context_port.c
```

This is a direction, not a requirement to split every current file immediately.
Pure file-layout changes must be separate from behavior changes.

Important rule:

```text
port/common contains tools, not policy.
selected ports contain policy.
```

For example, `port/common/fiber_port_basepri.h` may provide synchronized
BASEPRI read/write primitives, but `armv7m`, `armv7em`, or v8-M selected ports
decide whether BASEPRI is the scheduler mask mechanism and which threshold is
valid.

## Helper Reimplementation Backlog

The following current `fiber/target` helpers should migrate toward
`fiber/port/common` plus selected-port traits:

```text
fiber_basepri.h:
  move to port/common/fiber_port_basepri.h
  selected port owns BASEPRI policy and M7 errata enablement

fiber_vtor.h:
  move to port/common/fiber_port_vtor.h
  selected port owns whether VTOR exists and whether direct vectors are valid

fiber_irq.h / fiber_irq.c:
  split into port/common/fiber_port_exception.*
  selected port owns PendSV/SVC priority, vector validation, PRIGROUP policy,
  implemented-priority-bit validation, and direct/wrapper vector expectations

fiber_fpu.h / fiber_fpu.c:
  move to port/common/fiber_port_fpu.*
  selected port owns FPU presence, lazy/eager policy, FPCA clearing, and
  high-FP save/restore policy

fiber_pslim.h:
  move to port/common/fiber_port_psplim.h
  selected port owns PSPLIM access gates, context slots, secure/non-secure bank
  selection, and runtime support claim

fiber_feature_policy.h:
  replace gradually with selected-port traits

fiber_target.h:
  shrink to a compatibility facade during migration
```

Do not move these helpers all at once. The migration order should be:

```text
1. selected-port traits
2. BASEPRI helper
3. VTOR/vector helper
4. exception priority and vector validation
5. FPU helper
6. PSPLIM helper
7. v8-M secure/non-secure context helpers
```

Each step needs compile matrix coverage. Behavior-affecting steps also need the
H7 runtime validation checklist before the H7 claim is kept current.

## Native Fiber Adaptation Rules

The `fiber` implementation may follow FreeRTOS port structure closely, but the
runtime contract remains native.

Required adaptations:

```text
pxCurrentTCB:
  replaced by fiber-owned current FiberContext state

vTaskSwitchContext():
  replaced by fiber scheduler bridge and user pick_next hook

TCB first-field top-of-stack:
  replaced by FiberContext.sp with an equivalent saved-top-of-stack invariant

pxPortInitialiseStack():
  represented by fiber_port_init_context_frame()

prvPortStartFirstTask() / SVC first start:
  represented by fiber_port_start_first_context() and fiber_svc()

xPortPendSVHandler():
  represented by fiber_pendsv()

configMAX_SYSCALL_INTERRUPT_PRIORITY:
  represented by selected-port scheduler BASEPRI traits and validation

FreeRTOS tick and xTaskIncrementTick():
  excluded from the core; sleep/timer policy belongs to a user scheduler layer

FreeRTOS queues, semaphores, timers, task API, heap:
  excluded from the CPU-port core
```

Allowed strengthening:

```text
validate scheduler hook presence and immutability
validate returned FiberContext before restore
validate saved stack bounds and restore-frame headroom
validate SVC provenance, opcode, immediate, and stack source
validate vector wiring and exception priority setup
validate errata configuration instead of silently assuming it
fail closed on unvalidated v8-M/MVE/PAC/BTI scenarios
```

The selected port should be at least as conservative as the matching FreeRTOS
port for CPU correctness. It may be more paranoid when that improves failure
quality without creating hidden timing behavior.

### Option C: Use FreeRTOS Directly

Use FreeRTOS directly if the project needs:

```text
preemptive scheduling
priorities
delays
software timers
queues
semaphores
mutexes
event groups
stream buffers
heap implementations
ISR-safe RTOS APIs
the full production FreeRTOS ecosystem
```

This is not the v2 `fiber` goal. The `fiber` goal is a small cooperative
context-transfer core with a user-owned scheduler hook.

## Source and License Policy

The local FreeRTOS reference tree is MIT licensed.

Rules:

1. Do not silently copy FreeRTOS source into `fiber`.
2. If FreeRTOS source or substantial portions are copied or closely adapted,
   keep the required MIT copyright and permission notice.
3. Mark derived portions clearly in source comments or a third-party notice.
4. Do not describe derived code as clean-room implementation.
5. Prefer documenting the FreeRTOS source file used as a reference and writing a
   native `fiber` implementation against the documented CPU contract.

Using public CPU behavior, architecture manuals, and FreeRTOS as a reference for
concepts is different from copying FreeRTOS source text.

## Required Per-Port Parity Record

Every production-selected port must keep a FreeRTOS parity record.

Template:

```text
Fiber port:
  fiber/port/<port>/...

FreeRTOS reference files:
  _reference/FreeRTOS-Kernel/portable/<compiler>/<port>/...

Reference commit:
  <FreeRTOS commit hash or local reference snapshot>

Copied FreeRTOS code:
  no | yes, see license notice

Derived FreeRTOS code:
  no | yes, describe files/fragments

Symbol inventory:
  <FreeRTOS symbol or file-scope mechanism>
    kind: macro | function | static function | asm label | global | config gate
    FreeRTOS purpose:
    fiber decision: adopt | adapt | replace | exclude | defer
    fiber equivalent:
    rationale:
    validation:

Matched CPU behavior checklist:
  SVC first start:
  PendSV save/restore:
  PSP ownership:
  EXC_RETURN handling:
  FPU/MVE handling:
  stack-limit handling:
  scheduler critical-section policy:
  errata policy:
  priority/vector validation:

Fiber-specific differences:
  scheduler hook contract
  extra validation
  no tick scheduler
  no FreeRTOS task API

Validation status:
  compile-covered profiles
  hardware-validated boards
  trap modes covered
  unsupported or explicitly gated features
```

## Current v2 Direction

Do not replace the current `fiber/port` design with a FreeRTOS ABI adapter.

Continue in this order:

1. Keep `fiber_port_traits.h` as the selected-port contract checker.
2. Make each selected `fiber/port/*` header export CPU facts and frame traits.
3. For each port, create or update the FreeRTOS parity record before behavior
   is claimed.
4. Move feature policy from `fiber/target` into selected-port traits and
   `port/common` helpers gradually.
5. Compare each selected port against the matching FreeRTOS port files.
6. Document every intentional difference and every excluded FreeRTOS symbol.
7. Hardware-validate a port before claiming runtime support.

The guiding rule is:

```text
FreeRTOS is the CPU-port reference, not the fiber runtime architecture.
```
