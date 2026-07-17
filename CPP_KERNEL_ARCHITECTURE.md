# C++ Kernel Architecture Direction

## Status

This document freezes the intended layer above the C fiber runtime. It is a
design contract and implementation backlog, not a claim that a C++ kernel,
preemptive scheduler, synchronization library, or lwIP adapter exists today.

The existing C/assembly runtime remains a CPU context-transfer engine with an
external scheduler callback. Porting Cortex-M CPU mechanics from FreeRTOS does
not import FreeRTOS task lists, queues, timers, or scheduler policy.

## Layering

The target architecture is:

```text
selected C/assembly port
    CPU context, exceptions, masks, FPU/MPU/security and errata

portable C fiber core
    context lifecycle, current publication and scheduler callback boundary

C++ kernel and scheduler
    ready/sleep/wait state, time, policy and task ownership

C++ synchronization
    mutex, event, semaphore, channel and ISR handoff

service adapters
    lwIP sys_arch, timers, drivers and application services
```

Only the first two layers are part of the current runtime. The C++ layers must
use the frozen public C API and scheduler callback; they must not reach into a
selected port's private context layout.

## Scheduling Modes

The reference C++ kernel will make scheduling policy a compile-time choice,
not a runtime flag hidden inside the CPU port. The intended shape is equivalent
to:

```cpp
fiber::kernel<fiber::cooperative> cooperative_kernel;
fiber::kernel<fiber::preemptive> preemptive_kernel;
```

The exact names are not frozen yet. The semantic split is frozen:

| Mode | Selection rule | Switch requests |
| --- | --- | --- |
| Cooperative | deterministic round-robin over ready tasks | explicit yield, sleep, wait, or wake policy |
| Preemptive | fixed-priority ready selection with optional same-priority time slicing | explicit requests plus tick/ISR reschedule requests |

Both modes use the same selected CPU port, `FiberContext`, first-start path,
and PendSV save/restore engine. The scheduler decides *which* context runs;
the selected port decides *how* the CPU transfers to it.

The existing raw scheduler callback remains the expert customization surface.
The reference C++ scheduler is a provided policy, not a mandatory replacement
for a user scheduler.

## Preemption Boundary

Preemption does not move scheduler policy into SysTick assembly. A timer or ISR
updates kernel state and requests a reschedule. The selected port pends PendSV;
the scheduler callback runs in the already protected PendSV envelope and
returns one non-null restoreable context.

The future ISR surface must be explicit, for example a dedicated
`schedule_from_isr`/wake-from-ISR boundary. It must validate active ISR
priority in the same class of cases where FreeRTOS validates interrupt
priority. This API is not part of the current five-function public surface and
must not be invented independently by each adapter.

## Portable Application Contract

Code intended to run unchanged in cooperative and preemptive builds follows
these rules:

* task-local state may be accessed directly;
* shared mutable state uses a kernel mutex, channel, event, semaphore, or an
  appropriate atomic;
* ISR communication uses an explicit ISR-safe operation;
* code must not rely on "nothing can interrupt me until I yield";
* any preemption guard is mode-aware RAII owned by the C++ kernel, not a direct
  application write to PRIMASK or BASEPRI;
* blocking operations express wait state to the scheduler instead of polling
  while holding shared state.

Cooperative-only applications may intentionally rely on run-until-yield, but
that dependency must remain visible in their selected kernel policy. Switching
such code to preemptive mode is not automatically safe.

## lwIP Integration

The CPU port does not know about lwIP.

For `NO_SYS=1`, the cooperative kernel may drive lwIP's raw API from one event
loop and timer source. For `NO_SYS=0`, an adapter implements the lwIP
`sys_arch` contract using C-callable wrappers over the C++ kernel's threads,
semaphores, mailboxes, time, and protection primitives.

```text
lwIP C API -> sys_arch C wrappers -> C++ synchronization/kernel -> fiber core
```

The adapter must document callback/thread ownership. A raw-API callback model
must not be silently mixed with a threaded `sys_arch` model.

## Allocation And Failure Policy

The reference embedded configuration uses static allocation by default. The C
bridge is `noexcept`; exceptions and RTTI are not required. Allocation failure
is returned before start where recovery is meaningful. Violated runtime or CPU
invariants terminate through the existing fiber panic policy.

## Relationship To Optional Port Features

MPU, SecureContext, TF-M, and other selected-port feature ABIs remain below the
C++ kernel. The kernel may provide a feature-neutral policy facade, while board
or profile integration supplies an optional backend. Ordinary task code should
not include selected-port extension headers.

Application services such as PSA storage or cryptography require their own
application-level abstraction. A fiber feature ABI controls execution context;
it is not a general secure-service abstraction.

## Implementation Order

1. Complete and freeze the required STM32 CPU ports.
2. Define the minimal task-state and clock contracts without changing the C
   core ABI.
3. Implement a statically allocated cooperative round-robin reference kernel.
4. Add synchronization primitives with semantics valid in both modes.
5. Add the ISR reschedule boundary and the preemptive fixed-priority policy.
6. Add lwIP adapters and board-specific service integration.

Each step requires independent compile, link, generated-code, and hardware
evidence appropriate to its behavior. The CPU-port project must not grow queue,
timer, or networking policy merely to make a higher layer convenient.
