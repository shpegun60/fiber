# C++ Kernel Architecture Direction

## Status

This document freezes the intended layers above the processor Context engine.
It is a design contract and implementation backlog, not a claim that a
separate Fiber lifecycle, C++ kernel, preemptive scheduler, synchronization
library, or lwIP adapter exists today.

The existing v2 C/assembly runtime currently combines the future Context engine
with a thin raw Fiber facade and external scheduler callback. Its separation
after the port freeze is normative in `CONTEXT_FIBER_ARCHITECTURE.md`. Porting
Cortex-M CPU mechanics from FreeRTOS does not import FreeRTOS task lists,
queues, timers, or scheduler policy.

## Layering

The target architecture is:

```text
selected C/assembly Context port
    CPU context, exceptions, masks, FPU/MPU/security and errata

portable C Context engine
    context construction, current publication, dispatcher and switch requests

portable Fiber lifecycle
    stackful identity, execution lifetime and Context-dispatch adaptation

C++ kernel and scheduler
    ready/sleep/wait state, time, policy and task ownership

C++ synchronization
    mutex, event, semaphore, channel and ISR handoff

service adapters
    lwIP sys_arch, timers, drivers and application services
```

The current runtime physically implements the selected port plus the mechanics
that will become the Context engine. It does not yet implement the separate
Fiber lifecycle or C++ layers. During v2 those future layers use the frozen
public C API and scheduler callback. After extraction they use only the Context
consumer surface and must never reach into a selected port's private layout.

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

Both modes use the same selected Context port, execution-context type,
first-start path, and PendSV save/restore engine. The scheduler decides *which*
Task/Fiber runs; the Fiber adapter returns its contained context; the selected
port decides *how* the CPU transfers to it.

The existing raw scheduler callback remains the v2 expert customization
surface. In the separated architecture it becomes the private Fiber-to-Context
dispatcher adapter. The reference C++ scheduler remains a provided policy, not
a mandatory replacement for a user policy.

## Preemption Boundary

Preemption does not move scheduler policy into SysTick assembly. A timer or ISR
updates kernel state and requests a reschedule through the Context ISR boundary.
The selected port pends PendSV; the Fiber dispatcher adapter runs in the already
protected PendSV envelope, asks the scheduler for a Task/Fiber, and returns one
non-null restoreable context.

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

MPU, SecureContext, TF-M, and other selected-port feature ABIs remain inside or
below the Context backend and below Fiber and the C++ kernel. The kernel may
provide a feature-neutral policy facade, while board or profile integration
supplies an optional backend. Ordinary task code should not include selected-
port extension headers.

Application services such as PSA storage or cryptography require their own
application-level abstraction. A fiber feature ABI controls execution context;
it is not a general secure-service abstraction.

## Implementation Order

1. Complete and freeze the required STM32 Context ports under the current v2
   ABI.
2. Extract the standardized Context consumer surface without changing selected
   port assembly or frame layout.
3. Implement the portable Fiber lifecycle as a Context consumer.
4. Define the minimal C++ Task state and clock contracts.
5. Implement a statically allocated cooperative FIFO reference kernel.
6. Add synchronization primitives with semantics valid in both modes.
7. Add the validated ISR reschedule boundary and preemptive fixed-priority
   policy.
8. Add round-robin, EDF, and CBS as independent policy slices.
9. Add lwIP adapters and board-specific service integration.

Each step requires independent compile, link, generated-code, and hardware
evidence appropriate to its behavior. The CPU-port project must not grow queue,
timer, or networking policy merely to make a higher layer convenient.
