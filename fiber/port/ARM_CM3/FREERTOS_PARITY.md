# ARM_CM3 FreeRTOS Parity Record

Paired generated-object evidence is mandatory under
`../../../FREERTOS_ASM_PARITY.md`; this ledger supplies the port-specific
source classification and explains the exact per-context EXC_RETURN policy.

This is the exhaustive mechanism ledger for the privileged Cortex-M3 selected
port. Every relevant item in the pinned FreeRTOS files is classified as
reimplemented, adapted, replaced, intentionally excluded, or deferred. No
FreeRTOS source text is copied into the fiber implementation.

## Reference

```text
tree:   _reference/FreeRTOS-Kernel
commit: a50edad08b29052631aa469d4df6e6ec7ff68878
files:  portable/GCC/ARM_CM3/portmacro.h
        portable/GCC/ARM_CM3/port.c
```

Native fiber source group:

```text
fiber/port/ARM_CM3/fiber_portmacro.h
fiber/port/ARM_CM3/fiber_port_types.h
fiber/port/ARM_CM3/fiber_port_boot_types.h
fiber/port/ARM_CM3/fiber_port_boot.h
fiber/port/ARM_CM3/fiber_port_boot.c
fiber/port/ARM_CM3/fiber_port.c
fiber/port/ARM_CM3/fiber_port_exception.c
```

The port is compile/link-covered. It is not hardware-validated until a
matching STM32 Cortex-M3 board passes the runtime checklist.

## `portmacro.h` Ledger

| FreeRTOS item family | Fiber mapping | Decision |
| --- | --- | --- |
| `portCHAR`, `portFLOAT`, `portDOUBLE`, `portLONG`, `portSHORT`, `portSTACK_TYPE`, `portBASE_TYPE` | Fixed-width C types and selected `FiberContext` | Adapted; kernel compatibility aliases are not exported. |
| `TickType_t`, `portMAX_DELAY`, `portTICK_TYPE_IS_ATOMIC`, `portTICK_PERIOD_MS` | User scheduler time policy | Excluded from the CPU port. |
| `portSTACK_GROWTH`, `portBYTE_ALIGNMENT` | `fiber_portSTACK_GROWTH`, `fiber_portBYTE_ALIGNMENT`, `FIBER_PORT_STACK_ALIGNMENT` | Reimplemented. |
| `portDONT_DISCARD`, `portINLINE`, `portFORCE_INLINE`, `portMEMORY_BARRIER` | `fiber_compiler.h` and port-local barrier macros | Adapted to the frozen compiler ABI. |
| `portYIELD()` | `fiber_schedule()` -> `fiber_port_runtime_schedule()` | Adapted to cooperative scheduler selection and `PENDSVSET`; the direct request first requires exact privileged Thread/PSP `CONTROL` state. |
| `portNVIC_INT_CTRL_REG`, `portNVIC_PENDSVSET_BIT` | Same CPU constants with `fiber_port` prefix | Reimplemented. |
| `portEND_SWITCHING_ISR`, `portYIELD_FROM_ISR` | None | Excluded until an ISR-safe scheduler API exists. |
| `portSET_INTERRUPT_MASK_FROM_ISR`, `portCLEAR_INTERRUPT_MASK_FROM_ISR` | Internal BASEPRI helpers only | Public ISR API excluded; CPU mechanism retained internally. |
| `portDISABLE_INTERRUPTS`, `portENABLE_INTERRUPTS` | Selected-port BASEPRI read/write and asm snippets | Adapted. |
| `portENTER_CRITICAL`, `portEXIT_CRITICAL`, critical nesting | PendSV scheduler envelope only | Kernel-wide nesting API excluded. |
| `portTASK_FUNCTION_PROTO`, `portTASK_FUNCTION` | `entry_t`, a plain `void (*)(void *)` | Adapted without compatibility macros. |
| `portSUPPRESS_TICKS_AND_SLEEP` | User scheduler/platform | Excluded. |
| Optimized ready-priority macros and CLZ helper | User scheduler | Excluded from core; fiber imposes no priority policy. |
| `portASSERT_IF_INTERRUPT_PRIORITY_INVALID` | Startup priority-mask, BASEPRI, PRIGROUP, and vector validation | Adapted for owned SVC/PendSV state. Active-ISR validation remains deferred with ISR-safe APIs. |
| `portNOP` | None | Excluded. |
| `xPortIsInsideInterrupt` | direct IPSR checks in selected-port operations | Adapted. |
| `vPortRaiseBASEPRI`, `ulPortRaiseBASEPRI`, `vPortSetBASEPRI` | `fiber_port_basepri_*` and scheduler critical macros | Reimplemented with state-preserving checks around the external scheduler hook. |

## `port.c` Constant Ledger

| FreeRTOS item family | Fiber mapping | Decision |
| --- | --- | --- |
| SysTick registers, clock/count/pend bits, `portMAX_24_BIT_NUMBER`, `portMISSED_COUNTS_FACTOR` | User scheduler/platform | Excluded; fiber does not own a tick. |
| `portNVIC_SHPR2_REG`, `portNVIC_SHPR3_REG`, PendSV/SysTick priority encodings | `fiber_port_exception.c` | PendSV/SVCall part adapted; SysTick part excluded. |
| `portNVIC_PENDSVCLEAR_BIT` | Selected-port pending-state cleanup | Reimplemented. |
| `portSCB_VTOR_REG`, vector indexes 11 and 14 | Selected-port vector source and strong handler validation | Reimplemented and hardened. |
| `portFIRST_USER_INTERRUPT_NUMBER`, NVIC IP offset, AIRCR/PRIGROUP constants, priority masks | Startup priority probing and readback | Reimplemented. |
| `portVECTACTIVE_MASK` | IPSR checks | Adapted. |
| `portINITIAL_XPSR`, `portSTART_ADDRESS_MASK` | Synthetic frame builder and restore validator | Reimplemented. |
| `configTASK_RETURN_ADDRESS` / `portTASK_RETURN_ADDRESS` | `fiber_internal_task_return()` | Replaced by a mandatory panic target. |

The selected BASEPRI threshold is part of the exact context cohort together
with `__NVIC_PRIO_BITS`. For an 8-bit NVIC the default is `2`, not `1`, because
bit 0 is necessarily subpriority. Compile-time checks reject unimplemented
priority bits and reject bit 0 for that profile.

## `port.c` Function Ledger

| FreeRTOS function/path | Fiber path | Decision |
| --- | --- | --- |
| `pxPortInitialiseStack` | `fiber_port_context_init()` and `fiber_port_init_context_frame()` | Adapted and hardened with sealed metadata, exact frame geometry, Thumb PC, return panic target, and saved `r9`. |
| `prvTaskExitError` | `fiber_internal_task_return()` | Replaced. |
| `vPortSVCHandler` | strong `SVC_Handler` | Adapted. Fiber additionally validates IPSR 11, exact F9 EXC_RETURN, MSP origin/alignment, xPSR.T, zero stacked IPSR, absent `STACKALIGN`, nonzero aligned PC, SVC opcode, and immediate. |
| `prvPortStartFirstTask` | `fiber_port_start_first_context()` | Adapted to the scheduler-selected first context and mandatory SVC start. |
| `xPortStartScheduler` | `fiber_start()` plus selected-port startup operations | Split. Tick setup and internal task selection are intentionally absent. |
| `vPortEndScheduler` | None | Excluded for bare-metal one-shot startup. |
| `vPortEnterCritical`, `vPortExitCritical` | Internal PendSV scheduler envelope | Public kernel API excluded. |
| `xPortPendSVHandler` | strong `PendSV_Handler` | Adapted and hardened. The handler validates IPSR 14, exact FD EXC_RETURN, PSP origin/alignment, running context integrity, save headroom, and the optional xPSR `STACKALIGN` word before save. |
| `vTaskSwitchContext` | `fiber_port_scheduler_pick_next_from_pendsv()` | Replaced by the external scheduler hook under BASEPRI with CPU-state preservation checks. |
| `pxCurrentTCB` | assembly-load-only common current slot and `FiberContext.sp` | Adapted; only common runtime publishes the slot. |
| `xPortSysTickHandler`, `vPortSetupTimerInterrupt`, `vPortSuppressTicksAndSleep` | User scheduler/platform | Excluded. |
| `vPortValidateInterruptPriority` | startup exception/priority validation | Adapted for currently owned exception paths. |

## Paranoid Additions

Compared with the reference port, restore validation is mandatory and checks
the context extent, immutable structure, canary, saved SP/frame extent, exact
EXC_RETURN, xPSR.T, stacked IPSR, stacked PC floor/alignment, and optional code
address policy. PendSV validates the current context before its first metadata
load. SVC and PendSV reject foreign exception provenance before using a frame.
The external scheduler hook must preserve PRIMASK, BASEPRI, FAULTMASK, CONTROL,
and port-owned state.

## Intentionally Outside This Port

```text
FreeRTOS task lists and priority scheduler
tick and tickless idle
queues and synchronization
ISR-safe wake/yield API
MPU/unprivileged context
```

MPU support is not a conditional branch in this privileged profile. It is a
separate exact selected port (`ARM_CM3_MPU`) with its own context ABI and
parity ledger.

## Remaining Evidence

```text
STM32F1-class normal switching
first SVC and later PendSV handler provenance
BASEPRI/priority/vector readback
all integrity and malformed-frame traps
long-run stack/canary behavior
```
