# ARM_CM4 FreeRTOS Parity Record

This is the exhaustive mechanism ledger for the Cortex-M4/M4F selected port.
Every relevant item in the pinned reference is classified. No FreeRTOS source
text is copied into the fiber implementation.

## Reference

```text
tree:   _reference/FreeRTOS-Kernel
commit: a50edad08b29052631aa469d4df6e6ec7ff68878
files:  portable/GCC/ARM_CM4F/portmacro.h
        portable/GCC/ARM_CM4F/port.c
```

Native fiber source group:

```text
fiber/port/ARM_CM4/fiber_portmacro.h
fiber/port/ARM_CM4/fiber_port_types.h
fiber/port/ARM_CM4/fiber_port_boot_types.h
fiber/port/ARM_CM4/fiber_port_boot.h
fiber/port/ARM_CM4/fiber_port_boot.c
fiber/port/ARM_CM4/fiber_port.c
fiber/port/ARM_CM4/fiber_port_exception.c
```

The same source supports core-only M4 and hard-float M4F builds from compiler,
CMSIS, and silicon facts. Both are compile/link-covered and await hardware
validation on matching STM32 targets.

## `portmacro.h` Ledger

| FreeRTOS item family | Fiber mapping | Decision |
| --- | --- | --- |
| Primitive compatibility types and `StackType_t` | Fixed-width C types and selected `FiberContext` | Adapted; FreeRTOS aliases are not exported. |
| Tick types, atomic tick traits, delay constants, `portTICK_PERIOD_MS` | User scheduler time policy | Excluded from CPU port. |
| `portSTACK_GROWTH`, `portBYTE_ALIGNMENT` | Selected stack traits | Reimplemented. |
| used/inline/compiler barrier attributes | `fiber_compiler.h` plus port-local macros | Adapted to the frozen compiler ABI. |
| `portYIELD` and NVIC PendSV constants | `fiber_schedule()` and selected-port `PENDSVSET` | Adapted to cooperative scheduling. The direct request requires exact privileged Thread/PSP `CONTROL` state. |
| ISR yield and ISR interrupt-mask macros | None public | Excluded until an ISR-safe scheduler API exists. |
| BASEPRI disable/enable/raise/set helpers | Port-owned C and asm BASEPRI helpers | Reimplemented for the PendSV scheduler envelope. |
| critical nesting API | None public | Excluded; only the handler-local scheduler envelope exists. |
| task function macros | plain `entry_t` | Adapted without compatibility macros. |
| tickless and optimized task-priority macros | User scheduler/platform | Excluded. |
| interrupt-priority assertion | startup priority-mask, BASEPRI, PRIGROUP, and vector validation | Adapted for owned SVC/PendSV paths. Active-ISR validation is deferred with ISR APIs. |
| `xPortIsInsideInterrupt` | direct IPSR checks | Adapted. |
| `portNOP` | None | Excluded. |

## `port.c` Constant Ledger

| FreeRTOS item family | Fiber mapping | Decision |
| --- | --- | --- |
| SysTick registers/bits, 24-bit tick limit, missed-count factor | User scheduler/platform | Excluded. |
| SHPR2/SHPR3, minimum exception priority, PendSV priority | `fiber_port_exception.c` | Adapted; SysTick priority is not owned. |
| stale PendSV clear bit | startup cleanup | Reimplemented. |
| VTOR and slots 11/14 | selected vector source and strong handlers | Reimplemented and hardened. |
| NVIC IP, AIRCR, PRIGROUP, implemented-priority masks | startup probing/readback | Reimplemented. |
| `portINITIAL_XPSR`, `portINITIAL_EXC_RETURN`, start-address mask | selected frame ABI | Reimplemented. |
| `portFPCCR`, ASPEN/LSPEN bits | port-owned CPACR/FPCCR policy | Adapted with readback. |
| CM7 r0p0/r0p1 CPUID rejection in generic CM4F reference | build selection | Excluded from this concrete M4 port because M7 routes to `ARM_CM7/r0p1`; source guards reject M7. |
| task-return address | `fiber_internal_task_return()` | Replaced by a panic target. |

The selected BASEPRI threshold and `__NVIC_PRIO_BITS` are encoded in the exact
context cohort. An 8-bit NVIC defaults to threshold `2`; threshold `1` is
rejected because bit 0 is subpriority. Other values are checked for implemented
priority bits at compile time and startup.

## `port.c` Function Ledger

| FreeRTOS function/path | Fiber path | Decision |
| --- | --- | --- |
| `pxPortInitialiseStack` | `fiber_port_context_init()` and frame builder | Adapted and hardened with exact core/FP frame traits, sealed metadata, Thumb PC, return panic LR, and saved `r9`. |
| `prvTaskExitError` | `fiber_internal_task_return()` | Replaced. |
| `vPortSVCHandler` | strong `SVC_Handler` | Adapted. Fiber validates IPSR 11, exact F9 EXC_RETURN, MSP origin/alignment, xPSR.T, zero stacked IPSR, absent `STACKALIGN`, nonzero aligned PC, SVC opcode/immediate, and restore context. |
| `prvPortStartFirstTask` | `fiber_port_start_first_context()` | Adapted to mandatory scheduler-selected SVC start. |
| `xPortStartScheduler` | `fiber_start()` plus selected-port startup operations | Split; tick setup and internal scheduler state are excluded. |
| `vPortEndScheduler` | None | Excluded. |
| `vPortEnterCritical`, `vPortExitCritical` | PendSV-local scheduler envelope | Public kernel API excluded. |
| `xPortPendSVHandler` | strong `PendSV_Handler` | Adapted. Core save/restore order matches the reference; `s16-s31` are conditional on EXC_RETURN bit 4. Fiber additionally validates IPSR 14, accepted FD/ED EXC_RETURN, PSP alignment/origin, current context, save headroom, full FP extent, and xPSR `STACKALIGN` padding. |
| `vTaskSwitchContext` | user scheduler bridge | Replaced; hook CPU state is snapshotted and validated. |
| `pxCurrentTCB` | assembly-load-only current slot and `FiberContext.sp` | Adapted with common-only publication. |
| `xPortSysTickHandler`, timer setup, tickless sleep | User scheduler/platform | Excluded. |
| `vPortEnableVFP` | selected-port early FPU setup | Adapted and hardened with CPACR/FPCCR write/readback and eager/lazy policy. |
| `vPortValidateInterruptPriority` | selected-port startup exception validation | Adapted for currently owned exception paths. |
| XMC4000 `WORKAROUND_PMU_CM001` | None | Excluded as non-STM32 silicon policy. |

## FPU Contract

No-FPU M4 builds use only the basic frame and software `r4-r11` plus
EXC_RETURN. M4F builds conditionally preserve `s16-s31`; hardware owns the
basic low-FP frame. Stacked PC and xPSR remain at PSP offsets 24 and 28 for
both basic and extended frames. The extended FP area changes total extent, not
those offsets. The save upper bound also includes the optional hardware
alignment word reported by xPSR bit 9.

## Paranoid Additions

Restore validation is mandatory and checks context extent, immutable structure,
canary, saved SP/frame extent, exact EXC_RETURN, xPSR.T, stacked IPSR, stacked
PC floor/alignment, and optional code-address policy. PendSV validates current
before reading metadata. SVC/PendSV reject foreign exception provenance. The
external scheduler hook must preserve PRIMASK, BASEPRI, FAULTMASK, CONTROL,
and port-owned state.

## Intentionally Outside This Port

```text
FreeRTOS task lists and priority scheduler
tick and tickless idle
queues and synchronization
ISR-safe wake/yield API
MPU/unprivileged context
M7 errata policy
```

MPU and M7 are separate exact selected ports, not conditional modes hidden in
this context ABI.

## Remaining Evidence

```text
STM32F3/F4/G4/L4-class core-only and hard-float runs
basic and extended FP context stress
first SVC and later PendSV provenance
BASEPRI/priority/vector readback
all integrity and malformed-frame traps
```
