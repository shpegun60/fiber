# ARM_CM0 FreeRTOS Parity Record

This is the exhaustive mechanism ledger for the privileged Cortex-M0/M0+
selected port. The pinned FreeRTOS directory contains both non-MPU and optional
MPU/unprivileged branches. This profile deliberately implements only the
privileged ARMv6-M branch; every MPU family is explicitly deferred rather than
silently ignored. No FreeRTOS source text is copied into fiber.

## Reference

```text
tree:   _reference/FreeRTOS-Kernel
commit: a50edad08b29052631aa469d4df6e6ec7ff68878
files:  portable/GCC/ARM_CM0/portmacro.h
        portable/GCC/ARM_CM0/port.c
        portable/GCC/ARM_CM0/portasm.h
        portable/GCC/ARM_CM0/portasm.c
```

Native fiber source group:

```text
fiber/port/ARM_CM0/fiber_portmacro.h
fiber/port/ARM_CM0/fiber_port_types.h
fiber/port/ARM_CM0/fiber_port_boot_types.h
fiber/port/ARM_CM0/fiber_port_boot.h
fiber/port/ARM_CM0/fiber_port_boot.c
fiber/port/ARM_CM0/fiber_port.c
fiber/port/ARM_CM0/fiber_port_exception.c
```

The port is compile/link-covered for M0 and M0+. It is not hardware-validated
until matching STM32 boards pass the runtime checklist.

## `portmacro.h` Ledger

| FreeRTOS item family | Fiber mapping | Decision |
| --- | --- | --- |
| Primitive compatibility aliases and `StackType_t` | Fixed-width C types and selected `FiberContext` | Adapted; kernel aliases are not exported. |
| Tick types, delay constants, tick period, atomic tick traits | User scheduler | Excluded from CPU port. |
| `portARCH_NAME` | `FIBER_PORT_NAME` and exact build selection | Adapted. |
| stack growth/alignment | selected ARMv6-M traits | Reimplemented. |
| used/inline/compiler barrier attributes | `fiber_compiler.h` and local macros | Adapted. |
| `portYIELD`, NVIC PendSV register/bit | `fiber_schedule()` and selected `PENDSVSET` | Adapted to cooperative scheduling. |
| ISR yield macros | None | Excluded until an ISR-safe scheduler API exists. |
| PRIMASK set/restore and interrupt enable/disable | selected-port C/asm helpers | Reimplemented. Nonzero `FIBER_SCHEDULER_BASEPRI` is a compile error because ARMv6-M has no BASEPRI. |
| critical nesting API | None public | Excluded; PendSV uses a saved PRIMASK envelope only around the scheduler hook. |
| task function macros | plain `entry_t` | Adapted without compatibility macros. |
| tickless and ready-priority macros | User scheduler/platform | Excluded. |
| `xPortIsInsideInterrupt` | direct IPSR checks | Adapted. |
| `portNOP` | None | Excluded. |

## MPU Macro Families

The following FreeRTOS `configENABLE_MPU == 1` families do not belong to this
privileged context ABI and are deferred to a future exact `ARM_CM0_MPU` port:

```text
portPRIVILEGED_* / portUNPRIVILEGED_* / portSTACK_REGION
portFIRST_CONFIGURABLE_REGION through portTOTAL_NUM_REGIONS
portMPU_REGION_SIZE_256B through portMPU_REGION_SIZE_4GB
all strongly-ordered, device, normal-memory, shareability/cacheability traits
all privileged/unprivileged access-permission and execute-never traits
portSVC_RAISE_PRIVILEGE, portSVC_SYSTEM_CALL_EXIT, portSVC_YIELD
MPU wrapper, system-call, ACL, and kernel-object access macros
```

`portSVC_START_SCHEDULER` maps to fiber's mandatory first-start SVC. The other
FreeRTOS SVC services are excluded from privileged ARM_CM0 because it never
runs an unprivileged Thread context.

## `port.c` Constant Ledger

| FreeRTOS item family | Fiber mapping | Decision |
| --- | --- | --- |
| SysTick registers/bits, 24-bit limit, missed-count factor | User scheduler/platform | Excluded. |
| SHPR2/SHPR3 and PendSV/SysTick priorities | selected exception source | PendSV/SVCall part adapted; SysTick excluded. |
| VTOR and vector slots 11/14 | selected active-vector-source helper | Adapted. VTOR-less M0 validates the architecture/platform base at zero; M0+ uses VTOR when present. |
| initial xPSR, EXC_RETURN, PC/LR/xPSR frame offsets, padding bit | selected frame ABI and validators | Reimplemented. |
| MPU type/control/RBAR/RASR registers and all MPU masks/range helpers | future `ARM_CM0_MPU` | Deferred as one complete feature family. |
| CONTROL privilege constants | future `ARM_CM0_MPU` | Deferred; privileged ARM_CM0 uses Thread/PSP without unprivileged policy. |
| task-return address | `fiber_internal_task_return()` | Replaced by a panic target. |

## `port.c` / `portasm.c` Function Ledger

| FreeRTOS function/path | Fiber path | Decision |
| --- | --- | --- |
| non-MPU `pxPortInitialiseStack` | selected context init and frame builder | Adapted with exact Thumb-1 layout, sealed metadata, Thumb PC, return panic target, and saved `r9`. |
| MPU `pxPortInitialiseStack` variant | future `ARM_CM0_MPU` | Deferred. |
| `prvTaskExitError` | `fiber_internal_task_return()` | Replaced. |
| `vRestoreContextOfFirstTask` / `vStartFirstTask` | `fiber_port_start_first_context()` plus strong `SVC_Handler` | Adapted to scheduler-selected mandatory SVC start. |
| `SVC_Handler` / `vPortSVCHandler_C` non-MPU start service | strong `SVC_Handler` | Adapted and hardened. Fiber validates IPSR 11, exact F9 EXC_RETURN, MSP origin/alignment, xPSR.T, zero stacked IPSR, absent `STACKALIGN`, nonzero aligned PC, SVC opcode, and immediate. |
| MPU SVC dispatch, privilege raise/reset, syscall exit and yield | future `ARM_CM0_MPU` | Deferred. |
| non-MPU `PendSV_Handler` | strong `PendSV_Handler` | Adapted with Thumb-1 staging of `r8-r11`. Fiber validates IPSR 14, exact FD EXC_RETURN, PSP origin/alignment, current context, save headroom, and xPSR `STACKALIGN` padding. |
| MPU `PendSV_Handler` and MPU programming | future `ARM_CM0_MPU` | Deferred. |
| `ulSetInterruptMask`, `vClearInterruptMask` | saved PRIMASK scheduler envelope | Reimplemented. |
| `xPortStartScheduler` | `fiber_start()` plus selected startup operations | Split; tick setup and kernel scheduler state are excluded. |
| `vPortEndScheduler` | None | Excluded. |
| `vPortYield`, `vPortEnterCritical`, `vPortExitCritical` | `fiber_schedule()` and internal PRIMASK envelope | Adapted only where needed; no public critical nesting API. |
| `SysTick_Handler`, timer setup, tickless sleep | User scheduler/platform | Excluded. |
| `xPortIsInsideInterrupt` | IPSR preconditions | Adapted. |
| `prvGetMPURegionSizeSetting`, `prvSetupMPU`, `vPortStoreTaskMPUSettings` | future `ARM_CM0_MPU` | Deferred. |
| `xPortIsPrivileged`, buffer/kernel-object authorization, grant/revoke ACL functions | future optional MPU ABI | Deferred. |

## Paranoid Additions

Restore validation is mandatory and checks context extent, immutable structure,
canary, saved SP/frame extent, exact EXC_RETURN, xPSR.T, stacked IPSR, stacked
PC floor/alignment, and optional code-address policy. PendSV validates current
before reading its metadata. SVC/PendSV reject foreign exception provenance.
The handler save upper bound includes the optional hardware alignment word
reported by xPSR bit 9. The external scheduler must preserve PRIMASK, CONTROL,
and port-owned state.

## Intentionally Outside This Port

```text
FreeRTOS task lists and priority scheduler
tick and tickless idle
queues and synchronization
ISR-safe wake/yield API
MPU and unprivileged execution
BASEPRI
FPU context
```

## Remaining Evidence

```text
STM32F0/G0/C0/L0/U0/WB0-class normal switching
VTOR-present and VTOR-absent startup policy
first SVC and later PendSV provenance
PRIMASK and malformed-frame traps
long-run stack/canary behavior
```
