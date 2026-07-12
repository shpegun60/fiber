# GCC ARM_CM7 r0p1 FreeRTOS Parity Record

This record tracks the first FreeRTOS-style selected source group in `fiber`.
The goal is not to copy FreeRTOS source text. The goal is to audit every CPU
port mechanism in the local FreeRTOS reference and either reimplement it,
adapt it to the cooperative fiber model, or explicitly exclude it.

## Reference

FreeRTOS reference tree:

```text
_reference/FreeRTOS-Kernel
```

Reference commit:

```text
a50edad08b29052631aa469d4df6e6ec7ff68878
```

Reference files:

```text
portable/GCC/ARM_CM7/ReadMe.txt
portable/GCC/ARM_CM7/r0p1/portmacro.h
portable/GCC/ARM_CM7/r0p1/port.c
portable/GCC/ARM_CM4F/portmacro.h
portable/GCC/ARM_CM4F/port.c
portable/CMakeLists.txt
```

Native fiber files:

```text
fiber/port/ARM_CM7/r0p1/fiber_portmacro.h
fiber/port/ARM_CM7/r0p1/fiber_port.c
fiber/port/ARM_CM7/r0p1/fiber_port_exception.c
fiber/fiber_types.h
fiber/fiber_runtime_state.h
fiber/fiber_boot.h
fiber/port/fiber_static_assert.h
```

No FreeRTOS source text is copied into these files. If future work copies
substantial FreeRTOS source, the MIT license notice must travel with that
copied source.

## Build Selection

FreeRTOS production selection:

```text
FREERTOS_PORT=GCC_ARM_CM7
include path: portable/GCC/ARM_CM7/r0p1
source:       portable/GCC/ARM_CM7/r0p1/port.c
```

Fiber v2 selected build:

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV7EM=1
FIBER_CORTEX_M7_R0P1_ERRATA_837070=1
include path: fiber/port/ARM_CM7/r0p1
sources:      fiber/port/ARM_CM7/r0p1/fiber_port.c
              fiber/port/ARM_CM7/r0p1/fiber_port_exception.c
```

The current H7 application tree also routes selector-driven ARMv7E-M builds
directly to this concrete `ARM_CM7/r0p1` port through `fiber_port_selected.h`.
The generic `armv7em` implementation is active only for Cortex-M4/M4F; its
source guard rejects Cortex-M7 so the two implementations cannot collide.

This directory is now a native selected source group. It no longer includes the
generic `armv7em` `.c` implementation, and the selected files do not include
`fiber_target.h`. The source text is fiber-owned and keeps the validated
paranoid checks from the previous ARMv7E-M path.

## File Mapping

| FreeRTOS file role | Fiber file role | Decision |
| --- | --- | --- |
| `portmacro.h` | `fiber_portmacro.h` | Reimplemented with fiber names. Owns selected CPU traits, CM7 r0p1 constants, frame size traits, helper macros, and public port prototypes. It includes `mcu_core.h`, the shared compiler ABI, and panic contract, but only forward-declares `FiberContext` and does not consume its layout. |
| `port.c` | `fiber_port.c` | Reimplemented with fiber scheduler semantics. Owns seed frame, SVC first start, and PendSV switch for this selected source group. It includes the runtime headers it directly uses because this source file needs `FiberContext`, boot validation, panic, and scheduler bridge declarations. |
| `portasm.h` / `portasm.c` | none for this port | Excluded for this selected port. The FreeRTOS GCC ARM_CM7 r0p1 port keeps assembly in `port.c`; fiber follows that shape here. |
| `secure_context.*` | none | Excluded. Cortex-M7 has no ARMv8-M TrustZone context in this port. |
| `mpu_wrappers*` | none | Excluded. MPU task isolation is not part of the current cooperative fiber core. |

Naming convention:

```text
FreeRTOS portXXX item  -> fiber_portXXX item
generic fiber trait    -> FIBER_PORT_XXX
user/build option      -> FIBER_XXX
```

## `portmacro.h` Audit

| FreeRTOS item | Fiber item | Decision |
| --- | --- | --- |
| C++ `extern "C"` block | Same shape in `fiber_portmacro.h` | Adopted. |
| `portCHAR`, `portFLOAT`, `portDOUBLE`, `portLONG`, `portSHORT` | none | Excluded. Fiber uses C fixed-width/std types directly and does not expose FreeRTOS demo compatibility aliases. |
| `portSTACK_TYPE` / `StackType_t` | `uint32_t` stack words inside `FiberContext.sp` and frame builders | Adapted. No public FreeRTOS type alias is exported. |
| `portBASE_TYPE`, `BaseType_t`, `UBaseType_t` | `uint32_t`, `uintptr_t`, `size_t`, explicit bool-like `uint32_t` helpers | Adapted. No kernel-wide FreeRTOS base type exists. |
| `TickType_t`, `portMAX_DELAY`, `portTICK_TYPE_IS_ATOMIC` | user scheduler tick policy | Excluded from CPU port. Sleep/time is owned by the scheduler layer, not the context-switch core. |
| `portSTACK_GROWTH` | `fiber_portSTACK_GROWTH` | Reimplemented as `-1`. |
| `portTICK_PERIOD_MS` | user scheduler tick policy | Excluded. |
| `portBYTE_ALIGNMENT` | `fiber_portBYTE_ALIGNMENT` and `FIBER_STACK_ALIGN` | Reimplemented. Fiber validates stack alignment separately. |
| `portDONT_DISCARD` | shared `fiber_compiler.h` attribute helpers | Adapted. The selected port intentionally depends on the shared compiler ABI instead of duplicating toolchain attributes. |
| `portYIELD()` | `fiber_schedule()` plus `fiber_arm_cm7_r0p1_yield_request()` / `fiber_port_pend_switch()` | Adapted. Fiber rejects ISR/PRIMASK/BASEPRI/FAULTMASK delayed switches before pended PendSV. |
| `portNVIC_INT_CTRL_REG` | `fiber_portNVIC_INT_CTRL_REG` | Reimplemented. |
| `portNVIC_PENDSVSET_BIT` | `fiber_portNVIC_PENDSVSET_BIT` | Reimplemented. |
| `portEND_SWITCHING_ISR()` | none | Excluded. Current fiber core has no ISR fiber API. Future ISR wake APIs must be scheduler-level and audited separately. |
| `portYIELD_FROM_ISR()` | none | Excluded for the same reason. |
| `vPortEnterCritical()` / `vPortExitCritical()` declarations | none public | Excluded. Fiber does not provide a FreeRTOS critical nesting API. |
| `portSET_INTERRUPT_MASK_FROM_ISR()` | future scheduler/ISR policy | Excluded from current core. |
| `portCLEAR_INTERRUPT_MASK_FROM_ISR(x)` | future scheduler/ISR policy | Excluded from current core. |
| `portDISABLE_INTERRUPTS()` | `fiber_arm_cm7_r0p1_basepri_write(FIBER_PORT_SCHEDULER_BASEPRI)` and port-local asm snippets | Adapted internally. |
| `portENABLE_INTERRUPTS()` | `fiber_arm_cm7_r0p1_basepri_write(0)` and port-local asm snippets | Adapted internally. |
| `portENTER_CRITICAL()` / `portEXIT_CRITICAL()` | none public | Excluded. User scheduler may define its own critical policy above the fiber core. |
| `portTASK_FUNCTION_PROTO()` / `portTASK_FUNCTION()` | plain `void (*)(void *)` fiber entry | Adapted. No compatibility macro. |
| `portSUPPRESS_TICKS_AND_SLEEP()` | user scheduler/platform sleep policy | Excluded. |
| `configUSE_PORT_OPTIMISED_TASK_SELECTION` default | user scheduler | Excluded from core. Fiber does not impose priority scheduling. |
| `ucPortCountLeadingZeros()` | `fiber_arm_cm7_r0p1_count_leading_zeros()` | Reimplemented as an optional selected-port helper for user schedulers. |
| `portRECORD_READY_PRIORITY()` | user scheduler | Excluded. |
| `portRESET_READY_PRIORITY()` | user scheduler | Excluded. |
| `portGET_HIGHEST_PRIORITY()` | user scheduler, optional CLZ helper available | Excluded from core. |
| `portASSERT_IF_INTERRUPT_PRIORITY_INVALID()` | CM7 r0p1 selected-port priority setup and runtime readback validation | Adapted. The selected exception source validates implemented priority bits, grouping, SVC/PendSV priorities, vector routing, and the M7 revision gate. ISR-callable scheduler APIs remain intentionally excluded. |
| `portNOP()` | none | Excluded. |
| `portINLINE` / `portFORCE_INLINE` | `fiber_portFORCE_INLINE` | Reimplemented locally in `fiber_portmacro.h`; no CMSIS inline macro dependency. |
| `xPortIsInsideInterrupt()` | `fiber_arm_cm7_r0p1_is_inside_interrupt()` and direct `__get_IPSR()` guards | Reimplemented. |
| `vPortRaiseBASEPRI()` | `fiber_arm_cm7_r0p1_basepri_write(FIBER_PORT_SCHEDULER_BASEPRI)` | Adapted and hardened. The M7 r0p1 path preserves previous `PRIMASK` instead of unconditionally enabling interrupts. |
| `ulPortRaiseBASEPRI()` | `fiber_portASM_ENTER_SCHEDULER_CRITICAL` | Adapted. The PendSV path snapshots previous BASEPRI on the handler stack. |
| `vPortSetBASEPRI(value)` | `fiber_arm_cm7_r0p1_basepri_write(value)` and `fiber_portASM_WRITE_BASEPRI_R*_SYNC` | Adapted and hardened. |
| `portMEMORY_BARRIER()` | `fiber_portCOMPILER_BARRIER()` plus strict `DMB`/`DSB`/`ISB` policy | Adapted locally in `fiber_portmacro.h`; no CMSIS compiler-barrier dependency. |

## `port.c` Constant Audit

| FreeRTOS item | Fiber item | Decision |
| --- | --- | --- |
| `#ifndef __ARM_FP` hard error | `FIBER_HAS_FPU` / `FIBER_HAS_EXTENDED_FP_CONTEXT` | Changed. Fiber supports CM7 without forcing an FPU build; FP save/restore is gated by target traits. |
| `portISR_t` | direct function pointer use in vector validation | Adapted. |
| `portNVIC_SYSTICK_CTRL_REG`, `portNVIC_SYSTICK_LOAD_REG`, `portNVIC_SYSTICK_CURRENT_VALUE_REG`, and related SysTick constants | user scheduler/platform | Excluded. CPU context switch core does not own ticks. |
| `portNVIC_SHPR2_REG` / `portNVIC_SHPR3_REG` | `fiber_portNVIC_SHPR2_REG` / `fiber_portNVIC_SHPR3_REG` | Reimplemented as selected-port constants. Fiber validates and configures SVC/PendSV only; SysTick is not owned. |
| `portNVIC_SYSTICK_CLK_BIT`, `portNVIC_SYSTICK_INT_BIT`, `portNVIC_SYSTICK_ENABLE_BIT`, and count/pend bits | user scheduler/platform | Excluded. |
| `portNVIC_PENDSVCLEAR_BIT` | `fiber_portNVIC_PENDSVCLEAR_BIT` | Reimplemented and used by first-start cleanup. |
| `portNVIC_PEND_SYSTICK_SET_BIT` / clear bit | CM7 constants only | Reimplemented as reference constants; not used by core until a tick policy exists. |
| `portMIN_INTERRUPT_PRIORITY` | `fiber_portMIN_INTERRUPT_PRIORITY` | Reimplemented. |
| `portNVIC_PENDSV_PRI` / `portNVIC_SYSTICK_PRI` | `fiber_exception_runtime_check()` / `fiber_port_exception.c` setup | Adapted. Fiber owns PendSV/SVC priority policy, not SysTick. |
| `portSCB_VTOR_REG` | `fiber_portSCB_VTOR_REG` plus selected-port `fiber_port_vectors_*()` helpers | Adapted. Target-level `fiber_vtor.h` was removed. |
| `portVECTOR_INDEX_SVC` | `fiber_portVECTOR_INDEX_SVC` | Reimplemented. |
| `portVECTOR_INDEX_PENDSV` | `fiber_portVECTOR_INDEX_PENDSV` | Reimplemented. |
| `portFIRST_USER_INTERRUPT_NUMBER` | `fiber_portFIRST_USER_INTERRUPT_NUMBER` | Reimplemented. |
| `portNVIC_IP_REGISTERS_OFFSET_16` | `fiber_portNVIC_IP_REGISTERS_OFFSET_16` | Reimplemented. |
| `portAIRCR_REG` | `fiber_portAIRCR_REG` | Reimplemented. |
| `portMAX_8_BIT_VALUE` | `fiber_portMAX_8_BIT_VALUE` | Reimplemented. |
| `portTOP_BIT_OF_BYTE` | `fiber_portTOP_BIT_OF_BYTE` | Reimplemented. |
| `portMAX_PRIGROUP_BITS` | `fiber_portMAX_PRIGROUP_BITS` | Reimplemented. |
| `portPRIORITY_GROUP_MASK` | `fiber_portPRIORITY_GROUP_MASK` | Reimplemented. |
| `portPRIGROUP_SHIFT` | `fiber_portPRIGROUP_SHIFT` | Reimplemented. |
| `portVECTACTIVE_MASK` | `fiber_portVECTACTIVE_MASK` | Reimplemented as reference constant; fiber mostly uses IPSR directly. |
| `portFPCCR` | `fiber_portFPCCR` | Reimplemented as selected-port constant. |
| `portASPEN_AND_LSPEN_BITS` | `fiber_portASPEN_AND_LSPEN_BITS` plus `FIBER_FPU_LAZY` | Adapted. Fiber can run eager validation mode. |
| `portINITIAL_XPSR` | `fiber_portINITIAL_XPSR` | Reimplemented and used by the CM7 frame builder. |
| `portINITIAL_EXC_RETURN` | `fiber_portINITIAL_EXC_RETURN` / `FIBER_PORT_INITIAL_EXC_RETURN` | Reimplemented as fixed `0xFFFFFFFD`; the concrete CM7 frame ABI rejects incompatible overrides. |
| `portMAX_24_BIT_NUMBER` | none | Excluded. SysTick/tickless only. |
| `portSTART_ADDRESS_MASK` | `fiber_portSTART_ADDRESS_MASK` and `fiber_arm_cm7_r0p1_stacked_pc()` | Adapted. Stacked PC bit 0 is cleared. |
| `portMISSED_COUNTS_FACTOR` | none | Excluded. Tickless only. |
| `configSYSTICK_CLOCK_HZ` / `portNVIC_SYSTICK_CLK_BIT_CONFIG` | user scheduler/platform | Excluded. |
| `configTASK_RETURN_ADDRESS` / `portTASK_RETURN_ADDRESS` | `fiber_internal_task_return()` | Adapted. Fiber return is always a panic path. |

## `port.c` Function Audit

| FreeRTOS function/path | Fiber function/path | Decision |
| --- | --- | --- |
| `pxPortInitialiseStack()` | `fiber_port_init_context_frame()` | Adapted and hardened. Fiber validates/seals boot metadata, reserves exception headroom, clears stacked PC bit 0, stores a task-return panic LR, and preserves platform `r9`. |
| `prvTaskExitError()` | `fiber_internal_task_return()` | Replaced. A returned fiber panics; there is no task-delete API in the CPU port. |
| `vPortSVCHandler()` | `fiber_svc()` | Adapted and hardened. Fiber validates SVCall identity, exact incoming EXC_RETURN, MSP origin, 8-byte SVC frame alignment, stacked Thread/Thumb state, stacked PC, SVC opcode/immediate, current context, restore context, FPCA state, and BASEPRI clear through errata-safe macros. |
| `prvPortStartFirstTask()` | `fiber_port_start_first_context()` | Adapted and hardened. Fiber starts only via SVC, validates Thread/MSP state, optionally rewinds MSP through sealed boot policy, clears pending PendSV, enables faults/IRQs, and panics if SVC returns. |
| `xPortStartScheduler()` | `fiber_start()` plus port start helper and exception validation | Split. `fiber_start()` now owns idempotent PendSV/SVCall setup and validation, matching the FreeRTOS startup responsibility. Fiber has no tick setup, internal priority scheduler, or critical nesting setup; the user hook selects the first context. |
| `vPortEndScheduler()` | none | Excluded. A Cortex-M bare-metal fiber runtime does not implement scheduler shutdown. |
| `vPortEnterCritical()` / `vPortExitCritical()` | none public; internal scheduler critical helpers only | Excluded from public API. |
| `xPortPendSVHandler()` | `fiber_pendsv()` | Adapted and hardened. Save/restore order matches the FreeRTOS core pattern: PSP, optional high-FP save, `r4-r11` plus EXC_RETURN, scheduler call under BASEPRI, restore core frame, optional high-FP restore, PSP, exception return. Fiber additionally validates PendSV identity, exact live EXC_RETURN, source bounds, and the optional stacked alignment word before saving. |
| `vTaskSwitchContext()` call | `fiber_internal_scheduler_pick_next_from_pendsv()` | Replaced. User scheduler hook picks the next context; NULL and invalid contexts panic. |
| `pxCurrentTCB` first field | `fiber_internal_port_current_context` and `FiberContext.sp` | Adapted. Saved SP is updated only when saving the current context, matching the FreeRTOS invariant. |
| `xPortSysTickHandler()` | user scheduler/platform | Excluded. No preemptive tick in core. |
| `vPortSuppressTicksAndSleep()` | user scheduler/platform | Excluded. |
| `vPortSetupTimerInterrupt()` | user scheduler/platform | Excluded. |
| `vPortEnableVFP()` | `fiber_port_fpu_enable_early()` | Adapted and hardened. This port owns FPU detection, the local `FIBER_ENABLE_CPACR` default, CPACR/FPCCR setup, lazy/eager policy, barriers, and enforced CPACR/FPCCR readback checks. |
| `vPortValidateInterruptPriority()` | selected-port constants and `fiber_port_exception.c` validation | Adapted. Startup probing verifies the implemented priority mask against `__NVIC_PRIO_BITS`, confirms priority-register restoration, validates BASEPRI bits and PRIGROUP compatibility, and leaves future ISR-safe API priority checks outside the current API scope. |
| `WORKAROUND_PMU_CM001` | none | Excluded. This is XMC4000-specific, not STM32 Cortex-M7. |

Like the reference port, an implementation with eight NVIC priority bits
requires scheduler BASEPRI bit 0 to remain clear because that bit is
necessarily subpriority. The fiber default is `2` for that case, and both
compile-time and startup checks enforce the rule.

## Paranoid Differences

Fiber intentionally differs from FreeRTOS in these places:

```text
FreeRTOS: internal scheduler owns all tasks.
Fiber: user scheduler hook owns task selection, so every returned context is
       validated before restore. The just-saved current context is validated
       before the user hook runs as well.

FreeRTOS: r0p1 BASEPRI workaround disables IRQs and then enables them.
Fiber: r0p1 BASEPRI write preserves and restores the previous PRIMASK, so an
       existing critical section is not accidentally opened.

FreeRTOS: first task is selected by pxCurrentTCB before SVC.
Fiber: first context is selected by pick_next(NULL, user), then validated and
       seeded before SVC.

FreeRTOS: SysTick and priority scheduling are part of the kernel.
Fiber: tick, sleep, wake, and ready-list policy are outside the CPU port.

FreeRTOS: lazy FP is the normal CM7 path.
Fiber: lazy FP can be enabled, but conservative validation uses eager FP
       behavior for deterministic bring-up.

FreeRTOS: handler/vector/priority assertions depend on configASSERT options.
Fiber: the production CM7 port always performs startup vector, priority-mask,
       PRIGROUP, CPUID, SVC-priority, and errata-policy validation.

FreeRTOS: kernel scheduler code is built as part of the controlled port/kernel.
Fiber: an indirect user scheduler hook crosses the PendSV ABI, so its definition
       must use FIBER_SCHEDULER_HOOK_ATTR and must not execute FP/MVE code.
```

## Current Status

Done:

```text
FreeRTOS-referenced ARM_CM7/r0p1 directory exists
selected fiber_portmacro.h defines CM7/r0p1 CPU traits and helper constants
selected fiber_port.c owns native first-start and PendSV implementation text
selected files do not include fiber_target.h or fiber_settings.h
selected fiber_portmacro.h includes port/fiber_compiler.h only for compiler ABI
BASEPRI/FPU/frame/default policy is duplicated in this selected port instead
of inheriting target-wide helper policy
build-selected matrix uses this include directory and source files for M7/M7F
M7 r0p1 errata gate is forced for selected CM7/r0p1 builds
matrix relocatably links every mode and requires exactly one mandatory port ABI
symbol definition
parity record documents adopted/adapted/replaced/excluded port mechanisms
```

Required before claiming this directory as the production H7 runtime path:

```text
run H7 normal and trap validation through this selected source group
validate on affected Cortex-M7 r0p0/r0p1 hardware before claiming errata parity
```
