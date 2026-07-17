# ARM_CM4_MPU FreeRTOS Parity Record

## Status

This is implementation slice 1 for the exact `ARM_CM4_MPU` profile. It freezes
the public type layout, MPU geometry, protected basic/FP context views, port
traits, and exact cohort identity. It deliberately contains no runtime source,
SVC/PendSV handler, forward ABI implementation, selector route, or hardware
support claim.

The directory name follows the pinned FreeRTOS GCC port. That reference accepts
both Cortex-M4F and Cortex-M7F. Fiber therefore freezes both manifests while
giving them different port identities and always enabling the conservative
M7 r0p1 BASEPRI-workaround policy for the M7 cohort.

## Frozen Reference

The local FreeRTOS Kernel reference is commit:

```text
a50edad08b29052631aa469d4df6e6ec7ff68878
```

| File | Lines | SHA-256 |
| --- | ---: | --- |
| `portable/GCC/ARM_CM4_MPU/portmacro.h` | 502 | `fa624bd1cafad461c86d1858e5aa9328edefe71d0e19a328746f85a52e7c35ad` |
| `portable/GCC/ARM_CM4_MPU/port.c` | 1738 | `cc9b731bc23e52a91d7d37b5dda16d7b501cfb4d3b3a3c8229c355c66662bf59` |
| `portable/GCC/ARM_CM4_MPU/mpu_wrappers_v2_asm.c` | 2067 | `6b5110e0c14ba78c20d43c1edf17e5ac2311a6af0413d6aaab5df59edb2655c2` |

## Exact Slice-1 Manifest

```text
architecture        ARMv7E-M
core                Cortex-M4F or Cortex-M7F
compiler ABI        GCC-compatible Thumb with FP registers enabled
MPU                 present; total regions explicitly 8 or 16
VTOR                present
FPU                 present and used
selection           build-selected header compile only
runtime selectable  no
```

`FIBER_PORT_CM4_MPU_TOTAL_REGIONS` is mandatory and must be exactly `8` or
`16`. FreeRTOS defaults this setting to eight for backward compatibility;
fiber fails closed because the value changes `FiberContext` storage and exact
cohort identity.

## Protected Context Layout

The protected context mirrors FreeRTOS `MAX_CONTEXT_SIZE == 53`:

```text
extended active view:
  words  0..15  s16-s31
  words 16..32  s0-s15 and FPSCR
  words 33..42  CONTROL, r4-r11, EXC_RETURN
  words 43..51  PSP and copied r0-r3/r12/LR/PC/xPSR
  word      52  one-past cursor target

initial/basic view:
  words  0.. 9  CONTROL, r4-r11, EXC_RETURN
  words 10..18  PSP and copied basic hardware frame
  word      19  one-past cursor target
  words 20..52  reserved protected storage
```

The software frame is not placed on the unprivileged stack. Exception entry
creates the hardware frame there; the future privileged handler copies it into
`FiberContext` before switching MPU regions, as the reference port does.

Per-context MPU register storage follows the reference formula:

```text
total regions              8 or 16
configurable regions       total - 5
stack region               total - 5
RBAR/RASR pairs in context total - 4
global regions             final four regions
```

Fiber reserves the first global region for an exact current-context aperture
instead of FreeRTOS's broad general-peripherals mapping. The following three
global regions remain unprivileged code, privileged code, and privileged data.

| Total MPU regions | RBAR/RASR pairs | Protected image offset | Boot offset | Context size |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 4 | 36 | 252 | 344 |
| 16 | 12 | 100 | 316 | 408 |

Both layouts are 8-byte aligned. The boot record is 88 bytes and seals total
regions, per-context regions, protected word count, initial CONTROL, and every
ordinary context ABI field. Mutable task flags remain outside the seal and
reserve the reference padding and privilege bits.

## Exact Identity

```text
Cortex-M4F port ID  0x434D344D (CM4M)
Cortex-M7F port ID  0x434D374D (CM7M)
8-region layout     0x00010008
16-region layout    0x00010010
feature mask        0x00001C05
```

The feature mask records extended FP, CONTROL, MPU image, protected hardware
frame, and unprivileged execution. M4 and M7, 8 and 16 regions, NVIC priority
width, BASEPRI threshold, and M7 errata policy all participate in the exact
cohort symbol.

## `portmacro.h` Ledger

| FreeRTOS family | Fiber slice-1 mapping | Decision |
| --- | --- | --- |
| scalar/task typedefs | public fiber API types | Kernel-specific typedefs excluded. |
| `portUSING_MPU_WRAPPERS`, privilege bit | future optional MPU API | Deferred; no false wrapper support claim. |
| MPU permission/TEX/S/C/B encodings | `fiber_portMPU_*` constants | Retained. |
| `configTOTAL_MPU_REGIONS` | `FIBER_PORT_CM4_MPU_TOTAL_REGIONS` | Adapted to mandatory exact 8/16 manifest. |
| region number formulas | `fiber_portMPU_*_REGION` | Retained; general-peripheral region becomes current-context aperture. |
| `xMPU_REGION_REGISTERS` | `FiberPortMpuRegionRegisters` | Renamed, same RBAR/RASR pair. |
| `xMPU_REGION_SETTINGS` | future optional MPU metadata | Deferred with syscall/access validation. |
| system-call stack and ACL | future optional MPU ABI | Deferred; absent from mandatory base context. |
| `MAX_CONTEXT_SIZE` | 53-word protected union | Retained exactly. |
| task padding/privilege flags | `runtime_flags` bits | Retained as mutable port state. |
| stack growth/alignment | port traits | Retained. |
| SVC 100..103 | future port-owned SVC namespace | Deferred; numbers are not copied before dispatcher design. |
| yield/from-ISR macros | C++ scheduler/ISR boundary | Deferred outside slice 1. |
| critical-section macros | future selected-port scheduler envelope | Deferred to runtime slice. |
| optimized priority bitmap | C++ scheduler policy | Excluded from CPU port. |
| interrupt-priority assertion | future ISR API validation | Deferred until an ISR-safe API exists. |
| privilege query/reset/switch macros | future optional MPU ABI | Deferred. |
| memory barrier | mandatory runtime ABI implementation | Deferred to runtime slice. |

## `port.c` Function Ledger

| FreeRTOS path | Planned fiber owner | Slice-1 decision |
| --- | --- | --- |
| `pxPortInitialiseStack` | selected-port context constructor | Layout frozen; code deferred. |
| `prvRestoreContextOfFirstTask` | selected-port first-context restore | Deferred. |
| `vPortSVCHandler`, `vSVCHandler_C` | strong selected-port SVC handler/dispatcher | Deferred. |
| `xPortPendSVHandler` | strong selected-port PendSV handler | Protected geometry frozen; code deferred. |
| `vTaskSwitchContext` | common scheduler callback bridge | Replaced, as in existing ports. |
| `prvSetupMPU` | selected-port global MPU startup | Deferred with exact type/readback checks. |
| `prvGetMPURegionSizeSetting` | selected-port MPU encoder | Deferred with overflow/alignment validation. |
| `vPortStoreTaskMPUSettings` | base constructor plus optional MPU API | Register image is base; user configuration/access metadata is optional. |
| `xIsPrivileged`, `vResetPrivilege`, `vPortSwitchToUserMode`, `xPortIsTaskPrivileged` | optional MPU API and validated SVC paths | Deferred; no public stubs. |
| VFP enable and FPCCR setup | selected-port startup | Deferred with mandatory readback. |
| `xPortStartScheduler` | common start plus selected-port operations | Internal FreeRTOS scheduler/tick state excluded. |
| `vPortEndScheduler` | none | Excluded for bare-metal one-shot start. |
| `vPortEnterCritical`, `vPortExitCritical` | C++ kernel or selected-port envelope | FreeRTOS public kernel API excluded. |
| `xPortSysTickHandler`, `vPortSetupTimerInterrupt` | C++ scheduler/platform | Excluded from CPU port. |
| interrupt-priority validation | future ISR-safe boundary | Deferred. |

## `mpu_wrappers_v2_asm.c` Ledger

The complete reference file was reviewed and is not silently discarded. Its
system-call entry/exit wrappers, per-task syscall stack, authorization checks,
ACL integration, and generated wrapper table are a higher optional MPU feature
ABI. They are not required for basic unprivileged context switching and must
not enlarge the frozen eight-function runtime ABI.

A later wrapper slice must carry its own parity ledger, context-layout/version
change where storage is added, linker sections, negative privilege tests, and
hardware MemManage/SVC evidence. Until then no public header or stub claims
that wrapper-v2 services exist.

## Required Later Slices

1. Port-owned boot construction, linker ranges, MPU encoding, sealing, and
   initial basic/extended protected images.
2. Strong SVC first-start and controlled unprivileged yield/return services.
3. Strong PendSV protected save/copy/scheduler/MPU/restore path.
4. Frozen eight-function runtime ABI integration, archive/cohort/ELF proofs,
   and exact build selection.
5. M4F and M7F hardware validation for 8-region devices; 16-region hardware
   remains a separate claim.
6. Optional MPU configuration/syscall wrapper ABI only if required.

No later slice may infer privilege policy merely from `__MPU_PRESENT`, reuse a
privileged CM4/CM7 context, or activate selection before the complete runtime
and link proof exists.
