# ARM_CM4_MPU FreeRTOS Parity Record

## Status

Implementation slices 1-4 are complete for the exact `ARM_CM4_MPU` profile.
They freeze the public type layout, MPU geometry, protected basic/FP context
views, traits, and exact cohort identity, then add port-owned context
construction, exact linker ranges, default MPU-image encoding, and immutable
sealing. Slice 3 adds a strong SVC handler, protected first-context start,
port-owned CPACR/FPCCR preparation, exact MPU activation/readback, and fixed
unprivileged yield/return services. Slice 4 adds strong protected PendSV,
basic/extended FP save and restore, scheduler selection under BASEPRI, and
per-context MPU replacement under PRIMASK. The profile deliberately contains
no complete forward ABI implementation, selector route, or hardware support
claim.

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

## Exact Slice-4 Manifest

```text
architecture        ARMv7E-M
core                Cortex-M4F or Cortex-M7F
compiler ABI        GCC-compatible Thumb with FP registers enabled
MPU                 present; total regions explicitly 8 or 16
VTOR                present
FPU                 present and used
selection           build-selected construction/runtime compile/link proof only
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
creates the hardware frame there; privileged PendSV copies it into
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

## Construction Policy

The portable call remains unchanged:

```c
fiber_init(&context, stack_begin, stack_end, entry, arg);
```

The selected constructor interprets that range as one exact MPU stack region.
It requires a power-of-two extent, alignment to that extent, containment in the
linker-owned unprivileged RAM range, no overlap with privileged context data,
RW access, and execute-never policy. It never rounds outward and never exposes
adjacent memory. Every configurable region starts disabled; only the dedicated
stack region differs per context until a later optional MPU API exists.

The initial protected image uses the basic 19-word FreeRTOS layout with a
one-past cursor at word 19. CONTROL starts unprivileged with PSP selected, r9 is
copied from the live platform/static base, EXC_RETURN selects a basic Thread/PSP
return, and the copied hardware frame contains argument, port-owned return
veneer, entry PC, and Thumb xPSR. All remaining protected words are zeroed.

The boot seal covers every immutable ABI field plus all per-context RBAR/RASR
pairs. The protected register image, cursor, and runtime flags remain mutable.
Four linker-derived global images cover the read-only current-context slot,
unprivileged code, privileged code, and privileged data. Slice 2 constructs and
validates these images. Slice 3 writes and reads back the complete selected
image during protected first start. Slice 4 replaces the per-context portion
during PendSV with PRIMASK closed, then reads back every per-context and global
region before restore.

Compile/link proofs cover M4F/M7F with both 8 and 16 regions and compile the
runtime under both eager and lazy FP policy. They verify exact cohort
separation, privileged placement, the complete undefined linker-boundary
surface, successful synthetic placement, failure for every missing boundary,
strong slot-11 SVC and slot-14 PendSV ownership, exact three-service generated
code, privileged and unprivileged section placement, six exact protected FP
transfers, load-only current-slot access, exact reverse dependency surface,
M7 PRIMASK-preserving BASEPRI writes, duplicate-handler failures, and continued
absence of global selector routing.

## Protected SVC And First Start

The port owns fixed services `70`, `71`, and `72` for first start,
unprivileged yield, and unprivileged task return. They are fiber ABI values,
not copies of FreeRTOS services `100..103`. `SVC_Handler` accepts only exact
Thread/MSP first start or Thread/PSP basic/extended runtime provenance. The C
dispatcher validates zero masks, exact frame shape, SVC opcode and immediate,
continuation symbol, current context, linker ranges, and active MPU readback.
Unknown services and cross-routed continuation sites fail closed.

For an extended FP exception, PSP still points at the basic core frame; the
low FP extension follows it at higher addresses. The handler therefore never
adds 72 bytes before decoding stacked PC/xPSR. This is frozen by generated-code
proof and matches the pinned FreeRTOS CM4 MPU save path, which adds `0x20` only
when copying `s0-s16` after the basic frame.

First start clears pre-start FPCA, rewinds MSP from the active vector table,
clears stale PendSV, enters SVC, installs every per-context and global MPU
region, enables MemManage and `MPU_CTRL.ENABLE|PRIVDEFENA`, and reads every
region back. It then copies the protected basic hardware frame to PSP and
restores CONTROL, r4-r11, and EXC_RETURN. CPACR and FPCCR are prepared with
readback before the transfer. Cortex-M7 uses a PRIMASK-preserving synchronized
BASEPRI clear instead of FreeRTOS's unconditional IRQ re-enable workaround.

The unprivileged schedule veneer contains only SVC 71 and return; the task
return veneer contains only SVC 72 and a terminal loop. SVC 71 pends the
port-owned PendSV, but this profile remains non-selectable until the complete
forward runtime ABI and build-selection slice exists.

## Protected PendSV

PendSV accepts only Thread/PSP basic or extended EXC_RETURN, an exact live PSP,
zero incoming masks, matching CONTROL/FPCA state, an enabled and read-back MPU
image, and the configured CPACR/FPCCR policy. The current context seal, cursor,
stack extent, hardware frame, code address, and canary are validated before the
handler reads mutable context fields.

The save path starts at protected word zero. For an extended frame it first
saves `s16-s31`, then copies the 17 raw `s0-s15/FPSCR` words from `PSP + 32`;
it stores CONTROL, `r4-r11`, EXC_RETURN, PSP, and the copied basic hardware
frame after them. A basic frame skips the FP transfers and ends at cursor word
19; an extended frame ends at cursor word 52. `FPCCR.LSPACT` must be clear after
the VFP copy, so an incomplete lazy save cannot be published to the scheduler.

The scheduler bridge runs in privileged PendSV under the exact BASEPRI
threshold and snapshots PRIMASK, BASEPRI, FAULTMASK, CONTROL, IPSR, PSP, VTOR,
MPU state, CPACR, and FPCCR around the external hook. The returned context is
fully validated before common publishes it. PendSV then closes PRIMASK,
disables the MPU, replaces every per-context RBAR/RASR pair, reenables and
reads back the complete MPU image, clears BASEPRI with the M7 errata-safe path,
and restores the selected basic or extended image. No software frame is ever
written below the user PSP.

## `portmacro.h` Ledger

| FreeRTOS family | Fiber slice-4 mapping | Decision |
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
| SVC 100..103 | fixed fiber services 70/71/72 | Adapted: first start, yield, and task return are exact port-owned services; FreeRTOS privilege/syscall services remain excluded. |
| yield/from-ISR macros | unprivileged SVC yield plus future ISR boundary | Thread-mode yield implemented; ISR-safe API remains deferred. |
| critical-section macros | selected-port scheduler envelope | BASEPRI handler envelope implemented; FreeRTOS public critical API excluded. |
| optimized priority bitmap | C++ scheduler policy | Excluded from CPU port. |
| interrupt-priority assertion | future ISR API validation | Deferred until an ISR-safe API exists. |
| privilege query/reset/switch macros | future optional MPU ABI | Deferred. |
| memory barrier | mandatory runtime ABI implementation | Deferred to runtime slice. |

## `port.c` Function Ledger

| FreeRTOS path | Fiber owner | Slice-4 decision |
| --- | --- | --- |
| `pxPortInitialiseStack` | selected-port context constructor | Implemented for the unprivileged basic initial image; r9 is preserved and all unused protected words are zeroed. |
| `prvRestoreContextOfFirstTask` | selected-port first-context restore | Implemented for the validated basic initial image, with second MSP rewind and exact MPU readback. |
| `vPortSVCHandler`, `vSVCHandler_C` | strong selected-port SVC handler/dispatcher | Implemented with stricter origin, frame, opcode, immediate, continuation, context, and mask checks. |
| `xPortPendSVHandler` | strong selected-port PendSV handler | Implemented with protected basic/extended FP copy, exact cursor geometry, BASEPRI scheduler call, PRIMASK-closed MPU replacement, and restore. |
| `vTaskSwitchContext` | common scheduler callback bridge | Replaced by the frozen reverse scheduler ABI with CPU-state preservation and restore-before-publication validation. |
| `prvSetupMPU` | selected-port global MPU startup | Exact global images, TYPE check, complete first programming, MemManage enable, CTRL enable, switch-time per-context replacement, and per-region readback implemented. |
| `prvGetMPURegionSizeSetting` | selected-port MPU encoder | Replaced by stricter exact encoder that rejects rounding, overflow, bad alignment, region number, and access policy. |
| `vPortStoreTaskMPUSettings` | base constructor plus optional MPU API | Safe default implemented: configurable regions disabled and exact stack enabled; user configuration/access metadata remains optional. |
| `xIsPrivileged`, `vResetPrivilege`, `vPortSwitchToUserMode`, `xPortIsTaskPrivileged` | optional MPU API and validated SVC paths | Deferred; no public stubs. |
| VFP enable and FPCCR setup | selected-port startup | CPACR and ASPEN/LSPEN policy preparation with mandatory readback implemented. |
| `xPortStartScheduler` | common start plus selected-port operations | SVC transfer, FPCA clear, MSP rewind, and stale-PendSV clear implemented; FreeRTOS scheduler/tick state excluded. |
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

1. Completed: port-owned boot construction, linker ranges, exact MPU encoding,
   sealing, and the initial basic protected image.
2. Completed: strong SVC first-start, MPU/FPU preparation and readback, and
   controlled unprivileged yield/return services.
3. Completed: strong PendSV protected save/copy/scheduler/MPU/restore path,
   including the dynamic extended FP image.
4. Frozen eight-function runtime ABI integration, archive/cohort/ELF proofs,
   and exact build selection.
5. M4F and M7F hardware validation for 8-region devices; 16-region hardware
   remains a separate claim.
6. Optional MPU configuration/syscall wrapper ABI only if required.

No later slice may infer privilege policy merely from `__MPU_PRESENT`, reuse a
privileged CM4/CM7 context, or activate selection before the complete runtime
and link proof exists.
