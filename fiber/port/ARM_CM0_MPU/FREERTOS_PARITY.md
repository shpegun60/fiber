# ARM_CM0_MPU FreeRTOS Parity Record

## Status

This is implementation slice 1 for the exact `ARM_CM0_MPU` profile. It freezes
the public type layout, protected restore image, ARMv6-M MPU dictionary, port
traits, and exact cohort identity. It deliberately contains no runtime source,
SVC/PendSV handler, forward ABI implementation, selector route, linker
contract, public MPU extension ABI, or hardware support claim.

The pinned FreeRTOS `GCC/ARM_CM0` directory contains both a privileged branch
and an optional MPU/unprivileged branch. `fiber/port/ARM_CM0` remains the
privileged port. This new directory is a distinct, build-selected Cortex-M0+
MPU profile; it must not be inferred from `__MPU_PRESENT` by the global
architecture selector.

## Frozen Reference

The local FreeRTOS Kernel reference is commit:

```text
a50edad08b29052631aa469d4df6e6ec7ff68878
```

| File | Lines | SHA-256 |
| --- | ---: | --- |
| `portable/GCC/ARM_CM0/portmacro.h` | 334 | `80593eeb9e1a6f89a913e9aae19427b820b4090d7ba8ce81a265b5e823986b42` |
| `portable/GCC/ARM_CM0/port.c` | 1366 | `44a9d18193bf606bb8b6cc2b3341c207981c473d666a0c7075038e4fc18e1df9` |
| `portable/GCC/ARM_CM0/portasm.h` | 86 | `403910894bd2a6f588afa3998584ae27d3336f6a7ae0f32fce20dd2d0ff9b5c9` |
| `portable/GCC/ARM_CM0/portasm.c` | 491 | `1696254d07ebe24cd635067b0449e8c156e948967d07ca2b0e09b0d577c55395` |
| `portable/GCC/ARM_CM0/mpu_wrappers_v2_asm.c` | 1976 | `d93213034e67fbf076d8025007ca9b7bc31df8642256df44659e37f8d7df0a3e` |

## Exact Slice-1 Manifest

```text
architecture        ARMv6-M
core                Cortex-M0+ with an eight-region MPU
compiler ABI        GCC-compatible Thumb, soft-float
MPU                 CMSIS __MPU_PRESENT == 1
VTOR                CMSIS __VTOR_PRESENT == 0 or 1; separate cohorts
FPU                 absent and unused
selection           exact build-selected include path and type-only compile
runtime selectable  no
```

The profile fails closed unless `__CORTEX_M == 0`, `__ARM_ARCH_6M__`,
`__MPU_PRESENT == 1`, `__FPU_PRESENT == 0`, `__FPU_USED == 0`, and a valid
CMSIS NVIC priority width are present. `__VTOR_PRESENT` is intentionally a
selected-build fact rather than a global assumption: the later runtime must
validate either the applicable VTOR source or the architecture/platform vector
base and remap policy.

## Protected Context Layout

The `FiberPortProtectedContext` raw order is exactly the reference
`xMPU_SETTINGS.ulContext[20]` order:

```text
words  0.. 7  r4-r11
words  8..15  r0-r3, r12, LR, PC, xPSR
word      16  PSP for the copied basic hardware frame
word      17  CONTROL
word      18  EXC_RETURN
word      19  one-past save/restore cursor target
```

The protected image is privileged `FiberContext` storage. It is not a software
frame written to an unprivileged stack. Future PendSV must copy the basic
hardware frame into this image before replacing MPU regions, then rebuild that
hardware frame on the selected fiber's PSP before exception return, matching
the underlying FreeRTOS ARM_CM0 MPU mechanism.

`FiberContext` has this frozen 32-bit GCC layout:

```text
offset   0  protected_context_cursor
offset   4  four RBAR/RASR pairs (32 bytes)
offset  36  20-word protected image (80 bytes)
offset 116  mutable runtime_flags
offset 120  immutable FiberPortBoot (88 bytes)
size   208  bytes, aligned to 8
```

The prefix deliberately stays structurally close to FreeRTOS task MPU state:
its first word is the saved cursor, followed by MPU register pairs, protected
register image, and mutable flags. Fiber-specific sealed metadata follows those
mutable fields. Every field, offset, type size, region-image size, and alignment
has a static assertion in `fiber_portmacro.h`.

## MPU Geometry And Deliberate Difference

FreeRTOS stores five per-task pairs:

```text
regions 0..3  configurable task regions
region      4  task stack
regions 5..7  unprivileged flash, privileged flash, privileged RAM
```

Fiber needs `fiber_current()` to remain a safe portable call from an
unprivileged fiber. It therefore replaces FreeRTOS's broad unprivileged
general-peripherals region with an exact 32-byte unprivileged-read-only/XN
current-context aperture:

```text
regions 0..2  configurable task regions
region      3  task stack
region      4  current-context aperture, read-only and XN for unprivileged code
region      5  unprivileged executable code
region      6  privileged executable code
region      7  privileged writable data, XN for unprivileged code
```

Consequently, the Fiber context contains four RBAR/RASR pairs rather than the
five pairs in the FreeRTOS `xMPU_SETTINGS` layout. This is an intentional
security adaptation, not an accidental omission. The later optional MPU API
will have three configurable regions; it must not silently claim FreeRTOS's
four-region capacity or grant blanket peripheral access.

The ARMv6-M MPU dictionary preserves the pinned reference encodings:

```text
MPU TYPE                 0x00000800, eight unified regions
MPU CTRL                 ENABLE | PRIVDEFENA == 0x00000005
minimum region size      256 bytes
RBAR address mask        0xFFFFFF00
RBAR VALID bit           0x00000010
RASR size mask           0x0000003E
permissions and memory   exact renamed reference values
```

All encoder and linker-boundary code remains absent until a later slice can
validate overflow, power-of-two size, exact base alignment, widened coverage,
overlap, execute-never policy, and privileged-boundary isolation.

## Exact Identity

```text
port ID           0x434D304D (CM0M)
layout version    0x00010001
feature mask      0x00001C04
```

The feature mask records CONTROL, MPU image, protected hardware frame, and
unprivileged execution. The exact cohort symbol also distinguishes VTOR
presence, PRIMASK scheduling, stack alignment, FPU policy, and all other
selected port traits. The profile never reuses the privileged `ARM_CM0`
identity `0x434D3030`.

## `portmacro.h` Ledger

| FreeRTOS family | Fiber slice-1 mapping | Decision |
| --- | --- | --- |
| scalar/task typedefs and stack growth/alignment | `fiber_api_types.h`, selected `FiberContext`, ARMv6-M traits | Adapted; FreeRTOS API typedefs are not exported. |
| tick type, delay, ready bitmap, scheduler/list macros | user scheduler and later C++ Kernel | Excluded from CPU port. |
| `configENABLE_MPU`, `portUSING_MPU_WRAPPERS`, privilege bit | exact selected MPU profile identity | Adapted; no compatibility wrappers or no-op feature API. |
| MPU region numbers | `fiber_portMPU_*_REGION` constants | Adapted as documented above: current-context aperture replaces broad peripherals. |
| MPU region-size encodings | renamed `fiber_portMPU_REGION_SIZE_*` constants | Retained exactly; no encoder implementation yet. |
| S/C/B memory type and AP/XN encodings | renamed `fiber_portMPU_REGION_*` constants | Retained exactly; later policy validates every use. |
| `MPURegionSettings_t` and task-region descriptors | future optional MPU integration ABI | Deferred; no public header or stub exists. |
| `xMPU_SETTINGS` | selected `FiberContext` prefix plus `FiberPortBoot` | Adapted. Raw 20-word restore order is exact; FreeRTOS authorization metadata is not imported. |
| `CONTEXT_SIZE == 20` | `FiberPortProtectedContext` | Retained exactly. |
| task padding/privilege flags | `runtime_flags` bits | Retained as mutable selected-port state; not a public FreeRTOS flag API. |
| SVC services 100..103 | future native selected-port SVC namespace | Deferred. Fiber must not copy an unrelated FreeRTOS number space before its dispatcher/provenance design exists. |
| `portYIELD`, ISR-yield, critical nesting macros | future selected-port runtime and C++ scheduler boundary | Deferred; no runtime path exists in slice 1. |
| `portMAX_DELAY`, tickless, timer configuration | user scheduler/platform | Excluded. |
| privilege query/raise/reset macros | future optional MPU ABI and checked SVC routes | Deferred; no public stubs. |

## `port.c` And `portasm.c` Ledger

| FreeRTOS path | Planned Fiber owner | Slice-1 decision |
| --- | --- | --- |
| MPU `pxPortInitialiseStack` | selected port context constructor | Raw layout, CONTROL values, EXC_RETURN, and cursor are frozen; code deferred. |
| `vRestoreContextOfFirstTask` / `vStartFirstTask` | strong selected-port SVC first-start path | Deferred. Startup must preserve ARMv6-M VTOR/no-VTOR behavior and validate provenance. |
| `SVC_Handler` / `vPortSVCHandler_C` | strong selected-port SVC dispatcher | Deferred. First start, unprivileged yield, and return require an explicit native service contract. |
| MPU `PendSV_Handler` | strong selected-port protected switch path | Deferred. It will copy the full basic hardware frame into privileged storage and program the exact MPU image. |
| `ulSetInterruptMask` / `vClearInterruptMask` | selected PRIMASK scheduler envelope | Deferred to runtime; BASEPRI and FAULTMASK are prohibited by traits. |
| `prvGetMPURegionSizeSetting` | selected MPU encoder | Deferred with stricter overflow/alignment/coverage checks. |
| `prvSetupMPU` | selected pre-start MPU setup/readback | Deferred with exact linker boundaries and mandatory type/control readback. |
| `vPortStoreTaskMPUSettings` | base stack image plus optional MPU API | Deferred. Default stack region and optional heterogeneous regions must remain separately versioned. |
| `xPortStartScheduler` | common start plus selected operations | Deferred; FreeRTOS scheduler/tick mechanics are excluded. |
| `vPortEndScheduler`, SysTick handler/setup, tickless | none / user scheduler | Excluded. |
| `xIsPrivileged`, raise/reset privilege | optional MPU ABI and SVC paths | Deferred. |

## `mpu_wrappers_v2_asm.c` Ledger

The complete reference wrapper file was reviewed. Its system-call entry/exit
wrappers, per-task syscall stack, generated wrapper table, kernel-object ACL,
buffer authorization, and task lifecycle are not silently discarded. They are a
future optional MPU feature family and do not belong to the mandatory eight
function CPU runtime ABI.

If such functionality is required later, it must add a separate selected-port
extension header/source, the optional common context-configuration lifecycle
ABI when it mutates context policy, a new exact layout/cohort version if it adds
storage, a dedicated parity ledger, negative privilege tests, and hardware
MemManage/SVC evidence. Until then no file claims wrapper-v2 support.

## Required Later Slices

1. Add port-owned context construction, immutable seal/hash, exact MPU region
   encoding, linker ranges, and a safe default stack/current-context policy.
2. Add strong SVC first start plus controlled unprivileged yield and return
   services with complete opcode/origin/provenance validation.
3. Add strong Thumb-1 PendSV protected save/copy/scheduler/MPU/restore logic.
4. Add all eight forward runtime ABI adapters, archive/cohort/vector/ELF/LTO
   proofs, and only then allow this exact build-selected source group to link.
5. Add the optional pre-start MPU configuration ABI only if heterogeneous
   per-fiber policy is required.
6. Run matching Cortex-M0+ MPU hardware tests before any STM32 support claim.

No later slice may reuse privileged `ARM_CM0` saved-frame assembly, restore a
protected context from unprivileged memory, reintroduce a broad general
peripherals region, infer selection from `__MPU_PRESENT`, or activate this
profile before the complete runtime and link proof exists.
