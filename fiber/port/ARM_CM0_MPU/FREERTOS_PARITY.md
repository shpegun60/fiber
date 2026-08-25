# ARM_CM0_MPU FreeRTOS Parity Record

## Status

Slices 1-5 for the exact `ARM_CM0_MPU` profile freeze the public type layout,
protected restore image, ARMv6-M MPU dictionary, port traits, exact cohort,
construction/seal/strict MPU-region encoder, linker-isolation contract, and
the in-memory global MPU image. Slice 5 adds strong direct SVC/PendSV handlers,
the private unprivileged yield SVC route, protected save/copy/select/MPU-
replace/restore mechanics, exact vector/priority setup, and full MPU readback.

The profile deliberately contains no forward runtime ABI implementation,
selector route, public MPU extension ABI, or hardware support claim. It remains
explicitly non-selectable while its private protected execution mechanics are
paired against FreeRTOS. Forward-ABI/archive activation and board isolation are
separate proof slices.

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
  slice 5             construction/seal/exact stack-region image, exact linker
                      contract, SVC first start/yield/task return, protected
                      PendSV switch, MPU replacement/readback, and Thumb-1
                      first/ordinary restore
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
frame written to an unprivileged stack. PendSV copies the basic hardware frame
into this image before replacing MPU regions, then rebuilds that frame on the
selected fiber's PSP before exception return, matching the underlying FreeRTOS
ARM_CM0 MPU mechanism.

The shared `FIBER_PORT_SOFTWARE_FRAME_*` traits intentionally describe the
19-word logical protected transfer for ABI identity. They are not raw PSP
geometry for this profile. Slices 2-5 therefore do not include the generic
stack-resident `fiber_port_geometry.h`; the selected port uses explicit facts
instead:

```text
initial PSP reservation     32 bytes (one basic frame)
maximum physical PSP frame  36 bytes (basic frame plus alignment word)
minimum admitted usable stack, aligned to 8 bytes  40 bytes
```

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
general-peripherals region with one exact 256-byte unprivileged-read-only/XN
current-context aperture. ARMv6-M does not support the 32-byte minimum used by
the ARMv7-M MPU ports, so using a smaller aperture here would be invalid:

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

Slices 2-3 implement a strict exact-region encoder. It accepts only non-empty,
power-of-two ranges from 256 bytes through 2GB whose base is aligned to their
complete extent. It accepts only documented AP/S/C/B/XN bits and never rounds
the range outward. A representable 4GB MPU region cannot be described by this
ordinary 32-bit `[start, end)` API, so it is rejected rather than silently
covering unrelated memory. The encoder writes only an in-memory RBAR/RASR
pair; it does not program MPU registers.

Slice 3 adds `fiber_port_linker_contract.ld`, an application-owned assertion
fragment that is included after the board linker script has placed the
sections. It never chooses STM32 addresses itself. The integration must define
these exact range boundaries with no weak fallback:

```text
__fiber_mpu_unprivileged_code_start__ / end__
__fiber_mpu_privileged_code_start__   / end__
__fiber_mpu_privileged_data_start__   / end__
__fiber_mpu_current_context_slot_start__ / end__
__fiber_mpu_unprivileged_ram_start__  / end__
```

The fragment rejects a missing boundary, non-exact global code/data region,
non-256-byte current-slot aperture, unaligned or empty unprivileged RAM, and
every forbidden code/data/RAM overlap, including the current-slot aperture with
either code range. Privileged code may be disjoint from, or fully nested in,
the unprivileged executable range; partial overlap is rejected.
The application must name the current-slot output section
`.fiber_current_context_slot`. The fragment requires that it starts at the
declared aperture boundary and is exactly 256 bytes; its body must contain only
`KEEP(*(.bss.fiber_runtime_current_context_slot))` and deliberate padding. The
complete aperture must remain in the startup BSS zero-initialization span even
though it is larger than the four-byte common slot object.

`fiber_port_context_init()` and `fiber_port_context_seal_check()` load and
validate those boundaries before using context metadata. They require the
complete `FiberContext` in privileged data, the raw stack in unprivileged RAM,
and the entry address in unprivileged executable text outside privileged code.
The checks are construction/validation mechanics only; they do not write MPU
registers.

The selected profile provides `fiber_portPRIVILEGED_FUNCTION`,
`fiber_portUNPRIVILEGED_FUNCTION`, and `fiber_portPRIVILEGED_DATA` section
attributes for the port and integration objects. Every external direct callee
used by the protected construction path, including `fiber_panic`, must resolve
inside the privileged-code range; the future return veneer must resolve inside
the unprivileged-code range. The port checks those named targets before
accepting a layout, and the matrix proves every selected-port helper remains in
the privileged function section. The linker keeps the common current-context
slot in its existing
`.bss.fiber_runtime_current_context_slot` subsection and isolates that one
object in the region-4 aperture.

`fiber_port_mpu_build_global_regions()` constructs, but does not program, this
four-entry image:

```text
region 4  exact 256-byte current slot: privileged RW, unprivileged RO, XN
region 5  exact unprivileged code:     privileged/unprivileged RO, executable
region 6  exact privileged code:       privileged RO, unprivileged NA, executable
region 7  exact privileged data:       privileged RW, unprivileged NA, XN
```

This is the pure layout/image half of FreeRTOS `prvSetupMPU()`. The later start
slice must still check MPU type, enable required faults, write every global
region and `MPU_CTRL`, issue barriers, and read all state back before any
unprivileged exception return.

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

| FreeRTOS family | Fiber slices 1-5 mapping | Decision |
| --- | --- | --- |
| scalar/task typedefs and stack growth/alignment | `fiber_api_types.h`, selected `FiberContext`, ARMv6-M traits | Adapted; FreeRTOS API typedefs are not exported. |
| tick type, delay, ready bitmap, scheduler/list macros | user scheduler and later C++ Kernel | Excluded from CPU port. |
| `configENABLE_MPU`, `portUSING_MPU_WRAPPERS`, privilege bit | exact selected MPU profile identity | Adapted; no compatibility wrappers or no-op feature API. |
| MPU region numbers | `fiber_portMPU_*_REGION` constants | Adapted as documented above: current-context aperture replaces broad peripherals. |
| MPU region-size encodings | renamed constants plus `fiber_port_mpu_try_encode_exact_region()` | Retained and strengthened: exact power-of-two/base-aligned ranges only; no widening. |
| S/C/B memory type and AP/XN encodings | renamed constants plus strict attribute allowlist | Retained; only documented AP/S/C/B/XN bits reach an encoded enabled region. |
| `MPURegionSettings_t` and task-region descriptors | future optional MPU integration ABI | Deferred; no public header or stub exists. |
| `xMPU_SETTINGS` | selected `FiberContext` prefix plus `FiberPortBoot` | Adapted. Raw 20-word restore order is exact; FreeRTOS authorization metadata is not imported. |
| `CONTEXT_SIZE == 20` | `FiberPortProtectedContext` | Retained exactly. |
| task padding/privilege flags | `runtime_flags` bits | Retained as mutable selected-port state; not a public FreeRTOS flag API. |
| SVC services 100..103 | native `70` start, native `71` private yield, native `72` return | Adapted. Fiber owns a smaller profile-private namespace and validates exact opcode, origin, frame, and continuation for every service. |
| `portYIELD`, ISR-yield, critical nesting macros | private yield veneer plus PRIMASK-protected scheduler bridge | Adapted. The slice owns the unprivileged SVC yield and PendSV mechanics, but exposes no public forward scheduling operation or ISR API. |
| `portMAX_DELAY`, tickless, timer configuration | user scheduler/platform | Excluded. |
| privilege query/raise/reset macros | future optional MPU ABI and checked SVC routes | Deferred; no public stubs. |

## `port.c` And `portasm.c` Ledger

| FreeRTOS path | Fiber owner | Slice-5 status |
| --- | --- | --- |
| MPU `pxPortInitialiseStack` | `fiber_port_context_init()` | Implemented for the exact 20-word protected image. Fiber seeds r9 from the live platform value, zeros other saved registers, sets unprivileged CONTROL, and keeps the complete initial hardware frame in privileged context storage. |
| `vRestoreContextOfFirstTask` / `vStartFirstTask` | `fiber_port_start_first_context()` and `fiber_port_restore_first_context_from_svc()` | Implemented. The `+20/-32/-48/-32/-16` Thumb-1 cursor geometry and copied basic frame match the reference; Fiber adds first-image and PSP/CONTROL/EXC_RETURN readback checks. ARM_CM0 behavior intentionally does not rewind MSP. |
| `SVC_Handler` / `vPortSVCHandler_C` | strong `SVC_Handler()` and `fiber_port_svc_dispatch()` | Implemented for first start, private yield, and task return. It validates IPSR, exception origin, privileged/unprivileged frame range, xPSR, SVC opcode/immediate, and exact post-SVC continuation. Service 71 pends only the selected protected PendSV route. |
| MPU `PendSV_Handler` | strong selected-port protected switch path | Implemented. It validates before the first protected-cursor load, copies the complete basic frame into privileged storage, calls the scheduler under PRIMASK, replaces per-context MPU regions, and restores the selected image. |
| `ulSetInterruptMask` / `vClearInterruptMask` | selected PRIMASK scheduler envelope | Adapted for the private protected handler. BASEPRI and FAULTMASK are prohibited by traits; public forward runtime activation is still deferred. |
| `prvGetMPURegionSizeSetting` | `fiber_port_mpu_try_encode_exact_region()` | Implemented with stronger exact coverage, AP/S/C/B/XN allowlist, base alignment, 256B minimum, and a fail-closed 2GB maximum for the 32-bit exclusive-end API. |
| `prvSetupMPU` | `fiber_port_mpu_activate_first_context()` and `fiber_port_mpu_switch_to_context()` | Implemented. First start writes all context/global regions. Ordinary switches atomically replace only regions 0-3, retain immutable globals 4-7, and prove the complete active image by readback. |
| `vPortStoreTaskMPUSettings` | base stack image plus optional MPU API | Slices 2-5 implement only the safe default: regions 0-2 disabled, region 3 exact raw stack RW/XN, and linker-defined regions 4-7. Optional heterogeneous regions remain separately versioned. |
| `xPortStartScheduler` | private first-start helper plus later common forward adapters | FreeRTOS scheduler/tick mechanics are excluded. The protected first-start and switch mechanics are private and non-selectable until the separate forward-ABI/archive proof. |
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

## Slices 2-5 Construction And Linker Contract

`fiber_port_context_init()` is port-owned and currently compile/link-covered
only. It requires an aligned `FiberContext` in linker-isolated privileged data,
a non-overlapping raw stack in linker-isolated unprivileged RAM, a Thumb entry
in unprivileged executable text, and a raw stack range representable by exactly
one ARMv6-M MPU region. The default policy is intentionally conservative:

```text
regions 0..2  disabled
region 3      exact complete raw stack, privileged/unprivileged RW and XN
CONTROL       0x00000003 (unprivileged Thread mode using PSP)
PSP           stack_top - one basic hardware frame
```

The initial basic hardware frame stays in words 8..15 of the protected image,
matching `pxPortInitialiseStack()`. No synthetic frame is written to the user
stack; only the optional red-zone canary (`0xDEADBEEF`) is initialized there.
The final word of the protected image is the one-past cursor target, so the
Thumb-1 save path begins at the same geometry as FreeRTOS.

The initial PSP value is intentionally expressed against Fiber's exclusive
aligned `stack_top`: `stack_top - 32`. FreeRTOS receives `pxTopOfStack` as its
last usable stack word and stores `pxTopOfStack - 8` words. The two spellings
are not numerically identical because their top-of-stack conventions differ;
both reserve exactly the copied eight-word hardware frame below the usable
stack top. Fiber keeps its established exclusive-bound convention rather than
adding a profile-specific off-by-one stack API.

The seal covers immutable boot/ABI facts and all four RBAR/RASR pairs. It
excludes saved registers, the live cursor, and `runtime_flags`, because PendSV
mutates those fields. Slice 5 provides real unprivileged return and yield
veneers; the synthetic fixture uses them only for compile/link/ELF proof.

Before `fiber_port_context_init()` returns, a constructor-only check verifies
every word of the initial 20-word protected image, including the live-r9 seed,
all zeroed registers, explicit Thumb-bit return veneer, normalized stacked PC,
xPSR, PSP, CONTROL, EXC_RETURN, and the one-past cursor. Slice 5 repeats that
full first-image check immediately before first restore, including the current
r9 platform/static-base value. It is intentionally not a switch-time check:
ordinary PendSV save/restore legitimately mutates the protected image.

## Slice-5 Protected SVC And PendSV Contract

`fiber_port_start_first_context()` is a private staged entry only. It verifies
privileged Thread/MSP state, validates the exact selected first image and both
exception vectors, probes the implemented priority width, programs SVCall
priority zero and PendSV priority lowest with readback, clears stale PendSV
while PRIMASK is set, then issues `svc #70`. It intentionally does not
write MSP: the pinned FreeRTOS ARM_CM0 first-start path also preserves the
caller's MSP.

The strong `SVC_Handler()` passes only the hardware frame, incoming
EXC_RETURN, and the assembly-loaded common current slot to the privileged C
dispatcher. The handler uses a literal Thumb-address tail branch rather than a
narrow Thumb-1 `b`, so LTO cannot make the dispatcher out of range. The
dispatcher accepts only:

```text
service 70  privileged Thread/MSP first start, EXC_RETURN 0xFFFFFFF9
service 71  unprivileged Thread/PSP private yield, EXC_RETURN 0xFFFFFFFD
service 72  unprivileged Thread/PSP task return, EXC_RETURN 0xFFFFFFFD
```

Every service requires a valid SVC opcode, exact continuation address, expected
stack origin and range, xPSR Thumb/Thread shape, and the exact linked code
domain. A foreign SVC fails closed with `'u'`. Service 71 is reachable only
through the private unprivileged yield veneer; it pends PendSV under PRIMASK,
checks the pending bit, and returns so PendSV owns the actual save.

For service 70, the dispatcher disables interrupts, requires the exact
eight-region ARMv6-M MPU type and `MPU_CTRL == 0`, writes all four context and
four linker-derived global regions, enables `MPU_CTRL == 0x5`, issues barriers,
and reads every programmed register back before restoring the first context.
The Thumb-1 restore preserves the pinned FreeRTOS protected-image geometry:
it copies the eight-word hardware frame to PSP, restores r8-r11 and r4-r7,
advances the protected cursor, switches to unprivileged PSP Thread mode, then
returns through `0xFFFFFFFD`. Fiber's extra PSP/CONTROL/EXC_RETURN readbacks
are an intentional validation difference; they do not replace the reference
transfer order.

PendSV first proves `IPSR == 14`, `EXC_RETURN == 0xFFFFFFFD`, a clear
incoming PRIMASK, the active unprivileged CONTROL value, the current protected
context, the live PSP frame, and the active eight-region MPU image. Its C
preflight executes before the first assembly read of
`current->protected_context_cursor`. The preflight is an ordinary AAPCS
call, so r4-r11 remain intact until the explicit Thumb-1 serialization begins.

The handler then retains the reference ARM_CM0 MPU geometry: save r4-r11,
copy eight hardware-frame words to privileged storage, save PSP/CONTROL/
EXC_RETURN, mask with PRIMASK, choose the next context, replace MPU regions,
and restore the selected image. Fiber intentionally keeps PRIMASK set across
the scheduler callback and MPU replacement. The callback is a trusted
privileged scheduler-policy integration point: its code and user object must
be placed in privileged domains before this profile is exposed through the
normal forward ABI.

Fiber additionally snapshots and verifies PRIMASK, CONTROL, IPSR, PSP, vector
base, SVC/PendSV priority registers, pending-PendSV state, MPU control, selected
MPU region number, and all eight effective RBAR addresses/RASR values around the
scheduler callback. It validates the returned context before publication,
replaces only mutable regions 0-3 with MPU disabled, retains immutable
linker-derived regions 4-7, then reads back the complete next image before
exception return. The protected transfer has exactly eight hardware-frame words;
an xPSR `STACKALIGN` padding word is rejected with `'a'` rather than silently
copying an unmodelled ninth word.

The private SVC yield veneer and strong PendSV handler do not activate
`fiber_port_runtime_schedule()` or the other seven forward operations.
`FIBER_PORT_RUNTIME_SELECTABLE` remains zero.

## Slice-5 Evidence

The compile matrix builds the profile at `-O2` and `-Os`, then repeats the
synthetic linker/ELF retention proof under LTO. It proves all ten
linker-boundary relocations, privileged/unprivileged input-section placement,
one exact 256-byte current-slot output section containing the common slot,
privileged `FiberContext`/global image storage, unprivileged entry/return code
and raw stack placement, direct slot-11/slot-14 Thumb-vector ownership by the
strong `SVC_Handler`/`PendSV_Handler`, exact first-start/restore and
protected PendSV assembly shapes, the PRIMASK/MPU replacement envelope, and
generated-code proof that the current pointer is not dereferenced before its
preflight.

The synthetic positive link includes the actual
`fiber_port_linker_contract.ld` fragment. Two negative links deliberately
shrink the current-slot aperture and make the unprivileged-code range
non-power-of-two; both must fail. It repeats the boot and first-start runtime
compile/undefined-surface proof for both VTOR-present and VTOR-absent cohorts.
The construction/global-image builder must emit no CPU-state instruction; the
runtime object is the sole owner of SVC/PendSV/MPU writes. The separate
`freertos_asm_parity.ps1` proof compares first start, every protected
save/restore segment, the PRIMASK scheduler envelope, and MPU replacement
against the pinned FreeRTOS ARM_CM0 MPU branch at both optimization levels.

## Required Later Slices

1. Add all eight forward runtime ABI adapters, archive/cohort/vector/ELF/LTO
   proofs, and only then allow this exact build-selected source group to link.
2. Add the optional pre-start MPU configuration ABI only if heterogeneous
   per-fiber policy is required.
3. Run matching Cortex-M0+ MPU hardware and isolation tests before any STM32
   support claim.

No later slice may reuse privileged `ARM_CM0` saved-frame assembly, restore a
protected context from unprivileged memory, reintroduce a broad general
peripherals region, infer selection from `__MPU_PRESENT`, or activate this
profile before the complete runtime and link proof exists.
