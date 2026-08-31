# ARM_CM55F_MPU Non-secure FreeRTOS Parity Ledger

## Slices 1-4 Scope

This ledger covers all four implementation slices of the explicit
build-selected `ARM_CM55F_MPU/non_secure` Cortex-M55 scalar-FP MPU profile.
They freeze public storage, selected-port traits, exact protected context
geometry, sealed construction, FPU policy helpers, linker boundaries, and the
exact context cohort. Slice 2 adds strict protected first-start SVC and basic
protected restore. Slice 3 adds the strong protected `PendSV_Handler` with
the scalar-FP save/select/MPU-replacement/restore mechanics.

Slice 4 activates the frozen eight-operation runtime ABI without introducing a
generic `fiber_port.c`: `fiber_port_boot.c` continues to own
`fiber_port_context_init()`, while the mandatory SVC object owns the remaining
seven operations, strong SVC slot 11 ownership, and public SVC #71 yield. It
forces the separately compiled strong PendSV slot 14 object from an archive
through a private component anchor. This profile still has no global selector
route, optional heterogeneous MPU API, or hardware-support claim.

The selected manifest is:

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
FIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8 or 16
CMSIS __CORTEX_M=55
CMSIS __MPU_PRESENT=1
CMSIS __VTOR_PRESENT=1
CMSIS __FPU_PRESENT=1
CMSIS __FPU_USED=1
compiler=-march=armv8.1-m.main+fp -mthumb -mfloat-abi=hard or softfp
```

`-mcpu=cortex-m55 -mfpu=fpv5-sp-d16` is not a scalar-only target because this
GCC target exposes MVE. It belongs to a distinct MVE-FP cohort. Secure CMSE,
PAC, BTI, and MVE are rejected here rather than becoming runtime switches.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
FreeRTOS CMake port: GCC_ARM_CM55_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM55_NTZ/non_secure
```

| Reference file | SHA-256 | Disposition in this slice |
| --- | --- | --- |
| `portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` | M55 identity, scalar-FP compiler requirements, and selected traits are mapped. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | MPU region roles, RBAR/RLAR/MAIR facts, FP context geometry, and `xMPU_SETTINGS.ulContext` are mapped. |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | The `configENABLE_MPU=1`, `configENABLE_FPU=1`, no-MVE constructor branch is the construction reference. |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | `vStartFirstTask()` and the basic protected `vRestoreContextOfFirstTask()` are paired in slice 2. The MPU scalar-FP `PendSV_Handler` copy order is paired in slice 3. |

The exact reference configuration is:

```text
configENABLE_MPU=1
configENABLE_FPU=1
configENABLE_MVE=0
configENABLE_TRUSTZONE=0
configRUN_FREERTOS_SECURE_ONLY=0
configENABLE_PAC=0
configENABLE_BTI=0
configNUMBER_OF_CORES=1
configTOTAL_MPU_REGIONS=8 or 16
```

## Frozen Protected Context

FreeRTOS uses one `ulContext[MAX_CONTEXT_SIZE == 54]` backing array, not two
independent frames. The two views intentionally overlap:

```text
basic first-start image:
  words  0.. 7  r4..r11
  words  8..15  copied basic hardware frame r0..r3, r12, LR, PC, xPSR
  words 16..19  PSP, PSPLIM, CONTROL, EXC_RETURN
  word      20  one-past basic save cursor

extended scalar-FP saved image:
  words  0..15  s16..s31
  words 16..32  s0..s15, FPSCR
  words 33..40  r4..r11
  words 41..48  copied basic hardware frame r0..r3, r12, LR, PC, xPSR
  words 49..52  PSP, PSPLIM, CONTROL, EXC_RETURN
  word      53  one-past extended save cursor
```

`FiberPortProtectedContext` is an exact 216-byte union of those two views.
The constructor zeroes all 54 words, fills only the basic view, and points
`protected_context_cursor` at `basic.cursor_limit`. A later extended FP save
must overwrite the same backing array and move the cursor only to
`extended.cursor_limit`; it must never assume that the initial basic state
contains a separately initialized FP image.

The generic selected-port geometry follows the same distinction: the basic
protected restore image is 20 words with `EXC_RETURN` at word 19, so its
logical initial image is 112 bytes including the basic hardware frame. The
extended image adds 33 privileged FP words (`s16-s31` and copied
`s0-s15/FPSCR`). Its logical maximum is 320 bytes including the extended
hardware frame. This is separate from the physical PSP admission rule below.

`FiberContext` additionally holds the M55 MPU image, mutable runtime flags,
and sealed immutable boot metadata. The 8/16-region layout is intentionally
different and has separate exact cohort spellings:

| MPU regions | Per-context RBAR/RLAR pairs | protected image offset | boot offset | `sizeof(FiberContext)` |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 4 | 40 | 260 | 352 |
| 16 | 12 | 104 | 324 | 416 |

The protected image lives in privileged SRAM. The user PSP holds only the
hardware exception frame: 32 bytes for initial basic start and at most 108
bytes with scalar FP plus exception alignment padding. Context construction
therefore requires a conservative 112-byte usable PSP range, not 216 bytes.

## Fiber Mapping And Deliberate Differences

| FreeRTOS mechanism | Fiber mapping |
| --- | --- |
| `xMPU_SETTINGS.ulMAIR0` | `FiberContext.mair0` |
| `xMPU_SETTINGS.xRegionsSettings[]` | `FiberContext.mpu_regions[]` |
| `xMPU_SETTINGS.ulContext[54]` | overlapping `FiberPortProtectedContext` union |
| `xMPU_SETTINGS.ulTaskFlags` | `FiberContext.runtime_flags` |
| `pxPortInitialiseStack()` | `fiber_port_context_init()` |
| `prvSetupFPU()` | `fiber_port_fpu_prepare()` plus configuration/readiness readback |
| debug fill values | deterministic zero scratch values; `r9` is preserved for static-base ABI compatibility |
| FreeRTOS task control block ownership | Fiber adds sealed immutable boot metadata and exact-cohort retention |

The FPU policy preserves the reference CP10/CP11 and `FPCCR.ASPEN` model.
Fiber additionally reads policy back, makes `FIBER_FPU_LAZY` explicit
(`LSPEN=1` for lazy, `0` for eager), and rejects `LSPACT` before first start.
All three helpers are `general-regs-only`; no VFP or MVE instruction is valid
in construction or CPACR/FPCCR policy setup.

## Slice-1 Construction Proof

The compile matrix must prove, for 8 and 16 MPU-region manifests and both
hard-float and softfp `-O2`/`-Os` builds:

```text
type-only C/C++ storage has no CMSIS dependency
one exact C55P cohort is emitted for each manifest
the 8- and 16-region cohorts differ
all basic and extended union offsets are static-asserted
all constructor and FPU helpers remain privileged and emit no VFP/MVE transfer
the constructor owns only context_init, retains the runtime-defined cohort, and owns no handler
the construction linker proof retains all MPU boundaries and a compatible cohort relocation
missing linker boundaries and invalid FPU/MPU/core/MVE/CMSE manifests fail closed
```

`tools/freertos_asm_parity.ps1` compiles the same pinned FreeRTOS
`configENABLE_MPU=1`, `configENABLE_FPU=1`, no-MVE constructor at `-O2` and
`-Os`. The pairing records that both initial constructors seed a basic
protected image without VFP/MVE transfer instructions. Slice 3 separately
pairs the reference `vstmia`/`vldmia` copies of `s16-s31`, `s0-s15/FPSCR`,
the core image, and the copied hardware frame.

## Slice-2 Strict SVC Proof

`fiber_port_svc.c` adds the first-entry-only protected SVC mechanism:

```text
fiber_port_start_first_context(first)
  -> validates the selected first context and privileged start state
  -> rewinds MSP from the active vector table
  -> clears stale PendSV and enters SVC #70

SVC_Handler
  -> validates exact SVC provenance and the published common current context
  -> programs global MPU state while disabled
  -> calls fiber_port_restore_first_context_from_svc()
  -> restores the basic protected image and exception-returns to Thread/PSP
```

The restore preserves the FreeRTOS protected first-entry backbone: MPU disable,
MAIR0, RNR 4 and optionally 8/12 RBAR/RLAR pairs, MPU enable,
`[PSP][PSPLIM][CONTROL][EXC_RETURN]`, copied basic hardware frame, `r4-r11`,
cursor update, BASEPRI clear, and exception return. Both FreeRTOS and Fiber
must omit VFP/MVE transfer instructions here: the initial image is basic; the
extended scalar-FP representation is created only by the later PendSV save.

The matrix proves this for 8 and 16 regions, hard-float and softfp, `-O2` and
`-Os`, with an additional hard-float LTO synthetic ELF cohort. It proves one
strong `SVC_Handler` in vector slot 11 and rejects a competing strong SVC
handler. Slice 4 adds the seven non-construction forward operations here:
start preparation, protected first selection, first transfer, panic wait,
configuration validation, Thread-mode barrier, and the public SVC #71 schedule
veneer. `fiber_port_unprivileged_task_return()` remains the distinct private
SVC #72 return service.

### FAP-M55FMPU-SVC

FreeRTOS enters first start through its configurable SVC immediate and restores
the current TCB directly. Fiber uses fixed internal SVC #70, validates the
active vector slot, SVC opcode/call-site, masks, FPU state, linker placement,
MPU readback, sealed context, and common-published current context before the
same protected restore sequence. Fiber enables `MPU_CTRL.ENABLE | PRIVDEFENA`
instead of only `ENABLE`, because its selected privileged common runtime needs
the frozen current-context aperture during handler execution. These checks and
the SVC #72 task-return service add no context slot or scalar-FP transfer.

## Slice-3 Protected Scalar-FP PendSV Proof

`fiber_port_pendsv.c` owns the later runtime form of the same protected image.
Before it reads the mutable save cursor, its naked handler validates the live
current context, the basic or extended hardware frame, CPACR/FPCCR policy, and
the active MPU image. It then preserves the pinned FreeRTOS move order:

```text
extended save:
  PSP + 32 -> copy s0-s15/FPSCR
  s16-s31 -> protected image
  r4-r11, copied basic hardware frame, PSP, PSPLIM, CONTROL, EXC_RETURN

extended restore:
  PSP, PSPLIM, CONTROL, EXC_RETURN
  copied basic hardware frame, r4-r11
  copied s0-s15/FPSCR, s16-s31
```

The saved cursor is exactly `basic.cursor_limit` for the basic form or
`extended.cursor_limit` for the extended form. The scheduler is invoked through
the frozen reverse ABI under BASEPRI and must preserve the captured CPU and MPU
state. With PRIMASK asserted, Fiber disables the MPU, replaces MAIR0 and the
selected context's RBAR/RLAR pairs, publishes the next current context, then
reenables and reads the selected MPU image back before the inverse restore.

The matrix proves the handler for 8 and 16 regions, hard-float and softfp,
`-O2` and `-Os`, plus a hard-float LTO synthetic ELF. It checks the generated
VFP copy instructions, excludes MVE/VPR state, retains both the reverse ABI and
cohort identities, requires one strong handler in vector slot 14, and rejects a
competing strong `PendSV_Handler`. Slice 4 additionally proves that this
separate archive member is extracted by the mandatory SVC object's private
component-anchor call rather than by a startup weak handler alias.

## Slice-4 Runtime, Archive, And ELF Proof

The full runtime proof builds a static archive containing common runtime plus
the C55P boot, SVC, and PendSV objects. A portable application and the exact
cohort expectation are compiled outside that archive. For both 8- and
16-region manifests, it samples hard-float -O2, softfp -Os, and hard-float
-O2 LTO builds to prove:

- exactly one definition of each of the eight forward operations;
- strong SVC/PendSV handlers in vector slots 11 and 14;
- privileged, unprivileged, and syscall-flash placement of the runtime surface;
- extraction of boot, SVC, and PendSV archive members under section GC;
- external cohort retention and stale 8/16-region archive rejection; and
- failure for competing strong SVC or PendSV definitions.

The separate construction, SVC, and PendSV generated-code checks cover the
full hard-float/softfp -O2/-Os matrix. The archive proof is intentionally a
representative ABI/LTO cohort, not a claimed optimization cross-product.

SVC #71 is Fiber integration code, not a new FreeRTOS frame-layout claim. It
accepts only the exact syscall-flash veneer, validates the active protected
context, and requests PendSV; all protected frame movement remains the pinned
FreeRTOS-shaped SVC #70/PendSV logic described above.

## Deferred Work

The remaining work must not change this frozen layout:

1. optional heterogeneous MPU application policy only if explicitly requested;
2. MVE, SecureContext, TF-M, PAC, and BTI as different selected cohorts; and
3. matching M55F MPU execution and isolation hardware validation.

This profile has compile/assembly/archive/ELF evidence for its complete
build-selected runtime. It has no global auto-selection or hardware-support
claim.
