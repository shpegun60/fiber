# ARM_CM55_MVEF_MPU Non-secure FreeRTOS Parity Ledger

## Slices 1-4 Scope

This is the complete software runtime of the explicit build-selected
`ARM_CM55_MVEF_MPU/non_secure` Cortex-M55 MVE-FP MPU profile. It freezes
public storage, selected-port traits, the exact protected context geometry,
sealed construction, FPU policy helpers, linker boundaries, the exact context
cohort, strict SVC #70 first start, private SVC #72 task return, protected MPU
activation/basic restore, and strong `SVC_Handler` and `PendSV_Handler`
mechanics. Slice 4 activates the frozen eight-operation forward ABI: boot owns
`fiber_port_context_init()`, the mandatory SVC/runtime object owns the other
seven operations and public SVC #71 yield, and its private bundle anchor forces
the separately compiled PendSV component from a static archive.

The matrix proves the full selected runtime under hard-float and softfp
`-O2`/`-Os`, plus representative hard-float `-O2` LTO archive links. It also
proves exact cohort expectation, stale 8/16-region archive rejection,
privileged/unprivileged/syscall placement, vector slots 11/14, and duplicate
strong-handler failure. This profile deliberately has no global selector route,
optional heterogeneous MPU API, TrustZone/SecureContext or TF-M companion,
PAC/BTI policy, or hardware-support claim.

The selected manifest is:

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=8 or 16
CMSIS __CORTEX_M=55
CMSIS __MPU_PRESENT=1
CMSIS __VTOR_PRESENT=1
CMSIS __FPU_PRESENT=1
CMSIS __FPU_USED=1
compiler=-march=armv8.1-m.main+mve.fp -mthumb -mfloat-abi=hard or softfp
```

`__ARM_FEATURE_MVE` must report both integer and FP MVE bits. Secure CMSE,
PAC, and BTI are rejected. `ARM_CM55F_MPU` and `ARM_CM55_MVEF_MPU` use
separate region-manifest macros and exact cohorts even though the protected
array geometry is the same.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
FreeRTOS CMake port: GCC_ARM_CM55_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM55_NTZ/non_secure
```

| Reference file | SHA-256 | Slice-1 disposition |
| --- | --- | --- |
| `portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` | M55 identity, MVE-FP compiler requirements, and selected traits are mapped. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | MPU region roles, RBAR/RLAR/MAIR facts, FP context geometry, and `xMPU_SETTINGS.ulContext` are mapped. |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | The `configENABLE_MPU=1`, `configENABLE_FPU=1`, `configENABLE_MVE=1` constructor branch is the construction reference. |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | Protected basic first restore is mapped by slice 2; protected MVE-FP PendSV copy order is mapped by slice 3; slice 4 adds only Fiber runtime composition around those paired mechanics. |

The exact reference configuration is:

```text
configENABLE_MPU=1
configENABLE_FPU=1
configENABLE_MVE=1
configENABLE_TRUSTZONE=0
configRUN_FREERTOS_SECURE_ONLY=0
configENABLE_PAC=0
configENABLE_BTI=0
configNUMBER_OF_CORES=1
configTOTAL_MPU_REGIONS=8 or 16
```

FreeRTOS gates its protected FP copies with
`configENABLE_FPU || configENABLE_MVE`. In this configuration both are one.
The reference does not allocate, save, or restore a VPR software word. Fiber
therefore records MVE in the exact cohort but keeps the same 54-word physical
protected image as scalar-FP `C55P`.

## Frozen Protected Context

FreeRTOS uses one `ulContext[MAX_CONTEXT_SIZE == 54]` backing array. Its basic
and extended views overlap deliberately:

```text
basic first-start image:
  words  0.. 7  r4..r11
  words  8..15  copied basic hardware frame r0..r3, r12, LR, PC, xPSR
  words 16..19  PSP, PSPLIM, CONTROL, EXC_RETURN
  word      20  one-past basic save cursor

extended MVE-FP saved image:
  words  0..15  s16..s31
  words 16..32  copied s0..s15, FPSCR
  words 33..40  r4..r11
  words 41..48  copied basic hardware frame r0..r3, r12, LR, PC, xPSR
  words 49..52  PSP, PSPLIM, CONTROL, EXC_RETURN
  word      53  one-past extended save cursor
  no VPR software slot
```

`FiberPortProtectedContext` is an exact 216-byte union. The constructor clears
all 54 words, fills only the basic view, and points
`protected_context_cursor` at `basic.cursor_limit`. Slice 3 overwrites this
same image after an extended save, moves the cursor to
`extended.cursor_limit`, and retains the pinned FreeRTOS save/restore order.

The generic selected-port geometry follows the same distinction: the basic
protected restore image is 20 words with `EXC_RETURN` at word 19, so its
logical initial image is 112 bytes including the basic hardware frame. The
extended image adds 33 privileged FP words (`s16-s31` and copied
`s0-s15/FPSCR`), so its logical maximum is 320 bytes. The protected context
stays in privileged SRAM. The user PSP stores only the hardware exception
frame, so construction requires a conservative 112-byte usable PSP range
rather than the 216-byte protected backing size.

## Fiber Mapping And Deliberate Differences

| FreeRTOS mechanism | Fiber mapping |
| --- | --- |
| `xMPU_SETTINGS.ulMAIR0` | `FiberContext.mair0` |
| `xMPU_SETTINGS.xRegionsSettings[]` | `FiberContext.mpu_regions[]` |
| `xMPU_SETTINGS.ulContext[54]` | overlapping `FiberPortProtectedContext` union |
| `xMPU_SETTINGS.ulTaskFlags` | `FiberContext.runtime_flags` |
| `pxPortInitialiseStack()` | `fiber_port_context_init()` |
| `prvSetupFPU()` | `fiber_port_fpu_prepare()` plus CPACR/FPCCR readback |
| MVE-FP compiler capability | `__ARM_FEATURE_MVE & 3 == 3` and `FIBER_PORT_HAS_MVE == 1` |
| no FreeRTOS VPR storage | no Fiber VPR storage or frame slot |
| FreeRTOS task-control-block ownership | sealed boot metadata and exact `C55W` cohort retention |

Fiber adds fail-closed linker-layout, context-storage, seal, Thumb entry, stack
range, and FPU policy checks. These checks use general registers only; no Fiber
VFP or MVE transfer can occur before CP10/CP11 and FPCCR policy readback
succeeds. GCC may use transient MVE stores while compiling the reference
constructor; those are checked separately from saved-context or VPR state.

## Slice-1 Construction Proof

For 8- and 16-region manifests, hard-float and softfp `-O2`/`-Os`, plus
hard-float `-O2` LTO, the matrix proves:

```text
type-only C and C++ public storage has no CMSIS dependency
construction retains the exact C55W cohort defined by the mandatory SVC/runtime object; it differs from C55P
54-word basic/extended offsets, sizes, alignment, and cursor positions match
construction itself has no PendSV or forward-runtime ABI ownership
the selected compiler requires MVE FP, not scalar FP or integer-only MVE
construction and FPU policy emit no VFP/MVE transfer or MPU register write
linker boundaries and protected/current-slot MPU image are present
invalid core/FPU/MVE/CMSE/region-manifest inputs fail closed
missing linker boundaries fail closed
```

The generated construction shape is compared against the pinned FreeRTOS
`configENABLE_MPU=1`, `configENABLE_FPU=1`, `configENABLE_MVE=1` constructor
branch. The MVE proof specifically rejects an accidental VPR software slot;
slice 3 separately proves that the protected PendSV mechanics retain that
absence while preserving the conditional FP copy order.

## Slice-2 Strict SVC Proof (Historical Checkpoint)

At the original Slice-2 checkpoint, the same 8- and 16-region manifests,
hard-float and softfp `-O2`/`-Os`, plus hard-float `-O2` LTO, proved:

```text
strict SVC source owned one exact C55W cohort and strong SVC_Handler only
the isolated Slice-2 fixture resolves slot 11 to SVC_Handler and deliberately leaves slot 14 zero
SVC #70 first start and private SVC #72 task return were emitted
SVC #71, PendSV, forward runtime ABI, and vector/MVE/VPR state transfer were absent from the Slice-2 object
FreeRTOS-shaped MPU disable, MAIR0/RBAR/RLAR installation, enable, and basic restore match
PSP, PSPLIM, CONTROL, BASEPRI, MPU, linker, vector, context, and FPU policies are checked
duplicate strong SVC definitions fail the synthetic link
```

The SVC first-restore assembly is compared against the pinned FreeRTOS
`vStartFirstTask()` and `vRestoreContextOfFirstTask()` mechanisms. Both use
the basic 20-word protected view and neither transfers high FP, low FP, MVE,
or VPR state. Fiber's additional checks, private task-return service, and
`PRIVDEFENA` policy are recorded in `FAP-M55MVE-MPU-SVC`.

## Slice-3 Protected MVE-FP PendSV Proof (Historical Checkpoint)

`fiber_port_pendsv.c` owns the protected MVE-FP switch mechanics for the same
54-word privileged backing image. Before its naked handler reads the mutable
save cursor, it validates the live current context, basic or extended hardware
frame, CPACR/FPCCR policy, and active MPU image. It then preserves the pinned
FreeRTOS move order:

```text
extended save:
  PSP + 32 -> copy s0-s15/FPSCR
  s16-s31 -> protected image
  r4-r11, copied basic hardware frame, PSP, PSPLIM, CONTROL, EXC_RETURN

extended restore:
  PSP, PSPLIM, CONTROL, EXC_RETURN
  copied basic hardware frame, r4-r11
  copied s0-s15/FPSCR, s16-s31
  no VPR software slot or VPR transfer
```

The saved cursor is exactly `basic.cursor_limit` for a basic return or
`extended.cursor_limit` for an extended return. Scheduler selection consumes
the frozen reverse ABI under BASEPRI and validates scheduler CPU/MPU state.
With PRIMASK asserted, Fiber disables the MPU, replaces MAIR0 and the selected
context RBAR/RLAR pairs, publishes the selected context through common-owned
state, reenables the MPU, validates the readback, then performs the inverse
restore.

At the Slice-3 checkpoint, the matrix proved the component for 8- and 16-region manifests, hard-float and
softfp `-O2`/`-Os`, with a hard-float `-O2` LTO synthetic ELF. It checks the
generated VFP copy instructions and their order, rejects VPR/MVE context state,
retains reverse-ABI/cohort identity, resolves strong `SVC_Handler` and
`PendSV_Handler` in slots 11 and 14 in the Slice-3 fixture, and rejects a
competing strong `PendSV_Handler`. At that checkpoint the component deliberately
had no forward ABI implementation, public SVC #71 yield, or archive-extraction
claim.

## Slice-4 Forward Runtime And Archive Proof

Slice 4 preserves the paired construction, first-start SVC, and protected
PendSV mechanics above. It adds only the frozen runtime composition:

```text
fiber_port_boot.c
  -> fiber_port_context_init()

fiber_port_svc.c
  -> runtime memory barrier, panic wait, scheduler-environment check,
     prepare/start/select runtime operations, public SVC #71 yield,
     strong SVC_Handler, cohort definition, and handler-bundle anchor

fiber_port_pendsv.c
  -> protected first-selection bridge and strong PendSV_Handler
```

The handler-bundle anchor calls the separately compiled PendSV component anchor,
so a weak startup alias cannot satisfy archive extraction. This changes neither
the 54-word protected layout nor the FreeRTOS-derived `s16-s31`/copied
`s0-s15/FPSCR` transfer order. The public yield veneer is a direct SVC #71
request; scheduler policy still runs only in the protected PendSV bridge.

The full runtime proof covers both 8- and 16-region cohorts:

```text
hard-float and softfp -O2/-Os:
  construction, SVC, and PendSV generated assembly against pinned FreeRTOS
  no VPR software slot or VPR transfer

hard-float -O2, softfp -Os, and hard-float -O2 LTO:
  exact eight-function forward ABI
  archive extraction of boot, SVC, and PendSV objects
  exact external cohort expectation and stale 8/16 archive rejection
  privileged/unprivileged/syscall placement
  strong SVC_Handler and PendSV_Handler in vector slots 11 and 14
  duplicate SVC_Handler and PendSV_Handler negative links
```

## Deferred Work

1. Optional heterogeneous MPU API.
2. TrustZone/SecureContext or TF-M companion, PAC, BTI, and hardware validation
   as separate work.

This profile is a complete software-selected runtime only. It remains
explicitly build-selected and makes no hardware claim.
