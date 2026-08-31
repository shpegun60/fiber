# ARM_CM55F_MPU Non-secure FreeRTOS Parity Ledger

## Slice 1 Scope

This is the first construction-only slice of the explicit build-selected
`ARM_CM55F_MPU/non_secure` Cortex-M55 scalar-FP MPU profile. It freezes public
storage, selected-port traits, the exact protected context geometry, sealed
construction, FPU policy helpers, linker boundaries, and the exact context
cohort. It deliberately does not provide `fiber_port.c`, a forward runtime
ABI, `SVC_Handler`, `PendSV_Handler`, an optional heterogeneous MPU API, or a
hardware-support claim.

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
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | The protected scalar-FP first restore and PendSV save/restore order are deferred to later slices. |

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

## Slice-1 Proof

The compile matrix must prove, for 8 and 16 MPU-region manifests and both
hard-float and softfp `-O2`/`-Os` builds:

```text
type-only C/C++ storage has no CMSIS dependency
one exact C55P cohort is emitted for each manifest
the 8- and 16-region cohorts differ
all basic and extended union offsets are static-asserted
all constructor and FPU helpers remain privileged and emit no VFP/MVE transfer
the constructor owns no runtime ABI or SVC/PendSV handler
the synthetic linker proof retains all MPU boundaries and one cohort definition
missing linker boundaries and invalid FPU/MPU/core/MVE/CMSE manifests fail closed
```

`tools/freertos_asm_parity.ps1` compiles the same pinned FreeRTOS
`configENABLE_MPU=1`, `configENABLE_FPU=1`, no-MVE constructor at `-O2` and
`-Os`. The pairing records that both initial constructors seed a basic
protected image without VFP/MVE transfer instructions. The later scalar-FP MPU
SVC/PendSV slice must add direct generated-assembly pairing for the reference
`vstmia`/`vldmia` copies of `s16-s31`, `s0-s15/FPSCR`, core image, and the
hardware frame.

## Deferred Work

The next slices must add, without changing this layout:

1. strict first-start SVC and protected first restore;
2. strong protected PendSV with the exact FreeRTOS extended-FP copy order;
3. forward/reverse ABI activation, vector/archive/cohort proof, including
   moving the cohort definition from this construction object into the
   always-linked mandatory runtime object while retaining it here; and optional
   MPU application policy only if explicitly requested;
4. MVE, SecureContext, TF-M, PAC, and BTI as different selected cohorts.

This profile is compile/assembly/ELF construction evidence only. It has no
M55F MPU hardware validation claim.
