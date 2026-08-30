# ARM_CM55_MVEF_NTZ Non-Secure Parity Ledger

## Slices 1-3 Scope

This directory is the exact build-selected Cortex-M55 MVE-FP, Non-secure,
privileged, non-MPU, no-SecureContext, no-TF-M, no-PAC, and no-BTI context
cohort. It is deliberately non-selectable while the first three slices establish
the complete CPU/context runtime:

```text
implemented:
  selected types and immutable boot record
  exact MVE-FP frame traits and cohort identity
  sealed context construction and basic 18-word frame
  CPACR/FPCCR FPU policy and readback
  strict SVC first start and one strong SVC_Handler
  PSPLIM-aware MVE-FP PendSV and one strong PendSV_Handler
  all eight forward ABI operations through normal scheduling
  normal/LTO archive, vector, and exact-cohort proof

not implemented:
  global profile selection
  hardware validation
```

`FIBER_PORT_RUNTIME_SELECTABLE` remains `0`. The profile has no global
auto-selection or hardware-support claim. It must be deliberately compiled
with this selected profile until matching M55 MVE-FP hardware evidence exists.

The selected construction manifest is:

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
CMSIS __CORTEX_M = 55
compiler = -march=armv8.1-m.main+mve.fp -mthumb
FPU ABI = hard or softfp
```

The header requires `__ARM_FEATURE_MVE` bits zero and one. That means the GCC
target provides both MVE integer and MVE FP instructions. A scalar-FP M55
build belongs to the distinct `ARM_CM55F_NTZ` cohort, even though both cohorts
start from the same basic frame.

## Pinned FreeRTOS Reference

```text
_reference/FreeRTOS-Kernel
  commit: a50edad08b29052631aa469d4df6e6ec7ff68878
  portable/GCC/ARM_CM55_NTZ/non_secure/
```

| Pinned artifact | SHA-256 |
| --- | --- |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` |
| `portasm.h` | `185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C` |
| `portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` |

The selected FreeRTOS branch is:

```text
configNUMBER_OF_CORES = 1
configENABLE_MPU = 0
configENABLE_TRUSTZONE = 0
configRUN_FREERTOS_SECURE_ONLY = 0
configENABLE_FPU = 1
configENABLE_MVE = 1
configENABLE_PAC = 0
configENABLE_BTI = 0
```

## Frozen Frame And Traits

The pinned non-MPU FreeRTOS constructor uses the same basic frame when MVE is
enabled as when scalar FP is enabled. PendSV follows the exact
`configENABLE_FPU || configENABLE_MVE` branch in `portasm.c`:

```text
basic initial context:
  [PSPLIM][EXC_RETURN][r4-r11] + basic hardware frame
  40 + 32 = 72 bytes

maximum future extended context:
  [PSPLIM][EXC_RETURN][r4-r11] + [s16-s31] + extended hardware frame
  40 + 64 + 104 = 208 bytes, plus an optional 4-byte alignment pad

maximum bounded context: 212 bytes
basic EXC_RETURN:         0xFFFFFFBC
extended EXC_RETURN:      0xFFFFFFAC
```

Pinned FreeRTOS saves/restores `s16-s31` when `EXC_RETURN.bit4 == 0`. It does
not allocate an additional VPR word in its non-MPU software frame. Fiber
preserves that geometry exactly and records MVE in the cohort identity.

Fiber PendSV specifically follows the pinned `#else /* configENABLE_MPU */`
branch. That branch saves the conditional
high-FP state directly on PSP with `vstmdb` and restores it with `vldmia`.
The preceding FreeRTOS MPU branch copies the hardware frame into privileged
TCB-owned storage; it is a different context model and must not be reused by
this non-MPU `C55V` cohort.

| FreeRTOS fact | Fiber representation |
| --- | --- |
| `portARCH_NAME = Cortex-M55` | `FIBER_PORT_NAME = ARM_CM55_MVEF_NTZ` |
| `configENABLE_FPU = 1` | FPU/compiler/CMSIS facts and extended-frame traits are one |
| `configENABLE_MVE = 1` | `FIBER_PORT_HAS_MVE = 1` and compiler MVE-FP bits are required |
| `portUSE_PSPLIM_REGISTER = 1` | PSPLIM is software-frame word zero |
| `portINITIAL_EXC_RETURN` | basic `0xFFFFFFBC`; extended value `0xFFFFFFAC` |
| conditional `s16-s31` block | `FIBER_PORT_HIGH_FP_SOFTWARE_BYTES = 64` save/restore contract |
| no VPR software slot | ten-word software frame remains exact |
| exact identity | ASCII `C55V`, layout v1, feature mask `0x93` |

## Slice 1 Construction Evidence

`fiber_port_context_init()` constructs the same low-to-high basic image as
FreeRTOS `pxPortInitialiseStack()`: PSPLIM, basic EXC_RETURN, r4-r11 with the
selected r9 seed, stacked r0 argument, task-return LR, Thumb PC, and xPSR. It
adds Fiber-owned boot sealing, stack/context separation checks, canary setup,
exact word validation, and the one-shot exact-cohort relocation.

The constructor and FPU policy carry `general-regs-only`. Generated-code proof
must reject VFP or MVE instructions in these functions: CP10/CP11 is configured
by ordinary integer register writes before any later context transfer can use
the extended state.

The compile matrix and `tools/freertos_asm_parity.ps1` compare this constructor
with the pinned FreeRTOS MVE-FP branch under hard-float and softfp, at `-O2` and
`-Os`. They also prove the separate C55V cohort and MVE-FP manifest rejection.

## Slice 2 Strict SVC First Start

The pinned `vStartFirstTask()` and non-MPU `vRestoreContextOfFirstTask()` paths
are identical for scalar FP and MVE-FP: they restore the basic ten-word
`[PSPLIM][EXC_RETURN][r4-r11]` image and issue no MVE or VFP register transfer.
Fiber therefore implements the same integer-only first-context backbone:

```text
Thread/MSP privileged start
  -> configure lowest PendSV priority and clear a stale PendSV
  -> clear BASEPRI, enable faults/IRQs
  -> svc #70
  -> strong SVC_Handler restores PSPLIM, CONTROL, PSP and EXC_RETURN
```

The port additionally validates CPU/start policy, CPACR/FPCCR/LSPACT state,
active VTOR slot 11, SVCall priority, exact `0xFFFFFFB8` SVC provenance, the
stacked Thumb frame and opcode/immediate, the scheduler hook CPU state, the
sealed selected context, and PSPLIM/CONTROL/PSP readback. First selection runs
under the selected BASEPRI threshold. PendSV ownership is established by slice
3; SVC itself remains integer-only and never transfers MVE/VFP state.

The matrix proves the independently auditable SVC component: its seven local
forward operations, one strong `SVC_Handler`, exact reverse dependencies, and
hard/softfp `-O2`/`-Os` generated SVC parity. The comparison rejects VFP and
MVE instructions throughout the SVC-stage call graph: start preparation,
first-context transfer, the naked handler, and boot-side FPU/restore helpers.

## Slice 3 MVE-FP PendSV Runtime

`fiber_port.c` owns normal scheduling, protected first selection, scheduler
candidate selection/publication, save-side validation, and the strong
`PendSV_Handler`. The naked handler preserves the pinned non-MPU M55 ordering:

```text
PSP hardware frame
  -> conditional s16-s31 when EXC_RETURN.bit4 == 0
  -> [PSPLIM][EXC_RETURN][r4-r11]
  -> scheduler under BASEPRI
  -> restore [PSPLIM][EXC_RETURN][r4-r11]
  -> conditional s16-s31
  -> PSPLIM/PSP readback and exception return
```

The conditional high-register instructions are exactly `vstmdb r0!, {s16-s31}`
before the core frame and `vldmia r0!, {s16-s31}` after it. They
are guarded by `EXC_RETURN.bit4`; they are not an MVE vector-register save.

Fiber adds provenance, pre-save validation before metadata loads, structural
frame and bounds checks, FPU/CPU-state preservation across the scheduler hook,
common-owned current publication, and mask/register readback. None of those
checks add or reorder a saved context word. Both the pinned FreeRTOS MVE-FP
reference and Fiber are checked to contain no VPR software-frame transfer.

The complete matrix proves all eight forward operations, strong slots 11/14
owners, exact reverse dependencies, normal/LTO archive extraction, duplicate
handler failure, external exact-cohort retention, hard/softfp `-O2`/`-Os`
construction/SVC/PendSV parity, and production/lazy/no-rewind source variants.
This is complete software evidence, not a hardware-validation claim.

## Required Later Slices

1. Run an M55 MVE-FP board suite before assigning a hardware-validation claim.
2. Add M55 MPU, TrustZone/SecureContext or TF-M, and PAC/BTI profiles as
   separate exact cohorts rather than changing this non-MPU frame.

## Recorded Difference IDs

| ID | Reason |
| --- | --- |
| `FAP-M55MVE-CONSTRUCTION` | Fiber uses sealed metadata, a C55V cohort anchor, and direct frame-slot checks around the same FreeRTOS basic-frame geometry. |
| `FAP-M55MVE-SVC` | Fiber retains the FreeRTOS M55 first-start/restore transfer but limits SVC to the configured first-start immediate, adds exact provenance, FPU policy, vector/priority, context, scheduler-state, and special-register readback checks, and forbids VFP/MVE transfer in the basic first image. |
| `FAP-M55MVE-PENDSV` | Fiber preserves the pinned non-MPU conditional `s16-s31` before/after ten-word PSPLIM/core frame and explicitly rejects a VPR software slot; it adds provenance, frame/metadata, scheduler-state, mask, and special-register checks without changing saved-word ordering. |
