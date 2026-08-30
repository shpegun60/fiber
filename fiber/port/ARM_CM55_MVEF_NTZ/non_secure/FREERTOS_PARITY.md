# ARM_CM55_MVEF_NTZ Non-Secure Parity Ledger

## Slice 1 Scope

This directory is the exact build-selected Cortex-M55 MVE-FP, Non-secure,
privileged, non-MPU, no-SecureContext, no-TF-M, no-PAC, and no-BTI context
cohort. It is deliberately construction-only in slice 1:

```text
implemented:
  selected types and immutable boot record
  exact MVE-FP frame traits and cohort identity
  sealed context construction and basic 18-word frame
  CPACR/FPCCR FPU policy and readback

not implemented:
  the other seven forward runtime ABI operations
  SVC_Handler / first-context transfer
  PendSV_Handler / save-select-restore
  global profile selection
```

`FIBER_PORT_RUNTIME_SELECTABLE` is therefore `0`. This profile has no runtime
or hardware-support claim. It must not be selected by an application before
the SVC and PendSV slices are implemented and independently proven.

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
enabled as when scalar FP is enabled. A later PendSV implementation must follow
the exact `configENABLE_FPU || configENABLE_MVE` branch in `portasm.c`:

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
not allocate an additional VPR word in its non-MPU software frame. Fiber slice
1 preserves that geometry exactly and records MVE in the cohort identity; it
does not yet claim that an MVE runtime path has been implemented.

The later Fiber PendSV implementation must specifically follow the pinned
`#else /* configENABLE_MPU */` branch. That branch saves the conditional
high-FP state directly on PSP with `vstmdb` and restores it with `vldmia`.
The preceding FreeRTOS MPU branch copies the hardware frame into privileged
TCB-owned storage; it is a different context model and must not be reused by
this non-MPU `C55V` cohort.

| FreeRTOS fact | Fiber slice-1 representation |
| --- | --- |
| `portARCH_NAME = Cortex-M55` | `FIBER_PORT_NAME = ARM_CM55_MVEF_NTZ` |
| `configENABLE_FPU = 1` | FPU/compiler/CMSIS facts and extended-frame traits are one |
| `configENABLE_MVE = 1` | `FIBER_PORT_HAS_MVE = 1` and compiler MVE-FP bits are required |
| `portUSE_PSPLIM_REGISTER = 1` | PSPLIM is software-frame word zero |
| `portINITIAL_EXC_RETURN` | basic `0xFFFFFFBC`; future extended value `0xFFFFFFAC` |
| conditional `s16-s31` block | future `FIBER_PORT_HIGH_FP_SOFTWARE_BYTES = 64` contract |
| no VPR software slot | ten-word software frame remains exact |
| exact identity | ASCII `C55V`, layout v1, feature mask `0x93` |

## Construction Evidence

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
`-Os`. They also prove the separate C55V cohort, MVE-FP manifest rejection,
and the absence of forward runtime ABI symbols or strong exception handlers.

## Required Later Slices

1. Add strict SVC first start and prove its integer-only transfer against
   FreeRTOS `vStartFirstTask()` and `vRestoreContextOfFirstTask()`.
2. Add MVE-FP PendSV and prove the exact conditional `s16-s31` save/select/
   restore backbone against FreeRTOS `PendSV_Handler()`.
3. Add archive/ELF/vector/cohort tests only after both strong handlers exist.
4. Run an M55 board suite before assigning a hardware-validation claim.

## Recorded Difference IDs

| ID | Reason |
| --- | --- |
| `FAP-M55MVE-CONSTRUCTION` | Fiber uses sealed metadata, a C55V cohort anchor, and direct frame-slot checks around the same FreeRTOS basic-frame geometry. |
| `FAP-M55MVE-SVC` | Reserved for the later strict SVC first-start slice. |
| `FAP-M55MVE-PENDSV` | Reserved for the later conditional MVE-FP PendSV slice. |
