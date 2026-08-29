# ARM_CM55F_NTZ Non-Secure Parity Ledger

## Slices 1-4 Scope

This is the exact build-selected Cortex-M55 scalar-FP, Non-secure, privileged,
no-MPU, no-MVE, no-SecureContext, no-TF-M, no-PAC, and no-BTI layout cohort.
Slice 1 adds type-only public storage, immutable boot storage, the selected
portmacro, and a layout/cohort proof. Slice 2 adds sealed construction and FPU
policy: `fiber_port_context_init()`, the basic 18-word initial-frame builder,
and CPACR/FPCCR setup/readback. Slice 3 adds the strict first-start half of the
runtime in `fiber_port_svc.c`. Slice 4 completes the selected runtime in
`fiber_port.c`: the eighth forward ABI operation, strong `PendSV_Handler`, and
the scalar-FP save/select/restore path. The profile is complete for
compile/assembly/archive/ELF evidence, but it still makes no hardware-support
claim.

The selected manifest is:

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
CMSIS __CORTEX_M = 55
compiler = -march=armv8.1-m.main+fp -mthumb -mfloat-abi=hard
```

`-mcpu=cortex-m55 -mfpu=fpv5-sp-d16 -mfloat-abi=hard` is deliberately rejected
by this profile because GCC defines `__ARM_FEATURE_MVE` for that target. That
flag belongs to a future M55 MVE-FP cohort. Scalar FP without MVE uses the
explicit `armv8.1-m.main+fp` target above; softfp is an equivalent procedure-call
ABI variant when it still emits scalar FP instructions.

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
configENABLE_MVE = 0
configENABLE_PAC = 0
configENABLE_BTI = 0
```

## Frozen Frame And Traits

New contexts use the basic frame. A running fiber that uses scalar FP switches
to the extended frame when `EXC_RETURN.bit4` is clear:

```text
basic:
  [PSPLIM][EXC_RETURN][r4-r11] + basic hardware frame
  40 + 32 = 72 bytes, plus an optional 4-byte alignment pad

extended scalar FP:
  [PSPLIM][EXC_RETURN][r4-r11] + [s16-s31] + extended hardware frame
  40 + 64 + 104 = 208 bytes, plus an optional 4-byte alignment pad

maximum bounded context: 212 bytes
basic EXC_RETURN:         0xFFFFFFBC
extended EXC_RETURN:      0xFFFFFFAC
```

| FreeRTOS fact | Fiber slice-1 representation |
| --- | --- |
| `portARCH_NAME = Cortex-M55` | `FIBER_PORT_NAME = ARM_CM55F_NTZ` |
| ARMv8-M minor version one | `FIBER_PORT_ARMV81M_MAINLINE = 1` plus CMSIS M55 identity |
| `configENABLE_FPU = 1` | FPU/compiler/CMSIS facts and extended-frame traits are all one |
| `configENABLE_MVE = 0` | `FIBER_PORT_HAS_MVE = 0`; compiler MVE is rejected |
| `portINITIAL_EXC_RETURN` | basic `0xFFFFFFBC`, extended `0xFFFFFFAC` accepted later by runtime slices |
| `portUSE_PSPLIM_REGISTER = 1` | PSPLIM slot is word zero |
| dynamic `s16-s31` block | `FIBER_PORT_HIGH_FP_SOFTWARE_BYTES = 64` |
| dynamic FP hardware extension | `FIBER_PORT_EXC_FP_EXT_BYTES = 72` |
| exact profile identity | ASCII `C55F`, layout v1, feature mask `0x83` |

## Slice 2 Construction And FPU Policy

The non-MPU `pxPortInitialiseStack()` branch in the pinned FreeRTOS M55 source
creates the same basic image whether FPU is enabled or not. Slice 2 writes the
same frame in the same low-to-high order, including the PSPLIM slot, basic
`0xFFFFFFBC` `EXC_RETURN`, preserved `r9`, argument in stacked `r0`, Thumb task
return target, PC, and xPSR. The constructor verifies the sealed boot record,
the exact saved-SP position, every static frame word, canary placement when
enabled, stack and context separation, and the exact C55F cohort relocation.
It is compiled `general-regs-only`; neither construction nor FPU policy may
emit FP/MVE instructions before CP10/CP11 is configured.

FreeRTOS `prvSetupFPU()` grants CP10/CP11 access and sets `FPCCR.ASPEN` plus
`FPCCR.LSPEN`. Fiber performs those register writes with DSB/ISB readback and
also supports the existing explicit `FIBER_FPU_LAZY` policy: lazy one requires
`LSPEN == 1`; eager one requires `LSPEN == 0`; both require `ASPEN == 1`.
`LSPACT == 0` is required before first start. This is a stricter policy check,
not a different saved-state layout.

Slice 2 matrix evidence compiles hard-float and softfp construction under
`-O2` and `-Os`, compares the generated basic-frame code to an independent
FreeRTOS-shaped fixture, and verifies the exact cohort. Slice 3 extends that
matrix to the strict SVC path. Slice 4 compiles the complete three-object
runtime under hard-float and softfp `-O2`/`-Os`, compares independent
FreeRTOS-shaped construction, SVC, and PendSV fixtures, checks the exact eight
forward operations and reverse surface, and proves normal/LTO archive, vector,
section-GC, cohort-expectation, and duplicate-handler behavior.

## Slice 3 Strict SVC First Start

The pinned FreeRTOS `vStartFirstTask()` rewinds MSP through the active vector
table, enables faults and IRQs, then raises the scheduler-start SVC. Its
non-MPU first restore reads `[PSPLIM][EXC_RETURN][r4-r11]`, writes PSPLIM,
selects Thread/PSP through CONTROL, sets PSP to the basic hardware frame, clears
BASEPRI, and returns through the saved `EXC_RETURN`.

Fiber preserves that processor transfer in `fiber_port_start_first_context()`
and the strong `SVC_Handler`, then tightens it as follows:

```text
before scheduler selection:
  STKALIGN readback
  CPACR/FPCCR eager-or-lazy policy readback
  stable MSP plan from the active vector source
  direct slot-11 SVC vector and SVCall priority readback
  BASEPRI implementation/PRIGROUP policy validation

after scheduler selection and before exception return:
  exact Thread/MSP/basic SVC provenance 0xFFFFFFB8
  aligned MSP hardware frame, xPSR.T, stacked IPSR and SVC opcode/immediate
  CPACR/FPCCR policy and LSPACT revalidation
  sealed first context, basic-only EXC_RETURN 0xFFFFFFBC, PSPLIM/CONTROL/PSP
  readback, and FAULTMASK == 0
```

The first scheduler callback runs under the selected BASEPRI threshold and its
PRIMASK, CONTROL, BASEPRI, FAULTMASK, PSPLIM, CPACR, and FPCCR state is captured
  and verified afterward. Common runtime still owns first-context publication;
  the selected port only requests the candidate through the frozen reverse ABI.

At `-O2` and `-Os`, for hard-float and softfp, the matrix compares the retained
FreeRTOS first-start/first-restore instruction backbone through an independent
fixture: MSP setup, `cpsie i/f`, `svc #70`, PSPLIM/CONTROL/PSP writes, BASEPRI
clear, and exception return. It additionally requires the Fiber-only
provenance, FPU policy, current-slot, and readback operations, and rejects any
VFP/MVE instruction in the naked SVC/start transfer handlers.

## Slice 4 FP-Aware PendSV Runtime

The non-MPU branch of pinned FreeRTOS `PendSV_Handler()` owns this processor
backbone:

```text
PSP -> optional vstmdb r0!, {s16-s31}
    -> [PSPLIM][EXC_RETURN][r4-r11]
    -> scheduler under BASEPRI
    -> [PSPLIM][EXC_RETURN][r4-r11]
    -> optional vldmia r0!, {s16-s31}
    -> PSPLIM, PSP, exception return
```

`fiber_port.c` preserves that order exactly. Basic frames save only the ten-word
core software image. Extended scalar-FP frames additionally save and restore
`s16-s31`; their hardware frame is accounted for with the same `EXC_RETURN`
bit-4 rule and the same 212-byte maximum bound as the construction/restore
validator.

Fiber deliberately adds checks around, not inside, the FreeRTOS mechanism:

```text
before first current metadata load:
  current pointer, sealed boot fast-check/hash policy, canary, live PSP,
  PSPLIM, and FPU policy

before first PSP write:
  exact selected basic/extended EXC_RETURN, Thread/PSP provenance, software
  and hardware frame bounds, xPSR alignment padding

around scheduler selection:
  BASEPRI critical envelope, PRIMASK/CONTROL/BASEPRI/FAULTMASK/PSPLIM/CPACR/
  FPCCR snapshot, selected restore validation, common-owned current publication

before return:
  PSPLIM and PSP readback plus Thread PSP/mask invariants
```

The matrix compiles hard-float and softfp `-O2`/`-Os` generated code, compares
the FreeRTOS-shaped PendSV instruction backbone, verifies the production,
lazy-validation, and no-MSP-rewind variants, and rejects instrumentation in the
three naked transfer handlers. It also links the exact selected cohort through
an application-owned expectation object outside the archive and verifies both
strong vector slots under normal and LTO `--gc-sections` links. This is still
software evidence only; no M55F hardware run has been recorded.

## Intentional Boundaries

FreeRTOS keeps FPU and MVE behind `configENABLE_*` branches in one source tree.
Fiber turns every saved-state difference into a concrete selected profile. The
separate `ARM_CM55F_NTZ` profile therefore has no runtime switch that can turn
MVE, MPU, TrustZone, PAC, BTI, or SecureContext on after the context layout has
been compiled.

Slices 1-4 prove:

- C and C++ type-only headers compile without CMSIS leakage;
- the exact C55F cohort is emitted from `fiber_port_context_cohort.h`;
- wrong M55 identity, missing FPU, non-FP compiler ABI, MVE, Secure CMSE, MPU,
  PAC, and BTI manifests fail closed;
- sealed boot creation and exact basic-frame construction have one port-owned
  implementation and retain the exact cohort;
- CPACR/FPCCR policy is read back under both eager and lazy settings without
  emitting FP/MVE code in construction/FPU setup;
- all eight forward operations, one strong `SVC_Handler`, one strong
  `PendSV_Handler`, and a closed reverse/integration surface;
- FreeRTOS-shaped scalar-FP `vstmdb r0!, {s16-s31}` /
  `vldmia r0!, {s16-s31}` save/restore ordering;
- normal/LTO archive extraction, retained external exact-cohort expectation,
  slots 11/14, section GC, and competing-handler negative links.

Hardware validation is deferred until matching Cortex-M55F Non-secure hardware
is available.
