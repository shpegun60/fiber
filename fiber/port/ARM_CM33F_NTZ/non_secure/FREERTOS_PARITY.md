# ARM_CM33F_NTZ Non-Secure Parity Ledger

Slices 1-4 freeze the exact FPU-capable context identity and initial frame,
then add FPU setup, strict SVC first start, and the complete FP-aware PendSV
save/select/restore path. Paired generated-assembly proof is mandatory under
`../../../../FREERTOS_ASM_PARITY.md`; this remains a build-selected,
hardware-unvalidated profile.

## Pinned Reference

```text
_reference/FreeRTOS-Kernel
  commit: a50edad08b29052631aa469d4df6e6ec7ff68878
  portable/GCC/ARM_CM33_NTZ/non_secure/
```

Reference artifact hashes:

```text
port.c:                  BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A
portmacro.h:             F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B
portmacrocommon.h:       324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2
portasm.c:               DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5
mpu_wrappers_v2_asm.c:   00B42952962E48F8C9421F5EC66BBCE9E02465760560728FEE2D743CE1706F3E
```

The selected reference branches are:

```text
configENABLE_MPU = 0
configENABLE_TRUSTZONE = 0
configRUN_FREERTOS_SECURE_ONLY = 0
configENABLE_FPU = 1
configENABLE_MVE = 0
configENABLE_PAC = 0
configENABLE_BTI = 0
single core
privileged Non-secure execution
```

Hard-float and softfp compiler ABIs are both accepted when they emit FP
instructions and CMSIS reports `__FPU_PRESENT == 1` and `__FPU_USED == 1`.
The procedure-call ABI does not alter the saved exception frame. A soft ABI
that emits no FP instructions belongs to the no-FPU `ARM_CM33_NTZ` profile.

## Initial And Dynamic Frames

FreeRTOS `pxPortInitialiseStack()` is independent of `configENABLE_FPU`. A new
task has not used FP state, so it starts with the same basic 18-word image as
the no-FPU profile:

```text
low address / FiberContext.sp

word  0  PSPLIM
word  1  EXC_RETURN = 0xFFFFFFBC, basic frame
word  2  r4
word  3  r5
word  4  r6
word  5  r7
word  6  r8
word  7  r9
word  8  r10
word  9  r11
word 10  r0       hardware frame
word 11  r1
word 12  r2
word 13  r3
word 14  r12
word 15  LR
word 16  PC
word 17  xPSR

high address
```

When a running fiber uses FP, hardware clears EXC_RETURN bit 4 and stacks the
18-word low FP extension. FreeRTOS PendSV then places `s16-s31` between the
ten-word core software frame and that hardware frame:

```text
basic saved context:
  [PSPLIM][EXC_RETURN][r4-r11] + basic hardware frame
  40 + 32 = 72 bytes, plus an optional 4-byte alignment pad

extended saved context:
  [PSPLIM][EXC_RETURN][r4-r11] + [s16-s31] + extended hardware frame
  40 + 64 + 104 = 208 bytes, plus an optional 4-byte alignment pad

maximum bounded context: 212 bytes
basic EXC_RETURN:         0xFFFFFFBC
extended EXC_RETURN:      0xFFFFFFAC
saved SP modulo 8:        0
```

Construction therefore allocates 72 bytes, while stack admission reserves the
212-byte dynamic maximum. Initial construction must not seed or touch an FP
register. The complete construction call graph is compiled
`general-regs-only`, so it is safe before the later runtime slice enables
CP10/CP11 and configures FPCCR. The private boot constructor fills its output
record in place, leaving no `memcpy`/`memset` dependency that could hide an
unconstrained pre-FPU library call.

## Trait Mapping

| FreeRTOS fact | Fiber representation | Decision |
| --- | --- | --- |
| `portARCH_NAME = Cortex-M33` | `FIBER_PORT_NAME = ARM_CM33F_NTZ` | Exact build-selected identity. |
| `portHAS_ARMV8M_MAIN_EXTENSION = 1` | `FIBER_PORT_ARMV8M_MAINLINE = 1` | Compiler and CMSIS core must both identify Cortex-M33 Mainline. |
| `portSTACK_GROWTH = -1` | `fiber_portSTACK_GROWTH` | Retained. |
| `portBYTE_ALIGNMENT = 8` | `FIBER_PORT_STACK_ALIGNMENT = 8` | Retained. |
| `portINITIAL_XPSR` | `fiber_portINITIAL_XPSR` | Retained. |
| `portINITIAL_EXC_RETURN` | `0xFFFFFFBC` | New contexts always start basic. |
| EXC_RETURN bit 4 | exact accepted set `0xFFFFFFBC/0xFFFFFFAC` | Dynamic basic/extended discriminator. |
| `portUSE_PSPLIM_REGISTER = 1` | `FIBER_PORT_USES_PSPLIM_REGISTER = 1` | PSPLIM remains word 0. |
| `configENABLE_FPU = 1` | FPU and extended-frame traits are one | Requires silicon, CMSIS, and compiler agreement. |
| `configENABLE_MVE = 0` | `FIBER_PORT_HAS_MVE = 0` | MVE target is rejected. |
| `configENABLE_PAC/BTI = 0` | PAC/BTI traits are zero | Known compiler feature macros are rejected. |
| `configENABLE_MPU = 0` | no MPU image or extension API | MPU selector macros are rejected. |
| NTZ role | security extension present, running Non-secure | Secure CMSE builds are rejected. |
| dynamic FP software block | `FIBER_PORT_HIGH_FP_SOFTWARE_BYTES = 64` | Reserved only in the maximum bound. |
| dynamic FP hardware block | `FIBER_PORT_EXC_FP_EXT_BYTES = 72` | Reserved only when EXC_RETURN bit 4 is zero. |
| exact context cohort | ID `C3FN`, layout v1, feature mask `0x83` | Distinct from no-FPU `C33N/0x82`. |

## Function And Macro Ledger

| FreeRTOS symbol or family | Disposition through slice 4 |
| --- | --- |
| `pxPortInitialiseStack()` | Implemented by `fiber_port_context_init()` plus `fiber_port_init_context_frame()`. The six architecturally visible seed values have identical offsets; Fiber additionally zeroes the unspecified core slots, preserves r9, seals metadata, checks address maps, installs a canary, and validates every word. |
| `configENABLE_FPU` | Replaced by exact selected-port gates over `__FPU_PRESENT`, `__FPU_USED`, and `__ARM_FP`; it is not a user runtime toggle inside this profile. |
| `portCPACR`, CP10/CP11 constants | Reimplemented as the selected-port `fiber_portCPACR_REG` and exact full-access mask. |
| `portFPCCR`, ASPEN, LSPEN | Reimplemented as selected-port register bits; ASPEN is always set and LSPEN follows `FIBER_FPU_LAZY`. |
| `prvSetupFPU()` | Reimplemented by `fiber_port_fpu_prepare()`. Fiber adds DSB/ISB around writes, CPACR/FPCCR readback, and rejects active lazy preservation (`LSPACT`) before first start. |
| non-MPU `PendSV_Handler()` FP test | Implemented by exact basic/extended `EXC_RETURN` acceptance and bit-4 conditional save/restore. |
| `vstmdbeq {s16-s31}` / `vldmiaeq {s16-s31}` | Implemented as branch-equivalent `vstmdb`/`vldmia` operations, preserving the same placement around the ten-word core frame. |
| `vRestoreContextOfFirstTask()` / SVC | Reimplemented by `fiber_port_start_first_context()` and one strong fail-closed `SVC_Handler`. The first context must be basic, `CONTROL.FPCA` is cleared before SVC, and the handler verifies FPU policy again before restore. |
| MPU setup, wrappers, ACL | Excluded; a separate selected MPU profile owns them. |
| SecureContext and TF-M gateways | Excluded; a separate selected role and optional ABI own them. |
| MVE, PAC, BTI helpers | Excluded and fail closed for this exact profile. |
| SysTick, tickless idle, queues, ready lists, SMP locks | Excluded as scheduler/kernel policy. |
| `mpu_wrappers_v2_asm.c` | Audited and excluded; no stub is exported. |

## Construction Proof

The matrix compiles the exact profile with hard-float and softfp GCC flags at
`-O2` and `-Os`. It checks the 18 assignments and their order, the 72-byte
initial displacement, the 212-byte maximum, and the exact cohort identity. The
constructor is rejected if it contains any VFP/MVE instruction. The complete
runtime group must define all eight forward operations and exactly one strong
`SVC_Handler` and `PendSV_Handler`.

The source-level difference from FreeRTOS is intentional and recorded:

```text
FreeRTOS initializes PSPLIM, EXC_RETURN, r0, LR, PC, and xPSR and leaves the
remaining synthetic slots unspecified unless portPRELOAD_REGISTERS is enabled.

Fiber writes the same six values at the same offsets, zeroes every other slot,
and seeds r9 from the live ABI register. Frame size and exception semantics are
unchanged.
```

## FPU Setup And SVC First Start

The pinned FreeRTOS `prvSetupFPU()` grants CP10/CP11 full access and sets
`FPCCR.ASPEN|LSPEN` before it restores the first task from the start SVC.
Fiber performs the equivalent port-owned CPACR/FPCCR setup during its
one-shot runtime preparation. The difference is intentional:

```text
FreeRTOS:
  CPACR full access
  ASPEN = 1
  LSPEN = 1

Fiber:
  CPACR full access with readback
  ASPEN = 1 with readback
  LSPEN = FIBER_FPU_LAZY (0 or 1) with readback
  LSPACT = 0 before the first Thread-mode restore
```

FreeRTOS `vStartFirstTask()` rewinds MSP from VTOR, enables faults and IRQs,
then executes its start SVC. The Fiber helper retains that transfer but also
clears `CONTROL.FPCA`, clears stale PendSV, clears BASEPRI, verifies FAULTMASK,
and routes only the configured immediate to a strict strong `SVC_Handler`.
The handler accepts only the exact Non-secure Thread/MSP/basic SVC origin,
verifies the basic MSP frame/opcode/immediate, checks CPACR/FPCCR again,
restores the ten-word basic software frame, readbacks PSPLIM/CONTROL/PSP, and
returns through `0xFFFFFFBC`.

Generated first-start and SVC code is checked at `-O2` and `-Os` in hard-float
and softfp builds. These checks compare the retained FreeRTOS transfer core and
record the added provenance/readback behavior under `FAP-CM33F-SVC-START`.

## FP-Aware PendSV

The pinned non-MPU FreeRTOS `PendSV_Handler()` reads PSP, tests
`EXC_RETURN.bit4`, conditionally saves `s16-s31`, then writes exactly:

```text
[PSPLIM][EXC_RETURN][r4-r11]
```

After `vTaskSwitchContext()` it restores that core frame, conditionally restores
`s16-s31`, restores PSPLIM and PSP, and returns through the restored
EXC_RETURN. Fiber preserves that context geometry and order. The selected
handler differs only in hardening and scheduler ownership:

```text
exact PendSV/Non-secure Thread/PSP/basic-or-extended provenance
current-context preflight before context metadata reads
dynamic lower and upper bounds for basic or extended hardware/software frames
live PSPLIM equals current stack base before save
frozen scheduler bridge under selected BASEPRI
selected-context restore validation and common-owned current publication
PSPLIM, PSP, mask, and control readback before exception return
```

The generated parity proof covers the basic and extended FP branches at `-O2`
and `-Os`. It requires `vstmdb r0!, {s16-s31}` before the ten-word software
frame and `vldmia r0!, {s16-s31}` after it. Both hard-float and softfp builds
are included; the frame ABI is independent of the ordinary C procedure-call
ABI.

`LSPACT` is rejected during first start, where no interrupted FP Thread state
is valid. It is deliberately allowed while PendSV validates/saves a running
fiber: the first VFP instruction may complete a valid lazy preservation.

Normal and LTO archive/ELF proofs retain both selected strong handlers in
synthetic vector slots 11 and 14, preserve the exact context cohort, and reject
competing strong handler ownership.

## Fail-Closed Boundary

The profile remains outside global auto/profile selection so an unrelated
ARMv8-M build cannot select it accidentally. When explicitly build-selected it
defines `FIBER_PORT_RUNTIME_SELECTABLE == 1` and provides all eight frozen
forward operations plus strong `SVC_Handler` and `PendSV_Handler`.

The profile deliberately still excludes MPU, SecureContext, TF-M, MVE, PAC,
and BTI APIs. Those require distinct exact profiles and optional ABI artifacts.
Hardware support is not claimed until a real Cortex-M33F Non-secure target
passes the first-start, basic/extended FP switching, vector, priority, and
long-run stress suite.
