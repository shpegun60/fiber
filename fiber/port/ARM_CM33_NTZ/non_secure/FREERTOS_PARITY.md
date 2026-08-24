# ARM_CM33_NTZ Non-Secure Parity Ledger

Paired generated-object evidence is mandatory under
`../../../../FREERTOS_ASM_PARITY.md`. It currently covers only construction and
SVC first start; this ledger must not imply PendSV/runtime parity prematurely.

## Scope

This directory starts one exact build-selected Cortex-M33 NTZ profile from the
pinned FreeRTOS source group:

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

Slices 1-2 freeze the public storage, exact trait dictionary, context cohort,
sealed boot record, and initial-frame construction. Slice 3 adds only the
FreeRTOS-derived SVC first-start mechanism and the seven forward operations
needed before scheduling can begin. It deliberately does not add PendSV,
`fiber_port_runtime_schedule()`, archive activation, global selection, or a
hardware claim. The global selector continues to route ARMv8-M Mainline through
`transitional_v8m`.

The exact staged configuration is deliberately narrow:

```text
Cortex-M33 / ARMv8-M Mainline
single core
privileged fiber execution
configENABLE_MPU = 0
configENABLE_TRUSTZONE = 0
configRUN_FREERTOS_SECURE_ONLY = 0
configENABLE_FPU = 0
configENABLE_MVE = 0
configENABLE_PAC = 0
configENABLE_BTI = 0
```

`__MPU_PRESENT` may describe hardware capability, but it does not activate an
MPU ABI in this profile. A future MPU profile is a separate selected port and
optional policy ABI. Likewise, a hardware FPU may exist, but this exact ABI
rejects an FP compiler ABI and `__FPU_USED != 0`; an M33F frame is a separate
cohort.

## Frozen Layout

The non-MPU `pxPortInitialiseStack()` and `PendSV_Handler()` reference path
uses a ten-word software frame. The M33 Mainline version has an accessible
PSPLIM register, unlike the M23 NTZ profile.

```text
low address / FiberContext.sp

word  0  PSPLIM
word  1  EXC_RETURN = 0xFFFFFFBC
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

`fiber_port_context_init()` now seals the immutable boot record, initializes
the optional low-stack canary, and calls `fiber_port_init_context_frame()`.
That builder seeds word 0 from the lower stack boundary, matching FreeRTOS
`pxEndOfStack`, and verifies every initialized hardware and software-frame
word before returning. Normal PendSV must subsequently save and restore the
live PSPLIM value. The geometry is fixed now so later source cannot silently
turn an M33 frame into the M23 ignored-PSPLIM frame.

```text
software frame:               10 words / 40 bytes
EXC_RETURN software index:    1
basic hardware frame:         8 words / 32 bytes
initial saved context:        72 bytes
maximum with alignment pad:   76 bytes
saved SP modulo 8:            0
```

## Trait Mapping

| FreeRTOS fact | Fiber representation | Slice-1 decision |
| --- | --- | --- |
| `portARCH_NAME = Cortex-M33` | `FIBER_PORT_NAME = ARM_CM33_NTZ` | Exact profile identity, not an auto-selection claim. |
| `portHAS_ARMV8M_MAIN_EXTENSION = 1` | `FIBER_PORT_ARMV8M_MAINLINE = 1` | Requires compiler ARMv8-M Mainline target and CMSIS core 33. |
| `portSTACK_GROWTH = -1` | `fiber_portSTACK_GROWTH` | Retained. |
| `portBYTE_ALIGNMENT = 8` | `FIBER_PORT_STACK_ALIGNMENT = 8` | Retained. |
| `portINITIAL_XPSR` | `fiber_portINITIAL_XPSR` | Retained. |
| Non-secure `portINITIAL_EXC_RETURN` | `FIBER_PORT_INITIAL_EXC_RETURN = 0xFFFFFFBC` | Retained. |
| `portUSE_PSPLIM_REGISTER = 1` | `FIBER_PORT_USES_PSPLIM_REGISTER = 1` | Mandatory exact Mainline fact. |
| PSPLIM software word | `FIBER_PORT_HAS_PSPLIM_SLOT = 1` | Retained at word 0. |
| `ulSetInterruptMask` / `BASEPRI` | `FIBER_PORT_MASK_BASEPRI` and port-owned threshold | The threshold is part of the exact cohort. |
| Mainline `FAULTMASK` | `FIBER_PORT_HAS_FAULTMASK = 1` | Retained as a CPU fact. |
| VTOR handler lookup | `FIBER_PORT_HAS_VTOR = 1` | Exact profile requires VTOR. |
| `configENABLE_FPU = 0` | FPU and extended-frame traits are zero | FP compiler ABI is rejected. |
| `configENABLE_MVE = 0` | `FIBER_PORT_HAS_MVE = 0` | MVE compiler target is rejected. |
| NTZ no companion | no SecureContext/PAC-key/CONTROL slots | Future SecureContext, TF-M, PAC/BTI, and MPU roles are separate profiles. |
| context configuration variants | exact port ID, layout, traits, and cohort symbol | Strong stale-object separation. |

The traits distinguish hardware Security Extension capability from the selected
role: `FIBER_PORT_HAS_SECURITY_EXT == 1`,
`FIBER_PORT_RUNS_NONSECURE == 1`, and `FIBER_PORT_TARGETS_NS_BANK == 0`.
No fiber-owned SecureContext companion is present in this NTZ profile.

## Function And Macro Ledger

| FreeRTOS symbol/family | Current disposition |
| --- | --- |
| `pxPortInitialiseStack` | Implemented by `fiber_port_context_init()` plus `fiber_port_init_context_frame()`. Fiber adds a sealed boot record, address-map checks, canary, exact frame validation, and cohort retention around the same frame order. |
| `vRestoreContextOfFirstTask` / `vStartFirstTask` | Implemented by `fiber_port_start_first_context()` and the strong `SVC_Handler`. Fiber retains the same PSPLIM/EXC_RETURN/PSP/CONTROL transfer but validates the complete provenance and readbacks. |
| non-MPU `PendSV_Handler` | Deferred to switching slice; it must save/restore live PSPLIM around the user scheduler bridge. |
| `SVC_Handler` / `vPortSVCHandler_C` | Replaced by one strong fail-closed SVC handler dedicated to the configured first-start immediate. Generic syscall dispatch is not imported. |
| `ulSetInterruptMask` / `vClearInterruptMask` | Re-expressed by port-owned BASEPRI enter/exit helpers around `pick_next(NULL, user)`. Fiber additionally verifies PRIMASK, CONTROL, BASEPRI, and FAULTMASK preservation. |
| `xPortStartScheduler` | Split across the frozen forward ABI: prepare CPU state, select the first context through the user scheduler, publish it in common runtime, then enter SVC. No FreeRTOS scheduler is imported. |
| `vPortYield`, SysTick, tickless idle | Excluded as scheduler policy. Fiber's core remains explicit/cooperative. |
| FreeRTOS critical nesting, queues, ready lists, SMP locks | Excluded as FreeRTOS kernel policy. This profile is single-core. |
| `prvSetupMPU`, `vPortStoreTaskMPUSettings`, ACL and wrappers | Deferred to a separate MPU selected profile and optional port API. |
| SecureContext allocation/free and Secure image gateways | Absent from NTZ; a companion or TF-M profile must own them. |
| PAC/BTI helpers | Deferred to a supported v8.1-M profile. |
| `mpu_wrappers_v2_asm.c` | Recorded and excluded; no decorative stub is provided. |

## First-Start Assembly Parity

The pinned non-MPU/no-FPU FreeRTOS `portasm.c` first restore performs this
machine sequence:

```text
load current saved SP
ldm saved_sp!, {PSPLIM, EXC_RETURN}
msr PSPLIM, saved_psplim
mrs CONTROL; orr #2; msr CONTROL
skip the eight r4-r11 words
msr PSP, hardware_frame
msr BASEPRI, #0
bx EXC_RETURN
```

The normal FreeRTOS non-MPU PendSV restore later uses the fuller sequence:

```text
ldmia saved_sp!, {PSPLIM, EXC_RETURN, r4-r11}
msr PSPLIM, saved_psplim
msr PSP, hardware_frame
bx EXC_RETURN
```

Fiber slice 3 deliberately uses the full PendSV-shaped restore on first start:

```text
ldmia saved_sp!, {r2-r11}  ; r2=PSPLIM, r3=EXC_RETURN, r4-r11 restored
msr PSPLIM, r2
msr CONTROL, #2
msr PSP, hardware_frame
bx r3
```

| Pinned FreeRTOS assembly/C dispatch | Emitted Fiber assembly | Decision |
| --- | --- | --- |
| `ldr VTOR; ldr MSP; msr MSP` | MSP is read twice from the active VTOR during the one-shot plan, then `msr MSP` plus readback executes in the naked helper. | Same transfer with stable-source, alignment, RAM, and overlap checks. |
| `cpsie i; cpsie f; dsb; isb; svc` | Same ordered enable/barrier/SVC core after CONTROL, BASEPRI, FAULTMASK, and stale-PendSV checks. | Retained and hardened. |
| SVC assembly selects MSP or PSP from LR bit 2 | SVC requires exact `LR == 0xFFFFFFB8` and therefore exact Non-secure Thread/MSP/basic origin. | Narrowed intentionally: this handler is first-start only. |
| C dispatch reads `stacked_pc[-2]` and switches on the immediate | Fiber validates stacked xPSR/IPSR/PC, opcode high byte `0xDF`, and the exact immediate. | Stronger provenance; foreign SVC is rejected. |
| `ldm r0!, {r1-r2}` | `ldmia r0!, {r2-r11}` | Same PSPLIM/EXC_RETURN slots, plus restore of the seeded callee-saved frame. |
| `msr PSPLIM, r1` | `msr PSPLIM, r2; mrs PSPLIM; cmp` | Retained with synchronized readback. |
| `mrs CONTROL; orrs #2; msr CONTROL` | `movs #2; msr CONTROL; mrs CONTROL; cmp` | The Fiber precondition fixes privileged Thread/MSP state, so writing exact privileged PSP state is stricter than preserving unknown bits. |
| `adds r0, #32` | No add; full `ldmia` already advances over `r4-r11`. | Intentional full-frame consumption. |
| `msr PSP, r0` | `msr PSP, r0; mrs PSP; cmp` | Retained with readback. |
| `mov #0; msr BASEPRI, r0` | Same write plus DSB/ISB and readback. | Retained and hardened. |
| `bx r2` | exact saved-return check, then `bx r3` | Register allocation differs; EXC_RETURN semantics are identical. |

Restoring rather than skipping `r4-r11` preserves the constructor's seeded
`r9` value and makes first restore consume exactly the same ten-word software
frame that the later PendSV slice must consume. This is an intentional Fiber
strengthening, not an unnoticed divergence.

Around that reference core, Fiber additionally requires:

- privileged Non-secure Thread/MSP state before start;
- exact SVC-origin EXC_RETURN `0xFFFFFFB8`;
- an 8-byte-aligned basic MSP frame with Thumb xPSR, zero stacked IPSR, and no
  unexpected alignment padding;
- exact `0xDF` SVC opcode and `FIBER_SVC_START_NUMBER` immediate;
- one non-NULL, sealed, exact-cohort context selected under BASEPRI;
- exact saved EXC_RETURN `0xFFFFFFBC` after the assembly reload;
- readback of cleared BASEPRI, restored PSPLIM, `CONTROL[1:0] == 2`, and PSP;
- zero FAULTMASK before exception return;
- direct vector-slot ownership by the strong `SVC_Handler`.

Generated-disassembly proof is mandatory for this and every later port slice.
Source-token or compile-only parity is insufficient: the matrix must compare
the emitted SVC/start instructions and their order with the pinned FreeRTOS
sequence recorded above.

## Required Slice-3 Proofs

The compile matrix must prove:

- type-only C and C++ consumers compile without CMSIS;
- the exact build-selected Cortex-M33 manifest compiles;
- one exact ARMv8-M Mainline cohort symbol is emitted;
- the cohort includes `C33N`, `0xFFFFFFBC`, BASEPRI, FAULTMASK, PSPLIM, the
  PSPLIM slot, Security Extension, and Non-secure role;
- the ten-word frame, 72-byte initial geometry, and 76-byte maximum geometry
  remain fixed;
- the staged object group defines exactly one `fiber_port_context_init()`, one
  strong `SVC_Handler`, seven pre-scheduling forward operations, and no
  `PendSV_Handler` or `fiber_port_runtime_schedule()`;
- the frame builder assigns all 18 words in the FreeRTOS order, seeds PSPLIM
  from `stack_base`, preserves `r9`, and validates the completed frame;
- generated disassembly preserves the ordered SVC provenance checks, full
  ten-word restore, PSPLIM/CONTROL/PSP/BASEPRI readbacks, and final `bx`;
- a synthetic vector slot 11 resolves to the strong SVC handler, survives
  archive extraction and `--gc-sections`, while a competing strong SVC handler
  fails link;
- `FIBER_PORT_RUNTIME_SELECTABLE == 0` until PendSV, the eighth forward
  operation, a complete runtime archive, and ELF proof are present;
- selector mode, Secure CMSE, VTOR-less, wrong-mainline-core, and FP ABI
  manifests fail;
- no PendSV, schedule operation, switching archive, or global selection appears
  in this slice;
- global auto/profile selection continues to route Mainline builds to
  `transitional_v8m`.

The SVC mechanism is compile/disassembly/ELF covered only. No complete runtime,
PendSV, global-selection, or hardware claim is made by this slice.
