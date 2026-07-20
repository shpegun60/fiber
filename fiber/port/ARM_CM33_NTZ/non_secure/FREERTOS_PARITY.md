# ARM_CM33_NTZ Non-Secure Parity Ledger

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

Slice 1 freezes only the public storage, exact trait dictionary, context
cohort, and compile proof. It has no `fiber_port.c`, `fiber_port_boot.c`,
private header, handler, archive, or hardware claim. The global selector
continues to route ARMv8-M Mainline through `transitional_v8m`.

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

The construction slice must seed word 0 from the lower stack boundary, matching
FreeRTOS `pxEndOfStack`. Normal PendSV must subsequently save and restore the
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

| FreeRTOS symbol/family | Slice-1 disposition |
| --- | --- |
| `pxPortInitialiseStack` | Deferred to construction slice; frame order and all required slots are frozen above. |
| `vRestoreContextOfFirstTask` / `vStartFirstTask` | Deferred to SVC first-start slice. |
| non-MPU `PendSV_Handler` | Deferred to switching slice; it must save/restore live PSPLIM around the user scheduler bridge. |
| `SVC_Handler` / `vPortSVCHandler_C` | Deferred; Fiber will own one strong fail-closed SVC handler, not FreeRTOS syscall dispatch. |
| `ulSetInterruptMask` / `vClearInterruptMask` | Deferred to the BASEPRI scheduler-envelope implementation. |
| `xPortStartScheduler` | Deferred across the frozen eight-operation forward ABI; no FreeRTOS scheduler is imported. |
| `vPortYield`, SysTick, tickless idle | Excluded as scheduler policy. Fiber's core remains explicit/cooperative. |
| FreeRTOS critical nesting, queues, ready lists, SMP locks | Excluded as FreeRTOS kernel policy. This profile is single-core. |
| `prvSetupMPU`, `vPortStoreTaskMPUSettings`, ACL and wrappers | Deferred to a separate MPU selected profile and optional port API. |
| SecureContext allocation/free and Secure image gateways | Absent from NTZ; a companion or TF-M profile must own them. |
| PAC/BTI helpers | Deferred to a supported v8.1-M profile. |
| `mpu_wrappers_v2_asm.c` | Recorded and excluded; no decorative stub is provided. |

## Required Slice-1 Proofs

The compile matrix must prove:

- type-only C and C++ consumers compile without CMSIS;
- the exact build-selected Cortex-M33 manifest compiles;
- one exact ARMv8-M Mainline cohort symbol is emitted;
- the cohort includes `C33N`, `0xFFFFFFBC`, BASEPRI, FAULTMASK, PSPLIM, the
  PSPLIM slot, Security Extension, and Non-secure role;
- the ten-word frame, 72-byte initial geometry, and 76-byte maximum geometry
  remain fixed;
- `FIBER_PORT_RUNTIME_SELECTABLE == 0` until a complete runtime source group
  is proven;
- selector mode, Secure CMSE, VTOR-less, wrong-mainline-core, and FP ABI
  manifests fail;
- no runtime source or private implementation artifact appears in this slice;
- global auto/profile selection continues to route Mainline builds to
  `transitional_v8m`.

No runtime, archive, vector, LTO, or hardware claim is made by this slice.
