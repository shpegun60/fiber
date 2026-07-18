# ARM_CM23_NTZ FreeRTOS Parity Ledger

## Reference

This directory is derived by line-by-line comparison with the pinned local
FreeRTOS Kernel checkout:

```text
commit: a50edad08b29052631aa469d4df6e6ec7ff68878
path:   portable/GCC/ARM_CM23_NTZ/non_secure
```

Reference file identities for this audit:

| File | SHA-256 |
| --- | --- |
| `portmacro.h` | `23709D8EE3DE532A8394EAD05414FCF4FB4B37C94B5288ACF1FB1B829AA3F50E` |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` |
| `portasm.h` | `185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C` |
| `portasm.c` | `E15BDECFD24AB85165B69E3496E6FA644E5FF9C36EFBB3FFE6975FD5D7C9806C` |
| `mpu_wrappers_v2_asm.c` | `09388DD5EF2BA4C0B03C151343D2660F9EAE8E683DF188588E0DD2C73995E1DE` |

`portmacrocommon.h` is recorded even though slice 1 imports only CPU/context
facts. Kernel scheduler, queue, tick, SMP, and MPU-wrapper policy is accounted
for below rather than copied implicitly.

## Exact Profile

Implementation slice 1 freezes one exact build manifest:

```text
CPU architecture:             ARMv8-M Baseline
core:                         Cortex-M23
runtime image:                Non-secure
TrustZone SecureContext:      disabled
MPU task isolation:           disabled
FPU/MVE/PAC/BTI:              absent
scheduler interrupt mask:     PRIMASK
VTOR:                         required
runtime source/handlers:      not implemented in this slice
hardware support claim:       none
```

This corresponds to the non-MPU, `configRUN_FREERTOS_SECURE_ONLY == 0`,
`configENABLE_TRUSTZONE == 0`, `configENABLE_FPU == 0`, and
`configENABLE_PAC == 0` branches of the reference source. A future MPU profile
is a distinct exact context cohort; it must not be enabled by changing a macro
inside this layout.

`ARM_CM23_NTZ` is build-selected only. Architecture auto-selection continues
to route ARMv8-M Baseline builds through `transitional_v8m` until concrete
context-init, SVC, PendSV, startup, archive, and ELF slices are complete.

## Saved Frame

FreeRTOS reserves a PSPLIM word even though Non-secure Cortex-M23 has no
Non-secure PSPLIM register. Fiber preserves that distinction exactly:

```text
low address / FiberContext.sp

word  0  PSPLIM placeholder, always zero in this exact profile
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

The resulting frozen geometry is:

```text
software frame:               10 words / 40 bytes
EXC_RETURN software index:    1
basic hardware frame:         8 words / 32 bytes
initial saved context:        72 bytes
maximum with alignment pad:   76 bytes
saved SP modulo 8:            0
```

The older transitional baseline frame has nine software words and is not
ABI-compatible with this concrete profile.

## Trait Mapping

| FreeRTOS fact | Fiber representation | Decision |
| --- | --- | --- |
| `portARCH_NAME = Cortex-M23` | `FIBER_PORT_NAME = ARM_CM23_NTZ` | Retained with exact profile identity. |
| `portHAS_ARMV8M_MAIN_EXTENSION = 0` | `FIBER_PORT_ARMV8M_BASELINE = 1` | Checked against compiler architecture. |
| `portARMV8M_MINOR_VERSION = 0` | layout version `0x00010001` | Frozen in the exact cohort. |
| `portSTACK_GROWTH = -1` | `fiber_portSTACK_GROWTH` | Retained. |
| `portBYTE_ALIGNMENT = 8` | `FIBER_PORT_STACK_ALIGNMENT = 8` | Retained. |
| `portINITIAL_XPSR` | `fiber_portINITIAL_XPSR` | Retained. |
| Non-secure `portINITIAL_EXC_RETURN` | `FIBER_PORT_INITIAL_EXC_RETURN = 0xFFFFFFBC` | Retained. |
| PSPLIM context word | `FIBER_PORT_HAS_PSPLIM_SLOT = 1` | Retained without register access. |
| `portUSE_PSPLIM_REGISTER = 0` | `FIBER_PORT_USES_PSPLIM_REGISTER = 0` | Mandatory for Non-secure M23. |
| PRIMASK critical envelope | `FIBER_PORT_MASK_PRIMASK` | BASEPRI/FAULTMASK are absent. |
| VTOR-based handler validation | `FIBER_PORT_HAS_VTOR = 1` | This exact profile requires VTOR. |
| Cortex-M23 has no FPU/MVE | FPU, extended FP, MVE traits are zero | Fail-closed compiler checks added. |
| NTZ source group | no SecureContext/PAC-key slots | No optional artifact in this profile. |
| context variants | exact port ID, layout, feature mask, cohort symbol | Stronger stale-object guard than a TCB convention. |

Kernel scalar types, tick width, ready-priority bitmaps, SMP locks, trace hooks,
queue/task macros, and `portMAX_DELAY` are scheduler/kernel policy. They do not
belong to the CPU transfer ABI and are intentionally not exported.

## Function Ledger

| FreeRTOS symbol/family | Fiber disposition |
| --- | --- |
| `pxPortInitialiseStack` | Future `fiber_port_context_init`; slice 1 freezes its exact frame output. |
| `vRestoreContextOfFirstTask`, `vStartFirstTask` | Future SVC-only first-start slice. |
| `SVC_Handler`, `vPortSVCHandler_C` | Future strong fail-closed selected-port handler; FreeRTOS scheduler/system-call dispatch is not copied. |
| `PendSV_Handler` | Future scheduler-hook save/select/restore slice using the ten-word frame. |
| `ulSetInterruptMask`, `vClearInterruptMask` | Future saved-PRIMASK helpers; unconditional IRQ unmask is not acceptable. |
| `xIsPrivileged`, `vRaisePrivilege`, `vResetPrivilege` | Not part of this privileged non-MPU profile's public API. |
| `xPortStartScheduler` | Split across the frozen eight-function runtime ABI; no FreeRTOS scheduler is imported. |
| `vPortYield`, `SysTick_Handler`, timer/tickless functions | Scheduler policy excluded; this runtime exposes explicit scheduling only. |
| `vPortEnterCritical`, `vPortExitCritical` | FreeRTOS kernel critical nesting excluded. |
| `xPortIsInsideInterrupt`, interrupt-priority validation | Startup/handler invariants stay port-owned; no ISR-safe public scheduler API exists yet. |
| `vPortConfigureInterruptPriorities` | Relevant SVC/PendSV/vector readbacks are required later; SysTick policy is excluded. |
| `prvSetupFPU`, PAC/BTI helpers | Compile-time rejected for Cortex-M23. |
| `prvSetupMPU`, `vPortStoreTaskMPUSettings`, authorization/ACL functions | Deferred to a separate exact MPU profile and optional policy ABI. |
| `vSystemCallEnter`, `vSystemCallExit`, MPU wrapper veneers | Deferred with the MPU profile; no decorative stubs. |
| `mpu_wrappers_v2_asm.c` | Excluded from this privileged profile and retained in the MPU backlog. |
| Secure allocation/free functions | Absent from NTZ; SecureContext requires a separate companion artifact. |
| `vPortEndScheduler` | Not meaningful for the one-shot Cortex-M startup contract. |

## Macro Families Not Imported

The following reference families are accounted for but intentionally remain
outside this port dictionary:

- task/queue/kernel scalar aliases and tick policy;
- ready-priority selection and SMP lock macros;
- SysTick setup, tickless idle, and ISR-driven preemption;
- FreeRTOS critical nesting and interrupt-safe API policy;
- MPU region descriptors, MAIR/RBAR/RLAR programming, ACLs, and wrappers;
- SecureContext allocation/free SVC numbers and Secure image gateways;
- kernel object authorization and system-call stack state;
- trace, stack overflow, and application hook routing.

They are scheduler, kernel, MPU-profile, or companion-image responsibilities.
Omission here does not permit a later capable profile to ignore them.

## Slice 1 Proofs

The compile matrix must prove:

- type-only C and C++ consumers compile without CMSIS;
- the exact Cortex-M23 build-selected manifest compiles;
- one exact ARMv8-M Baseline cohort symbol is emitted;
- the cohort includes NTZ ID, Non-secure EXC_RETURN, PSPLIM slot, Security
  Extension, and Non-secure role;
- software-frame size/index/modulo constants match the reference assembly;
- Secure CMSE, wrong core/profile, VTOR-less, and FPU manifests fail;
- global auto/profile selectors do not expose this incomplete runtime.

No runtime, archive, ELF-vector, LTO, or hardware claim is made by this slice.
