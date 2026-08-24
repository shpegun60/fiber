# ARM_CM23_NTZ FreeRTOS Parity Ledger

Paired generated-object evidence for the ten-word NTZ save/restore path is
mandatory under `../../../../FREERTOS_ASM_PARITY.md`; this ledger supplies the
port-specific source and placeholder-PSPLIM classification.

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

Implementation slices 1-5 freeze one exact build manifest:

```text
CPU architecture:             ARMv8-M Baseline
core:                         Cortex-M23
runtime image:                Non-secure
TrustZone SecureContext:      disabled
MPU task isolation:           disabled
FPU/MVE/PAC/BTI:              absent
scheduler interrupt mask:     PRIMASK
VTOR:                         required
runtime source:               constructor, SVC first start, PendSV switch
SVC handler:                  strong, fail-closed, implemented
PendSV handler:               strong, fail-closed, implemented
forward ABI:                  all eight frozen operations
hardware support claim:       none
```

This corresponds to the non-MPU, `configRUN_FREERTOS_SECURE_ONLY == 0`,
`configENABLE_TRUSTZONE == 0`, `configENABLE_FPU == 0`, and
`configENABLE_PAC == 0` branches of the reference source. A future MPU profile
is a distinct exact context cohort; it must not be enabled by changing a macro
inside this layout.

`ARM_CM23_NTZ` is build-selected only. Architecture auto-selection deliberately
continues to route ARMv8-M Baseline builds through `transitional_v8m`; concrete
M23 promotion is a separate selector-policy decision, not an implication of
this profile's archive/ELF proof.

## Saved Frame

FreeRTOS reserves a PSPLIM word even though Non-secure Cortex-M23 has no
Non-secure PSPLIM register. Its initial-stack constructor seeds the slot with
`pxEndOfStack`; the Non-secure restore path consumes but ignores the value, and
later PendSV saves write zero into the same slot. Fiber preserves this lifecycle
exactly: the initial frame stores `FiberPortBoot.stack_base`, while every
ordinary NTZ PendSV save stores zero and never accesses PSPLIM.

```text
low address / FiberContext.sp

word  0  ignored PSPLIM slot, initially stack_base; zero after first save
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

## First Start And PendSV

Slice 3 implements SVC first start by adapting the pinned FreeRTOS
`vStartFirstTask` and non-MPU `vRestoreContextOfFirstTask` paths. It is stricter
than the reference dispatcher:

- startup requires privileged Thread mode on MSP with `PRIMASK == 0`;
- the active VTOR slot 11 must resolve directly to the selected strong
  `SVC_Handler`, and SVCall priority is written and read back as zero; both are
  revalidated under PRIMASK after first scheduler selection;
- stale PendSV state is cleared before first SVC, and the selected strong
  PendSV handler plus priority are validated along with SVC;
- SVC provenance must be the exact Non-secure Thread/MSP/basic
  `EXC_RETURN = 0xFFFFFFB8`;
- the stacked MSP frame, xPSR, PC, SVC opcode, and immediate are validated
  before the selected context is read;
- scheduler selection runs under a saved-PRIMASK envelope and must preserve
  `PRIMASK` and `CONTROL`;
- the selected context is fully validated before restore;
- `CONTROL` is set and read back as privileged Thread/PSP (`2`), matching the
  ARMv8-M reference first restore; exact `EXC_RETURN` remains the authority for
  the actual exception unstack and security/stack provenance;
- restore consumes but never writes the ignored PSPLIM word, restores
  `r4-r11`, programs PSP at word 10, and returns through exact
  `EXC_RETURN = 0xFFFFFFBC`.

Slice 4 adapts the non-MPU `PendSV_Handler` from `portasm.c`. Its ordinary save
and restore geometry matches the reference exactly:

- PendSV must arrive with exact Non-secure Thread/PSP/basic
  `EXC_RETURN = 0xFFFFFFBC` and an 8-byte-aligned PSP;
- Fiber validates the common-owned current context before any assembly metadata
  load, then proves the software frame and basic hardware frame fit before
  reading stacked xPSR; it subsequently proves the optional stacked-alignment
  pad fits in the declared stack;
- it stores ten words in reference order: zero for the inaccessible PSPLIM
  slot, `EXC_RETURN`, `r4-r7`, and staged `r8-r11`;
- the user scheduler hook replaces `vTaskSwitchContext()` under a PRIMASK
  envelope and must preserve `PRIMASK` and `CONTROL`; Fiber validates and
  publishes the selected restore target through the frozen reverse ABI;
- restore adds 24 bytes from word 0 to staged `r8-r11`, programs PSP at
  hardware-frame word 10, then subtracts 36 bytes to load word 1
  (`EXC_RETURN`) together with `r4-r7`.

No M23 NTZ path emits `mrs` or `msr psplim`. This is compile/generated-code
evidence for one exact build-selected profile only; auto/profile selection does
not select it, and it has no Cortex-M23 hardware claim.

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
| `pxPortInitialiseStack` | `fiber_port_context_init` plus `fiber_port_init_context_frame`; initial slot is `stack_base`, all frame words are explicitly seeded, and the boot record is sealed and revalidated. |
| `vRestoreContextOfFirstTask`, `vStartFirstTask` | Adapted as the SVC first start described above, with exact frame restore and stronger provenance/readback checks. |
| `SVC_Handler`, `vPortSVCHandler_C` | Replaced by one strong fail-closed handler for the start service only; FreeRTOS scheduler/system-call dispatch is not copied. |
| `PendSV_Handler` | One strong fail-closed selected-port handler. It saves the exact ten-word non-MPU NTZ frame, calls the scheduler bridge under PRIMASK, and restores the selected frame. |
| `ulSetInterruptMask`, `vClearInterruptMask` | Adapted as private saved-PRIMASK helpers around startup setup and first scheduler selection; state is restored and read back. |
| `xIsPrivileged`, `vRaisePrivilege`, `vResetPrivilege` | Not part of this privileged non-MPU profile's public API. |
| `xPortStartScheduler` | Startup portion is split across the frozen eight-operation forward ABI. No FreeRTOS scheduler is imported. |
| `vPortYield`, `SysTick_Handler`, timer/tickless functions | Scheduler policy excluded; this runtime exposes explicit scheduling only. |
| `vPortEnterCritical`, `vPortExitCritical` | FreeRTOS kernel critical nesting excluded. |
| `xPortIsInsideInterrupt`, interrupt-priority validation | Startup/handler invariants stay port-owned; no ISR-safe public scheduler API exists yet. |
| `vPortConfigureInterruptPriorities` | PendSV is configured/read back as the lowest priority, SVCall as priority zero, and both direct vector slots are validated. SysTick policy is excluded. |
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

## Slices 1-5 Proofs

The compile matrix must prove:

- type-only C and C++ consumers compile without CMSIS;
- the exact Cortex-M23 build-selected manifest compiles;
- one exact ARMv8-M Baseline cohort symbol is emitted;
- the cohort includes NTZ ID, Non-secure EXC_RETURN, PSPLIM slot, Security
  Extension, and Non-secure role;
- software-frame size/index/modulo constants match the reference assembly;
- Secure CMSE, wrong core/profile, VTOR-less, and FPU manifests fail;
- the source group emits exactly eight forward-ABI operations;
- the initial constructor writes all 18 words in exact low-to-high order,
  including `stack_base`, `EXC_RETURN`, `r4-r11`, and the hardware frame;
- boot metadata is sealed, hashed, checked against exact context identity, and
  address-map validated during context creation;
- one strong `SVC_Handler`, one strong `PendSV_Handler`, and exactly one start
  SVC instruction are emitted;
- generated code retains exact Non-secure SVC provenance construction,
  `CONTROL = 2`, PSP programming, and the `+24/-36` Thumb-1 restore geometry;
- generated PendSV code validates the current context before metadata access,
  saves the exact ten-word frame, runs the scheduler under PRIMASK, restores
  through the exact `+24/-36` geometry, and contains no PSPLIM instruction;
- reverse-ABI anchor, scheduler selection, and assembly-only current-slot
  dependencies are exact and no unexpected common helper is imported;
- a static archive containing common plus the selected M23 source group links
  with the unchanged portable application in normal and LTO modes;
- an application-owned external expectation retains one exact cohort relocation,
  and a mismatched cohort cannot link;
- the final ELF retains one exact strong cohort identity, strong handlers in
  vector slots 11 and 14, and the expectation section under `--gc-sections`;
- a competing strong SVC/PendSV definition fails the link deliberately;
- global auto/profile selectors deliberately continue to route ARMv8-M
  Baseline through `transitional_v8m`.

The archive/ELF/LTO proof activates this exact build-selected profile only. It
does not make a Cortex-M23 hardware claim and does not promote Secure, MPU,
SecureContext, or TF-M behavior into this non-MPU Non-secure ABI.
