# ARM_CM55_NTZ Non-secure FreeRTOS Parity

## Scope

This is the exact single-core, privileged, Non-secure, no-MPU, no-FPU, no-MVE,
no-SecureContext, no-TF-M, no-PAC, and no-BTI Cortex-M55 profile.
It is deliberately a concrete baseline rather than a runtime-configurable
combination of M55 features.

The profile is build-selected only:

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
selected include path = fiber/port/ARM_CM55_NTZ/non_secure
compiler = -mcpu=cortex-m55 -mthumb -mfloat-abi=soft
CMSIS __CORTEX_M = 55
```

The local FreeRTOS reference is pinned at:

```text
_reference/FreeRTOS-Kernel
a50edad08b29052631aa469d4df6e6ec7ff68878
```

| Pinned artifact | SHA-256 |
| --- | --- |
| `portable/GCC/ARM_CM55_NTZ/non_secure/port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` |
| `portable/GCC/ARM_CM55_NTZ/non_secure/portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` |
| `portable/GCC/ARM_CM55_NTZ/non_secure/portasm.h` | `185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C` |
| `portable/GCC/ARM_CM55_NTZ/non_secure/portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` |
| `portable/GCC/ARM_CM55_NTZ/non_secure/portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` |

## Frozen Cohort

```text
FreeRTOS configuration              Fiber trait / policy
----------------------------------  ---------------------------------------
configNUMBER_OF_CORES = 1           single selected-port runtime
configENABLE_MPU = 0                no MPU image or unprivileged API
configENABLE_TRUSTZONE = 0          Non-secure role without SecureContext
configENABLE_FPU = 0                no FP compiler ABI or extended frame
configENABLE_MVE = 0                no MVE register context
configENABLE_PAC = 0                no PAC-key context slots
configENABLE_BTI = 0                no BTI policy
```

The CPU still implements the ARMv8-M Security Extension. `NTZ` means this
profile does not own TrustZone context integration; it does not claim that the
hardware lacks TrustZone.

`FIBER_PORT_CONTEXT_ABI_PORT_ID` is ASCII `C55N` (`0x4335354E`). The feature
mask is `0x82`: Non-secure role plus one PSPLIM slot. This identity differs
from every M33 profile even though the no-feature software frame has the same
ten-word geometry.

## Context Frame

The selected port owns this stack-resident software frame, low address to high
address:

```text
PSPLIM
EXC_RETURN
r4-r11
hardware exception frame: r0-r3, r12, LR, PC, xPSR
```

The initial frame contains the ten-word software frame and eight basic hardware words.
The first SVC starts with the MSP-origin exception return `0xFFFFFFB8`; normal
PSP restore uses `0xFFFFFFBC`. The port preserves PSPLIM on every switch.

No MVE or FP register is saved by this profile. An M55F or M55 MVE-FP profile
must add the extended frame and `s16-s31` save/restore as an independent
cohort. It must not reuse this cohort with a different compiler ABI.

## Mapping

| FreeRTOS mechanism | Fiber implementation | Deliberate difference |
| --- | --- | --- |
| `pxPortInitialiseStack()` | `fiber_port_context_init()` then `fiber_port_init_context_frame()` | Builds the same ten-word software and basic hardware frame, then seals Fiber boot metadata. |
| `vStartFirstTask()` | `fiber_port_start_first_context()` | Common runtime chooses and publishes the first fiber before the port performs the one SVC transfer. |
| `vRestoreContextOfFirstTask()` | `SVC_Handler()` | Fiber validates SVC origin, current context, exact frame, PSPLIM, and CPU state before the equivalent restore. |
| `PendSV_Handler()` | `PendSV_Handler()` | Keeps FreeRTOS save/BASEPRI/select/restore mechanics but calls the frozen reverse ABI and the user scheduler instead of `vTaskSwitchContext()`. |
| `pxCurrentTCB` | assembly-load-only current-context slot | Common runtime owns publication; port assembly may load but never store it. |
| FreeRTOS ready lists / queues / SMP locks | external scheduler policy | Intentionally excluded from the CPU port. |

## Excluded Reference Paths

| Reference feature | Disposition |
| --- | --- |
| MPU PendSV, SVC syscall and region image | Separate future M55 MPU profile. |
| SecureContext companion | Separate future M55 SecureContext profile. |
| TF-M OS wrapper | Separate future M55 TF-M profile. |
| FPU or MVE extended context | Separate M55F/M55 MVE-FP profile. |
| PAC key save/restore and BTI policy | Separate exact PAC/BTI cohort after the relevant instructions and context slots are implemented. |
| SMP paths | Excluded. Fiber v2 selected ports are single-core. |

## Intentional Differences

| ID | Difference | Reason |
| --- | --- | --- |
| `FAP-COMMON-START` | Common runtime validates lifecycle and scheduler policy before port transfer. | Fiber has no FreeRTOS scheduler global. |
| `FAP-COMMON-SCHEDULER` | PendSV calls the reverse ABI scheduler selector. | Scheduler policy belongs above the context backend. |
| `FAP-COMMON-PROVENANCE` | Fiber validates boot seal, stack/frame bounds, vectors, priorities, and CPU state. | Additional integrity proof around equivalent ARM mechanics. |
| `FAP-COMMON-MASK-RESTORE` | BASEPRI writes use the selected-port synchronized vocabulary. | Preserves the frozen mask contract. |
| `FAP-M55-CONCRETE-MVE` | FreeRTOS requires `configENABLE_MVE` to be explicitly set; this profile instead hard-rejects compiler MVE and fixes `FIBER_PORT_HAS_MVE = 0`. | Feature selection must select a different port because MVE changes the saved-context ABI. |
| `FAP-M55-SINGLE-CORE` | FreeRTOS marks the M55 port as not SMP-validated; Fiber has one selected-port runtime and no SMP scheduler path. | CPU context mechanics remain single-core by contract. |
| `FAP-M55-FULL-FIRST-RESTORE` | SVC restores all fiber-owned callee-saved state and validates the frame. | FreeRTOS starts from its TCB-owned image; Fiber uses sealed context storage. |
| `FAP-M55-PSPLIM-READBACK` | PendSV validates PSPLIM and PSP after restore. | Detects a malformed context before exception return. |

## Required Evidence

The profile is accepted only when the following are green for `-O2` and `-Os`:

- pinned-reference hash verification;
- generated first-start, first-restore, and PendSV mechanism parity;
- exact `C55N` cohort/layout compile proof;
- selected type-only C/C++ header proof without CMSIS leakage;
- strong SVC/PendSV, archive extraction, vector slots 11/14, GC, and LTO;
- exact forward/reverse unresolved-symbol surfaces and negative links;
- wrong-core, FPU, MVE, CMSE, and wrong-architecture manifest rejection.

This ledger makes no hardware-validation claim. M55/STM32N6 FPU, MVE, MPU,
TrustZone, vector, and security behavior require their matching later profiles
and hardware evidence.
