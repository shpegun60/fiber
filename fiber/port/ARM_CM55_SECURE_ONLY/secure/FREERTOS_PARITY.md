# ARM_CM55 Secure-Only Scheduler Reference Ledger

## Status

Staged scalar privileged Secure-only scheduler, 2026-11-02. Seven C/header files
implement the eight forward operations, strong handlers, exact storage/context
providers and sealed construction. `FIBER_PORT_RUNTIME_SELECTABLE=0`; there is
no auto route, complete-group acceptance or hardware claim.

This is a scheduler executing in the Secure image, not the separate
`ARM_CM55/secure` SecureContext companion. It has no NSC imports/exports, TF-M
adapter, Non-secure scheduler, MPU, FPU, MVE, PAC or BTI state. Those different
feature tuples remain separate roadmap work, not silently excluded support.

## Exact Tuple

```text
FreeRTOS pin: a50edad08b29052631aa469d4df6e6ec7ff68878
Actual sources: portable/GCC/ARM_CM55_NTZ/non_secure/{port.c,portasm.c}
configRUN_FREERTOS_SECURE_ONLY=1, configENABLE_TRUSTZONE=0
configENABLE_MPU/FPU/MVE/PAC/BTI=0
Compiler: -mcpu=cortex-m55 -mthumb -mfloat-abi=soft -mcmse
Selected architecture: FIBER_PORT_ARMV81M_MAINLINE=1
CMSIS core55, VTOR present, priority bits1..8, CMSE level3
Port identity C5SO: 0x4335534F
Private layout: 0x00010001; features: 0x02
Public storage: arm_cm55_secure_only revision1 regions0
Initial EXC_RETURN FD; first SVC origin F9
```

Ordinary register names address Secure state. `FIBER_TZ_NS` is rejected by
presence. Scalar M55 GCC can report `__ARM_ARCH_8M_MAIN__` instead of the newer
spelling; admission combines that compiler fact with the explicit architecture
and actual CMSIS core identity. Actual recorded build commands, not falsifiable
preprocessor declarations alone, establish the compiled CPU tuple.

Public storage is 76 bytes/alignment4, with `sp` at0 and 72-byte immutable boot
record at4. The initial 18-word/72-byte image is
`[PSPLIM, EXC_RETURN, r4-r11, hardware r0-r3/r12/LR/PC/xPSR]`. Architectural
alignment can add four bytes to a saved frame. Unlike the TrustZone NS-handler
Secure-origin case, these Secure-only handlers always restore their Secure
Thread frame; no absent-NS-frame skip applies.

## Source And Function Disposition

The audited scalar C3SO implementation is the mechanical Fiber baseline. No
selected-port source includes another concrete profile. The CPU-specific
reference for this new profile is the actual M55_NTZ Secure-only branch, not
the M33 object or its earlier test result.

| Artifact | Disposition |
| --- | --- |
| `fiber_port_types.h` | CMSIS-free public type, own `arm_cm55_secure_only` storage/cohort namespace; unchanged physical scalar geometry. |
| `fiber_port_boot_types.h` | Locally owned immutable record; same scalar field dictionary. |
| `fiber_portmacro.h` | Own M55/CMSE manifest, C5SO identity, local register/barrier/vector helpers, FD/F9 constants, exact offsets and geometry assertions. Reject foreign MPU manifests, compiler FP/MVE/PAC/BTI and NS-bank input. |
| `fiber_port_boot.h` | Private constructor/hash/validation declarations; no sibling include. |
| `fiber_port_private.h` | Private handlers/build/start/selection declarations and frozen directional ABI imports. No C current-slot declaration. |
| `fiber_port_boot.c` | Scalar construction, address/hash/structural/canary/frame checks and cold MSP planning retained. Constructor explicitly captures/forwards r9 and checks the constructed slot. |
| `fiber_port.c` | Scalar runtime, context/storage providers, first SVC, PendSV and protected reverse selection retained, using the Secure bank and own exact cohort. |

All Fiber function names and algorithms from the scalar baseline are retained:
the eight forward functions; `fiber_port_init_context_frame`; boot creation,
hash, fast/full checks; save/restore/current-pointer/canary/MSP validators;
environment and interrupt preconditions; exception/vector/priority setup;
PRIMASK/BASEPRI helpers; CPU-state capture/validation; first/next scheduler
bridges; and `fiber_port_start_first_context`, `SVC_Handler`, `PendSV_Handler`.
No scalar baseline function is removed or replaced by a decorative stub.
The ordinary C ABI preserves caller r9, while exact initial static-base
inheritance requires a consistently reserved-r9 whole-program ABI. Captured
constructor-to-builder consistency is enforced in either mode.

Reference operation mapping remains explicit:

| Reference responsibility | Fiber implementation / deliberate difference |
| --- | --- |
| `pxPortInitialiseStack` | `fiber_port_context_init` plus frame builder; complete deterministic GPR image and explicit r9 policy, sealed bounds/identity, own task-return target. |
| `vStartFirstTask` / `vRestoreContextOfFirstTask` | Validated MSP plan, owned SVC70, restore initialized r4-r11 instead of skipping their reference debug gaps; PSP selection via exception return. |
| `SVC_Handler` / `vPortSVCHandler_C` | Exact first-start immediate, instruction/provenance/environment validation; no generic kernel syscall dispatcher. |
| `PendSV_Handler` | Same scalar PSPLIM/EXC_RETURN/r4-r11 save/restore transfer, with validation before boot-field reads and a protected external scheduler bridge. |
| `vTaskSwitchContext` / current TCB | Frozen reverse selection/publication and assembly-read-only common current slot; common owns policy/lifecycle. |
| BASEPRI/PRIMASK critical operations | Selected local synchronized register helpers, exact mask/CPU-state readback. |
| SysTick/tickless/kernel-ready/heap/task-delete mechanisms | Not imported into CPU/runtime ABI; scheduler/timer/allocation policy belongs above this five-operation cooperative runtime. |
| MPU, FP, MVE, TrustZone companion, PAC/BTI conditionals | Rejected in this exact tuple; not erased from the roadmap or purportedly covered by scalar tests. |

## Evidence And Remaining Gates

The maintained `tools/test_cm55_secure_only.ps1` compiles the actual pinned
M55 reference `port.c` and `portasm.c` and real Fiber runtime/boot at O2/Os.
It passes 117 numeric/storage/manifest/symbol/ordered-transfer checks, including
36 exact-diagnostic negatives. These include a real wrong-core CMSIS header,
VTOR absence, invalid priority widths and alternate PAC predefines, in addition
to security/FP/MVE/MPU policy rejection. C/C++ allocating public storage compiles without
CMSIS. Both strong handlers, exactly eight forward definitions and the exact
unresolved reverse/integration surface are checked.

```text
Focused evidence:
  %TEMP%/cm55-secure-only-0a9b0ab5d66149d3901af5c5ee677096
Parent rehash: 337 recorded entries, zero mismatches
Exact 40 repository-local inputs:
  %TEMP%/fiber-qualified-repo-inputs-a19fc5eb19c84606ae3c229936f50514
ZIP SHA-256:
  9C5CECDB38C41824470BBDBCBC3C1D8051E3D153D7D3815DC5B5C8324F945EAF
```

Ordered transfer subsets are not closed whole-body parity. Actual Secure-only
first SVC/PendSV execution, normal/LTO complete common-runtime archive/ELF,
weak-startup extraction, vector/cohort/reverse/stale/duplicate negatives,
adversarial compiler flags, dual-r9 ABI modes and compiled oracle controls
remain required before runtime promotion. AN547 execution is a distinct gate;
no M33/AN505 receipt is relabeled as M55 evidence. Global all-optimization,
final-LTO paired parity and hardware qualification remain separate.
