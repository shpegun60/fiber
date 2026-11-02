# ARM_CM33 Secure-Only Scheduler Reference Ledger

## Status

Staged scalar, privileged, non-MPU Secure-only scheduler, 2026-11-02.
The seven C/header files implement the eight forward operations, context
construction, strong SVC/PendSV, reverse ABI v1 and exact context/storage
providers. `FIBER_PORT_RUNTIME_SELECTABLE=0` remains fixed pending complete-group
qualification. There is no global automatic route or hardware claim.

This directory is a **scheduler in a Secure image**, not the SecureContext
companion in `ARM_CM33/secure`. It neither imports nor exports that companion's
NSC API. No Non-secure scheduler, TF-M or SecureContext allocation is implied.
This adds the baseline scalar/unprotected Secure-only tuple to the roadmap;
it does not exclude the pending FP or protected Secure-only tuples.

## Exact Reference Tuple

```text
FreeRTOS: a50edad08b29052631aa469d4df6e6ec7ff68878
Source: portable/GCC/ARM_CM33_NTZ/non_secure
configRUN_FREERTOS_SECURE_ONLY = 1
configENABLE_TRUSTZONE = 0
configENABLE_MPU = 0
configENABLE_FPU = 0
configENABLE_MVE = 0
configENABLE_PAC = 0
configENABLE_BTI = 0
Compiler: cortex-m33, Thumb, soft float, -mcmse
CMSIS: Cortex-M33, VTOR present
Focused paired scheduler mask: 0x80 on both sides
```

The reference directory name does not determine the executing Security state.
The actual `port.c` Secure-only branch selects `portINITIAL_EXC_RETURN =
0xFFFFFFFD`; ordinary register names address the executing Secure bank.

## Adaptation From The Audited Scalar Baseline

The implementation starts from the current audited Fiber `ARM_CM33_NTZ`
source group, not from an unreviewed copy of the kernel. Its seven C/header
files are reproduced locally; the selected port has no include dependency on
another concrete profile. Shared compiler/diagnostic/cohort headers and the
frozen generic forward/reverse ABI remain intentional dependencies.

| File | Meaning and modification |
| --- | --- |
| `fiber_port_types.h` | Same public 76-byte saved-SP/boot storage; independent `arm_cm33_secure_only_v1_r0` allocating-consumer identity and include/name namespace. No CMSIS dependency. |
| `fiber_port_boot_types.h` | Same 72-byte immutable boot fields; independent type-header namespace and Secure-only ownership comment. |
| `fiber_port_boot.h` | Same boot interface; own include guard and canonical sensitive/general-register declarations. |
| `fiber_port_private.h` | Same private declarations and generic ABI imports; independent guard, plus an explicit initial-r9 argument and sensitive/general-registers-only builder attributes. |
| `fiber_port_boot.c` | Same structural/hash/address/canary/MSP/restore logic using the Secure bank. Construction captures r9 before integration calls, forwards that value explicitly, and checks its saved slot. |
| `fiber_port.c` | Same CPU envelope, reverse ABI and strong handlers; role/name substitutions plus four exact exception encodings. The frame builder consumes the captured r9 argument instead of reading a later C callee's temporary register value. No new common-runtime branch. |
| `fiber_portmacro.h` | Local dictionary, strict Secure-CMSE admission, independent identity, role/EXC_RETURN changes, staging gate, foreign MPU/FP/MVE/PAC/BTI rejection. |

### Changed Dictionary Entries

| Entry | Baseline to Secure-only change |
| --- | --- |
| Port name, include guards and `FIBER_PORT_CM33_*` storage assertions | Independent `ARM_CM33_SECURE_ONLY` namespace; no stale NTZ name is an exported layout macro. |
| `FIBER_PORT_STORAGE_COHORT_PORT` | `arm_cm33_ntz` to `arm_cm33_secure_only`; revision 1 and region count 0 remain. |
| `FIBER_PORT_CONTEXT_ABI_PORT_ID` | C33N to C3SO, `0x4333534F`; layout generation `0x00010001`. |
| `fiber_portINITIAL_EXC_RETURN` | `0xFFFFFFBC` to `0xFFFFFFFD`, matching the actual reference Secure-only constructor branch. |
| `fiber_portSVC_ORIGIN_EXC_RETURN` | `0xFFFFFFB8` to `0xFFFFFFF9`, Secure Thread/MSP/basic first-start provenance. |
| `FIBER_PORT_RUNS_NONSECURE` | 1 to 0. `HAS_SECURITY_EXT=1` and `TARGETS_NS_BANK=0` remain; ordinary names now address Secure state, not the NS bank. |
| Feature mask | Remove RUNS_NONSECURE bit; retain PSPLIM slot, exact mask `0x02`. No SecureContext slot is added. |
| `FIBER_PORT_RUNTIME_SELECTABLE` | Staging 0 until complete-group proofs, not an application override. |
| Compiler admission | Require CMSE level exactly 3. Reject the obsolete NS-bank selection input even when defined as zero. Reject foreign MPU region manifests by presence and reject FP/MVE/PAC/BTI inputs. |

All other scalar frame, BASEPRI/PRIMASK, vector, priority, barrier, alignment,
stack extent and public offset macros retain their scalar-baseline definitions.
The initial image is 18 words/72 bytes: `[PSPLIM, EXC_RETURN, r4-r11]` followed
by the eight hardware words. Maximum saved extent is 76 bytes with padding.
The initial register image and intended incoming-r9 policy are unchanged.
The explicit constructor-to-builder seed keeps construction internally
consistent across integration calls. It does not recover an outer C caller's
ordinary-AAPCS r9 temporary. The existing platform/static-base inheritance
contract applies only when the integration ABI reserves r9 throughout the
common/port/hook call graph. Qualification therefore separates ordinary-ABI
callee-save/frame/switch tests from reserved-r9 exact initial/first-restore
seed tests, including LTO and hostile builds in both modes. The earlier
ordinary-mode M55 TF-M seed-oracle failures remain recorded, not reclassified
as proof of a reserved/static-base ABI violation.

### Function Inventory

No baseline function is removed or renamed. The following local functions
retain their scalar-baseline algorithm, substituting the local dictionary and
Secure bank. These are Fiber mechanisms, not a claim that every name exists
in FreeRTOS:

```text
fiber_port_init_context_frame
fiber_port_runtime_memory_barrier
fiber_port_panic_wait
fiber_port_require_scheduler_configuration_environment
fiber_port_runtime_schedule
fiber_port_primask_save_disable
fiber_port_primask_restore
fiber_port_validate_svc_vector
fiber_port_validate_pendsv_vector
fiber_port_probe_implemented_priority_mask
fiber_port_count_implemented_priority_bits
fiber_port_validate_basepri_priority_policy
fiber_port_validate_exception_start_configuration
fiber_port_prepare_exception_start
fiber_port_runtime_prepare_start
fiber_port_capture_scheduler_cpu_state
fiber_port_validate_scheduler_cpu_state
fiber_port_scheduler_pick_first_from_start
fiber_port_runtime_select_first
fiber_port_scheduler_pick_next_from_pendsv
fiber_port_runtime_start_first
fiber_port_start_first_context
fiber_addr_plausible_ram
fiber_addr_plausible_code
fiber_port_hash32_accum
fiber_port_boot_record_compute_hash
fiber_port_boot_record_fast_check
fiber_port_boot_record_check
fiber_port_boot_create
fiber_port_boot_check
fiber_port_validate_initial_frame
fiber_port_context_init
fiber_port_validate_context_pointer
fiber_port_validate_stack_canary
fiber_port_capture_validation_cpu_state
fiber_port_validate_validation_cpu_state
fiber_port_context_validate_save_current
fiber_port_prepare_start_msp_plan
fiber_port_validate_start_msp_for_boot
fiber_port_context_validate_restore
fiber_port_context_prepare_first_start
fiber_port_require_start_environment
fiber_port_require_start_interrupt_state
fiber_port_runtime_prepare
```

`SVC_Handler` changes the incoming exact exception literal B8 to F9 and the
restored exception literal BC to FD. `PendSV_Handler` changes its corresponding
incoming and restored BC literals to FD. The four instructions remain MVN of
the complemented immediate, not a broader mask that admits foreign encodings.
All other instructions in those scalar naked source bodies are retained.

Private inline r9, xPSR, stacked-PC, BASEPRI, scheduler-critical and vector-base
helpers also retain their baseline algorithms. They access the Secure bank
through protected port-local ordinary-register accessors; no `*_NS` alias
is selected. These helpers no longer rely on unprotected CMSIS function bodies.

## Generated-Code Comparison And Limits

`tools/test_cm33_secure_only.ps1` compiles actual pinned reference `port.c` and
`portasm.c` plus the local runtime and boot objects at O2/Os. It preserves their
complete disassembly, attributes, preprocessed sources and commands, checks
numeric context/security geometry, the exact eight forward definitions plus
strong handlers, the exact unresolved reverse/integration surface and C/C++
public storage without CMSIS. It separately enforces ordered PendSV transfer
subsets from both generated objects. These subsets are **not** closed whole-body
parity and do not excuse arbitrary instructions between the matched operations.

The first reference restore skips 32 bytes of initial r4-r11; Fiber restores
the initialized GPR image. The reference generic SVC dispatcher and SVC102 are
replaced by exact owned SVC70. Fiber keeps its validated MSP plan rather than
the reference VTOR rewind alone, uses reverse ABI instead of a TCB scheduler,
and adds integrity, bounds, provenance, priority and CPU-state readbacks. The
reference sets CONTROL.SPSEL in Handler mode by ORing bit 1. Fiber clears
CONTROL in its privileged Thread/MSP entry veneer, then its SVC restore writes
CONTROL=2 and requires the low two bits to read back as 2 before returning.
Handler execution still uses physical MSP; the written SPSEL selects Thread
PSP on exception return. These are explicit adaptations, not identical assembly.

The Secure-only handler always uses the Secure Thread frame. Its S bit is not
the Non-secure-handler Secure-origin case that skips NS frame accesses in a
TrustZone companion profile. Conflating these two roles would corrupt context.

The post-r9-repair focused gate passes 110 checks with 29 exact-diagnostic
manifest negatives at
`%TEMP%/cm33-secure-only-12c9aac86bc64e70952af6345846fecf`.
The preceding `15cff987cf314baba0fd2c6d2a57c297` result qualifies only its
pre-repair source bytes.
Those historical focused receipts are compile/symbol/layout/subset evidence
only, not complete-group or closed-body evidence. The separate maintained
`tools/test_cm33_secure_only_runtime.ps1` owns actual common lifecycle,
archive/vector/cohort/GC/LTO, compiler and selected-group admission proofs;
its fixture README states their exact boundaries. Fresh closed-body reference
parity and final integration acceptance remain separate before promotion.
Hardware remains unqualified. No other profile's receipt is transferred here.
