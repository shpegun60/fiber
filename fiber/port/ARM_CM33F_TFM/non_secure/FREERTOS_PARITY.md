# ARM_CM33F_TFM Staged Port

## Canonical Context Adapter Identity

The optional OS mutex wrapper includes the canonical Context declaration and
queries `ctxrt_v1_current()`. Its exact external imports are that getter,
`fiber_panic`, and `fiber_port_runtime_schedule`. Mutex owner storage remains
the same context pointer; masks, scheduling, four wrapper exports, frames,
profile/cohort identity and the frozen eight/reverse ABI are unchanged.
It does not require the legacy five-operation compatibility object. Focused
target tests link C/C++ pure Context consumers with exactly engine/state/panic,
without legacy compatibility or optional configuration, and compile a reverted
legacy-getter wrapper that must fail that link solely for `fiber_current`.
These are declaration-boundary/target-link proofs, not an actual TF-M v2 Secure
image, veneer, PSA service or physical-board qualification. Historical evidence
and reference fingerprints below retain their original scope and provenance.

## Status And Scope

This is a build-selected, scalar-FP, non-MPU Cortex-M33 Non-secure TF-M
profile. `FIBER_PORT_RUNTIME_SELECTABLE` remains 0. No automatic route, shared
configuration, or common-runtime ABI has been added. Compile/typed-provider and
modeled CPU tests are not real TF-M, hardware, or full reference-parity proof.

The public facade remains `fiber_core.h` with the same five operations, static
contexts/stacks, and external scheduler callback. The generic forward ABI remains
eight operations and reverse ABI v1. There is no per-context TF-M attachment,
FreeRTOS `SecureContext`, fiber SecureContext, or C55S gateway dependency.

Identity is ASCII C3FT (`0x43334654`), layout `0x00010001`, feature mask `0x83`,
and public storage `arm_cm33f_tfm_v1_r0`. Context/boot sizes are 76/72 bytes.
New contexts have the basic 72-byte image; the maximum saved image is 212 bytes
including optional alignment padding. Basic/extended EXC_RETURN values are
`0xffffffbc`/`0xffffffac`. This is not the MPU 54-word protected image.

## Sources And Function Ledger

Reference pin: FreeRTOS-Kernel `a50edad08b29052631aa469d4df6e6ec7ff68878`.
The reference branch is `portable/GCC/ARM_CM33_NTZ/non_secure` with FPU=1,
MVE=0, MPU=0, TRUSTZONE=0 and RUN_FREERTOS_SECURE_ONLY=0. The TF-M integration
reference is `portable/ThirdParty/GCC/ARM_TFM`, whose README names TF-Mv2.0.0.
The complete progenitor file/hash inventory is in the dedicated fixture's
`provenance.json`; copying a sibling implementation is not reference parity.

| Functions | Immediate Source | Deliberate Differences |
| --- | --- | --- |
| `fiber_port_init_context_frame` | M33F_NTZ `fiber_port.c`; reference `pxPortInitialiseStack` | Distinct cohort; fiber immutable boot, live R9 policy and common task-return policy retained |
| `fiber_port_fpu_require_configured`, `fiber_port_fpu_require_ready`, `fiber_port_fpu_prepare` | M33F_NTZ; reference `prvSetupFPU` | Inherited exact readback/fail-closed checks; no SecureInit call |
| `fiber_port_runtime_memory_barrier`, `fiber_port_panic_wait`, `fiber_port_require_scheduler_configuration_environment`, `fiber_port_runtime_schedule` | M33F_NTZ | Protected local raw CPU wrappers instead of CMSIS function bodies |
| `fiber_port_primask_save_disable`, `fiber_port_primask_restore` | M33F_NTZ | Canonical helper attributes retained |
| `fiber_port_validate_svc_vector`, `fiber_port_validate_pendsv_vector`, `fiber_port_probe_implemented_priority_mask`, `fiber_port_count_implemented_priority_bits`, `fiber_port_validate_basepri_priority_policy`, `fiber_port_validate_exception_start_configuration`, `fiber_port_prepare_exception_start` | M33F_NTZ | Protected local raw SHPR wrappers; only SVCall/PendSV callers |
| `fiber_port_runtime_prepare_start` | M33F_NTZ plus C3TF | Cold TF-M bundle retention and validated initialization before FP preparation |
| `fiber_port_capture_scheduler_cpu_state`, `fiber_port_validate_scheduler_cpu_state`, `fiber_port_scheduler_pick_first_from_start`, `fiber_port_runtime_select_first`, `fiber_port_scheduler_pick_next_from_pendsv` | M33F_NTZ | Own identity; inherited full callback-boundary CPU/FP checks |
| `fiber_port_runtime_start_first`, `fiber_port_start_first_context`, `SVC_Handler`, `PendSV_Handler` | M33F_NTZ; reference `portasm.c` | Strong owned handlers, fiber validation/selection in place of RTOS scheduling; canonical GRO protection added to naked declarations/definitions |
| `fiber_addr_plausible_ram`, `fiber_addr_plausible_code` | M33F_NTZ boot | Existing opt-in permissive defaults only; all declarations/definitions protected |
| `fiber_port_hash32_accum`, `fiber_port_boot_record_compute_hash`, `fiber_port_boot_record_fast_check`, `fiber_port_boot_record_check`, `fiber_port_boot_create`, `fiber_port_boot_check` | M33F_NTZ boot | Own seal identity; all local helpers sensitive and GRO |
| `fiber_port_validate_initial_frame`, `fiber_port_context_init`, `fiber_port_validate_context_pointer`, `fiber_port_validate_stack_canary` | M33F_NTZ boot | Cold reverse-v1 retention; helper attribute closure |
| `fiber_port_capture_validation_cpu_state`, `fiber_port_validate_validation_cpu_state`, `fiber_port_prepare_start_msp_plan`, `fiber_port_validate_start_msp_for_boot` | M33F_NTZ boot | Local raw CPU wrappers and helper attribute closure |
| `fiber_port_context_validate_save_current`, `fiber_port_context_validate_restore`, `fiber_port_context_prepare_first_start`, `fiber_port_require_start_environment`, `fiber_port_require_start_interrupt_state`, `fiber_port_runtime_prepare` | M33F_NTZ boot | Scalar-FP mechanics retained; separate cohort |
| `fiber_port_read_r9`, `fiber_port_initial_xpsr`, `fiber_port_stacked_pc`, `fiber_port_basepri_read`, `fiber_port_basepri_write`, `fiber_port_scheduler_critical_enter`, `fiber_port_scheduler_critical_exit`, `fiber_port_vectors_base_addr`, `fiber_port_vectors_base_ptr`, `fiber_port_read_initial_msp` | M33F_NTZ macro header | Canonical forced-inline sensitive/GRO protection |
| `fiber_port_cpu_ipsr`, `fiber_port_cpu_primask`, `fiber_port_cpu_control`, `fiber_port_cpu_faultmask`, `fiber_port_cpu_psplim`, `fiber_port_cpu_psp`, `fiber_port_cpu_msp`, `fiber_port_cpu_wfe`, `fiber_port_cpu_priority_get`, `fiber_port_cpu_priority_set` | Local CPU wrappers | Raw instructions/register accesses; no inherited CMSIS function attributes |
| `fiber_port_tfm_require_prestart_environment`, `fiber_port_tfm_capture_cpu_state`, `fiber_port_tfm_validate_cpu_state`, `fiber_port_tfm_initialize`, `fiber_port_tfm_require_initialized` | C3TF integration | CPACR/FPCCR added to six existing observations; full CONTROL comparison retained |
| `fiber_port_tfm_primask_save_disable`, `fiber_port_tfm_primask_restore`, `fiber_port_tfm_require_unmasked_thread`, `fiber_port_tfm_require_running_fiber`, `fiber_port_tfm_mutex_handle_is_valid`, `fiber_port_tfm_mutex_state_check`, all four `os_wrapper_mutex_*` functions | C3TF cooperative adapter; reference TF-M wrapper ABI | Local raw observations; existing cooperative semantics retained, not FreeRTOS tick-timeout equivalence |

## Macro Ledger

| Macro Families | Ownership / Meaning |
| --- | --- |
| Include guards, `FIBER_PORT_NAME`, `FIBER_PORT_CM33F_TFM_*`, context ABI ID, storage port token | New exact profile identity; no C3TF/C5TF/NTZ alias |
| Layout version, context sizes/offsets, EXC_RETURN/PSPLIM/software-frame dictionaries, FP frame sizes | M33F_NTZ and pinned non-MPU FP branch; unchanged geometry |
| FPU/toolchain/CMSIS facts and security/stack feature flags | M33F_NTZ scalar-FP contract; MVE/PAC/BTI/MPU/Secure CMSE excluded |
| Architecture and foreign MPU checks | Exact M33/v8.0-M target; foreign region macros rejected on presence |
| `FIBER_PORT_RUNTIME_SELECTABLE` | Fixed 0; callers cannot override it, including with 0 |
| Barrier, BASEPRI, scheduler-mask and vector macros | M33F_NTZ mechanics, unchanged policy |
| `fiber_portFORCE_INLINE` | Selected-port-owned sensitive/GRO forced-inline closure; override rejected |
| `FIBER_FPU_LAZY`, validation, canary, redzone, MSP-rewind settings | Existing settings only; no new optional production policy macro |
| `FIBER_PORT_TFM_*`, `FIBER_PORT_TFM_OS_WRAPPER_*` | Existing C3TF v2 initializer/mutex surface and values |

## Initialization And External Integration

Initialization is privileged Non-secure Thread/MSP, unmasked and pre-start.
The first attempt publishes INITIALIZING, calls `tfm_ns_interface_init`, verifies
IPSR/PRIMASK/BASEPRI/FAULTMASK/full CONTROL/PSPLIM/CPACR/FPCCR unchanged, and only
then publishes READY or sticky FAILED. Reentry/FAILED do not call the provider
again; READY is idempotent. `fiber_start` invokes the same operation automatically.
An early explicit call is optional. Admission rejection precedes latch/provider
effects. The initializer does not configure FP or repair a leaked value.

The Secure TF-M provider must grant NS FP access and permit the selected NS
FPCCR policy (including LSPEN changes for eager mode). The external initializer must
work in the entry FP configuration and preserve it, including FPCA. Later CPU
preparation configures the inherited CPACR/FPCCR policy. A running FP fiber may
have CONTROL=6: mutex admission checks only privilege/stack bits, not exact 2.
No Secure-bank permission or FP payload preservation is established by NS
register readback alone.

Real integration needs TF-Mv2.0.0 NS interface source/header files and the actual
`s_veneers.o`, with `TFM_NS_MANAGE_NSID=OFF` and compatible hard/softfp compiler
ABIs. No real TF-M checkout is available in this workspace. Typed providers are
an explicit test boundary, not Secure TF-M execution.

The static cooperative mutex permits prestart creation and owner-checked runtime
acquire/release. Free acquisition accepts any timeout; finite contended waits
return ERROR immediately; WAIT_FOREVER cooperatively schedules. There is no timer
service, priority inheritance or FreeRTOS blocking-semaphore equivalence claim.

## Pending Qualification

The focused runner owns target C/C++/archive/cohort/role and source-derived host
adapter tests, actual pinned reference compilation, and raw hostile codegen
checks. Explicit `-QemuRoot` additionally enables actual M33 common/FP execution,
whole-group admission and compiled negative controls. This uses real common and
all four port objects, but only a test Secure bootstrap and typed NS TF-M provider.
No real Secure TF-M service is executed. The dedicated fixture README describes
the exact boundaries and maintained modes; a run without QEMU is `NOT_RUN`, not
CPU execution qualification. Independent full CPU assembly/frame-transfer parity
is owned by a separate gate. This leaf must remain staged until the parent accepts
all required evidence and the cohort. No board has been programmed.
