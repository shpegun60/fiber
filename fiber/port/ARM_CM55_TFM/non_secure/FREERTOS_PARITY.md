# ARM_CM55 TF-M Non-secure Parity Ledger

## Status And Scope

C5TF source group implemented, 2026-11-02. Complete-group target/host and
dual-r9 actual M55 qualification pass, with separate pinned-reference whole-body
parity. Selectable metadata is now one; the post-metadata complete-group replay
passes, including per-object dependency roles and compiled controls. It is
recorded as complete software runtime profile 21. All eight forward
operations and strong SVC/PendSV handlers exist. No global selector route,
hardware result or actual Secure TF-M image execution is implied.

The final consumer receipt is
`%TEMP%/fiber-c5tf-role-boundary-final/cm55-tfm-d4a569b3ee514afbab41f2d59139a6fa/receipt.json`:
16 target ELFs, 112 negative checks, 24 object-role proofs, 200 source-derived
host adapter scenarios and sixteen actual M55 dual-r9 execution tuples with
controls. The parent independently rehashes 11,803 recorded input/artifact
entries with zero mismatches. Its 72 exact repository inputs are archived at
`%TEMP%/fiber-qualified-repo-inputs-c770e3d17baf41138be002473ea0c237`, ZIP SHA-256
`E0D1A75CEE2A08A690E435262B4E077B22930C0A7CF7F123EFD47E120AC51AD9`.
The closed reference-transfer parity receipt remains separate; a later
all-profile/final-LTO gate cannot be inferred from this focused qualification.

The subsequent A32 repair replaces unannotated CMSIS inline CPU calls with
annotated port-owned primitives; attributes of their sensitive caller do not
propagate into CMSIS. The complete target/host/dual-r9 consumer suite passes
again at `%TEMP%/cm55-tfm-e3dd95d7dce04a3e8c0c824ad88655f7` with the same
16/112/200/16 proof counts and all object-role controls. Parent independently
rehashes 11,803 input/artifact entries with zero mismatches and archives the
72 exact repository inputs at
`%TEMP%/fiber-qualified-repo-inputs-dd9d0efe49db482bbabe68d2816e3f0f`, ZIP SHA-256
`891B15A3B37B5C4E1F6777EA4847F1DF680E1652E7D81FC28F36BED83185C241`.
Naked start/SVC/PendSV text, frame layout and identity are unchanged. Fresh
attributes-only whole-port closure and immutable reference replay remain
separate gates; hostile consumer builds do not imply either proof.

The CPU baseline is the actual implemented `ARM_CM55_NTZ/non_secure` group.
The TF-M initialization/mutex policy is adapted separately from
`ARM_CM33_TFM/non_secure`. This is not an M33 CPU port renamed as M55.
The pinned FreeRTOS ARM_TFM README explicitly instructs using the matching
M55_NTZ CPU sources and adds an OS-wrapper, not another exception engine.

Only these twelve files belong to the new production group:

```text
fiber_port.c                  CPU runtime and strong SVC/PendSV
fiber_port_boot.c             sealed construction and validation
fiber_portmacro.h             exact private CPU/geometry dictionary
fiber_port_types.h            CPU-neutral public storage
fiber_port_boot_types.h       CPU-neutral boot record
fiber_port_boot.h             private boot declarations
fiber_port_private.h          private runtime/reverse declarations
fiber_port_tfm.c               external TF-M initialization boundary
fiber_port_tfm_abi.h           optional initialization API
fiber_port_tfm_os_wrapper.c    static cooperative TF-M mutex
fiber_port_tfm_os_wrapper.h    exact four-operation TF-M wrapper ABI
FREERTOS_PARITY.md             this source/evidence ledger
```

Four C objects are required. No MPU maps, FP/MVE transfers, fiber-owned Secure
companion/NSC symbols, SecureContext slot, PAC keys or BTI policy are added.
Public allocating storage remains CMSIS-free. The five portable operations and
the frozen eight-operation generic/reverse boundaries remain unchanged.

## Exact Manifest And Identity

```text
compiler: -mcpu=cortex-m55 -mthumb -mfloat-abi=soft
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
selected include path: fiber/port/ARM_CM55_TFM/non_secure
CMSIS __CORTEX_M=55, __VTOR_PRESENT=1, __NVIC_PRIO_BITS=1..8
Non-secure CMSE level 1; no Secure -mcmse build
FPU_USED=0; no compiler FP/MVE/PAC/BTI ABI; no MPU profile manifest
FIBER_PORT_RUNTIME_SELECTABLE=1; post-metadata replay pending
port identity: C5TF / 0x43355446
layout: 0x00010001
features: 0x82 (PSPLIM slot + Non-secure role)
storage: arm_cm55_tfm / revision1 / regions0
```

Physical FPU/MPU presence is not a request to use them. Normal CMSIS hardware
presence fields may describe an equipped M55, but this exact source group
rejects FP use/compiler ABI, MVE, PAC/BTI, Secure execution and every existing
MPU region-count input: `FIBER_PORT_CM4_MPU_TOTAL_REGIONS`,
`FIBER_PORT_CM33_MPU_TOTAL_REGIONS`, `FIBER_PORT_CM33F_MPU_TOTAL_REGIONS`,
`FIBER_PORT_CM55_MPU_TOTAL_REGIONS`, `FIBER_PORT_CM55F_MPU_TOTAL_REGIONS`,
`FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS` and `FIBER_PORT_MPU_TOTAL_REGIONS`.
Presence is rejected even when the supplied value is zero. The fixed-geometry
CM0/CM3 MPU dictionaries have no region-count input macro; no synthetic
configuration spelling is introduced for them. This is a selected private
dictionary check, not a new public-header or shared feature-selection policy.
GCC's scalar M55 compiler can report `__ARM_ARCH_8M_MAIN__`;
the explicit architecture result plus actual CMSIS core contract is retained
from the M55 baseline. It is not proof against a deliberately falsified build
manifest; compiler command/ISA evidence is a separate qualification obligation.

The ten-word software frame is PSPLIM, BC EXC_RETURN and r4-r11. Eight hardware
words follow. Initial image is eighteen words/72 bytes; maximum basic saved
extent is 76 with the optional architectural padding word. Public context is
76 bytes/alignment4, with sp at0 and a 72-byte boot record at4. No TF-M or Secure
handle is stored in the frame. B8 is the exact NS Thread/MSP first-SVC origin;
BC is the exact basic NS Thread/PSP restore form.

## Pinned Primary Sources

Local FreeRTOS root:
`C:\Users\admin\Documents\my_workspace\stm32\experiments\_reference\FreeRTOS-Kernel`

Pin: `a50edad08b29052631aa469d4df6e6ec7ff68878`.
Actual M55 files, not M33 substitutes, were read and hashed for this addition.

| Pinned artifact | SHA-256 |
| --- | --- |
| `GCC/ARM_CM55_NTZ/non_secure/port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` |
| `GCC/ARM_CM55_NTZ/non_secure/portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` |
| `GCC/ARM_CM55_NTZ/non_secure/portasm.h` | `185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C` |
| `GCC/ARM_CM55_NTZ/non_secure/portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` |
| `GCC/ARM_CM55_NTZ/non_secure/portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` |
| `ThirdParty/GCC/ARM_TFM/README.md` | `43EAC6335CBC2B3B90FA53817B844774B5DCCDC8D477308C2E83128F83B4EE0A` |
| `ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c` | `9A6242DB2128A3220495C6739078959CF56D56649F1FFB2634C6430603938901` |

Paths above are relative to `portable/`. The relevant reference configuration
is single-core, MPU/FPU/MVE/PAC/BTI=0, `configENABLE_TRUSTZONE=0` and
`configRUN_FREERTOS_SECURE_ONLY=0`. Hardware TrustZone remains present; TF-M,
not this library, owns the Secure image.

### Live Fiber Adaptation Inputs

These are baseline hashes at source creation, not later qualification receipts.

| Input relative to fiber/port | SHA-256 |
| --- | --- |
| `ARM_CM55_NTZ/non_secure/fiber_port.c` | `F033A669E97225E2A70B0A13F5BF2512190CB2E0A8E99E76B440EB24FF56CD59` |
| `ARM_CM55_NTZ/non_secure/fiber_portmacro.h` | `78FDC4D1ECB48B09C755656C16D4C1B67367867B5E78258BFC29CCB452854708` |
| `ARM_CM55_NTZ/non_secure/fiber_port_types.h` | `EDF9538E20CF2EE75D16C79A6CC01E9E675D01DEAA83245C484FF7A80D2042A7` |
| `ARM_CM55_NTZ/non_secure/fiber_port_boot_types.h` | `CE835EDCA42A0707040A003277F3FDF9D3B00B8C2377813A7C6203B38169FD03` |
| `ARM_CM55_NTZ/non_secure/fiber_port_boot.h` | `98297DC564E4A5DC8AB0A6E9DB02918E39BE6AD7771D03664792FCE9D14EE9DE` |
| `ARM_CM55_NTZ/non_secure/fiber_port_boot.c` | `F08D0BC8686A1076407E6D38626B484A3D2583B6195DFD0411AEFF86696CCD7F` |
| `ARM_CM55_NTZ/non_secure/fiber_port_private.h` | `3E8FEA58400241CA9C724A4E1432901A49F3931378853FC724C7916DC15EF3A4` |
| `ARM_CM33_TFM/non_secure/fiber_port_tfm.c` | `1315F107E7E4D7F5C2F19D82BCDDD5425CF9000D3E460DA02D1388A9EF8D2708` |
| `ARM_CM33_TFM/non_secure/fiber_port_tfm_abi.h` | `FF333E144C7ACF74673BDF23243042ACE5AFFB518AC2E2D38FF8E59D38941848` |
| `ARM_CM33_TFM/non_secure/fiber_port_tfm_os_wrapper.c` | `FB74C41A2B5E4C83DCDF8E9E24225A314D28AC05E1A2DE170BBA03ACE5886DA2` |
| `ARM_CM33_TFM/non_secure/fiber_port_tfm_os_wrapper.h` | `8EC83F7A6C80340E5DF9E898E198E0E6AFA550C5E4295F7C06C3E6BD89BC1F43` |

## Runtime And Ownership Contract

`fiber_port.c` defines the exact context-cohort provider, including existing
storage-cohort provider mechanics. The constructor retains its exact
expectation and cold reverse-v1 dependency after the frame helper, preserving
the baseline r9-capture order. Cold start preparation independently retains
reverse v1, exact cohort and the profile-specific
`fiber_port_arm_cm55_tfm_integration_bundle_v1_anchor` defined only by
`fiber_port_tfm.c`. The runtime calls the real initializer helper before CPU
MSP/exception preparation. No read is added to the PendSV hot path.

The common image alone owns reverse services and current storage. Naked SVC
and PendSV contain the only current-slot address/load sequences; C has no
declaration/lvalue for it. The optional TF-M wrapper calls public
`fiber_current()` and the selected-port schedule operation, not common private
scheduler state. Only one selected group and one TF-M wrapper provider may be
linked; duplicate handlers/providers are errors.

CPU handlers and boot validation retain the current M55_NTZ source mechanics:
live PSP validation before source-stack writes, exact security/basic tokens,
PSPLIM preservation, ten-word transfer, BASEPRI-preserving selection and
post-selector CPU-state checks. First restore writes CONTROL2 and reads2,
not the obsolete post-write zero comparison. Successful resume does not call C
after restoring GPRs; terminal panic branches after a failed restore readback
remain possible and intentionally never resume. Frame/canary/MSP ownership
checks do not claim containment of arbitrary physical exception-stack damage.
No source-level M33/M55 similarity substitutes for actual generated parity.

Every new C helper and private/public integration declaration uses the canonical
sensitive/general-register bundle; local inline CPU helpers use
INLINE_SENSITIVE plus GENERAL_REGS_ONLY. Naked functions remain pure assembly.
Compiler-generated `memcpy`/`memset` imports in boot construction are retained
from the baseline aggregate-initialization/assignment model; a real integration
must provide qualified scalar helpers and the required sensitive build flags.
An arbitrary vendor library or external TF-M call graph is not qualified by
these source attributes.

## TF-M Interface Policy And External Prerequisites

This optional boundary preserves the existing M33_TFM policy, without copying
M33 CPU startup/exception code. `fiber_port_tfm_initialize()` may be called
explicitly in unmasked privileged NS Thread/MSP before start; normal cold
preparation invokes it automatically. Its ordinary BSS state is
UNINITIALIZED -> INITIALIZING -> READY or FAILED. READY is idempotent success;
reentry, FAILED or an unknown nonzero state returns ERROR. No failed attempt is
reset/retried. CPU-state leakage after the external call is terminal.

The sole external initializer is `tfm_ns_interface_init()`; it is not supplied
by this port. The four exact v2.0 wrapper spellings are create/acquire/release/
delete. The static mutex has no heap, FreeRTOS semaphore or waiting list.
Immediate acquisition works for any timeout. Busy WAIT_FOREVER yields through
the user scheduler; busy finite/zero timeouts return ERROR because the port
owns no clock. Recursive acquisition and wrong-owner release/delete fail.
The scheduler must eventually run the owner; fairness is not implemented here.

Actual TF-M integration requires tag TF-Mv2.0.0, its generated NS interface
sources/headers and matching Secure-image `s_veneers.o`, with
`TFM_NS_MANAGE_NSID=OFF` as required by the pinned ARM_TFM README. No actual
TF-M v2.0 interface checkout or Secure veneer is qualified here. Test doubles
can prove the interface boundary, ordering and failures only; they cannot prove
PSA service execution, an actual Secure TF-M image or a physical board.

## Exhaustive Function Disposition

Definitions below include static and inline helpers. Private header declarations
refer to the same definitions; no additional CPU operation is hidden there.
Local enum frame indices, boot guards, state enums and CPU snapshots are the
explicit Fiber hardening structures described above, not undocumented FreeRTOS
context slots.

| Function | Owner | Actual reference or deliberate local policy |
| --- | --- | --- |
| `fiber_port_init_context_frame` | `fiber_port.c` | M55 `port.c:pxPortInitialiseStack`, no-MPU/no-FP/no-MVE: seed PSPLIM, BC, r4-r11, core8; local r9 seed and terminal-return policy. |
| `fiber_port_runtime_memory_barrier` | `fiber_port.c` | Local forward ABI operation; DMB/compiler ordering, not a FreeRTOS scheduler. |
| `fiber_port_panic_wait` | `fiber_port.c` | Local terminal forward ABI operation; barriers and WFE, no recovery. |
| `fiber_port_require_scheduler_configuration_environment` | `fiber_port.c` | Local forward ABI admission: Thread mode. |
| `fiber_port_runtime_schedule` | `fiber_port.c` | M55 `portmacrocommon.h` yield/ICSR PendSV request; validate current, privileged PSP Thread and masks first. |
| `fiber_port_primask_save_disable` | `fiber_port.c` | Local hardening around priority setup; preserve PRIMASK, CPSID, DSB/ISB. |
| `fiber_port_primask_restore` | `fiber_port.c` | Local inverse with exact PRIMASK readback. |
| `fiber_port_validate_svc_vector` | `fiber_port.c` | Local exact strong slot11 validation, not a wrapper-routing flag. |
| `fiber_port_validate_pendsv_vector` | `fiber_port.c` | Local exact strong slot14 validation. |
| `fiber_port_probe_implemented_priority_mask` | `fiber_port.c` | M55 `port.c` implemented-priority probe; save/restore one priority byte under PRIMASK. |
| `fiber_port_count_implemented_priority_bits` | `fiber_port.c` | Local decoding of that real probe. |
| `fiber_port_validate_basepri_priority_policy` | `fiber_port.c` | M55 `port.c` priority/PRIGROUP constraints; actual CMSIS-width and threshold checks. |
| `fiber_port_validate_exception_start_configuration` | `fiber_port.c` | M55 start exception policy plus exact vector/STKALIGN/priority readback. |
| `fiber_port_prepare_exception_start` | `fiber_port.c` | M55 scheduler startup priorities; clear stale PendSV and preserve incoming PRIMASK. No SysTick ownership. |
| `fiber_port_runtime_prepare_start` | `fiber_port.c` | Local cold forward ABI: reverse-v1/cohort/TF-M anchor; checked TF-M initialization before CPU/MSP/exception preparation. |
| `fiber_port_capture_scheduler_cpu_state` | `fiber_port.c` | Local preservation snapshot: PRIMASK, CONTROL, BASEPRI, FAULTMASK, PSPLIM. |
| `fiber_port_validate_scheduler_cpu_state` | `fiber_port.c` | Local post-selector comparison; does not repair leaked CPU state. |
| `fiber_port_scheduler_pick_first_from_start` | `fiber_port.c` | M55 `vTaskSwitchContext` policy substitution: frozen reverse candidate selector under saved/restored BASEPRI. |
| `fiber_port_runtime_select_first` | `fiber_port.c` | Local forward ABI facade for that first selector; no publication. |
| `fiber_port_scheduler_pick_next_from_pendsv` | `fiber_port.c` | M55 scheduler call substitution; exact Handler14/masks/PSPLIM checks, CPU-preserving reverse selection, validate then publish. |
| `fiber_port_runtime_start_first` | `fiber_port.c` | Local forward ABI facade; prepared MSP and strong vectors checked under PRIMASK before naked start. |
| `fiber_port_start_first_context` | `fiber_port.c` | Actual M55 `portasm.c:vStartFirstTask`; checked optional MSP rewind, masks/barriers and Fiber SVC70. |
| `SVC_Handler` | `fiber_port.c` | Actual M55 `vRestoreContextOfFirstTask`, no-MPU/no-FP/no-MVE; strict B8/MSP/SVC admission then PSPLIM, BC, full r4-r11, CONTROL2/read2 and PSP. Terminal panic branches are explicit differences. |
| `PendSV_Handler` | `fiber_port.c` | Actual M55 non-MPU PendSV: live PSP, PSPLIM/BC/r4-r11 save, BASEPRI selector, inverse ten-word restore. Local before-write bounds/padding/metadata/readback guards; no FP block. |
| `fiber_port_read_r9` | `fiber_portmacro.h` | Local r9 platform/static-base preservation policy; pinned debug-marker seed is not imported. |
| `fiber_port_initial_xpsr` | `fiber_portmacro.h` | M55 initial Thumb xPSR constant. |
| `fiber_port_stacked_pc` | `fiber_portmacro.h` | M55 initial entry PC clears Thumb function-pointer bit. |
| `fiber_port_basepri_read` | `fiber_portmacro.h` | M55 mask helper MRS BASEPRI; local compiler-memory clobber. |
| `fiber_port_basepri_write` | `fiber_portmacro.h` | M55 mask helper MSR BASEPRI; synchronized DSB/ISB, no M7 erratum path. |
| `fiber_port_scheduler_critical_enter` | `fiber_portmacro.h` | M55 PendSV scheduler threshold, returning previous BASEPRI. |
| `fiber_port_scheduler_critical_exit` | `fiber_portmacro.h` | Restore the captured BASEPRI, not unconditional enable. |
| `fiber_port_vectors_base_addr` | `fiber_portmacro.h` | M55 `vStartFirstTask` VTOR source; mask implemented address bits. |
| `fiber_port_read_initial_msp` | `fiber_portmacro.h` | M55 `vStartFirstTask` vector word0 read. |
| `fiber_port_vectors_base_ptr` | `fiber_portmacro.h` | Local typed address view of that VTOR source. |
| `fiber_addr_plausible_ram` | `fiber_port_boot.c` | Integration-owned exact RAM map; weak permissive default only under explicit bring-up setting. |
| `fiber_addr_plausible_code` | `fiber_port_boot.c` | Integration-owned exact code map; same explicit weak-default policy. |
| `fiber_port_hash32_accum` | `fiber_port_boot.c` | Fiber-only FNV-1a byte accumulation; no FreeRTOS equivalent or cryptographic-integrity claim. |
| `fiber_port_boot_record_compute_hash` | `fiber_port_boot.c` | Fiber-only immutable boot tuple seal. |
| `fiber_port_boot_record_fast_check` | `fiber_port_boot.c` | Fiber-only magic/version/guards/sealed/bounds/geometry/exact-identity checks. |
| `fiber_port_boot_record_check` | `fiber_port_boot.c` | Fiber-only fast check plus recomputed seal. |
| `fiber_port_boot_create` | `fiber_port_boot.c` | M55 stack construction bounds with Fiber alignment/redzone/address-map/sealed boot metadata. |
| `fiber_port_boot_check` | `fiber_port_boot.c` | Fiber-only recomputation of raw-to-aligned stack geometry and integration map. |
| `fiber_port_validate_initial_frame` | `fiber_port_boot.c` | M55 initial eighteen-word frame oracle plus Fiber seed/return checks. |
| `fiber_port_context_init` | `fiber_port_boot.c` | Forward constructor; context/raw-stack disjointness, boot creation, canary, actual frame helper, cold reverse-v1 after helper and final frame validation. |
| `fiber_port_validate_context_pointer` | `fiber_port_boot.c` | Fiber-only null/alignment/overflow and configured address-map admission. |
| `fiber_port_validate_stack_canary` | `fiber_port_boot.c` | Fiber-only aligned raw-prefix extent/readback; no reference canary. |
| `fiber_port_capture_validation_cpu_state` | `fiber_port_boot.c` | Fiber-only snapshot around optional runtime address hooks. |
| `fiber_port_validate_validation_cpu_state` | `fiber_port_boot.c` | Fiber-only comparison after those integration hooks. |
| `fiber_port_context_validate_save_current` | `fiber_port_boot.c` | Fiber-only sealed current/live PSP and PSPLIM preflight; historical ctx->sp is intentionally not the running PSP. |
| `fiber_port_prepare_start_msp_plan` | `fiber_port_boot.c` | M55 vector-MSP startup adapted to the existing rewind setting, one-shot private plan and real address checks. |
| `fiber_port_validate_start_msp_for_boot` | `fiber_port_boot.c` | Fiber-only planned MSP versus task-stack/redzone disjointness and repeat vector sampling. |
| `fiber_port_context_validate_restore` | `fiber_port_boot.c` | M55 basic saved form with Fiber metadata, minimum extent before frame words, PC/xPSR and complete alignment-padding extent. |
| `fiber_port_context_prepare_first_start` | `fiber_port_boot.c` | Fiber-only saved-context/MSP-plan validation; return rewind top or zero for preserve-MSP policy. |
| `fiber_port_require_start_environment` | `fiber_port_boot.c` | M55 privileged NS Thread/MSP start precondition. |
| `fiber_port_require_start_interrupt_state` | `fiber_port_boot.c` | Fiber-only explicit clear PRIMASK/BASEPRI/FAULTMASK start precondition. |
| `fiber_port_runtime_prepare` | `fiber_port_boot.c` | M55 STKALIGN startup policy plus Fiber one-shot MSP plan. |
| `fiber_port_tfm_require_prestart_environment` | `fiber_port_tfm.c` | M33_TFM interface policy only: unmasked privileged NS Thread/MSP. |
| `fiber_port_tfm_capture_cpu_state` | `fiber_port_tfm.c` | M33_TFM interface policy: snapshot IPSR/masks/CONTROL/PSPLIM before the external initializer. |
| `fiber_port_tfm_validate_cpu_state` | `fiber_port_tfm.c` | M33_TFM interface policy: reject external initializer CPU-state leaks. |
| `fiber_port_tfm_initialize` | `fiber_port_tfm.c` | TF-M v2.0 `tfm_ns_interface_init` boundary: automatic/explicit idempotent success; INITIALIZING/reentry and FAILED cannot retry. |
| `fiber_port_tfm_require_initialized` | `fiber_port_tfm.c` | Local cold startup helper turns nonzero initialization status into terminal Q. |
| `fiber_port_tfm_primask_save_disable` | `fiber_port_tfm_os_wrapper.c` | M33_TFM mutex policy: preserve then briefly mask PRIMASK. |
| `fiber_port_tfm_primask_restore` | `fiber_port_tfm_os_wrapper.c` | M33_TFM mutex policy: exact PRIMASK restoration/readback. |
| `fiber_port_tfm_require_unmasked_thread` | `fiber_port_tfm_os_wrapper.c` | M33_TFM mutex policy: no Handler or masked waiting. |
| `fiber_port_tfm_require_running_fiber` | `fiber_port_tfm_os_wrapper.c` | M33_TFM mutex policy: privileged PSP Thread plus public fiber_current(); no common private storage. |
| `fiber_port_tfm_mutex_handle_is_valid` | `fiber_port_tfm_os_wrapper.c` | TF-M single global mutex adaptation: exact private static address and created marker. |
| `fiber_port_tfm_mutex_state_check` | `fiber_port_tfm_os_wrapper.c` | Local fail-closed created/owner consistency checks. |
| `os_wrapper_mutex_create` | `fiber_port_tfm_os_wrapper.c` | TF-M v2.0 mutex ABI; one static mutex, only before first start, no heap/semaphore. |
| `os_wrapper_mutex_acquire` | `fiber_port_tfm_os_wrapper.c` | TF-M v2.0 mutex ABI; owner-checked immediate acquisition; busy WAIT_FOREVER cooperatively schedules; busy finite timeout errors without a fabricated clock. |
| `os_wrapper_mutex_release` | `fiber_port_tfm_os_wrapper.c` | TF-M v2.0 mutex ABI; only current owner may release; exact state publication/readback. |
| `os_wrapper_mutex_delete` | `fiber_port_tfm_os_wrapper.c` | TF-M v2.0 mutex ABI; delete only valid unowned mutex; no detach/free of a context. |

### A32 CPU Primitive Additions

Each helper lives in this profile's `fiber_portmacro.h`, with canonical
inline-sensitive/general-registers-only attributes. No generic ABI operation
or public application function is added. The TF-M host fixture substitutes
only its documented CPU-state boundary under the new names.

| Function | Replaced operation and disposition |
| --- | --- |
| `fiber_port_cpu_read_ipsr` | `__get_IPSR`; raw MRS of the executing Non-secure bank. |
| `fiber_port_cpu_read_control` | `__get_CONTROL`; raw MRS, preserving the existing mask/privilege checks. |
| `fiber_port_cpu_read_primask` | `__get_PRIMASK`; raw MRS. |
| `fiber_port_cpu_read_faultmask` | `__get_FAULTMASK`; raw MRS. |
| `fiber_port_cpu_read_psp` | `__get_PSP`; raw MRS. |
| `fiber_port_cpu_read_msp` | `__get_MSP`; raw MRS used by the startup plan. |
| `fiber_port_cpu_read_psplim` | `__get_PSPLIM`; raw MRS. |
| `fiber_port_cpu_wait` | `__WFE`; raw WFE with compiler memory ordering. |
| `fiber_port_cpu_priority_index` | Fiber-only bounds check; system priority indexing matches CMSIS, external extent uses the actual selected CMSIS `NVIC->IPR` array size. |
| `fiber_port_cpu_get_priority` | `NVIC_GetPriority`; the same selected-bank byte address and implemented-bit shift, with the checked index. |
| `fiber_port_cpu_set_priority` | `NVIC_SetPriority`; the same byte write and priority shift/truncation, with the checked index. |

## Exhaustive Macro Disposition

Each locally defined macro is listed below (one row per file definition name;
alternative definitions of the same name share its row). Imported common/CMSIS
macros are dependencies, not copied definitions of this group.

| Macro | Owner | Actual reference or deliberate local policy |
| --- | --- | --- |
| `fiber_portSTRINGIFY2` | `fiber_port.c` | Local preprocessor conversion of the selected SVC immediate; no CPU behavior by itself. |
| `fiber_portSTRINGIFY` | `fiber_port.c` | Local preprocessor conversion of the selected SVC immediate; no CPU behavior by itself. |
| `FIBER_PORT_ARM_CM55_TFM_FIBER_PORTMACRO_H_` | `fiber_portmacro.h` | Fiber-only include guard; no runtime reference behavior. |
| `FIBER_PORT_NAME` | `fiber_portmacro.h` | New C5TF selected-profile/storage identity; no borrowing of C55N/C3TF providers. |
| `fiber_portFORCE_INLINE` | `fiber_portmacro.h` | Compiler spelling only; M55 inline assembly, with local canonical sensitive/GP function annotations. |
| `fiber_portASM` | `fiber_portmacro.h` | Compiler spelling only; M55 inline assembly, with local canonical sensitive/GP function annotations. |
| `fiber_portCOMPILER_BARRIER` | `fiber_portmacro.h` | M55 DSB/ISB/compiler ordering; shared startup/mask mechanics, not a scheduler policy. |
| `fiber_portDATA_SYNC_BARRIER` | `fiber_portmacro.h` | M55 DSB/ISB/compiler ordering; shared startup/mask mechanics, not a scheduler policy. |
| `fiber_portINST_SYNC_BARRIER` | `fiber_portmacro.h` | M55 DSB/ISB/compiler ordering; shared startup/mask mechanics, not a scheduler policy. |
| `FIBER_PORT_RUNTIME_SELECTABLE` | `fiber_portmacro.h` | Exact selected runtime metadata, now 1 after complete-group gates; post-metadata replay is required. Not a reference CPU feature or application override. |
| `fiber_portSTACK_GROWTH` | `fiber_portmacro.h` | Actual M55 portmacro/pxPortInitialiseStack: downward stack, 8-byte boundary, Thumb xPSR and even stacked entry PC. |
| `fiber_portBYTE_ALIGNMENT` | `fiber_portmacro.h` | Actual M55 portmacro/pxPortInitialiseStack: downward stack, 8-byte boundary, Thumb xPSR and even stacked entry PC. |
| `fiber_portINITIAL_XPSR` | `fiber_portmacro.h` | Actual M55 portmacro/pxPortInitialiseStack: downward stack, 8-byte boundary, Thumb xPSR and even stacked entry PC. |
| `fiber_portSTART_ADDRESS_MASK` | `fiber_portmacro.h` | Actual M55 portmacro/pxPortInitialiseStack: downward stack, 8-byte boundary, Thumb xPSR and even stacked entry PC. |
| `fiber_portINITIAL_EXC_RETURN` | `fiber_portmacro.h` | Actual M55 Non-secure basic tokens: PSP BC, first MSP B8; no Secure/extended token admitted. |
| `fiber_portSVC_ORIGIN_EXC_RETURN` | `fiber_portmacro.h` | Actual M55 Non-secure basic tokens: PSP BC, first MSP B8; no Secure/extended token admitted. |
| `fiber_portPSPLIM_SLOT_WORDS` | `fiber_portmacro.h` | Actual M55 no-MPU/no-FP/no-MVE frame: PSPLIM1 + EXC_RETURN1 + GPR8; EXC_RETURN index1. |
| `fiber_portCORE_SOFTWARE_WORDS` | `fiber_portmacro.h` | Actual M55 no-MPU/no-FP/no-MVE frame: PSPLIM1 + EXC_RETURN1 + GPR8; EXC_RETURN index1. |
| `fiber_portSOFTWARE_FRAME_WORDS` | `fiber_portmacro.h` | Actual M55 no-MPU/no-FP/no-MVE frame: PSPLIM1 + EXC_RETURN1 + GPR8; EXC_RETURN index1. |
| `fiber_portEXC_RETURN_WORD_INDEX` | `fiber_portmacro.h` | Actual M55 no-MPU/no-FP/no-MVE frame: PSPLIM1 + EXC_RETURN1 + GPR8; EXC_RETURN index1. |
| `FIBER_PORT_HAS_BASEPRI` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_FAULTMASK` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_VTOR` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_PSPLIM` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_FPU` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_EXTENDED_FP_CONTEXT` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_STACK_ALIGNMENT` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `FIBER_PORT_BOOT_CLEARS_FPCA` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_MVE` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_PAC` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_BTI` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_USES_PSPLIM_REGISTER` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_INITIAL_EXC_RETURN` | `fiber_portmacro.h` | Actual M55 Non-secure basic tokens: PSP BC, first MSP B8; no Secure/extended token admitted. |
| `FIBER_PORT_SCHEDULER_MASK_KIND` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_IS_V8M` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_SECURITY_EXT` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_RUNS_NONSECURE` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_TARGETS_NS_BANK` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_CONTROL_SLOT` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_PSPLIM_SLOT` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_SECURE_CONTEXT_SLOT` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_HAS_PAC_KEY_SLOT` | `fiber_portmacro.h` | Actual M55 scalar NS manifest/config branch: Mainline BASEPRI/FAULTMASK/VTOR/PSPLIM, current NS bank, no MPU/FPU/MVE/CONTROL/SecureContext/PAC-key slots or M7 workaround. Hardware Security Extension is present. |
| `FIBER_PORT_SCHEDULER_BASEPRI` | `fiber_portmacro.h` | M55 configMAX_SYSCALL_INTERRUPT_PRIORITY analogue with existing Fiber default, implemented-width and PRIGROUP validation. |
| `FIBER_SCHEDULER_BASEPRI` | `fiber_portmacro.h` | M55 configMAX_SYSCALL_INTERRUPT_PRIORITY analogue with existing Fiber default, implemented-width and PRIGROUP validation. |
| `FIBER_PORT_CONTEXT_ABI_PORT_ID` | `fiber_portmacro.h` | New C5TF selected-profile/storage identity; no borrowing of C55N/C3TF providers. |
| `FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION` | `fiber_portmacro.h` | New C5TF selected-profile/storage identity; no borrowing of C55N/C3TF providers. |
| `FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT` | `fiber_portmacro.h` | Fiber identity bit vocabulary; PSPLIM 0x2 and Non-secure 0x80, unchanged basic frame shape. |
| `FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE` | `fiber_portmacro.h` | Fiber identity bit vocabulary; PSPLIM 0x2 and Non-secure 0x80, unchanged basic frame shape. |
| `FIBER_PORT_CONTEXT_ABI_FEATURE_MASK` | `fiber_portmacro.h` | New C5TF selected-profile/storage identity; no borrowing of C55N/C3TF providers. |
| `FIBER_PORT_EXC_BASE_BYTES` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `FIBER_PORT_EXC_FP_EXT_BYTES` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `FIBER_PORT_EXC_PER_LEVEL_BYTES` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `FIBER_PORT_SOFTWARE_FRAME_WORDS` | `fiber_portmacro.h` | Actual M55 no-MPU/no-FP/no-MVE frame: PSPLIM1 + EXC_RETURN1 + GPR8; EXC_RETURN index1. |
| `FIBER_PORT_SOFTWARE_FRAME_BYTES` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `FIBER_PORT_EXC_RETURN_WORD_INDEX` | `fiber_portmacro.h` | Actual M55 no-MPU/no-FP/no-MVE frame: PSPLIM1 + EXC_RETURN1 + GPR8; EXC_RETURN index1. |
| `FIBER_PORT_HIGH_FP_SOFTWARE_BYTES` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `FIBER_PORT_INITIAL_CONTEXT_BYTES` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `FIBER_PORT_MAX_SAVED_CONTEXT_BYTES` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `FIBER_PORT_SAVED_SP_MOD8` | `fiber_portmacro.h` | Actual basic M55 geometry: core32, software40, no FP extension/high block, initial72, maximum76 with pad4, saved SP mod8=0. |
| `fiber_portNVIC_INT_CTRL_REG` | `fiber_portmacro.h` | Actual M55 SCB ICSR 0xE000ED04 and PendSV set/clear bits28/27. |
| `fiber_portNVIC_PENDSVSET_BIT` | `fiber_portmacro.h` | Actual M55 SCB ICSR 0xE000ED04 and PendSV set/clear bits28/27. |
| `fiber_portNVIC_PENDSVCLEAR_BIT` | `fiber_portmacro.h` | Actual M55 SCB ICSR 0xE000ED04 and PendSV set/clear bits28/27. |
| `fiber_portVECTOR_INDEX_SVC` | `fiber_portmacro.h` | Actual M55 SVC11/PendSV14 vectors and lowest implemented exception priority; SVCall configured highest. |
| `fiber_portVECTOR_INDEX_PENDSV` | `fiber_portmacro.h` | Actual M55 SVC11/PendSV14 vectors and lowest implemented exception priority; SVCall configured highest. |
| `fiber_portLOWEST_EXCEPTION_PRIORITY` | `fiber_portmacro.h` | Actual M55 SVC11/PendSV14 vectors and lowest implemented exception priority; SVCall configured highest. |
| `fiber_portBASEPRI_SYM` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `fiber_portASM_WRITE_BASEPRI_R0` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `fiber_portASM_WRITE_BASEPRI_R2` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `fiber_portASM_WRITE_BASEPRI_R3` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `fiber_portASM_SNAP_BASEPRI_R3` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `fiber_portASM_WRITE_BASEPRI_R0_SYNC` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `fiber_portASM_WRITE_BASEPRI_R2_SYNC` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `fiber_portASM_WRITE_BASEPRI_R3_SYNC` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `fiber_portASM_ENTER_SCHEDULER_CRITICAL` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `fiber_portASM_EXIT_SCHEDULER_CRITICAL` | `fiber_portmacro.h` | Actual M55 MRS/MSR BASEPRI scheduler envelope; synchronized writes and preserved previous state, no Armv7-M7 workaround. |
| `FIBER_PORT_CM55_TFM_CONTEXT_SP_OFFSET` | `fiber_portmacro.h` | Fiber-only asserted public offsets/size/alignment: sp0, boot4, context76/align4, boot72. |
| `FIBER_PORT_CM55_TFM_CONTEXT_BOOT_OFFSET` | `fiber_portmacro.h` | Fiber-only asserted public offsets/size/alignment: sp0, boot4, context76/align4, boot72. |
| `FIBER_PORT_CM55_TFM_CONTEXT_SIZE` | `fiber_portmacro.h` | Fiber-only asserted public offsets/size/alignment: sp0, boot4, context76/align4, boot72. |
| `FIBER_PORT_CM55_TFM_CONTEXT_ALIGNMENT` | `fiber_portmacro.h` | Fiber-only asserted public offsets/size/alignment: sp0, boot4, context76/align4, boot72. |
| `FIBER_PORT_CM55_TFM_BOOT_SIZE` | `fiber_portmacro.h` | Fiber-only asserted public offsets/size/alignment: sp0, boot4, context76/align4, boot72. |
| `FIBER_SVC_START_NUMBER` | `fiber_portmacro.h` | Fiber defaults to ordinal70 versus the pinned FreeRTOS start ordinal; checked 8-bit immediate. |
| `FIBER_PORT_ARM_CM55_TFM_FIBER_PORT_BOOT_H_` | `fiber_port_boot.h` | Fiber-only include guard; no runtime reference behavior. |
| `FIBER_PORT_ARM_CM55_TFM_FIBER_PORT_BOOT_TYPES_H_` | `fiber_port_boot_types.h` | Fiber-only include guard; no runtime reference behavior. |
| `FIBER_PORT_ARM_CM55_TFM_FIBER_PORT_PRIVATE_H_` | `fiber_port_private.h` | Fiber-only include guard; no runtime reference behavior. |
| `FIBER_PORT_ARM_CM55_TFM_NON_SECURE_FIBER_PORT_TFM_ABI_H_` | `fiber_port_tfm_abi.h` | Fiber-only include guard; no runtime reference behavior. |
| `FIBER_PORT_TFM_SUCCESS` | `fiber_port_tfm_abi.h` | TF-M v2.0 mutex/initializer result vocabulary: success0, error UINT32_MAX, WAIT_FOREVER UINT32_MAX; not a new generic port operation. |
| `FIBER_PORT_TFM_ERROR` | `fiber_port_tfm_abi.h` | TF-M v2.0 mutex/initializer result vocabulary: success0, error UINT32_MAX, WAIT_FOREVER UINT32_MAX; not a new generic port operation. |
| `FIBER_PORT_ARM_CM55_TFM_NON_SECURE_FIBER_PORT_TFM_OS_WRAPPER_H_` | `fiber_port_tfm_os_wrapper.h` | Fiber-only include guard; no runtime reference behavior. |
| `FIBER_PORT_TFM_OS_WRAPPER_SUCCESS` | `fiber_port_tfm_os_wrapper.h` | TF-M v2.0 mutex/initializer result vocabulary: success0, error UINT32_MAX, WAIT_FOREVER UINT32_MAX; not a new generic port operation. |
| `FIBER_PORT_TFM_OS_WRAPPER_ERROR` | `fiber_port_tfm_os_wrapper.h` | TF-M v2.0 mutex/initializer result vocabulary: success0, error UINT32_MAX, WAIT_FOREVER UINT32_MAX; not a new generic port operation. |
| `FIBER_PORT_TFM_OS_WRAPPER_WAIT_FOREVER` | `fiber_port_tfm_os_wrapper.h` | TF-M v2.0 mutex/initializer result vocabulary: success0, error UINT32_MAX, WAIT_FOREVER UINT32_MAX; not a new generic port operation. |
| `FIBER_PORT_ARM_CM55_TFM_FIBER_PORT_TYPES_H_` | `fiber_port_types.h` | Fiber-only include guard; no runtime reference behavior. |
| `FIBER_PORT_NAME` | `fiber_port_types.h` | New C5TF selected-profile/storage identity; no borrowing of C55N/C3TF providers. |
| `FIBER_PORT_STORAGE_COHORT_PORT` | `fiber_port_types.h` | New C5TF selected-profile/storage identity; no borrowing of C55N/C3TF providers. |
| `FIBER_PORT_STORAGE_COHORT_REVISION` | `fiber_port_types.h` | New C5TF selected-profile/storage identity; no borrowing of C55N/C3TF providers. |
| `FIBER_PORT_STORAGE_COHORT_REGIONS` | `fiber_port_types.h` | New C5TF selected-profile/storage identity; no borrowing of C55N/C3TF providers. |

## Focused Evidence And Open Gates

Initial local GCC14.3.1 object builds passed for all four C objects at O0/O2/Os
using the actual scalar M55 target and CMSIS55 fixture. These twelve builds are
not execution or complete-group qualification. Initial artifacts are at:

```text
%TEMP%/fiber-c5tf-local-4e4aa41c0db748a68bcef0824cc02491
```

The final focused compile repeated all four objects at O0/O2/Os and added
O2-LTO/Os-LTO: twenty objects total, with exact eight-operation/strong-handler
symbol checks in all five modes. Twelve non-LTO objects were disassembled with
no FP/MVE instruction or instrumentation dependency found. Four C11/C++17
public/private-header syntax checks passed; the public checks use no CMSIS
include path. Eight exact-diagnostic manifest spot checks rejected Secure
CMSE, missing CMSE, a real hard-FP compiler ABI, synthetic MVE/PAC/BTI feature
facts, a foreign M55F MPU manifest and an attempted selectability override.
Synthetic feature cases are manifest diagnostics, not actual ISA execution.
The same root retains `focused-receipt.json`, per-object logs/symbols and
disassemblies; `freeze.json` records all twelve final file hashes. LTO objects
are not final-LTO generated-code or link evidence.

The bounded foreign-MPU follow-up rejected all seven existing region-count
inputs at values 0/8/16 in C11/C++17 at O2/Os: 84 exact-diagnostic negatives.
Before the change, the CM4/CM33/CM33F inputs compiled in all 36 combinations.
Sixteen mixed-header negatives also rejected the fixed-geometry CM0/CM3 MPU
type headers in both include orders. Four positive private-header probes and
all twenty object builds above passed again. This is compile-only evidence;
the public type-only header remains CPU-neutral and does not validate runtime
selection. Follow-up receipts and the refreshed twelve-file freeze are at:

```text
%TEMP%/fiber-c5tf-foreign-mpu-f7b804a2bbcf4412a63caa1aa3ca7772
```

The parent/Dalton full-group gate and Tesla actual-M55 assembly parity are
separate owners. Required qualification includes public C/C++ without CMSIS,
all eight operations, strong vectors11/14, normal/GC/LTO/archive extraction,
cold constructor/start reverse mismatch controls, storage/context stale-cohort
rejection, missing TF-M integration/external initializer, wrong-core/domain/
FP/MVE/MPU/PAC/BTI manifests, canonical attribute/instrumentation negatives,
and initialization/mutex ownership/contention/CPU-state failures. Compare
actual pinned M55 no-feature start/restore/PendSV at O2 and Os with explicit
hardening differences and mutation-sensitive generated-code classifiers.
Those tests and central registration are not added by this production slice.

No full matrix, commit, push, board programming, actual TF-M Secure image,
runtime promotion or hardware qualification was performed by this addition.
