# FreeRTOS-Style Cortex-M Support Plan

## Goal

Make `fiber` match the FreeRTOS Cortex-M CPU-port behavior where it matters for
a cooperative STM32 fiber library:

- correct PSP based exception return;
- correct callee-saved core register handling;
- correct `EXC_RETURN` handling;
- correct high FP register handling;
- correct PendSV priority and trigger rules;
- correct v8-M stack-limit handling where supported;
- clear and honest support boundaries per Cortex-M core family.

This is not a plan to clone the FreeRTOS scheduler. The target is FreeRTOS-like
CPU context-switch robustness without tasks, priorities, tick scheduling, queues,
a common FreeRTOS-style MPU task-management API, or the FreeRTOS API surface.
Selected MPU ports may still own optional pre-start region/privilege
configuration and an SVC yield path for unprivileged fibers.

The portable API and mandatory CPU runtime ABI stay minimal. Feature-specific
MPU, SecureContext, and TF-M operations are separate selected-port integration
ABIs in separate headers and sources. `fiber_core.h` does not include them,
common runtime objects do not call them, and ports without the feature provide
no no-op compatibility stubs. Every production profile supplies a safe default
that runs feature-blind portable application code without an extension call.
TrustZone Secure companion gateways are versioned cross-image ABIs; TF-M
profiles use the matching NTZ-style CPU port and TF-M integration instead of the
fiber-owned SecureContext companion.

The future user lifecycle for a fiber-owned SecureContext companion is frozen
in `TRUSTZONE_SECURE_CONTEXT_CONTRACT.md`. It intentionally uses a selected-port
pre-start attachment rather than copying FreeRTOS's task-side allocation macro:
fiber contexts are static and sealed before `fiber_start()`, while PendSV still
owns all automatic Secure save/load work.

The policy for using FreeRTOS `portable/` as a reference, rather than as a
compiled backend, is documented in `V2_FREERTOS_PORT_REFERENCE_POLICY.md`.

`CONTEXT_FIBER_ARCHITECTURE.md` freezes the later module boundary around this
work. FreeRTOS parity belongs to selected processor Context backends: initial
frame construction, exception entry/return, register save/restore, masks,
FPU/MPU/security state, and architecture errata. FreeRTOS scheduler lists,
queues, task policy, and public APIs are not imported. The portable Fiber and
C++ Kernel layers consume the Context dispatcher surface and remain independent
of every concrete `portable/` implementation.

`STM32_PORT_FREEZE_INVENTORY.md` is the current execution ledger for this plan.
It records ten runtime-capable concrete profiles, including the explicitly
build-selected `ARM_CM0_MPU` protected runtime and its archive/linker proof,
then the remaining CM33 MPU/security, CM55/N6, and announced CM85/V8 work,
planning ranges, and the exact gate before Context extraction.

The required common-core boundary before production ports are added in bulk is
defined in `V2_OPAQUE_CONTEXT_CONTRACT.md`. `fiber_api_types.h` exposes only
the forward declaration and callbacks, while each selected port owns its
complete `FiberContext`, `FiberPortBoot` record, boot/hash implementation, and
CPU state. The current physical `sp + FiberPortBoot` shape is transitional, but
common runtime sources now operate through the callable port ABI and do not
access that layout.

## Current Baseline

Primary target, pending a fresh hardware run after the current hardening diff:

- STM32H7 / Cortex-M7.

Implemented and aligned with the FreeRTOS non-MPU PendSV pattern:

- `r4-r11` are saved and restored.
- `LR` is preserved as `EXC_RETURN`.
- PSP is used for fiber stacks.
- PendSV performs the actual switch.
- PendSV is configured at the lowest priority.
- `s16-s31` are saved and restored only when `EXC_RETURN` reports an extended
  FP frame.
- `FIBER_FPU_LAZY = 0` keeps FP stacking deterministic by default.
- The initial stacked `PC` has bit 0 clear; Thumb state comes from `xPSR.T`.
- initial `EXC_RETURN` is selected-port-owned. The concrete CM7 value is fixed
  at `0xFFFFFFFDu`; only transitional v8-M bring-up still accepts an input.
- First-fiber start uses SVC and enters the first fiber by exception return.
  The direct boot trampoline has been removed; each selected port must provide
  an SVC first-start symbol.
- The current validated privileged CM7 request path rejects Handler mode and
  rejects scheduler jumps while PRIMASK, BASEPRI, or FAULTMASK is nonzero.
- `fiber_schedule()` delegates its environment checks and PendSV request through
  the single final selected-port ABI operation. The selected CM7 port preserves
  the historical
  `IPSR -> current -> PRIMASK -> BASEPRI -> FAULTMASK -> PENDSVSET` sequence.
  A fresh H7 board run is still required after this source-boundary change.
- Future unprivileged MPU paths use a validated yield SVC and enforce zero mask
  state as a selected-port restore invariant instead of reading privileged mask
  registers from common Thread-mode code.

Closed hardening items from the FreeRTOS comparison:

- the compile matrix now runs one paired generated-assembly cohort for M0,
  M0+, M0+ MPU, M3, M4F, M7 r0p1, M23 NTZ, M33 NTZ, M33F NTZ,
  CM3 MPU, and CM4 MPU. It verifies the pinned FreeRTOS commit plus every
  consumed portable-file hash, compiles both objects with identical CPU/FPU
  flags, and checks ordered first-start, save, mask, MPU/FP, restore, and
  exception-return operations. Every accepted divergence has a normative
  `FAP-*` rationale in `FREERTOS_ASM_PARITY.md`;
- stacked `PC` bit 0 handling is fixed;
- each selected port publishes its initial `EXC_RETURN`; the concrete CM7 port
  rejects attempts to override its fixed `0xFFFFFFFDu` ABI;
- `CONTROL.FPCA` is cleared before the first fiber entry when needed;
- real switches are rejected when `PRIMASK` would defer PendSV;
- real switches are rejected when `BASEPRI` would defer PendSV;
- real switches are rejected when `FAULTMASK` would defer PendSV;
- STM32H7 hardware validation covered a normal long-running switch loop,
  pre-boot FP use, current-fiber tracking, and forced delayed-switch traps for
  `PRIMASK` (`'p'`) and `BASEPRI` (`'b'`);
- STM32H7 validation also covered `FIBER_FPU_LAZY = 1` in a long-running
  switch loop; switch barriers are now mandatory and have no disable knob;
- current-fiber ownership is implemented through `fiber_start()`,
  `fiber_current()`, `fiber_schedule()`, and the scheduler bridge;
- startup mask cleanup no longer emits `FAULTMASK` on baseline cores that do
  not implement it;
- obsolete archived `fiber/old` source was removed so audits and validation
  only cover the active runtime implementation;
- runtime exception setup validation checks PendSV priority, PendSV/SVC vector
  routing, SVCall priority for SVC first-start, BASEPRI priority-bit policy,
  FreeRTOS-style `AIRCR.PRIGROUP` compatibility, and Cortex-M7 r0p0/r0p1 errata
  gating;
- ARMv7E-M SVC first-start validates privileged Thread/MSP setup, MSP read-back,
  pending-PendSV cleanup, SVC provenance, SVC MSP-frame alignment, SVC opcode
  and immediate value,
  restore-context integrity, fault exception enable, BASEPRI cleanup, PSP setup,
  and `CONTROL.FPCA` state before exception return. Thread PSP selection is
  performed by the `EXC_RETURN` value, matching the FreeRTOS first-task start
  model;
- handler-side scheduler calls use the FreeRTOS critical-section pattern:
  `BASEPRI` on BASEPRI-capable ports and saved `PRIMASK` on BASEPRI-less ports;
- initial software-frame sizing, saved-SP modulo validation, and saved
  `EXC_RETURN` word selection now come from selected port traits instead of a
  common hard-coded 36-byte assumption;
- each current selected port now owns `fiber_port_types.h`,
  `fiber_port_boot_types.h`, `fiber_port_boot.h`, `fiber_port_private.h`, and
  `fiber_port_boot.c`;
  `fiber_port_selected.h` is the sole public type selector and selects one
  local `fiber_port_types.h`. The matching selected `fiber_portmacro.h` owns CPU
  traits and inline mechanics, while `fiber_port_private.h` shares cross-file
  implementation declarations only inside that concrete port. `fiber_types.h`
  remains a source-compatible facade. The physical `sp + FiberPortBoot` layout
  is transitional, while common sources already use the opaque callable ABI;
- build-selected portmacro workflow exists for the first FreeRTOS-referenced
  Cortex-M7 source group:
  `fiber/port/ARM_CM7/r0p1/fiber_portmacro.h` and `fiber_port.c`. The
  matrix compiles this source group for Cortex-M7/Cortex-M7F build-selected
  modes with its port-owned errata workaround always enabled;
- scheduled context restore recomputes the selected-port boot-record hash by
  default; `FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0` is an explicit
  performance opt-out, while mandatory structural, canary, frame, EXC_RETURN,
  xPSR, and Thumb-PC validation remain active. Optional
  `FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1` adds linker-map validation of
  runtime context/stack and saved-PC addresses;
- portable FPU policy defaults to `FIBER_FPU_LAZY = 0`; PendSV publication and
  context-boundary DSB/ISB serialization are mandatory selected-port behavior;
- source comments no longer claim full "all STM32" validation;
- M0/M0+ MSP rewind behavior is documented as platform-dependent;
- M23, M33, M55/MVE, TrustZone/Non-secure, and PAC/BTI runtime use is now
  explicitly policy-gated until FreeRTOS-style context layout and hardware
  validation exist.

## Support Matrix

| Core family | Current state | Target state |
| --- | --- | --- |
| Cortex-M0/M0+ | Concrete `port/ARM_CM0` SVC/PendSV/frame code is compile/link-covered | Validate on hardware and document MSP rewind policy |
| Cortex-M0+ MPU | Exact build-selected `ARM_CM0_MPU` slices 1-6 implement protected construction/linker isolation, all eight forward runtime ABI operations, strong SVC/PendSV ownership, first-start/public-yield/task-return SVC services, full protected Thumb-1 save/select/MPU-replace/restore, and MPU readback. Normal/LTO archive extraction, exact MPU section placement, VTOR-present/absent cohort expectation, direct vectors, generated FreeRTOS assembly parity, and stale/duplicate negative links pass. It remains outside global auto/profile selection and exposes no public optional MPU extension. | Run Cortex-M0+ MPU hardware and isolation validation; add the optional heterogeneous-MPU feature only if a product needs it. |
| Cortex-M3 | Concrete `port/ARM_CM3` SVC/PendSV/frame code is compile/link-covered | Validate on hardware |
| Cortex-M3 MPU | Exact reference audit plus slices 1-4, 6, and 7 are complete: type/layout, MPU construction, linker isolation, protected SVC/PendSV, all eight forward ABI operations, exact build-selected facade, portable-application archive extraction, exact MPU section placement, cohort, section-GC, normal/LTO, vector, and duplicate-handler proofs pass; hardware runtime is unvalidated | Run the complete Cortex-M3 MPU hardware and isolation suite before any STM32/runtime claim |
| Cortex-M4F | Concrete `port/ARM_CM4` source group is compile/link-covered and FPU-aware | Run M4F hardware FP stress validation |
| Cortex-M4F/M7F MPU | Exact build-selected `port/ARM_CM4_MPU` slices 1-5 implement the pinned FreeRTOS 53-word protected FP context, exact 8/16-region MPU construction, all eight forward ABI operations, strong fail-closed SVC/PendSV, unprivileged yield/return veneers, dynamic basic/extended FP save/restore, exact MPU replacement/readback, CPACR/FPCCR policy, scheduler BASEPRI envelope, and M7 errata-safe BASEPRI writes; portable application archive extraction, exact MPU linker placement, cohort, vectors, GC, and normal/LTO modes are compile/ELF-covered | Establish separate M4F and M7F hardware/isolation claims; keep the protected profile outside global auto/profile selection |
| Cortex-M7F | STM32H7 embedding build selects the concrete FreeRTOS-referenced `ARM_CM7/r0p1` source group; compile matrix requires one complete port ABI definition set | Re-run H7 normal and all trap modes after current hardening; validate r0p0/r0p1 on affected hardware |
| Cortex-M23 | Exact build-selected `ARM_CM23_NTZ` slices 1-5 freeze the FreeRTOS ten-word non-MPU Non-secure frame, implement sealed context construction, strong fail-closed SVC first start, exact `0xFFFFFFB8` provenance, and PendSV save/select/restore with `+24/-36` Thumb-1 geometry; the ignored PSPLIM slot starts with `stack_base`, each ordinary save writes zero, and register access stays disabled. Static archive extraction, exact cohort, vector, section-GC, normal/LTO, and duplicate-handler proofs pass. | Validate the concrete Non-secure profile on hardware; keep global selector routing and Secure/MPU roles separate |
| Cortex-M33 | Exact build-selected `ARM_CM33_NTZ/non_secure` slices 1-4 freeze the pinned FreeRTOS Mainline NTZ non-MPU/no-FPU ten-word `[PSPLIM][EXC_RETURN][r4-r11]` layout and implement sealed construction, paranoid SVC first start, exact live-PSPLIM PendSV save/restore, the eighth forward operation, paired `-O2`/`-Os` assembly parity, and normal/LTO archive/vector/ELF proofs. Global auto-selection and hardware support remain unclaimed. | Validate the concrete NTZ runtime on Cortex-M33 hardware; keep MPU, SecureContext, TF-M, and M33F as separate profiles. |
| Cortex-M33F | Exact build-selected `ARM_CM33F_NTZ/non_secure` slices 1-4 define the FPU cohort, sealed 72-byte basic initial frame, 212-byte maximum frame, CPACR/FPCCR setup/readback, strict SVC first start, and exact basic/extended FP PendSV save/select/restore with PSPLIM. Hard-float and softfp builds pass paired construction/SVC/PendSV generated-assembly checks; normal/LTO archive proof retains strong SVC/PendSV handlers in slots 11/14, all eight forward ABI operations, and rejects competing handler ownership. Global auto-selection and hardware support remain unclaimed. | Validate first start plus basic/extended FP switching, vectors, priority readback, and long-run FPU stress on real Cortex-M33F Non-secure hardware. |
| Cortex-M33 MPU | `ARM_CM33_MPU/non_secure` slices 1-3 freeze the explicit build-selected `GCC/ARM_CM33_NTZ/non_secure` no-FPU/no-TrustZone 8- or 16-region cohort, sealed unprivileged construction, exact RBAR/RLAR/MAIR0/global-image/linker policy, and direct protected SVC first start. The first SVC validates vector/frame provenance, programs and reads back globals while MPU is disabled, restores MAIR0 and selected pairs, enables `MPU_CTRL=ENABLE|PRIVDEFENA`, validates the active image, then restores `PSP`/`PSPLIM`/`CONTROL` and the protected frame. `-O2`/`-Os` parity, LTO, synthetic vector slot 11, and duplicate-SVC negative links pass. PendSV, forward runtime ABI, optional MPU API, and hardware support remain unclaimed. | Add protected PendSV save/select/MPU-replace/restore, then archive/ELF/cohort proof and hardware MPU-isolation validation. Keep FPU, SecureContext, TF-M, PAC/BTI, and MVE as separate cohorts. |
| Cortex-M55/MVE | Transitional SVC/PendSV/frame code exists and is compile-covered, but MVE/PAC/BTI policy is not FreeRTOS-level | Add MVE/PAC/BTI context policy and hardware validation |
| Cortex-M85/MVE/PACBTI | No concrete selected port. The pinned FreeRTOS graph contains CM85 Non-secure, Secure companion, NTZ, MPU, and TF-M variants; ST now lists the preannounced STM32V8 Cortex-M85 series. | Include the exact STM32V8 profile before an all-announced-STM32 freeze, or record an explicit preannouncement deferral. |

## Priority Roadmap

### P0: Next Validation

0. Keep STM32H7 runtime validation current after behavior changes.

   `cf610cc` changed the ARMv7E-M/H7 `FiberContext.sp` invariant to the
   FreeRTOS `pxTopOfStack` model. Commit `775648c` then integrated the larger
   scheduler-driven v2 execution model: direct target switching is removed,
   PendSV asks the scheduler bridge for the next context, handler-side scheduler
   calls use the port critical-section policy, and runtime exception setup plus
   unvalidated feature policies are enforced.

   This is architecturally cleaner, but it is behavior-affecting. The later
   ARMv7E-M SVC first-start checkpoint is also behavior-affecting because the
   first fiber is entered by SVC exception return instead of a direct branch.

   The 2026-07-11 STM32H7 run passed the active H7 validation set after two SVC
   migration fixes:

   - SVC first-start must select Thread PSP through `EXC_RETURN`, not by
     writing `CONTROL.SPSEL` from Handler mode;
   - PendSV must validate the interrupted stack source through active
     `LR`/`EXC_RETURN` bit 2, not by reading `CONTROL.SPSEL`.

   Repeat `H7_RUNTIME_VALIDATION.md` after every behavior-affecting change to
   startup, PendSV, scheduler bridge state, saved stack layout, exception setup,
   interrupt-mask policy, or selected-port traits.

1. Maintain a compile/link matrix for representative Cortex-M targets.

   Tooling:

   ```powershell
   .\tools\compile_matrix.ps1
   ```

   Current matrix set:

   - Cortex-M0 or M0+
   - explicit build-selected Cortex-M0+ MPU profile with normal/LTO archive,
     exact MPU linker, vector, and stale-cohort negative proofs
   - Cortex-M3
   - Cortex-M4 without FPU
   - Cortex-M4F
   - Cortex-M7 without FPU
   - Cortex-M7F
   - Cortex-M23
   - Cortex-M33 without FPU
   - Cortex-M33F
   - Cortex-M55 without FPU
   - Cortex-M55F
   - Cortex-M55 MVE-FP
   - ARMv8-M/ARMv8.1-M
     `FIBER_TRANSITIONAL_V8M_RUN_NONSECURE=1` compile mode
   - ARMv8-M/ARMv8.1-M Secure-to-Non-secure bank compile mode with
     `FIBER_TZ_NS=1` and `-mcmse`
   - build-selected portmacro mode with `FIBER_PORT_BUILD_SELECTED=1`
   - Cortex-M7/Cortex-M7F build-selected source group
     `fiber/port/ARM_CM7/r0p1/fiber_port.c`, including the port-owned errata
     workaround
   - exact eight-function forward ABI and reverse ABI v1 symbol sets
   - exactly one active selected-port relocation to
     `fiber_internal_runtime_port_abi_v1_anchor`
   - strong selected-port `fiber_panic()` references with one weak common
     fallback definition
   - assembly-only current-slot references and rejection of transitional
     reverse symbol names
   - exactly one strong selected-port `SVC_Handler` and `PendSV_Handler` for
     every compiled profile
   - CM7 static-archive extraction with startup weak aliases
   - CM7 vector slots 11/14 resolving to selected strong handlers
   - deliberate competing strong-handler link failure
   - CM7 handler retention under `--gc-sections` and LTO
   - adversarial generated-code checks for the public sensitive ABI, scheduler
     hook, and selected-port build counter-flags

   Passing the matrix is compile/link coverage only; runtime support still
   requires profile-specific hardware validation.

2. Keep expanding the focused STM32H7 runtime stress tests.

   The canonical checklist is `H7_RUNTIME_VALIDATION.md`. That file is the
   gate for promoting the v2 ARMv7E-M path back to H7 runtime-validated after
   behavior-affecting changes.

   Already covered manually on hardware:

   - normal scheduler-driven `fiber_schedule()`;
   - missing scheduler hook traps with `'K'`;
   - `NULL` scheduler hook traps with `'K'`;
   - changing the scheduler hook after the current context is published traps with
     `'k'`;
   - scheduler jump with `PRIMASK != 0` must trap;
   - scheduler jump with `BASEPRI != 0` must trap on BASEPRI-capable cores;
   - scheduler jump with `FAULTMASK != 0` must trap on FAULTMASK-capable cores.
   - scheduler hook returning `NULL` traps with `'N'`;
   - scheduler hook returning a context with `sp == NULL` traps with `'P'`.

   Remaining useful cases:

   - `fiber_schedule()` from Handler mode must trap;
   - invalid `AIRCR.PRIGROUP` for the scheduler `BASEPRI` policy must trap with
     `'g'`;
   - scheduler hook returning an uninitialized or corrupted context must trap
     before PendSV restores PSP;
   - scheduler hook mutation of PRIMASK, FAULTMASK, or BASEPRI must trap for
     both first selection and PendSV selection;
   - damaged software canary must trap with `'c'`;
   - scheduler hook returning a context with an exact-encoding-invalid
     EXC_RETURN must trap with `'x'`;
   - insufficient restore-frame headroom must trap with `'X'`;
   - package the manual checks into a repeatable board validation mode.

3. Keep the FPU startup hygiene stress test active.

   Already covered manually on hardware:

   - execute floating-point code before `fiber_start()`;
   - enter the first fiber;
   - verify that clearing `CONTROL.FPCA` prevents pre-fiber FP active state from
     leaking into the fiber runtime;
   - run the existing FP switch stress afterward.

4. Keep lazy-FPU validation separate from portable defaults.

   The H7 path has passed a long run with:

   ```c
   #define FIBER_FPU_LAZY 1
   ```

   Treat this as target-specific evidence, not proof that every Cortex-M target
   should use lazy stacking. Mandatory barriers are not part of performance
   tuning. New core families should first pass eager FP policy, then lazy FP.

5. Keep source support claims aligned with README, DECISIONS.md, and this plan
   before every release.

### P1: FreeRTOS Port Parity Decisions

1. Finish the FreeRTOS-style port ownership split.

   The opaque callable phase of `V2_OPAQUE_CONTEXT_CONTRACT.md` is complete:
   each selected port exports `fiber_port_types.h`, the selected facade
   completes `FiberContext` for application allocation, and common runtime
   uses `fiber_port_runtime_abi.h` with incomplete context pointers. CPU-state
   snapshots remain private local data in selected port wrappers; common runtime
   has no selected-port token type to allocate or inspect. Common runtime files
   no longer include the selected complete port contract or contain
   architecture-specific switch assembly.

   Move out of common code:

   - transitional fallback `fiber_port_init_context_frame()`;
   - any transitional common PendSV implementation;
   - direct startup trampoline mechanics;
   - SVC first-start mechanics;
   - CONTROL/PSP/MSP programming;
   - PendSV/SVC priority setup and vector routing validation;
   - BASEPRI/PRIMASK scheduler critical-section assembly;
   - Cortex-M7 r0p0/r0p1 errata policy;
   - PSPLIM/FPU/MVE/PAC/BTI policy decisions that depend on the selected
     architecture profile.

   Keep in common code:

   - public cooperative API semantics;
   - scheduler hook storage and current-context ownership policy;
   - CPU-neutral immutable metadata helpers that do not reveal where the
     selected port embeds that metadata;
   - portable diagnostics and integration-defined RAM/code plausibility hooks.

   Freeze the reverse dependency before bulk porting. Every selected port uses
   only `fiber_runtime_port_abi.h` to reach common scheduler/current state. Its
   v1 symbol set, assembly-only current-slot rule, retained link anchor, exact
   undefined-symbol and no-store allowlists, version-mismatch negative link,
   section-GC, and LTO proofs are normative in
   `V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md`. A separately archived handler bundle
   uses its own unique extraction anchor; startup weak handler names are not an
   extraction mechanism.

   The v1 anchor versions the complete mandatory bidirectional contract: all
   eight common-to-port functions, all reverse v1 symbols, calling conventions,
   required compiler attributes, and normative semantics. The matrix must fail
   both old-common/new-port and new-common/old-port combinations. The separate
   context-layout relocation still proves selected public type/header/object
   compatibility. One always-linked mandatory port identity object defines the
   exact profile/context anchor; every other mandatory selected-port object and
   the build-owned expectation object retain it. Stale object mixtures therefore
   fail even when the generic runtime ABI generation is unchanged.

   The reverse-runtime proof cohort is active: every selected-port relocatable
   group has an exact unresolved-symbol allowlist, selected ports define no
   common-owned reverse symbol, C cannot access the current slot, generated
   assembly may only load it through the exact address/load pair, and both v1/v2
   mismatch directions fail from static archives under section GC and LTO.
   The independent exact profile/context cohort guard is also active: one
   selected runtime object defines its generated identity, boot and exception
   retain it, and a separately compiled build-owned expectation is kept outside
   a precompiled port archive. Real Secure-role/Non-secure-role stale runtime,
   boot, exception, and complete-archive links fail in both directions under
   section GC and LTO.

   The start, schedule, SVC, PendSV, scheduler-hook, and reverse-helper call
   graph uses sensitive plus general-registers-only attributes. Adversarial
   instrumentation, stack-protector, sanitizer, profiler, and LTO builds must
   prove that no hidden runtime calls or FP/MVE instructions enter those paths.

   Keep in the selected port:

   - the complete `FiberContext` layout and any port-specific boot data;
   - context construction, final sealing, and restore validation;
   - saved-SP, EXC_RETURN, CONTROL, PSPLIM, MPU, security, PAC, FP, and MVE
     storage as required by that profile;
   - runtime MSP preparation and first-context SVC transfer.

   Do not add MPU, SecureContext, or TF-M functions to either mandatory ABI.
   FreeRTOS keeps those concerns in MPU port files, Secure companion files, or
   Non-secure/TF-M variants; fiber follows the same artifact split. A selected
   profile without a feature exports no extension functions. A capable profile
   supplies a separate integration-only header and matching source or
   cross-image companion, while its mandatory CPU mechanics remain private to
   the selected port. Portable application code includes only `fiber_core.h`;
   profile integration uses an extension header only for a deliberate
   non-default, non-portable policy.

   A context-mutating extension additionally links optional common
   `fiber_runtime_context_configuration.c` and calls only the versioned guard
   declared by `fiber_runtime_context_configuration_abi.h`. This preserves
   common lifecycle ownership without adding MPU/security operations to the
   base reverse ABI. Profiles without an extension omit both files.

   The common metadata hash is not the final context proof. Every production
   port owns an immutable seal over its layout/configuration identity and
   validates mutable saved state separately before restore. The structural move
   must preserve current scheduler critical-section placement; callback-wrapper
   redesign is a separate behavior change.

   A transitional fallback may exist only under an explicitly transitional
   directory such as `port/transitional_v8m`. A port cannot be claimed as
   FreeRTOS-level while it depends on transitional PendSV or frame layout.

   The `fiber/port` helper-root convention is reserved for reusable helper code, not
   selected-port fallback behavior.

   Before bulk porting, add exact build-selected manifests. An architecture
   macro is only a compatibility gate; each production profile records selected
   include path, source group, compiler/toolchain identity and version,
   CPU/FPU/ABI flags, MPU/privilege mode, security-domain role,
   FP/MVE/PAC/BTI and errata policy, context identity, and companion artifacts.
   Auto/profile/force modes cannot claim production MPU, unprivileged,
   TrustZone, NTZ, TF-M, MVE, PAC, or BTI support.

   The concrete roadmap includes both configurations hidden inside some
   FreeRTOS directories:

   - `ARM_CM0` privileged and `ARM_CM0` MPU/unprivileged;
   - `ARM_CM3` and `ARM_CM3_MPU`;
   - `ARM_CM4F` and `ARM_CM4_MPU`;
   - privileged `ARM_CM7/r0p1` and M7 MPU/unprivileged behavior referenced from
     `ARM_CM4_MPU` with CPUID-validated errata 837070 policy;
   - exact CM23 Secure-only, Non-secure with/without a SecureContext companion,
     and NTZ profiles, plus the corresponding CM33/CM55 roles and their TF-M
     profiles relevant to current STM32 targets;
   - CM35P and CM52 as reference-portability rows without an STM32 hardware
     claim, including the distinct CM52 TF-M build profile in the local
     FreeRTOS graph;
   - CM85 as announced STM32V8 scope rather than a permanently non-STM32
     reference row. Until the preannouncement is admitted into the freeze, the
     exclusion must be explicit. If admitted, cover the local FreeRTOS
     Non-secure, Secure companion, NTZ, MPU, PAC/BTI, MVE, and TF-M mechanics.

   Initial production compiler evidence is GNU Arm Embedded GCC only. Other
   compiler families need their own compiler-port matrix before inheriting a CPU
   runtime claim.

2. Keep Cortex-M7 r0p1 errata policy explicit.

   FreeRTOS wraps `BASEPRI` writes in PendSV on Cortex-M7 r0p1 because of ARM
   errata 837070. The ARMv7E-M scheduler-driven `fiber` PendSV path now writes
   `BASEPRI` around the scheduler bridge, then restores the previous value
   before restoring the selected context.

   The concrete `ARM_CM7/r0p1` port always enables the FreeRTOS-style workaround
   around handler-side `BASEPRI` writes. Unlike the FreeRTOS minimum sequence,
   the fiber helper preserves and restores the previous `PRIMASK` instead of
   unconditionally re-enabling IRQs; this keeps SVC/start critical sections
   closed while still serializing the `BASEPRI` write. The compile matrix builds
   Cortex-M7 and Cortex-M7F through this concrete source group. Runtime startup
   checks CPUID and the immutable port trait. Real
   affected M7 hardware validation is still required before claiming parity with
   the FreeRTOS CM7/r0p1 port.

3. Finish Cortex-M23 support or keep it explicitly excluded.

   Options:

   - implement a v8-M Baseline path with a PSPLIM slot similar to FreeRTOS NTZ;
   - or mark M23 as not supported until hardware/toolchain validation exists.

   Current policy: M23 has an exact build-selected concrete NTZ runtime, but it
   is not hardware-supported. Exact `ARM_CM23_NTZ` slices 1-5 freeze the missing
   PSPLIM-slot and Non-secure context identity, build the matching initial
   context, and implement SVC first start plus PendSV switching. Static archive,
   external cohort expectation, vector, section-GC, normal/LTO, and
   duplicate-handler evidence is complete. Global auto/profile selection still
   deliberately routes ARMv8-M Baseline through `transitional_v8m`.
   FreeRTOS has a PSPLIM slot in the CM23 NTZ context layout, but it also gates
   actual PSPLIM register access through target/security configuration because
   Non-secure Cortex-M23 does not have a Non-secure PSPLIM register. The
   transitional fiber baseline path still has no PSPLIM slot. The concrete NTZ
   profile has the slot, seeds its initial value from `stack_base`, keeps
   `FIBER_PORT_USES_PSPLIM_REGISTER == 0`, and is intentionally ABI-distinct
   from that fixture. Its PendSV save path writes zero into the ignored slot,
   matching the reference NTZ branch.

   Future direction: copying the FreeRTOS-style M23 layout is useful if `fiber`
   wants to claim ARMv8-M Baseline/Mainline parity. That work should be done as
   a dedicated ARMv8-M portability pass after the unsupported-port gate exists,
   not as part of STM32H7/M7 hardening. The implementation should separate:

   - a context slot for PSPLIM;
   - a compile-time `FIBER_PORT_USES_PSPLIM_REGISTER` trait;
   - M23 Non-secure behavior, where PSPLIM register access must stay disabled;
   - M23 Secure-only behavior, which needs separate validation;
   - M33/M55 Mainline behavior, where PSPLIM register access is expected.

4. Implement and validate ARMv8-M Non-secure behavior.

   Required checks:

   - a port-owned `FIBER_PORT_INITIAL_EXC_RETURN = 0xFFFFFFBCu` path;
   - PSPLIM symbol selection;
   - CPACR/NSACR behavior for FP access;
   - vector table and PendSV wiring in the current security domain.
   - context slots for `CONTROL`, `PSPLIM`, and security-domain state when
     matching a FreeRTOS CM33/CM55-style port.

   Current policy: Non-secure and Secure-to-Non-secure bank builds remain
   unsupported until their selected ports provide the required security-domain
   context state.

5. Complete MVE/PAC/BTI policy for Cortex-M55 class targets.

   Required checks:

   - MVE-FP uses the current extended FP save/restore model;
   - MVE without scalar FP is rejected by runtime policy validation;
   - PAC/BTI context support is compile-blocked until save/restore is
     implemented;
   - hardware validation is still required before enabling MVE runtime by
     default.

### P2: API Safety

1. Keep current-fiber tracking on the preferred API path.

   The preferred low-level API now mirrors the FreeRTOS `pxCurrentTCB`
   ownership model:

   ```c
   FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
   FIBER_API_THREAD_FUNCTION
   FiberContext *fiber_current(void);

   FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
   FIBER_API_THREAD_FUNCTION
   void fiber_schedule(void);

   void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                      void *user);
   FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
   void fiber_start(void);
   ```

   `fiber_start()` calls the configured scheduler hook with `current == NULL`,
   the selected port validates the returned first context, and common runtime
   publishes it through reverse ABI v1.
   PendSV later saves that context, asks the scheduler bridge for the next
   context, and restores only the returned context. The core API does not
   accept `from` or `to` from Thread mode.

   Each selected port uses SVC for first start. Ports no longer have a direct
   trampoline fallback. PendSV must still verify from the
   active `EXC_RETURN` value that the interrupted Thread context used PSP before
   saving a source context. A pre-start or foreign PendSV now traps with `'j'`
   instead of publishing a bogus saved stack pointer.

   The port also checks live PSP source-save headroom before writing the
   software frame. If the save would cross the current fiber stack base, it
   traps with `'d'` before modifying memory. This is stricter than the small
   FreeRTOS PendSV snippets, which rely on the broader RTOS stack-checking
   infrastructure.

   There is no v2 public API for starting from a caller-provided port boot
   record. Ports without hardware validation are not runtime-supported.

2. Move vector wiring to exclusive selected-port handler ownership.

   Rationale: FreeRTOS treats exception handlers as part of its CPU-port
   integration. The final fiber boundary follows the same static ownership
   discipline while keeping stronger runtime checks:

   - each selected port defines strong `SVC_Handler` and `PendSV_Handler`;
   - application and CubeMX strong wrappers are removed or excluded;
   - competing strong definitions intentionally fail the link;
   - wrapper/direct-vector settings are deleted;
   - the matrix proves archive extraction through the unique handler-bundle
     anchor when needed, and proves vector slots 11 and 14;
   - runtime startup validates the selected active vector source, priority
     readback, and actual SVC/PendSV dispatch;
   - VTOR-capable ports read back the applicable VTOR bank, while ports without
     VTOR validate their architecture/platform vector base and remap policy;
   - H7 validation specifically reads back `SCB->VTOR`.

   The handler migration is complete for every current selected port. Runtime
   vector-table patching and application-owned branch wrappers are not fallback
   paths.

   The selected ARMv7E-M SVC handler must retain the existing dispatch checks:
   MSP-frame alignment, SVC opcode, and configured immediate. It traps with
   `'u'` when the instruction is not the selected start service.

3. Keep the ARMv7E-M SVC-based first-fiber start path validated separately.

   FreeRTOS starts the first task through an SVC handler and enters the task by
   exception return. The ARMv7E-M `fiber` path now does the same high-level
   thing, while adding extra local checks:
   privileged Thread/MSP setup, optional MSP rewind and read-back, pending
   PendSV cleanup before interrupts reopen, SVC immediate validation,
   seeded-current validation, fault exception enable, BASEPRI cleanup, SVC
   MSP-frame alignment, SVC opcode/immediate validation, PSP setup, and
   `CONTROL.FPCA` verification. The SVC handler does not set
   `CONTROL.SPSEL` from Handler mode; the first Thread-mode PSP entry is
   selected by `EXC_RETURN`, as in the FreeRTOS first-task start path.

   The direct trampoline is no longer available. New ports must add an SVC
   first-start path before they can become runtime-supported.

   MPU/unprivileged ports additionally own yield and task-return SVC services.
   Their selected service namespace must reject collisions and unknown
   immediates, and a returned unprivileged fiber must reach the common `'R'`
   sink through a port-owned veneer rather than branching into privileged
   common text. Linker/MPU validation must also keep writable stacks separate
   from writable context and scheduler state.

4. Consider moving PendSV assembly into a dedicated assembly source.

   Rationale: naked C plus inline assembly works, but a dedicated assembly file
   can make architecture-specific variants clearer once M23/M33/M55 support is
   expanded.

## Definition of Done

The library can claim FreeRTOS-style STM32 Cortex-M CPU-port support only when:

- each claimed core family has an explicit support status;
- each claimed core family has a concrete selected port header/source pair that
  exports the full port interface;
- common runtime files contain no architecture-specific PendSV, SVC, direct
  trampoline, or synthetic-frame fallback for claimed ports;
- the claimed core families compile with representative GCC target flags;
- the STM32H7/M7 path remains hardware validated;
- M23, M33 Non-secure, and M55/MVE are either implemented and validated or
  explicitly excluded;
- announced M85/STM32V8 is either implemented with its exact profile evidence
  or explicitly deferred as preannouncement scope;
- docs and source comments use the same support claims;
- context-switch safety checks reject delayed-switch cases caused by interrupt
  masks.
