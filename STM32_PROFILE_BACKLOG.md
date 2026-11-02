# STM32 Profile Backlog

## Purpose And Baseline

This is the implementation backlog accompanying
[`STM32_PORT_FREEZE_INVENTORY.md`](STM32_PORT_FREEZE_INVENTORY.md), not a new
support declaration or a replacement for a profile's `FREERTOS_PARITY.md`.
It reconciles source groups, implemented manifests, pending processor-state
mechanics, and unresolved inclusion choices before Context/Fiber extraction.

Recorded implementation inventory on 2026-11-02:

```text
Fiber:             current shared v2 worktree
Runtime profiles:  21 recorded complete software profiles
Staged profiles:   ARM_CM55/non_secure + secure, C55S, not runtime-complete
                   ARM_CM33_SECURE_ONLY/secure, C3SO, qualification pending
                   ARM_CM55_SECURE_ONLY/secure, C5SO, qualification pending
                   ARM_CM33F/non_secure + secure, C3FS, construction/manifest slice
                   ARM_CM33F_TFM/non_secure, C3FT, consumer qualification passed,
                     activation and independent reference parity still pending
FreeRTOS pin:      a50edad08b29052631aa469d4df6e6ec7ff68878
Reference root:    experiments/_reference/FreeRTOS-Kernel
Compiler baseline: GNU Arm GCC from STM32CubeIDE 2.0.0
```

The twenty-one-profile count describes existing implementations and their recorded
software evidence. It does not certify the current tree after a runtime change.
The hash-backed audit-repair matrix PASS remains historical software evidence;
the later Armv8-M CONTROL readback correction has a refreshed full matrix and
separate six-case QEMU qualification recorded in `PORT_ARCHITECTURE_AUDIT.md`.
Neither result proves correct board execution or completes the port roadmap.

The subsequent A22-A24/C55S private-pool full matrix also passed, including the
explicit CONTROL, CM33 CMSE and default-M55 pool QEMU gates. The audit document
retains that separate working-tree receipt; it is not a complete C55S runtime
or whole-handler execution claim.

The primary scope remains distinct STM32 execution profiles through Cortex-M55.
M85 retains the conditional scope recorded in the inventory. Missing FP, MPU,
TrustZone, Secure-only, or TF-M work is not implicitly excluded by this document.

## Status Vocabulary

- **Implemented**: an existing concrete runtime profile with a parity ledger and
  recorded software proofs; fresh qualification and hardware status are separate.
- **Staged**: selected layout or cross-image artifacts exist, but required runtime
  operations or complete-group qualification are still missing. It cannot count
  as a complete runtime.
- **Pending**: identified implementation work in the through-M55 feature roadmap.
- **Unresolved**: an exact manifest inclusion or target-policy choice still needs
  an explicit decision. This means neither supported nor excluded.

A profile is selected by its processor-state and execution contract, not by a
vendor name or source directory. Compiler ABI, hard/softfp, region count, and
errata variants require their own applicable proof even when they share code.
Do not silently promise the Cartesian product of every reference configuration.
Conversely, absence of a concrete directory must not silently remove a feature
from the required freeze boundary.

## Pinned Source Groups

Paths in this section are relative to the pinned reference root. The exact GCC
build mapping is in
[`portable/CMakeLists.txt`](../../../../_reference/FreeRTOS-Kernel/portable/CMakeLists.txt).

| FreeRTOS GCC source group | Fiber mapping and meaning |
| --- | --- |
| `ARM_CM0` | Privileged `ARM_CM0` and separate build-selected `ARM_CM0_MPU`; the optional MPU branch is in the same reference directory. |
| `ARM_CM3`, `ARM_CM3_MPU` | Existing privileged and protected M3 profiles. |
| `ARM_CM4F`, `ARM_CM4_MPU`, `ARM_CM7/r0p1` | Existing M4/M7 profiles. Protected M7 behavior is covered through the CM4 MPU reference and explicit M7 errata policy, not a missing `ARM_CM7_MPU` directory. |
| `ARM_CM23_NTZ/non_secure` | Existing reference-portability Baseline NTZ profile; an ignored Non-secure PSPLIM slot is not a Mainline PSPLIM implementation. |
| `ARM_CM33_NTZ/non_secure` | CPU source group for existing M33 scalar, FP, and scalar MPU profiles; also the CPU half of M33 TF-M. |
| `ARM_CM33/non_secure` plus `ARM_CM33/secure` | Non-secure CPU runtime plus matching fiber-owned SecureContext companion. The scalar, non-MPU Fiber pair is implemented. |
| `ARM_CM55_NTZ/non_secure` | CPU source group for six implemented M55 no-companion profiles: scalar, scalar-FP, MVE-FP, each without/with MPU. Also the CPU basis for implemented scalar M55 TF-M. |
| `ARM_CM55/non_secure` plus `ARM_CM55/secure` | Staged C55S pair, then pending FP/MVE and protected SecureContext cohorts. |
| `ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c` | TF-M v2.0.0 OS-wrapper reference, added to the matching `_NTZ` CPU sources; not another SVC/PendSV engine. |
| `ARM_CM85_NTZ/non_secure`, `ARM_CM85/non_secure`, `ARM_CM85/secure` | Reference sources available for the conditional M85 workstream; no complete Fiber M85 runtime is established here. |

The Non-secure CPU groups use `port.c`, `portasm.c`, and applicable MPU wrapper
assembly, plus their headers. The companion groups use `secure_context.c`,
`secure_context_port.c`, `secure_init.c`, and `secure_heap.c` as source evidence;
Fiber's bounded static pool is a deliberate documented allocation policy.

Three distinctions prevent false completion or duplicate work:

1. `secure/` is a SecureContext companion, not a Secure-only scheduler. In the
   reference CPU sources, Secure-only scheduling is selected with
   `configRUN_FREERTOS_SECURE_ONLY=1` and `configENABLE_TRUSTZONE=0`.
2. TF-M owns the Secure provider. Its `_NTZ` CPU source reuse does not make the
   plain NTZ and TF-M profiles interchangeable. Fiber SecureContext and TF-M
   companions must not be combined in one selected profile.
3. A `_NTZ` source-group name is not proof that the silicon lacks the Security
   Extension. Do not add a duplicate CPU engine solely for a directory label.

The pin also contains CM23 companion, CM35P, CM52, and STAR-MC3 groups. Directory
presence alone does not add STM32 obligations. CM23 expansion remains the
inventory's additional reference-portability work unless a matching target is
added. GCC/IAR/Arm Compiler duplicates are not separate processor profiles;
material ABI or generated-state differences still need exact evidence.

## Implemented Runtime Inventory

These are twenty-one recorded runtime profiles, not twenty-one hardware claims or a
fresh all-profile matrix result for the current shared tree.

| # | Fiber profile | Implemented manifest boundary |
| --- | --- | --- |
| 1 | `ARM_CM0` | Privileged M0/M0+, Thumb-1, separate VTOR-present/absent traits. |
| 2 | `ARM_CM0_MPU` | Explicit M0+ protected profile, MPU replacement and unprivileged yield/return; not global automatic selection. |
| 3 | `ARM_CM3` | Privileged ARMv7-M, SVC/PendSV and BASEPRI. |
| 4 | `ARM_CM4` | Privileged M4/M4F with conditional FP state. |
| 5 | `ARM_CM7/r0p1` | Privileged M7/M7F with conditional FP and errata 837070 policy. |
| 6 | `ARM_CM3_MPU` | Protected M3 context and MPU replacement. |
| 7 | `ARM_CM4_MPU` | Protected M4F/M7F FP context and explicit M7 errata policy. |
| 8 | `ARM_CM23_NTZ/non_secure` | Non-MPU, scalar Baseline NTZ; reference portability. |
| 9 | `ARM_CM33_NTZ/non_secure` | Non-MPU, scalar Mainline NTZ with PSPLIM. |
| 10 | `ARM_CM33/non_secure` plus `secure` | Non-MPU, scalar fiber SecureContext pair; construction/attach, lifecycle and strong handlers. A30 adds BC/FC dual-origin handling and paired layout generation 2. Its new 75-launch actual-common origin suite passes; closed-body parity is separate. |
| 11 | `ARM_CM33_TFM/non_secure` | Non-MPU, scalar NTZ CPU frame plus TF-M v2.0.0 initialization/mutex adapter; no fiber SecureContext. |
| 12 | `ARM_CM33_MPU/non_secure` | Scalar, protected, 8/16-region manifests; no fiber SecureContext or TF-M. |
| 13 | `ARM_CM33F_NTZ/non_secure` | Non-MPU, scalar-FP NTZ with PSPLIM. |
| 14 | `ARM_CM55_NTZ/non_secure` | Non-MPU, scalar M55 NTZ. |
| 15 | `ARM_CM55F_NTZ/non_secure` | Non-MPU, scalar-FP M55 NTZ. |
| 16 | `ARM_CM55_MVEF_NTZ/non_secure` | Non-MPU, MVE-FP M55 NTZ. |
| 17 | `ARM_CM55_MPU/non_secure` | Scalar M55 MPU, 8/16-region manifests. |
| 18 | `ARM_CM55F_MPU/non_secure` | Scalar-FP M55 MPU, 8/16-region manifests. |
| 19 | `ARM_CM55_MVEF_MPU/non_secure` | MVE-FP M55 MPU, 8/16-region manifests. |
| 20 | `ARM_CM33F_MPU/non_secure` | Scalar-FP protected M33, explicit 8/16-region manifests, complete eight-operation runtime; post-selectable six-gate replay passes. Executed r8 and compile/link-only r16 evidence remain distinct. |
| 21 | `ARM_CM55_TFM/non_secure` | Scalar M55 NTZ CPU with separate TF-M v2 initialization/mutex integration; post-selectable target/host/dual-r9/per-object-role qualification passes. Actual TF-M Secure image and PSA integration remain unqualified. |

The concrete M33/M55 manifests above reject PAC/BTI. The current M55 MVE
profiles require FP+MVE and reject integer-only MVE. Those rejections describe
the implemented manifests; they are not roadmap exclusions.

`ARM_CM55/non_secure` plus `secure` is staged C55S: an eleven-word Non-secure
software-frame dictionary, scalar M55/CMSE manifest, eight immutable
identity/capacity NSC veneers, and a retained, budgeted Secure-only pool.
Slice 4 adds private memory-only pool initialization/allocation/lookup. Slice 5
adds a ninth NSC entry for one-shot Secure CPU/pool initialization; focused and
combined execution evidence are recorded separately from source availability.
Slice 6 adds guarded NSC allocation/load/save, making twelve imports with the
same context identity/layout and pool geometry. The later 481-input combined
checkpoint includes its 148-scenario lifecycle suite; the subsequent private
Secure cohort guard has separate focused evidence. Earlier snapshots never
qualify later source changes. The subsequent staged Non-secure slice implements
sealed construction and pre-start attachment using the eight immutable identity
queries. Its source and focused evidence are separate from the earlier lifecycle
checkpoint. A subsequent staged first-start component adds an owned SVC-70,
reserved-MSP plan and guarded first Secure initialization/allocation/load; its
new execution qualification is separate and is not implied by those earlier
receipts. PendSV component execution is now separately qualified; Slice 11
adds all eight forward adapters and prepares the CPU/MSP environment before
the first protected scheduler selection. Whole-common-runtime execution,
archive/vector and policy requalification are in progress. Runtime selection
stays zero until those proofs pass.
No Secure-only scheduler is implied by the pool's Secure-only placement.

## Pending And Unresolved Manifests

The descriptions below identify feature tuples, not promised directory names.
Scalar means FPU=0/MVE=0; scalar-FP means FPU=1/MVE=0; MVE-FP means
FPU=1/MVE=1. M33 has no MVE cohort. An included protected tuple needs explicit
region-count and compiler manifests rather than inheriting another profile's
8/16-region or hard/softfp proof.

| Core / role | Exact feature tuple or selection | Status |
| --- | --- | --- |
| M33, existing scalar fiber SecureContext | Secure-origin PendSV interruption with three-word Non-secure header | A30 repair implements BC/FC dual origin, conditional GPR transfer and three-word-only restore validation; paired layout generation is 2. The actual-common AN505 suite passes 75 launches and 2,382 checks at O0/O2/Os plus O2/Os LTO, including mapped poison/watchpoint, branch-removal and old-layout companion controls. Fresh closed-body parity remains separate; no board claim. |
| M33, Non-secure without fiber companion | Scalar-FP + MPU | C3FP is complete explicit build-selected runtime #20. Post-selectable manifest/constructor/first/running/complete-group gates pass, with 161 full-runtime AN505 executions. A new immutable parity replay and combined-tree qualification remain separate; no board claim. See `ARM_CM33F_MPU/non_secure/FREERTOS_PARITY.md`. |
| M33, fiber SecureContext | Scalar-FP, no MPU | New staged C3FS construction/manifest/companion artifacts are being implemented against the separately compiled real FP reference pair. Runtime and actual FP/Secure switching qualification remain pending; C33S scalar evidence does not qualify C3FS. |
| M33, fiber SecureContext | Scalar + MPU; scalar-FP + MPU | Pending protected companion cohorts; exact paired manifests must be defined. |
| M55, fiber SecureContext | Scalar, no MPU | Staged C55S; Secure, constructor, attachment, first-start and running-component evidence are separate. All eight forward adapters now exist; complete real-common/two-image qualification and release hash/map policy proofs are in progress. Runtime selection remains zero. |
| M55, fiber SecureContext | Scalar-FP, no MPU; MVE-FP, no MPU | Pending, separately identified FP and MVE manifests. |
| M55, fiber SecureContext | Scalar + MPU; scalar-FP + MPU; MVE-FP + MPU | Pending protected companion cohorts; current six no-companion runtimes do not cover these. |
| M33, Secure-only scheduler | Scalar, no MPU | Staged C3SO, CMSE level 3, ordinary Secure register bank, initial EXC_RETURN FD. Focused construction/manifest/transfer-subset gate passes; complete-group, closed-body parity and Secure runtime execution are still pending. This is not the SecureContext companion. |
| M33, Secure-only scheduler | Scalar + MPU; scalar-FP with/without MPU | Pending distinct manifests; not covered by staged unprotected scalar C3SO and not excluded. |
| M55, Secure-only scheduler | Scalar, no MPU | Staged C5SO, exact M55/CMSE3 scalar tuple, independent storage/profile identity and FD/F9 Secure-bank frame. Actual pinned M55 reference objects, numeric geometry, symbols and 36 negatives pass at O2/Os. Complete-group execution and closed-body parity remain pending. |
| M55, Secure-only scheduler | Scalar + MPU; scalar-FP or MVE-FP with/without MPU | Not implemented; exact additional manifests remain visible work, not covered by staged scalar C5SO. |
| M33, TF-M | Scalar-FP without MPU | Staged C3FT source group and consumer gates pass; runtime-selectable remains zero pending activation and independent reference parity. It is distinct from the scalar C3TF provider and actual TF-M Secure-image integration remains unqualified. |
| M33, TF-M | Scalar or scalar-FP with MPU | Not implemented; exact additional TF-M manifest inclusion remains unresolved. Existing scalar/non-MPU C3TF is complete software work. |
| M55, TF-M | Scalar without MPU | C5TF is complete software runtime #21, with separate scalar M55 CPU and TF-M interface glue. Target/host/actual-M55 dual-r9 and per-object dependency-role gates pass, plus separate reference parity. Typed fixtures do not establish execution with an actual TF-M Secure image. |
| M55, TF-M | Scalar-FP or MVE-FP without MPU | Pending feature cohorts; exact paired TF-M/compiler manifests must be fixed before implementation. |
| M55, TF-M | Scalar, scalar-FP or MVE-FP with MPU | Not implemented; exact inclusion and unprivileged service-entry/memory policy remain unresolved. |
| Applicable target, PAC/BTI | Exact supported architectural/compiler/security tuple | Unresolved target/manifests; generic reference conditionals are not target capability proof. |
| M55, integer-only MVE | MVE=1/FPU=0 and chosen security/MPU role | Unresolved inclusion and exact reference/compiler policy; not covered by MVE-FP. |

Unresolved rows remain visible work before a full-coverage freeze claim. A scope
decision must enumerate included tuples and explicitly document any deferral;
this document makes no such exclusions. No automatic all-combinations claim
follows from listing candidate feature tuples.

### Integer-Only MVE Reference Finding

A separate read-only audit of the pinned M55/M55_NTZ sources compiles the actual
`port.c` and `portasm.c` for `-mcpu=cortex-m55+nofp -mfloat-abi=softfp`,
`configENABLE_MVE=1`, `configENABLE_FPU=0`. Twelve O2/Os, MPU and applicable
TrustZone configurations produce 24 source objects. Compiler MVE=1 with no
`__ARM_FP` and ELF `MVE Integer only` attributes is a distinct admitted reference
tuple, not the existing Fiber MVE-FP tuple.

The reference retains conditional high-register transfers and, for MPU, copies
the low shared-register payload/FPSCR plus CONTROL. However, its startup FPU
setup and TrustZone access-grant calls are guarded by FPU alone. Successful
compilation therefore does not establish CPACR/lazy-preservation readiness for
integer MVE. This CMSIS version also turns FPSCR accessors into zero/no-op with
FPU facts zero, despite explicit VMRS/VMSR assembling. A new cohort must own
these startup and access rules rather than reusing those no-op accessors.

The existing MVE-FP manifests correctly reject this different compiler target.
The common extended-state and FPCA predicates currently require FPU; a future
integer-MVE adaptation must narrowly accept FPU-or-MVE without weakening the
existing selected-profile manifests. This row remains included unresolved work,
not a claimed hardware defect or an implicitly excluded feature.

```text
Read-only actual-reference compiler/ELF evidence, input drift 0:
  %TEMP%/fiber-m55-mvei-readonly-20261102a
150 recorded invocations, including six expected current-Fiber rejections
No execution or hardware qualification
```

## Ordered Implementation Phases

Each phase preserves the five public operations and frozen eight-operation
generic forward port ABI. New feature mechanics stay selected-port-owned;
cross-image and private layout/cohort changes receive their appropriate identity.

1. **Preserve the qualified CONTROL correction.** Distinguish exception-entry SPSEL from
   post-MSR stored SPSEL and SG bank transitions. Close the scoped QEMU and
   maintained regression evidence before new C55S runtime edits. Emulator evidence
   remains separate from board evidence and final freeze qualification.
2. **Finish scalar non-MPU C55S.** Implement Secure initialization, allocation,
   save/load, then sealed construction/attachment and first/ordinary context
   switching. Before a complete freeze claim, bind all three Secure companion
   objects to an exact private configuration/layout identity, including
   equal-size pool-geometry collisions; the nineteen-runtime cohort mechanism
   does not cover those objects automatically. Prove matching and stale private
   objects under O2/Os, LTO, archives and GC. Independently close the same
   confirmed private-object binding gap in the existing CM33 Secure companion:
   individual pool-size checks do not bind gateway capacity/identity facts to
   that pool. Preserve both profiles' separate manifests and proofs. Prove
   ordinary no-attachment and attached paths, exact cross-image
   identity, vectors, archive extraction, GC/LTO and negative links. Do not mix
   FP, MPU or TF-M expansion into this completion slice.
3. **Close M33 scalar-FP MPU.** This can proceed independently after phase 1,
   alongside C55S. Pair with `ARM_CM33_NTZ/non_secure` configured for FP+MPU;
   define and prove the exact protected manifests.
4. **Add non-MPU FP/MVE SecureContext cohorts.** M33 scalar-FP and M55
   scalar-FP precede M55 MVE-FP. Prove Secure/Non-secure FP access policy and
   deferred preservation, not only Non-secure high-register transfer order.
5. **Add protected SecureContext cohorts.** Establish scalar paired privilege
   ownership first, then FP/MVE. Without PAC, the reference protected backing
   is 22 words for scalar and 55 for FP/MVE, versus 21/54 without a companion.
   Secure allocation gains privilege information and Secure save/load gains
   CONTROL state. Do not reuse the smaller image with an ignored handle word.
6. **Close selected Secure-only scheduler manifests.** Resolve exact M33/M55
   feature tuples, implement scalar first, then FP/MVE and protected variants
   as selected. These require Secure compiler/vector/banked-state contracts,
   not the Non-secure runtime plus an NSC companion.
7. **Close TF-M provider cohorts.** M55 scalar comes first, followed by the
   selected FP/MVE/protected tuples and unresolved M33 additions. TF-M depends
   on its matching NTZ CPU proof and provider interface, not on C55S lifecycle.
   It may run in parallel once those prerequisites and manifests are fixed.
8. **Resolve conditional feature and M85 scope, then freeze.** Do not retire
   transitional coverage until every remaining role has a concrete replacement
   or an explicit scope decision. Complete the global gates below before
   beginning Context extraction.

Reference geometry is in
[`ARM_CM55/non_secure/portmacrocommon.h`](../../../../_reference/FreeRTOS-Kernel/portable/GCC/ARM_CM55/non_secure/portmacrocommon.h).
Secure FP lazy-preservation and protected CONTROL handling are in
[`secure_context_port.c`](../../../../_reference/FreeRTOS-Kernel/portable/GCC/ARM_CM55/secure/secure_context_port.c);
the protected allocation signature is in the adjacent `secure_context.c`.

## Conditional M85 Scope

Preserve the inventory's two boundaries:

- Through-M55 / STM32N6 is the primary current completion baseline. M85 work is
  conditional, not automatically a prerequisite merely because the pin has it.
- An all-announced-STM32 boundary includes the inventory's STM32V8/M85 row
  unless an explicit deferral is recorded. This document records no deferral.

A reference-only M85 implementation is not STM32V8 support. Before including a
target cohort, fix its actual core/revision, FPU precision policy, MVE, MPU,
security/provider role, PAC/BTI, compiler ABI and errata manifest. A directory
rename or byte-identical shared source is not generated-code or target proof.
Do not invent additional saved state solely from a product or precision label.

The pinned-reference read-only inventory on 2026-11-02 found 20 corresponding
CM55/CM85 file pairs: only the two `portARCH_NAME` strings differ; all eight
Secure-companion files are byte-identical. Twelve explicit M85 witness
manifests at O2/Os produced 60 byte-identical CM55/CM85 object pairs. This is
evidence for reusing the mechanism design, not a Fiber M85 implementation or
STM32V8 hardware claim.

Keep the reference's distinct security roles: NTZ Non-secure, Secure-only and
Non-secure plus companion. Source branches include MPU off/8/16, separate
FPU/MVE and PAC/BTI axes; not every source combination is a silicon claim.
PAC transfers four key words (`PAC_KEY_P_0` through `PAC_KEY_P_3`) and uses CONTROL
bits 6/7 plus an external random-key callback. BTI uses CONTROL bits 4/5 and
requires matching compiler-generated landing pads, without adding a context
slot. Do not confuse the reference's 16-word PAC backing-store allowance with
the four transferred key words. Its maximum backing formula is
`21 + TrustZone + 33 * (FPU || MVE) + 16 * PAC`; the maximum protected
Non-secure-origin transfer payload is
`20 + TrustZone + 33 * (FPU || MVE) + 4 * PAC` words. A basic transfer without
the extended FP/MVE form uses `20 + TrustZone + 4 * PAC` words instead.
The inventory receipt is
`%TEMP%/fiber-m85-reference-inventory-20261102a/results.json`; no Fiber
cohort, final runtime link, exception execution or hardware was qualified.

## Gates Before CPU Extraction

The mandatory order remains
[`CONTEXT_FIBER_ARCHITECTURE.md`](CONTEXT_FIBER_ARCHITECTURE.md): complete the
included processor-state contracts, record a stable checkpoint, then mechanically
separate Context, Fiber lifecycle, Tasks and scheduler policy.

Real pre-extraction blockers are:

1. An unclosed known runtime defect, including the CONTROL correction.
2. A required pending cohort, or unresolved inclusion boundary hidden behind a
   claim of complete coverage. C55S layout/veneer staging is not runtime closure.
3. Missing selected-profile frame, save/restore, feature, SVC/PendSV, vector,
   directional ABI, exact-cohort, stale-object or negative-link evidence.
4. Missing global optimization proof at `-O0`, `-Og`, `-O2`, `-Os`, `-O3`, plus
   final linked-ELF disassembly at `-O2 -flto` and `-Os -flto`.
5. Missing clean full matrix, exact-commit release-blocking CI, retained evidence
   bundle, or recorded stable pre-extraction commit. See
   [`CI_VALIDATION_PLAN.md`](CI_VALIDATION_PLAN.md).

Extraction must wait because unfinished banked state, companion ownership,
protected images and provider contracts can still change the backend being
separated. Combining those changes with dispatcher/current/start ownership
migration would lose the stable behavioral comparison required by the contract.
After extraction, repeat the same applicable software suites against that
checkpoint; moving names and ownership is not permission to redesign mechanics.

Unavailable hardware can be explicitly recorded as deferred for software freeze;
available hardware tests remain part of the documented evidence process.
Compile, host, emulator, assembly and ELF results never imply hardware isolation,
PSA concurrency, electrical behavior, or complete TrustZone integration. TF-M
image/veneer and board evidence must retain their separate status.

Optional heterogeneous-MPU policy APIs, dynamic reclamation, SMP, ISR scheduling,
host backends, portable synchronization, and later Task/scheduler policies are not
new prerequisites for this port freeze. Their later roadmap position must not
be used to defer processor-state mechanics required by an included profile.
