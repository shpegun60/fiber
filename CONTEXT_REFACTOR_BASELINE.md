# Context Refactor Baseline

## Scope Decision

On 2026-11-02 the implementation priority changes from completing every
candidate feature combination before extraction to a bounded usable baseline.
The immediate target is a clean Context engine consumed by Fiber for:

| STM32 target | Existing backend | Required mechanics |
| --- | --- | --- |
| F0 | ARM_CM0 | M0 Thumb-1, PRIMASK, device vector-source policy |
| G0 | ARM_CM0 | M0+ Thumb-1, PRIMASK, device VTOR capability |
| G4 | ARM_CM4 | M4F basic/extended FP state and BASEPRI |
| H7 | ARM_CM7/r0p1 | M7 FP state, BASEPRI and applicable errata policy |
| H7S | ARM_CM7/r0p1 | Same CPU engine with separate board/startup/linker integration |

These are CPU-profile mappings, not blanket hardware validation of every device
or an SMP claim for dual-core parts. F0, not H0, is the confirmed target.

This decision supersedes the universal pre-extraction prerequisite in the older
port-freeze roadmap. It does not declare the full STM32 catalog complete, erase
remaining proofs, or redefine a failed qualification as PASS. All existing
concrete profiles remain in the repository and their applicable regression
gates remain enabled. Additional feature combinations stay visible in
`STM32_PROFILE_BACKLOG.md`; they no longer block this bounded extraction.

## Architecture That Must Scale

The dependency direction remains normative:

```text
selected CPU backend
    -> portable Context runtime
    -> Fiber lifecycle
    -> C++ Task/Kernel and scheduler policies
```

The backend owns complete opaque context storage, stack/frame construction,
SVC/PendSV, masks, special registers, exception configuration and feature state.
Context owns one current slot, one dispatcher/user pair, first-selection and
configuration lifecycle, publication and CPU-transfer orchestration. It never
knows a Fiber or Task representation. Fiber contains a context and adapts its
lifecycle to the dispatcher; scheduler policy stays above Fiber.

MPU, TrustZone/SecureContext, TF-M, FPU/MVE and future applicable PAC/BTI state
remain selected-profile responsibilities. Keep the frozen eight-operation
forward ABI, reverse-v1 ownership, optional extension ABIs and exact cohort
guards while extracting. An unsupported extension has no public stub. A new
profile must not require a processor-family conditional in Context or Fiber.
Static-lifetime/single-core limits remain explicit; dynamic reclamation or SMP
requires a separately reviewed contract, not an implicit extension.

## Mechanical Order

1. Retire `transitional_v8m`: reject ambiguous v8-M runtime selection and obsolete
   opt-ins, migrate applicable tests to concrete profiles, retain stale-object
   negatives, and delete the fallback source group. No concrete assembly changes.
2. Record a hash-backed baseline with exact successful and unavailable evidence.
   Complete the current combined replay; preserve earlier FAIL receipts. Board
   unavailability is recorded, not reported as hardware PASS.
3. Introduce an internal versioned Context facade over the existing engine.
   A facade alone is not completed separation and adds no second runtime state.
4. Move actual current/dispatcher/start/panic ownership into Context and invert
   the compatibility bridge. Preserve reverse symbols, context identity and
   selected-port mechanics until their own explicit migration checkpoint.
5. Implement a genuine Fiber consumer with context containment and lifecycle.
   The existing five-call API remains a compatibility surface until replacement
   consumers and migration tests are complete.
6. Add C++ kernel policy separately. No tick, queue, priority or ISR preemption
   implementation is smuggled into this mechanical refactor.

## Current Implementation

The concrete-selection retirement and additive facade checkpoints are complete.
`53b69aa2c4c63eb72230d35b94fa7c6af8ebbee9` makes `context/` the sole portable
engine/state/panic owner. The old five calls in `fiber/fiber_core.c` delegate
one-way into it; removed providers and the additive bridge are not alternative
build inputs. The frozen CPU forward/reverse symbols and storage identity remain
compatible, and backend native-object comparisons are recorded separately.

`fiber/lifecycle` is the distinct Fiber v1 consumer, with five operations and
contained Context storage. Its initialization requires Context's optional
configuration service, not another lifecycle latch or a ninth CPU operation.
Pure Context users do not select that service merely by using the five Context
operations. Consumer qualification and migration evidence are independent of
the earlier additive-facade receipts; see `PORT_ARCHITECTURE_AUDIT.md`.

The backend directories and shared compiler-policy header temporarily retain
their old physical paths. That does not introduce a dependency on Fiber
lifecycle logic; physical relocation can be a later mechanical checkpoint.
C++ Task/Kernel, timer/ISR dispatch, reclamation and richer scheduler policies
are not implemented by this ownership extraction.

Pre-extraction and post-inversion aggregate failures remain separate captured
receipts in `PORT_ARCHITECTURE_AUDIT.md`. Focused mechanical and repair receipts
qualify their exact inputs, not the entire later tree. They cannot replace a
fresh combined replay or be relabeled as a software freeze.

The latest retained combined compile/link/codegen replay passes for immutable
`624a4353983e03e766533df3abaa396593c750be`: 1,086 source files, 916 external
inputs, zero drift, all final settings and source-inventory checks complete.
Earlier `847953d` and `ad29f15` receipts remain historical. The post-repair
receipt, hashes and exact scope are recorded in
`PORT_ARCHITECTURE_AUDIT.md#post-repair-combined-matrix` and summarized in
`STM32_PROFILE_BACKLOG.md`. This accepts the bounded Context/Fiber implementation
and its selected software gates, not the entire port roadmap. The later
`e971263` standalone CONTROL guard receipt is not another combined matrix run.

| Bounded milestone | Status |
| --- | --- |
| Concrete-only selection; transitional fallback removed | Implemented |
| Context engine/state/panic ownership; one-way legacy adapter | Implemented |
| Distinct static-storage Fiber lifecycle consumer | Implemented and separately qualified |
| Combined compile/link/codegen matrix for the captured source | PASS at `624a435` |
| Post-inversion CM0 public Context/Fiber SVC/PendSV execution | Captured QEMU O2/Os normal/final-LTO direct/archive suite: 298 cases PASS; not M0+ or board evidence |
| Post-inversion CM4F Context/Fiber FP-state execution | Captured AN386 O2/Os normal/final-LTO direct/archive eager/lazy suite: 288 cases PASS; bounded paired upstream final ELFs, not G4 board or full panic-suite evidence |
| Post-inversion CM7 Context/Fiber FP-state execution | Separate captured AN500 r1p2 suite: 288 cases PASS and eight paired upstream final ELFs; fresh CM4 replay and 296 executable-image comparisons pass. Not H7/H7S hardware or affected-r0p1 erratum evidence |
| Complete post-inversion classic exception/FP runtime and board suites | Pending; not established by that aggregate |
| Global O0/Og/O2/Os/O3 and final-linked-LTO FreeRTOS parity | Pending |
| Exact-cohort global coverage inventory | Initial 27-group/141-row declaration and 2,755-cell plan; no new compiler/ELF/CPU proof, exhaustive reconciliation and execution pending |
| Bounded CM0/CM0+ non-MPU seven-mode parity | Separate captured five-option/final-LTO gate: 28 final pairs, 56 positive ELFs and 84 compiled controls PASS; not global parity or G0 execution |
| Bounded CM4F/CM7 hard-FP seven-mode runtime/parity | Separate opt-in full grids: 504 executions, fourteen link-only reference final ELFs and 112 associations per profile PASS; old 296-image executable subsets unchanged. Not softfp, MPU, global parity or board evidence |
| Classic MPU CONTROL repair and basic CM4 pilot | Separate seven-image AN386 pilot PASS for Context/Fiber return and two fault cases; not FP-active/lazy, final-LTO, other MPU CPUs or board evidence |
| Classic MPU CONTROL software regression guards | Standalone clean-commit `e971263` PASS: 63 ARM codegen cells, scalar guards, cohort negatives, byte-coverage and strict closing controls; not new CPU execution or reference equivalence |
| CM4 MPU bounded basic grid | Separate `b2a7d17` AN386 run: 49 observations across Context/Fiber, O2/Os, ordinary/final LTO and direct/archive; eight link-only reference ELFs and 144 mechanism checks. MPU8 eager/FP-inactive only, not MPU FP-active, global parity or boards |
| CM4 MPU FP-active pilot | Separate selected-byte O2/direct/non-LTO run: four Context/Fiber eager/lazy positives, ten causal FP mismatches and one model; one pinned link-only reference and four bounded FP associations. Not pre-save LSPACT, full FP grid, global parity or boards |
| CM4 MPU bounded FP grid | Separate selected-byte 53-observation run: 32 Context/Fiber eager/lazy O2/Os ordinary/final-LTO direct/archive positives, 20 causal negatives and model; eight link-only references, 32 associations and 61 byte-identical compile/execution ELFs. Not strict low-FP self-selection, pre-save LSPACT, all optimizations or boards |
| CM4 MPU read-only lazy-state observer | Separate four-image O2/native/direct AN386 run: 88 pre/post pairs and 176 snapshots with exact terminal completion; lazy extended LSPACT 1 -> 0, eager/basic 0 -> 0. Uses immutable FP-pilot ELFs, not full-grid lazy observation, new reference execution or boards |
| Isolated H7S managed Debug/Release integration | Fresh headless-generated 35-object builds and final-ELF audits PASS for the captured application and pinned production export; not CubeMX regeneration or board execution |
| Exact-commit release-blocking CI | Not established |
| C++ Task/Kernel, timer/ISR preemption, reclamation and SMP | Separate future contracts and implementation |

The F0/G0/G4/H7/H7S mappings remain CPU-profile claims. The local H7S managed
source-admission repair and later isolated Debug/Release build receipt are
separately recorded in `H7_RUNTIME_VALIDATION.md`. The latter regenerates build
recipes from the captured project, not CubeMX application sources. It does not
migrate the board application to Fiber v1 or establish board execution.

## Evidence Boundary

Every extraction checkpoint must retain the applicable constructor, consumer,
frame, dispatcher-order, attribute, ABI, exact-cohort, archive/GC/LTO and vector
positive/negative tests. Compare generated backend instructions and frame bytes
against the captured pre-extraction source, independently of the pinned FreeRTOS
comparison. Preserve FP eager/lazy, reserved-r9 and M7 errata variants.

The required O0/Og/O2/Os/O3 and final-linked-LTO coverage remains visible work;
O2/Os parity or raw-compiler inventories must not be relabeled as that global
gate. Extend the focused classic-baseline checks before accepting affected
generated-code transformations. Hardware results remain separate. A bounded
extraction checkpoint is not an all-profile software freeze or a CI claim.

## Remaining Catalog

The broader through-M55 feature backlog, conditional M85 work and global
optimization/CI qualification are retained, not removed. Staged artifacts remain
staged until independently admitted. Existing NS/Secure pairs are not promoted
by this scope decision. New backends and optional features must later pass the
same Context conformance boundary without changing portable Fiber ownership.
