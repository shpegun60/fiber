# CM0 O2 Direct Cell Composition Contract

## Status And Exact Cell

This is the bounded proof contract implemented by
`tools/fixtures/cm0_final_cell/compose.py`. Its presence is not a measured PASS;
local outcomes and exact receipts are recorded in `PORT_ARCHITECTURE_AUDIT.md`.
It does not relabel retained root components as full semantic ABI proof.
Only this canonical inventory key is in scope:

```text
Cohort: cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default
ArtifactRole: runtime
SourceGroup: CM0
Representation: final
Mode: O2
Linkage: direct
```

The target is ARMv6-M, cortex-m0, Thumb, soft ABI, no FPU/MPU/VTOR,
NVIC priority bits 2, BASEPRI not applicable, and the default AAPCS r9 ABI.
No other profile, optimization, linkage or snapshot receives credit.

## Retained Evidence And Admission

The input catalog is
`C:/fz-freeze-replay-inputs-20261105-e1/cm0-current.json`, SHA256
`39E08F24184D31883E5F85234C191060F680E2C76F0C40048F93B84649610CB7`.
It binds current E9 inventory and the actual producer/join receipts and
artifact manifests. The inventory source identity must be exactly
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.
The build root is `C:/fz-replay-refresh-cm0-o2-20261105-e2`:

| Receipt | SHA256 |
| --- | --- |
| `Native/results.json` | `D5FF0D8A8368EC38C816ABC627D506278EB47978676A69ACC11FD19603D96FBB` |
| `Reference/results.json` | `7BED24B7333F93BA383AE3D0B6438733954B64807E2BA347B987404801004B36` |
| `Join/results.json` | `4F648D74E3EAF1AE1DDCDF29C06E29BD530FECB07306060729E7FD4869FDF15A` |

Authenticate receipt/manifest buffers before interpreting them or importing
helpers. Close complete artifact memberships, original/captured/generated
inputs, physical identities, parser/helper bytes, compiler/workers, commands,
streams, dependencies and environment. Keep historical snapshots distinct.
Do not override drifted originals or infer authority from PASS labels.

Native object order is core, state, panic, selected runtime, boot, exception,
expectation, application, startup (indices 0 through 8). Preserve this exact
order, source hashes, compile flags and link recipes. Reuse the authenticated
positive objects and twins; new controls must not modify retained evidence.

## Common Prerequisites

All three common inventory obligations are independently mandatory:

- `cpu-neutral-engine`: bind actual core/state/panic sources and dependencies
  to the canonical ownership/source-boundary predicates. No selected CPU
  implementation or backend-private state ownership may enter the engine.
- `reverse-v1-ownership`: common providers own the four reverse services,
  sole current slot and v1 anchor; ports consume the frozen interface.
- `source-provider-identity`: exact canonical runtime source-reader roles,
  actual consumed dependencies and original object providers agree.

Reuse the ownership contracts in `compile_matrix.ps1`, actual provider checks
in `classic_final_image/run.py`, and existing authenticated join/closure
adapters. Do not invoke the entire matrix or duplicate ELF decoding logic.

## Typed ABI And Reverse Services

Use captured `context/context_port_abi.h` for the frozen forward-eight surface
and `context/context_runtime_port_abi.h` for reverse-v1. An independently
spelled type oracle must check the declarations, not derive expected types
from the declarations being tested. Bind actual provider compilations to
those same captured headers and applicable attributes.

The reverse header declares exactly these four services:

```c
CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(CtxrtContextV1 *current);
void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next);
void fiber_internal_runtime_require_current_context(void);
void fiber_internal_task_return(void);
```

All four carry the published sensitive/general-registers-only declarations;
task-return also carries `CTXRT_API_NORETURN`. Require
`FIBER_RUNTIME_PORT_ABI_VERSION == 1u`. The included panic declaration,
anchor, retain macro and assembly-visible slot are not additional reverse
services. The slot deliberately has no C declaration in this interface.
Candidate selection, publication and require-current belong to state object
1; task-return belongs to core object 0. Check unique actual definitions,
typed consumers, original calls/address references, and map-bound final
targets. Verify the real cold v1-anchor dependency and retained read, not
merely anchor existence. This is not proof of the C services' semantics.

## Eight Mandatory Runtime Obligations

| Obligation | Required evidence |
| --- | --- |
| `forward-eight` | Reuse `Pilot.prelink()`: exactly eight strong function providers, context-init in boot object 4 and the other seven in runtime object 3; independently typed declarations, actual header dependencies and soft-ABI attributes. Do not equate symbol names with semantic ABI equivalence. |
| `reverse-v1` | All four services and cold anchor dependency above, with original provider/relocation and final map/target evidence; stale-reverse link control below. |
| `current-slot-isolation` | One state-owned four-byte aligned NOBITS slot, actual input section/offset and final writable/non-executable zero-fill origin. Bind selected-port source-body and generated-code load-only predicates to exact authenticated producer source/disassembly/ELF bytes. Correct slot placement alone is insufficient. |
| `strong-handlers` | Unique strong executable SVC/PendSV definitions in runtime object 3, exact mapped final origins and both duplicate-handler link controls. |
| `exact-profile-context-cohort` | Exact admitted target/defines/flags and canonical private/storage identities; runtime provider, boot/exception references and expectation references agree. Bind original relocation addends and applied final pointers. |
| `generated-assembly-reference-parity` | Complete eight-root, three-mechanism comparison under the explicit acceptance rule below, including declared differences. |
| `final-elf-vectors` | Reuse `Pilot.audit_final()` and startup-origin predicates: 1024-byte vector section, initial MSP `0x20010000`, entry/Reset and slots 11/14 resolve to actual strong handlers. Bind original startup relocations, applied pointers and the VTOR=0 startup predicate. |
| `negative-link-controls` | All five actual fresh links below reject solely for their intended cause, with complete command/provider/input/output closure and matching positive authority. |

For slot isolation, reuse `Test-ReverseAbiSlotCIsolation`,
`Test-GeneratedCurrentSlotLoadOnly` and selected-port source-body contracts.
Prove that direct slot access stays in the admitted naked assembly sequences;
port C may not declare, read, write or take its address. Account for every
generated slot-address reference and its complete admitted load-only sequence;
reject a store through that address, an escaping address, or an unclassified
use. A slot ABS32 relocation alone is not access-policy proof. This is the
bounded direct-access predicate, not arbitrary pointer-alias semantics. If
retained producer artifacts cannot support the exact generated-code predicate,
report this obligation incomplete. Do not replace missing evidence with a
source grep, slot-symbol check or a claim of software-cell completion.

## Generated-Reference Acceptance Rule

For this cell, this obligation means complete generated mechanism comparison
with explicitly admitted differences, not whole-provider equivalence. Reuse
unchanged `cm0_final_join` and `cm0_freeze_parity/closed_roots.py::check_pair`:

- Native roots: `fiber_port_start_first_context`, `SVC_Handler`, `PendSV_Handler`.
- Reference roots: `vStartFirstTask`, `SVC_Handler`, `vPortSVCHandler_C`,
  `vRestoreContextOfFirstTask`, `PendSV_Handler`.
- Match complete own-object protocols and final preservation/origins, including
  pools, padding, relocations and exact first-start/first-restore/PendSV mapping.
- Bind pinned reference `a50edad08b29052631aa469d4df6e6ec7ff68878` and both
  actual providers (`port.c`, `portasm.c`), not a substituted model.
- Require captured master-ledger unique headings and nonempty rationales for
  exactly `FAP-COMMON-START`, `FAP-COMMON-PROVENANCE`,
  `FAP-CM0-STAGED-FRAME`, `FAP-COMMON-SCHEDULER`,
  `FAP-COMMON-MASK-RESTORE`, with the existing per-mechanism assignments.
- Preserve the CM0 checker's exact O2 padding and staged-frame differences;
  do not impose CM3 zero-tail rules or compare only sizes/counters/hashes.
- Check each side's own twins using the existing load-image comparison. Do
  not claim independent ordinary-root relocation proof from load equivalence.

Success may state `MechanismParityWithDeclaredDifferences=True` only.
Instruction, whole-provider, policy, initial-register-value and runtime
handler-routing equivalence remain unproved. Earlier component flags stay
unchanged; the composer supplies a new narrowly defined obligation result.

## Control Classes And One Batched Link Suite

Pure admission/type-oracle controls mutate synthetic facts: missing/duplicate
providers, wrong signatures/owners/attributes, vector targets, identities or
ledger entries must reject. These do not count as compiler/linker tests.
Actual typed-oracle compilation uses exact captured headers and target flags.
Actual canonical-header read/write/address probes must fail specifically
because the current-slot C identifier is undeclared; these are compile
controls, not the five link controls.

Reuse `context_facade` stale-input recipes and strict unresolved diagnostic
classification. Clone recorded compile/link recipes into a fresh control
directory; change only the declared control input and output/dependency paths:

1. Replace object 6 with the actual expectation compiled against a private
   generated header changing NVIC bits 2 to 3. Require exactly the alternate
   private identity missing; derive and bind its full original import.
2. Replace object 7 with the actual application compiled against private
   storage revision 999. Require exactly
   `fiber_port_storage_cohort_arm_cm0_v999_r0` missing.
3. Replace state object 1 after changing only its anchor definition to v2.
   The real unchanged port consumers must require exactly missing
   `fiber_internal_runtime_port_abi_v1_anchor`.
4. Add one strong SVC definition; require exactly duplicate `SVC_Handler`.
5. Add one strong PendSV definition; require exactly duplicate `PendSV_Handler`.

The positive link authority is the authenticated retained native recipe.
Revalidate unchanged consumed object hashes before/after links. Retain actual
control source deltas, dependencies, objects/imports and complete raw command
records/streams. Use a separate closed duplicate-symbol diagnostic grammar.
Compile failure, unrelated diagnostics, timeout, missing outputs/records or
closing drift invalidate a control; command FAIL is not automatically proof
PASS. No archives, forced undefined anchors or whole-archive options are added.
These controls do not prove startup weak-alias precedence or panic override.

## Completion And Nonclaims

Until all common prerequisites, eight obligations and complete closing seals
pass, `CellContractSatisfied=False`, `RequiredCellSatisfied=False`,
`RequiredCellsSatisfied=0`, and `FullABIProof=False`. Missing generated
slot-access/source-body evidence prevents completion even if all links pass.
Completed evidence may credit only this exact bounded static cell contract;
retain all 2774 canonical keys and backlog without crediting other entries.
Do not promote old producer/join records, alter frozen predicates or infer
completion from plan accounting, root components or aggregate PASS counts.

Regardless of bounded-cell completion, keep `FullSemanticABIProof=False`,
`WholeProviderEquivalence=False`, `InstructionEquivalence=False`,
`PolicyEquivalence=False`, `SourceIRProof=False`,
`SourceToMachineSemanticProof=False`, `KernelRuntimeProof=False`,
`HandlerRoutingProven=False`, `CpuExecution=False`, `BoardExecution=False`,
`HostedCIQualified=False`, `ArchiveQualification=False`, and
`GlobalFreezeQualified=False`. No other modes/targets, CPU/Context migration,
full frame-constructor semantics or hardware behavior are qualified here.

## Maintained Entry Points

`components.py` requires explicit native-build, native-receipt-sha256,
native-artifacts-sha256 and output-dir arguments. It runs one fresh batched
five-link-control suite, typed and attribute compile probes, three specific
undeclared-slot compile controls, a same-object generated-slot replay and three
isolated common compiles. This entry point always retains zero cell credit.
Both dependency inventories must contain the actual probe and both canonical
ABI headers. Negative compile diagnostics use a closed source-bound GCC grammar.

`compose.py` requires explicit inventory, inventory-receipt-sha256,
inventory-artifacts-sha256, catalog, catalog-sha256 and output-dir arguments.
The catalog must contain only CM0/O2/direct. It authenticates the current plan
and both producers/prior join, recomputes the unchanged mechanism join, reruns
the producer's prelink/final predicates, and binds original/final references
with `bindings.py`. It executes the fixed component suite afresh in a child
output directory; it does not infer completion from an old component PASS.
Only after all three common prerequisites, eight runtime obligations and final
input/output closure may its new coverage credit this one exact static cell.
All other canonical keys and backlog records remain pending and visible.

During recomputed read-only predicates, source and data readers use the exact
admitted immutable byte buffers, including legacy helper loaders and captured
parser modules. Path resolution within this scope is lexical only, so a live
reparse cannot select a different admitted buffer. Only exact-byte capture
copies below the declared recomputed input directory may be written. This is
not a filesystem sandbox or a new physical-identity proof: real physical path,
membership and hash checks remain mandatory before and after the scope. The
fresh compiler component suite runs outside the buffered-reader scope and
performs its own full input/output closure.

A late failure revokes cell and obligation credit. Recovery first attempts a
FAIL receipt, then attempts the remaining debug artifacts independently and
preserves the primary cause. Metadata recovery never retries a compiler stage.
The caller must require successful process completion and complete closing
evidence; a live or partially written receipt is not terminal authority.

The tests include pure model/fault-injection controls and separately identified
read-only retained-ELF integration tests. `test_bindings.py` currently consumes
the exact retained build above, including its captured parser. These fixed-seed
local tests are not a portable fresh-build CI bootstrap or hosted-CI claim.
No test executes Arm target code or programs a board. Generalized fresh-build
CI admission, other profiles/modes/linkages and global freeze remain separate.
