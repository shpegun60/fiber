# Ordinary Final Cell Composition

## Status And Boundary

This directory maintains prerequisites for extending the bounded CM0/O2/direct
static-cell contract to thirty ordinary routes. `profiles.py` supplies independent
metadata; `abi.py` supplies declaration probes and source/dependency predicates;
`controls.py` adapts the qualified generic Suite; `components.py` executes one
selected fresh component batch. Thin final bindings remain a separate input to
future composition. There is no ordinary-cell composer here and these modules
do not qualify a cell or promote retained producer/join receipts. The published
CM0 component and its qualified helpers remain unchanged for their existing scope.

Only these profiles crossed with `O0`, `Og`, `O2`, `Os`, `O3`, linkage `direct`,
artifact role `runtime`, representation `final`, are admitted:

| Profile | Native port directory | CPU / ABI | NVIC / BASEPRI | VTOR | Reference port |
| --- | --- | --- | --- | --- | --- |
| CM0 | ARM_CM0 | cortex-m0 / soft | 2 / not applicable | 0 | ARM_CM0 |
| CM0PLUS | ARM_CM0 | cortex-m0plus / soft | 2 / not applicable | 0 | ARM_CM0 |
| CM0PLUSVTOR | ARM_CM0 | cortex-m0plus / soft | 2 / not applicable | 1 | ARM_CM0 |
| CM3 | ARM_CM3 | cortex-m3 / soft | 4 / 16 | 1 | ARM_CM3 |
| CM4 | ARM_CM4 | cortex-m4 / hard, fpv4-sp-d16 | 4 / 16 | 1 | ARM_CM4F |
| CM7 | ARM_CM7/r0p1 | cortex-m7 / hard, fpv5-d16 | 4 / 16 | 1 | ARM_CM7/r0p1 |

All six selectors have MPU0, classic security, default AAPCS r9, no PSPLIM,
MVE, PAC or BTI. These are exact fixture/cohort facts, not STM32 silicon MPU,
VTOR, erratum, hardware-operation or board-coverage claims. Reject LTO,
archives, caller-defined profiles and other inventory tuples here.

## Pure Metadata API

`profiles.py` performs no filesystem I/O, helper import or execution:

```python
profile(name, mode)                 # fresh JSON-like contract
route_contract("CM7/Os/direct")     # exact closed route lookup
profile_contract(name)              # mode-independent metadata only
require_native(result, name, mode)  # receipt metadata checks only
require_reference(result, name, mode)
```

`Rejected` denotes admission failure. No implicit mode or string/boolean/
integer alias is admitted. Returned dictionaries are independent across calls.
Primary consumer fields are `Profile`, `Mode`, `Cohort`, `SourceOrder`,
`PrivateSymbol`, `StorageSymbol`, `FloatABI`, `SourceInventorySha256`, `Target`,
`CompileFlags`, `SlotOwners`, `ReverseReferences`, `ColdAnchors`,
`CohortConsumers`, `StartupVectors`, `ForwardOwners` and `ReverseOwners`.
`CohortArtifact` is a full typed artifact oracle; it is not derived from the
receipt being checked. Hash-shaped receipt fields are declarations only until
the enclosing authenticated closure verifies their bytes and identities.

Source order is common core/state/panic, selected runtime/boot/exception,
expectation, typed application, startup: nine native objects. Context-init
belongs to boot index 4; the other seven forward operations to runtime index
3. Reverse selection/publication/require-current belong to state index 1;
task-return to core index 0. Slot and v1 anchor belong to state index 1;
private and storage identities to runtime index 3; startup to index 8.
Native C recipes append the exact TU parent include directory; reference C
recipes do not. Both startup recipes are separately fixed by their producers.

## Maintained Component Interface

The generic CLI is `components.py` with exactly these required arguments:

```text
python tools/fixtures/ordinary_final_cell/components.py \
  --native-build <native-build> \
  --native-receipt-sha256 <receipt-sha256> \
  --native-artifacts-sha256 <artifact-manifest-sha256> \
  --profile <closed-profile> --mode <ordinary-mode> \
  --inventory <e9-inventory> \
  --inventory-receipt-sha256 <inventory-receipt-sha256> \
  --inventory-artifacts-sha256 <inventory-artifact-manifest-sha256> \
  --output-dir <fresh-output>
```

The continuation marks above are presentation only, not PowerShell syntax.
Run with unoptimized Python. Admission authenticates the producer and current
inventory descriptors before output creation; the selected Suite may then run
managed host compiler/linker tools, never target code. The programmatic entry is:

```python
components.run_components(native_bundle, *, profile, mode, inventory,
                          helpers, watch, output_dir) -> dict
controls.create_suite(native_bundle, *, profile, mode, inventory,
                      helpers, watch, output_dir) -> Suite
```

`components.load_helpers()` returns `(helpers, watch)` from fixed source pins;
the Python API requires caller-authenticated bundles and helper execution
buffers. Suite methods retain `start()`, `command()`, `compile_tuple()`,
`run_link_controls()` and `finish(error=None)`. Subclassing adapts selection
without changing qualified-helper globals. Component orchestration reuses the
five intended link rejections, runtime save-temps replay, five ABI probes and
three isolated common-source compiles; completion is not a cell verdict.

The pure ABI entry points are `emit_probes(profile)`, `inspect_sources(profile,
sources)`, `inspect_provider_dependencies(profile, sources, receipt_bytes,
source_root=...)` and `inspect_preprocessed_attributes(profile, bytes)`.
Source hashes, metadata and declared dependencies do not prove actual object
providers, successful compiler attempts or final origins without their enclosing
input/command/ELF closure. Component success additionally requires complete
phases, error-free input closure and output sealing, with literal integer
`RequiredCellsSatisfied=0`; it is not exit-zero or prior-PASS trust.

Measured profile-smoke and test receipts, source revisions and outcomes belong
only to [the parent audit section](../../../PORT_ARCHITECTURE_AUDIT.md#ordinary-direct-component-generalization).
This contract asserts no forthcoming smoke or test result.

## Independent Source Authority

The enclosing gate must authenticate E9 using the independent receipt hash
`1910B53001FD37DF4B6DC57805EE49E4381B2529E1E3ECB47FDB312EB43A4DFC`
and artifact-manifest hash
`640C2CAC37DFC0A10F5A6E8538E7A9F81C7967DEEDEAA4B2924A15CAA1600CEA`.
Read `inputs/tools/freeze_cohorts.json` using its artifact entry; raw SHA256 is
`BC6B8EADABCAA6637FDD121D03B5CA341EEE31848D7E007D1D027AEE63EC8CBE`.
Its source identity is
`69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313`.
Canonical content fingerprints are not raw-file hashes. Bind full artifact
facts, selected source groups and the complete unchanged 2774-key plan and
26 backlog records. Historical E8 is not current E9.

The maintained prerequisite modules themselves must be captured and pinned by
their enclosing run; they were not present in E9. Actual consumed current C/H/provider bytes and
commands have their own producer authority, not presumed equality to every
historical E9 source capture. Expected symbol spellings follow the published
port/layout/trait identity macros, not observed ELF symbols or output hashes.

## Required Composition

Preserve the same common-three and runtime-eight obligation names as the
qualified CM0 contract. Reuse unchanged family join, canonical protocol,
source ownership, typed ABI, final ELF/map, generated-slot and link-control
predicates. Authenticate producer receipts/manifests, all actual providers,
original/captured/generated dependencies, tools, streams and source buffers
before execution; close physical identities and exact memberships afterward.
Metadata equality, a queue label or a prior PASS is not one of these proofs.

Each selected runtime has four reverse BL references with original addend
-4 and one task-return ABS32 with original addend zero. The independent rows
fix source owner, function/input section, target, kind and multiplicity, not
offsets. Bind actual relocations, map placements and applied final targets.
Cold anchor references occur once in prepare-start and once in context-init:
prove the retained literal load into r3 and immediate byte read through r3,
using actual mapped bytes and the qualified decoder. Discover mode-specific
positions; do not infer execution or C-callee semantics from those reads.
The two direct slot load sequences retain SVC/r0 and PendSV/r1 ownership.
Generated source/assembly and whole-object identity remain separate mandatory
evidence; slot placement alone does not satisfy isolation.

`components.slot_source_trivia(source_bytes)` accepts exactly two original slot
mentions in two literal address/load string pairs, one each for r0 and r1. Only
whitespace and complete block comments may separate the strings. A comment ends
at its first `*/`; matching cannot consume intervening C tokens by backtracking
to a later terminator. Backslashes in either gap reject phase-two splices.
Only comment bytes in those matched gaps become spaces, preserving byte length
and CR/LF positions. Other source bytes remain unchanged. This is a bounded
matched-trivia adapter, not a general C lexer, preprocessor or alias analysis.

`components.check_slot(slot, source, assembly, original_object, replayed_object,
profile=..., mode=...)` records `OriginalSourceSha256`,
`QualifiedNormalizedSourceSha256`, exact gap transformations and the unchanged
qualified result as `QualifiedSourceCheck`. Top-level `SourceSha256` identifies
the original consumed source; the nested qualified source hash identifies the
normalized predicate input. Original source authentication and actual compile
dependencies remain mandatory. Assembly and both object buffers pass unchanged
to the pinned `slot.check_generated`: exactly two immediate generated load pairs
within SVC/r0 and PendSV/r1, plus whole-object replay equality, still must hold.
Normalization is not a source rebuild or permission to alter generated accesses.

Original startup ABS32 references at 4/44/56 and final pointers must bind
Reset/SVC/PendSV, entry/MSP, strong owners and source-backed VTOR behavior.
Use final soft/hard e_flags independently of assembler FP attribute omissions;
do not apply C FP-attribute requirements indiscriminately to startup.S.

## Family Exceptions

- CM0 variants share native source/storage identity but retain distinct CPU/
  VTOR cohort selectors. Reference has five TUs, two port owners and five
  roots, including the C SVC helper. VTOR0 explicitly disables handler checks;
  VTOR1 retains them. BASEPRI is inapplicable. Preserve the CM0 checker's exact
  mode-specific whole-body/section padding and declared staged-frame difference.
- CM3 reference has four TUs and three roots from port.c. Both thresholds are
  16, NVIC bits 4 and handler checking enabled. Its local-pool and EXC_RETURN
  differences remain explicit; no CM0 staged-frame substitution is admitted.
- CM4/CM7 use hard ABI and eager native FP state, while the pinned reference
  retains ASPEN=1/LSPEN=1 lazy policy. Preserve FP-validation/setup rationales;
  mechanism acceptance does not establish FP-policy equality.
- CM7 uses r0p1 sources and its exact erratum metadata/define. The native
  preserving-PRIMASK contract must not be replaced by the reference's
  unconditional CPSID/CPSIE behavior. Retain the CM7 difference rationale.
- CM3/CM4/CM7 reference/native O0 padding is one post-island NOP per transfer
  root; other ordinary modes require zero. CM0 uses its separate fixed model.

Reference pin is `a50edad08b29052631aa469d4df6e6ec7ff68878`.
Require complete own-prelink and final-body preservation/origins, fixed
mechanism assignments and nonempty captured master-ledger rationales, plus
the already-qualified policy supplement where required. Compare each side's
own twins; this is not independent ordinary-root REL proof. Do not compare
native/reference bytes as if declared differences were absent.

## Accounting And Nonclaims

Only a complete newly composed bounded static cell may receive its exact
canonical key's credit. No such ordinary composer is implemented by these
prerequisites: they return zero new cell credit and leave all 2774 canonical
keys and 26 backlog records unchanged. Actual positive/negative compiler/link evidence must
be distinguished from pure admission controls and independently admitted for
the selected profile/mode. Do not relabel historical components or the prior
CM0 qualification to cover the new Cartesian product.

Full semantic ABI, whole-provider/instruction/policy equivalence, source/IR
semantics, C-callee semantics, kernel execution, CPU/board operation, handler
routing, hardware, hosted CI, final-LTO/archive and global freeze qualification
remain pending and unclaimed by these ordinary prerequisites.
`FullSemanticABIProof=False` is an intentional nonclaim, not a blocker to the
explicit bounded static obligations. No measured thirty-cell PASS is asserted.
