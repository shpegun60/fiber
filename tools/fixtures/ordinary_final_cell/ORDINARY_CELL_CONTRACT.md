# Ordinary Final Cell Composition

## Status And Boundary

`compose.py` implements a generic single-cell composition for one explicitly
selected ordinary route. `profiles.py` supplies independent metadata;
`recompute.py` replays unchanged family predicates and thin `bindings.py`
checks; `abi.py`, `controls.py` and `components.py` supply fresh declaration,
link-control, generated-slot and common-source evidence. `coverage.py` accounts
for the one final verified key without dropping the rest of the inventory.
Metadata and component modules alone still grant no cell credit. The published
CM0 composer and qualified producers/readers/helpers remain unchanged for their
existing scopes; this composer does not broaden their individual claims.

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

## One-Cell Composer Interface

Use one fresh unoptimized Python process per route, with isolation, site loading
disabled and bytecode writes disabled. `compose.py` requires `-I -S -B` and
rejects inherited `elftools` package/module state. There is no implicit route.
The seven required arguments are:

```powershell
& $Python -I -S -B tools/fixtures/ordinary_final_cell/compose.py `
  --inventory $Inventory `
  --inventory-receipt-sha256 $InventoryReceiptSha256 `
  --inventory-artifacts-sha256 $InventoryArtifactsSha256 `
  --catalog $Catalog `
  --catalog-sha256 $CatalogSha256 `
  --route $Route `
  --output-dir $FreshOutput
```

`$Route` is an exact selector such as `CM3/Os/direct`. All catalog rows must
have closed ordinary-route metadata, even when only one is selected. Catalog
membership and unselected receipt descriptors grant no proof or credit. Select
exactly one row; authenticate its native, reference and prior-join receipts,
artifact maps, original/captured/generated inputs and their inventory bindings
before creating output. The selected inventory descriptor must equal the
independently caller-bound current E9 descriptor, not a historical substitute.
Reject output overlap with repository, admitted inputs/tools and catalog-declared
evidence roots before creation. No catalog value supplies executable code or argv.

The programmatic orchestration is `compose(prepare(args))`; `succeeded(report)`
requires the final one-cell scope, exact common/runtime satisfaction, literal
credit one, successful input/output closure, no errors and false broad claims.
Run another route in another fresh process. A 30-row catalog is not an atomic
batch, an in-process replay request or authority to award aggregate credit.

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

Measured component/composer and test receipts, source history and outcomes belong
only to [the parent audit section](../../../PORT_ARCHITECTURE_AUDIT.md#ordinary-direct-component-generalization).
This contract asserts neither a forthcoming run result nor a final measured
thirty-route PASS. Preliminary source revisions must not be relabeled as the
final Cartesian-product qualification.

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

The composer and maintained prerequisite modules themselves must be captured
and pinned by their enclosing run; they were not present in E9. Actual consumed
current C/H/provider bytes and commands have their own producer authority, not
presumed equality to every historical E9 source capture. Expected symbol
spellings follow the published port/layout/trait identity macros, not observed
ELF symbols or output hashes.

## Required Composition

Preserve the same common-three and runtime-eight obligation names as the
qualified CM0 contract. Reuse unchanged family join, canonical protocol,
source ownership, typed ABI, final ELF/map, generated-slot and link-control
predicates. Authenticate producer receipts/manifests, all actual providers,
original/captured/generated dependencies, tools, streams and source buffers
before execution; close physical identities and exact memberships afterward.
Metadata equality, a queue label or a prior PASS is not one of these proofs.

The common prerequisites are exactly `cpu-neutral-engine`,
`reverse-v1-ownership` and `source-provider-identity`. The runtime obligations
are exactly `forward-eight`, `reverse-v1`, `current-slot-isolation`,
`strong-handlers`, `exact-profile-context-cohort`,
`generated-assembly-reference-parity`, `final-elf-vectors` and
`negative-link-controls`. Every one must complete for the selected exact key.

Recomputation binds native Pilot owner/prelink/final predicates to the same
authenticated source/object providers, and compares complete family protocols,
final roots, own twins and producer bindings with the selected prior join.
Difference acceptance requires nonempty captured master-ledger rationales and
the independently pinned FP policy supplement where applicable, not equal
native/reference instructions or policy. Thin bindings and metadata do not
replace these complete checks.

Predicate reads execute against admitted immutable data/source buffers and exact
capture aliases. For CM3, its inner frozen source loader is the sole spec-loader
authority, delegated through the original stdlib spec function rather than a
second stacked frozen spec loader. The outer buffered data/source/code hooks,
capture aliases and lexical path-resolution hooks remain active. This routing is
not filesystem identity proof. Leave the immutable scope before fresh component
tool execution and real physical closing; restore all temporary hooks without
changing qualified-helper globals.

Fresh components must use the selected native descriptor, profile, mode, cohort
and inventory identity. Authenticate their returned/written receipt equality and
complete artifact map. Close both replay and outer inputs against real hashes,
physical identities and memberships, and seal the exact intended output bytes
and output membership. Only the successfully sealed final result can retain
one-cell credit; partial predicate or component success is insufficient.

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

`coverage(required, backlog, contracts, verified_keys)` returns the full coverage
and missing-work dictionaries. The pure layer preserves all 2774 canonical keys
in order, every role's missing obligations and deep copies of all 26 backlog
records (23 Pending, three ReferenceOnly). It does not authenticate inputs or
infer completion from receipt labels. The one-cell composer passes only
`[selected_contract]` and either `[]` or `[exact_five_tuple]`, where the tuple is
`(Cohort, ArtifactRole, Representation, Mode, Linkage)`.

The selected key may receive exactly one bounded static-cell credit only after
all common-three/runtime-eight proofs and final closures succeed. The other
2773 keys and all backlog records remain uncredited. Any late replay, component,
input, output or sealing failure revokes every obligation and all credit.
Recovery attempts to persist the FAIL receipt first, then regenerates full
zero-credit coverage/missing-work with `verified_keys=[]`, and refreshes the
failure receipt/manifest. Secondary persistence errors remain explicit and do
not restore a PASS or credit. There is no atomic batch or aggregate credit
inferred from the other catalog rows.

Actual positive/negative compiler/link evidence must be distinguished from pure
admission controls and independently admitted for the selected profile/mode.
Do not relabel historical components or the prior CM0 qualification to cover
the new Cartesian product.

Full semantic ABI, whole-provider/instruction/policy equivalence, source/IR
semantics, C-callee semantics, kernel execution, CPU/board operation, handler
routing, hardware, hosted CI, final-LTO/archive and global freeze qualification
remain pending and unclaimed by this ordinary composition. `FullABIProof=False`
and `FullSemanticABIProof=False` are intentional nonclaims, not blockers to the
explicit bounded static obligations. The eager-native/lazy-reference FP policy
difference is retained, not qualified as equal. No measured thirty-cell PASS is
asserted.
