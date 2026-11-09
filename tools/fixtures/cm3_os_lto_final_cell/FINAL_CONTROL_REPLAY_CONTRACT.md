# CM3 Os-LTO Final Transport And Canonical Controls

## Scope

This defines the ninth bounded component after the eight-component
selected-replacement final replay. This document is not an implementation,
an admission, a test receipt or evidence that any new control executed.
Implementation follows the completed eight-component checkpoint. Actual
composition waits for final authenticated source pins and independent tests.

Execute exactly sixteen transport controls and one canonical control on each
side: 32 transport plus two canonical controls. Native means the selected
replacement's own final-supported machine/final/map/startup/dumps, not an
original-native path substituted because its bytes happen to agree. Reference
means the same admitted original reference bundle used by the eighth component.
Do not multiply this set by also running it against original-native twins.

Only additive pure control code, its independent tests, contract and later
composition belong in this slice. No runtime C/ASM, frozen helper/entrypoint,
reference pin, default matrix, toolchain, board or existing capture changes.
No new producer commands or inspection commands are authorized.

## Pure API

```python
inspect(core, read, batch, port, original, final, helpers)
require_result(proof, batch, port, original, final, helpers)
```

batch has exactly Root, Result, Artifacts, ReceiptSha256 and ManifestSha256.
port, original and final are freshly recomputed same-reader component records.
They are not retained successful receipts used instead of actual inspection.
The new component validates final with the published final validator, which
also validates its port/original inputs. The caller separately repeats every
earlier detailed validator, including the full port lowered validator, and all
eight shared-image/authority joins before success and after sealing.

helpers is an exact seventeen-key dictionary. The first fourteen are unchanged
from FINAL_REPLACEMENT_REPLAY_CONTRACT.md. All paths below are relative to
tools/fixtures/:

| Helper | Source |
|---|---|
| abi | cm3_os_lto_final_cell/abi.py |
| link_helpers | cm3_lto_link_contract/audit.py |
| binding_helpers | cm3_lto_runtime_bindings/bindings.py |
| native_roots | cm3_lto_roots/native.py |
| reference_roots | cm3_reference_lto_roots/reference.py |
| native_protocol | cm3_lto_protocol/protocol.py |
| reference_protocol | cm3_reference_lto_protocol/protocol.py |
| decoder | cm55_tfm_parity/elf.py |
| checker | cm3_freeze_parity/check.py |
| os_join | cm3_os_lto_join/compose.py |
| join | cm3_lto_join/join.py |
| guard | cm3_os_lto_final_cell/batch_guard.py |
| original_replay | cm3_os_lto_final_cell/original_replay.py |
| port_replay | cm3_os_lto_final_cell/port_replay.py |
| final_replacement_replay | cm3_os_lto_final_cell/final_replacement_replay.py |
| native_mutations | cm3_lto_roots/mutations.py |
| reference_mutations | cm3_reference_lto_roots/mutations.py |

core is the existing same-reader classic_final_image/elf.py module. Never open
a second parser/import environment, load helpers on demand, or invoke a compiler,
objdump, readelf, shell or subprocess. Reject missing/extra helpers, wrong APIs,
changed catalogs and foreign helper identities. All helper/source/contract bytes
must be authenticated and enrolled before the witness constructor. Available
snapshots alone are not explicit reader permissions.

## Frozen Recipe Authorities

The buffer implementation adapts, rather than executes, the following frozen
filesystem recipes. Their current raw SHA-256 values are:

| Source under tools/fixtures/ | SHA-256 |
|---|---|
| cm3_lto_roots/mutations.py | 32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353 |
| cm3_reference_lto_roots/mutations.py | E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C |
| cm3_lto_protocol/witness.py | 39E1994A74DB225CD3BB2010AE07C49FD1DB2EE2006BCAD2FC59BD3092E6CF51 |
| cm3_reference_lto_protocol/witness.py | B3968C5C51BCB7DFF13425B6656715DB4FA9674C18503AA04FDE7EA0A0F89D5F |

These sources already belong to the admitted legacy.FIXED source closure.
Require their exact bytes in the new bootstrap closure; that does not mean
their filesystem runner bodies executed. Authenticate all other helper pins
against the completed current checkpoint, not an earlier candidate digest.

Do not call either mutations.run_cases or mutations.mutate, either protocol
witness_type or its _constant_control method, or a witness constructor from
this pure leaf. In particular reference.mutate itself invokes _physical per
edit. Do not mock, bypass or fabricate _physical, stat, lstat, resolve, link
counts, file IDs or private-file closing evidence.

Implement explicit byte-buffer recipes corresponding to the fixed cases.
Named pure helpers may be reused: _symbol, native _symbol_file_offset,
reference _symbol_offset, _address_offset, _relocation_offset, encode_bl and
reference _dis_line/_dis_record. They must operate on the supplied parsed ELF
objects or literal bytes, never a new physical read. Reproduce the coherent
checks using fresh core._ELF objects through the strict local buffer facade;
reference coherent cases must also check actual changed dump records. Do not
replace these checks with a successful transport count or a stored coherence
flag. Preserve an explicit distinction between adapted recipes and unchanged
transport/canonical predicates.

## Explicit Input Roles

Inputs has exactly Final, Reference and Ledgers. Final and Reference each have
exactly Machine, Final, Disassembly, LinkMap, Startup and MachineDisassembly.
Ledgers has exactly Master and Policy. Every leaf is exactly Path/Sha256, with
canonical absolute string paths and uppercase SHA-256. These are fourteen
logical roles and fourteen distinct already-admitted paths.

Join all fourteen bindings to final.Inputs, not caller-selected substitutes.
The native provider pair is the selected machine and original native startup;
the reference provider pair is its own machine and startup. Keep original map
provider identity strings while mapping those identities to the appropriate
case-local buffers. A map's foreign-provider text never grants a new read role.

Read and independently hash every positive input through read(Path, sha256).
Reject non-bytes, missing permissions, wrong bytes and undeclared paths even
when the caller's read callback ignores its digest argument. Join every size
to final.ReadInputs and its independently validated original/port inventories.
Ledger sizes also equal decoded final.ControlBytes lengths. No new receipt,
manifest, producer binary, source/header or inspection output is needed.
The new leaf must not claim it separately reread the earlier authority files.

Use one exact-membership local Path read_bytes/read_text facade for positive
and derived buffers. Require canonical paths, bounded strict text decoding and
no physical fallback. No file writes, directory operations, physical Path APIs
or module loading occur in inspect or require_result. A case cannot read any
other case's private buffers. Positive buffers remain immutable throughout.
Generate each recipe's edits before its predicate phase; then freeze the exact
five/six complete byte buffers and their hashes. A fresh adapter/coherence
parser consumes those frozen buffers only. Reject any buffer/hash/membership
change during or after the predicate, and close all positive/derived buffers
before returning success. In-memory generation is not permission to change
bytes underneath an active parser.

Before mutating, freshly construct both real adapters and decoders, evaluate
all six roots and recompute os_join.check_join plus both ledger rationale sets.
Compare this complete baseline to the freshly validated final component.
Do not accept an O2-labeled witness verdict as an Os result or modify any
checker's expected token tables. The lower-level frozen matchers are reused
for their actual predicates, not their standalone O2 receipt scope strings.
The canonical/returned transport root order is exactly native
fiber_port_start_first_context, SVC_Handler, PendSV_Handler and reference
prvPortStartFirstTask, vPortSVCHandler, xPortPendSVHandler. Adapter dictionary
iteration order does not replace these explicit ordered catalogs.

## Exact Transport Catalog

Preserve this order on both sides. Expected is the exact regex fragment from
the corresponding frozen CASES entry. Only core.Rejected with a message
matching ^REJECT: followed by that fragment and a colon counts as rejection.
An assertion, permission failure, recipe/precondition error or unrelated
diagnostic is FAIL, not a successful mutant rejection.

| Native name | Native Expected | Reference name | Reference Expected |
|---|---|---|---|
| machine-nonrelocation-byte | LTO-PRESERVATION | machine-nonrelocation-byte | REF-LTO-PRESERVATION |
| machine-bl-addend | LTO-RELOC | machine-bl-addend | REF-LTO-RELOC |
| machine-slot-addend | LTO-SLOT | machine-slot-addend | REF-LTO-SLOT |
| applied-slot-word | LTO-SLOT | applied-slot-word | REF-LTO-SLOT |
| coherent-slot-in-bss | LTO-(ORIGIN\|SYMBOL) | coherent-slot-in-bss | REF-LTO-ORIGIN |
| globalized-slot | LTO-SYMBOL | localized-slot | REF-LTO-SYMBOL |
| wrong-slot-section-target | LTO-SLOT | wrong-slot-named-target | REF-LTO-RELOC |
| function-alias | LTO-SYMBOL | function-alias | REF-LTO-SYMBOL |
| slot-object-alias | LTO-SYMBOL | slot-object-alias | REF-LTO-SYMBOL |
| code-without-execute | LTO-SYMBOL | code-without-execute | REF-LTO-SYMBOL |
| callee-data-mapping | LTO-SYMBOL | callee-data-mapping | REF-LTO-SYMBOL |
| coherent-callee-entry | LTO-ORIGIN | coherent-callee-entry | REF-LTO-ORIGIN |
| wrong-machine-section-size | (LTO-)?ORIGIN | wrong-machine-section-size | REF-LTO-ORIGIN |
| foreign-map-provider | (LTO-)?ORIGIN | foreign-map-provider | REF-LTO-ORIGIN |
| missing-root-reference | LTO-RELOC | missing-root-reference | REF-LTO-RELOC |
| extra-root-reference | LTO-RELOC | extra-root-reference | REF-LTO-RELOC |

Each case has exactly five derived role instances: Machine, Final, Disassembly,
LinkMap and Startup. Unchanged copied roles remain present. No-op changes,
unsupported layouts, ambiguous symbols/relocations/map rows or out-of-bounds
edits fail before a rejection can be credited. Use fresh adapters for cases;
do not reuse positive or another case's cached origin evidence.

For coherent-slot-in-bss, move the slot by minus four, update both applied slot
words and verify actual file-backed words against the new aligned BSS symbol.
Native must retain valid BSS extent/definition metadata. Reference must also
swap the neighboring ulMaxPRIGROUPValue address, preserve nonoverlapping BSS
extents, and update/verify both disassembly words. Provider semantics remain
unclaimed. Then the intended origin/symbol predicate must reject.

For coherent-callee-entry, move the final callee entry by plus two, reduce size
by two and actually encode the corresponding BL. Native uses
fiber_port_context_validate_restore from SVC_Handler+0x72; reference uses
vTaskSwitchContext from xPortPendSVHandler+28 and updates/verifies its BL dump
record. Fresh core._ELF/_address_form checks must establish binary coherence
before the intended origin rejection. Both coherent cases keep Machine bytes
unchanged. Do not count an incoherent edit rejected for some other reason.

## Exact Canonical Controls

Each side has one case named coherent-svc-immediate with Expected equal to
CM3-CLOSED-ROOTS and six derived roles, adding MachineDisassembly to the five
transport roles. Change both Machine and Final opcode fields and both matching
dump records; keep LinkMap and Startup unchanged.

| Side/root | Relative offset | Before bytes | After bytes |
|---|---:|---|---|
| Native/fiber_port_start_first_context | 82 | 46df | 47df |
| Reference/prvPortStartFirstTask | 22 | 00df | 01df |

At execution, derive each file offset from the fresh unique Thumb root symbol
and actual owning section. Check exact root metadata, bounds, original opcode
and one matching root/section/address dump record before applying the recipe.
Never use the observations below as a global fixed file-offset patch. Verify
each changed dump's displayed bytes, SVC immediate and address against its
own changed ELF. Native is decimal SVC70 to SVC71; reference is SVC0 to SVC1.

A read-only authoring check authenticated the completed original-composition
receipt F72CFBB8E8A9184797341220A220DB3B45B026D66E58F5ED6CDC0139114F532E,
then checked its bound selected-final/reference ELF bytes with ELF32 field
reads, not a predicate, test suite or admission. The observed bindings were:

| Side/role | SHA-256 | File offset | Original bytes |
|---|---|---:|---|
| Native/Machine | D4733951A229C74AA38FB9B301A73BB1B9C08D977AB048BE84A1515E9EC76C3C | 1158 | 46df |
| Native/Final | 442FC283272617068BDCDBAF4D69EE15ACFD6AABFD2B1317E32303326C13C1FF | 6230 | 46df |
| Reference/Machine | E67747ADE8AB0905AE474715555EA8D0E9433C7002C8D8D50A7B9235373AC45A | 194 | 00df |
| Reference/Final | 204E56BE22721E5DBDBCF136252F9AC4DC2D8FABEB6A0E63B6B3F51FE9353DBA | 5314 | 00df |

For each changed pair, all three real transport function calls must succeed.
Then use the real changed decoder and NativeProtocolView/ReferenceProtocolView
with the unchanged checker. Only checker.Rejected whose message starts with
REJECT:CM3-CLOSED-ROOTS:Native/fiber_port_start_first_context/ or
REJECT:CM3-CLOSED-ROOTS:Reference/prvPortStartFirstTask/, respectively, is PASS.
Retain the actual first-start canonical tokens for detached pure token checks.
TransportPreservationAccepted is true; TwinComparisonExecuted and
SourceAuthorityPreserved are false. No mutant inherits positive capture/twin
authority, even though its transport is deliberately preserved.

## Closed Result

The exact thirty top-level keys are Status, Scope, Profile, Mode, Linkage, LTO,
Cohort, SourceInventorySha256, BatchRoot, BatchAuthority, PortProofSha256,
OriginalProofSha256, FinalProofSha256, Inputs, LedgerBytes, Baseline, Controls,
DerivedBuffers, ReadInputs, LogicalRoles, ReadFiles, DerivedRoleInstances,
TransportControlsExecuted, CanonicalControlsExecuted, FreshControlsExecuted,
ImmutableInputsConsumed, ToolInvocations, CompilerInvocations,
RequiredCellsSatisfied and Nonclaims.

Status is CM3-OS-LTO-FINAL-CONTROLS-REPLAYED-NOT-QUALIFIED. Scope is
CM3_OS_LTO_SELECTED_FINAL_AND_REFERENCE_34_BUFFER_CONTROLS_ONLY. Identity is
CM3/Os-lto/direct, literal LTO true, and the existing fixed cohort/source hash.
BatchAuthority is exactly Receipt/Manifest bindings and joins final. The three
full component hashes use sorted compact ASCII JSON with allow_nan disabled
and no newline. They bind the complete supplied port/original/final records.

LogicalRoles and ReadFiles are integer fourteen, DerivedRoleInstances is
integer 172, TransportControlsExecuted is integer 32, and
CanonicalControlsExecuted is integer two. FreshControlsExecuted and
ImmutableInputsConsumed are literal true only after every case and closing
buffer check passes. ToolInvocations, CompilerInvocations and
RequiredCellsSatisfied are literal integer zero. Bool/int aliases reject.

ReadInputs is the sorted fourteen-row unique Path/Sha256/Bytes inventory,
with independently joined positive integer sizes. LedgerBytes is exactly
Master/Policy lowercase byte hex matching the input hashes and captured final
ledger controls. Baseline is exactly TransportRoots, CanonicalJoin and
PolicyDifferenceRationales, with complete freshly recomputed bounded evidence
equal to the corresponding final fields; retain its false mutant/stronger
claims unchanged.

Controls is exactly Native/Reference, each exactly Transport/Canonical with
sixteen/one ordered rows. Each successful row has exactly Name, Expected,
Status, BufferIndices, Rejection and Coherence. Status is PASS. Rejection has
exactly Type/Message; Type is CORE for transport or CHECKER for canonical.
Message must match the side/case-specific diagnostic above, not generic error
text. BufferIndices selects exactly the case's ordered five/six derived rows.
Every derived row belongs to one case, with no omission, duplication or alias.

Coherence is null except for the two coherent transport cases and the
canonical case. Its case-specific exact keys are:

- Slot: Kind, OriginalAddress, MutatedAddress, Loads, NeighborSwap,
  ImmutableOriginControlCoherenceChecked, ProviderSemanticsClaimed. Kind is
  SLOT-IN-BSS; the two flags are true/false. Loads has exactly the two handler
  Root/RootRelativeOffset/Bytes/DisassemblyUpdated records: native offsets
  0xB4/0xC8, reference 32/64. Addresses are aligned integers, differing by minus
  four. NeighborSwap is null on native, or exactly Name/BeforeAddress/
  AfterAddress for reference ulMaxPRIGROUPValue. DisassemblyUpdated is false
  for native and true for reference; do not invent native dump coherence.
- Callee: Kind, Name, OriginalAddress, MutatedAddress, OriginalSize,
  MutatedSize, Root, RootRelativeOffset, BranchBytes, DisassemblyUpdated,
  ImmutableOriginControlCoherenceChecked, ProviderSemanticsClaimed. Kind is
  CALLEE-ENTRY. Use the exact names/sites above, even target addresses differing
  by plus two, positive sizes differing by minus two, actual four-byte BL hex,
  and true/false coherence/provider flags. DisassemblyUpdated is false on
  native and true on reference.
- Canonical: Kind, Root, RootRelativeOffset, BeforeOpcode, AfterOpcode,
  TransportPreservationAccepted, TransportRoots, CanonicalTokens,
  CanonicalTokenSha256, CanonicalRejected, TwinComparisonExecuted,
  SourceAuthorityPreserved. Kind is SVC-IMMEDIATE. Retain all three changed
  transport records and the actual first-start token list; token hash uses
  compact ASCII JSON. The preservation/rejection flags are true and the last
  two fields false. No caller-selected root, immediate or token subset.

DerivedBuffers is ordered Native then Reference; within each side, sixteen
transport cases in catalog order then the canonical case. Role order is
Machine, Final, Disassembly, LinkMap, Startup, then MachineDisassembly only for
canonical. Thus 2 * (16 * 5 + 6) equals 172 role instances, not 172 distinct
original inputs or evidence of physical private files.

Each derived row has exactly Side, Stage, Case, Role, Input, Output and Edits.
Stage is Transport or Canonical. Input is exactly Path/Sha256/Bytes and joins
the appropriate admitted positive role. Output is exactly Sha256/Bytes/Data,
where Data is complete lowercase byte hex, with independently recomputed hash
and positive integer length. Edits is an ordered list of exact
FileOffset/Before/After rows, with integer bounded offsets and lowercase byte
hex; Before and After must differ. Offsets are relative to the sequential
buffer state, allowing exact variable-length map/dump replacements.

Replay edits forward to obtain Output and backward to reconstruct Input;
verify every extent, before/after substring, hash and size. A copied unchanged
role has empty Edits and identical bytes/hash/size. Each case nevertheless has
at least one real edit and exactly the recipe's changed roles. Reconstructed
positive bytes must agree across all occurrences of each path. No unused,
extra or cross-case buffers, invented edits, physical identities or case counts.

## Detached Validation And Claims

require_result performs no I/O, ELF/decoder construction, helper loading or
capture admission. It repeats the supplied component validators, full proof
hash/authority/input/size joins, closed typed schemas, exact catalog/order,
buffer-edit/hash reconstruction, case-specific coherence fields and narrow
diagnostics. It may recompute pure baseline token/ledger predicates and the
canonical negative token match. It must not turn a retained rejection string
or a shallow count into a claim that fresh binary predicates executed.
Fresh execution comes from inspect and its authenticated same-reader call and
source/buffer bindings, not from detached validation alone.

Coherence must join actual case bytes, not only self-consistent metadata or
an expected rejection prefix. CanonicalTokens must exactly equal that side's
baseline first-start RawCanonicalTokens with only its single specified SVC
operand changed: native 70 to 71 or reference 0 to 1. A different bad immediate
such as 72 is not equivalent evidence, even if it produces the same rejection.
Every retained changed transport record must bind that case's complete output
hashes, own provider/map roles and actual reconstructed root-body bytes.

Slot/callee original addresses, sizes and roots join baseline definition and
reference metadata. Mutated symbol fields, applied words, BL bytes/targets and
any changed dump records join the exact reconstructed case buffers and recipe
edits. Required field/slice offsets must be derived and bounded from actual
ELF32 buffer metadata, never accepted as free caller-selected coordinates.
Bounded structured byte-field/slice checks are permitted here; fresh ELF/decoder
objects, transport constructors or binary predicate replay are not. Insufficient
baseline provenance is a contract failure, not permission to trust a flag.

Nonclaims is the final component's independent closed 27-name literal-false
catalog, replacing only MutantsReexecuted with AllProducerMutantsReexecuted.
The latter remains false: these 34 bounded controls are not every producer's
mutant catalog. Preserve every other stronger false field, including
qualification, full ABI/instruction/source-to-machine semantics, ordinary-root
preservation, handler routing, final reference parity, policy equivalence,
arbitrary callback safety, other-six-body identity, whole-cell, CI/archive,
CPU/board and global-freeze claims. No negative-link control credit follows.
Do not mutate any of the eight earlier records or their false mutant fields.

A later additive composition uses the same one immutable reader for all nine
components and adds only a bounded FinalControlComponentReplayed fact.
Recorded inspection/ABI/isolation/common/port counts stay 2/41/12/45/36;
tools, compiler and required-cell credit stay zero, RequiredCellCount stays
2774, and pending remains the unchanged exact common-attribution projection.
The new 32/2 counters describe only this component's controls, never new tool
commands or qualification credit. On any replay, closure, seal, post-seal,
summary or recovery failure, revoke every success fact and executed-control
counter as well as existing recorded-command credits. Recover only an owned
fresh output tree and preserve earlier attempts unchanged.

Pure implementation does not create 172 private files. A later owner may seal
the derived byte records and optionally materialize predetermined output files
outside the reader, with real output physical/tree closure. Such output facts
must remain separate from the leaf's buffer-only evidence.

## Future Independent Controls

Before execution authorization, tests must exercise all 34 recipes on admitted
actual-byte fixtures without compiler/tool/admission claims, plus missing roles,
digest-ignoring readers, wrong helper/catalog/cohort, no-op or out-of-bounds
edits, incorrect SVC locations/opcodes/dumps, incoherent slot/callee edits,
unrelated rejection families, canonical transport failure, unsupported layouts,
cross-case reads, mutable/aliased buffers, forged rows/counts/sizes/flags,
component substitutions and detached validation with I/O/binary inspectors
disabled. No assertion or outer I/O fence may satisfy an intended predicate
rejection test. Any lifecycle doubles must be disclosed separately from actual
byte predicates. Add coordinated negatives for token/hash disagreement with
the SVC bytes, transport-record/hash/body substitution, and slot/callee fields
disagreeing with baseline metadata or reconstructed case bytes. This contract
grants no execution credit before tested code and fresh composition complete.
