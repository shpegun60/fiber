# Native CM3 LTO Canonical Protocol Composition

## Fixed Scope

This separate, native-only composition joins complete machine-root canonical
protocol checks to the existing CM3 LTO machine-to-final preservation adapter.
It admits only native O2-lto direct linkage for
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`.
The initial retained producer is `C:/fz-cm3-lto-transport-20261105-e3`.
This contract does not report an implementation, test or qualification PASS.

Exactly three roots are admitted: `fiber_port_start_first_context`,
`SVC_Handler` and `PendSV_Handler`. Their preservation evidence covers 492
bytes, 170 instructions and 13 references: 11 named BL/addend -4 fields and
two section-symbol ABS32/addend 0 fields. Counts do not replace full matching.
This is not a native/reference join or the ordinary six-body checker result.

## Minimal Interface

```python
NativeProtocolView(decoded_machine, transport_image)
check_native(decoded_machine, transport_image, checker) -> dict
```

The enclosing gate constructs the unchanged canonical decoder's
`Object(actual_machine, actual_machine_disassembly)` and the existing
`NativeCM3LTOImage` from the same authenticated machine bytes. Machine
disassembly is the retained output for that ET_REL object, not final-executable
disassembly, reconstructed instructions or a caller-authored protocol list.

Recompute the three `transport_image.function(name)` preservation records.
Bind the decoder's whole machine bytes, each root's extent and raw body hash
to those same records. Associate records by exact name, not incidental list
order. Reject missing, duplicate or extra roots and differing machine bytes.
Identical captured copies are permitted only with explicit original identities.

The view implements `function(name, *, literal_islands=True)` for those roots
only. Retain the entire decoder result; its sole permitted projection is
specified below. Do not mutate decoder symbols/relocations, transport records,
reader/checker globals, protocol tables, ELF bytes or disassembly.

## Proven Slot-Role Projection

The frozen decoder renders a section-symbol literal using its referred section
label. The canonical native protocol instead uses the logical current-slot
name, `fiber_internal_runtime_current_context_slot`. Neither name string alone
establishes that these targets have the same role.

Permit projection only for the proven ABS32 reference at SVC root offset
`0xB4` and PendSV root offset `0xC8`. There are exactly two projected references;
first-start has none. Each requires original addend 0 and the adapter's exact
dedicated four-byte input slot section, local slot at offset 0, unique provider
and kept input-section placement, mapped final slot and output-section proof.
The literal LDR, pool location and complete reference must be the same ones
consumed by the preservation adapter, not another occurrence of a matching label.

Both raw STT_SECTION names are empty. Keep the original/final raw relocation
symbol dicts unchanged, together with `OriginalTargetSection` and
`FinalTargetSection`. Input `.bss.fiber_runtime_current_context_slot` and output
`.bss` are section labels, not replacement raw symbol names. The E3 output-slot
displacement `0x480` is derived from proven placements, never a name-based or
hardcoded substitute for origin evidence.

Only the corresponding canonical LDR target role and that reference's literal
descriptor `Relocations[].Target` may become the logical slot name. Parse the
descriptor structurally and preserve its offsets, bytes, reference links,
relocation kind, order and all other fields. All other tokens remain unchanged.
Retain each original/projected token and the supporting root/reference/origin
identity. Reject an unproved, extra, missing, differently typed or nonzero-addend
projection. This role projection proves no slot contents or scheduler semantics.

## Complete Native Matching

Use the unchanged CM3 checker as the protocol authority:
`checker._match(view, "Native", name, checker._NATIVE[name])` for all three roots.
Require exact complete sequences, including instruction constants/registers,
branch indices, literal bytes/descriptors, reference targets and tail layout.
Do not accept prefixes, fingerprints, subsets or caller-selected expected tokens.

Require literal `TailNops == 0` for every O2-lto root. The existing matcher also
admits a one-NOP O0 layout; its successful return alone is therefore insufficient.
Literal descriptors are not instructions and must not inflate the 170 total.
Do not call `check_pair()` with a dummy reference object or expected-token view,
fabricate three missing bodies, or claim paired mechanisms/difference-ledger
validation before independently captured reference LTO evidence exists.

## Evidence And Hash Domains

Retain unmodified machine-to-final preservation records beside separate native
canonical records and exactly two slot-role projection records. The adapter's
own `CanonicalProtocolValidated=False` remains intact; only the new composition
may report its separately established native-machine canonical validation.

Keep these domains explicitly distinct:

- Whole-machine and per-root machine/final hashes cover actual ELF bytes.
- Unprojected decoder-token hashes cover the complete decoder token JSON.
- Projected semantic-token hashes cover only the proved role-projected JSON.
- The checker's `BodySha256` is its canonical-token JSON hash, not raw body bytes.

Use the frozen checker's exact token serialization for its hash. Retain both
token forms, not just their digests, and never compare a token hash to a byte
hash as evidence of preservation. "Semantic tokens" names a logical role view,
not source-language, C-callee, IR-to-machine or whole-program semantic proof.

## Required Negative Controls

Include coherent changes to machine and final ordinary instruction constants,
with corresponding real decoded text, that retain bounds/mappings/references
and pass preservation but fail canonical matching. Examples include the fixed
BASEPRI threshold or SVC immediate. Preservation-only success must not promote
that altered protocol. Also test mismatched machine/body binding, false or
additional slot projections, wrong section/addend/origin, changed descriptor
bytes/links/offsets, extra instructions and branches into data or padding.

Explicitly reject one tail NOP even when all three roots use that layout, and
test raw-byte/token-hash confusion, fabricated reference credit and scope
promotion. Mutants use private copies; retained E3 and frozen helpers stay intact.

## Authority And Exclusions

An enclosing authenticated gate owns producer/manifest/input closure, exact
cohort/recipe/tool/provider provenance, same-buffer helper/parser loading,
physical identities, twin comparison, output sealing and closing rechecks.
The pure protocol module does not supply or replace that envelope or rerun tools.

Full ABI obligations, source/IR-to-machine semantics, policy equivalence,
reference/native equivalence, kernel/C-callee correctness, whole-object proof,
exception routing, MMIO, CPU/board execution and archive/general-LTO coverage
remain false or unproved. Required-cell/global counters stay typed integer 0;
global qualification stays false. No production or frozen ordinary-reader,
decoder, checker or transport-adapter changes are authorized by this contract.
