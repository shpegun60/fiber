# Reference CM3 LTO Canonical Protocol Composition

## Fixed Scope And Status

This separate reference-only composition adds complete canonical machine-root
matching to the fixed reference CM3 O2-lto direct transport envelope. It admits
only `cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default` and FreeRTOS
pin `a50edad08b29052631aa469d4df6e6ec7ff68878`. The initial producer is
`C:/fz-cm3-reference-lto-transport-20261105-e3`.

The exact roots are `prvPortStartFirstTask`, `vPortSVCHandler` and
`xPortPendSVHandler`: 136 complete bytes including pools/alignment, 39
instructions and three named references. First-start is LOCAL STT_FUNC, size
32; SVC and PendSV are GLOBAL STT_FUNC, sizes 36 and 68. Counts alone do not
establish complete matching. This is not native protocol validation or a join.
This contract reports no implementation, actual-control or qualification PASS;
those require a separately retained successful parent execution receipt.

## Frozen Source Cohort

The root envelope, reference adapter and actual mutation helper are respectively
`cm3_reference_lto_roots/{witness.py,reference.py,mutations.py}`. The decoder is
`cm55_tfm_parity/elf.py`; the checker is `cm3_freeze_parity/check.py`. All paths
are under `tools/fixtures/`. Require these exact SHA-256 values before use:

```text
RootEnvelope     3B9168D52F7AA63339264A8E7B655DF94FF1AC644FF08D20E4B617CED5699B54
ReferenceAdapter 3E53C4C0C5030B973A599FBDD0CB0B7FDECC625DEFD8C204A8C9691C5F6A616D
ActualMutations  E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C
Decoder          394BA0549C2325BC5BB988EB1A6EBA89263CAF3E351189582931C59A64D5752D
Checker          F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A
```

Authenticate captured bytes and execute those same immutable buffers, including
nested helper/parser loads. Record the new protocol and wrapper source hashes
separately. Do not mutate frozen decoder/checker tables, transport records,
symbols, ELF metadata or ordinary-reader policies to make a protocol match.

## Same-Machine Composition

```python
ReferenceProtocolView(decoded_machine, transport_image)
check_reference(decoded_machine, transport_image, checker) -> dict
```

Construct unchanged `decoder.Object(actual_machine, actual_machine_disassembly)`
and `ReferenceCM3LTOImage` from the exact same authenticated machine bytes.
The decoder uses the retained ET_REL machine disassembly, not final disassembly,
saved assembly, an ordinary O2 object or a manufactured expected-token image.

Recompute all three `transport_image.function(name)` records and bind them by
exact name. Require whole-machine byte equality, unique decoded definitions,
literal integer metadata, raw local/global function roles and Thumb entries.
Bind each decoded root's section, normalized offset, size and complete body hash
to its preserved machine origin and exact machine-provider hash. Missing,
duplicate, extra or mismatched roots/bytes/origins reject before protocol credit.

Keep each adapter record unmodified, including its original/final reference
symbol metadata, named slot/callee origins and complete mapping/data evidence.
The full source-to-final producer authority is not supplied by this pure view.

## Raw Reference Tokens Only

Call `decoded_machine.function(name, literal_islands=True)` and retain the
complete raw token sequence. Both slot ABS32 references are already named
`pxCurrentTCB`; no native section-slot projection is necessary or permitted.
Require `SemanticProjections=0` and empty projection evidence. No label alias,
normalization of raw symbol facts or replacement expected-token body is allowed.

For each root, invoke the unchanged fixed reference model:
`checker._match(view, "Reference", name, checker._REFERENCE[name])`.
Require the complete sequence, register/constants, literal descriptor bytes,
reference targets, branch indices and mapping/tail layout. Do not accept a
prefix, fingerprint, subset or caller-selected protocol. Preserve adjacent data
boundaries and alignment; descriptors are not instructions or CFG assertions.

Every matched root must have literal integer `TailNops == 0`. The checker's
allowed O0 tail variant is insufficient for this O2-lto composition. This does
not remove the real in-body NOP before first-start's pool. Do not fabricate
native roots or call `check_pair()` with a dummy side to obtain mechanism or
difference-ledger credit.

## Evidence And Hash Domains

Retain complete raw tokens and their exact serialized JSON hashes beside raw
machine/final body hashes and provider/origin records. The checker's
`BodySha256` hashes canonical token JSON, not machine or final instruction bytes.
Use its frozen serialization; never substitute one hash domain for another.
No projected or source-semantic hash is invented for these unprojected tokens.

Only the separate composition may report reference canonical validation after
all checks succeed. Old transport records keep `CanonicalProtocolValidated=False`
and all their existing false proof flags. Canonical success neither rewrites
the original producer scope nor promotes transport capture into source proof.

## Independent Coherent SVC Control

Keep the frozen root envelope's 16 actual transport controls and 80 private
files distinct from this additional protocol control. Use six private inputs:
Machine, Final, MachineDisassembly, Disassembly, LinkMap and Startup. Preserve
original machine/startup linker-map provider identities when supplying copies.

In first-start, independently locate the real SVC immediate at root offset 22
in machine and final. Require original bytes `00df`, change only that instruction
to `01df` (SVC 0 to SVC 1), and patch the corresponding byte/mnemonic/immediate
records in both disassemblies. Leave mappings, extents, references, map and
startup intact. Require actual edits in both ELF files and both decoded texts;
retain all original/changed bytes or hashes and actual patched addresses.

Bind all six complete input buffers before parsing, with no unknown-input disk
fallback. Under that immutable envelope, require all three transport roots to
accept and bind their recomputed records to the same changed machine. Then
require rejection by the frozen canonical checker at Reference/first-start,
not an unrelated parser, stale disassembly, input-binding or origin failure.
Preservation acceptance alone must not promote the changed SVC protocol.

After parsing, recheck all six physical artifact bytes/hashes and exact private
directory membership. Retain the checker diagnostic, positive transport result,
executed source buffers and closing evidence. Control success requires both
outcomes; a setup exception or unexecuted control is not a passing rejection.
These edited private files have `SourceAuthorityPreserved=False` and
`TwinComparisonExecuted=False`; do not claim mutant twin equality or producer
source/configuration authority. Never alter retained E3 or frozen sources.

## Enclosing Authority And Nonclaims

The authenticated outer envelope owns producer/manifest/input closure, fixed
pin/configuration/recipe/tool/provider provenance, physical input admission,
genuine positive ordinary/emit-relocs twin comparison, output seals and closing
rehashes. The pure protocol module supplies none of these and executes no tools.

Full API/ABI, source/IR-to-machine semantics, per-TU origin, native/reference join,
policy, C/kernel semantics, whole-object proof, exception routing, MMIO,
CPU/hardware and global qualification remain false or unproved. Required-cell
and global credit remain typed integer zero. No archive/other-mode claim,
production change, frozen-reader change or default-matrix credit is authorized.
