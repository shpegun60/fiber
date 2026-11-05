# Native CM3 LTO Machine-To-Final Roots

## Fixed Scope

This separate adapter specifies machine-to-final preservation for exactly
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`, native O2-lto,
direct linkage. Target facts are Cortex-M3/ARMv7-M, ordinary AAPCS, soft ABI,
no FPU/FP stacking, VTOR1, no MPU, classic security, priority bits 4 and raw
BASEPRI threshold 16. These fixture facts are not silicon or execution proof.

The initial machine authority is the retained E3 producer output at
`C:/fz-cm3-lto-transport-20261105-e3/emit-relocs/`:
`image.elf.ltrans0.ltrans.o`, `image.elf`, `image.elf.dis`, and `image.map`.
E3's capture/build PASS alone does not qualify these roots. This contract is
not a report that an adapter, envelope, test suite or actual replay has passed.

The three complete roots total 492 bytes, 170 instructions and 13 applied
references: 11 named BL relocations with original addend -4 and two
section-symbol ABS32 relocations with original addend 0. No other mode,
cohort, reference build, archive or LTO partitioning policy is admitted.

## Reader Boundary

```python
NativeCM3LTOImage(core, machine, final, disassembly,
                  *, provider_objects, link_map)
```

`core` is the authenticated, unchanged ordinary `classic_final_image/elf.py`.
Reuse its ELF/address decoding and bounded utilities without changing its
globals, symbol policies, relocation allowlists or existing reader behavior.
The adapter has no caller-selected profile, mode, roots or target allowlist.
Its function interface admits only `fiber_port_start_first_context`,
`SVC_Handler` and `PendSV_Handler`.

`provider_objects` maps original absolute linker-map object identities to
captured machine-byte files. The actual machine providers are the saved LTRANS
object and native startup object; GIMPLE inputs are not machine providers.
Copied filenames do not replace original map identities. No ELF rebasing,
symbol rewriting, ET_EXEC-to-ET_REL conversion or reassembled `.s` substitute
is permitted. Root ownership must select the supplied saved machine bytes.

## Outer Authority

The enclosing producer envelope is separate and is not supplied by this reader.
It must authenticate caller-bound producer receipts, complete artifact/input
closure, the exact source/cohort/flags/tool chain and saved-machine selection
before parser import or qualification. It binds helper/parser bytes actually
executed, original provider identities, final/map/disassembly hashes and closes
all inputs. The reader does not establish source-to-IR or IR-to-machine semantics.

Canonical protocol validation is a separate enclosing-checker obligation,
pending the next composition; this reader reports `CanonicalProtocolValidated=False`.
General instruction-constant semantics and source/IR correctness remain unproved.

The envelope must independently compare ordinary and emit-relocs twins using
the unchanged `compare_load_images`, retaining load geometry/bytes, entry,
allocated sections and vector evidence. Twin equality is not root preservation.
The adapter's final input is the actual emit-relocs executable, not a rewritten
copy. Preserve the historical producer's original scope and receipt bytes.

## Complete Root Preservation

Require real ELF32 little-endian ARM ET_REL machine input without GIMPLE/fat
fallback, and the corresponding real ARM ET_EXEC output. Complete section,
symbol, mapping and relocation bounds must reject malformed or ambiguous input.
Bind raw instruction bytes to disassembly; do not trust mnemonic text alone.
Final function entries require executable-load coverage and Thumb-entry mapping.
Reject cross-name positive-extent STT_FUNC overlap in both machine and final.

The admitted root extents are 104 bytes for first-start, 184 for SVC and 204
for PendSV. The instruction total excludes literal data. Account for every
root byte/reference using complete bounds, mappings, literal islands, tail
layout and decoded address forms; no ignored relocation, extra instruction,
branch-to-padding acceptance or silently enlarged extent is allowed.

Use the original machine's unapplied REL fields as addend authority. Apart
from the exact relocation fields, each complete mapped root is byte-preserved.
Bind each root's unique machine section/offset/size to its final extent through
an explicit kept input-section placement in the actual GNU ld map. Map symbol
printouts, output symbol names or apparent instruction equality are insufficient.
Check placement size, containment, alignment and storage/permission consistency.

## Named Calls

The 11 root calls are R_ARM_THM_CALL BL references to the fixed names
`fiber_panic`, `fiber_port_context_validate_restore`,
`fiber_port_context_validate_save_current`, and
`fiber_port_scheduler_pick_next_from_pendsv`, at fixed root-relative relocation sites.
Decode each original addend as -4; require the final relocation and actual
decoded BL destination to resolve to the exact corresponding Thumb entry.

Independently bind each callee's machine definition and final address through
its provider, section, offset, extent and unique map placement. Coherently
changing a final symbol and branch must not defeat that placement authority.
This establishes call destination origin, not C-callee body correctness.
Record actual post-LTO bindings: E3's `fiber_panic` is global, not the source's
weak default. Do not assert that source weak/global ABI properties survived LTO.

## Section-Symbol Current Slot

Both root ABS32 references target the machine STT_SECTION symbol for
`.bss.fiber_runtime_current_context_slot`, with section-relative value 0 and
unapplied word/addend 0. The slot itself is a LOCAL OBJECT, four bytes at offset
0 in that dedicated four-byte SHT_NOBITS section. This local-data handling is
limited to this declared slot, not a relaxation of the ordinary reader.

The final residual ABS32 target is the output `.bss` section symbol. Both raw
STT_SECTION `st_name` values are empty strings; readelf displays the referred
section names, which differ here. Require raw empty names and the exact section
indices/placements, not name-string matching. Preserve the raw symbol dicts
without normalization, with separately labelled `OriginalTargetSection` and
`FinalTargetSection`. Do not manufacture a named-slot relocation or conflate
prettyprinted section labels with raw ELF symbol metadata.

Require the exact original provider/input-section placement to determine the
slot's final address, then bind the unique final local slot definition to that
same four-byte aligned NOBITS extent. Require final RAM load coverage with PF_W
set and PF_X clear, and no file-backed slot bytes. Reject overlap with any other
positive-extent STT_OBJECT in both machine and final.
Derive the output-section-relative displacement from those actual placements.
In E3, input offset 0 maps to output `.bss` offset `0x480`: `.bss` starts at
`0x20000000`, and the dedicated input section/slot is at `0x20000480`.
Those constants describe E3, not a substitute for map/provider authority.

For each literal, require final word = mapped input-section base + original
section-symbol offset + original addend. Also bind the residual output-section
symbol and its actual section-relative displacement to that same resolved
address, and verify the literal LDR's decoded address. An arbitrary address
elsewhere in valid BSS, a matching slot name or an output-section base alone
must not satisfy the reference.

## Evidence And Controls

Retain each complete root's machine/final hashes, instruction/mapping/literal
records, all 13 references, original/applied bytes, decoded addends/destinations,
and root/callee/slot provider-map origins. Keep machine and final relocation
symbol names, types, sections and values distinct. Root totals cannot replace
per-reference consumption or independently established placement evidence.

Negative controls must cover non-relocation byte drift, BL/addend corruption,
coherent callee retargeting, extra/missing references, nonzero original ABS32,
wrong output section/displacement, coherent retargeting into other valid BSS,
slot/provider/map extent or identity changes, ambiguous placements/symbols or overlaps,
function load/Thumb or slot PF_W/!PF_X violations, mapping/literal/branch-tail
changes and disassembly/raw-byte disagreement.
Controls use private copies and do not change retained E3 or production files.

Successful evidence is limited to these three machine-to-final roots.
Source/IR-to-machine semantics, full ABI obligations, policy equivalence,
reference/native equivalence, C/kernel correctness, complete-object proof,
exception routing, MMIO, CPU/board execution and archive/LTO generalization
remain false or unproved. Required-cell/global counters stay typed integer 0;
Global qualification stays false; no production or ordinary reader changes are authorized.
