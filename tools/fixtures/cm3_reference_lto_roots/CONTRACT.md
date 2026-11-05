# Pinned Reference CM3 LTO Machine-To-Final Roots

## Fixed Scope

This standalone reference adapter admits only pinned FreeRTOS CM3 O2-lto direct
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`: Cortex-M3/ARMv7-M,
Thumb, ordinary AAPCS, soft ABI, no FPU/MPU/TrustZone, VTOR1, priority bits 4 and
raw BASEPRI threshold 16. Pin: `a50edad08b29052631aa469d4df6e6ec7ff68878`.
It does not generalize native LTO admission or modify an ordinary reader.

Initial machine authority is the retained reference E3 capture at
`C:/fz-cm3-reference-lto-transport-20261105-e3/emit-relocs/`:
`image.elf.ltrans0.ltrans.o`, `image.elf`, `image.elf.dis` and `image.map`.
Capture/build PASS is not root qualification. This contract does not report
that an adapter, test suite, outer envelope or actual replay has passed.

## Reader And Provider Boundary

```python
ReferenceCM3LTOImage(core, machine, final, disassembly,
                     *, provider_objects, link_map)
```

Use authenticated frozen `classic_final_image/elf.py` only for its existing
ELF construction, address decoding and bounded utilities. Do not mutate core
globals, symbol policies, allowlists or ordinary behavior, and do not weaken
native adapter predicates. No caller-selected modes, roots or target sets.

`provider_objects` binds original absolute linker-map object identities to
captured byte files. The actual machine providers are the saved LTRANS object
and unchanged startup object, not the three slim-IR inputs. A copied basename,
map symbol printout or same-named final symbol is not provider identity.
No ELF rebasing/rewriting, ET_EXEC-to-ET_REL conversion, reassembled saved `.s`,
ordinary-object substitute or guessed machine owner is permitted.

## Exact E3 Roots And Placement

Require actual ELF32 little-endian ARM ET_REL machine and ARM ET_EXEC final
inputs, complete section/symbol/relocation bounds and no GIMPLE/fat fallback.
The machine's whole `.text` section is `0x24C` bytes and its kept map placement
starts at final `0x434`. Independently bind the unique provider, input section,
size, offset and containing output section; these numbers alone are not origin.

| Root | Raw machine value | Offset | Size | Binding | Mapped final start |
|---|---:|---:|---:|---|---:|
| `prvPortStartFirstTask` | `0x79` | `0x78` | 32 | LOCAL | `0x4AC` |
| `vPortSVCHandler` | `0x55` | `0x54` | 36 | GLOBAL | `0x488` |
| `xPortPendSVHandler` | `0x99` | `0x98` | 68 | GLOBAL | `0x4CC` |

Require these exact STT_FUNC bindings/extents, retain raw Thumb-valued metadata
and separately label normalized addresses. First-start is local and need not
have a named map entry: whole-section placement plus its offset is authority.
All three declared extents total 136 bytes including pools/padding, not 136
instruction bytes. Do not enlarge a function or substitute original TU sections.

Require executable final load coverage and Thumb entry mapping. Reject ambiguous
definitions, duplicate placements and cross-name positive-extent STT_FUNC overlap
in machine and final. Capture complete machine/final section bytes and bind
raw instructions to disassembly; mnemonic text alone is insufficient.
Preserve each complete root except its exact admitted relocation fields.
Retaining the surrounding merged section is not complete-object semantic proof.

## Full Pool And Mapping Consumption

Preserve mapping symbols and every byte, including adjacent data boundaries:

- SVC: `$d` at machine `0x74`, covering its four-byte relocated pool word.
- First-start: separate `$d` boundaries at `0x92` and `0x94`, retaining the
  two-byte alignment span and following four-byte unrelocated pool word.
- PendSV: separate `$d` boundaries at `0xD6` and `0xD8`, retaining the
  two-byte alignment span and following four-byte relocated pool word.

Translate all boundaries through proven placement; do not flatten adjacent data
descriptors, discard alignment/tails, treat pools as instructions or infer CFG
unreachability. Decode literal LDR addressing from actual bits and bind each
instruction to its exact pool location and resolved word. No unconsumed bytes,
extra references, branch-to-data/tail acceptance or permissive indirect-branch
rule may be introduced. First-start's unrelocated bytes are preserved, not
semantically qualified by this adapter.

## Three Applied References

Exactly three root references are admitted; all other machine relocations remain
outside this three-root proof. Require original machine REL fields, residual
final relocation metadata and decoded applied values to agree independently.

| Machine `.text` place | Root-relative place | Kind | Named target | Required original addend |
|---:|---:|---|---|---:|
| `0x74` | SVC `0x20` | `R_ARM_ABS32` | `pxCurrentTCB` | 0 |
| `0xB4` | PendSV `0x1C` | `R_ARM_THM_CALL` | `vTaskSwitchContext` | -4 |
| `0xD8` | PendSV `0x40` | `R_ARM_ABS32` | `pxCurrentTCB` | 0 |

Read and decode those addends from unapplied machine bytes; readelf target values
are not addends. ABS32 must retain the named object target in both stages, not
silently accept native section-symbol handling. Bind each final word to the
independently mapped slot plus addend zero and each LDR to that exact word.

`pxCurrentTCB` is GLOBAL STT_OBJECT, four bytes at machine `.bss+8` within a
12-byte NOBITS section. That input `.bss` maps to `0x20000008`, yielding slot
`0x20000010`, not the output section base. Independently bind its provider and
offset/extent to the matching final GLOBAL object. Require aligned NOBITS,
zero-fill RAM coverage, PF_W set, PF_X clear and no file-backed slot bytes.
Reject overlapping positive-extent STT_OBJECTs in both stages or retargeting to
another valid BSS address. Preserve actual names/bindings instead of aliases.

The sole root BL targets GLOBAL STT_FUNC `vTaskSwitchContext`, raw machine value
`0xE9`, size 12, offset `0xE8`, mapped final start `0x51C`. Independently verify
original THM_CALL addend -4, actual BL encoding and final decoded destination
against its unique provider/section/offset/extent placement. Keep odd Thumb
symbol values separate from normalized addresses. Coherently editing a final
symbol and branch must not bypass map origin. This proves destination origin,
not the callee's fail-stop/C/kernel semantics or source global ABI preservation.

## Outer Authentication And Actual Controls

The separate enclosing gate authenticates caller-bound producer receipts,
complete input/artifact membership/hashes, pin/blob/configuration bindings,
three-C-plus-startup recipe, tools/workers and same-buffer helper/parser loads
before qualification. It binds the actual machine, final, map, disassembly and
provider identities, then closes all source/tool/evidence bytes and memberships.
The reader alone supplies none of that producer/source authority.

The envelope independently compares genuine ordinary/emit-relocs twins using
unchanged `compare_load_images`, retaining PT_LOAD geometry/bytes, entry,
allocated sections and vector evidence. It retains all real mutant files,
expected rejection reasons, source hashes and closing seals. Positive capture
or synthetic-only controls cannot replace actual ELF mutation qualification.

Actual controls must cover root byte/bounds/binding drift; mapping/pool/padding
changes; missing/extra/wrong-site relocations; wrong ABS32/BL addends; decoded
LDR/BL disagreement; coherent callee/slot retargeting; provider/map ambiguity;
symbol overlap; function load/Thumb and slot storage/permission violations.
Mutate private copies only; retain failed attempts and never rewrite E3 evidence.

## Nonclaims

Canonical protocol validation is a separate checker obligation and remains
`CanonicalProtocolValidated=False` here. Coherent changes to both machine and
final may preserve transport while changing semantics; no general instruction-
constant, source/IR-to-machine, per-TU origin, API/full ABI, policy, C/kernel,
native/reference join, complete-object, CPU/board or global proof follows.
Required-cell/global credit remains typed integer zero; global qualification
and those stronger proof flags remain false. No archive/other-mode coverage,
production change, ordinary-reader change or default-matrix credit is granted.
