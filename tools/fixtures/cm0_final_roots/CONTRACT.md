# Pinned CM0 Reference Final Roots

This gate consumes ordinary/emit-relocs final twins and their exact owning
objects from the separately qualified CM0 producer. It executes no target
image, emulator, compiler, linker or objdump. Producer source/pin/cohort/mode
authentication and the same five owning-object protocols remain caller
obligations, not inferred from a compatible ELF or a declared reference pin.

## Fixed Reader

```python
ReferenceCM0FinalImage(
    port_object, portasm_object, final_elf, disassembly,
    provider_objects=providers, link_map=link_map, mode="O2"
).function(root)
```

Exactly five roots and ordinary modes O0/Og/O2/Os/O3 are accepted. No caller
can provide an architecture, instruction or relocation allowlist. The shared
classic reader is loaded unchanged, with no patched globals. Its structural
ELF, load, symbol and bit-decoding checks are reused, not weakened for CM0.

| Root | Owner |
| --- | --- |
| `vStartFirstTask` | `portasm.c` |
| `SVC_Handler` | `portasm.c` |
| `vPortSVCHandler_C` | `port.c` |
| `vRestoreContextOfFirstTask` | `portasm.c` |
| `PendSV_Handler` | `portasm.c` |

The five direct provider objects are physically distinct. Explicit mappings
from original map identities to retained copies are supported. Owning root
definitions, called restore/scheduler entries and current-TCB storage must
match their original object, section, offset, extent and map placement.
Aliases, changed bindings/visibility and invented provider origins reject.
Current-TCB storage remains a four-byte aligned NOBITS object; executable
sections require executable file-backed load ownership.

## Complete Bytes And Pools

Fixed source-transcribed instructions, mode-dependent C dispatcher branches,
all Thumb-1 alias NOPs, original REL addends, applied calls, symbol values and
mapping boundaries are checked. The complete original and final owning
sections are bound, not only function bytes. Ordinary bytes cannot differ;
only the specified relocation fields may change.

Three pool-bearing roots contain five literal LDR instructions sharing
three external words. Both LDR addresses and registers are bit decoded.
Each complete four-byte word must occupy the exact separately mapped pool
beyond `st_size` in its owning section. Three ABS32 fields retain original
addend zero; the C-helper pointer must preserve its Thumb tag. The two BL
fields retain original addend minus four and exact map/provider-bound
restore/scheduler destinations. Final REL metadata must name those exact
definitions. Pool bytes are not absorbed into an enlarged function.

O0 has separate two-byte data alignment before its three pool words. Its
first-start section additionally contains one exact `46c0` Thumb NOP after
the function extent. Both forms remain explicit external padding, not root
instructions, discarded bytes or an unreachability proof. Root-contained
totals are 206 bytes/92 instructions for O0 and 164/71 for other modes;
whole owning-section totals are 226 and 176 bytes respectively.

Only fixed `BX r3` helper-dispatch sites and the specified `BX r2`/`BX r3`
stack-derived transfer sites are accepted. This is not generic indirect
branch admission and does not prove runtime stack values or EXC_RETURN.
The C helper's complete generated protocol is checked, not general C or
kernel semantics.

## Retained Witness

```text
python -B tools/fixtures/cm0_final_roots/reference_witness.py \
  --profile CM0|CM0PLUS|CM0PLUSVTOR --mode O0|Og|O2|Os|O3 \
  --port-object <port.o> --portasm-object <portasm.o> \
  --final-elf <emit-relocs.elf> --plain-elf <ordinary.elf> \
  --disassembly <emit-relocs.dis> --link-map <emit-relocs.map> \
  --provider-object <object> ... --output-dir <fresh-external-directory>
```

Supply exactly five providers, including both prelinks. Nine physical input
files are required: only the intended two prelink/provider overlaps are
allowed. Same-path twins, hard-link aliases, missing/extra providers and
output locations inside the repository, its ancestors or frozen input
memberships reject before snapshots or reader import. Existing protected
unrelated WIP is not an admissible input. The parser package is supplied by
the separately authenticated producer environment; a standalone invocation
does not authenticate an arbitrary Python installation.

The runner retains private byte copies and seventeen actual ELF mutant
classes per mode. O0 adds two classes for the out-of-function NOP and data
alignment. Mutations cover ordinary bytes, BL destination/addend/metadata,
ABS32 slot/helper value and Thumb tag, original pool addend, root extent,
external mapping, all three BX roles, literal targets, a coherent callee
symbol/BL swap, NOBITS overlap and RAM load writability. All are parsed,
never executed. Expected rejection stage and reason class are checked.
Equal-mutant twins alone are deliberately insufficient. Input/copy/mutant
hashes, sources and complete output membership are closed; seal failures
must not leave a successful result.

Pure reader controls use `test_reference_elf.py --output-dir <fresh-external>`.
Pure witness controls use `test_reference_witness.py --report <fresh-TEMP-json>`.
Their synthetic fixtures and metadata tests are not real build cells or
additional actual ELF mutations. Failed attempts remain historical.

## Limits

This is bounded reference final-root preservation with documented caller
obligations. Native/reference final mechanism composition is still a
separate gate. Constructor/C-callee/kernel semantics, runtime register and
memory effects, handler routing, dynamic exception targets, MPU/FP/security,
other cohorts, archives/final LTO, CPU/board and global freeze are not proved.
Global required-cell counters remain integer zero. Later interpretation or
documentation never upgrades a captured local receipt into hosted CI or a
hardware result.
