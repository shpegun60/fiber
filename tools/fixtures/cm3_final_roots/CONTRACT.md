# Pinned CM3 Reference Final Roots

This is a fixed, source-transcribed reader for the non-MPU GCC/ARM_CM3 port
at FreeRTOS commit `a50edad08b29052631aa469d4df6e6ec7ff68878`. It is not a
producer, installed tool, runnable kernel, native/reference equivalence gate,
or global software-freeze qualification.

## API

```python
image = ReferenceCM3FinalImage(
    prelink, final, disassembly,
    provider_objects={original_absolute_object_path: captured_object_path, ...},
    link_map=emit_relocs_map,
    mode="O2",  # exactly O0, Og, O2, Os, O3; literal str only
)
proof = image.function("prvPortStartFirstTask")
```

Exports: `ReferenceCM3FinalImage`, `ROOTS`, `PIN`, `core`, `native`, `Rejected`,
and `compare_load_images`. `native` aliases `core`; exception and twin-comparison
identities come from the immutable classic structural reader. `image.final`
exposes the fixed-symbol wrapper and `image.instructions` is the unchanged
structural reader's parsed disassembly index. No caller protocol, symbol list,
profile, ABI override or subclass scope extension is accepted.

Exactly four physically distinct provider files are required, represented by
four distinct absolute original-object identities. The map must place exactly
these four providers. All three roots must have one original port-object owner
whose complete file bytes equal `prelink`. `vTaskSwitchContext` and
`pxCurrentTCB` must have one other shared provider owner. Provider roles are
derived from definitions, not caller JSON or object filenames. The remaining
two objects are link-only consumer/startup providers, not simulated kernel code.
The outer receipt must independently establish the exact four-TU source set,
their source/config/compiler identities, dependency closure and map-producing
link command. This reader does not establish those facts from ELF bytes.

## Complete Fixed Bodies

Instruction rows transcribe pinned `portable/GCC/ARM_CM3/port.c`:
`vPortSVCHandler` at line 228, `prvPortStartFirstTask` at 247, and
`xPortPendSVHandler` at 455. The separate existing authority is
`tools/fixtures/cm3_freeze_parity/check.py`'s flat `_REFERENCE` model; the reader
does not import that model or learn expected hashes from compiler output.

All offsets below are decimal, relative to their owning function.

| Root | Binding | Base size | Instructions | Exact data mappings |
| --- | --- | ---: | ---: | --- |
| `prvPortStartFirstTask` | local | 32 | 10 | 26..28 padding; 28..32 VTOR word |
| `vPortSVCHandler` | global | 36 | 10 | 32..36 TCB word |
| `xPortPendSVHandler` | global | 68 | 19 | 62..64 padding; 64..68 TCB word |

O0 has exactly one in-function `00bf` post-pool NOP at each base size, with a
`$t` mapping at that point. Other modes have no post-pool instruction. Thus the
three complete bodies total 136 bytes/39 instructions, or O0 142/42. Each O0
owning input section also has one unchanged `00bf` alignment NOP outside
`st_size`; it is retained and verified, not counted as a root instruction.
Input section sizes are 32/36/68, or O0 36/40/72. Each starts with the named
root at offset zero in `.text.<root>`. The full map-placed input section is
bounded and byte-preserved except the explicit verified applied fields below.
Padding/pool mapping boundaries are not merged. Alternative mapping layouts,
NOP aliases and additional executable/data tails are rejected.

First-start reads MSP through the literal `0xE000ED08`, enables I/F, retains
DSB/ISB, SVC 0 and its source NOP. It does not clear CONTROL like the FP port.
SVC restores exactly r4-r11, writes PSP, clears BASEPRI and performs the exact
`orr lr,lr,#13` before BX LR. PendSV saves/restores the eight core registers,
preserves r3/LR around the scheduler call, sets BASEPRI 16 then clears it to 0.
There are no FP transfers, IT blocks or CM7 PRIMASK sequences in this contract.
`SoftwareFrameWords=8` records this instruction contract, not a runtime TCB or
whole-CPU correctness result.

## Relocations And Origin

| Root | Offset | Kind | Symbol | Original addend |
| --- | ---: | --- | --- | ---: |
| SVC | 32 | R_ARM_ABS32 (2) | `pxCurrentTCB` | 0 |
| PendSV | 28 | R_ARM_THM_CALL (10) | `vTaskSwitchContext` | -4 |
| PendSV | 64 | R_ARM_ABS32 (2) | `pxCurrentTCB` | 0 |

No other root relocation is admitted. Unapplied prelink bytes provide original
REL addends. Applied final metadata must preserve kind and symbol identity;
the decoded final BL must name the exact map/provider-bound Thumb entry.
Literal words must equal the independently placed current-TCB symbol address.
The slot is an aligned four-byte writable NOBITS object originally defined in
`.bss.pxCurrentTCB`. Its provider and callee must be strong global definitions;
only the first-start root may, and must, be local. Interior targets, symbol
aliases, duplicate definitions, wrong placement/extent and veneers reject.
Callee origin is checked, not the C callee's body or relocation semantics.

The final reader never fabricates ET_REL bytes or zeros applied fields. Raw
root/section hashes and applied-reference evidence remain distinct. GNU ld
[`--emit-relocs`](https://sourceware.org/binutils/docs/ld/Options.html#index-_002d_002demit_002drelocs)
retains relocation metadata; original REL addends require separate authority
under [AAELF32 idempotency](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#562-idempotency).

## Shared Machinery And Limits

`classic_final_image/elf.py` supplies unchanged ELF32 little-endian ARM
ET_REL/ET_EXEC parsing, section/load geometry, PF_W/NOBITS guards, full bounded
mapping walks, independent BL/LDR/BX address decoding and GNU ld input-section
origin checks. `classic_final_image/reference_elf.py` supplies only the fixed
symbol wrapper for the same three reference names/callee/slot. No module global,
FP type map or decoder allowlist is patched. Dependency: captured pyelftools
0.33, as in the existing producer. Soft ABI uses the existing prelink/final
flag obligation: original float bits zero or soft-only; final flags exactly
original flags OR `0x200`. Other codegen attributes are an outer admission gate.

Call `compare_load_images(ordinary, emit)` separately: it verifies load layouts,
entry/vector bytes, allocated sections and loader-visible bytes. Constructing
this reader with only the emitted twin does not establish twin identity.

All returned roots keep `SourcePinBindingVerified`, `CohortBindingVerified`,
`ModeBindingVerified`, `RequiredCellSatisfied`, `FinalParity`,
`KernelRuntimeProof`, `CPUProof` and `GlobalProof` false. Identical non-O0 bytes
cannot distinguish Og/O2/Os/O3; the authenticated producer command supplies mode.
Complete roots do not prove first-task execution, vector routing, scheduler
semantics, a real TCB, stack safety, hardware policy, LTO or archive extraction.

## Synthetic Controls

The new test file independently spells out CM3 instruction rows in objdump
halfword notation. It reuses only existing synthetic ELF serialization helpers,
not reader protocol data. All files are fake temporary inputs. Controls cover
all five modes, local/global bindings, eight-word frames, ORR LR, BASEPRI,
barriers, separate padding/pools, original and applied relocations, owner/map
binding, aliases, ABI rejection, O0 instruction/section tails, unknown scopes,
and same-both-twins geometry/PF_W negatives. These are not actual ELF mutations.

For an authorized parent-run pure check, with an existing captured pyelftools
provider on `PYTHONPATH`:

```text
<PYTHON313> -B tools/fixtures/cm3_final_roots/test_reference_elf.py --output-dir <FRESH_EXTERNAL_DIRECTORY>
```

The output is a source-hash-bound synthetic receipt with closing source drift
checks and no actual-witness or CPU claim. Source implementation alone is not
execution evidence. Actual provider/final validation requires its own retained
receipt; synthetic files must never be counted as actual compiler outputs.

## Retained Actual Witness

`reference_witness.py` consumes five distinct input roles and four ordered
providers, with the actual port prelink first and only that intended overlap.
Regular-file, reparse, physical-alias and output-membership admission precede
any output write. The output must be fresh and outside the repository and all
frozen input directories. Captures preserve the eight distinct original files.

The standalone witness executes the closed local reader/mutator helper graph
from immutable, hashed source buffers. Nested legacy file-spec imports use the
same buffer loader and cannot load unknown local sources or bytecode caches.
The expected protocol/model globals are not patched. Executed source-buffer
identities are recorded. The enclosing gate still owns interpreter/package,
producer pin/cohort/recipe and prelink-protocol authentication.

It separately compares original load-image twins and reads all three roots.
Thirteen actual mutation classes reuse the unchanged classic mutation recipes
for these same root/slot/callee names. Eleven preserve equal mutated twins
before exact root rejection; two corrupt twin load/storage geometry. Every
mutation must make a real bounded edit and reject at its exact stage/reason.
All five files per mutant and all original/captured inputs are hash-checked at
closing. These actual byte mutations remain distinct from synthetic controls.

```text
<PYTHON313> -B tools/fixtures/cm3_final_roots/reference_witness.py \
  --prelink-object <actual-port-object> --final-elf <emit-relocs-image> \
  --plain-elf <ordinary-image> --disassembly <emit-relocs-disassembly> \
  --link-map <emit-relocs-map> \
  --provider-object <actual-port-object> --provider-object <providers-object> \
  --provider-object <consumer-object> --provider-object <startup-object> \
  --mode O2 --output-dir <FRESH_EXTERNAL_DIRECTORY>
```

Use the producer's captured pyelftools package on `PYTHONPATH`. Pure witness
controls have a separate `test_reference_witness.py --report <FRESH_TEMP_JSON>`
entry. They cover admission and loader behavior, including A-to-B-to-A source
replacement, nested imports and CLI alias rejection without writes; they do
not invoke a compiler or claim actual ELF mutation coverage. Actual measured
results and independent replay receipts belong in `PORT_ARCHITECTURE_AUDIT.md`.
