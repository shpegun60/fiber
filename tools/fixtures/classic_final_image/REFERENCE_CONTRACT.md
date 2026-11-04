# Pinned CM4 Reference Final-Image Pilot

This is an opt-in link-only companion to the native pilot. It builds the
actual `portable/GCC/ARM_CM4F/port.c` from the locally pinned FreeRTOS
`a50edad08b29052631aa469d4df6e6ec7ff68878`. It compiles an unchanged,
hash-checked captured copy, without reimplementing or modifying the upstream
port. Exactly the CM4 hard-FP, VTOR1, no-MPU, p4/b16,
ordinary-AAPCS target and O2 direct linkage are admitted initially.

The native inventory's eager cohort identifies the target/ABI, not an
upstream FP policy claim. The reference retains its upstream ASPEN+LSPEN
lazy setup. The recorded eager/lazy difference is not erased or declared
equivalent by this final-image witness.

## Build And Ownership

Four fresh translation units are required: the pinned port, typed boundary
providers, typed consumer and fixture startup. Both ordinary and
`--emit-relocs` links consume exactly the same frozen objects, target flags
and script, with `--build-id=none`. Direct input-section placements are
retained in the emitted map. Source/tool/dependency hashes, original REL
addends, commands, terminal outcomes and object checkpoints are retained.
Actual compiler dependencies must match precompile discovery. No archive,
LTO or additional optimization is implicitly admitted.

The providers define `pxCurrentTCB`, `vTaskSwitchContext` and
`xTaskIncrementTick` with their real upstream C types. The current TCB is
NULL. Scheduler/tick/assert calls enter explicit fail-stop boundaries.
No actual TCB, stack, ready list or scheduler model is invented. Fixture
reset cannot start the reference scheduler. No target instruction runs.
Vectors retain the actual SVC, PendSV and SysTick symbols; this only proves
link-time placement, not active VTOR, exception execution or board routing.

Two explicitly kept unowned Thumb NOPs outside function extents provide
the coherent-callee-retarget negative control. They are deliberately not
a valid function origin. The synthetic memory map and all fixture code
are test artifacts, not production integration changes.

## Fixed Reader Surface

`ReferenceCM4FinalImage` is separate from the native reader. No caller can
provide a different root/callee/slot allowlist. Exactly these complete
prelink roots are admitted:

| Root | Binding | Bytes | Original References |
| --- | --- | ---: | --- |
| `prvPortStartFirstTask` | local | 40 | none |
| `vPortSVCHandler` | global | 32 | `pxCurrentTCB` ABS32+0 |
| `xPortPendSVHandler` | global | 92 | `vTaskSwitchContext` BL-4 and `pxCurrentTCB` ABS32+0 |

The independent reviewed prelink protocol is checked before final-image
replay. The final reader retains all code, literal islands, alignment
padding, local branches, mapping symbols and extents. Only the exact
observed IT-EQ/high-FP-save/restore forms are added, with raw bytes and
operands bound. The local first root is not permission for other local,
weak, ambiguous or caller-selected definitions.

The first root has two exact adjacent data mappings: padding `[34,36)`
and literal pool `[36,40)`. Both prelink and final must retain them.
Conflating or shifting their boundary rejects, even when bytes still match.
`DataMappings` records both; the logical literal island remains `[34,40)`.

Original REL addends come only from ET_REL bytes. Applied ET_EXEC fields
are decoded without fabricating an ET_REL view of final bytes. Function
and current-TCB entry origins bind actual provider symbols/sections/offsets
to independently retained input-section map placements. Final symbol-table
self-consistency alone is insufficient. ELF32LE ARM, load/section ownership,
permissions, NOBITS boundaries and complete twin load equality remain strict.

## Replay And Negative Controls

`reference_witness.py` consumes existing objects/final ELFs/disassembly/map.
It executes no tool. Each input is copied and hashed before use; exact
original provider path identities remain map keys. It replays all three
positive roots. The five witness roles and four providers must represent
eight distinct physical files, with only the intentional prelink/provider
overlap. Same-path twins, cross-role aliases and hard links reject before
capture; pure input-identity controls exercise those cases. The witness
then retains thirteen actual bounded mutation classes:

- ordinary instruction byte change;
- applied BL destination plus two;
- applied current-TCB ABS32 plus four;
- applied REL kind and symbol substitutions;
- original BL and ABS32 addend changes;
- local first-root binding changed to global;
- root extent and data-mapping boundary changes;
- coherent callee symbol plus BL retarget to unowned Thumb NOP padding;
- NOBITS current-TCB storage overlapping file-backed text;
- writable current-TCB owner without writable load permission.

Each control requires a real changed field, the intended rejection stage
and matching rejection reason. Failure to construct a control is FAIL,
not a successful rejection. Eleven controls must preserve identical twin
load images; the two structural storage controls reject at twin validation.
Closing source/input/captured-input/mutant hashes must not drift.

## Non-Claims

This is reference prelink-bound final-root preservation and entry-origin
evidence. It is not native/reference semantic equivalence, C-callee/internal
relocation or constructor closure, successful MMIO, actual scheduler/TCB
semantics, archive/LTO coverage, CPU/board execution or global qualification.
It satisfies zero required global parity cells on its own. Existing native
pilot admission and tests are not replaced by the reference companion.

## Commands

The build uses the installed/captured pyelftools 0.33 package, like the
native pilot. Output directories must be fresh and external to the repo.

```text
python -B tools/fixtures/classic_final_image/reference_run.py \
  --gcc <existing-arm-gcc-14.3.1> --git <existing-git> \
  --freertos <clean-pinned-local-FreeRTOS> \
  --inventory <retained-source-inventory> --output-dir <fresh-build>
```

With an existing successful build, in PowerShell:

```powershell
$b = '<successful-build>'
$receipt = Get-Content "$b/results.json" -Raw | ConvertFrom-Json
$providerArgs = @()
foreach ($row in $receipt.Sources) {
    $providerArgs += '--provider-object'
    $providerArgs += $row.Object
}
$env:PYTHONPATH = "$b/python"
python -B tools/fixtures/classic_final_image/reference_witness.py `
    --prelink-object "$b/objects/00-port.o" `
    --final-elf "$b/emit-relocs.elf" --plain-elf "$b/ordinary.elf" `
    --disassembly "$b/emit-relocs.dis" --link-map "$b/emit-relocs.map" `
    @providerArgs --output-dir '<fresh-reader-output>'
```

Separate pure suites are `test_reference_run.py --report <fresh-TEMP-json>`
(28 controls), `test_reference_elf.py --output-dir <fresh-directory>`
(75 controls), and `test_reference_witness.py --report <fresh-json>`
(11 input-identity controls). They execute no native tool or target image.
