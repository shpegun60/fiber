# Native CM4 Final-Image Build Pilot

Exactly one hard/eager, p4/b16, VTOR1, no-MPU CM4 cohort at O2 with direct
linkage. Nine fresh actual translation units produce an ordinary ET_EXEC
and an `--emit-relocs` ET_EXEC from identical objects and linker script.
Both links use `--build-id=none`. Nothing executes either image.

```text
python -B tools/fixtures/classic_final_image/run.py --gcc <existing-arm-gcc> \
  --cmsis <existing-CMSIS-Core-Include> --inventory C:/fzin-20261104-e8 \
  --output-dir <fresh-external-directory>
```

The retained inventory authorizes the exact cohort and source group; fresh
current source/header/tool bytes are captured and compilation uses the copied
project/CMSIS tree. No old compiled object is reused. The existing reviewed
CM4 native protocols check the fresh ET_REL first-start/SVC/PendSV bodies.
All nine original ET_REL objects, unapplied relocations, commands, dependencies,
disassembly, attributes and final twins are retained. Failed attempts remain.
Actual compilation emits separate `-MD -MF` dependencies which must equal the
precompile discovery paths and hashes. Object bytes are frozen before prelink
validation and rechecked immediately before/after each link and at closing.
Both links retain maps and source-bound callee section/offset/size records for
the independent final reader; these are not C-callee semantic proofs.

The typed application initializes static storage, registers its dispatcher,
then starts. Only its entry calls current/yield. It is not a board fixture.

`Pilot.command(argv, label, timeout=60)` records the attempt before invoking
the captured managed process runner, returns its byte Result, and records
terminal failure/timeout information in finally. `scope_report()` provides
the conservative report schema; importing this module performs no I/O.

Build PASS requires zero closing input drift plus identical entry, allocated
sections and PT_LOAD geometry/bytes. It is not final-root relocation proof:
the independent strict reader must bind final bytes to the original REL
addends and reviewed protocols. This pilot builds no reference, archive or
LTO cell. Required coverage stays zero; policy, whole-object, final-root,
CPU/board and global qualification flags remain false. See CONTRACT.md.

## Separate Reader Controls

`test_run.py --report <fresh-TEMP-json>` runs pure command, dependency,
object-checkpoint, admission and scope controls without executing a tool.
`test_elf.py --output-dir <fresh-directory>` runs synthetic ELF controls.
The managed process runner's own tests live under `freeze_cohorts`.

The optional actual-witness mode additionally requires all four witness
paths, every original provider object, and the emitted-relocations linker
map. For example, in PowerShell with an existing successful build:

```powershell
$build = 'C:/fresh-successful-cm4-build'
$providerArgs = @()
$receipt = Get-Content "$build/results.json" -Raw | ConvertFrom-Json
foreach ($row in $receipt.Sources) {
    $providerArgs += '--provider-object'
    $providerArgs += $row.Object
}
python -B tools/fixtures/classic_final_image/test_elf.py `
    --prelink-object "$build/objects/03-fiber_port.o" `
    --final-elf "$build/emit-relocs.elf" `
    --disassembly "$build/emit-relocs.dis" `
    --plain-elf "$build/ordinary.elf" `
    --link-map "$build/emit-relocs.map" @providerArgs `
    --output-dir '<fresh-external-reader-output>'
```

The reader binds roots, callees and the current slot to actual input symbols
and separately retained input-section placements in the linker map. It
verifies original addends and applied root relocation fields, independently
decodes admitted branch/literal address forms, and retains complete root
bytes. Unsupported forms fail closed. C-callee bodies and their internal
relocation semantics remain outside this three-root proof.

Both the build and reader need installed `pyelftools` 0.33; the builder's
`--python-modules` directory must contain its `elftools` package. The builder
copies and hashes that package instead of installing or downloading it.
Set `PYTHONPATH` to the build's captured `python` directory for the reader
replay. Declared source/tool/package capture is not a claim of complete
host-OS or Python-standard-library closure. Failed attempts and negative
mutants remain separate retained evidence, not additional qualified cells.
