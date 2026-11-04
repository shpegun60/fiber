# Native Classic Cortex-M Final-Image Build Pilot

Exactly six no-MPU cohorts are admitted: CM0/VTOR0, CM0+/VTOR0 and
CM0+/VTOR1 (soft/no-FPU, p2/b0), CM3 (soft/no-FPU, p4/b16, VTOR1),
plus CM4 and CM7/r0p1 (hard/eager,
p4/b16, VTOR1). O0/Og/O2/Os/O3 use direct linkage. One invocation selects
one pair (default CM4/O2). Nine fresh actual translation units produce an ordinary ET_EXEC
and an `--emit-relocs` ET_EXEC from identical objects and linker script.
Both links use `--build-id=none`. Nothing executes either image.

```text
python -B tools/fixtures/classic_final_image/run.py --gcc <existing-arm-gcc> \
  --cmsis <existing-CMSIS-Core-Include> --inventory C:/fzin-20261104-e8 \
  --profile CM7 --mode Og \
  --output-dir <fresh-external-directory>
```

The retained inventory authorizes the exact cohort and source group; fresh
current source/header/tool bytes are captured and compilation uses the copied
project/CMSIS tree. No old compiled object is reused. The existing reviewed
profile-specific native protocols check the fresh ET_REL first-start/SVC/PendSV
bodies, including the exact O0-only tail NOP. No input protocol is generated
from the observed output. Startup uses the compiler's selected CPU/FPU flags.
Its copy loops are Thumb-1-safe. A build-owned predicate derived from the
target controls the VTOR write; VTOR0 images omit it completely. Final float
ABI is checked against the admitted cohort, not inferred from a function name.
Two explicitly retained unowned Thumb NOPs provide a deterministic invalid
callee destination for the coherent-symbol/BL negative control, independent
of incidental linker padding. They are fixture code, not a production change.
All nine original ET_REL objects, unapplied relocations, commands, dependencies,
disassembly, attributes and final twins are retained. Failed attempts remain.
Actual compilation emits separate `-MD -MF` dependencies which must equal the
precompile discovery paths and hashes. Object bytes are frozen before prelink
validation and rechecked immediately before/after each link and at closing.
Both links retain maps and source-bound callee section/offset/size records for
the independent final reader; these are not C-callee semantic proofs.

The typed application initializes static storage, registers its dispatcher,
then starts. Only its entry calls current/yield. It is not a board fixture.
Processor coverage is not an exact device-manifest claim: these images use
synthetic memory geometry, and M0+/VTOR1 does not qualify a G0 part's MPU.

`--profile` admits only CM0/CM0PLUS/CM0PLUSVTOR/CM3/CM4/CM7; `--mode` admits only
O0/Og/O2/Os/O3. Unsupported selection fails before output creation.
For a thirty-pair sweep, invoke the
builder and reader once for every Cartesian pair with fresh output directories;
do not promote a subset or a failed attempt to a complete sweep.

CM3-specific helper and attribute admission is described in
`../cm3_final_image/CONTRACT.md`. Its initial producer extension does not
claim the previously recorded final-root or reference-join qualification
for CM3; those require their own actual image evidence.

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
    --float-abi $receipt.CohortArtifact.target.float_abi `
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

Standalone actual-witness admission requires exactly nine provider objects
and thirteen distinct physical input files. Only the intentional prelink
object/provider overlap is permitted. Same-path twins, hard links and
cross-role/provider aliases reject before snapshots or reader construction;
comparing an emit-relocs ELF with itself is not an ordinary/emit twin proof.
Fourteen focused identity controls extend the pure suite to 176 tests.

Both the build and reader need installed `pyelftools` 0.33; the builder's
`--python-modules` directory must contain its `elftools` package. The builder
copies and hashes that package instead of installing or downloading it.
Set `PYTHONPATH` to the build's captured `python` directory for the reader
replay. Declared source/tool/package capture is not a claim of complete
host-OS or Python-standard-library closure. Failed attempts and negative
mutants remain separate retained evidence, not additional qualified cells.
