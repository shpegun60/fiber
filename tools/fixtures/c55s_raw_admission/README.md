# C55S Raw Source-Group Admission

Run from the repository with an explicit, unused evidence directory:

```powershell
python -B tools/fixtures/c55s_raw_admission/run.py --repo . --arm-gcc $ArmGcc --cmsis-core $CmsisCore --build $Evidence
```

The runner captures an inventory-checked immutable copy before compiling. It
uses the actual six C55S Non-secure sources, four common sources and standard
build-owned cohort-expectation TU. The unchanged shared native-ELF classifier,
exact import comparisons, active raw-hook probes and compiled negative controls
remain mandatory. O2/Os each cover ordinary objects and sectioned/unsectioned
slim-IR native LTO, with baseline and all six simultaneous raw hook families.
There are no instrumentation-disabling compiler counterflags or new allowlists.

All twelve positive cells must contain the eight actual forward definitions.
Each native common/whole group must retain the four-byte expectation object and
its single ABS32 relocation to the exact cohort defined by the actual port group.
The actual preprocessed manifest must still report RuntimeSelectable zero.

The maintained source mutant uses a compiler definition to rename only the
actual port TU's `fiber_port_runtime_schedule` identifier. Its original body and
attributes remain; the original operation is genuinely undefined in common
code. Both baseline and raw mutations compile and lower normally. Reversing
exactly the two repaired C55S exemptions in a captured copy of the actual shared
runner must reproduce twelve false PASS cells. The repaired runner must reject
the same twelve cells with exactly `Actual forward ABI functions missing`.
Their native port images must have exactly that one missing forward definition,
the renamed body present, and no independent classifier defects. Compiler or
linker errors, a different missing symbol, or a different rejection fail the test.
The historical runner bytes, exact two-hunk delta, commands, disassemblies,
captured inputs and complete artifact hashes are retained outside the repository.

This is compiler/source-group admission evidence only. It neither activates the
staged profile nor executes Secure gateways, exceptions or a board. It does not
qualify every policy tuple, optimization, external memory implementation or
callback closure. Transitional and the stopped CM33F Secure tree are not selected.
