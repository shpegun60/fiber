# C3FP Auxiliary Running Assembly Parity

This fixture compares the actual selected C3FP PendSV object with the actual
pinned `GCC/ARM_CM33_NTZ/non_secure/portasm.c` MPU+FP branch. It is not another
runtime profile, a constructor test, a linked whole-runtime proof, or CPU
execution. The C validators and scheduler/publication helpers are real compiled
code, not fixture substitutes, but their behavior is outside this assembly gate.

Run `tools/freertos_asm_parity.ps1 -Cm33fRunningOnly -Optimization -O2` and repeat
with `-Optimization -Os`; supply `-ArmGcc`, `-CmsisCore`, `-FreeRtosKernel`, and
`-BuildRoot` as needed. Each invocation covers hard/softfp and 8/16 MPU regions
with exact M33/FPv5-SP-D16 compiler flags. There is no package installation or
optional dependency skip: the Python oracle uses only the standard library.
The explicit fixture BASEPRI threshold is 128 on both sides (not a claim about
the port's default threshold); CMSIS implements four priority bits.
Use a fresh BuildRoot for each attempt; an existing C3FP-RUNNING directory is
rejected rather than leaving an old PASS beside a failed rerun. Focused-only
invocations retain their evidence even without an explicit BuildRoot.

`check.py` verifies little-endian ARM ET_REL objects and matches objdump bytes
against the ELF. Function sizes and ARM mapping symbols account for executable
bytes, pool data and padding. BL/literal targets come from actual ELF relocations;
changed relocation kinds/addends and unconsumed relocations are rejected. The
two complete PendSV instruction templates are closed. Register aliases, numeric
spellings, narrow/wide encoding suffixes, ldm/stm and push/pop aliases are canonicalized;
operands, flags-setting mnemonics, transfer counts, writeback, offsets, ordering,
conditions and local branch destinations are retained. No arbitrary instruction
filter removes differences. Only a final unreachable alignment NOP is optional.

The closed actual transfer subsequences are then symbolically interpreted, not
executed as CPU instructions. The independent numeric oracle checks words 0..19
and cursor 20 for basic saves, words 0..52 and cursor 53 for extended saves,
core-frame origin at raw PSP, low FP/FPSCR at PSP+32, original high FP before
low-copy scratch clobbers S16, exact inverse restoration, PSP/PSPLIM/CONTROL
order and cursor reset to word zero. All four outgoing/incoming form pairings
are checked with captured CONTROL values 1 and 5 independently of FTYPE. Restore
destinations start poisoned; basic restore must leave FP destinations and the
extended-frame reserved word untouched. An extended-to-basic reuse case preserves nonzero word 20 (S4)
and the untouched permanent word 53; stale basic-tail words are not zero guards.

`mutants.ps1` changes copied actual production/reference C inline assembly,
then compiles it with the same flags. Each of the four configurations kills 30
production and three reference mutants: offset, FP predicate, transfer counts,
writeback, same-count save/restore FP swaps, special-register source, both cursor
publications, CONTROL readback, validation call, scheduler/slot target and
relocation addends, unknown code and running SVC origin/frame/site selection.
Failures must be a sole expected diagnostic line, never a traceback substring.
Python `-O`, `-OO`, environment optimization and optimized compiled imports
are rejected explicitly; a RuntimeError counterfeit must not be admitted.
The mutant diagnostic predicate itself is challenged with a traceback, as is
an actual copied checker with SystemExit changed to RuntimeError.

Artifacts under `C3FP-RUNNING` include exact commands, preprocessed/assembler
sources, objects, relocations, attributes, disassembly, per-case results,
mutation diagnostics and before/after input hashes. Drift makes the attempt
INCOMPLETE and prevents a PASS artifact manifest. Source evolution while other
agents implement the port is not a qualified result. The actual SVC entry,
yield/return veneers and pinned SVC entry are also closed-template checked;
their C dispatch behavior is not. Full first-start, C validation, MPU replacement, archive/GC/LTO, scheduler and actual exception
execution retain separate proof obligations. The old constructor row is untouched.
