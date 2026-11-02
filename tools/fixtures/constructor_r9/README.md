# Constructor R9 Audit

`tools/test_constructor_r9.ps1` builds the real public `fiber_init`, common
state/configuration sources and exact existing selected-port source groups.
It executes constructor instructions and bounded linked SVC/PendSV GPR restore
slices, not exception entry/return, FP, TrustZone or TF-M.
M23/M33/M55 instruction effects use Unicorn's supported M0/M4 instruction
subsets. The ELF is compiled for the actual requested core and its attributes
are checked; this does not turn Unicorn into those hardware models.

## Contract

The normative decision is `DECISIONS.md:1576-1588`, also the CM3 MPU leaf's
initial-R9/static-base paragraph. There are two deliberately separate probes:

- Ordinary AAPCS: no fixed-R9 option. An assembly wrapper seeds R9 immediately
  before the actual public API. The caller's R9 must survive the call, but a
  different initial frame value is `BORROWED-R9`, an observation rather than an
  ABI defect. The initial frame must be valid and both first/running restore
  slices must restore their frame's R9. R9 has no process-static-base meaning
  in this configuration.
- Reserved R9: all C objects and final LTO links explicitly use `-ffixed-r9`,
  matching the documented platform-register proof. The initial frame must
  preserve the static-base seed exactly, as must the caller return and first
  restored R9. Running restoration must preserve its saved-image R9. This is
  intentional ABI reservation, not masking the ordinary probe or qualifying
  every PIC/TLS static-base implementation.

The independent numeric oracle checks frame location, all other initial words,
and boot geometry. No emulator hook repairs R9, bypasses a real constructor,
supplies a frame, or skips the compiled memory/address-policy functions.
Ordinary address hooks legally borrow R9 across their own nested calls and
restore it; reserved hooks never borrow it. Source/ELF symbol provenance and
public/port/builder entry traces distinguish borrowing from caller corruption.
An inlined builder need not retain a separate ELF symbol.

The restore probes execute only the actual linked GPR load/move instructions,
with independently calculated frame pointers. First restore uses the actual
constructor frame. Running restore uses a distinct saved-image R9; it is not
a full save/exception-switch proof. No CPU state/SG/FP instructions are bypassed
and then represented as executed: the bounded slice is the declared limit.

## Coverage And Controls

The twelve profiles are CM23NTZ, CM33NTZ, CM33TFM, CM33FNTZ, CM55NTZ,
CM55FNTZ, CM55MVEFNTZ, scalar companion-aware CM33S and classic CM0/3/4/7.
Dedicated FP profiles cover hard and softfp; classic M4/M7 also cover soft.
Each target variant covers O2/Os, normal/LTO and ordinary/hostile flags in both
register contracts. Four distinct seeds are executed per ELF.

Each target variant also compiles five controls: an ordinary wrong-frame
assignment, an AAPCS-conforming public caller that borrows R9, and a reserved
wrong-frame assignment, plus corrupted first and running R9 restores. Exact classifications and caller preservation are
required. Ordinary controls prove the observer, not an invented static-base
contract. The reserved wrong-frame control must produce `STATIC-BASE-R9`.
The two compiled restore controls must produce `FIRST-RESTORE-R9` and
`SWITCH-RESTORE-R9`, respectively, without converting them into frame-only errors.
An actual compiled UDF probe per ELF verifies that emulator faults are not
classified as R9 results. Unmapped/MMIO/unsupported instructions fail as
qualification/infrastructure errors, never as proof of an R9 defect.

Hostile flags remain enabled on actual sources and a deliberately unannotated
probe. Its instrumentation/coverage counters must execute. Boundary stubs are
not hostile-compiled; memory helpers are loop-explicit scalar assembly, with
no branch-count exclusion or fixed-R9 option in the ordinary configuration.
Unexecuted Secure/TF-M link boundaries trap if reached. No Secure initialization
or running-fiber success is synthesized. Selected sources/providers are real;
the fixture does not replace the public API, constructor or frame builder.

Python optimization and dependency guards run on direct/import/extraction
paths, with exact single-line diagnostics. A counterfeit traceback is rejected.
Classifier controls separately check ordinary borrowing, reserved corruption,
caller corruption, panic and the positive path. All checks are unconditional.

## Setup And CI

Only the audit suite needs Python dependencies; ordinary API users do not.
No package is installed automatically and missing/wrong packages fail.

```powershell
$modules = Join-Path $env:TEMP 'fiber-constructor-r9-python'
python -m pip install --target $modules -r tools/fixtures/constructor_r9/requirements.txt
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_constructor_r9.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC -CmsisCore $env:CMSIS_CORE_INCLUDE
```

The runner discovers that temporary modules directory, then the existing
`%TEMP%/fiber-classic-audit-python`, or the selected interpreter's default
modules. `-Python`, `-PythonModules` / `FIBER_CONSTRUCTOR_R9_PYTHONPATH` select
another audit environment; `-BuildRoot` selects a parent for unique evidence.
`-ImmutableInputs` first byte-copies the exact selected source/fixture/CMSIS
inventory, verifies every copy against its original hash, and runs the complete
suite from that isolated tree. `immutable-inputs/manifest.json` and
`child-command.json` retain the original-to-copy mapping and exact invocation.
Production work outside that snapshot can continue without invalidating it.
`-DevelopmentProfiles CM33NTZ,CM55NTZ` and `-DevelopmentModes O2-lto` are marked
`CompleteSuite=false` and cannot be reported as full-suite qualification.

`results.json` separates ordinary observations from actual reserved/caller ABI
failures. It records Python/tool commands, exact C/ABI/mode source groups,
ELF hashes, execution traces, controls and before/after consumed-source hashes.
Linked data/BSS is confined below the fixture context/argument/stack regions;
every ELF load segment is independently checked against that separation.
Input drift, compiler/link failures, unexpected traps and ABI failures throw;
configuration failures are collected across the extent, never silently skipped
or converted to an ABI pass. Any unqualified configuration makes the final FAIL.
the PowerShell runner prints final PASS only on successful completion. No full
matrix, production source edits, hardware or actual Secure-image claim is made.

Historical receipts remain untouched. In particular, temporary evidence root
`fiber-constructor-r9-4778c794c8e3492bb5d0c112c8dc071c` used an overstrong
ordinary-frame oracle: those frame-only FAILs are not reserved-ABI defects.
The maintained report explicitly records this superseded-oracle distinction.

## Infrastructure And Assembly Findings

The preserved full extent at `fiber-constructor-r9-fec4e1435a99482aa62c3c68ec0d2bcb`
had 61 unqualified configurations/controls: 48 literal-pool errors, four
Thumb1 operand errors, and nine strict-warning-policy failures. The final LTO
link now explicitly retains `-ffunction-sections -fdata-sections`, matching the
compile commands; no source extraction, handler rewrite or LTO fallback is used.
This qualifies sectioned LTO only: it does not establish that those historical
pool errors were harness-only, or qualify unsectioned production assembly.
The known no-VTOR diagnostic and the exact CM0 exception-file vector-index
warning are source-scoped and recorded as non-R9 diagnostics. All other
warnings remain failures; this is not a warning-free vector-runtime claim.

`m0_initial_msp_probe.c` separately qualifies the actual initial-MSP helper's
assembly with R0 and ABI-conforming, preserved R8 result registers, under
O2/Os and both R9 contracts. It does not borrow reserved R9. The emitted
actual-header instruction and assembler result distinguish a Thumb1 operand
constraint defect from the public constructor ABI test. All eight actual-header
probes must now assemble. Two additional O2 controls, one per R9 ABI, restore
the original general-register constraints in the actual preprocessed header;
each must emit the exact invalid R8 LDR and single low-register assembler error.
Only those explicitly mutated controls accept assembly rejection. A production
probe or configuration failure still fails the default runner.
