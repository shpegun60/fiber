# C55S Private Pool Regression

`tools/test_m55_secure_pool.ps1` compiles the actual private C55S pool source
for Cortex-M55 and executes the resulting Thumb instructions with Unicorn's
Cortex-M33 scalar model. The fixture supplies no allocator implementation,
CPU-register stubs, CMSIS headers, NSC gateway, or runtime library.

## Run

Reuse the audit-only pinned packages, Python 3.10 or newer, and ARM GCC:

```powershell
$modules = Join-Path $env:TEMP 'fiber-classic-audit-python'
python -m pip install --target $modules -r tools/fixtures/classic_audit/requirements.txt
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_m55_secure_pool.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC
```

The script also accepts `-Python`, `-PythonModules`, `-FreeRtosRoot`, and
`-BuildRoot`. It discovers the same temporary package directory and environment
variable (`FIBER_CLASSIC_AUDIT_PYTHONPATH`) as the classic regression. Missing or
incorrect dependencies fail; nothing is downloaded, installed, or skipped by
the test. No CMSIS dependency is required by this CPU-neutral private API.

## Coverage

- Three compile-selected geometries: count/stack capacity 1/8, 3/128, 5/256.
- `-O2` and `-Os`, each normal and LTO, with strict aliasing and warnings as errors.
  Every cohort has an untouched M55 baseline ELF and an executable companion
  with `-fno-branch-count-reg`. Unicorn cannot execute M55 `DLS`/`LE` instructions;
  disabling only counted-loop conversion avoids substituting instruction stubs.
  ELF geometry, linkage, and dependency checks also cover the untouched baseline.
- Actual C implementation linked to C++17 callers of all three private APIs.
- Exact single-image `N * (24 + S + 8)` NOLOAD ELF reservation and one four-byte
  ordinary BSS state, no initialized data or unintended NSC entries.
- Poisoned retained storage with only BSS initialized by the harness; successful
  initialization clears the complete image and publishes READY last.
  Previously allocated valid retained contents are also reset after fresh BSS.
- Actual instruction hooks stop initialization immediately after its one-way
  gate and midway through clearing. Neither interrupted initialization nor
  completed initialization can be retried to erase storage.
- Valid allocations, inclusive saved-PSP bounds, all handle/index conventions,
  minimum and maximum stack sizes, opaque owners, duplicate owners, invalid
  requests/handles, exhaustion, and no mutation on ordinary rejection.
- Every seal byte, every metadata field, and partially populated free records
  are corrupted independently. Both lookup and allocation execute the actual
  fail-closed UDF path. Unready private operations likewise fail closed.
  A byte injected after the final clear store makes the actual verifier fail;
  READY must not be published and initialization remains non-retryable.
- After the real READY store, an instruction hook corrupts the marker before
  its final volatile readback; initialization must execute fail-closed UDF.
  A valid first FREE slot followed by a corrupt allocated record/seal must also
  fail closed without publishing the earlier slot. A valid-hole case succeeds.
- Stack/register ABI preservation, RAM redzones, rejected out-of-bounds memory
  accesses, no external/helper dependencies, and no CPU/FP/gateway instructions.
- Six invalid-manifest diagnostics, including handle and seal-allocation limits.
- Four additional default-M55 ELF probes enable function instrumentation,
  stack protection, undefined-behavior sanitization, and profiling/coverage.
  Canonical attributes must keep every helper/runtime dependency out of the
  final linked private call graph. All nine function identities remain distinct.
- Eight generated-source guard-removal mutants, covering `-O2`/`-Os` and normal/
  LTO builds, must be killed by these two focused cases. One removes the final
  READY readback guard; the other breaks the scan at the first FREE slot.
  Only the expected actual success return from the wrong implementation counts
  as killing a mutant; build failures, invalid accesses, or emulator faults do
  not. Production sources are never edited. Mutated sources, hashes, assembly,
  ELFs, disassembly, and `mutant_results.json` remain in the evidence directory.

Unique preserved build directories contain exact commands, source/reference
hashes, generated assembly, ELF/map/disassembly, and JSON execution evidence.
The pinned FreeRTOS no-MPU/no-FP comparison informs the record prefix, handle,
owner, and seal geometry; its heap and mutable lifecycle are not copied here.

This is actual ARM-instruction execution of the generated C paths, not execution
on a Cortex-M55 CPU or board. It does not qualify TrustZone transitions, register
banking, interrupts, exception return, MPU behavior, or physical reset retention.
Central matrix and root documentation remain outside this fixture's ownership.
