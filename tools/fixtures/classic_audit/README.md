# Classic Audit Regressions

`tools/test_classic_audit.ps1` covers audit A09, A10, A11, A13, and A14.
It is standalone and does not invoke or edit `compile_matrix.ps1`.
All Python dependencies are audit-only; ordinary library consumers need none.

## Setup And CI

From the repository root, with Python 3.10 or later, the ARM GCC toolchain,
CMSIS Core headers, and the pinned local FreeRTOS checkout installed:

```powershell
$modules = Join-Path $env:TEMP 'fiber-classic-audit-python'
python -m pip install --target $modules -r tools/fixtures/classic_audit/requirements.txt
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_classic_audit.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC -CmsisCore $env:CMSIS_CORE_INCLUDE
```

The script discovers this temporary modules directory automatically. Existing
Python environments are also supported. `-Python` selects an interpreter;
`-PythonModules` or `FIBER_CLASSIC_AUDIT_PYTHONPATH` selects another modules
directory. `-FreeRtosRoot` overrides the local reference path. `-BuildRoot`
selects the parent for a unique, preserved evidence directory. Missing tools,
wrong Python dependency versions, failed builds, and failed execution tests
throw; no maintained regression is silently skipped. The script never installs
packages, deletes evidence, programs hardware, or changes a reference checkout.

Optimized Python (`PYTHONOPTIMIZE`, `-O`, or `-OO`) is rejected by both the runner
and the direct Python fixture because execution checks include assertions.
The runner uses unconditional dependency-version checks and executes eight
preflight regressions: pinned versions, each version mismatch, both optimization
levels, direct-fixture rejection at both levels, and rejection of a counterfeit
`RuntimeError` traceback containing the expected diagnostic. Negative controls
require exit status 1 and the sole exact diagnostic line on stderr, not a
substring match. Version mismatches use child-process metadata stubs without
modifying installed packages.

The tested setup is Windows Python 3.13 with the two pinned packages above and
STM32CubeIDE GNU Arm GCC 14.3.1. `commands.log` records the resolved Python
executable/version and exact compile/link commands. `reference.json` records
the FreeRTOS pin, consumed comparison-source hashes, and comparison boundaries.

## Evidence And Boundaries

- Real boot/runtime sources compile at `-O2` and `-Os`, without `-ffixed-r9`.
- CM0 and no-VTOR CM0+ execute the actual boot MSP plan and perform two reads
  at address zero, with no optimized undefined-instruction trap. Repeated
  preparation still fails the mandatory one-shot check.
- CM0 MPU constructors and initial validators execute through register-pressure
  C callers with unrelated r9 values. Other initial register checks stay active.
- Vector placement is proved for all 48 ARMv6-M vector words (192 bytes), before
  SVC/PendSV slot reads. RO maps are accepted; user stack, privileged RAM, current
  aperture, unmapped addresses, misalignment, address wrap, and a table crossing
  the RO boundary are rejected. A no-VTOR positive fixture links code/table at
  zero, rather than pretending a writable RAM alias is immutable flash.
- All four classic ports reject a raw prefix outside the approved RAM range
  before any canary access, both at construction and map-on save validation.
  Revoked-map boot checks and corrupted-canary checks also execute.
- The actual weak boot fallback and an ordinary application override link in
  both object orders and both archive orders, with section GC, normal/LTO builds,
  and `gcc-ar` indexing. The override archive has an independently referenced
  anchor: as with any static archive, the override member must be extracted.
- Every final ELF has zero undefined symbols. Disassembly and execution reports
  remain beside the ELF and compiler-generated assembly.

Unicorn executes the generated Thumb C paths. This is not an MPU, exception-return,
interrupt-priority, remap-alias, or board execution qualification. Only VTOR MMIO
is modeled; other MMIO or unmapped accesses fail the harness. Negative vector
tests require panic `V` and zero attempted accesses to the rejected table,
including the unmapped cases, rather than treating a host/emulator fault as PASS.

No-VTOR integrations must describe the entire active table at zero in a validated
immutable RO code map. A board flash/remap alias outside those linker ranges fails
closed. An alias-specific linker/remap contract needs separate integration proof;
this suite does not widen RAM or code maps to admit an unproved alias.
