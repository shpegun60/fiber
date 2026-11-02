# C3FP Constructor Qualification

Run from the repository with existing ARM GCC, CMSIS and pinned Python packages:

```powershell
./tools/test_cm33f_mpu_constructor.ps1 -ArmGcc <arm-none-eabi-gcc.exe> -CmsisCore <CMSIS/Include> -BuildRoot <artifacts>
```

Optional `-FreeRtosRoot`, `-Python` and `-PythonModules` select existing inputs.
Nothing is installed or silently skipped. The executable checks require
`unicorn==2.1.4` and `pyelftools==0.33`, as pinned in
`../classic_audit/requirements.txt`. Python optimization must be disabled.

## Evidence

The eight constructor configurations are O2/Os x hard/softfp x 8/16 MPU regions,
using exact Cortex-M33 SP-FP compiler flags. The baseline uses the default eager
FPU policy. A separate lazy-policy ELF per configuration qualifies only the FPU
helpers; it does not expand the claimed constructor grid. No M55 loop-counter
workaround or alternate compiler target is used.

Both Fiber and FreeRTOS constructors execute actual ARM instructions under
Unicorn's Cortex-M33 model. The entire pinned `ARM_CM33_NTZ/non_secure/port.c`
is compiled with MPU and FPU enabled. FreeRTOS collects unrelated functions into
one privileged section, preventing ordinary section GC from isolating its
constructor. The fixture therefore assembles the compiler-generated
`pxPortInitialiseStack` body into a separate section, preserving its original
alignment modulo four. The maintained runner compares every function byte and
relocation (including the literal target) with the original full-source object.
No reference C algorithm is rewritten, mocked, or substituted. Both original
and isolated assembly, objects and disassembly are archived.

Numeric checks cover the entire 54-word initial basic backing, its one-past
cursor at word 20, outer geometry, raw-stack/current-slot MPU images, all boot
fields, independent bytewise FNV seal, r9 preservation, zero runtime flags and
the untouched user hardware-frame space. The pinned reference's debug seeds,
unmodified tail, task-privilege flag and wrappers-v2 stack metadata are checked
separately before comparing the shared processor-state backbone. Entry Thumb-bit
normalization and private return targets are intentional differences.

Negative paths include raw and normalized bounds, malformed entry/context/
stack arguments, poisoned outputs, every immutable ABI field, every remaining
protected backing word, resealed invalid MPU pairs and bounds before canary
access. The encoder exercises all AP/valid SH/XN/AttrIndx combinations and
failure-output preservation. SH is checked numerically: NON=0, OUTER=2,
INNER=3; SH=1 and RLAR bit 4 are rejected. The pinned reference's SH=1 definition
is a known defect, not a copied oracle.

Compile/ELF checks require exact constructor dependencies and privileged
placement, reject handlers/runtime ownership, FP/SIMD instructions and CPU
control writes, and verify a separately compiled hostile instrumentation/
stack-protector/coverage/sanitizer object. This also checks inlined callees;
canonical attributes on only the outer function are insufficient.
The real private boot header is compiled as C++; its retained eleven-function
address table must resolve to the actual unmangled C definitions in the ELF,
without static initializers or C++ runtime helpers.

The production linker fragment is included in positive links. All twelve
missing-boundary cases and five malformed-placement cases run for both region
geometries, retaining the intended failure diagnostics.

`commands.log`, source/dependency hashes, reference pin, generated assembly,
objects, ELF/map/disassembly, negative-link logs, `execution.json` and an artifact
hash manifest remain under the unique reported build directory. A changed input
invalidates the run.

## Explicit Boundaries

`probe.c` supplies test-only cohort/storage bytes, current-slot storage and
panic/return targets because this constructor-only link deliberately excludes
the production SVC/PendSV objects. The separate first-start gates instead use
the real SVC-owned providers. This runner checks exactly one provider pair in
its probe object and final ELF, and rejects handlers, forward adapters or bundle
ownership in the constructor-only image. These are not runtime support or a
usable final application link.
The exact public storage name is
`fiber_port_storage_cohort_arm_cm33f_mpu_v1_r8` or `_r16`.

FPU helpers execute separately against mapped CPACR/FPCCR test words with
instruction-hook write-readback fault injection. This proves the compiled
policy/guard paths, not real CPACR effects, lazy FP stacking or exception entry.
Unicorn constructor execution does not prove MPU enforcement, FP exception
restoration, SVC/PendSV correctness or silicon behavior. No board is programmed.
