# Isolated H7S Boot Build

`tools/test_h7s_snapshot_build.ps1` qualifies only fresh offline Debug and
Release builds of the real `h7s_fiber_test_Boot` project. It does not run the
firmware, QEMU, CubeMX, a debugger or a programmer, and does not close an IDE.
No package installation, network provisioning or global preference update is
part of the procedure.

The production library is exported directly from exact Git commit
`471ec5cfd1e69aefc273f6dd47d487bb1b4e5c6a`: `context/`, `fiber/`,
`basic_types.h` and `mcu_core.h`. Git blob identities are checked. No live
untracked library files, tests, protected WIPs, `.git` directory or previous
build output enter this export. Boot application/project files, Core, and
required sibling Drivers inputs are copied and content-addressed separately;
they are not described as belonging to the library commit. The four harness
files have their own captured identities as well.

The launcher uses private configuration, p2 metadata, workspace, Java home and
temporary directories. Child environment overrides are process-local. The
installation, live Boot files, open IDE workspace and real user home are not
build outputs. The output root must be new, short, space-free and outside the
live project and installation. It is never recursively cleaned or reused.

Original project/settings bytes are sealed separately from the working copy.
CDT may rewrite only its private project/cache metadata; those before/after
hashes are recorded and generated source/option admission is checked again.
Production C/header/linker inputs and their sealed originals remain immutable.

Preflight checks project identity/builders, source exclusions, linked-resource
locations, output paths and the absence of pre/post-build hooks. The selected
provider is actual `ARM_CM7/r0p1`; all alternate ports and tools remain excluded.
Regeneration deliberately admits `fiber/lifecycle/fiber_v1.c`, making 35 input
objects. This is not a migration of the board application to the new Fiber API.
The extra public storage consumer contributes a retained cohort expectation;
the exact three-pointer output consists of storage expectations from
`app_core.o` and `fiber_v1.o`, plus the runtime expectation from
`fiber_port_context_cohort_expectation.o` (12 bytes total on this target).
unused APIs/configuration may still be garbage-collected without failing the
audit. Existing Debug C O2/C++ O1/GNU++20 and Release Os/GNU++14 options are
preserved, with M7/FPv5-D16/hard ABI and no introduced LTO or QEMU priority
settings. Each generated compile command is associated with its declared source,
object and dependency file: exactly 33 C sources, one C++ source and the one
expected startup assembler. Compiler driver, source suffix, source-list language
and any explicit `-x` selection must agree. C/C++ must contain exactly one correct
optimization and language-standard option; missing, wrong or duplicate options
fail. The startup's explicit `-x assembler-with-cpp` command correctly has no
optimization or C/C++ standard option. No other GCC rule is silently skipped.

The audit requires exact source/object/dependency sets, enrolled input paths,
actual prelink eight-operation and Context/legacy owners, one current slot and
reverse-v1 owner, strong real SVC/PendSV vectors, correct device linker placement,
and the retained read-only cohort expectations. It does not require every
unreferenced API to survive section GC. Only SVC/PendSV prelink ownership permits
the exact three-definition set: one strong `ARM_CM7/r0p1/fiber_port.o` definition
and the two existing weak definitions in `Core/Src/stm32h7rsxx_it.o` and
`Core/Startup/startup_stm32h7s3l8hx.o`. Missing, duplicated, competing or unexpected
owners fail; no other ABI gains a weak-definition exception. Final SVC/PendSV
handlers must still be strong global functions. Reset is independently required
to have its one weak definition in the exact startup object, matching the real
STM32 startup. Its final symbol must be a weak Thumb function wholly within an
allocated executable section, with exact entry/vector-1 agreement and the
device's initial MSP value. Pre-build negative controls test the
admission/diagnostic predicates. After each successful build, changed copies
of the actual ELF must reject cleared Thumb vectors, wrong-handler vectors and
invalid expectation pointers, plus a weak final SVC symbol, for the exact intended
reason. Reset-specific changed ELF copies also reject a strong Reset binding,
wrong entry, wrong initial MSP and a non-Thumb Reset vector. These are audit
controls, not additional firmware executions or CPU behavioral tests.
Every handler's complete Thumb function extent must be in an allocated executable
PROGBITS section with matching file backing in an executable PT_LOAD segment.
The aligned four-byte current slot must lie wholly in allocated writable RAM
storage and a writable load segment, not merely have the correct symbol binding.
Every PT_LOAD memory extent must fit a device memory region, and every nonempty
physical file-load extent must also fit a device region; file offsets/sizes are
bounded by the actual ELF. Empty NOLOAD physical extents carry no file bytes.
Changed actual ELF controls reject a foreign SVC address with a matching vector,
a current slot redirected into read-only flash, and a foreign physical load
address, each by exact diagnostic equality. Helper controls cover alignment,
whole-extent boundaries, permissions and mismatched/truncated file backing.
The maintained controls include assembler-without-optimization acceptance and
rejection of C/C++ optimization omissions/duplicates, wrong languages and
unassociated generated compile rules.

Example using an already available Python module directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_h7s_snapshot_build.ps1 `
  -PythonModules "$env:TEMP\fiber-classic-audit-python" -BuildRoot C:\h7sb-unique
```

Optional explicit paths are `-RepoRoot`, `-BootProjectRoot`, `-CubeIdeRoot`,
`-ArmGcc`, `-MakeExe`, `-Python`, and `-PythonModules`. `-TimeoutSeconds` bounds
each headless configuration build. `-PreflightOnly` is an explicit incomplete
mode: it never launches the IDE and records `CompleteSuite=false`. A normal
run never falls back to this mode. Unoptimized Python and pyelftools 0.33 are
required; missing maintained dependencies fail rather than install or skip.

Every attempt preserves a FAIL-first `results.json`, command logs, source
copies, Git export, generated recipes, actual ELF/map outputs, negative ELF
copies and an artifact hash manifest. PASS requires both fresh configurations
and zero enrolled-input/copy drift. Raw IDE stderr and nonzero exits remain
evidence; a success message cannot substitute for actual objects and final
ELFs. This gate establishes bounded build/link admission, not board execution,
interrupt timing, silicon erratum effectiveness or global runtime parity.

Historical PASS receipt SHA256
`3E18C92F0ED00B9467B4384FFD191C97C84DEBE8AF2C2DD926ADE4BCD0926075`
is preserved unchanged but superseded for ELF admission by revision 2. Its oracle
accepted the three malformed ELF storage cases above; this was an audit gap,
not evidence of a production binary defect. New receipts explicitly identify
the superseded receipt and must qualify both configurations again.
