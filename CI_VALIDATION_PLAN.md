# CI Validation Plan

## Status

No CI workflow is currently committed. The local validation entry point is
`tools/compile_matrix.ps1`. This document freezes how that proof will move into
CI; it does not describe an operational hosted pipeline.

The older roadmap placed complete port inventory and CI before Context-interface
extraction. The [2026-11-02 bounded scope decision](CONTEXT_REFACTOR_BASELINE.md)
supersedes that sequencing for F0/G0/G4/H7/H7S: Context ownership and its separate
Fiber consumer are implemented with captured local software evidence, without
declaring a global software freeze. Exact-SHA release-blocking CI and the
remaining all-optimization/final-linked-ELF gates are still required before that
broader freeze. They are not waived or retrospectively reported as completed.

CI is a software evidence layer. It does not run a board and cannot create a
hardware support claim.

The initial executable inventory/planner is `tools/freeze_cohorts.py`, with
explicit tuples in `tools/freeze_cohorts.json`. It requires the five object
and seven final modes below, and separates runtime forward-eight/reverse-v1
obligations from paired Secure-companion obligations. It is not a compiler
driver or CI workflow: every generated cell starts as `NOT_RUN`, and even a
complete synthetic key-accounting result leaves `GlobalFreezeQualified=false`.
The 141 initial rows do not exhaust all admitted axes; their reconciliation
and unimplemented required tuples remain visible in `scope_backlog`.

## Reproducible Inputs

Every acceptance run must record and pin:

```text
Fiber commit SHA
Arm GNU Toolchain package, version, and archive checksum
CMSIS Core source revision or immutable archive checksum
FreeRTOS Kernel commit and consumed portable-file SHA-256 values
CI workflow revision
host runner image
host GCC package/version for source-derived architectural-state tests
Python version and pinned emulator/ELF-reader package versions
QEMU binary/package/shared-library identity and maintained machine manifest
WSL distribution/userland identity for the current architectural-test wrappers
```

Pinned Python sources and contracts require their raw LF bytes. Configure
`core.autocrlf=false` before the initial Windows checkout and verify worktree
bytes against raw Git blobs before admission. Checkout conversion must fail
closed; do not normalize or repin authenticated inputs to hide that mismatch.

The current locally proven baseline is:

```text
Arm compiler:
  GNU Tools for STM32 14.3.rel1.20251027-0700
  arm-none-eabi-gcc 14.3.1 20250623

CMSIS Core(M):
  5.6

FreeRTOS Kernel:
  a50edad08b29052631aa469d4df6e6ec7ff68878
```

CI must use explicit paths rather than filesystem discovery:

```text
ARM_NONE_EABI_GCC
CMSIS_CORE_INCLUDE
FREERTOS_KERNEL_REFERENCE
```

The existing FreeRTOS parity script also verifies the SHA-256 identity of every
consumed portable source/header, so a modified checkout at the expected commit
fails closed.

The audit gate additionally checks the complete tracked reference content and
rejects tracked, untracked, or ignored worktree drift before compiling. Host
test prerequisites and the maintained audit runners are described in
`tools/PORT_AUDIT_TESTS.md`. Install the pinned packages from
`tools/fixtures/classic_audit/requirements.txt` in the runner environment; do
not silently skip executable guard checks when a prerequisite is absent.

The executed CONTROL and Secure gateway/pool gates use an explicitly prepared
isolated QEMU prefix, supplied through `FIBER_CONTROL_QEMU_ROOT` or the matrix's
`-ControlQemuRoot` argument. Current local qualification uses QEMU 8.2.2 package
`1:8.2.2+ds-0ubuntu1.18` on x86-64 Ubuntu 24.04 WSL with M3/AN385, M33/AN505,
and M55/AN547 machines. Preserve the binary, package and resolved-library hashes;
the optional local provisioning recipe's current APT candidate is not a CI pin.
Normal tests never provision packages. Acceptance CI must provide the qualified
environment and execute these gates, not accept the explicit `NOT_RUN` status
as architectural coverage. The current wrappers require WSL; availability on a
future hosted runner must be qualified rather than assumed.

Acceptance invocation must also pass `-RequireArchitectureExecution` to the
matrix. This fails before compiler discovery or output creation if the QEMU
prefix is absent or if `-SettingsOnly` requests an incomplete cohort. It does
not provision or certify the supplied prefix: each executed runner still
validates its actual environment and must pass. The default developer invocation
continues to report missing QEMU gates as `NOT_RUN`, not execution evidence.

## Pull-Request Gate

The future workflow must run the executable per-port gate for every pull
request and every push to the protected integration branch. No such automatic
execution or branch-protection configuration is established by this document:

```text
paired pinned-FreeRTOS/Fiber assembly parity at -O2 and -Os
port-specific normal and LTO ELF/archive retention
strong handler and vector-slot ownership
ABI and exact-cohort links
section-GC and stale-object/archive rejection
negative configuration and duplicate-symbol links
sensitive generated-code checks
executable classic ARM guard checks in the qualified emulator
source-derived architectural-state regressions with explicit hardware stubs
stale C/C++ allocating-consumer storage rejection
reference-drift and complete Secure-companion adversarial-code negatives
executed CONTROL entry/write/return and banked SG distinctions
executed CM33 immediate-caller/seal guards with isolated guard-removal mutants
private C55S pool lifecycle and compiler-variant evidence with explicit limits
```

The initial runner is Windows because the current scripts resolve
`arm-none-eabi-*.exe`. A Linux runner requires a separate portability change to
resolve both suffixed and unsuffixed tool names without changing proof
semantics.

## Final Freeze Gate

After every required port/profile is implemented or explicitly excluded, a
nightly, manually dispatched, and release-blocking job runs every claimed exact
CPU/ABI/FPU/MVE/MPU/security/errata cohort at:

```text
-O0
-Og
-O2
-Os
-O3
-O2 -flto final linked-ELF disassembly
-Os -flto final linked-ELF disassembly
```

The LTO proof reads the final linked ELF. Intermediate LTO objects or generated
assembly are not accepted as evidence. Unsupported combinations remain
negative compile/link cases.

The final software-freeze commit is accepted only when this job passes against
that exact SHA. For the already implemented bounded Context/Fiber extraction,
this remains an outstanding post-extraction requirement, not an inherited
pre-extraction PASS. Repeat the same qualified gates after later mechanical
Context/backend or Fiber-interface changes.

## Artifacts

Every final freeze run, and every failed pull-request run, retains:

```text
complete textual log
input-version manifest and checksums
Fiber and FreeRTOS object disassembly
final LTO ELF disassembly
ELF and linker map files
nm symbol tables
objdump section and vector dumps
assembly-parity result per exact cohort and optimization level
negative-test failure diagnostics
```

Artifacts must be named by Fiber commit, toolchain identity, exact cohort, and
optimization mode. CI success without retained freeze artifacts is not a
release proof.

## Required CI Preparation

Before adding the workflow:

1. Use the implemented explicit `-BuildRoot` output parameter of
   `tools/compile_matrix.ps1`. The path must not already exist, even when empty:
   stale outputs must never satisfy a later run. An explicit output is always
   kept; automatic temporary outputs are also kept on failure. Successful
   automatic runs are removed only without `-KeepBuild` and only after the exact
   owned temporary directory and absence of reparse points are checked.
2. Add the final all-optimization cohort defined in
   `FREERTOS_ASM_PARITY.md`.
3. Make every result identify the exact cohort and optimization mode.
4. Add immutable toolchain/CMSIS/FreeRTOS acquisition with checksum checks.
5. Add artifact upload on both failure and final-freeze success.
6. Add the pull-request and final-freeze jobs without weakening any local
   fail-closed check.

Toolchain compatibility testing with newer compiler releases may be added as a
non-blocking job. It does not replace the pinned acceptance toolchain until an
explicit compiler-baseline update is reviewed and recorded.

The filesystem-only `tools/test_matrix_artifacts.ps1` gate covers exact output
admission, stale-directory/file rejection, preserved explicit outputs, owned
temporary cleanup and root/nested/junction cleanup rejection. This preparation
does not mean that a hosted workflow or the final optimization matrix exists.
For CI, choose an absent job-specific path under the artifact staging root and
upload that directory plus the externally captured console log on failure.
The configuration-only `tools/test_matrix_execution_policy.ps1` gate executes
the actual matrix admission function and covers required/missing QEMU,
settings-subset rejection, and unchanged optional developer use. Its PASS is
not architectural execution or hosted CI evidence.
