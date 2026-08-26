# CI Validation Plan

## Status

No CI workflow is currently committed. The local validation entry point is
`tools/compile_matrix.ps1`. This document freezes how that proof will move into
CI after the required port inventory is complete and before the software
freeze or Context-interface extraction.

CI is a software evidence layer. It does not run a board and cannot create a
hardware support claim.

## Reproducible Inputs

Every acceptance run must record and pin:

```text
Fiber commit SHA
Arm GNU Toolchain package, version, and archive checksum
CMSIS Core source revision or immutable archive checksum
FreeRTOS Kernel commit and consumed portable-file SHA-256 values
CI workflow revision
host runner image
```

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

## Pull-Request Gate

Every pull request and every push to the protected integration branch runs the
current executable per-port gate:

```text
paired pinned-FreeRTOS/Fiber assembly parity at -O2 and -Os
port-specific normal and LTO ELF/archive retention
strong handler and vector-slot ownership
ABI and exact-cohort links
section-GC and stale-object/archive rejection
negative configuration and duplicate-symbol links
sensitive generated-code checks
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
that exact SHA. The same job is repeated after Context-interface extraction.

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

1. Add an explicit deterministic build-output parameter to
   `tools/compile_matrix.ps1`; `-KeepBuild` with a random temporary directory is
   insufficient for reliable artifact upload.
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
