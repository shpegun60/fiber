# C3FP Type And Manifest Proof

`tools/test_cm33f_mpu_manifest.ps1` is a standalone compile/codegen qualification
for the ARM_CM33F_MPU headers. It accepts `-ArmGcc`, `-CmsisCore`, and
optional `-BuildRoot`/`-FreeRtosRoot`; toolchain and pinned-reference discovery
follow existing focused-suite conventions. It never installs dependencies,
programs a board, runs the full matrix, or edits production files.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_cm33f_mpu_manifest.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC -CmsisCore $env:CMSIS_CORE_INCLUDE
```

## Implemented Proof

- Exact C3FP ID `0x43334650`, layout `0x00010008`/`0x00010010`, feature `0x1C87`,
  and public storage tag `arm_cm33f_mpu`, revision 1, region count 8/16.
  The established declaration spells this as
  `fiber_port_storage_cohort_arm_cm33f_mpu_v1_r8`/`r16`.
- Public storage C11 and C++17 (actual ARM GCC/G++) without CMSIS or MCU include
  paths; dependency-file and undefined-symbol checks prevent hidden runtime
  dependencies. No storage expectation/provider anchor is fabricated or linked.
- Every integer/special register offset in both protected views, both cursor
  offsets 80/212, 16 high and 17 low FP words, union backing 54 words, every
  immutable boot-record field, region-pair offsets, 8-byte outer alignment,
  and complete outer sizes 352/416.
- Real `core_cm33.h` positives derive `__FPU_USED` from the compiler. Both region
  manifests, hard/softfp ABIs, and `-O2`/`-Os` build independently in C and C++.
- Strict missing/wrong CPU, FPU presence/use, MPU, VTOR, priority bits, scalar
  FP precision and ABI, Secure CMSE, MVE, PAC/BTI (including zero-valued feature
  macros), foreign/invalid region manifests, and derived-trait override checks.
  Synthetic contradictions occur only in explicit negative fixtures after
  actual CMSIS inclusion. Rejection must carry the intended diagnostic.
- Independent raw RBAR.SH oracle: NON=0, OUTER=2, INNER=3; SH=1 is reserved.
  The port's shifted values are checked against those numeric constants and
  separately against `mpu_armv8.h`. The pinned FreeRTOS INNER=1 definition is a
  reference defect, not a value to copy or a parity obligation.
- The actual pinned M33 NTZ `port.c` and `portasm.c` compile with MPU=1/FPU=1,
  MVE/TrustZone/PAC/BTI=0, wrappers v2, syscall stack 128 and ACL=0. Actual
  `xMPU_SETTINGS`/`MAX_CONTEXT_SIZE` prove the backing and prefix geometry.
  Ordered disassembly checks retain the 16+17 FP save and inverse restore
  transfers, independently for both region counts, FP ABIs and optimizations.

The unique evidence directory preserves exact compiler commands, positive and
negative diagnostics, dependency files, generated/preprocessed assembly,
disassembly, compiler identities, source/CMSIS/reference hashes, macro dumps,
and a JSON result. Any consumed profile/fixture change during qualification
invalidates the run rather than accepting incoherent evidence.

## Qualification Boundary

This runner consumes headers only, even though the profile now has production
constructor, SVC/PendSV, adapters and a mandatory SVC-owned cohort provider.
The probe must emit none of those definitions or provider bytes. Runtime
metadata is now one after the separate complete-group qualification;
this header proof does not establish constructor execution, runtime/link
compatibility, encoder rejection paths, exception execution or hardware support.
The reference codegen is not a fabricated Fiber constructor or a completion claim.
