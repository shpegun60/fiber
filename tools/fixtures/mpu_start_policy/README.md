# Protected MPU Startup Policy

The current protected MPU SVC provenance checks use the validated initial MSP.
They do not implement preserve-current-MSP startup. Their dictionaries must
reject `FIBER_REWIND_MSP=0`, rather than accept and silently ignore it.

`tools/test_mpu_start_policy.ps1` compiles 54 configurations at O2/Os: M0+
VTOR-present/absent, M3, M4F/M7F, M33 scalar/FP and M55 scalar/FP/MVE-FP;
applicable hard/softfp and 8/16-region configurations are separate. Each makes
three real compiler invocations. Default and explicit `1` must produce identical
objects; `0` must fail with the selected dictionary's exact policy diagnostic.
The staged C3FP header is included, not claimed runtime-complete.

This is an admission regression, not an emulator or board startup test. Existing
assembly/ELF and execution gates qualify the default mechanics separately.
The fixture's synthetic CMSIS facts do not assert that every hardware member of
a core family physically has an MPU. No device is programmed.
