# Scalar Secure-Only M55 Focused Gate

`tools/test_cm55_secure_only.ps1` compiles the actual pinned M55_NTZ
Secure-only reference branch and the staged C5SO implementation. It records
commands, source hashes, complete object disassembly/attributes and negative
diagnostics. The tuple is Secure-only=1, TrustZone/MPU/FPU/MVE/PAC/BTI=0.

`main.h` is an explicit test device declaration over real CMSIS core55, not a
CPU instruction emulator. Public C/C++ type probes deliberately omit it and
CMSIS. Geometry checks use independent numeric C5SO identity/FD/F9 expectations.
Ordered transfer subsets compare the real generated objects but do not prove
whole-handler equivalence, final-LTO behavior, MPU enforcement or execution.
No M33 evidence is transferred to this new profile.
