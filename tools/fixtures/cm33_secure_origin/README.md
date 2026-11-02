# C33 Secure-Origin Runtime Gate

This suite builds the actual four-source scalar ARM_CM33 Non-secure provider,
three-source Secure companion and real common/public runtime. No constructor,
handler, selector adapter, gateway or provider is substituted. The only added
NSC entry is the fixture's register window. Production remains unchanged.

The two-image AN505 run uses explicit SAU/MPC attribution and IRQ0 Non-secure
targeting for the real startup priority probe. This QEMU exposes eight priority
bits: the fixture declares eight, uses PRIGROUP=0, and independently checks the
port's default scheduler BASEPRI=2. It does not bypass startup validation.

## Proof Split

Cases 0-4 complete two actual PendSV switches and resume Thread execution:
unattached NS/NS, attached S/S, both mixed attachment directions, and attached
NS/NS. The register windows and isolated Unix-socket RSP transport reuse the
mechanism established by `m55_secure_running` and `cm33_secure_guards`; they
execute on AN505 M33, not Unicorn or M55. The separate maintained `arm_control`
FC/DCRS1 probe is the independent architectural basis, not a historical receipt
accepted as runtime success.

Independent numeric checks cover the initial image and layout 0x00020001,
observed BC/FC/DCRS, Handler CONTROL and masks, exact NS header/frame images,
Secure hardware r4-r11/basic frames, all-register resume, both stack banks,
Save-before-NS-stores, explicit zero-handle calls, allocation owner/geometry,
whole Secure pool byte transitions at genuine Secure gateway exits, and actual
BXNS returns with NS-bank preservation. Ordinary initial R9 is unspecified;
running register windows deliberately seed it like all other GPRs.

Case 10 relocates an already-owned FC image to exactly `stack_top-12` and stops
at the real final PendSV BX before executing it. This is a bounded valid-image
restore proof, not an invented Thread continuation. Cases 11-13 inject a short
four-byte extent, zero FC handle, or invalid DCRS and require exact terminal
diagnostics with no current-slot publication, further SG call, NS-state repair,
or context mutation. The short image leaves poison after its proven extent;
a required CPU read watchpoint at its first unproven header word must not fire.
Secure memory is snapshotted only at Secure stops: AN505 correctly rejects
Secure-memory debugger reads from Non-secure stops. Late negative checks do
not pretend to reread Secure pool memory from that state.

A separately rebuilt, internally consistent Secure cohort advertises layout
0x00010001. The actual generation-two NS runtime must reject its third query in
SVC before initialize, allocation or CPU-policy changes. This is a compiled
old-contract identity fixture, not qualification of a historical Secure binary.

Five independently compiled controls remove S admission, S save/restore skips,
the S restore-validator branch, or the initial header extent guard. Each must
fail at its exact oracle; arbitrary QEMU faults/timeouts do not count. Save/load
controls must show the exact 32-byte error before exception return. The extent
control must trigger the exact read watchpoint from the actual restore
validator in PendSV, proving the sensor and guard order on mapped poison.
Missing watchpoint support, arbitrary faults and timeouts are failures.

The pin `a50edad08b29052631aa469d4df6e6ec7ff68878` is checked clean. Its actual
`portable/GCC/ARM_CM33/non_secure/portasm.c` non-MPU/TZ branch is the source
comparison: bit 6 suppresses NS r4-r11 save/restore and the three special words
remain handle, PSPLIM, EXC_RETURN. This runner does not execute a second
FreeRTOS scheduler; its source files are hashed in the evidence.

## Commands

Only the audit suite needs QEMU/WSL; API users need no Python packages. Python
uses WSL's default stdlib modules, with no pip installation or silent skip.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_cm33_secure_origin.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC -CmsisCore $env:CMSIS_CORE_INCLUDE `
  -QemuRoot /absolute/path/to/extracted-qemu
```

The runner accepts `-BuildRoot`, `-FreeRtosRoot`, `-WslDistro`, and timeout.
O0/O2/Os/O2-LTO/Os-LTO are mandatory by default. Development filters and
`-DevelopmentNoMutants` set `CompleteSuite=false`. Direct, import and extraction
optimization guards require an exact one-line diagnostic; a counterfeit
traceback is rejected. Every input is hashed before/after, every tool command
and linked image is retained. Failure throws; only a completed run prints PASS.
No hardware, M55 runtime, full Secure-world isolation or new public API claim.
