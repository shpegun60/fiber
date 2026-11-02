# Executed CONTROL Transition Regression

`../../test_arm_control.ps1` builds bare-metal ARM ELF fixtures and executes them
with QEMU TCG. No host register model, CMSIS header, library runtime source, or
board programming is involved. The fixtures deliberately use assembly around
stack/mode transitions so a compiler-generated frame cannot hide the active SP.

## Normal Run

An existing isolated QEMU prefix is required. Normal runs do not download or
extract packages. Missing QEMU or any maintained machine is a failure, not a
skip. The prefix must contain `usr/bin/qemu-system-arm` and its extracted shared
libraries. `-WslDistro` defaults to `Ubuntu-24.04`.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/test_arm_control.ps1 `
    -ArmGcc $env:ARM_NONE_EABI_GCC `
    -QemuRoot /home/ruslan/.cache/fiber-qemu-control-owner-20261101 `
    -BuildRoot "$env:TEMP/fiber-control-evidence"
```

This execution policy applies only to the child PowerShell process. No persistent
execution policy or WSL/global setting is changed.

## Explicit Provisioning

On x86-64 Ubuntu WSL, opt in to download/extract provisioning:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/test_arm_control.ps1 `
    -ArmGcc $env:ARM_NONE_EABI_GCC -ProvisionQemu
```

Without `-QemuRoot`, this creates a unique `~/fiber-qemu-control.XXXXXXXX` prefix.
An explicit new private prefix can also be supplied. The command queries existing
APT metadata, downloads QEMU and missing dependencies with `apt-get download`,
and extracts `.deb` files with `dpkg-deb -x`. It does not run `sudo`, install
packages, refresh package indexes, register packages, or run maintainer scripts.
Provisioning refuses uid 0. Dependencies already installed in WSL are used
read-only; `qemu-ldd.txt` records the actual library resolution. APT candidate
availability is an explicit provisioning prerequisite, not a test-time network
dependency. Downloaded archives and the prefix are retained for reuse.

## Assertions

`mps2-an505` executes Cortex-M33, `mps3-an547` executes Cortex-M55, and
`mps2-an385` executes Cortex-M3. Each basic
image enters SVC first from Thread/MSP and then from Thread/PSP. It samples actual
`CONTROL`, `IPSR`, `EXC_RETURN`, `SP`, `MSP`, and `PSP` before/after Handler writes.

| Case | Entry CONTROL | After MSR 2 | After MSR 3 | Active Handler SP |
| --- | --- | --- | --- | --- |
| M33 | 0 | 2 | 3 | MSP |
| M55 | 0 | 2 | 3 | MSP |
| M3 | 0 | 0 | 1 | MSP |

The MSP-origin Handler leaves SPSEL=1, but exception return restores Thread/MSP
and CONTROL=1. The PSP-origin Handler leaves CONTROL=0, but return restores
Thread/PSP and CONTROL=2. Thus return selection is tested against a conflicting
Handler value, not just an unchanged register.

Two M33 negative images encode the obsolete Handler-readback assumptions 0 after
MSR 2 and 1 after MSR 3. Actual execution must reject them with exact semihost
exit statuses 42/43 and their corresponding failure markers. An arbitrary crash,
timeout, or other nonzero status is not accepted as a successful negative test.

The separate M33 banked image configures disjoint Secure/NS memory and NSC SG
stubs using this QEMU board's SAU, IDAU/NSCCFG, and MPC interfaces. It checks:

- NS Thread/PSP exception entry clears NS SPSEL while Secure CONTROL remains 2.
- NS Handler -> SG -> Secure Handler preserves IPSR=11 and Secure CONTROL=2;
  physical SP is MSP_S, distinct from PSP_S. MSR 3 reads back 3 on MSP_S.
- Secure PendSV preempts that Handler. Entry clears S.SPSEL, retains S.nPRIV=1,
  and leaves NS CONTROL=0. Exception return restores S CONTROL=3 in Handler mode.
- SG return leaves NS CONTROL unchanged. A later NS Handler MSR 3 reads 3 while
  SP stays MSP_NS. Exception return restores NS Thread/PSP with CONTROL=2.

The independent `origin.c`/`origin.S` AN505 image instead enters Secure Thread
through SG and requests **Non-secure** PendSV there. It observes exact scalar
EXC_RETURN FC (S=1, DCRS=1), CONTROL_NS=0 in the handler and physical MSP_NS.
PSP_NS is unchanged before, during and after interruption, and eight poisoned
words immediately below it remain untouched: no NS hardware frame exists.
The handler overwrites every r4-r11 and records those clobbered values. Hardware
then restores all eight distinct Secure sentinels. Secure PSP is restored;
both banked CONTROL values and the later NS Thread/PSP return are checked.

Three compiled fixture controls must fail exactly: omitted PendSV request
(exit 81), omitted NS GPR clobber (88), and an obsolete NS-hardware-frame PSP
expectation (83). These are architecture-fixture controls, not production-port
mutants. Together with the six earlier cases, the complete suite has ten images.

AN547 uses vectors at 0 in boot TCM and RAM at `0x20000000` in DTCM, as mapped by
QEMU's AN547/SSE-300 sources. Its basic fixture does not reuse AN505's IoTKit
security-controller configuration or claim execution of the banked SG case.

Every image has a bounded execution timeout (default 10 seconds, configurable
1..60). Positive cases require exit 0 and the exact PASS marker. Fault vectors
fail; semihosting uses `SYS_EXIT_EXTENDED`, not an unbounded breakpoint wait.

## Evidence And Boundary

Each invocation prints a unique evidence directory and retains compiler identity,
fixture/ELF SHA256, exact command arguments, ELF/map/disassembly, per-image QEMU
logs, and a result ledger. Emulator version/hash, downloaded package
versions/SHA256, WSL user/system identity, machine list, library resolution, and
the isolated prefix path are retained separately. Inspect these receipts for the
actual run identity; the provisioning recipe intentionally uses current local
APT candidates rather than claiming a permanently pinned emulator package.
`inputs-before.json`, `receipt.json` and `artifacts.json` additionally retain
the exact local compiler/fixture inputs, completed case set and output hashes;
input drift fails the invocation even after successful emulator runs.

Initial qualification on 2026-11-01 used STM32 ARM GCC 14.3.rel1 and QEMU 8.2.2,
Ubuntu package `1:8.2.2+ds-0ubuntu1.18`, with the initial five cases passing before
the separately requested M55 addition. A fresh
explicit provisioning receipt is
`%TEMP%/fiber-control-owner/arm-control-651740c66a634f1bad873838fadae24e`.
The earlier `/tmp` prefix disappeared between runs; the home-directory prefix
above is the reusable qualification tool root, not a system installation.
After the M55 addition all six cases passed without provisioning, including with
a nested Windows build path containing spaces. That receipt is
`%TEMP%/fiber-control-owner/nested build root/audit-owner/arm-control-a063e3e401ad4edc867ef0bb446f2dc2`.

These are executed emulator instruction/exception regressions. They are not
execution of the Fiber runtime, hardware qualification, complete CMSE ABI
qualification, or proof of a complete TrustZone security policy. The raw SG
stubs are fixture assembly, not production NSC veneers.

The later ten-case qualification is
`%TEMP%/arm-control-a41faa3c18eb45059fe4b0febd2bf8e6`, with receipt SHA-256
`A553D7A804F3A56DB8CA8D40726F8C429081E674DB239F6EC3854B82223D7369`.
All fifteen inputs and sixty-seven artifacts were independently rehashed.
Its thirteen repository-local input files were preserved at
`%TEMP%/fiber-qualified-repo-inputs-1b52ed80d58243a89466a3fb893f54e2`;
source ZIP SHA-256 is
`51B40BA5BB4C63F8F1968DA035AEEBEB0B95958316D146FD713242B437A7F144`.

## Primary References

- [Armv8-M Architecture Reference Manual DDI0553B.y](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf):
  MRS/MSR operations, SG operation, `ActivateException()`, and
  `LookUpSP_with_security_mode()`. Stored banked SPSEL, exception-entry updates,
  and active Handler stack selection are distinct rules.
- [QEMU machine documentation](https://www.qemu.org/docs/master/system/arm/mps2.html)
  and [8.2.2 board source](https://github.com/qemu/qemu/blob/v8.2.2/hw/arm/mps2-tz.c).
- QEMU 8.2.2 [CONTROL and exception helpers](https://github.com/qemu/qemu/blob/v8.2.2/target/arm/tcg/m_helper.c),
  [SSE/IDAU mapping](https://github.com/qemu/qemu/blob/v8.2.2/hw/arm/armsse.c),
  [MPC](https://github.com/qemu/qemu/blob/v8.2.2/hw/misc/tz-mpc.c), and
  [security controller](https://github.com/qemu/qemu/blob/v8.2.2/hw/misc/iotkit-secctl.c).
- [Arm semihosting ABI](https://github.com/ARM-software/abi-aa/blob/main/semihosting/semihosting.rst).

The reference FreeRTOS `SecureContext_Init` writes CONTROL 2 (no MPU) or 3 (MPU)
in Handler mode. This fixture explains why neither write implies switching the
active Handler stack to PSP, and why an Armv7-M write-ignored rule must not be
substituted into Armv8-M post-write readback checks.
