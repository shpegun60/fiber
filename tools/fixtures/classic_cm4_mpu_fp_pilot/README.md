# CM4 MPU FP-Active Pilot

This opt-in test extends, but does not modify or replace, the qualified
`classic_cm4_mpu_basic_grid` fixture. It exercises actual Context/FiberV1 and
ARM_CM4_MPU providers on the existing QEMU AN386 model. No board programming,
tool installation, production instrumentation, or default-matrix changes occur.

## Inventory

- Four positive O2/direct/non-LTO images: Context and FiberV1, eager and lazy FP.
- Three privileged contexts per image: two FP-active workers and one GRO worker.
- Ten actual backend mutations: high-save/high-restore/low-save/low-restore
  omissions and saved-FPSCR corruption, each under eager and lazy policy.
- One model probe and one pinned, link-only FreeRTOS reference ELF.
- Four hash-bound associations using the maintained three basic mechanisms and
  additional decoded high/low FP-copy ordering checks against the reference.

All C uses general registers only. A user-stack assembly oracle seeds/checks
R4-R11, stack cookies, active SP and FPCA. PSP is validated only in privileged
Handler code; unprivileged `MRS PSP` is not a valid task-side oracle. Across the genuine public C yield it
requires only high-FP preservation; a separate assembly envelope calls the real
naked SVC71 primitive and requires all S0-S31 and FPSCR. The dispatcher verifies
basic/extended privileged serialization and post-save FPCCR/CONTROL. It poisons
only the outgoing low16/FPSCR hardware-frame copy after the protected save, so a
missing restore cannot pass merely because the original user frame survived.
The constructor-seeded task return must reach the production SVC72 panic path.

The first four backend mutations must fail the named generated-code mechanism
and the resumed payload oracle. Saved-FPSCR corruption deliberately preserves
the ordered copy mechanism; only the payload oracle must reject it. A generic
fault, timeout, GPR failure or wrong panic is never an expected FP-negative PASS.

## Running

Use `tools/test_classic_cm4_mpu_fp_pilot.ps1` with explicit `ArmGcc`, `CmsisCore`,
`FreeRtosRoot`, actual `Python` executable and existing `PythonModules` containing
pyelftools 0.33. The default only compiles/links/inspects; it must not launch WSL.
`-ExecutePilot -QemuRoot <existing-linux-prefix>` explicitly enables QEMU runs.
Every run requires a fresh external `BuildRoot` and captures selected sources,
the 26 pinned reference inputs, CMSIS, Python package and compiler/tool closure.
Failures retain their own evidence directories and are never overwritten.

`CompleteSuite` remains false, even on pilot PASS. `RequestedInventoryComplete`
only describes the literal inventory above. No O0/Og/Os/O3, final LTO, archive,
softfp, MPU16, hardware or whole-port equivalence claim is made. The reference
is not executed. In particular, observing post-save LSPACT=0 does not prove a
pre-save lazy LSPACT=1 transition; `PreSaveLspactObserved` remains false. That
requires a separate bounded observation without production hooks.
