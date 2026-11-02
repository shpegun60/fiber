# CM33F MPU Running Execution

This fixture runs the `ARM_CM33F_MPU/non_secure` CPU engine through its private
component entry on the real QEMU `mps2-an505` Cortex-M33 model. It does not prove
public start/schedule integration, execute FreeRTOS, establish assembly parity,
or qualify hardware/TrustZone in general. Separate runners own those boundaries.

## Invocation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/test_cm33f_mpu_running_execution.ps1 `
  -ArmGcc <existing-arm-none-eabi-gcc.exe> -CmsisCore <CMSIS-Include> `
  -QemuRoot /home/ruslan/.cache/fiber-qemu-control-owner-20261101 `
  -WslDistro Ubuntu-24.04 -BuildRoot <optional-artifact-parent> `
  -FreeRtosRoot <optional-pinned-reference-root>
```

An existing extracted QEMU root is mandatory. There is no implicit download,
provisioning, package installation, or global configuration change. The currently
qualified extraction is Ubuntu's QEMU 8.2.2 (`1:8.2.2+ds-0ubuntu1.18`); every run
records the actual version, executable SHA256, machine list and `ldd` output.
The exception-trace grammar is checked explicitly, not silently bypassed for
different QEMU versions. A strict timeout and exact sole terminal PASS line are
required. A fault, timeout, failure diagnostic or nonzero exit fails the runner.
The default requires `FIBER_PORT_RUNTIME_SELECTABLE=1`. Pre-promotion proofs
must explicitly supply `-ExpectedRuntimeSelectable 0`; no production flag is
overridden by the fixture.

The runner requires the reference identity
`a50edad08b29052631aa469d4df6e6ec7ff68878`, checks tracked changes to the four
`GCC/ARM_CM33_NTZ/non_secure` source/header files and records their hashes.
This is reference identity evidence only, not a new assembly comparison or a
claim that the reference ran in QEMU.

## Execution Surface

The existing first-start fixture supplies only the Secure bootstrap and its
report transport: real SAU/MPC memory attribution, NSACR CP10/CP11 permission,
NS vector handoff and a model probe. No CPU registers are mocked. New NS vectors
point directly at production `SVC_Handler` and `PendSV_Handler`. Privileged
integration constructs two contexts and invokes the staged private start call.

The real common core, state and panic sources are compiled separately. The
production SVC object owns the cohort/storage providers and seven adapters;
construction owns the eighth operation. There is no fixture provider, common
source wrapper, barrier rename or reverse-call replacement. The application
panic override is the terminal reporting oracle. Fixture/common C run
general-registers-only; task assembly alone seeds or observes FP registers.

For each O2/Os and hard/softfp combination, with eager and lazy FP stacking:

- Basic/basic, extended/extended and extended-A/basic-B cases execute six switches
  `A -> B -> A -> A -> B -> B -> A` including both self-switches.
- Production SVC71 is followed by six actual SVC-to-PendSV tailchains, checked in
  QEMU's exception trace. Basic/extended EXC_RETURN counts must match the case.
- The scheduler observes the outgoing context fully saved and still current,
  the live masks/PSP/PSPLIM, the actual outgoing MPU image, exact hardware-frame
  geometry/owned continuation, r0-r12/LR, r4-r11, protected cursor/guard, and
  all s0-s31/FPSCR words when active.
- Callbacks observe the old current/map and resumed tasks record the new current;
  subsequent callbacks and the terminal oracle validate resumed records/maps.
  Unlike the archived pre-adapter fixture, this refresh does not instrument the
  production barrier and does not claim an observation inside the publication
  window. The previous staged 988-check receipt remains scoped to its archived
  input bytes; this runner produces a distinct refreshed receipt.
- Resumed task assembly captures every GP register before scratch use, Thread
  CONTROL/SP, the read-only current slot, and active FP data/FPSCR into its own
  stack. Later privileged observations verify those captures independently.
- After all six switches, the real owned SVC72 reaches terminal common return
  policy. The oracle checks final restored state, both self-switch records,
  pending B's saved form and final active map/masks before accepting panic R.

Eight negative ELFs per O2/Os hard/softfp combination exercise unowned SVC71,
unowned SVC72, changed immutable seal, invalid candidate cursor, permanent guard
corruption, callback BASEPRI drift, callback MPU-region drift and an actual
unprivileged write fault at the common current slot. Panic negatives require
the exact code/exception/count/current publication state; the fault requires
exact PC/CFSR/MMFAR/EXC_RETURN. Rejection is not inferred from arbitrary failure.

AN505's probed MPU has **eight** regions. Sixteen-region images are compiled and
linked with genuine r16 geometry but **never executed**. Those static checks are
inside this runner, so they are absent if central integration omits its explicit
QEMU gate. The model's actual priority mask determines CMSIS priority bits; the
MPU geometry is not fabricated to satisfy a sixteen-region manifest.

## Evidence

Each unique artifact root retains exact commands/exit codes, compiler identity,
QEMU identity, the Secure and all NS final ELFs/maps/disassemblies/attributes,
preprocessed/assembly/object/dependency files, terminal and exception logs,
case execution/compile-only labels, checks and receipt. Inputs include this
runner, both fixture directories, root/shared/profile and CMSIS headers, actual
common state source, reference identity files, GCC/binutils/subprocess binaries
and GCC system headers. Before/after input hashes reject drift; artifact hashes
bind retained outputs. No full central matrix is launched here.
Nonbinary input bytes are also copied immutably with an original/copy/hash map.
Only the reused Secure bootstrap/transport/launcher files are inputs from the
sibling first-start fixture; its unrelated NS cases/prose are not consumed.
Profile C/H/linker inputs are protected; independent profile prose is not a
compiler input or a parity claim by this execution gate.
