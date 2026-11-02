# CM33F MPU Common Runtime Integration

This is the full common/provider integration gate, distinct from the private
component `test_cm33f_mpu_running_execution.ps1`. It compiles unmodified real
`fiber_core.c`, `fiber_runtime_state.c` and `fiber_panic.c` separately, without
CMSIS or a private selected-port include path for those objects. Production boot,
SVC and PendSV objects provide exactly the frozen eight generic operations. The
production SVC object supplies the sole private cohort and public storage cohort.
The build-owned expectation source is compiled separately and retained by GC.
There are no fixture generic/reverse providers, common-source wrappers or barrier
renames. The application overrides only the documented weak panic hook.

## Invocation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/test_cm33f_mpu_runtime.ps1 `
  -ArmGcc <existing-arm-none-eabi-gcc.exe> -CmsisCore <CMSIS-Include> `
  -QemuRoot /home/ruslan/.cache/fiber-qemu-control-owner-20261101 `
  -WslDistro Ubuntu-24.04 -BuildRoot <optional-artifact-parent> `
  -FreeRtosRoot <optional-pinned-reference-root>
```

The default requires selectable manifest **1**. While production is awaiting
promotion, qualification must explicitly add `-ExpectedRuntimeSelectable 0`.
That checks the real manifest; it does not override a production macro. A pending
receipt is not evidence that the advertised profile was already promoted.

An existing isolated QEMU root is mandatory; there is no provisioning, network
fallback, package installation, hardware access or implicit compile-only mode.
The maintained launcher and Secure bootstrap are reused read-only from the
running/first-start fixtures. Each run records the actual QEMU version/binary
hash, library resolution, model list and WSL identity. Qualification currently
uses Ubuntu QEMU 8.2.2 (`1:8.2.2+ds-0ubuntu1.18`), AN505 Cortex-M33, real SAU/MPC
attribution and NSACR CP10/CP11 permission. CPU registers are not mocked.

## Actual Execution

O2/Os, hard/softfp, normal/LTO, eager/lazy builds use real final ELF images.
An ordinary common/port archive group is linked with GC and weak startup aliases;
production cold references must extract the actual SVC and PendSV objects.
Basic/basic, extended/extended and extended-A/basic-B cases run six switches
`A -> B -> A -> A -> B -> B -> A`. Additional direct-object/strong-startup basic
images execute for every O2/Os, FP ABI and normal/LTO combination.

The application calls all five public operations. First selection is reached
only through real `fiber_start()` and its production adapters. Its callback
requires configuration closed, current still NULL, prepared FPU and priorities,
MPU off, privileged Thread/MSP, PRIMASK=1 and other masks clear. Later callbacks
require PendSV, scheduler BASEPRI, old current/map still active, fully saved
protected state and correct frame/PSPLIM bounds. Task assembly calls actual
public `fiber_current()` and `fiber_schedule()` from unprivileged Thread mode.
It captures callee-saved GP registers (respecting public C-call AAPCS clobbers),
SP/CONTROL/current and active s0-s31/FPSCR data for later privileged checks.
Six actual SVC-to-PendSV tailchains and the basic/extended mix are checked in
QEMU exception logs. Real SVC72 terminates through actual common return policy
and the application panic oracle, only after every expected resume is checked.

All executed cases require exit zero, exactly one expected terminal marker as
the final nonempty line, no failure/fault/timeout diagnostics and a strict timeout.
Thirteen negatives cover missing/null registration, null first/next candidates,
registration attempted during first selection, first BASEPRI drift, foreign
SVC71/72 inside valid syscall flash but at non-owned continuation sites,
running PRIMASK/MPU drift, a bad first seal, masked registration and a
linker-placement mutant that puts common Thread code in privileged flash. Exact
panic code, exception, phase, callback counts, current publication and MPU state
are required; arbitrary failure never passes.

The model probe must report **eight** MPU regions. Genuine sixteen-region
images are compile/link-only, not run on a fabricated MPU model. An additional
default-weak-panic image links real common fallback policy without an application
override; its deliberate terminal wait is **not executed**. Receipts distinguish
sixteen-region images and default-panic link-only cases from QEMU executions.

## Build Controls

For both region counts/FP ABIs and O2/Os normal/LTO, the gate checks:

- Exactly one owner of each generic operation: constructor in boot, seven in SVC;
  no additional `fiber_port_runtime_*` operation is accepted.
- Final public current/schedule/load/barrier code in unprivileged flash, generic
  schedule veneer in syscall flash and other generic operations privileged.
  Both vector words must select the real strong handlers, not weak defaults.
- Each handler's duplicate strong definition is rejected by its exact symbol.
- A freshly compiled real common-state source control changing only the v1
  anchor definition to v2 cannot satisfy the actual v1 references.
- Removing the sole provider invocation from a temporary SVC copy rejects the
  exact private cohort; no replacement provider is manufactured.
- Real opposite-region public storage and private boot objects, and a coherent
  port with the wrong separately compiled build expectation, fail their exact
  identities in both directions. A synthetic storage revision-zero control
  additionally proves revision rejection; it is not a historical-layout claim.
- Archives missing either SVC or PendSV cannot hide behind startup weak aliases.

GCC's LTO plugin can label constant intermediate definitions `D`. The final
linker can put constants in an executable flash output section (`nm` says `T`).
The gate therefore requires each exact provider to be a one-byte GLOBAL OBJECT
in allocated, nonwritable flash using ELF symbols/section flags, not a letter
heuristic. Failed-link controls are never executed. Link flags do not
use `-u`, whole-archive, allow-multiple-definition or warn-mismatch bypasses.
Whole-program LTO may localize the common data anchor and resolve the selected
weak fallback into a final strong function. The input anchor mismatch still
must fail; the fallback proof requires the real weak common input, no oracle
definition, and the exact final panic body calling the real barrier before wait.

## Provenance And Limits

Before/after SHA256 inputs include the runner, owned fixture files, actual reused
bootstrap/launcher files, profile C/H/linker files, root/shared/common/CMSIS and
GCC headers, compiler/binutils/subprocess binaries and four pinned reference
identity files. Nonbinary input bytes are copied immutably with a verified
original/copy/hash map. Unconsumed sibling NS fixtures and profile prose are not
compiler inputs and are not qualified by this gate. They may evolve independently.
Every command/status, source control, final ELF/map/disassembly/attributes,
dependency/preprocessed/assembly/object file, vector bytes, distinct execution
log/trace and receipt is retained and hashed. Duplicate execution-log paths fail
qualification. Original failures remain recorded even if input drift also occurs.

Reference pin `a50edad08b29052631aa469d4df6e6ec7ff68878` and its four
`GCC/ARM_CM33_NTZ/non_secure` files are identity-checked, not assembled or executed
by this gate. This does not establish FreeRTOS parity, a generic fault-containment
guarantee, hardware behavior or complete TrustZone qualification. The full central
matrix is not launched here; central integration requires an explicit QEMU root.
