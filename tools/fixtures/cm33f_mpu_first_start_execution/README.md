# Actual CM33F MPU First-Start Execution

This standalone regression executes the ARM_CM33F_MPU constructor and
SVC70 first-basic-restore component on QEMU `mps2-an505` (Cortex-M33). It does
not select a complete Fiber runtime or provide a scheduler implementation. It
links the real production PendSV and SVC71/72 veneers for compatibility, without
executing them or claiming their running behavior.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/test_cm33f_mpu_first_start_execution.ps1 `
  -ArmGcc <existing-arm-none-eabi-gcc.exe> `
  -QemuRoot /absolute/existing/isolated/qemu/root
```

Optional parameters: `-CmsisCore`, `-FreeRtosRoot`, `-BuildRoot`, `-WslDistro`
(default `Ubuntu-24.04`) and `-TimeoutSeconds` (default 10, maximum 60).
The root must already contain `usr/bin/qemu-system-arm`; no downloads,
provisioning, package installation, root access or global configuration changes
are supported. Missing tools fail rather than skip a maintained test.

## Real Secure Bootstrap

A separate Secure ELF starts in Secure state, assigns AN505 SSRAM/internal SRAM
blocks through their actual MPC registers, configures real SAU regions and
NSACR CP10/CP11 Non-secure access, targets IRQ0 Non-secure for the production
priority-width probe, sets the real Non-secure VTOR/MSP/CONTROL/limits and
branches with `BXNS`. It is a fixture bootstrap, not a SecureContext companion
or NSC operation. The NS image never includes Secure private/runtime headers.

The model probe reads actual MPU_TYPE, MVFR0 and the implemented IRQ0 priority
mask before compiling the matching CMSIS priority-bit fact. With the qualified
QEMU 8.2.2 model these are eight MPU regions, MVFR0 `0x10110021`, and priority
mask `0xff` (eight bits). IRQ0 is not enabled or deliberately raised. Registers
are not mocked or overwritten with fabricated geometry/feature observations.

The address policy is entirely fixture-owned:

| Role | Range (Exclusive End) |
| --- | --- |
| Secure bootstrap code alias | `0x10000000..0x10010000` |
| NS privileged code/vectors | `0x00010000..0x00020000` |
| NS unprivileged code | `0x00020000..0x00028000` |
| NS production service veneers | `0x00028000..0x00029000` |
| NS current-context RO aperture | `0x20004000..0x20004020` |
| NS privileged RW/MSP | `0x20004020..0x20006000` |
| NS unprivileged RAM | `0x20006000..0x20008000` |
| Exact task stack allocation | `0x20006000..0x20007000` |

The full 2048-byte NS vector span lies in privileged RO code. Startup zeros
the separate current-slot section and privileged BSS separately. The fixture
supplies the readonly reverse-v1 marker and common-owned current slot explicitly;
the actual production SVC object alone defines the exact context/storage cohort
pair. Object and final-ELF checks require that ownership; no fixture supplies
any forward adapter, bundle or cohort provider. This direct concrete-type
allocator includes the mandatory storage-expectation header; the board script
retains its relocation under section GC.
The board layout also consumes the actual production linker-contract fragment.
The real SVC and PendSV handlers occupy vector slots 11 and 14. The fixture does
not supply the cold component anchor: first-start preparation reaches that
strong function in the real separately compiled PendSV object, which retains
the reverse-v1 and context identities off the PendSV hot path. This dependency
is not a complete runtime-provider claim. The fixture does
not shadow the production task-return veneer: its reverse task-return policy
is `fiber_panic('R')`, as in common `fiber_core.c`. Candidate selection is
terminal `'K'` because no scheduler is configured; the publication provider
checks nonnull and brackets the current-slot store with barriers. These
reverse dependencies, and a faithful checked current-context guard, are linked
for the real components, not exercised by this subset. Production placement also
requires the public current/schedule addresses. Explicit C fixtures named
`fixture_unexecuted_fiber_current`/`fixture_unexecuted_fiber_schedule` expose
those assembler spellings as terminal UDF73/UDF74 loops, never as working common
runtime operations. The private first-start bridge remains the exercised entry.

## Execution Oracle

At `-O2` and `-Os`, for hard and softfp scalar single-precision ABIs:

1. Run the actual constructor while MPU is disabled; check its initial basic
   CONTROL `3`, EXC_RETURN `0xffffffbc` and sampled r9. Change live r9 after
   construction so restoration cannot pass by merely inheriting that value.
2. Publish the fixture context, call the actual first-start function and execute
   the owned `SVC #70` (`46 df`) through the actual selected SVC_Handler and
   dispatcher. The startup origin is basic NS Thread/MSP `0xffffffb8`.
3. The actual unprivileged task uses a naked assembly first instruction to save
   r0-r12/LR on its mapped stack before consuming any scratch register. It
   captures physical SP and CONTROL, and reads the real current-slot aperture.
4. The task deliberately issues `SVC #255`. The expanded handler admits the
   PSP-origin `0xffffffbc`; the privileged dispatcher rejects the unowned
   service site with code `'u'`. The fixture requires that exact terminal code,
   without claiming service71/72 execution or an application task-return path.
5. Privileged fixture panic inspects the actual terminal frame and live
   PSP/PSPLIM, Handler CONTROL, masks, CPACR/FPCCR, MAIR0 and all eight MPU
   RBAR/RLAR pairs. Unprivileged reads of privileged-only registers are not
   treated as observations of those registers. The oracle checks raw address,
   AP/XN, MAIR `0x04ff` and exclusive-end RLAR constants independently, without
   asking production map/encoder helpers to validate their own output.

Initial r0 is `0x13572468`, r9 is sampled `0x55667788`, LR is the real production
SVC72 veneer, and the other initial general registers are zero. Task CONTROL is
exactly `3`; Handler exception entry yields CONTROL `1`, not a supposed universal
Handler RAZ rule. Initial task SP is `0x20007000`; after the 56-byte capture and
32-byte terminal basic frame, PSP is `0x20006fa8`, with PSPLIM `0x20006020`.
The terminal frame proves Thread IPSR zero, Thumb state and no alignment padding.
The cursor must advance back to the beginning of the protected basic image.

Each mode also executes five intentional rejection cases:

- Corrupt initial CONTROL to `2`: startup rejects with panic `'q'`, no task.
- Do not publish current context: actual first SVC rejects with `'C'`, no task.
- Issue privileged SVC70 from an unowned code site: reject with `'u'`, no task.
- Attempt an unprivileged read of private context storage: actual MemManage,
  CFSR `0x82`, exact MMFAR and faulting instruction PC.
- Attempt an unprivileged write to the readable current aperture: the same
  actual access-violation checks, while the legitimate read has succeeded.

The model must report eight regions. All four r16 ABI/optimization combinations
are compiled and linked but are **not executed** or called a hardware result.
The runner does not force MPU_TYPE, emulate extra regions or silently skip r8.
The original six cases and their 120 runner checks are preserved. Separately,
28 ELF compatibility records require unique strong production handlers in the
actual vector image and real service71/72 opcodes with exact global post-SVC
sites, plus the strong real cold component anchor, bundle, all eight real forward
operations, first-pick helper, exact production providers and adapter placement.
The promotion flag is now one after the separate complete-group gate. These records alone are not
additional running-service execution scenarios.

## Pinned Comparison And Evidence

Comparison source is local FreeRTOS-Kernel
`a50edad08b29052631aa469d4df6e6ec7ff68878`, GCC `ARM_CM33_NTZ/non_secure`:
`port.c` constructs unprivileged CONTROL `3` / initial `0xffffffbc`; the MPU
`vRestoreContextOfFirstTask` in `portasm.c` loads MAIR0, RNR4 alias blocks
(RNR8/12 for 16 regions), PSP/PSPLIM/CONTROL, copies the basic hardware frame
onto PSP and restores integer state before exception return. Fiber additionally
checks its sealed maps, exact SVC provenance, CPU state and readbacks. Reference
debug register seeds differ from Fiber's zero/live-r9 policy. This runner records
the exact pin and hashes and rejects tracked changes in the four inspected
reference files; it does **not execute** the reference or claim a full dependency
comparison. The receipt states `ReferenceIdentityChecked=true`,
`ReferenceAssemblyCompared=false`, and `ReferenceExecuted=false`;
`ReferenceAssemblyRunner=test_cm33f_mpu_first_start_codegen.ps1` identifies
Dalton's separate generated first-start parity runner, not a comparison run here.

QEMU's [MPS2 documentation](https://www.qemu.org/docs/master/system/arm/mps2.html)
identifies AN505 as Cortex-M33. Its
[8.2.2 board source](https://gitlab.com/qemu-project/qemu/-/blob/v8.2.2/hw/arm/mps2-tz.c)
describes the SSRAM/MPC layout and IoTKit integration. Model observations above
come from actual execution, not an inference from those documents.

Every run preserves exact command arrays/exit codes, tool and QEMU identity/hash,
WSL identity, model facts, source before/after hashes, preprocessed sources,
assembly, dependencies, objects, ELFs/maps/symbols/attributes/disassembly, QEMU
logs, per-case execution/compile-only status, checks, receipt and artifact hashes.
Each QEMU process has a strict timeout and must exit zero with exactly one
expected terminal marker, with no failure/fatal/timeout diagnostics. Input drift
fails qualification. Only a complete grid prints final `PASS`.

This is NS first basic restore plus bounded rejection/isolation evidence. No
PendSV, scheduling, full public runtime, FP instructions or extended/lazy frame
stress, application task return, complete TrustZone system, or board behavior is
qualified. FPU access/configuration and inactive basic-frame state are checked;
no FP save/restore claim follows from hard/softfp compilation.
