# CM4 MPU Context Pilot

This is an unqualified development fixture, not a full runtime qualification.
The launcher defaults to compile preflight, which invokes neither WSL nor QEMU.
Execution requires the explicit `-ExecutePilot` switch and a separately
approved existing QEMU root. Every receipt has `CompleteSuite=false`.
Both Python's finalizer and PowerShell independently require the exact ordered
six consumer/case rows and the separate model. Compile mode requires every row
and model to remain COMPILED/Executed=false, with no execution evidence.
Execution mode requires all seven to be PASS/Executed=true with terminal
evidence and actual model facts. The requested mode fixes Verdict/Execution;
compiled-only rows cannot receive a pilot execution PASS. Fifty-three synthetic
orchestration controls include all six individually skipped executions and the
skipped model; they are not target execution evidence.
Both closing contracts require the exact boolean
`ArtifactsVerifiedBeforePass=true`. Finalization persists FAIL/false first,
verifies artifacts, and only then publishes the candidate success receipt and
verifies its final manifest. Any failure in either verification rewrites
FAIL/false and preserves a best-effort failure manifest. Four controls call the
actual finalizer with only reference/drift stubs: success, first/final manifest
failure injection and a prior run error. They perform no CPU/tool execution.

The pilot inventory is Context/FiberV1, O2, ordinary native direct links,
hard-float Cortex-M4, eight MPU regions, eager FP policy and FP-inactive tasks.
For each consumer it builds a return case, a current-aperture store fault and
a peer-stack read fault. The separate model image reads CPUID, MPU_TYPE,
MVFR0 and the actual IRQ0 priority mask, restoring the original priority byte.
Execution must reject model facts different from the compiled manifest before
running any application image. Register readback is not itself enforcement.

The real selected two-source ARM_CM4_MPU engine owns all eight operations and
both strong SVC/PendSV handlers. The source recipe selects the actual Context
engine/state/panic roles. Only FiberV1 adds optional configuration and the real
lifecycle consumer; no legacy shim, fake reverse service or cohort provider is
linked. The build-owned expectation is a separate actual source/object. Context
retains eight read-only bytes (one context and one storage pointer). FiberV1
retains twelve: its separately compiled lifecycle consumer adds a second storage
pointer. Both exact pointer multiplicities are checked, not inferred as a
golden value from the linked subject.

## Address Contract

| Range | Role |
| --- | --- |
| 00000000..00000008 | RO bootstrap MSP and Reset words |
| 00000400..00000800 | Nonzero active 1024-byte RO vector table |
| 00000800..00010000 | Privileged RO code |
| 00010000..00020000 | Unprivileged code, constants and complete current/yield call chains |
| 20000000..20000020 | Separate 32-byte current aperture: privileged RW, user RO |
| 20002000..20003000 | Exact worker A stack |
| 20004000..20005000 | Exact worker B stack |
| 20008000..20010000 | Privileged metadata/data and reserved MSP |
| 2000E000..20010000 | Reserved MSP, disjoint from metadata |

Both tables carry the same MSP and Thumb Reset values. Startup installs VTOR
at 0x400 before entering fixture_main. Linker assertions and final ELF audits
check both section/symbol placements, reset words and the actual literal-load,
VTOR-store, DSB/ISB startup sequence. The selected port deliberately requires a
nonzero VTOR before its C vector-table reads; the pinned FreeRTOS MSP rewind
uses assembly instead. This is a fixture admission contract, not a claim that
address-zero vectors are universally invalid. The first CPU attempt with
VTOR=0 remains a failed receipt; it reached panic V before priority setup or
MPU/task execution and is not relabeled by this fixture repair.

Startup zeros the current section separately. Privileged setup clears the task
stacks explicitly; no initial RAM contents are assumed. Each task records only
to its own stack mailbox. Task arguments are immutable user-readable constants.
The scheduler hook reads the mailboxes in privileged mode without changing MPU
RNR or masks. It performs NULL-first selection, one self-selection and six
cross-selections. Worker A returns after four real public yields. Its original
constructor-seeded return address must enter the production SVC72 veneer;
the actual common return policy calls the application panic terminal with R.

The return terminal requires real SVC IPSR11, the exact stacked production
return-site PC, basic PSP frame bounds, current identity and exact selection
counts. Return and fault terminals both report stacked xPSR. Firmware and host
require Thumb/Thread xPSR, eight-byte-aligned frame PSP and containment of all
32 core-frame bytes plus four bytes when xPSR.STKALIGN is set. Thus PSP
20002FE0 is valid without padding but rejected with padding; 20002FD8 admits
the padded frame. These are parser boundary controls, not observed CPU events.
Each isolated MemManage case requires IPSR4, EXC_RETURN FFFFFFFD,
CFSR 82, HFSR zero, the exact compiled access PC, MMFAR target, Thread xPSR and
the worker A PSP frame. Generic faults/timeouts/nonzero exits are not PASS.
The known semihost terminal channel is stderr exclusively: stdout must be
empty, both streams must be strings, and split-channel/counterfeit terminals
reject for both the model and consumer images.

## Evidence Limits

The preflight captures native objects, dependency files, provider relocations,
maps, final ELF bytes/vectors/placements, exact cohorts, actual common owners,
the no-FP Thread call closure, commands and tool/source/artifact hashes.
All object/symbol inspections invoke the absolute sibling
`arm-none-eabi-nm.exe`, enrolled before inspection and in the refreshed initial
input snapshot. The inherited unused gcc-nm/ar enrollments do not imply their
execution or an LTO qualification.
The installed QEMU binary/library closure is inspected before/after only in
execution mode. No provisioning code is called.

Existing pinned FreeRTOS ARM_CM4_MPU object evidence remains owned by
`tools/freertos_asm_parity.ps1` (SVC-dispatch, first-restore, PendSV-MPU) and
the port's parity ledger. The pilot records the actual reference commit and
source hashes and checks bounded mechanisms in its own final native providers.
It neither runs FreeRTOS nor claims new paired final-ELF/LTO reference parity.
A later 16-configuration qualification must explicitly associate its final
native/LTO provider evidence with the applicable maintained reference mechanism
proof, or add separately reviewed actual reference ELF associations.

FP-active/lazy switching, all four hash/map policies, 16 regions, CM7, softfp,
other optimization modes, board behavior, whole-provider parity and CI are not
qualified here. No automatic compile-matrix dispatch is added.
