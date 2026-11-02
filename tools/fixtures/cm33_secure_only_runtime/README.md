# C3SO Common Runtime Execution Gate

`tools/test_cm33_secure_only_runtime.ps1` builds the real common `fiber_core.c`,
`fiber_runtime_state.c`, weak `fiber_panic.c`, and both production C3SO objects.
There are no fixture reverse-ABI, current-slot, scheduler, barrier, or context
provider substitutes. The application uses all five public operations; its
pick callback implements only policy and observation. The application panic
override is the documented terminal observer, not a scheduler operation.

Required arguments are `-ArmGcc` and an existing absolute WSL `-QemuRoot`.
Optional arguments are `-CmsisCore`, `-FreeRtosRoot`, `-WslDistro` (default
`Ubuntu-24.04`), `-BuildRoot`, `-TimeoutSeconds`, and
`-ExpectedRuntimeSelectable` (default 0 for the staged profile). There is no
download, installation, implicit host fallback, or compile-only success path.

The original 245-execution receipt at
`%TEMP%/cm33-secure-only-runtime-2511c36b61704c9aa04cd97c3d39d0ab` remains
historical baseline/register-pressure evidence, not instrumentation proof.

## Raw Compiler Admission

The mandatory phase enables `-finstrument-functions`,
`-fstack-protector-all`, `-fprofile-arcs -ftest-coverage`,
`-fsanitize=undefined`, `-fsanitize-coverage=trace-pc`, and `-pg` separately
at O2/Os, normal/LTO and both r9 ABIs: 48 raw protected-port executions.
No instrumentation, sanitizer, stack-protector, profiling or coverage
counterflags occur in those compiles. Each unannotated positive probe must
actually acquire the selected family's hooks.

All five real production/common objects are compiled raw. Native LTO
relocatable outputs, not fat-object fallback bytes, check every generated
port body and the explicitly sensitive common functions. Raw ordinary common
init/registration wrappers are not part of the frozen sensitive attribute
contract; their instrumentation is recorded separately in
`raw-outside-sensitive-functions.json`. This includes the registration-only
private storage helper, not a new protected public operation. Function bodies
stop at the next symbol or disassembly-section boundary. Each raw cold public
export must actually retain instrumentation (except UBSAN, which may have no
applicable checks); this is not a whole-common-object hook rejection.

A separate native raw port-only group has an exact eleven-symbol reverse/import
surface: the existing frozen common callbacks/anchors, both address-map hooks,
`memcpy` and `memset`. No unresolved internal port helper is accepted. The raw
whole common/port group separately checks sensitive bodies and rejects any
sensitive-to-cold edge, including from a port function.

Each actual adversarial execution links raw port objects with real common
objects compiled on neutral flags (neither instrumentation enables nor
counterflags), plus neutral application/oracle objects. The resulting native
group must retain exactly the two address-map imports, `memcpy` and `memset`, with no
compiler instrumentation hooks, including resolved gcov code. This is a
whole-port attributes proof and a separate raw common-sensitive generated-code
proof, not a claim that all ordinary common wrappers resist instrumentation.
No fake compiler runtime hooks or reverse providers are linked.

Five current-source compiled attribute-removal controls per build mode include
the hash helper, incoming-r9 inline, CONTROL reader and priority reader, plus
removal of only the hash helper's no-profile attribute to expose `__gcov0.*`
counters. A sixth compiled control adds a cold registration call to the real
sensitive `fiber_current` body; the production-body oracle must reject it.
These give 40 attribute-removal and eight cold-edge controls. Separate metadata
records raw port, common and harness flags, plus repository HEAD attribution
and exact production C/H hashes. HEAD is not a clean-worktree claim. The prior counterflag receipts
remain historical; counterflags are not an accepted ABI policy or fallback.

`-CompilerAdversarialOnly` omits the 245 baseline executions and always records
`CompleteSuite=false`. A full invocation runs both phases. Unsupported
`-fstack-check=generic` probing is not included in the canonical attribute
bundle and is not claimed. Independent whole-group/callgraph auditing and
profile promotion remain parent-owned.

`-AdmissionOnly` runs the four reserved-r9 default-policy lifecycle/link-control
cases (including portable/default and constructor archive proofs), skips the
raw compiler grid and other lifecycle cases, and records `CompleteSuite=false`.
It cannot be combined with `-CompilerAdversarialOnly`; neither focused mode is
a complete-runtime receipt.

## Execution Boundary

The single ELF starts Secure on QEMU `mps2-an505` (Cortex-M33), with vectors at
`0x10000000`, code at `0x10000800`, globals at `0x30000000`, integration MSP
ending at `0x30004000`, and two 8-KiB task stacks above it. No NS image,
SAU/NSACR handoff, MPU enable, or FP enable is supplied. CMSIS describes the
model's physical MPU/FPU honestly; the compiler ABI and port remain scalar
soft-float CMSE 3. Ordinary Secure PSP/PSPLIM are used; distinct NS-bank
markers must remain unchanged. Model priority bits are measured, not assumed.

O2/Os and normal/LTO use reserved-r9 and ordinary AAPCS configurations. Exact
public-entry r9 seed/first-restore checks apply **only** to the complete
`-ffixed-r9` chain, including the additional register-pressure configurations.
Ordinary AAPCS uses hostile compiler options but assigns no static-base meaning
to initial r9: it verifies public callee-save behavior, the actual constructed
frame, and r4-r11 preservation across switches separately. No naked public
wrapper changes the library calling convention.

Positive executions require real common first selection, first Secure SVC70
return with FD, six Secure PendSV FD returns (A-B-A-A-B-B-A), same-context
restores, actual `fiber_current` publication, masks, PSPLIM and GP captures,
and actual common task return. PendSV is requested directly by scheduling;
this is not an SVC-yield tailchain claim. Address-map-on-switch and
preserve-current-MSP policies have separate positive executions. Default
canary/hash validation stays enabled and permissive map hooks stay disabled.

Negatives check missing/null policy, null candidates, first-callback CPU drift,
bad hash, bad saved EXC_RETURN, bad alignment, Thread mask admission, foreign
SVC origins, pre-start PendSV, a CPU-drifting map hook, and foreign/stale boot
ABI identities with recomputed valid hashes. Each expects an exact panic code,
phase, exception number, callback count, and current-context state. Each run
must exit zero under a strict timeout with exactly one expected final marker;
faults, nonzero exits, timeouts, and diagnostic substrings cannot count as PASS.

## Build Controls And Provenance

The four O2/Os, normal/LTO admission cases additionally compile the unchanged
`tools/fixtures/portable_application.c`. They rebuild the actual common and
selected-port objects without scheduler BASEPRI, rewind or validation policy
overrides. Direct and ordinary archive final links check the five public
imports plus the exact storage cohort, public-only compiler dependencies,
strong vectors, live v1/private/storage providers and scalar generated code.
A retained seven-word policy section proves the actual compiled defaults:
priority-derived nonzero BASEPRI, rewind=1, map-on-switch=0, boot hash=1,
canary=1, permissive hooks=0, and the expected runtime-selection metadata.
The application translation unit gets no fixture or CMSIS include path.
These eight final ELFs are explicitly link-only evidence, not new executions.
LTO may inline the ordinary cold `fiber_init` and registration wrappers; all
five definitions are checked in their real common owner and all five imports
in the unchanged application input. The sensitive public bodies and port
constructor remain required in each final ELF.

The gate checks the exact eight generic providers and their production owners,
real private and public storage cohort objects in read-only Secure flash,
strong vector bindings, direct and ordinary archive extraction with weak
startup defaults, GC and LTO. Negative links require specific undefined or
duplicate symbols: missing v1, missing cohort, mixed BASEPRI configuration,
wrong explicit build expectation, synthetic stale storage revision, missing
boot/runtime, and duplicate SVC/PendSV. Default weak panic is linked and its
real barrier-then-wait body checked, but its infinite wait is not executed.

Constructor-only execution has no first-start or production handler roots.
The unmodified constructor rejects a v2-only common object. A compiled
current-source control removing only its v1 read must link and execute with
that same object; this proves sensitivity without opaque prebuilt archives.
The same four build modes also place the real common objects (renaming only
the common anchor definition to v2) and the real selected-port objects in
ordinary static archives. The constructor-only archive link must fail solely
on the missing v1 anchor, diagnosed in `fiber_port_context_init`; no failed
ELF is admitted. Removing only the constructor's anchor read in a compiled
port-archive control must instead link and execute. Its final symbols must
contain neither the v1 object nor first-start/production-handler roots.
A separately compiled single-store r9 seed-corruption mutant must reach the
constructor's exact one-shot panic before first selection, only in reserved
ABI modes. These are labeled controls, not unmodified production executions.

The output retains commands, source copies, preprocessed/assembly/dependency
files, objects, archives, final ELFs, maps, disassembly, vectors, QEMU output,
exception traces, and artifact hashes. Input copies and before/after hashes
cover the runner, fixtures, production/common/shared/profile headers, CMSIS,
compiler system headers and compiler/binutils programs. The actual compiler
dependency census must be covered by that inventory. QEMU and its resolved
dynamic libraries are hashed before and after; identity/version/model/WSL
records are retained. Input drift fails the receipt.

The initially qualified isolated package is Ubuntu QEMU
`1:8.2.2+ds-0ubuntu1.18` (upstream 8.2.2); every invocation records the actual
binary and dependency hashes instead of trusting that label. The pinned
FreeRTOS identity is `a50edad08b29052631aa469d4df6e6ec7ff68878`; the four
GCC/ARM_CM33_NTZ/non_secure source identities and tracked diff are recorded
as comparison provenance only. This runner neither executes FreeRTOS nor
compares its assembly. Tesla's separate parity gate owns that claim.

No hardware, FP/MPU stress, full TrustZone isolation, all-port, runtime-selection
promotion, or arbitrary corrupted-MSP fault-containment claim is made.
