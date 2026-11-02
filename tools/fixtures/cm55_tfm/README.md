# C5TF Independent Consumer Gate

Run `tools/test_cm55_tfm.ps1 -ArmGcc <gcc> -CmsisCore <CMSIS Include>`.
Optional parameters: `-BuildRoot`, `-FreeRtosRoot`, `-HostGcc`, `-Python`,
`-QemuRoot`, `-WslDistro` (default `Ubuntu-24.04`),
`-ExpectedRuntimeSelectable` (0 or 1, default 1).
The last parameter checks the selected source's exact metadata, not an override
or a way to activate a staged runtime. Its matching manifest and opposite-value
negative compile even with `-R9Only`. Receipts report the verified value.
`-R9Only -QemuRoot <existing-prefix>` runs only the focused dual-ABI R9 grid.
Host GCC is mandatory: explicit `-HostGcc`, then PATH, then the existing
`C:\msys64\ucrt64\bin\gcc.exe` fallback. Nothing is
downloaded or installed. This gate never programs hardware.
The selected host compiler's bin directory is added to the child proof PATH
for compiler-helper/runtime DLL loading; the caller's PATH is restored afterward.

## Target Evidence

The gate compiles the actual twelve-file C5TF group (four production C units)
and the real common core/state/panic with default scalar Cortex-M55 soft-ABI
flags, at O2 and Os, with and without LTO. It does not use a Cortex-M33 object
as M55 evidence, nor disable default low-overhead-loop code generation.

Allocating C and C++ consumers include only `fiber_core.h`, use static
contexts/stacks, provide an external round-robin callback, and use the five
portable calls. Public and common objects compile without a CMSIS include
directory. Exact consumer undefined sets contain only the five operations and
the explicitly derived storage identity. The archive contains real common plus
the complete port group; constructor-only controls separately exercise port-
archive extraction. Both direct and archive links retain
strong real SVC/PendSV vector entries and every storage expectation contribution;
the expectation section is not assumed to be four bytes.

Role checks precede final linking. CPU+boot has an exact base reverse/hooks/memory
dependency set plus only the two named private TF-M prestart dependencies
(`fiber_port_tfm_require_initialized` and the integration-bundle anchor).
It may not import the public `fiber_current` operation. The initializer imports
exactly `fiber_panic` and `tfm_ns_interface_init`; the mutex wrapper imports
exactly `fiber_current`, `fiber_panic`, and `fiber_port_runtime_schedule`.
These per-role checks supplement, not replace, the combined-group proof.
LTO IR omits assembly-only references and lowered memory calls, so every LTO
role is also lowered to native relocatable code and checked against the full
native dependency set. Every original port object is checked for any definition
of common-owned services/storage, including weak definitions, before a strong
common provider could hide it. Other weak port providers are forbidden too.
Actual compiled controls add `fiber_current` to real CPU source and a weak
common reverse anchor; each must fail its specific role check at O2/Os with and
without LTO.

Checks include the frozen eight-operation forward surface, exact expected
runtime-selectability (currently 1),
C5TF identity/layout/features/storage, derived private-policy cohorts, generated
prestart call order, and exact readonly one-byte reverse-v1 cold reads in both
construction and prestart preparation. A compiled constructor mutant with a
decoy context-cohort byte read must fail the reverse-v1 read oracle. Constructor-
only archive links also require v1; missing/wrong-v1 controls keep real common
callbacks/state and rename only the marker.

Real negative links cover stale M55_NTZ and M33_TFM allocating C/C++ consumers,
missing external TF-M initializer, missing mandatory adapter units, mixed
constructor/runtime private policies, and duplicate complete strong providers.
Manifest negatives check intended diagnostics rather than accepting any compiler
failure. Predefining `FIBER_PORT_RUNTIME_SELECTABLE=1` is still rejected even
when 1 matches the selected source. Foreign CM4/CM33/CM33F MPU region macros are rejected on presence,
including empty, zero, 8/16, negative and nonnumeric values. Final ELF
attributes and disassembly are recorded; ordinary FP/MVE
instructions, unexpected compiler dependencies and fiber SecureContext symbols
are forbidden. This is not a full byte-complete CPU frame-transfer parity proof;
the independent actual FreeRTOS M55 assembly gate owns that obligation.

`provider.c` and `tfm_v2_boundary.h` are explicitly test-only typed external
integration providers. They model the TF-M v2.0 initializer/mutex signatures
and references, not PSA/SG execution. `memory.c` supplies scalar freestanding
memory operations, not missing runtime callbacks. A real integration must use
the actual TF-M v2.0 NS interface sources/headers and Secure veneer import, with
`TFM_NS_MANAGE_NSID=OFF` as required by the pinned ARM_TFM README. No real TF-M
checkout is present here, so none of that Secure integration is qualified.

## Host Adapter Evidence

The host gate compiles source-derived copies of the actual initializer and
mutex adapter. It substitutes only the private CPU observation header, the
equivalent public-declaration include path, and the two ARM PRIMASK primitive
bodies. All lifecycle/mutex logic is unchanged. Original/replacement primitive
bodies and hashes are recorded in each build. The untouched production sources
are separately compiled for M55 by the target grid.

Each host scenario starts a fresh process/BSS at O2/Os with/without LTO and
NDEBUG. Explicit checks, not C/Python assertions, test one-shot success, READY
idempotence, external failures/sticky rejection, reentry, exact six-field CPU
leak detection, admission-before-effects and valid retry after admission rejection.
Native host pointer sizes are not evidence of target storage/frame geometry;
that is checked only in actual M55 objects. Mutex cases cover static
create/delete/recreate, invalid handles, current-owner
identity, recursion, foreign release, owned deletion, free acquisition for any
timeout, contended finite/zero timeouts returning ERROR without yielding, and
WAIT_FOREVER yielding to a fixture callback which releases the actual mutex.
Mask boundaries are substituted observations, not executed ARM instructions.
Panic interception is a test harness facility, not a recoverable production API.

Compiled adapter mutants must hit named failed checks. Receipt classifier
controls reject bad exit, missing/duplicate report, unrelated exit and timeout.
The host scheduler callback is explicitly a cooperative boundary substitute;
these tests do not execute Secure TF-M, a real exception return, Thread/PSP
scheduling or a physical no-FP M55.

## Actual R9 ABI Probe

An explicit `-QemuRoot` enables the maintained mps3-an547 Cortex-M55 probe through
the existing isolated WSL QEMU prefix. Only `inspect` and `run` of the shared
`arm_control/qemu.sh` are used; there is no provisioning. Without a prefix the
runner prints `NOT_RUN` and records that R9 execution is not qualified.

A fixture Secure bootstrap attributes code/RAM to Non-secure and enters
privileged NS Thread/MSP. It exposes no NSC service and executes no TF-M code.
An independent first execution writes/reads/restores an NS IRQ priority byte to
measure the model's implemented priority mask. AN547 reports `0xff` (eight bits);
all execution C units use that measured `__NVIC_PRIO_BITS`. The static link grid
uses its separate three-bit fixture configuration. Real production priority
validation remains enabled, not bypassed to accommodate the model.
The real public `fiber_init`, real common code and complete C5TF group are
separately compiled at O2/Os, normal/LTO and effective hostile flags in two
explicit modes, following the frozen contract in `DECISIONS.md:1576-1588` and
`ARM_CM3_MPU/FREERTOS_PARITY.md:168`:

- Reserved R9: `-ffixed-r9` on the complete common/port/compiler-boundary/hook
  chain, including LTO link. Four independent caller sentinels must match both
  software-frame word7 and post-return R9. Reserved hooks never borrow R9 while
  calling C: their complete emitted bytes are checked for read-only R9 use and
  the exact C call target. Reserved assembly tasks do not reload the seed after
  first restore. `-ffixed-r9` alone cannot constrain handwritten assembly.
  This qualifies the deliberate reserved-register mode, not default
  ordinary ABI code generation or a physical platform's complete static-base ABI.
- Ordinary AAPCS: post-return R9 must match the caller sentinel. The initial
  frame's R9 has no caller-entry/static-base meaning. Hooks may temporarily use
  R9 and restore it per AAPCS. A separate legal caller-scratch positive control
  keeps a different R9 value live across the constructor and must still pass.

Both modes independently check the complete initial scalar frame, stack bounds,
PC/argument/xPSR, zero-register policy, origin/masks and actual hook execution.
The production explicit-seed builder and constructor consistency assertion stay
enabled. Ordinary mode does not replace that consistency contract with any
arbitrary accepted value; it declines only the nonspecified caller-derived
initial value requirement.

Two constructed contexts then run through the actual strong first-SVC and four
real PendSV switches using real common scheduler/current state. Initial restore
must match the recorded frame image in either mode. Ordinary tasks establish
known live R9 values; reserved tasks retain their reserved sentinels. The external
round-robin selector independently checks the actual saved slot and subsequent
task resumes check the restored live register. PSPLIM, exception token, masks,
frame bounds and exact owner/switch counts are checked. The automatic TF-M init
calls a typed test-only provider once, which uses the actual mutex-create wrapper.
No Secure TF-M, PSA/SG or real TF-M checkout is exercised.

Hostile flags are `-finstrument-functions -fstack-protector-all -fprofile-arcs
-ftest-coverage -fsanitize=undefined -fsanitize-coverage=trace-pc`, without
counter-options, on all production common/port units. Explicit test-only
compiler-boundary fixtures count instrumentation/coverage/gcov registration;
stack/UBSan failures and unneeded gcov runtime calls terminate, not silently
succeed. The probe does not qualify those fixtures as production compiler
runtimes.
The same hostile flags are applied at LTO link, where GCC lowers sanitizer
coverage. Hostile compiler-boundary fixtures are native separately compiled
objects so link-time instrumentation cannot recursively instrument its own
test helpers; the Secure bootstrap is always a native object in Secure flash.
A reserved wrong-frame compiled mutant must hit the exact production constructor
panic9, with the known wrong slot and a call site inside the constructor; no
caller resumes. Ordinary compiled controls separately violate caller preservation,
corrupt the real PendSV save slot, and corrupt the real PendSV restore register.
Each must fail its exact independent check, not timeout or an arbitrary fault.
Negative reports must contain exactly the constructor/event prefix appropriate
to their intended failure, with the expected exit code and no extra output.
The test overrides only the documented weak panic policy to emit exact terminal
evidence. No switch handler, scheduler or forward/reverse runtime provider is
replaced by a fixture.

This is bounded actual M55 NS construction and SVC/PendSV R9 execution, not a
complete runtime, PSA/SG, real TF-M Secure-image or physical no-FP proof. ELF/object maps,
symbols/disassembly, commands, exact reports and QEMU/loader-library hashes are
preserved. No prior A01 or sibling-port result substitutes for this probe.

`r9_history.json` classifies prior unmodified raw failed receipts as stronger-
oracle mismatches: all their tuples used ordinary AAPCS but required initial
caller-seed equality. The observed codegen/data remains valid; those results do
not establish a violation of the reserved-R9 ABI. Old receipts are immutable,
not rewritten as PASS. New dual-mode results must qualify independently.

## Receipts

Every invocation gets a unique preserved artifact directory. Commands, exit
codes, elapsed times, maps, ELF attributes, symbols/disassembly, generated
sources, negative classifications and before/after source/tool/header hashes
are retained. The three consumed Markdown inputs (this README, the C5TF ledger,
and pinned ARM_TFM README) are snapshotted byte-for-byte with a source/hash index;
unrelated mutable repository root docs are not treated as consumed inputs.
The local FreeRTOS reference must be exactly
`a50edad08b29052631aa469d4df6e6ec7ff68878`, with no tracked or untracked changes,
before and after. Actual M55 source and ARM_TFM wrapper/README hashes are evidence
inputs, not a claim that the real Secure TF-M provider was executed. Any input
drift, failed build, missing test dependency or unclassified negative fails.
