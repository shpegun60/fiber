# C55S Actual Common Runtime

## Public And Default Admission

`tools/test_m55_secure_runtime_admission.ps1` composes the complete existing
runtime gate with maintained public/default/constructor-archive admission.
It accepts `-ArmGcc -CmsisCore -QemuRoot -WslDistro`, optional `-BuildRoot`,
`-FreeRtosRoot`, `-Python`, and `-ExpectedRuntimeSelectable 0`. It never
changes the production profile or permits metadata promotion.

Before any build it copies the consumed repository/CMSIS inputs into a
read-only source snapshot and makes a local, non-hardlinked sparse FreeRTOS
checkout of the exact pin. The sparse checkout contains `include` and the
actual M55 reference branch, not a substituted implementation. Tracked and
untracked cleanliness are required before and after. Stable external compiler
tools/headers are hashed before/after. Source/snapshot mappings, commands,
source/tool hashes and contemporaneous artifact hashes are retained.
The actual `gcc -### -flto` linker-plugin path must agree with its compiler
query and exist; `liblto_plugin.dll` is a required before/after input. Missing,
duplicate and nonexistent plugin plans, plus an omitted manifest row, are
maintained rejection controls, not changes to the installed toolchain.
Nothing is downloaded or provisioned; the stopped unrelated reference task is
not an input.

The static phase compiles the unchanged shared `portable_application.c` as C11
and C++17 without CMSIS, device, private runtime or optional SecureContext
headers. Its exact imports are the five public calls plus its derived public
storage token. The C-only fixture's `static _Alignas(8)` spelling is mapped to
GCC's aligned attribute in C++ only; this is not a library-user macro. Final
stack sizes/alignment are checked. Direct and full static-archive GC links use
actual common/NS objects and imports generated from the three actual Secure
production units. The static Secure root program is not executed; it is not a
bootstrap or a fake runtime provider.
The include closure is an exact eleven-header repository allowlist. A real
compiled declaration-only optional-header leak must be rejected even though
its public undefined-symbol set is unchanged. Explicit optional-header use by
an application remains supported; this control targets the plain five-call
consumer contract, not opt-in users.

Constructor-only C/C++ archive tests run O2/Os native/LTO, with no optional
attachment call, handlers, scheduler or Secure provider retained. Current
common must link and contain the constructor's actual cold readonly one-byte
reverse-v1 read. The incompatible common model removes only the real v1 marker
definition; it is not presented as an entire historical checkout. It must fail
solely for that missing marker. Every diagnostic line must be a recognized
function context, exact undefined reference, or final collect2 summary; unknown
or mixed failures are rejected. Controls exercise the real link method with
synthetic mixed diagnostics and a compiled missing-v1-plus-RAM-overflow program.
Removing only the actual constructor retain
must make the same stale archive link successfully with no v1 marker. This is
an explicitly unexecuted causal control, never a production configuration.

Default-policy observations independently read nine actual target constants:
eager FP policy, MSP rewind, hash1/map0, no permissive hooks, enabled canary,
32-byte redzone, model-derived BASEPRI and metadata0. A compiled hash0 control
must fail only the observer's default-hash assertion; hash0 remains a supported
explicit production policy. Separate no-policy-override images execute all
five original positive scenarios in O2/Os native/LTO, direct/archive and both
ordinary/reserved NS r9 modes: 80 additional launches. They reuse real common,
the real paired Secure provider, actual handlers and the existing runtime
oracle. They are not TF-M execution.

Final `CompleteSuite=true` additionally requires the unchanged existing 2,490
runtime launches and one model probe, with no `Development*` argument supplied
to that runner, plus all 80 new default launches and static admission. Thus
the composed complete execution inventory is 2,571 launches. Its original
runtime evidence remains closed; extra defaults use separate command logs and
cannot invalidate that runtime's final SHA256 inventory.
`-DevelopmentAdmissionOnly` and `-DevelopmentDefaultOnly` are development
preflights only and always force `CompleteSuite=false`. No subset PASS is an
activation qualification. No full composed qualification is claimed merely
because these new files exist; inspect the invocation's final receipt.
Receipts from before these diagnostic/plugin checks remain evidence for their
recorded source version only. Focused development replays do not retroactively
qualify that older full run or replace a fresh complete invocation.

`tools/test_m55_secure_runtime.ps1` runs the actual five-operation common API,
all eight selected-port forward operations, real common reverse ABI/state,
and actual C55S Secure gateway/pool in two images on the existing AN547 QEMU.
It neither fabricates common/cohort providers nor promotes RuntimeSelectable.
Application panic, address hooks, scheduler and one Secure work SG are fixture
providers, explicitly separate from the actual twelve production gateways.

## Invocation And Inventory

Supply `-ArmGcc -CmsisCore -QemuRoot -WslDistro`; `-BuildRoot` and
`-FreeRtosRoot` are optional. QemuRoot is an existing absolute WSL prefix.
The runner uses its extracted libraries and firmware directory, installs
nothing, and fails for unavailable tools, timeouts, missing reports, unknown
stops, unexpected faults or source drift. There is no forced-include option.

The full inventory is 2,490 runtime QEMU launches plus one actual priority-mask
model probe, not a claim that every case has a Cartesian product of all flags:

| Cases | Variants | Launches |
|---|---|---:|
| Five zero/attached/mixed NS/S-origin positives and ten paired hash/map controls | Ten codegen modes x four policies x two NS/common r9 modes | 1,200 |
| Seventeen lifecycle/API precedence and twenty actual-MSR CPU guards | Ten modes, policy00, ordinary r9 | 370 |
| Eighty pointer/frame/provenance/pool/partial-gateway/query controls | Ten modes, policy11, ordinary r9 | 800 |
| Actual common weak panic and actual port terminal wait, all eight operations live | Ten modes x two r9 modes, policy00 | 20 |
| Eight actual selected-source mutants and two compiled fault-record mutants | Ten modes, policy00, ordinary r9 | 100 |

The modes are O2/Os, optimized LTO, archive+GC, archive+GC+LTO, and hostile O2/Os.
All links use section GC. Normal runtime archives use linker groups, not `-u`
or whole-archive. Ordinary/reserved r9 applies to NS/common only; the Secure
image always uses the standard CMSE ABI. Any `Development*` parameter forces
CompleteSuite=false, even when the chosen subset passes. The final executed
inventory must match the planned case/mutant identities exactly.

## Oracles And Link Proofs

Numeric expectations cover the complete 19-word cold image, inherited r9,
512-byte allocation request/owner, three-slot 3,168-byte pool, independent
handle/stack/seal geometry and all eight C55S query values. Live observations
cover actual public-schedule ICSR stores, SVC first restore, six PendSV switches,
Secure Thread interruption, observed BC/FC EXC_RETURN, NS/S PSP/PSPLIM, complete
GPR/flags transfer, common-owned publication, and protected first-NULL scheduler.
The first scheduler sees prepared CPU priorities/STKALIGN, not fixture setup.

Policy00 is explicitly selected, not described as an unoverridden global
default: current shared defaults are hash1/map0. Warm map0 must make zero RAM
and code-hook calls; cold/lazy full checks remain allowed. Hash0 must preserve
the deliberately corrupted warm hash without repair, while hash1 rejects it.
CPU/control disturbances execute real MSR instructions. Handler physical MSP
is distinguished from banked SPSEL; normal C movement of active Thread PSP is
not mistaken for forbidden register repair.
There is no invented global ban on valid construction after registration/start:
invalid constructor entry still fails with E, while closed attachment and
scheduler reconfiguration fail with k. Handler calls honor their earlier
IPSR/common-current guards rather than being forced to a later diagnostic.

Tests compile actual supported BASEPRI2/BASEPRI4 cohorts, keep the actual
build-owned expectation outside archives, and require exact missing-key sets
for a stale complete archive, each stale component, and cohort-only removal.
The no-expectation stale link is an explicitly unexecuted causal control.
Missing/foreign Secure providers, reverse-anchor/function removal, missing
common state/core/configuration, and missing SVC/PendSV components are rejected
for exact symbols or the owned-handler linker diagnostic. Raw object ownership,
common dependency independence, final strong vectors, readonly one-byte keys,
and final undefined sets are inspected. Negative controls must compile first.

Partial failures require exact panic/origin, sticky plan phase, unchanged
applicable contexts/frames/current slot, and no later gateway or task resume.
Pool corruption requires actual Secure UDF/UsageFault6, exact F5 exception frame,
MSP selection independent of SPSEL, and exact fault status. A generic fault is
never PASS. Compiled counterfeit Thread and wrong-stack records must fail.

## Evidence And Boundaries

The runner records commands, input hashes before/after, fixture hashes, execution
plan, model mask, ELF/disassembly/dependency artifacts, per-launch traces and
receipts, results and a SHA256 inventory. The exact clean FreeRTOS reference pin
is checked and source files are hashed. This gate does not rerun or replace the
separate frozen reference-transfer experiment in `test_m55_secure_running.ps1`.
The reference PendSV S-bit branch skips NS GPR transfer for Secure origin;
actual FC/no-NS-basic-frame behavior is observed here, not invented by a model.
First-start policy remains deliberately different: Fiber restores r4-r11/r9
and allocates attached first contexts inside owned SVC70, whereas the pinned
reference first restore discards the GPR slots and initially uses handle0.

Hostile flags are unmasked on the six actual NS and three actual Secure units:
instrument-functions, SSP-all, gcov, UBSan, trace-pc and generic stack checking.
Same-run normal/hostile undefined sets and instrumentation counters are checked.
Common/application TUs are neutral; this is not whole-program hostile admission.
NS tasks deliberately have 8 KiB stacks to budget generic compiler stack probes.
A preserved development 4 KiB run faulted on a 4,392-byte-below-frame probe in
public schedule, before its guards. Existing supported-build contracts require
stack-check counterflags. Passing the larger unmasked fixture proves neither
probe elimination nor safe minimum-size stacks under generic stack checking.
The Secure fixed-r9 configuration is likewise not admitted: a preserved
development build emitted CLRM r9 and failed the independent save-image oracle.

AN547 is the actual QEMU model, including its physical FP capability and measured
priority mask. Scalar soft/general-register ABI tests do not establish physical
absence of FP, arbitrary boards, all compiler versions, timings or hardware
security isolation. No board is programmed and no public profile is activated.
