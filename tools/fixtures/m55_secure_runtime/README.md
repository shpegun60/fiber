# C55S Actual Common Runtime

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
