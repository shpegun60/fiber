# C55S Handler SG Lifecycle Fixture

`tools/test_m55_secure_lifecycle.ps1` requires existing Arm GCC/CMSIS and an
explicit WSL `-QemuRoot`; `-WslDistro`, `-BuildRoot`, `-FreeRtosRoot`, and timeout
are configurable. Nothing is provisioned. It separately compiles actual C55S
gateway, identity, and unchanged private-pool sources, then executes real Secure
and NS images through SG on M55 `mps3-an547` at O2/Os, with and without LTO.
Default low-overhead-loop codegen is retained. No hardware is programmed.

## Scope

The fixture qualifies Handler-mode SG primitives and banked-register transfers,
not full Secure Thread execution, actual task switching, a Non-secure runtime
provider, attachment integration, or physically absent FP/MVE hardware. A
fixture `__FPU_PRESENT=0` does not prove the latter on QEMU. Exact CONTROL=2 is
a scalar policy invariant, not proof about MPU or all lazy-FP state.

Wrong NS Thread callers need a private scratch Secure PSP to execute compiler
CMSE stack housekeeping before the save admission check. That stack is seeded
while paused at entry and restored to empty before the rejected return. This
does not establish a graceful zero return for arbitrary Thread calls with an
empty Secure PSP. Direct Secure-origin checks use actual private BL calls from
SVC and PendSV context, not an LR bit substituted for a call.

## Maintained Cases

One structured Python plan generates both the compiled NS request table and
the debugger's checked JSON plan. Its 94 requests cover unready and wrong
exception/origin admission, six CONTROL readback injections per new operation,
partial/loaded state rejection, invalid sizes/handles/owners, unattached zero
handles, duplicate/exhausted allocation, live PSP/PSPLIM bounds/alignment,
inclusive stack boundaries, and repeated three-owner SVC/PendSV cycles.

CONTROL admission injections force 0/1/3/6/10/14 only after observing the actual
MRS result 2; they are not pre-SG SFPA seeds. Compiler MSP/FPCXT stack housekeeping
is permitted, but rejected admission must precede backend calls and lifecycle
register/record effects. Actual nonzero Secure masks and the complete NS bank
are preserved. Allocation geometry, owner, size, state, and both seal words are
checked against an independent address/size model, not forwarded arguments.

Each mode executes success, seven terminal post-update readback failures,
eleven metadata/seal corruption UDF cases, fifteen compiled gateway mutants,
one counterfeit Thread-resume fixture and two compiled unknown-store controls:
37 launches per mode, 148 total. A partial-update failure stops in the originating
Non-secure Handler. Its actual IPSR 11/14 and exact request/result are checked
before exception return and corroborate the terminal report. A correct-looking
report after Thread resumption is not accepted. No rollback, recovery latch, or
safe resume is claimed.

Load must write/read back PSPLIM before PSP. Save must publish the exact live
PSP, execute DSB/ISB, recheck ownership and volatile saved PSP, then clear/read
back PSPLIM before PSP and both final registers. The instruction trace checks
executed ordering. Mutants remove origin/exception/exact CONTROL guards, reverse
register order, alter PSP publication, remove exact publication readback, or
ignore failing register readbacks. Each must stop at its named operation,
request, and direct/NS origin; unrelated crash/timeout is not a mutant kill.

Every ST/VST/PUSH-family instruction is observed before execution. Unknown
forms fail closed rather than escaping a narrower breakpoint filter. Compiled
STL/STLEX controls must be rejected while paused before the instruction executes;
STC/VSTM classifier controls separately cover unsupported mnemonic families.
The maintained assembly control is also compiled and disassembled in every
mode. Its STC word is undefined in the M55 decoder, so only this never-executed
classifier counterexample uses the generic ARM force-Thumb decoder. Both dumps
are retained. This is neither M55 coprocessor support nor an override of the
production decoder; actual STL/STLEX controls are separately stopped before
execution in QEMU.

Corruption faults require the exact production UDF PC, UNDEFINSTR only, current
IPSR=6, the actual originating SVC/PendSV stacked IPSR and T=1, Secure/basic
EXC_RETURN=0xFFFFFFF5, and independently observed Secure MSP frame. MODE is
checked before SPSEL in the vector: Handler still uses MSP after CONTROL=2.
Nineteen invalid report mutations per genuine UDF must all be rejected.

## Build Evidence

Every mode checks exact twelve CMSE exports/imports under GC/LTO. A frozen
nine-entry provider must fail C and C++ consumer links solely on the new
allocate/load/save symbols; matching twelve-entry links must succeed.

The reused maintained hostile whole-companion checker enables instrumentation,
SSP, coverage and sanitizers after counterflags; validates active settings and
contaminated controls; checks expanded canonical attributes, the complete
private call graph, no external support/counters, and exact mutable geometry.
Only the named GCC CMSE security forms are allowed in NSC bodies, with the
checker's static count/local return-adjacency checks and actual pinned reference
contrast. No ordinary FP/MVE datapath instruction is allowed. Full bounded
transfer parity/encoding qualification is a separate actual-FreeRTOS gate.

The actual pinned FreeRTOS sources compile/link in every mode, with generated
load/save assembly and explicit stronger-guard comparison notes. HEAD and clean
tracked/untracked reference status are required. Private pool configuration
cohort mixing is a separate gate, not addressed by this runner.

Unique evidence roots preserve source/tool/CMSIS/fixture hashes before/after,
commands, preprocessed sources, objects, maps, imports, ELFs, disassembly,
compiled mutant sources, traces, exact fault/kill receipts, and output SHA256s.
The adapted initializer runner independently retains its unchanged 53 cases.
