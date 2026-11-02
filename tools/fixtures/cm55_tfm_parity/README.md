# C5TF Actual-Source Parity

Invoked by `tools/freertos_asm_parity.ps1` at O2/Os, or its bounded
`-Cm55TfmOnly` mode. No package installation, host ARM emulation, board access,
global selection, runtime-profile promotion or final link is performed.

The real Fiber runtime/boot/initializer/wrapper and pinned M55_NTZ assembly,
C constructor/SVC dispatcher and TF-M semaphore wrapper are compiled with
default M55 soft-ABI flags. `os_wrapper/mutex.h` is an explicit TF-M 2.0 ABI
compile boundary, not a replacement implementation. No source body is
extracted, renamed, patched or replaced on the positive path.

`elf.py` derives its ELF32/objdump decoder from the frozen C3FP checker. It
checks every decoded byte against the actual object and respects symbol sizes,
mapping symbols, literal pools and relocations. It additionally admits named
section data relocations, local C helpers and the C branch forms used here.
Only spelling/encoding aliases, local target addresses, literal addresses and
one terminal alignment NOP are normalized. Counts, offsets, register lists,
writeback, flag-setting forms and relocation addends remain significant.

`expected-O2.json` and `expected-Os.json` are fixed GCC 14.3.1 closed baselines
reviewed against actual source; the runner never generates/updates its oracle.
All 54 emitted functions in the runtime, initializer, wrapper and reference
assembly/wrapper are checked; only constructor and SVC C-dispatch functions are
selected from the larger pinned C object. The actual boot constructor is the
55th closed body, added for the R9 repair. Other boot functions retain real
compile/dependency/attribute checks, not complete boot behavior parity. All seven objects
have exact undefined dependency sets. Unexpected helpers and FP/MVE/PAC/BTI
instructions or attributes fail. The boot object intentionally imports memcpy
and memset; frame construction does not.

`symbolic.py` is a bounded ordinary-integer instruction/data-flow interpreter,
NOT a CPU emulator. `oracles.py` checks independent numeric 18-word frame
values, exact write extent/canaries, the ten-word save/restore inverse and first
restore CONTROL2 plumbing. The Fiber boot-record check is an explicit admitted
external call; caller-saved registers are poisoned across it. Transfer slices
use an artificial interpreter return sentinel after actual compared slices;
they do not model exception entry/return or speculate that CONTROL bit values
demonstrate real hardware behavior. CPU register reads/writes are explicit
value inputs/outputs only. The repaired private builder accepts `initial_r9`
in R1 and is tested with a different live R9. The actual caller captures entry
R9 before cold anchor reads/hooks and forwards it even while its generated
code uses R9 for stack_end (O2) or context_end (Os). AAPCS fifth-argument stack
passing is interpreted, not replaced with register arguments. Explicit
boot-factory/memcpy/admission providers define narrow boundaries, preserve
callee-saved registers and do not simulate full seal/address-policy behavior.
Post-builder saved-slot corruption must hit the actual caller's exact '9'
panic; the corresponding guard-removal mutant must fail this independent
oracle. These 16 cases extend the original 89 to 105 bounded scenarios.

`--r9-dataflow-only` on check.py is an explicitly scoped independent oracle
for compiled R9 mutants. It does not consult closed baselines, does not emit a
general parity receipt, and is never a substitute for the normal full check.
Its optimized invocations and counterfeit diagnostics have maintained controls.
`policy.py` checks sticky TF-M initialization, six
CPU preservation checks, ownership/recursive/busy/delete cases, unmasked
cooperative retry and pinned semaphore result/timeout policies. These 105
bounded scenarios supplement closed baselines, not actual TF-M/CPU execution.

The actual M33 TF-M policy source relation permits only the exact leading
initializer profile comment, bundle symbol and count-checked A32 raw CPU-reader
call names versus CMSIS calls. C3TF may use either the complete old CMSIS dialect
or the complete canonical `fiber_port_cpu_read_*` dialect; C5TF must retain only
canonical readers. Mixed readers within a file or dialects between the two files
are rejected. Those substitutions are a policy source-relation
check only: the compiler receives unmodified production, and all generated
instructions remain subject to the closed body/data-flow checks. Reader counts
are retained in wrapper-policy-source.json; no condition, instruction or
register choice is normalized away. Forty-three source-relation controls cover
both allowed C3TF dialects, each missing reader count, same-count register swaps,
changed numeric policy, mixed dialects and noncanonical C5TF readers. Their exact
diagnostics are recorded in `wrapper-policy-controls.json`; these source-only
controls do not replace the complete compiled closed-body gate. The CPU reference
remains the actual M55_NTZ source/manifest.

43 bounded compiled mutations change fixture copies of real production or
pinned reference source. None edit either checkout. They cover transfer
offset/count/order/writeback, wrong destinations, FP origin, first R9 restore,
Handler CONTROL2 readback, SVC provenance, constructor values/cursor/CPU/helper,
initializer ordering/sticky state/preservation/readback, mutex owner/recursion/
timeout/yield and reference constructor/wrapper/SVC behavior. Mutants must
compile and produce a sole intended rejection diagnostic; compile errors and
tracebacks cannot masquerade as rejection. Eight R9 mutations must also fail
the independent data-flow oracle: zero/late/context-end builder values, wrong
or re-read caller arguments, capture after cold reads and removed readback.
In addition to those 43 source-relation controls, 49 harness controls cover all seven
Python modules with -O/-OO, environment and compiled-import optimization plus
counterfeit traceback diagnostics. No Python assertion controls acceptance.

Every command/result is retained. Actual .d closure must resolve to a hashed
source/tool header or an evidence-root generated input. Source drift produces
INCOMPLETE with no PASS manifest. Documentation inputs use retained snapshot
paths plus attribution-only SourcePath. All artifacts stay under the fresh
evidence root. No unrelated C55S sources are hashed as consumed dependencies.

See the FAP-C5TF entries in FREERTOS_ASM_PARITY.md for every intentional
difference. Final links, actual exception/Secure/TF-M behavior and runtime
activation remain separate consumer/integration qualification obligations.

Pre-repair 54-body/89-scenario receipts remain historical. The constructor's
old builder-live-R9 assumption was invalidated by the actual M55 LTO consumer
reproducer. Its old source/oracles are retained separately; this refresh only
changes the repaired builder and adds its real caller baseline. Other 53
closed bodies, including all SVC/PendSV paths, remain unchanged. This object/
data-flow proof does not qualify actual LTO behavior or promote the runtime.

The A32 refresh compiles the real port-local annotated raw CPU/NVIC wrappers.
All 55 normal O2/Os closed bodies still match the existing baselines, including
the naked transfer/start bodies; no baseline was changed to accommodate A32.
The geometry oracle requires current selectable metadata exactly one. Normal
parity is not an instrumentation-exclusion proof: hostile flags, LTO, actual
target execution and promotion remain separate consumer gates. The global
ledger identifies the immutable post-A32 capture and historical older receipts.
