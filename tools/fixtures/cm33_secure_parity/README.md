# M33/M55 Scalar Secure Parity

Maintained entry: `tools/freertos_asm_parity.ps1`, O2/Os. Focused switches:
`-Cm33SecureContextOnly` (A30), `-Cm33SecureOnly` (C3SO) and
`-Cm55SecureOnly` (C5SO). Each accepts
the driver's explicit compiler, CMSIS, pinned FreeRTOS and fresh build roots.
The ordinary driver runs all three modes. No install, final runtime link, board access,
actual exception execution or profile promotion is performed.

The actual production translation units are compiled unchanged. A30 consumes
the generation-2 CM33 Non-secure runtime, handlers, attachment and boot code;
its reference is actual pinned `ARM_CM33/non_secure`, MPU/FPU/MVE disabled and
TrustZone enabled. Only the two consumed Secure contract headers are included,
not unrelated Secure pool/gateway implementation. C3SO consumes the actual
Secure-only runtime/boot and actual pinned `ARM_CM33_NTZ/non_secure` with
Secure-only=1, TrustZone/MPU/FPU/MVE=0, M33 soft ABI and `-mcmse`. The reference
directory name is not a Security-state inference. The separate C5SO mode uses
actual `ARM_CM55_SECURE_ONLY/secure` and pinned `ARM_CM55_NTZ/non_secure`,
default Cortex-M55 soft/CMSE flags, ARMv8.1-M attributes and independent fixed
C5SO baselines. It does not inherit a C3SO receipt or disable M55 loop counters.

All emitted functions in each production object and reference portasm object
have compiler-specific closed baselines. The larger reference port.c object
selects its actual constructor and SVC dispatcher. The baseline records exact
undefined dependency sets and SHA-256 of complete decoded instruction graphs,
including every hardening and panic path. Full canonical bodies are retained.
The imported C5TF ELF decoder validates object bytes, mapping symbols, literal
pools, branch indices and exact relocation targets/addends. Only documented
encoding/spelling aliases, local addresses and one terminal alignment NOP are
normalized. No changed operand, offset, count, order, writeback, instruction or
branch is filtered away. Baselines are fixed files, never learned by a run.
Exact numeric selected-header geometry is checked independently. M33 flags and
ARMv8-M Mainline attributes are retained; general-registers-only attributes
may name the ISA ceiling `8-M.MAIN` rather than the original compiler CPU name.

A30 has 68 O2 / 68 Os closed bodies and 69 independent scenarios. They execute
the actual decoded whole PendSV on both sides for every BC/FC combination,
including the 44-byte NS and 12-byte Secure-origin save extents. Secure-origin
fixtures intentionally do not map an NS core/GPR frame. The actual compiled C
restore validator runs with minimum 12-byte FC storage, nonzero attachment and
handle admission, NS PC/xPSR/padding bounds and malformed encodings. Actual
capture/readback helpers and the Secure-save C function run with PSP corruption
at the explicit external gateway boundary. These add behavioral proofs to the
closed bodies, not only source-pattern assertions. Twenty-five compiled
mutants must reject; 23 must additionally reject the independent oracle with
no closed-baseline lookup. Two mutation candidates that only alter structurally
compared checks are labelled as such in `mutants.py`.

C3SO has 53 O2 / 53 Os closed bodies and 24 independent scenarios: actual
numeric 18-word constructors, full first SVC/restore, malformed first-start
admission and the scalar ten-word PendSV save/restore inverse on both sides.
Fifteen compiled mutants must reject; 14 additionally reject the independent
oracle. C3SO remains explicitly staged inventory, not a complete profile claim.

C5SO independently has 53 O2 / 53 Os bodies, the same 24 scalar oracle cases,
15 compiled mutations, 14 independent rejections and 31 controls on actual
M55-generated objects. These are normal-flag codegen/data-flow checks, not
adversarial instrumentation proof or CPU execution. Pre-helper-attribute-repair
C3SO/C5SO receipts are historical. The new baselines cover the canonical
helper/raw-CPU wrapper repair; neither profile is promoted here.

The A32 Boot baseline admits exactly one generated `memset` call, in
`fiber_port_boot_create`, and the existing two `memcpy` calls, in that factory
and `fiber_port_context_init`. No runtime/transfer object gains a libc allowance.
The real compiled factory prefix is interpreted up to the explicit memset
boundary and must pass current SP, zero and 72 bytes as its first three
arguments. Neither memset itself nor the complete factory is modeled as a
replacement implementation. Wrong fill and an extra memset in context_init
are compiled from copied production and must reject both the closed checker
and independent site/argument oracle. Exact per-function hashes still cover
all remaining instructions, arguments, helper targets and panic paths.

`machine.py` is a bounded integer data-flow interpreter, NOT an ARM emulator.
All CPU-register values are explicit inputs/outputs; it does not model real
exception entry/return or Security state. Scheduler and Secure helper effects
are explicit AAPCS providers. Restore descriptor seal/hash/canary admission is
also an explicit boundary; only the real compiled dynamic representation
validator is executed after that admission. No boot hash algorithm, Secure
image or kernel provider is fabricated as production parity. The private
constructor check for C3SO proves explicit captured-argument consistency; A30
checks its existing private builder in isolation, not the caller-to-builder R9
pipeline. Neither establishes inheritance of an outer ordinary-C application's
R9 seed. Actual normal/LTO and reserved-R9 consumer
qualification remain separate obligations.

`--behavior-only` is a labelled independent mutant classifier. It cannot write
a general parity PASS receipt. All mutations compile copied actual source;
neither checkout is edited. Compile failures, tracebacks and partial diagnostics
cannot count as intended rejection. Thirty-one controls cover -O/-OO,
PYTHONOPTIMIZE, optimized compiled imports, both classifier entry paths and
counterfeit SystemExit-to-RuntimeError diagnostics. No Python assert controls
acceptance. Commands, preprocessing, assembly, objects, relocations, attributes,
dependency closure, diagnostics and source/tool hashes are retained. Source
drift produces INCOMPLETE without an artifact PASS manifest. Documentation
artifacts are immutable copies, never mutable live repository paths.

The explicit snapshot inventory includes top-level `context/*.h` alongside
the legacy `fiber` headers that forward to these canonical declarations and
types. This does not compile or qualify the Context engine. Dependency closure
still rejects every uncaptured dependency, even when that file exists; no
assembly baseline, dependency allowlist or behavioral oracle is broadened.

## C33S A32 Fixture Admission

Only the A30 Boot baseline changed for the canonical helper-closure repair:
four outlined helpers and nine changed callers at O2, two outlined helpers and
four changed callers at Os. Every dependency set and complete non-Boot body
remains fixed. The existing cold memcpy/memset imports are not broadened.
The RAW_READY production/test/leaf-ledger inputs remain a separate frozen set.

PSP mutations select exactly one actual source anchor, accepting the old CMSIS
read or the canonically annotated local read. Missing/duplicate anchors reject.
The alternate source spelling is compiled and must pass complete parity and
the independent oracle; both compiled guard-removal mutants must then fail
both checks. These controls are additional to the existing 23 mutations.

The C33S cohort fixture in Test-C33SCohortMechanisms accepts exactly one strong
C helper call and either one ABS32 exact-key relocation or the matching
MOVW/MOVT exact-key pair. Queries permit no other relocation or helper call;
the initializer retains its original exact dependency set and precommit trace.
Both address forms and direct builtin/CMSIS caller spellings compile actual
copied source, link the real pool and execute with the existing explicit CPU,
AIRCR and CMSE-return doubles. This is not exception/security-state execution.
Normal and supported-counterflag variants remain distinct from RAW_READY.

Fifteen compiled cohort mutants cover the original six controls plus wrong
keys, extra provider calls and foreign query helpers in both address forms,
and missing/wrong high halves or mixed materialization. Each must reject for
its exact intended diagnostic. Neither helper allowlists nor numeric cohort
facts are widened. The dedicated archive/cohort runner additionally compiles
both relocation shapes and wrong-key/extra-call controls at O2/Os while
retaining its C/C++, GC, LTO and all eight query-owned RETAIN-removal proofs.
Its exact inventory is 540 checks and 32 query-owned RETAIN-removal mutants;
the additional 44 checks are 32 compiled address positives and 12 negatives.
The caller/AIRCR runner compiles and executes both accepted caller spellings
and their guard-removal mutants; its supported build contract is unchanged.
