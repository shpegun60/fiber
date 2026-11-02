# ARM_CM33F Non-Secure Staged Construction Ledger

## Status And Identity

This is a new **staged** Cortex-M33 scalar-SP TrustZone pair, not another
complete runtime. `FIBER_PORT_RUNTIME_SELECTABLE` is 0. Build-selected source
and include paths are required; no global selector/route has been added.
Implemented here: the type-only public storage, private dictionary, sealed
basic constructor, cold-frame checker, and one-shot pre-start attachment.
There is no port runtime bundle/provider, SVC, PendSV, first restore, yield,
scheduler adapter, running-frame validator or live-handle BSS. The companion
now has pool backing and a boot initializer, but no allocation/load/save export
and no NS startup caller. No Secure allocation/transfer lifecycle is active.
Do not satisfy those absent operations with dummy implementations.

| Fact | Exact Value |
| --- | --- |
| Port ID | C3FS `0x43334653` |
| Private layout | `0x00010001`, corrected semantics from new identity's inception |
| Feature mask | `0x8B`: extended FP, PSPLIM, SecureContext, Non-secure |
| Public storage | `arm_cm33f`, revision1, regions0 |
| `FiberPortBoot` | 76 bytes, alignment4; secure request offset28 |
| `FiberContext` | 80 bytes, alignment4; saved SP offset0, boot offset4 |
| Initial image | 19 words/76 bytes, basic EXC_RETURN `0xFFFFFFBC` |
| Reference NS extended image | 53 words/212 bytes, optional alignment adds4 |
| Reference Secure-origin NS image | 3-word/12-byte prefix, not an NS hardware frame |

The initial image is handle0, PSPLIM, EXC_RETURN, r4-r11, then the eight core
hardware words. r9 occupies word8; argument is word11, LR/PC/xPSR words16/17/18.
Stack top is eight-byte aligned, initial saved SP is four modulo eight.
The dictionary budgets maximum216 bytes (software44, high-FP64, hardware104,
alignment4); the constructor still writes only76 bytes. Its 216-byte usable
minimum plus the configured red zone is saved-frame geometry, not an application
call-stack, exception nesting, lazy-stacking or Secure MSP depth qualification.

No guessed FP Secure-origin EXC_RETURN allowlist is emitted. The three-word
reference geometry is a fact, not an implemented runtime admission branch.
Initial basic BC alone is checked here. The implemented scalar C33S A30 generation2
BC/FC representation is a hardening baseline, not automatic proof of the FP
bit4/SFPA/DCRS combinations. A new running-state slice must qualify those first.

## Exact Manifest

The maintained tuple uses actual `-mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16`,
hard or softfp, with NS CMSE level1 and Secure `-mcmse` level3. Private NS code
requires Mainline, CMSIS `__CORTEX_M == 33`, VTOR1, FPU present/used1,
`__ARM_FP == 4`, and 1..8 NVIC bits. MPU region manifests, MVE, exposed v8.1-M,
PAC and BTI facts are rejected. Non-MPU describes policy, not physical MPU
absence. Type-only public headers include no CMSIS, CPU dictionary or runtime
provider. Public allocating facades retain their own `arm_cm33f` storage key;
direct concrete-type allocators must include the storage expectation header.
Board linkers must KEEP `*(.fiber_port_context_cohort_expectation)`.

Compiler/CMSIS facts are a manifest, not a proof of literal target flags. GCC14
can expose indistinguishable scalar M33/M55 predefines. Exact M33 command lines,
input-object and final-ELF v8-M ISA admission remain mandatory; the focused
wrong-M55-object control demonstrates that limit instead of inventing a macro.

## Construction And Attachment

`fiber_port_boot.c` adapts the current C33S constructor/hash/overlap/canary
checks and the hardened C55S cold-only implementation. All private helpers,
weak optional map defaults and hook declarations carry the canonical sensitive
or forced-inline-sensitive attributes plus general-registers-only. Strict
integration RAM/code hooks remain mandatory unless the explicit permissive
development setting is selected. GCC may emit `memset`/`memcpy` for aggregate
boot-record creation/copy; linked implementations must also be instrumentation
safe and general-registers-only. The focused fixture supplies explicit bytewise
support, not hidden port operations or an FP-capable library assumption.

The exact context-cohort read and frozen reverse-v1 read both execute cold
inside `fiber_port_context_init`. No production context/storage provider is
defined: a future mandatory runtime object owns that definition; constructor
fixtures explicitly provide it. No common operation or ABI has changed.

One local assembly label identifies the actual r9 sample without adding an
instruction or exported symbol. The sample is passed explicitly into the frame
builder and checked immediately after construction. Under ordinary AAPCS,
callee r9 preservation and captured-seed consistency are required, not equality
with an unrelated public-entry register activation. A process-wide static-base
guarantee requires consistently reserved r9 across the full build/call graph;
the focused `-ffixed-r9` modes intentionally qualify that distinct contract.
No later checker compares the seed with a later live r9.

`fiber_port_secure_context_attach(ctx, bytes)` retains the existing optional
common context-configuration ABI and exact context identity. It rejects Handler
mode before common lifecycle checks, validates caller storage, cold handle0,
boot seal and size, then checks eight C3FS-namespaced companion queries. Each
hook/query boundary is checked against the captured IPSR, PRIMASK, BASEPRI,
FAULTMASK, CONTROL and PSPLIM. It then seals the requested size; no allocation,
load, CPU/FPU policy write or handle publication occurs. Repeated attachment,
closed lifecycle, stale identities, unaligned/oversized requests and corrupted
boot records fail closed. The cold handle0 validator is not weakened into a
post-allocation/running checker.

## Reference Mapping And Differences

Pinned source is actual `portable/GCC/ARM_CM33/{non_secure,secure}` at
`a50edad08b29052631aa469d4df6e6ec7ff68878`, MPU0/FPU1/TZ1/Secure-only0,
MVE/PAC/BTI0. It is not the NTZ or MPU reference. Full reference inventory and
hashes are also maintained in `tools/fixtures/cm33f_secure_reference/README.md`.

| Reference | This Slice / Required Later Delta |
| --- | --- |
| NS `port.c:1652` initial stack | Copied19-word basic geometry; Fiber initializes every GPR, normalizes Thumb PC, retains explicit r9 policy, adds bounds/seal/canary checks. Reference debug seeds and heap/TCB coupling are not copied. |
| NS `portasm.c:146` first restore | Absent. Reference skips initial r4-r11; future Fiber full-GPR/r9 restoration is an intentional difference requiring its own proof. |
| NS `portasm.c:441` PendSV bit6 | Absent. Reference Secure-origin skips all NS GPR/FP transfers and saves prefix3 only. No NS PC/xPSR reads may be introduced on that branch. |
| Same PendSV bit4 | Absent. Conditional s16-s31 transfers and raw basic/extended envelopes must be implemented and independently executed. |
| NS `port.c:1109` SVC100/101/102 | Not copied. Fiber attachment records a pre-start request rather than importing FreeRTOS SVC/heap/task APIs. No new public/common operations. |
| NS `port.c:1015` FPU setup | Absent. Future Secure grant must precede NS CPACR CP10/11 enable/readback and chosen NS FPCCR ASPEN/LSPEN policy. |
| Secure `secure_init.c` | Queries remain read-only. The ninth Secure NSC export owns PRIS, NSACR.CP10/11 grant and FPCCR.LSPENS clear/TS set with readback; it cannot repair prerequisites of earlier queries. NS CPACR/FPCCR setup is still absent here. |
| Secure init/allocate/free | Secure static backing, whole-image scrub and one-shot boot initialization now exist; see the Secure ledger. Allocate/free remain absent. Capacity is configured reservation, not proof of a usable allocated FP context. |
| Secure load/save helpers | Absent. Non-MPU has no per-context CONTROL slot. Preserve active FPCA/SFPA appropriately; do not transplant scalar exact-CONTROL2 admission or clear those bits during transfers. |
| Secure S0 lazy trigger | Absent. Real `VSTMDB/VLDMIA {s0}` requires4 bytes below live PSP, plus genuine deferred-stack extent/readback/seal/owner proof before execution. Zero net pointer movement does not eliminate scratch. |
| CMSE envelopes | Real eight-query plus one-initializer companion/imports are compiled and linked. GRO prevents FP cleanup in qualified GCC14 bodies; generated envelopes are inspected, not assumed instruction-free for arbitrary compilers. |

Exact reference SHA256:

| Source | SHA256 |
| --- | --- |
| NS `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` |
| NS `portasm.c` | `6F39F5CB7A24766DF3FA025E41E0E502301550136151B5E2EABDFA9AC4E42D60` |
| Secure `secure_context.c` | `E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72` |
| Secure `secure_context_port.c` | `B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E` |
| Secure `secure_init.c` | `1B8444698089651C6415D48A2B6716BA6C6DC32F71C51B679F5A8A9A3968DE55` |
| Secure `secure_heap.c` | `CE5D5F7FC774E7EC51157F5078361F3CB0A20CE9C94593396F543E5046E53F42` |

## Maintained Evidence Boundary

`tools/test_cm33f_secure_manifest.ps1` records commands, tool/reference pin,
input hashes before/after, preprocessed/assembly/object/ELF/map/disassembly,
actual CMSE import artifacts, execution observations, compiled controls and
artifact hashes under a unique build root. It installs nothing and runs no
board/full matrix. Eight O2/Os x hard/softfp x normal/LTO configurations cover
C/C++ public/manifest/import declarations, real Secure query archives, and two
coherent r9 ABI modes per constructor configuration. Actual unchanged reference
constructors are additionally compiled/executed in four non-LTO combinations.
Each configuration additionally compiles the actual NS port and Secure
query/initializer/pool helper graph with raw `-finstrument-functions`, stack protector,
UB sanitizer, profile arcs, test coverage and trace-pc coverage. No disabling
counterflags or instrumentation providers are added for those port objects;
their real linked helper chains must remain free of those dependencies. The
common fixture/library support is not advertised as globally hostile-qualified.
No CMSIS register-access function is reachable in this new port chain: local
annotated raw assembly reads/barriers are used. The Secure initializer's FPCCR
policy operations have explicit bounded body/readback tests, not hardware proof.
This is isolated C3FS evidence, not closure of inherited A32 in other profiles.

Constructor/attachment execution uses Unicorn2.1.4/pyelftools0.33 and labelled
NS query doubles plus a labelled optional-lifecycle guard, not SG or a fake
eight-operation provider. Actual `fiber_init` and task-return bodies come from
common source; a fixture-only section-marker override on discarded other public
APIs avoids LTO section co-retention. Those tested functions have no such marker
and are not rewritten. There is no forward operation or runtime bundle in the
fixture ELF. Public C/C++ caller storage is bound under GC/LTO.

Separate real Secure query-body runs use explicit CPACR/CONTROL register doubles
and stop before BXNS. They establish bounded integer preflight/order behavior,
not genuine SG/BXNS, SFPA/FPCA, physical FPU, lazy stacking or paired switching.
The original 216-check paired-reference suite is separate compiled-reference
evidence, not an activation result for this new Fiber pair. A final generated
receipt, not this ledger's prose, is authoritative for exact counts/hashes.

The Secure pool/initializer extension preserves this NS context identity, cold
handle0 rules, sealed request and RuntimeSelectable0. The new initializer import
declaration does not make attachment call it. Private Secure cohort generation2
rejects stale metadata-only backing; it is not a public context-layout bump.
The initializer's system-register/MMIO fault-model execution does not qualify
SG transitions, lazy FP preservation or a complete paired runtime.
