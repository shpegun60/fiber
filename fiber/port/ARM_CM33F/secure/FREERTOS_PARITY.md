# ARM_CM33F Secure Staged Companion Ledger

## Implemented Boundary

The C3FS companion implements **eight read-only identity/capacity NSC queries
and one one-shot boot initializer**, plus genuine Secure-private pool backing.
The nine exports carry the distinct `c3fs_v1` namespace. It cannot allocate,
save, load or free a context; no dummy lifecycle symbol makes a caller link.
The NS profile remains
`RUNTIME_SELECTABLE=0`, with no global route or complete runtime bundle.

Shared identity is port `0x43334653`, layout `0x00010001`, feature `0x8B`.
This new generation1 identity adopts corrected frame semantics from inception;
it is not scalar C33S generation1/2 or either NTZ FP profile. Secure ABI is1;
the capacity ABI is separately1, with eight-byte stack alignment.

## Before Any Query

Secure boot must establish **CONTROL.nPRIV=0 and full Secure CPACR.CP10/11
access**, with the required architectural synchronization, before the first
query. The executing Secure CPACR at `0xE000ED88` is meant, not its NS alias.
Every actual query begins with a force-inline sensitive/GRO read-only preflight:
nPRIV mismatch or incomplete CP10/11 causes terminal UDF75 before manifest-helper
effects and before a return. It does not return0 to enable a retry. nPRIV is an
explicit profile policy here, not a claim that Handler privilege is inferred
from CONTROL.nPRIV. Integration owns valid Secure MSP/stack/startup state.

Canonical general-registers-only currently suppresses GCC14's FP/FPSCR CMSE
cleanup in these query envelopes, even with hard-FP compiler flags. The gate
inspects all qualified generated bodies and rejects FP instructions, unsupported
policy writes or missing preflight. It admits the exact flags-only
APSR_nzcvqg encoding that objdump calls CPSR_fs, not arbitrary MSR writes.
Removing GRO is a compiled negative control, not an allowed manifest. No claim
is made that arbitrary CMSE/compiler combinations are FP-instruction free or
that hardware SG/SFPA state is emulated by the body tests.

There is **no FPU setup side effect** in a query or cohort helper. The boot
initializer now owns Secure NSACR.CP10/11 grant, Secure FPCCR.LSPENS clear and
TS set with ordered readback. NS CPACR CP10/11 and NS FPCCR policy
must then be enabled/read back in the NS bank before NS FP instructions that
depend on that grant. Hard-FP application/library code may execute before
Fiber startup; its earlier access permissions remain a boot integration
obligation. A later initializer cannot repair an already executed query or
application FP instruction. No current query claims that NS access is granted,
that LSPENS/TS are initialized, or that FPU/lazy-state preparation is complete.

## Capacity And Backing

Each Secure object requires explicit
`FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT` and
`FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES`. Count must be nonzero; byte
capacity is eight-byte aligned and leaves room for an eight-byte top seal.
They are configured reservation limits reported to attachment, not physical RAM
discovery or proof of a usable FP stack. Actual FP allocation must additionally
budget lazy/exception stacking, seals and scratch before it can be implemented.

The private revision1 record contract is24 bytes/alignment4:
saved PSP, limit, top, opaque owner at offsets0/4/8/12, then capacity and
allocation-state words16/20. The reference's actual record is16 bytes; neither
has a non-MPU CONTROL slot. The top seal contract is two `0xFEF5EDA5` words.
The pool now instantiates count records and count stack slots. Its exact NOLOAD
cost is `count * (24 + capacity + 8)` bytes, with eight-byte alignment, plus a
four-byte normal BSS pool marker. The gateway adds another four-byte normal BSS
marker. Board startup must zero both markers and map the pool to Secure RAM.
The initializer owns every NOLOAD byte, including padding/tails, and scrubs then
reads back the whole image. No records, seals or usable handles are published
by this slice; zeroed seal space is not an allocated context seal.

All three gateway/pool objects bind the same evaluated 12-fact key: profile,
layout, features, identity ABI, capacity ABI, record revision, count, capacity,
alignment, seal-word count, seal-byte count and seal value. Two independently
delimited16-bit halves encode each uint32 fact (24 immediate operands); arbitrary
valid integer macro expressions are evaluated, not token-pasted. One RO provider
byte is emitted only by the real strong, sensitive/noIPA/GRO C helper
`fiber_secure_context_pool_c3fs_g2_cohort_provider`. Address-only relocations
retain the actual pool image and marker without reading or initializing either.
Every independently callable query uses an ordinary C dependency on that helper
followed by the exact volatile key read. No ASM-only archive extraction claim.

The build-owned `fiber_secure_context_cohort_contract.ld` ASSERT rejects missing
generation2 backing, but does not extract archives. The `c3fs_g2_` exact key and
new C helper distinguish this stage from the historical metadata-only g1
companion. This is a private build-generation change, not a saved-context
semantics change: port/layout/storage/callable ABI identities stay unchanged.
Board scripts own the NSC
VMA. Use a proper INCLUDE or explicit `.gnu.sgstubs` address; the maintained
two-`-T` recipe also passes `--section-start=.gnu.sgstubs=0x10020000`. Do not
reuse that synthetic address as a board memory map.

This is internal exact binding, not an external application-capacity expectation.
A coherently rebuilt companion with other legal limits is coherent and reports
those actual configured values. Defining expected values only on some outside
application command line does not pin a whole already-built archive.

## Boot Initializer Contract

`fiber_secure_context_gateway_c3fs_v1_initialize()` captures the immediate
CMSE caller kind before helpers. The same integer preflight applies before any
return: Secure nPRIV0 and Secure CPACR full CP10/11 access remain prerequisites,
not state repaired by initialization. The supported GCC14 hard/softfp generated
CMSE prologue, complete body/helper text, and veneers are byte-accounted; no FP
instruction may precede that preflight or appear later in this integer slice.

Admission requires a direct NS caller in SVC11, both normal BSS markers zero,
AIRCR.BFHFNMINS clear, shared CONTROL FPCA and Secure SFPA clear, and
both banked FPCCR.LSPACT bits clear. These are visible-state checks, not proof
that no suspended FP owner exists. Integration additionally owns a serialized,
exclusive boot phase with no live Secure thread, other FP context or concurrent
policy writer. SG clears SFPA; its entry value is not evidence about the caller's
previous Secure FP state. No arbitrary MSP corruption containment is claimed.

FPCA is not banked: both architectural CONTROL views expose the same active
bit. The additional CONTROL_NS FPCA test is conservative read-consistency
hardening, not admission of an independently banked NS FPCA. NS writes to FPCA
depend on NSACR permission. The earlier isolated register-double tests included
an independent NS FPCA stimulus as a corruption model, not a possible coherent
hardware state. The paired proof distinguishes real shared-state writes from
explicit destination-register corruption after an actual MRS. QEMU's raw GDB
`control_ns` field does not itself include the shared bit; use actual CPU MRS
when claiming an architectural CONTROL_NS observation.

After the sticky INITIALIZING latch, the order is:

1. Set AIRCR PRIS using VECTKEY, preserving other fields, and verify readback.
2. Write Secure PSPLIM0 then PSP0; verify both.
3. Require private whole-pool boot initialization to return exactly1.
4. Write Secure CONTROL2 and require exact2 readback. Handler still uses MSP;
   SG is not exception entry and banked SPSEL can retain the written value.
5. Grant NSACR CP10/11; clear FPCCR LSPENS; set FPCCR TS, in reference order,
   with barriers/readback and unrelated policy preservation.
6. Publish READY and verify it. Return1 only then.

Pre-commit invalid admission returns0 without pool/CPU backend writes (compiler
integer stack spills are not excluded). CPACR/nPRIV violations trap UDF75.
After commit, readback/pool failures return0 with sticky INITIALIZING; failed
marker latching or whole-image scrub/readback traps. A caller must treat either
post-commit failure as terminal until an integration-owned fresh BSS boot, not
retry it. There is no interrupt-mask write, Secure CPACR grant, NS CPACR write,
NS CONTROL write, FP instruction, heap call or per-context CONTROL slot here.

Primary register semantics: Arm Cortex-M33 Devices Generic User Guide
[100235_0100_06_en](https://documentation-service.arm.com/static/66be2153882fec713ef49e49),
CONTROL table2-18 (page32), FPCCR table4-64 (pages297-300). FPCA is shared; LSPACT is banked;
LSPEN/LSPENS/TS are shared. The quiescent boot admission is Fiber hardening, not
a claim that the reference contains these checks or that SG establishes them.

## Pinned FP Mapping And Deferred Work

Actual reference is `portable/GCC/ARM_CM33/secure` at
`a50edad08b29052631aa469d4df6e6ec7ff68878`, paired with its NS directory,
MPU0/FPU1/TrustZone1/Secure-only0. All exact source hashes, functions and NS
geometry are enumerated in the companion NS leaf ledger and
`tools/fixtures/cm33f_secure_reference/README.md`.

| Reference / C33S Baseline | Staged C3FS Decision |
| --- | --- |
| C33S identity/capacity/exact-cohort hardening | Adapted to unique C3FS namespaces, private geometry and explicit configured limits; no copied scalar lifecycle. |
| Reference `secure_init.c` AIRCR/NSACR/FPCCR | Adapted into the ninth NSC export in exact relative order, with narrower caller/boot admission and explicit readbacks. No setup in queries. |
| `SecureContext_Init` | PSPLIM0/PSP0, record initialization then CONTROL2 are preserved in order. Fiber adds two sticky state markers, verified whole static-image scrub, exact return/readback checks and boot-only FP admission. CONTROL2 is not an active-FP transfer predicate. |
| Reference heap/owner/stack-seal allocation | Deferred. Static backing exists, but no allocator/owner publication/seal creation or lookup operation is supplied. |
| `SecureContext_LoadContextAsm` | Deferred. PSPLIM then PSP; no scalar CONTROL clear copied into active FP state. |
| `SecureContext_SaveContextAsm` | Deferred. The real S0 VSTMDB/VLDMIA trigger touches4 bytes below live PSP; bounds must precede the store and include deferred frame effects. |
| Secure-origin NS PendSV branch | Reference saves prefix3 only; running FP EXC_RETURN/SFPA/DCRS admission is not guessed or implemented here. |
| Generated CMSE mechanics | Actual query/compiler bodies and SG/import addresses are preserved; body-only emulation stops before BXNS and is not two-image execution. |

Both NS and Secure manifests require actual scalar-SP `__ARM_FP==4`, CMSIS33,
FPU present/used1 and the correct CMSE compilation role. MVE/PAC/BTI/exposed
v8.1-M are rejected. Predefines do not identify every literal wrong-target
command; maintained object/final-ELF ISA admission remains mandatory.

## Evidence Limits

Run `tools/test_cm33f_secure_manifest.ps1` with an existing ARM GCC, CMSIS,
pinned kernel and Python packages. Its immutable receipts cover eight
O2/Os x hard/softfp x normal/LTO configurations, C/C++ declarations/storage,
ordinary archive extraction, exact-key binding, real generated query bodies,
and bounded constructor/attachment/query/initializer execution plus compiled
controls. Commands, input/artifact hashes, preprocessed/assembly/ELF/import/map
artifacts remain in the unique output. Counts belong to the final receipt.
Raw instrumentation/SSP/sanitizer/profile/coverage builds additionally link and
execute the actual annotated private helper chains without supplying fake
instrumentation hooks. Local inline-sensitive/GRO CPU reads avoid CMSIS
accessor instrumentation. This proves neither global A32 closure nor a new
FP preservation operation. It does not waive mandatory integration counterflags.

The isolated manifest gate does not qualify actual SG transitions. Secure
allocation/transfer, FP stacking/preservation, a complete paired runtime,
physical no-FPU support, board or exhaustive equivalence remain unqualified.
Active-transfer FPCA/SFPA predicates, genuine lazy-trigger bounds,
two-image FP data preservation and final common-five/port-eight links are gates,
not missing tests silently treated as equivalence.

The isolated manifest proof explicitly models system-register/MMIO reads,
writes and injected failures and stops before BXNS. Its model is not a physical
FPU/banked-state test. `tools/test_cm33f_secure_initialize.ps1` adds a separate
actual two-image AN505 proof; its fixture README defines the CPU, injection,
counterfactual-control and source/reference byte-evidence boundaries. Exact
counts and current verdict belong to that generated receipt, not this ledger.
The foundation's prior 275-check receipt remains historical, not evidence for
the newly added pool/CPU operations. Fresh receipts record exact generated byte
intervals/hashes, complete text decode coverage, all nine veneers and actual
unmodified FP reference objects alongside the new compiled predicate controls.
