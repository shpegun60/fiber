# ARM_CM33F Secure Staged Companion Ledger

## Implemented Boundary

The C3FS companion implements **eight read-only identity/capacity NSC queries**
and a strong private C manifest helper. Symbols carry the distinct `c3fs_v1`
namespace. It does not initialize, allocate, save, load or free a context. There
is no pool BSS, NOLOAD storage, CPU startup latch or lifecycle export. Do not
add no-op lifecycle providers to make a caller link. The NS profile remains
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

There is **no FPU setup side effect** in a query or helper. A future private
initializer must own Secure NSACR.CP10/11 grant, Secure FPCCR.LSPENS clear and
TS set with correct ordering/readback. NS CPACR CP10/11 and NS FPCCR policy
must then be enabled/read back in the NS bank before NS FP instructions that
depend on that grant. Hard-FP application/library code may execute before
Fiber startup; its earlier access permissions remain a boot integration
obligation. A later initializer cannot repair an already executed query or
application FP instruction. No current query claims that NS access is granted,
that LSPENS/TS are initialized, or that FPU/lazy-state preparation is complete.

## Manifest, Not Physical Storage

Each Secure object requires explicit
`FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT` and
`FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES`. Count must be nonzero; byte
capacity is eight-byte aligned and leaves room for an eight-byte top seal.
They are configured **future** limits reported to attachment, not physical RAM
discovery or proof of a usable FP stack. Actual FP allocation must additionally
budget lazy/exception stacking, seals and scratch before it can be implemented.

The private revision1 record contract is24 bytes/alignment4:
saved PSP, limit, top, opaque owner at offsets0/4/8/12, then capacity and
allocation-state words16/20. The reference's actual record is16 bytes; neither
has a non-MPU CONTROL slot. The top seal contract is two `0xFEF5EDA5` words.
These layout assertions do not instantiate a record or stack array.

All three query/manifest objects bind the same evaluated 12-fact key: profile,
layout, features, identity ABI, capacity ABI, record revision, count, capacity,
alignment, seal-word count, seal-byte count and seal value. Two independently
delimited16-bit halves encode each uint32 fact (24 immediate operands); arbitrary
valid integer macro expressions are evaluated, not token-pasted. One RO provider
byte is emitted only by the real strong, sensitive/noIPA/GRO C manifest helper.
Every independently callable query uses an ordinary C dependency on that helper
followed by the exact volatile key read. No ASM-only archive extraction claim.

The build-owned `fiber_secure_context_cohort_contract.ld` ASSERT rejects missing
generation1 metadata, but does not extract archives. Board scripts own the NSC
VMA. Use a proper INCLUDE or explicit `.gnu.sgstubs` address; the maintained
two-`-T` recipe also passes `--section-start=.gnu.sgstubs=0x10020000`. Do not
reuse that synthetic address as a board memory map.

This is internal exact binding, not an external application-capacity expectation.
A coherently rebuilt companion with other legal limits is coherent and reports
those actual configured values. Defining expected values only on some outside
application command line does not pin a whole already-built archive.

## Pinned FP Mapping And Deferred Work

Actual reference is `portable/GCC/ARM_CM33/secure` at
`a50edad08b29052631aa469d4df6e6ec7ff68878`, paired with its NS directory,
MPU0/FPU1/TrustZone1/Secure-only0. All exact source hashes, functions and NS
geometry are enumerated in the companion NS leaf ledger and
`tools/fixtures/cm33f_secure_reference/README.md`.

| Reference / C33S Baseline | Staged C3FS Decision |
| --- | --- |
| C33S identity/capacity/exact-cohort hardening | Adapted to unique C3FS namespaces, private geometry and explicit configured limits; no copied scalar lifecycle. |
| Reference `secure_init.c` AIRCR/NSACR/FPCCR | Deferred to actual initializer and fresh policy/readback proof; no unconditional setup in queries. |
| `SecureContext_Init` | Deferred. CONTROL2 is boot policy, not a valid blanket active-FP transfer predicate. |
| Reference heap/owner/stack-seal allocation | Deferred. A bounded static pool may replace heap only with qualified destructive-init, extent, owner, seal and failure-state checks. |
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
and bounded constructor/attachment/body-preflight execution plus compiled
controls. Commands, input/artifact hashes, preprocessed/assembly/ELF/import/map
artifacts remain in the unique output. Counts belong to the final receipt.
Raw instrumentation/SSP/sanitizer/profile/coverage builds additionally link and
execute the actual annotated private helper chains without supplying fake
instrumentation hooks. Local inline-sensitive/GRO CPU reads avoid CMSIS
accessor instrumentation. This proves neither global A32 closure nor a new
FPCCR/lazy-state operation; those operations remain absent.

No Secure lifecycle, actual SG transition, FP stacking/preservation, full paired
runtime, physical no-FPU support, board or exhaustive equivalence is qualified.
Future FPCA/SFPA predicates, NSACR/LSPENS/TS readback, genuine lazy-trigger bounds,
two-image FP data preservation and final common-five/port-eight links are gates,
not missing tests silently treated as equivalence.
