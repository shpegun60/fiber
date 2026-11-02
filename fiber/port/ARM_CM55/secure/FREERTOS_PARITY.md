# ARM_CM55 SecureContext Gateway FreeRTOS Parity Ledger

## Slice 7 Status

This paired Secure artifact implements twelve C55S NSC veneers: four immutable
cohort identity facts, four immutable SecureContext capacity facts, and one
stateful Secure CPU/pool initializer plus allocation, load, and save. The Secure
manifest explicitly provides the maximum attached-fiber count and maximum
Secure stack size. A private, aligned `.fiber_secure_context_pool` reservation
contains the FreeRTOS-shaped record prefix and fixed stack capacity. Slice 4
adds Secure-private one-shot memory initialization, static allocation, and owned
lookup. Slice 5 composes the private pool initializer with Secure CPU setup in
one guarded NSC entry. Slice 6 adds guarded NSC allocation/load/save around the
unchanged private pool and scalar CPU stack-transfer policy. The three pool
operations themselves stay Secure-private; there is no attachment or Non-secure
caller runtime. Slice 7 binds the two gateway objects to the pool object's exact
private configuration without changing any NSC name, context layout, or pool
geometry. The matching
Non-secure import surfaces are
`ARM_CM55/non_secure/fiber_port_secure_gateway_abi.h` and
`ARM_CM55/non_secure/fiber_port_secure_context_gateway_abi.h`.

The C55S cohort spelling and `v1` are part of every exported symbol. Therefore
a generic CM33 import library, another C55 profile, or a v2-only companion
cannot satisfy the Non-secure link. Returned immutable values are retained for
the later sealed attachment and stateful lifecycle guards as a second line of
identity validation.

## Pinned Reference

```text
FreeRTOS commit:  a50edad08b29052631aa469d4df6e6ec7ff68878
Secure companion: portable/GCC/ARM_CM55/secure/
```

| Reference file | SHA-256 | Current disposition |
| --- | --- | --- |
| `secure_context.h` | `8209F4BAF60741E8ED5516AF9706FC4B5B2EE3CF16452EDB0C034B7DDDE443B4` | Its opaque record prefix and 8-byte stack policy are mapped to Secure-private static capacity storage. |
| `secure_context.c` | `E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72` | Static pool initialization, index-plus-one handles, duplicate-owner prevention, and record construction are adapted. The scalar no-MPU CPU initialization order is composed with the private pool. NSC allocation/load/save add exact caller/exception/policy/ownership gates and success returns. Heap/free are excluded by the static-lifetime policy. |
| `secure_context_port.c` | `B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E` | Scalar no-MPU load writes PSPLIM then PSP; save stores PSP then clears PSPLIM and PSP. Both are adapted locally with barriers/readbacks. CONTROL stack slots and FP/MVE deferred-stacking triggers are absent for this exact configuration. |
| `secure_heap.h` | `E58805B998EE73A9EB84627EBD2955787CDFD0CD968D1BC7D93423441BAB6C87` | Allocation vocabulary is inventoried; no heap API is exported by this static profile. |
| `secure_heap.c` | `CE5D5F7FC774E7EC51157F5078361F3CB0A20CE9C94593396F543E5046E53F42` | Heap allocation is deliberately replaced by bounded preallocated stacks, not silently omitted. |
| `secure_init.h` | `7704E518DFAAE39170274B7DD924B1A214FFFB12DC37C050E7D3457B5AA0E149` | Initialization vocabulary is composed into one C55S NSC entry, not exported as generic FreeRTOS names. |
| `secure_init.c` | `1B8444698089651C6415D48A2B6716BA6C6DC32F71C51B679F5A8A9A3968DE55` | Keyed AIRCR.PRIS update precedes SecureContext initialization. BFHFNMINS preflight and readback are intentional hardening. NSFPUAccess is not adopted by this scalar no-FPU cohort. |
| `secure_port_macros.h` | `5F2DF28DF3D445F08727CAF41F83ED6C67E0494E40AF5572B5E18F6416B2838D` | IPSR, PSPLIM, PSP, and CONTROL instructions are mapped locally with explicit barriers/readbacks. Interrupt-mask manipulation and mask-changing assertion paths are not imported. |

All listed M55 Secure reference files are byte-identical to their pinned CM33
counterparts. FreeRTOS itself does not export a versioned companion identity
handshake. Fiber adds this narrow CMSE-only augmentation alongside stateful
SecureContext startup so both firmware images can fail closed on a foreign
cohort or ABI version.

## Exact NSC Surface

```text
fiber_secure_gateway_c55s_v1_abi_version
fiber_secure_gateway_c55s_v1_context_port_id
fiber_secure_gateway_c55s_v1_context_layout_version
fiber_secure_gateway_c55s_v1_context_feature_mask
fiber_secure_context_gateway_c55s_v1_abi_version
fiber_secure_context_gateway_c55s_v1_stack_alignment
fiber_secure_context_gateway_c55s_v1_max_stack_bytes
fiber_secure_context_gateway_c55s_v1_max_contexts
fiber_secure_context_gateway_c55s_v1_initialize
fiber_secure_context_gateway_c55s_v1_allocate
fiber_secure_context_gateway_c55s_v1_load
fiber_secure_context_gateway_c55s_v1_save
```

All twelve Secure definitions use `cmse_nonsecure_entry`, canonical
`FIBER_API_ATTR_SENSITIVE`, and `FIBER_GENERAL_REGS_ONLY`. This includes the
original eight query names, which are unchanged. The
Non-secure import header intentionally carries no Secure entry attribute. The
identity gateway reports C55S / `0x43353553`, layout `0x00010001`, feature mask
`0x8A`, and ABI version `1`. The capacity gateway reports independent ABI
version `1`, 8-byte stack alignment, and the exact Secure-manifest count and
stack-capacity values. The initializer and allocation/load/save are private
selected-backend integration operations, not additions to the five portable or
eight generic-port operations. A query-only or nine-entry C55S import library
cannot satisfy the new complete import set; neither the cohort identity/layout
nor the existing v1 query values are changed. This additive staged surface does
not change saved-context representation or the gateway ABI version.

## Secure Capacity Reservation

The Secure manifest must define both
`FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT` and
`FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES`; there is no default Secure RAM
budget. The fixed `.fiber_secure_context_pool` image is retained in a dedicated
`NOLOAD` section and is eight-byte aligned. It reserves one 24-byte record plus
one requested-capacity stack and two 32-bit seal words per context. The private
initializer erases and reads back every byte of that image before allocation.
Count is bounded to `0xFFFFFFFE` so the opaque index-plus-one handle retains zero
as invalid. There are two separate four-byte state markers in normal Secure
BSS, not in retained NOLOAD storage: the unchanged private pool marker and the
new `fiber_secure_context_gateway_state`. For the three-context/1024-byte
fixture, the pool image stays exactly 3168 bytes; the eight BSS bytes are
additional and both markers must be zero-initialized by Secure startup.

## Secure-Private Object Cohort

`fiber_secure_context_cohort.h` binds the identity gateway, capacity/lifecycle
gateway, and private pool objects to one evaluated tuple. This is a Fiber-added
build-consistency mechanism, not a copied FreeRTOS operation or a new NSC API.
The generation-1 key starts `fiber_secure_context_cohort_c55s_g1` and has this
fixed field order:

| Tag | Exact unsigned 32-bit fact |
| --- | --- |
| `p` | C55S port ID |
| `l` | Non-secure context layout version |
| `f` | Context feature mask |
| `i` | Identity gateway ABI version |
| `c` | SecureContext gateway ABI version |
| `r` | Independent private record-layout revision, initially `1` |
| `n` | Maximum Secure context count |
| `b` | Per-context maximum usable stack bytes |
| `a` | Secure stack alignment, asserted equal to the gateway contract |
| `w` | Stack seal word count |
| `s` | Stack seal byte count |
| `v` | Stack seal value |

Each field becomes `_tag_hi_lo`, with two independently delimited evaluated
16-bit constants. Each component is in `0..65535`; the original fact is checked
against the uint32 domain before conversion. The pair is injective because
`value = hi * 65536 + lo`. Equivalent constant expressions therefore name the
same provider: no arbitrary count/capacity expression is token-pasted into an
identifier. Twelve facts require 24 immediate operands; the consumer's one
scratch output brings its total to 25, below GCC's 30-operand limit. Private
revision 1 separately asserts all six record offsets, size 24, alignment 4,
and pointer width 32. A semantic/layout change must revise that private record
identity and its matching assertions even when aggregate storage size is equal.

Every one of the eight independently rootable immutable queries first calls
the strong, non-NSC C function
`fiber_secure_context_pool_c55s_v1_cohort_provider`, then performs a volatile
address load and byte read of its own exact key. The C helper is an ordinary
archive/LTO-visible extraction edge, not an asm-only symbol-index assumption.
Its canonical sensitive/noipa/general-register-only definition emits exactly
one strong one-byte object in `.rodata.fiber_c55s_private_cohort`. Its
unconditional extended asm restores the input section, escapes literal `%`
signs, and uses neither weak/common definitions nor conditional duplicate
suppression. Calling it performs no pool initialization, state/BSS access,
allocation, or CPU-policy write. The new byte is read-only program storage;
pool and BSS geometry do not change. The linker must map its `.rodata*` with
Secure read-only program data; merging it into read-only `.text` is permitted.

Initializer retention is after direct immediate-NS-origin, SVC, zero-state, and
BFHFNMINS preflight, but before publishing INITIALIZING. Its remaining CPU/pool
ordering and failures are unchanged. There are no cohort calls or reads added
to allocation/load/save hot paths. Compiler-generated CMSE entry/exit security
housekeeping is still subject to the exact `FAP-CMSE-M55` classification.

### Build-Owned Generation Gate

The Secure image integration must include
`fiber_secure_context_cohort_contract.ld`, either at top level from the board
script or as an additional `-T` after that primary script. It asserts that
`fiber_secure_context_pool_c55s_v1_cohort_provider` is defined. It has no
`EXTERN`, `-u`, forced extraction, or new memory layout: an ordinary query or
initializer must supply the real C dependency. The fragment rejects a wholly
pre-guard archive whose original twelve NSC names would otherwise still link.
Omitting this build-owned assertion loses that whole-old-archive protection.
All objects built before this guard require a clean rebuild; the generation
assertion is not per-object provenance for a mixture of old unguarded gateways
and a new provider.

GNU CMSE linking with a secondary `-T` assertion fragment can require an
explicit `--section-start=.gnu.sgstubs=<NSC address>` even when the primary
script spells a literal veneer VMA. The focused cohort fixture uses
`0x10008000`; the central synthetic fixture uses `0x0C010000`. These are fixture
addresses, not production board defaults. Secure image integration owns the
actual NSC address and attribution: supply the matching explicit section start
for the secondary-script recipe, or correctly INCLUDE the assertion at top
level in the primary board script and qualify that complete link recipe. The
assertion fragment itself does not place veneers or configure security
attribution. This is a linker-integration requirement, not a CPU-source fix.

This is internal Secure-object agreement, not an external application's
expected-capacity check. A coherent guarded archive built as `2/208` is valid
and its queries report `2/208`, even if unrelated application compile defines
say `3/128`. No external expectation object is supplied here. In contrast,
mixing guarded `3/128` gateway objects with a `2/208` pool fails the exact-key
relocation even though both pool reservations occupy 480 bytes. Returned
capacity values remain configured facts, not physical discovery. Public and
cross-image ABI versions, C55S layout/features, and twelve NSC exports remain
unchanged.

## Ordered Secure CPU Startup

`fiber_secure_context_gateway_c55s_v1_initialize` preserves the selected
FreeRTOS sequence: `SecureInit_DePrioritizeNSExceptions` from the first-start
NS SVC path, then `SecureContext_Init` with `configENABLE_MPU=0`. Its exact
ordering and intentional hardening are:

1. Test the immediate Non-secure caller in the entry itself, before a helper
   can replace LR. Require IPSR equal to the private SVC constant `11` and a
   zero gateway marker. IPSR is not proof of the exact Non-secure call site;
   the future Non-secure runtime must validate its own first-start site.
2. Read AIRCR and reject BFHFNMINS=1 before any commitment. PRIS=1 together
   with BFHFNMINS=1 is architecturally UNPREDICTABLE; fault-routing policy is
   not silently changed. These preflight rejections leave gateway/pool state
   and policy registers unchanged.
3. Retain the private cohort through its state-free C helper and exact read,
   then publish INITIALIZING (`0x53434742`), issue DSB/ISB, and verify the latch.
   Failed latch readback executes UDF: returning zero could permit a retry
   if the latch had remained zero.
4. Write keyed AIRCR with PRIS=1, preserving all other non-key fields, issue
   DSB/ISB, and verify the result except for VECTKEYSTAT.
5. Write Secure PSPLIM=0, then Secure PSP=0, issue DSB/ISB, and read both back.
6. Call the unchanged memory-only `fiber_secure_context_pool_boot_initialize`.
   Require exactly `1`; any other return leaves the gateway INITIALIZING.
7. Write Secure CONTROL=2, issue ISB, and require the entire readback to equal
   `2`, not just bits [1:0]. This deliberately verifies that implemented FPCA
   and SFPA bits were also cleared; it does not add FPU/MVE support.
8. Publish READY (`0x53434752`), issue DSB/ISB, and verify before returning `1`.
   Failed READY publication also executes UDF. Other postcommit failures
   return zero without clearing INITIALIZING; initialization cannot retry.

SG is not exception entry into the Secure bank. Armv8-M permits the banked
CONTROL.SPSEL write/readback in Handler mode; CONTROL=2 is correct even while
the Handler physically executes on MSP. There is no entry-time CONTROL=0
assumption. No PRIMASK, BASEPRI, FAULTMASK, NS-bank register, SAU, ITNS, NSACR,
or FPU-policy register is written by the initializer. The serialized single-core
boot contract remains mandatory; interrupt masking is not introduced to obtain it.

The direct GCC/Clang CMSE builtin is used instead of its unannotated inline
wrapper, and the selected-register/barrier instructions use local volatile
assembly rather than instrumentable CMSIS inline wrappers. This keeps the
incoming-LR test ahead of helpers even under hostile instrumentation options.
CMSIS still supplies the exact M55 manifest. Compiler-generated CMSE entry/exit
housekeeping (including FPCXTNS save/restore and register clearing when emitted)
is not an FP arithmetic ABI or application FPU-policy initialization.

## Private Lifecycle Mapping

| FreeRTOS operation or fact | C55S private implementation and difference |
| --- | --- |
| `SecureContextHandle_t`, `securecontextINVALID_CONTEXT_ID` | `FiberSecureContextHandle`, `FIBER_SECURE_CONTEXT_HANDLE_INVALID`; uint32 index plus one, zero invalid, no reuse/free/generation promise. |
| `SecureContext_t` | `FiberSecureContextRecord`; PSP/PSPLIM/top/owner prefix preserved, with checked byte-count and allocation-state fields added. |
| `secureconfigMAX_SECURE_CONTEXTS` | Required `FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT`; no hidden default. |
| Heap-selected stack size | Required `FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES`; fixed slot stride, requested usable size must be nonzero, eight-byte aligned, and within capacity. |
| `securecontextSTACK_SEAL_SIZE/VALUE` | `FIBER_ARM_CM55_SECURE_CONTEXT_STACK_SEAL_*`; same two `0xFEF5EDA5` native words above the requested usable stack, accessed through character object representations to avoid aliasing a declared byte array as uint32 storage. |
| `SecureContext_Init` record initialization | `fiber_secure_context_pool_boot_initialize`; memory-only private operation. Normal BSS state changes 0 -> INITIALIZING -> READY before/after full volatile scrub/readback. Repeated INITIALIZING/READY calls return zero before erasing; unknown state or failed verification traps. No IPSR, PRIS, PSP, PSPLIM, or CONTROL operation is implemented here. |
| `ulGetSecureContext` | `fiber_secure_context_pool_allocate` scans all records, verifies canonical free or complete allocated state, rejects duplicate request owners/exhaustion without mutation, and traps duplicated stored ownership or corruption. |
| `SecureContext_AllocateContext` construction | Private `fiber_secure_context_pool_allocate` seeds saved PSP to top, derives limit/top from the trusted slot, records opaque owner/size, writes the seal, publishes allocated state, validates, and returns index plus one. No malloc or automatic activation. |
| `vReturnSecureContext`, `SecureContext_FreeContext`, `vPortFree` | Deliberately absent: static lifetime, no free/detach/reuse API or stub. |
| Handle/owner checks in reference load/save wrappers | `fiber_secure_context_pool_lookup_owned`; range checked before indexing, metadata checked before seal access, invalid/unallocated/foreign requests return NULL. The pointer stays Secure-private and backs the guarded Slice-6 CPU load/save entries. |

The native private helper inventory is `fiber_secure_context_pool_fail_closed`,
`fiber_secure_context_pool_require_ready`,
`fiber_secure_context_pool_record_is_free`,
`fiber_secure_context_pool_write_stack_seal`,
`fiber_secure_context_pool_stack_seal_is_valid`, and
`fiber_secure_context_pool_record_is_valid`. Slice 7 adds the state-free
`fiber_secure_context_pool_c55s_v1_cohort_provider` described above. All helpers
and the three private lifecycle entry functions use canonical sensitive/
general-register-only attributes.
`fiber_secure_contextPOOL_STORAGE` keeps the exact aligned NOLOAD image;
`POOL_INITIALIZING`, `POOL_READY`, `STATE_FREE`, and `STATE_ALLOCATED` are
profile-private state encodings, not additional public settings.

Callers must be serialized single-core Secure code. This private foundation
does not promise concurrency, interrupt/reentrant allocation, or handles valid
across a Secure reset. It changes neither the five portable calls nor the eight
generic port operations. No application-side extra initialization call is added.

## Guarded NSC Allocation And Stack Transfer

Every new entry tests `__builtin_arm_cmse_nonsecure_caller()` directly before
any helper can replace LR, then reads IPSR locally. Allocation and load permit
only NS SVC (`11`) or NS PendSV (`14`); save permits only NS PendSV. All require
the gateway READY marker and exact live Secure CONTROL equal to `2`. This
additional admission check preserves the scalar, privileged-PSP startup policy
without silently repairing it: nPRIV, SPSEL, FPCA, or SFPA drift is rejected.
SG is not Secure exception entry, so no CONTROL=0 assumption is made. The
check proves only this banked CONTROL policy, not physical FP/MPU absence or
absence of latent lazy FP state. Since SG clears SFPA, rejection of extension
bits must also be tested by injection at the actual admission MRS. Rejection
before backend effects means before pool or explicit CPU-register writes;
compiler CMSE MSP/FPCXT entry housekeeping may already have executed. The
Non-secure runtime must still validate its own exact call site; IPSR alone is
not provenance. All calls require serialized single-core operation.

| Entry | Reference mapping and exact behavior |
| --- | --- |
| `c55s_v1_allocate(uint32_t bytes, uintptr_t owner)` | Maps `SecureContext_AllocateContext` with `configENABLE_MPU/FPU/MVE=0`. Both live PSP and PSPLIM must be zero, stronger than the reference PSPLIM-only test. The unchanged pool rejects zero/unaligned/oversized requests, zero/duplicate owners, and exhaustion; it constructs top-as-initial-PSP and the two seal words without heap allocation or activation. Returns a nonzero index-plus-one handle only on success. |
| `c55s_v1_load(uint32_t handle, uintptr_t owner)` | Maps reference owned load wrapper plus scalar `SecureContext_LoadContextAsm`. Requires nonzero owner and both live stack registers zero. Handle zero succeeds only in that empty state. Nonzero handles use checked owned lookup before reading saved PSP/limit. Write PSPLIM, DSB/ISB, verify it; write PSP, DSB/ISB, verify both. No per-context CONTROL word is read and no CONTROL write occurs. |
| `c55s_v1_save(uint32_t handle, uintptr_t owner)` | Maps reference owned save wrapper plus scalar `SecureContext_SaveContextAsm`. Requires nonzero owner. Handle zero succeeds only when PSP and PSPLIM are both zero. For nonzero handles, owned lookup validates the record/seal; live PSPLIM must match, and live PSP must be eight-byte aligned in the inclusive limit-to-top range. Store PSP through a volatile record access, DSB/ISB, require owned relookup to return the same record and independently read back the stored PSP equal to captured live PSP. Then clear PSPLIM, DSB/ISB, verify zero; clear PSP, DSB/ISB, verify both zero. Pointer identity alone is not successful PSP publication. |

Load/save return `1` only after the complete operation. Rejection or failed
readback returns `0`; corrupted Secure pool metadata/seals trap in the private
pool. A partial CPU or saved-PSP update is terminal for the selected-backend
caller: do not retry, select another context, or resume Thread mode. These
entries provide no rollback or additional sticky state; the future NS caller
must treat a failed transition as terminal. This differs from the initializer's
unchanged sticky INITIALIZING contract. No new BSS or pool storage is added.

The new functions use local volatile system-register assembly, not potentially
instrumented CMSIS/CMSE inline wrappers. They write no CONTROL, interrupt mask,
Non-secure bank, SAU, ITNS, NSACR, or FPU policy register and contain no explicit
FP/MVE stacking trigger. Ordinary FP/MVE data operations remain outside C55S.
This is not a blanket no-`V*` instruction claim: GCC's exact M55 CMSE security
housekeeping is separately qualified as `FAP-CMSE-M55`, including FPCXTNS and
VSCCLRM. A `__FPU_PRESENT=0` fixture is not physical hardware removal; physical
no-FPU/no-MVE QEMU execution remains unqualified.

## CMSE Proof

The maintained matrix checks build the Secure image with
`-mcpu=cortex-m55 -mcmse`, emit a GNU CMSE import library through
`--cmse-implib --out-implib`, and link the
Non-secure probe against it at `-O2`, `-Os`, and `-O2 -flto`. They require:

1. exactly twelve C55S v1 NSC imports inside the aligned `.gnu.sgstubs` region;
2. matching Non-secure import linkage;
3. missing import, v2-only import, and foreign generic-profile import failures;
4. exact retained Secure pool section geometry for a manifest-budgeted probe;
5. fail-closed Secure manifests for wrong role/core, FPU, MVE, PAC, MPU, and
   invalid or missing pool capacity.

The Secure-only link probe roots all three private lifecycle functions under GC
and LTO. Their symbols must remain absent from the exact twelve-entry CMSE import
surface. Executable memory/handle/corruption regressions are a separate focused
runner; link retention alone is not execution evidence.

Historical Slice-5 compile/link inspection with GCC 14.3.1 and real `core_cm55.h`
passed at `-O0`, `-O2`, `-Os`, `-O2 -flto`, and `-Os -flto`, plus `O0/O2/Os`
with instrumentation, stack-protector, profiling, UBSan, coverage, and `-pg`
options enabled for all three production translation units. The linked images
retain exactly nine imports, both four-byte BSS markers, and the unchanged pool
geometry, with no instrumentation dependencies or mask/NS-bank writes. Both
Secure and Non-secure C++ import declarations compile. Actual pinned
`secure_init.c` and `secure_context.c` also compile at `-O2/-Os`; inspected
initialization emits PSPLIM before PSP, then record initialization before
CONTROL=2. This is structural evidence, not execution equivalence.

Focused Slice-6 structural proof with GCC 14.3.1 and real `core_cm55.h` passed
the same eight configurations: `O0/O2/Os`, `O2/Os` LTO, and hostile `O0/O2/Os`
instrumentation. Exact twelve-import linkage, C/C++ declarations, direct
incoming-LR guards, both four-byte BSS markers, and the 3168-byte fixture pool
were retained without linked instrumentation hooks or mask/NS-bank writes.
The new entries have no explicit CONTROL write. Actual pinned CM55
`secure_context.c` and `secure_context_port.c` compile at `O2/Os`; inspected
scalar assembly confirms PSPLIM-before-PSP load and stored-PSP-before-clear
save. The recorded inputs did not drift during this focused proof. It did not
execute SG transitions or establish hardware equivalence; fresh maintained
execution and combined qualification are separate gates.

Maintained two-image Cortex-M55 SG qualification is separate and must cover
real NS SVC success, rejected Secure/NS Thread/wrong-exception callers,
BFHFNMINS rejection with legal retry, repeated calls, preinitialized/failed
pool behavior, failed latch publication, and sticky postcommit failures.
Injected CONTROL readbacks `6/10/14` must be rejected with INITIALIZING retained;
extension-bit observation belongs inside the write/read interval because SG
clears SFPA. Link probes alone do not execute any of these paths.

Slice-6 maintained proof must cover exact twelve-entry CMSE/import/archive/LTO
linkage, stale nine-entry and foreign companions, hostile instrumentation,
direct incoming-LR checks, real NS SVC/PendSV SG cycles, zero/invalid/wrong-owner
handles, duplicate owners/exhaustion, live-stack admission, exact CONTROL
rejection (including `6/10/14`), geometry/seal corruption, PSP-store/readback
faults, and partial PSPLIM/PSP update failures. Guard mutants must be exercised
with all other gates valid. Actual pinned CM55 allocation/load/save assembly
must be compared at `-O2/-Os`; link retention alone proves no execution behavior.

Slice-7 maintained qualification must independently root each immutable query
through ordinary calls, not guard/provider `-u` or `--whole-archive`. Required
coverage includes O2/Os, normal and LTO archives with GC, representative mixed
LTO boundaries, equivalent expressions, single-fact mismatches, equal-size
count/capacity collisions, exactly one retained read-only provider, unchanged
twelve NSC imports/storage/hot paths, and rejection of wholly pre-guard archives
by the separately supplied generation fragment. A coherent different-budget
archive must remain accepted. Hostile instrumentation and existing lifecycle
provenance/ordering regressions must also be requalified for the new helper
edge. Source compilation or successful linkage alone is not execution proof.

Focused Slice-7 GCC 14.3.1 object/archive smoke passed at O2/Os with and without
LTO, all with section GC and no guard/provider force-root. Across 128 ordinary
query-root cases, all eight individual query roots accepted matching tuples,
equivalent arithmetic expressions, and coherent alternate-budget archives;
the equal-480-byte mixed configuration failed on its exact undefined key.
Separate complete-image checks retained twelve NSC imports, one read-only
provider byte, both four-byte BSS markers, and unchanged pool geometry. The
generation fragment rejected pre-guard archives in all four modes. The helper
remained an archive-indexed strong C symbol and its optimized body was only a
return, with no state or CPU-policy operations.

Additional O0/O2/Os, O2/Os LTO, and hostile O0/O2/Os compile/link checks passed
incoming-LR guards, C/C++ declarations, storage checks, and absence of linked
instrumentation hooks. Recorded production inputs did not drift. Allocation,
load, and save source bodies compare unchanged against the qualified 481-input
pre-guard snapshot. These are focused structural results, not new SG execution
or whole-matrix qualification. The maintained private-cohort and lifecycle
regressions, mixed-LTO boundaries, and fresh combined qualification remain
separate gates; no hardware or exhaustive feature/compiler equivalence is
claimed.

No Non-secure Fiber runtime, attachment, or Non-secure SVC/PendSV assembly is
claimed by this slice. Backend NSC allocation/load/save are implemented, but
their maintained execution qualification and the complete C55S scheduler are
separate gates. This companion and private allocator are not a twentieth
complete runtime profile. No hardware validation or exhaustive optimization/
feature-combination equivalence is claimed.
