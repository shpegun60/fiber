# ARM_CM33 Secure Gateway Parity Ledger

## Status

This is the paired Secure companion for the exact no-MPU, no-FPU
`ARM_CM33/non_secure` layout profile. Its NSC surface contains exactly four
versioned identity queries plus a separate eight-function stateful
SecureContext gateway. A Secure-private fixed pool backs one-shot
initialization, allocation, owned save, and owned load. The paired Non-secure
source is a complete build-selected runtime with strong SVC/PendSV and exact
FreeRTOS-shaped Secure save/select/load ordering. Hardware remains unclaimed.
The private-cohort slice binds the two gateway objects and pool configuration
without adding NSC exports, changing storage, or changing transfer hot paths.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
Secure companion: portable/GCC/ARM_CM33/secure/

secure_context.h:      8209F4BAF60741E8ED5516AF9706FC4B5B2EE3CF16452EDB0C034B7DDDE443B4
secure_context.c:      E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72
secure_context_port.c: B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E
secure_init.h:         7704E518DFAAE39170274B7DD924B1A214FFFB12DC37C050E7D3457B5AA0E149
secure_init.c:         1B8444698089651C6415D48A2B6716BA6C6DC32F71C51B679F5A8A9A3968DE55
```

FreeRTOS exposes `SecureContext_Init`, allocation, load, save, free, and
Secure initialization services as NSC functions. It does not define a
companion-version handshake. Fiber therefore separates immutable cohort
identity from stateful SecureContext allocation while keeping pool internals
Secure-private:

```text
fiber_secure_gateway_v1_abi_version
fiber_secure_gateway_v1_context_port_id
fiber_secure_gateway_v1_context_layout_version
fiber_secure_gateway_v1_context_feature_mask

fiber_secure_context_gateway_v1_abi_version
fiber_secure_context_gateway_v1_stack_alignment
fiber_secure_context_gateway_v1_max_stack_bytes
fiber_secure_context_gateway_v1_max_contexts
fiber_secure_context_gateway_v1_initialize
fiber_secure_context_gateway_v1_allocate
fiber_secure_context_gateway_v1_load
fiber_secure_context_gateway_v1_save
```

The version is part of each symbol spelling, so an old or unrelated CMSE import
library fails at Non-secure link time. The returned values let attachment fail
closed on a mismatched cohort or impossible capacity. Initialization preserves
FreeRTOS PRIS, zero PSP/PSPLIM, privileged CONTROL, and pool-clear ordering.
Stateful entries first validate the immediate Non-secure caller, then allocation
preserves the IPSR-then-PSPLIM gate; save preserves
PSP-record-before-PSPLIM/PSP-clear; load preserves PSPLIM-before-PSP. Fiber
narrows initialization to exact exception 11, save to exact exception 14, and
allocation/load to exact exception 11 or 14. It requires zero pre-load PSP and
PSPLIM, rejects reinitialization, validates owner/seal, proves Secure stack
bounds, and reads registers back. Initialization enters an irreversible
in-progress state before its first destructive write, so a partial failure
cannot clear the pool again. Generated ordering is pinned under
`FAP-CM33-SECURE-CONTEXT-INITIALIZE`,
`FAP-CM33-SECURE-CONTEXT-ALLOCATOR`, and
`FAP-CM33-SECURE-CONTEXT-LOAD`, and
`FAP-CM33-SECURE-CONTEXT-SAVE` at `-O2` and `-Os`.

## Static Storage Mapping

FreeRTOS keeps an eight-entry metadata array and obtains every Secure stack from
`secure_heap` through `pvPortMalloc`; `SecureContext_FreeContext` later returns
that stack through `vPortFree`. That matches a dynamic task lifecycle but is the
wrong ownership model for sealed static fibers.

Fiber therefore maps only the durable parts of `SecureContext_AllocateContext`:

```text
FreeRTOS record prefix       -> FiberSecureContextRecord first four words
index + 1 opaque handle      -> identical zero-invalid handle convention
two 0xFEF5EDA5 seal words    -> identical per-request stack-top seal
one task / one context       -> one opaque owner token / one handle
secure_heap allocation       -> manifest-budgeted fixed Secure pool
SecureContext_FreeContext    -> intentionally absent for static Fiber lifetime
```

`FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT` and
`FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES` are mandatory Secure-image
configuration, not defaults in the portable API. A slot reserves exactly the
configured capacity plus eight seal bytes; an attach request may use an
eight-byte-aligned size no larger than that capacity. The pool metadata and
stack slots live in `.fiber_secure_context_pool`, which the Secure linker must
map to Secure RAM only. Pool initialization explicitly clears every record and
every fixed stack slot, so that custom `NOLOAD` placement never relies on a
generic startup `.bss` clear to erase stale Secure RAM. The one-shot versioned
initialize veneer owns this destructive operation and rejects reinitialization
after the gateway has opened.

The pool only initializes, reserves, validates, and looks up Secure records.
The separate NSC gateway owns exact-runtime-exception initialization,
allocation, save, and load; it never dereferences or mutates a Non-secure
`FiberContext`. The Non-secure runtime writes the returned handle to frame word
zero after first-start or lazy PendSV allocation. One port-private live handle
mirrors FreeRTOS `xSecureContext`; Secure save clears it before selection and
Secure load republishes it after ownership validation. Generated
PRIS/init/allocation/save/load/SVC/PendSV ordering is proved at `-O2` and `-Os`.

## Secure-Private Object Cohort

`fiber_secure_context_cohort.h` is local to this C33S companion. It is not a
shared macro engine, CMSIS dependency, public lifecycle API, or extra NSC entry.
The strong non-NSC helper is
`fiber_secure_context_pool_c33s_v1_cohort_provider`; the exact key starts
`fiber_secure_context_cohort_c33s_g1`. The fixed generation-1 schema is:

```text
p  port ID (C33S / 0x43333353)
l  Non-secure saved-context layout version (current generation 2, 0x00020001)
f  context feature mask (0x8A)
i  identity gateway ABI version (1)
c  SecureContext gateway ABI version (1)
r  independent CM33 private record-layout revision (initially 1)
n  maximum Secure context count
b  per-context maximum usable stack bytes
a  stack alignment
w  seal word count
s  seal byte count
v  seal value
```

Every fact is checked in the uint32 domain, evaluated by the compiler, and
rendered as separately delimited `_tag_hi_lo` 16-bit components. This preserves
arithmetic-expression settings without pasting arbitrary tokens into names.
Each component is nonnegative and at most 65535; `value = hi * 65536 + lo`
makes the pair injective. Twelve facts use 24 immediate operands; one scratch
output makes the consumer total 25. Private revision 1 asserts 32-bit pointers,
all six field offsets `0/4/8/12/16/20`, record size 24, record alignment 4,
matching gateway/stack alignment, and seal word/byte geometry. Future private
record semantics/layout changes require their own revision and assertions, not
a gratuitous public or Non-secure context-layout bump.

All eight independently rootable identity/capacity queries call the helper and
perform a volatile exact-key address load and byte read. The ordinary strong C
call is visible to archive/LTO indexing and extracts the actual pool member;
the subsequent exact data relocation, not that common helper name, binds its
configuration. The helper has canonical sensitive/noipa/general-register-only
attributes and emits one strong one-byte object in
`.rodata.fiber_c33s_private_cohort` through unconditional extended asm. Literal
assembler percent signs are escaped and the original section is restored.
There is no weak/common definition, hash-only comparison, or conditional
duplicate suppression. Its optimized executable body is only a return: no
pool initialization, state/BSS access, allocation, or CPU-policy operation.
Map the provider with Secure read-only program data; a read-only `.text` merge
is permitted. No RAM reservation, pool metadata, or BSS marker is added.

Initializer retention follows the existing immediate-NS-origin, exact SVC,
zero-state, and BFHFNMINS preflight, before publishing INITIALIZING. The
remaining initializer order and failure behavior stay unchanged. In particular,
this does not replace CM33's void pool initializer, its masked CONTROL startup
readback, or its save implementation with C55S semantics. Allocation/load/save
receive no new calls, exact-key reads, or behavioral changes.

### CM33 Storage Boundary

Unlike C55S's single pool-image object and separate normal-BSS pool marker,
CM33 retains three existing NOLOAD objects: the record array, aligned fixed
stack array, and four-byte initialized marker. The gateway's separate four-byte
state remains normal BSS. For `3/256`, records occupy 72 bytes and stacks 792;
for `2/400`, records occupy 48 bytes and stacks 816. Both total 868 bytes with
the initialized marker, or 872 in the eight-byte-aligned proof section. This
equal aggregate size is not identity: the exact key encodes count and capacity
separately. This slice preserves these objects, alignments, initialization
policy, and static-lifetime semantics rather than importing C55S storage.

### Build-Owned Generation Gate

Secure integration must include `fiber_secure_context_cohort_contract.ld` at
top level in the primary board script, or pass it as a secondary `-T`. It
asserts that the C33S generation-1 C helper is defined. It is not an extractor:
no provider `-u`, `EXTERN`, or `--whole-archive` is supplied. Ordinary gateway
query/startup references must provide the real C dependency. The assertion
rejects a wholly pre-guard archive even though its original twelve NSC names
still match. All pre-guard objects require a clean rebuild; this presence
assertion does not establish individual provenance for old unguarded gateways
mixed with a new provider.

With GNU CMSE and a secondary `-T`, explicitly supply the board's
`--section-start=.gnu.sgstubs=<NSC address>` where required even if the primary
script has a literal veneer VMA. The manual fixture uses `0x10008000`, not a
production board default. Alternatively, correctly INCLUDE the assertion in
the primary script and qualify that complete recipe. NSC placement and
security attribution remain board-owned, not duties of this ASSERT fragment.

This guard enforces internal Secure-object agreement, not external application
expected capacity. A coherent guarded `2/400` archive is valid and reports its
own facts even when unrelated application defines say `3/256`. There is no
external expectation object here. Capacity queries are configuration facts,
not physical discovery. Public ABI, cross-image symbol spellings, twelve NSC
exports, and the `C33S` context identity/layout/features stay unchanged.

### Compiler ISA Boundary

The nominal C33S configuration key is not proof of the pool compiler's actual
instruction set. Local GCC 14.3.1 emits identical complete predefine sets for
soft-CMSE Cortex-M33 and Cortex-M55, including `+nofp+nomve`, while M55 pool
compilation can emit v8.1-M low-overhead loops and raise final ELF attributes.
Checking Mainline and absent FP/MVE/PAC macros alone cannot reject that case.
The private header now checks the exposed Mainline/M-profile/Thumb-2/Secure
facts and rejects exposed unsupported v8.1, FP-register ABI, MVE, PAC, and BTI
features. Its diagnostic is:

```text
[fiber]: C33S private pool requires a scalar ARMv8-M Mainline Secure compiler target
```

For the qualified GCC path, `pool.c` pushes target options and selects
`arch=armv8-m.main` before including the pool declarations. This covers every
definition, including all static helpers, rather than only extern prototypes.
It pops options at the end of that source: no pragma escapes to gateway/CMSIS
translation units or to code after a textual pool-source include. The ceiling
does not require optional DSP hardware and adds no executable policy operation.
Normal M33 O2/Os pool instruction and relocation images were unchanged in the
isolated comparison against the pre-ceiling objects.

An M55 command-line target can still compile a safely bounded body: that is
not a claimed preprocessor rejection of its literal flags. Input objects with
higher architecture attributes are unsupported and must fail maintained image
admission, independently of whether their particular bodies use a higher
instruction. Both input-object and final-ELF ISA auditing are mandatory. In
the isolated O2/Os normal/LTO links, all bounded bodies lacked higher-ISA loops;
M55 non-LTO objects and final ELFs retained v8.1-M attributes, while M55 LTO
inputs retained v8.1-M attributes but constrained regeneration produced a
v8-M final ELF. Inspecting only the final ELF would miss that unsupported input.
Other compiler paths require their own qualified ceiling/admission evidence;
these GCC measurements are not a blanket compiler-equivalence claim.

This combination is a source-owned GCC codegen ceiling plus build-owned ISA
admission, not a forged CPU-name test or a successful nominal-key link being
misreported as wrong-ISA rejection. Compiler-option, object, and final-ELF
qualification remain distinct from configuration binding.

### Focused Evidence And Remaining Gates

Focused GCC 14.3.1 actual-object/archive smoke passed O2/Os with and without LTO,
all with section GC. Across 128 ordinary C query-root cases, all eight query
roots accepted matching tuples, expression-equivalent `(1u+2u)/(1u<<8)`, and
coherent alternate-budget archives; the equal-872-byte mixed configuration
failed on its exact undefined key. Complete links retained twelve NSC imports,
one read-only provider byte, and the original records/stacks/initialized/gateway
storage geometry. The generation ASSERT rejected exact pre-edit archives in
all four modes. No forced provider root or image execution was used.

After the source ceiling and exposed-fact guard were applied, the 128-case
smoke passed again with no production-input drift. Native O2/Os pool-object
instruction/relocation dumps and all four normal/LTO linked M33 instruction
images matched the pre-ceiling baseline, ignoring only filename banners and
blank lines. The allocation/load/save source bodies also remained unchanged.
Actual lower-M3, Non-secure M33, and hard-FP M33 builds failed with the stated
source diagnostic. Hostile private-pool builds passed at O0/O2/Os without
instrumentation dependencies. A textual-include fixture proved that subsequent
M55 code regained its original target options while the pool remained bounded.
Eight actual production-pool object/link probes established the M33/M55
normal/LTO attribute distinction above; they observed unsupported inputs, not
execution or enforcement by the separate maintained admission runner.

Maintained qualification must separately cover C/C++ ordinary archive roots,
individual stale objects in both directions, normal/mixed/full LTO, synthetic
encoding boundaries for every field, missing/duplicate providers, hostile
helper instrumentation, preserved initializer provenance/order, actual compiler
ISA rejection, and the existing CM33 lifecycle regressions. Synthetic encoder
values are not accepted production manifests. Fresh combined qualification and
hardware validation are not established by these focused link results.

## Caller And Typed-Storage Hardening

Each stateful NSC entry (`initialize`, `allocate`, `load`, `save`) evaluates
`__builtin_arm_cmse_nonsecure_caller()` directly, before any helper call or state mutation.
This is deliberate additional Fiber policy: the reference checks Handler mode,
not immediate caller security. IPSR and caller security prove different facts;
neither authenticates a particular Non-secure instruction site. The trusted
Non-secure port separately owns its SVC-site and scheduler validation. Pure
identity/capacity queries remain callable from either security state.

The seal is still two native `0xFEF5EDA5` words at the requested stack top.
Reference heap storage is untyped, but Fiber stack slots are declared byte
arrays. The helpers therefore copy and compare the constant's character object
representation instead of casting the declared arrays to uint32 pointers.
This preserves bytes, capacity, alignment, and ABI without relying on an invalid
effective-type assumption. Legal compiler coalescing into wider instructions
does not undo the source-level fix.

`tools/test_cm33_secure_guards.ps1` executes the production gateway and private
pool with separately linked Secure/Non-secure images and generated CMSE veneers
on QEMU M33. The maintained cohort covers `-O0`, `-O2`, `-Os`, and both optimized
LTO links, real caller-state positives/negatives, exact incoming-LR checks before
calls, seal corruption, and four isolated caller-guard-removal mutants. These
are additional instruction/CMSE regression proofs, not hardware isolation or
complete TrustZone policy qualification. No common ABI or context layout changed.

## A26: AIRCR Fault-Routing Precondition

Before entering INITIALIZING or setting PRIS, the Secure initializer requires
BFHFNMINS=0. Arm defines the two bits set together as UNPREDICTABLE; checking
the resulting AIRCR afterwards cannot make that write safe. This is an explicit
strengthening of the pinned reference, not a platform remap policy: return 0
untouched when BFHFNMINS is set, without silently clearing it. Valid-input CPU
ordering, masks, gateway ABI, storage and context geometry remain unchanged.
The maintained two-image proof passes five production optimization/LTO modes
and stops five guard-removal mutants before the exact forbidden AIRCR store.
Together with the four original caller mutants this is 14 cases / 28 ELFs.
The parent replay and actual O2/Os FreeRTOS comparison receipts are recorded in
`PORT_ARCHITECTURE_AUDIT.md`; this is not STM32 hardware qualification.

## A32/A33 Raw Compiler Closure And Key Reach

The immutable pre-repair paired audit is retained at
`%TEMP%/fiber-c33-paired-raw-prefix-20261102b`. It reproduces raw CMSIS-helper
instrumentation/forced-inline failures and three unsectioned native-LTO
assembler failures at the exact-key `ldr =symbol` loads. The receipt remains
FAIL; its input manifest SHA-256 is
`D1B0A7D4A70298165814AAD423588A5E9A16F81D53458D74B53FA799DFCAA4ED`.

Stateful entries now invoke the GCC CMSE caller builtin at the original direct
admission site, avoiding an instrumentable wrapper that can itself call before
reading LR. Local CPU/barrier primitives carry the canonical inline-sensitive
bundle and existing GRO restriction. They preserve the CMSIS instruction and
clobber behavior, including the implicit ISB in CONTROL writes and the caller's
additional explicit ISB. The CM33 CONTROL readback remains `(CONTROL & 3)==2`;
it is not changed to the CM55 companion's distinct admission policy.

Each retained query/initializer still calls the same strong pool C provider and
performs the same volatile exact-key byte read. Its address is now materialized
with ARM MOVW/MOVT low/high relocations instead of an assembler-managed literal
pool. All twelve facts, halfword encoding, data symbol, generation, export ABI,
pool geometry, seals, ownership and initializer commitment/order are unchanged.
This is a range repair, not whole-function byte equivalence with FreeRTOS.

The dedicated paired raw gate checks all eight individual call/key relocation
sites, actual helper/caller-wrapper mutants and matched unreachable literal
pressure controls at O2/Os. The MOVW/MOVT variant must lower; reverting only the
address materialization must fail at the exact saved-assembly key loads. Query
archive/cohort and caller-guard fixtures must explicitly understand this measured
relocation/builtin spelling change; old receipts remain historical rather than
being relabeled as proof of current bytes. Actual pinned reference, CMSE image
execution, platform security attribution and hardware remain separate gates.
