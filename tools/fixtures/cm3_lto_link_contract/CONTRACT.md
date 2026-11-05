# Native CM3 LTO Final-Link Contract

## Fixed Static Scope

This separate static audit admits only native CM3 O2-lto direct linkage for
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`: Cortex-M3/ARMv7-M,
Thumb, ordinary AAPCS, soft ABI, no FPU/MPU/TrustZone, VTOR1, priority bits 4
and raw BASEPRI threshold 16. Initial evidence is the retained native capture
`C:/fz-cm3-lto-transport-20261105-e3`, not an arbitrary current checkout.

Audit both existing ordinary and emit-relocs LTO finals against each link's own
saved machine, map and common native startup provider. The two machine hashes
may agree; that does not replace separate original provider identities.
No compiler, linker, target or earlier mutation suite is rerun by this gate.
This contract reports no implementation, test, audit or qualification PASS.

The result is bounded symbol, placement, target-attribute and retained pointer
contract evidence. It is not complete callable ABI, function semantics,
source/IR-to-machine correctness or a replacement for the closed-root protocols.

## Outer Admission And Reader Boundary

Authenticate caller-bound capture receipt/artifact hashes and complete admitted
input bindings before selected helper/parser imports or output creation. Require
the exact successful native capture scope, source group, target recipe and
captured tool/configuration authority. Use authenticated immutable helper and
binary buffers, including nested imports; no unbound live-source substitution.
Fresh external output must not overlap repository, capture or admitted inputs.
Reject reparse escapes and unintended physical aliases before mkdir.

Use unchanged generic `classic_final_image/elf.py` ELF/map construction and
`compare_load_images`. Do not invoke or weaken ordinary global-slot/global-anchor
or weak-panic predicates. Do not widen existing root adapters to fit this audit.
Original linker-map object identities bind captured machine/startup bytes.
Only actual ELF32 little-endian ARM ET_REL machine objects and ARM ET_EXEC finals
are authority, never WPA IR, saved assembly or reconstructed/rebased ELF.

## Target And Definition Audit

Require the fixed CM3 code-generation attributes on actual machine and final
evidence, consistent with `cm3_final_image/admission.py`. Final float-ABI bits
are exactly soft `0x200`; E3 flags are `0x05000000` for machine and `0x05000200`
for final. Reject contradictory FP/VFP/MVE/PAC/BTI claims. Generic FP-number-model
tags alone are not an FPU-use claim. Attributes are not physical CPU proof.

Require exactly one defined GLOBAL STT_FUNC with bounded positive extent,
default visibility, Thumb entry and executable storage/load for every declared
callable below. Bind its actual input section/offset/size through a unique full
map placement to the final definition. Reject aliases, overlaps, foreign
providers or name-only origin. Preserve raw metadata and actual function sizes.

The public five operations are:

```text
ctxrt_v1_init
ctxrt_v1_current
ctxrt_v1_set_dispatcher
ctxrt_v1_start
ctxrt_v1_yield
```

The eight forward operations declared by `context/context_port_abi.h` are:

```text
fiber_port_context_init
fiber_port_runtime_memory_barrier
fiber_port_panic_wait
fiber_port_require_scheduler_configuration_environment
fiber_port_runtime_prepare_start
fiber_port_runtime_select_first
fiber_port_runtime_start_first
fiber_port_runtime_schedule
```

Other legitimate internal helpers are not additional forward ABI operations.
Four-byte public veneers and actual THM_JUMP24 tail transfers must not be
misclassified as missing functions or forced through a BL-only root decoder.
This audit establishes definition placement, not complete body/call semantics.

## Strong Handlers, Vectors And Common State

Require unique strong GLOBAL SVC_Handler/PendSV_Handler definitions, independent
machine/map origins and executable Thumb entries. The 1024-byte read-only vector
section is at address zero; slots 11/14 contain their exact odd symbol values.
Bind reset entry/vector and initial stack `0x20010000` to the startup provider.
Vector contents do not prove routing or exception execution.

The post-LTO current slot is a LOCAL four-byte STT_OBJECT at offset zero in its
dedicated four-byte NOBITS input section. Map it into final writable,
non-executable zero-fill BSS; E3 places it at `0x20000480`. Reject overlap or
substitution by another valid BSS address. Do not require pre-LTO global binding.

The reverse-v1 anchor is a LOCAL one-byte read-only object with value byte 1.
In E3 it is machine `.rodata+1`, final `0x1649`. Bind actual section placement,
not an ordinary-reader GLOBAL predicate. This proves retained identity/storage,
not every cold ABI read or reverse-service implementation.

Default `fiber_panic` is GLOBAL FUNC after LTO, despite its weak source definition.
Require its unique actual machine/final placement and retain the real binding.
Do not require post-LTO WEAK or infer that application override behavior passed.

Reject named undefined final symbols and legacy `fiber_init`, `fiber_current`,
`fiber_start`, `fiber_schedule`, `fiber_scheduler_set_pick_next` or `fiber_v1_*`
callable API. Legitimate common configuration state must not be rejected through
a coarse symbol-prefix rule. Typed fixture compilation is not complete C ABI proof.

## Exact Cohorts And Pointer Authorities

Require the complete private cohort key from admitted ordinary source/object
authority, not a partial VTOR/priority substring, plus exactly
`fiber_port_storage_cohort_arm_cm3_v1_r0`. Here v1 is storage revision 1 and r0
is zero MPU regions. Both are GLOBAL one-byte read-only objects with value 1.
E3 places private key at `.rodata+0`/`0x1648` and storage key at +2/`0x164A`.

The retained `.fiber_port_context_cohort_expectation` is eight read-only bytes:
storage pointer at offset 0 and build-owned private pointer at offset 4.
`.pilot_roots` is 20 read-only bytes, five pointers in the public-five order above.
Bind both complete input sections and their final placements, actual provider
objects, exact named targets and all seven original R_ARM_ABS32 fields. Decode
the original machine words independently as zero addends; require each applied
pointer to equal its exact mapped object/function value, retaining Thumb bits.

The emit-relocs final must retain the corresponding exact seven residual
relocations with matching sites/kinds/targets. The ordinary final normally has
no such metadata: validate its applied bytes from its own original REL authority
and map instead of requiring emit-relocs records. Independently compare final
load geometry/bytes, allocated/vector sections and entry across genuine twins.
Printed symbol names, pointer counts or linker ASSERT text alone are insufficient.

## Future Fresh-Link Controls

These are distinct subsequent work, not outcomes of the existing-image audit:

- A typed strong application panic must win a genuine fresh LTO link. Bind actual
  plugin resolution, the supplied provider's map placement and final call targets.
- Competing strong SVC/PendSV definitions must fail on their intended symbols.
- Valid-but-mismatched private cohort, storage revision and reverse-v1 inputs must
  fail on their exact unresolved identities, not unrelated compile/link errors.

Retain real compiler/plugin/worker commands, resolution/response files, original
REL and fresh artifact closure for those controls. A regular-object panic adds
another machine provider; do not relax the frozen two-provider root adapter or
claim its unchanged root qualification for that different integration.

## Closure And Nonclaims

The witness retains source/binary copies, original identities, input hashes,
per-twin metadata/map/reference records and comparison evidence. Close physical
bindings and all admitted memberships/hashes, including exact output membership.
Seal results/manifest consistently; late drift or sealing failure must persist
FAIL. No partial result, copied historical PASS or unexecuted control promotes.

Full API/ABI, source/IR semantics, per-TU machine ownership, general code/override
semantics, policy, kernel behavior, archive/other-mode/cohort coverage and
CPU/hardware/global qualification remain false or unproved. Required-cell/global
credit remains typed integer zero. No production, frozen reader or matrix change.
