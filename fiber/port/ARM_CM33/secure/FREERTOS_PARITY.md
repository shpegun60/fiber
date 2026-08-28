# ARM_CM33 Secure Gateway Parity Ledger

## Status

This is the paired Secure companion for the exact no-MPU, no-FPU
`ARM_CM33/non_secure` layout profile. Its NSC surface contains exactly four
versioned identity queries plus a separate eight-function stateful
SecureContext gateway. A Secure-private fixed pool backs one-shot
initialization, allocation, owned save, and owned load. The paired Non-secure
source is a complete build-selected runtime with strong SVC/PendSV and exact
FreeRTOS-shaped Secure save/select/load ordering. Hardware remains unclaimed.

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
Allocation preserves the IPSR-then-PSPLIM gate; save preserves
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
