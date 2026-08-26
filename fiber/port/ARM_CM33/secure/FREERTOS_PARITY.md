# ARM_CM33 Secure Gateway Parity Ledger

## Status

This is a Secure companion foundation for the exact no-MPU, no-FPU
`ARM_CM33/non_secure` layout profile. Its NSC surface remains exactly four
versioned identity queries. A Secure-private fixed pool now provides the later
allocation substrate, but it exports no allocator/handle entry through NSC and
still has no Secure service, SVC, PendSV, selected runtime, or user-facing API.
It is not a SecureContext runtime claim.

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
companion-version handshake. Fiber therefore adds a smaller v1 identity-only
gateway surface while keeping its pool state Secure-private:

```text
fiber_secure_gateway_v1_abi_version
fiber_secure_gateway_v1_context_port_id
fiber_secure_gateway_v1_context_layout_version
fiber_secure_gateway_v1_context_feature_mask
```

The version is part of each symbol spelling, so an old or unrelated CMSE import
library fails at Non-secure link time. The returned values allow the future
Non-secure first-start path to fail closed if the Secure image has a mismatched
context cohort.

## Deliberate Boundary

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
configured capacity plus eight seal bytes; a future attach request may use an
eight-byte-aligned size no larger than that capacity. The pool metadata and
stack slots live in `.fiber_secure_context_pool`, which the Secure linker must
map to Secure RAM only. Pool initialization explicitly clears every record and
every fixed stack slot, so that custom `NOLOAD` placement never relies on a
generic startup `.bss` clear to erase stale Secure RAM. It is an explicit,
destructive Secure-boot operation and must never be called again after an
allocation exists.

The pool only initializes, reserves, validates, and looks up Secure records. It
does not expose NSC allocation, mutate a Non-secure `FiberContext`, write PSP or
PSPLIM, or participate in SVC/PendSV. The later selected Non-secure runtime
must prove the FreeRTOS-shaped allocation, save, and load ordering at `-O2` and
`-Os`.
