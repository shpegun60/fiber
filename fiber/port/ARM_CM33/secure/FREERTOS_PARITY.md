# ARM_CM33 Secure Gateway Parity Ledger

## Status

This is a gateway-only Secure companion artifact for the exact no-MPU, no-FPU
`ARM_CM33/non_secure` layout profile. It exports four versioned NSC identity
queries and no SecureContext state, stack allocator, Secure service, SVC,
PendSV, or user-facing API. It is not a SecureContext runtime claim.

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
companion-version handshake. Fiber therefore adds a smaller gateway-only v1
identity surface before introducing any stateful operation:

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

The next Secure companion slice owns fixed-pool/application-storage policy and
the exact `SecureContext_AllocateContext` equivalent. The later selected
Non-secure runtime must then prove FreeRTOS-shaped handler-side allocation,
save, and load ordering at `-O2` and `-Os`. This gateway artifact does not
pretend to perform any of those actions.
