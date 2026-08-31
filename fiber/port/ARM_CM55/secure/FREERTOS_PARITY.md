# ARM_CM55 SecureContext Gateway FreeRTOS Parity Ledger

## Slice 3 Status

This paired Secure artifact implements eight immutable C55S NSC veneers: four
cohort identity facts and four SecureContext capacity facts. The Secure
manifest explicitly provides the maximum attached-fiber count and maximum
Secure stack size. A private, aligned `.fiber_secure_context_pool` reservation
contains the FreeRTOS-shaped record prefix and fixed stack capacity, but Slice
3 does not read, initialize, allocate, attach, load, or save it. The matching
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

| Reference file | SHA-256 | Slice-3 disposition |
| --- | --- | --- |
| `secure_context.h` | `8209F4BAF60741E8ED5516AF9706FC4B5B2EE3CF16452EDB0C034B7DDDE443B4` | Its opaque record prefix and 8-byte stack policy are mapped to Secure-private static capacity storage. |
| `secure_context.c` | `E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72` | Fixed static capacity is adopted; FreeRTOS heap allocation, initialization, and lifecycle remain deferred. |
| `secure_context_port.c` | `B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E` | Future Secure PSPLIM/PSP save-load ordering reference. |
| `secure_heap.h` | `E58805B998EE73A9EB84627EBD2955787CDFD0CD968D1BC7D93423441BAB6C87` | Future allocation vocabulary; it must not introduce a default Fiber heap. |
| `secure_heap.c` | `CE5D5F7FC774E7EC51157F5078361F3CB0A20CE9C94593396F543E5046E53F42` | Dynamic FreeRTOS allocation reference, deliberately deferred. |
| `secure_init.h` | `7704E518DFAAE39170274B7DD924B1A214FFFB12DC37C050E7D3457B5AA0E149` | Future Secure initialization interface reference. |
| `secure_init.c` | `1B8444698089651C6415D48A2B6716BA6C6DC32F71C51B679F5A8A9A3968DE55` | Future PRIS and Secure CPU-startup ordering reference. |
| `secure_port_macros.h` | `5F2DF28DF3D445F08727CAF41F83ED6C67E0494E40AF5572B5E18F6416B2838D` | Future Secure compiler/architecture helper vocabulary. |

All listed M55 Secure reference files are byte-identical to their pinned CM33
counterparts. FreeRTOS itself does not export a versioned companion identity
handshake. Fiber adds this narrow CMSE-only augmentation before stateful
SecureContext mechanics so both firmware images can fail closed on a foreign
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
```

Each Secure definition is `cmse_nonsecure_entry`, `used`, and `noinline`. The
Non-secure import header intentionally carries no Secure entry attribute. The
identity gateway reports C55S / `0x43353553`, layout `0x00010001`, feature mask
`0x8A`, and ABI version `1`. The capacity gateway reports independent ABI
version `1`, 8-byte stack alignment, and the exact Secure-manifest count and
stack-capacity values.

## Secure Capacity Reservation

The Secure manifest must define both
`FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT` and
`FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES`; there is no default Secure RAM
budget. The fixed `.fiber_secure_context_pool` image is retained in a dedicated
`NOLOAD` section and is eight-byte aligned. It reserves one 24-byte record plus
one requested-capacity stack and two 32-bit seal words per context. It remains
inert in Slice 3: later one-shot Secure initialization must erase the whole
image before any allocation or Secure PSP/PSPLIM operation. Count is bounded
to `0xFFFFFFFE` so a later opaque index-plus-one handle retains zero as the
invalid value.

## CMSE Proof

The matrix builds the Secure image with `-mcpu=cortex-m55 -mcmse`, emits a
GNU CMSE import library through `--cmse-implib --out-implib`, and links the
Non-secure probe against it at `-O2`, `-Os`, and `-O2 -flto`. It proves:

1. exactly eight C55S v1 NSC imports inside the aligned `.gnu.sgstubs` region;
2. matching Non-secure import linkage;
3. missing import, v2-only import, and foreign generic-profile import failures;
4. exact retained Secure pool section geometry for a manifest-budgeted probe;
5. fail-closed Secure manifests for wrong role/core, FPU, MVE, PAC, MPU, and
   invalid or missing pool capacity.

No generated SecureContext initialization, allocation, save/load, attachment,
or Non-secure SVC/PendSV assembly is claimed by this slice.
