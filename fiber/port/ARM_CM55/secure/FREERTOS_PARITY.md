# ARM_CM55 Secure Identity Gateway FreeRTOS Parity Ledger

## Slice 2 Status

This paired Secure artifact implements exactly four immutable C55S identity
veneers. It has no SecureContext pool, allocation, attachment, initialization,
save, load, SVC/PendSV handler, or second fiber runtime. The matching
Non-secure import surface is
`ARM_CM55/non_secure/fiber_port_secure_gateway_abi.h`.

The C55S cohort spelling and `v1` are part of every exported symbol. Therefore
a generic CM33 import library, another C55 profile, or a v2-only companion
cannot satisfy the Non-secure link. Returned immutable values are retained for
the later stateful lifecycle guard as a second line of identity validation.

## Pinned Reference

```text
FreeRTOS commit:  a50edad08b29052631aa469d4df6e6ec7ff68878
Secure companion: portable/GCC/ARM_CM55/secure/
```

| Reference file | SHA-256 | Slice-2 disposition |
| --- | --- | --- |
| `secure_context.h` | `8209F4BAF60741E8ED5516AF9706FC4B5B2EE3CF16452EDB0C034B7DDDE443B4` | Future opaque-handle contract; no handle exists in this slice. |
| `secure_context.c` | `E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72` | Future SecureContext lifecycle reference. |
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
```

Each Secure definition is `cmse_nonsecure_entry`, `used`, and `noinline`. The
Non-secure import header intentionally carries no Secure entry attribute. The
gateway contract reports C55S / `0x43353553`, layout `0x00010001`, feature mask
`0x8A`, and ABI version `1`.

## CMSE Proof

The matrix builds the Secure image with `-mcpu=cortex-m55 -mcmse`, emits a
GNU CMSE import library through `--cmse-implib --out-implib`, and links the
Non-secure probe against it at `-O2`, `-Os`, and `-O2 -flto`. It proves:

1. exactly four C55S v1 NSC imports inside the aligned `.gnu.sgstubs` region;
2. matching Non-secure import linkage;
3. missing import, v2-only import, and foreign generic-profile import failures;
4. fail-closed Secure manifests for wrong role/core, FPU, MVE, PAC, and MPU.

No generated SecureContext allocation/save/load or Non-secure SVC/PendSV
assembly is claimed by this slice.
