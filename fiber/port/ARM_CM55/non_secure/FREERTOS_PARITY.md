# ARM_CM55 Non-secure SecureContext FreeRTOS Parity Ledger

## Slice 1 Status

This staged selected-port profile freezes the exact scalar Cortex-M55
TrustZone Non-secure context dictionary used by the pinned FreeRTOS
`GCC/ARM_CM55/non_secure` port. It is build-selected only, has no runtime claim,
and provides no context constructor, SVC/PendSV handler, forward runtime ABI,
SecureContext pool, attachment API, or global selector route. Slice 2 adds only
the paired immutable identity gateway in `ARM_CM55/secure`; it does not change
this profile into a runtime port.

The future profile is one privileged, no-MPU, no-FPU, no-MVE Non-secure
scheduler image paired with one matching `ARM_CM55/secure` SecureContext
companion. FPU, MVE, MPU, PAC, BTI, TF-M, and Secure-only scheduling remain
separate exact profiles.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
CPU runtime:     portable/GCC/ARM_CM55/non_secure/
Secure companion: portable/GCC/ARM_CM55/secure/
```

| Reference file | SHA-256 | Slice-1 disposition |
| --- | --- | --- |
| `non_secure/portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` | M55 identity and explicit MVE configuration requirement are mapped to exact compiler/trait gates. |
| `non_secure/portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | The shared ARMv8-M frame dictionary is the reference for the future runtime. |
| `non_secure/port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | Deferred to the construction/SVC/PendSV runtime slices. |
| `non_secure/portasm.c` | `6F39F5CB7A24766DF3FA025E41E0E502301550136151B5E2EABDFA9AC4E42D60` | Deferred to the exact SecureContext save/select/load and restore slices. |
| `non_secure/portasm.h` | `185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C` | Deferred selected-port assembly vocabulary; it must be mapped before a C55S runtime source uses inline assembly. |
| `non_secure/mpu_wrappers_v2_asm.c` | `0DC69DD4372646D176CDF98429C8BC9A056E6B0200CB558C51DF4E1F10378D4F` | Explicitly outside no-MPU C55S. Its unprivileged syscall wrappers belong to the separately audited C55M/C55P/C55W MPU cohorts. |
| `secure/secure_context.h` | `8209F4BAF60741E8ED5516AF9706FC4B5B2EE3CF16452EDB0C034B7DDDE443B4` | Future paired opaque-handle contract. |
| `secure/secure_context.c` | `E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72` | Future Secure-private pool and lifecycle reference. |
| `secure/secure_context_port.c` | `B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E` | Future Secure PSPLIM/PSP load-save ordering reference. |
| `secure/secure_heap.h` | `E58805B998EE73A9EB84627EBD2955787CDFD0CD968D1BC7D93423441BAB6C87` | Future Secure-private allocation vocabulary; Fiber must select a static-pool or application-storage policy explicitly. |
| `secure/secure_heap.c` | `CE5D5F7FC774E7EC51157F5078361F3CB0A20CE9C94593396F543E5046E53F42` | Future dynamic FreeRTOS reference only; it cannot silently introduce a heap into Fiber's static-lifetime default. |
| `secure/secure_init.h` | `7704E518DFAAE39170274B7DD924B1A214FFFB12DC37C050E7D3457B5AA0E149` | Future Secure initialization interface reference. |
| `secure/secure_init.c` | `1B8444698089651C6415D48A2B6716BA6C6DC32F71C51B679F5A8A9A3968DE55` | Future PRIS and Secure CPU-startup ordering reference. |
| `secure/secure_port_macros.h` | `5F2DF28DF3D445F08727CAF41F83ED6C67E0494E40AF5572B5E18F6416B2838D` | Future Secure compiler/architecture helper vocabulary; it stays in the paired Secure artifact. |

The pinned M55 `port.c`, `portasm.c`, `portasm.h`, `portmacrocommon.h`, and all
listed Secure companion sources are byte-identical to the pinned CM33
counterparts. Only
`portmacro.h` differs: FreeRTOS names Cortex-M55, reports ARMv8.1-M minor
version one, and requires an explicit `configENABLE_MVE` setting. Fiber does
not import a FreeRTOS config macro; its selected compiler manifest instead
requires scalar `-march=armv8.1-m.main` and rejects compiler MVE state.

## Frozen Non-secure Layout

The future Non-secure software frame is exactly eleven words:

```text
low address -> high address
  word 0  opaque SecureContext handle
  word 1  PSPLIM
  word 2  EXC_RETURN
  words 3..10  r4..r11
```

The initial synthetic frame therefore consumes 76 bytes with the hardware
exception frame. The maximum no-FPU saved representation is 80 bytes including
the exception-alignment word. `FiberPortBoot.secure_stack_bytes` is frozen at
offset 28; it is only a zero-default request field in this slice. `FiberContext`
is 80 bytes and has exact cohort identity `C55S` / `0x43353553` with feature
mask `0x8A`.

## Manifest And Boundary

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
include path: fiber/port/ARM_CM55/non_secure
compiler: -march=armv8.1-m.main -mthumb -mfloat-abi=soft
CMSIS: __CORTEX_M=55, __VTOR_PRESENT=1, __FPU_USED=0
Non-secure compiler: __ARM_FEATURE_CMSE=1
```

Secure `-mcmse` compilation reports CMSE level 3 and is rejected by the
Non-secure profile. The eventual Secure image is a separate artifact, not a
second fiber runtime. Its Slice-2 identity veneers are link-proved separately.
Runtime selection is zero until the future source group can provide all eight
mandatory forward operations and strong vector handlers.

## Deferred Work

1. Versioned Secure identity/gateway ABI and a paired Secure-image manifest.
2. Secure-private static pool and one-shot initialization.
3. Sealed pre-start attachment API.
4. Exact constructor, first SVC, Secure save/load, PendSV, archive, CMSE, and
   generated-assembly proof.
5. M55 hardware TrustZone validation.
