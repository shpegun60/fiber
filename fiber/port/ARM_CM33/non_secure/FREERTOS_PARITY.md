# ARM_CM33 Non-Secure SecureContext Parity Ledger

## Status

Slice 1 freezes only the build-selected public storage and physical saved-frame
dictionary for the no-MPU, no-FPU Cortex-M33 TrustZone Non-secure profile. It
does not provide `fiber_port_context_init()`, SVC, PendSV, a Secure companion,
or `fiber_port_secure_context_abi.h`; consequently it is not a runtime port or
a SecureContext support claim.

The profile is intentionally absent from global port selection. It may be
included only through an explicit `FIBER_PORT_BUILD_SELECTED=1` manifest with
the `ARM_CM33/non_secure` include path, an ARMv8-M Mainline Cortex-M33 target,
and a GCC Non-secure `__ARM_FEATURE_CMSE == 1` compilation. Secure `-mcmse`
builds identify as CMSE level 3 and fail closed.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
CPU runtime:     portable/GCC/ARM_CM33/non_secure/
Secure companion: portable/GCC/ARM_CM33/secure/

port.c:                BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A
portmacro.h:           60DB3E36671EA9075ED11F369940330355377B7B0B2F044E843E8853BFC9FBAE
portmacrocommon.h:     324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2
portasm.c:             6F39F5CB7A24766DF3FA025E41E0E502301550136151B5E2EABDFA9AC4E42D60
secure_context.h:      8209F4BAF60741E8ED5516AF9706FC4B5B2EE3CF16452EDB0C034B7DDDE443B4
secure_context.c:      E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72
secure_context_port.c: B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E
```

## Frozen Non-MPU, No-FPU Frame

The selected FreeRTOS configuration is:

```text
configENABLE_MPU = 0
configENABLE_TRUSTZONE = 1
configRUN_FREERTOS_SECURE_ONLY = 0
configENABLE_FPU = 0
configENABLE_MVE = 0
configENABLE_PAC = 0
configENABLE_BTI = 0
```

`pxPortInitialiseStack()` seeds `xSecureContext = 0`, then `PSPLIM`, then
`EXC_RETURN`. The non-MPU `PendSV_Handler()` saves and restores that same order
around `SecureContext_SaveContext()` and `SecureContext_LoadContext()`.

```text
low address / FiberContext.sp

word  0  xSecureContext = 0 initially
word  1  PSPLIM
word  2  EXC_RETURN = 0xFFFFFFBC
word  3  r4
word  4  r5
word  5  r6
word  6  r7
word  7  r8
word  8  r9
word  9  r10
word 10  r11
word 11  r0        hardware frame
word 12  r1
word 13  r2
word 14  r3
word 15  r12
word 16  LR
word 17  PC
word 18  xPSR

high address
```

This is eleven software words / 44 bytes, a 76-byte initial saved context, and
an 80-byte maximum saved context with the exception alignment word. Starting
from an 8-byte aligned stack top, `FiberContext.sp` is four modulo eight while
the hardware frame remains 8-byte aligned.

The public `FiberContext` remains a saved-SP plus port boot record. The boot
record adds `secure_stack_bytes`: zero means no attachment; a future pre-start
selected-port attach operation will seal a nonzero requested size. The live
opaque secure handle is deliberately not duplicated in C storage: it belongs
to software-frame word 0 exactly as `xSecureContext` belongs to the FreeRTOS
saved task frame.

## Deliberate Boundary

This slice provides neither a selected-port SecureContext header nor a stub.
It cannot allocate, save, load, free, or otherwise touch Secure state. The
common pre-publication lifecycle guard is now implemented separately and has a
versioned optional link anchor, but this layout-only profile does not retain or
call it. The next slices must introduce, in order:

1. a versioned Non-secure-to-Secure companion gateway ABI;
2. a matching `ARM_CM33/secure` companion artifact and two-image compatibility
   proofs;
3. sealed pre-start attachment plus first-start allocation/load;
4. FreeRTOS-shaped PendSV save/load ordering with generated-assembly evidence
   at `-O2` and `-Os`.

TF-M remains an alternative profile using the NTZ CPU mechanics and TF-M
integration. It must not be linked with this fiber-owned companion.

## Slice-1 Proof

The compile matrix proves C and C++ public-type consumption without CMSIS, the
exact build-selected CM33 manifest, one retained context cohort with distinct
`C33S` identity and SecureContext-slot token, fixed 11-word geometry, and
fail-closed rejection of selector mode, Secure CMSE, wrong core/architecture,
VTOR-less, FPU, MVE, and a runtime-selectable override. A separate optional
common ABI probe proves matching and mismatched lifecycle-anchor links under
normal and LTO builds. It also proves that no selected runtime or SecureContext
API artifact has been introduced yet.
