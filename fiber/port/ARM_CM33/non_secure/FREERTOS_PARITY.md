# ARM_CM33 Non-Secure SecureContext Parity Ledger

## Status

Slices 1-6 freeze the build-selected public storage, physical saved-frame
dictionary, exact context construction, sealed pre-start attachment, paired
identity/stateful NSC gateways, Secure-private storage, all eight mandatory
forward runtime operations, and strong SVC and PendSV for the no-MPU, no-FPU
Cortex-M33 TrustZone Non-secure profile. This is a complete selected runtime
port: first start initializes and loads Secure state, while PendSV performs
Secure save/unload, scheduler selection, one-time lazy allocation, Secure
load, and exact eleven-word Non-secure restore.

The profile remains intentionally absent from global auto/profile selection.
It may be
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
record adds `secure_stack_bytes`: zero means no attachment; the implemented
pre-start selected-port attach operation seals a nonzero requested size. The
durable opaque handle belongs to software-frame word 0. One port-private live
handle mirrors FreeRTOS `xSecureContext` only while a context is active; common
runtime and public storage cannot inspect or mutate it.

## Deliberate Boundary

The profile-specific attach header records and reseals a request but cannot
load, save, free, or otherwise switch Secure state from Thread mode. It retains
the optional common pre-publication lifecycle ABI, rejects Handler mode before
that guard, and checks the matched Secure identity/capacity veneers without
changing CPU state. Every cross-image result is checked only after a fresh
Non-secure CPU-state readback. The paired `ARM_CM33/secure` image exports four
immutable identity queries plus a separate
eight-function stateful gateway. It initializes PRIS and Secure Thread state,
preserves the FreeRTOS allocation/save/load ordering, accepts initialization
only from exact exception 11 (`SVCall`), save only from exact exception 14
(`PendSV`), and allocation/load only from one of those two runtime exceptions.
It requires zero pre-load Secure PSP/PSPLIM and delegates to the fixed Secure
pool. Initialization becomes irreversibly in-progress
before its first destructive write, so partial failure cannot retry. The real
GNU CMSE
image, generated import library, matching Non-secure construction/attach link,
missing-import/lifecycle negative links, and v1/v2 mismatch negative link are
compile-matrix-covered at `-O2`, `-Os`, and `-O2 -flto`.

Strong SVC 70 validates exact origin/opcode/immediate and the initial frame,
then initializes the Secure companion, allocates an attached first context,
writes frame word zero, loads owned Secure state, revalidates the frame, and
restores `[handle, PSPLIM, EXC_RETURN, r4-r11]`. Strong PendSV validates current
before metadata reads, saves and unloads Secure state before selection, saves
the exact eleven-word Non-secure software frame, selects under BASEPRI, lazily
allocates an attached never-run context, restores PSPLIM, loads owned Secure
state, restores r4-r11/PSP, and returns through exact EXC_RETURN. Generated
construction, Secure initialization, allocation, save/load, SVC, and segmented
PendSV are pinned at `-O2` and `-Os` under
`FAP-CM33-SECURE-CONTEXT-CONSTRUCTION`,
`FAP-CM33-SECURE-CONTEXT-INITIALIZE`,
`FAP-CM33-SECURE-CONTEXT-ALLOCATOR`,
`FAP-CM33-SECURE-CONTEXT-SAVE`,
`FAP-CM33-SECURE-CONTEXT-LOAD`,
`FAP-CM33-SECURE-CONTEXT-FIRST-START`, and
`FAP-CM33-SECURE-CONTEXT-LAZY-ALLOCATE`.

For a later attached context, sealed `secure_stack_bytes != 0` plus frame
handle zero means not-yet-allocated. PendSV allocates it exactly once after
unloading current Secure state and before owned load; unattached contexts keep
both request and handle zero.

TF-M remains an alternative profile using the NTZ CPU mechanics and TF-M
integration. It must not be linked with this fiber-owned companion.

## Current Proof

The compile matrix proves C and C++ public-type consumption without CMSIS, the
exact build-selected CM33 manifest, one retained context cohort with distinct
`C33S` identity and SecureContext-slot token, fixed 11-word geometry, and
fail-closed rejection of selector mode, Secure CMSE, wrong core/architecture,
VTOR-less, FPU, MVE, and a runtime-selectable override. A separate optional
common ABI probe proves matching and mismatched lifecycle-anchor links under
normal and LTO builds. The paired gateway proof additionally covers GNU CMSE
Secure/Non-secure image compatibility at `-O2`, `-Os`, and `-O2 -flto`, while
proving exact twelve-veneer import surface, all eight selected forward-runtime
operations, strong slots 11/14, current-slot assembly-load-only access,
duplicate-handler rejection, Secure pool placement, and missing/mismatched
companion and lifecycle failures. Independent handler and attachment bundle
anchors also prove ordinary one-pass static-archive extraction under section
GC in normal and LTO builds, without `--whole-archive` or a linker group. Lazy
allocation bounds-checks the returned handle against the guarded companion
capacity query before writing frame word zero. This is
compile/assembly/CMSE/ELF/LTO evidence only; no hardware claim is made.
