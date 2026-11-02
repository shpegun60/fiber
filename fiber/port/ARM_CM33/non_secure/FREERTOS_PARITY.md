# ARM_CM33 Non-Secure SecureContext Parity Ledger

## Status

Slices 1-6 freeze the build-selected public storage, physical saved-frame
dictionary, exact context construction, sealed pre-start attachment, paired
identity/stateful NSC gateways, Secure-private storage, all eight mandatory
forward runtime operations, and strong SVC and PendSV for the no-MPU, no-FPU
Cortex-M33 TrustZone Non-secure profile. This is a complete selected runtime
port: first start initializes and loads Secure state, while PendSV performs
Secure save/unload, scheduler selection, one-time lazy allocation, Secure
load, and exact eleven-word Non-secure restore in the historically qualified
Non-secure-origin branch. The 2026-11-02 A30 repair below additionally implements
the reference Secure-origin branch. Its current source is compile/link covered;
fresh dual-origin execution and closed-body parity are pending, so the old
runtime receipts do not qualify this new branch.

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

For a Secure-origin interruption the pinned reference does not transfer the
Non-secure GPR or hardware frame. The entire Non-secure saved image is instead:

```text
word 0  owned nonzero SecureContext handle
word 1  Non-secure PSPLIM
word 2  EXC_RETURN = 0xFFFFFFFC
```

The 12-byte header ends at the interrupted Non-secure PSP. Restore never reads
Non-secure PC/xPSR or r4-r11 for that representation: hardware restores the
Secure frame. A nonzero sealed attachment and live handle are required. Exact
BC/FC admission permits only the S-bit difference, not arbitrary DCRS, FTYPE,
Mode, SPSEL or ES encodings. This is distinct from a Secure-only scheduler's
ordinary FD frame.

### A30 Dual-Origin Repair

Private layout generation is now `0x00020001` on both sides of the identity
handshake. Storage size/alignment and the first-start image are unchanged; the
new generation prevents a layout-1 companion or old private object from silently
sharing the expanded representation contract. Public opaque storage remains
revision 1 because its physical extent does not change.

The PendSV provenance check admits exact BC/FC. Its bounds check reserves 44
bytes before an NS-origin save and 12 bytes before a Secure-origin save, proves
the live PSP upper bound in both cases, and reads hardware xPSR only on the NS
branch. Secure state is saved/unloaded before either NS image store. Integer
save/restore is conditional on S; special-word order remains handle, PSPLIM,
EXC_RETURN. The restore validator proves the three-word header before reading
it and branches before any absent NS frame read. The private save helper also
receives EXC_RETURN and rejects Secure origin without an owned Secure stack.
NSC and scheduler CPU-state guards now include the unchanged NS PSP.

Twelve actual NS objects compile at O0/O2/Os. The existing complete paired
gateway/NS port synthetic link gate passes direct/archive, normal/LTO, vector
and competing-strong-handler cases at:

```text
%TEMP%/fiber-c33s-a30-gateway-af21d075cf174a15b514a98c8ddcaef6
```

This gate's instruction checks are ordered subsets, not a new whole-body parity
or actual Secure-origin execution result. The earlier attempt using raw `ar`
rather than `gcc-ar` failed LTO archive extraction and is retained separately;
it is a test-invocation error, not a production-handler failure. Fresh branch
execution, poisoned absent-frame tests and compiled removal controls remain
required before accepting A30 or a current full-branch parity claim.

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

## Secure-Private Object Binding

The CM33 companion now binds its two gateway objects and private pool through
an independent C33S generation-1 configuration key. Every immutable query and
the precommit initializer retain a real strong C pool-helper call followed by
an exact read-only key read. Allocation/load/save hot paths and the eleven-word
Non-secure context remain unchanged; no new NSC or public operation is added.

Secure integration includes `secure/fiber_secure_context_cohort_contract.ld`
to reject wholly pre-guard archives. This ASSERT does not extract members;
ordinary query/startup calls do. Pre-guard objects need a clean rebuild. The
board still owns NSC placement, explicit veneer section-start options where
needed, and security attribution. The Secure ledger records the twelve-fact,
24-halfword schema and CM33-specific NOLOAD record/stack/marker geometry.

This is internal Secure-object consistency, not an external expected-capacity
object. A coherent alternate-budget companion reports its own configured facts;
the Non-secure attachment/runtime still validates those returned capacities.
The nominal key does not prove compiler ISA: actual pool/object/final-ELF
architecture qualification remains separate, especially where GCC M33/M55
predefines coincide. The private GCC pool source bounds all its own definitions
to baseline ARMv8-M Mainline and restores its options afterwards. Unsupported
higher-ISA input attributes must still fail image admission even when LTO
regenerates a safely bounded final image. New focused archive smoke is not a
claim of fresh SG, whole-matrix, exhaustive compiler-combination, or hardware
qualification.

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

The later A30 actual-common AN505 gate adds 75 dual-origin launches and 2,382
checks at O0/O2/Os and O2/Os LTO, including mixed attachment, real Secure
interruption, exact twelve-byte header bounds, required mapped-poison read
watchpoint controls and old-layout companion rejection. Its maintained runner
is `tools/test_cm33_secure_origin.ps1`; detailed boundaries are in that
fixture's README. Parent rehashes 204 input entries and 2,112 artifacts with
zero mismatches, then preserves 66 repository inputs in
`%TEMP%/fiber-qualified-repo-inputs-f05d6f2d92414d7faeb75953468ca35e`, ZIP SHA-256
`18CE199698613E73E05536D4D29C6442F27A74B853916B9F9EFB02D1A511E62B`.
The focused receipt is
`%TEMP%/fiber-cm33-secure-origin-c72804f2abed47478d18f53cc451e191/results.json`,
SHA-256 `4F58DB769ECFB670DD209920803A3CD518FFB26A05A8BF39043CDDCDA2AF7310`.
Whole-body reference parity and global compiler-attribute closure remain
separate gates; there is no new hardware claim.
