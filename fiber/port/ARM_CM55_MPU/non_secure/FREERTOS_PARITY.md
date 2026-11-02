# ARM_CM55_MPU Non-secure FreeRTOS Parity Ledger

## Protected Startup MSP Policy

This profile requires `FIBER_REWIND_MSP=1`. Its first-SVC provenance contract
uses the validated initial MSP; preserve-current startup is not implemented.
The dictionary explicitly rejects `0` instead of silently ignoring it. Default
startup instructions, frames and context/cohort identity are unchanged. The
pinned FreeRTOS start also restores the initial MSP; no alternate preserve mode
is imported. `tools/test_mpu_start_policy.ps1` maintains positive/default-byte
and exact-diagnostic negative compiles; execution qualification stays separate.

## Sensitive Inline Helpers

Audit A27 adds canonical inline-sensitive/general-registers-only attributes to
the local r9 reader, BASEPRI read/write and four vector-source helpers. These
protect forced-inline code from hostile instrumentation without imposing the
noinline/noipa boundary used by enclosing sensitive operations. No API, frame,
MPU image, identity or normal-code behavior is intentionally changed.

The maintained MPU constructor attribute runner covers this profile's applicable
O2/Os, region-count and compiler-ABI variants. Normal instructions/relocations
match its annotation-removal control; hostile constructors retain the exact
dependency set, while compiled r9 annotation-removal mutants are rejected for
instrumentation/coverage escape. Complete helper probes and the combined matrix
are separate evidence. This does not assert hostile-flag closure of every
runtime/CMSIS call graph.

## Status

This is slice 5 of the explicit build-selected `ARM_CM55_MPU/non_secure`
ARMv8.1-M Mainline profile. It freezes public storage, selected-port traits,
the exact protected frame shape, cohort identity, sealed construction, and
linker-derived global MPU image. `fiber_port_boot.c` owns
`fiber_port_context_init()` and `fiber_port.c` owns the remaining seven frozen
forward operations plus the protected SVC/PendSV engine: strict first-start SVC,
public SVC 71 yield, complete protected PendSV save/select/MAIR0-plus-context-
MPU replacement/restore, and strong slots 11 and 14. It consumes frozen reverse
ABI v1 for scheduler selection and current publication. It remains outside the
global selector, exposes no optional MPU policy API, and has no hardware-support
claim.

The reference is the MPU branch selected by `configENABLE_MPU = 1` inside the
Non-secure `GCC/ARM_CM55_NTZ/non_secure` source group. It is not the separate
TrustZone-capable `GCC/ARM_CM55/non_secure` port and is not an MVE, PAC, or
SecureContext profile.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
FreeRTOS CMake port: GCC_ARM_CM55_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM55_NTZ/non_secure
```

| Reference file | SHA-256 | Current disposition |
| --- | --- | --- |
| `portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` | M55 identity and `configENABLE_MVE` policy mapped to the selected manifest. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | MPU region roles, RBAR/RLAR/MAIR dictionary, `xMPU_SETTINGS`, and `MAX_CONTEXT_SIZE` audited. |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | Protected `pxPortInitialiseStack()` and fixed MPU-image construction are implemented. |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | First start/activation/restore and protected PendSV save/select/program/restore are assembly-paired. |
| `mpu_wrappers_v2_asm.c` | `00B42952962E48F8C9421F5EC66BBCE9E02465760560728FEE2D743CE1706F3E` | Deferred to a future optional MPU-wrapper ABI; no Fiber stub exists. |

## Exact Reference Configuration

```text
configENABLE_MPU = 1
configENABLE_TRUSTZONE = 0
configRUN_FREERTOS_SECURE_ONLY = 0
configENABLE_FPU = 0
configENABLE_MVE = 0
configENABLE_PAC = 0
configENABLE_BTI = 0
configNUMBER_OF_CORES = 1
configTOTAL_MPU_REGIONS = 8 or 16
```

The Fiber manifest is equally narrow:

```text
FIBER_PORT_BUILD_SELECTED = 1
FIBER_PORT_ARMV81M_MAINLINE = 1
FIBER_PORT_CM55_MPU_TOTAL_REGIONS = 8 or 16
CMSIS __CORTEX_M = 55
CMSIS __MPU_PRESENT = 1
CMSIS __VTOR_PRESENT = 1
```

The profile rejects Secure CMSE, active FPU use, an FP register ABI, MVE, PAC,
and BTI. It retains ARMv8.1-M `RLAR.PXN` for a future configurable-region ABI;
the fixed initial and global images do not use that bit. Scalar M55, scalar-FP
M55, MVE-FP M55, TrustZone/SecureContext, TF-M, PAC/BTI, and future MPU-FP/MVE
profiles are distinct cohorts.

## Frozen Storage And Frame

For this exact configuration FreeRTOS uses:

```text
xMPU_SETTINGS
    ulMAIR0
    xRegionsSettings[portTOTAL_NUM_REGIONS]
    ulContext[MAX_CONTEXT_SIZE == 21]
    ulTaskFlags
```

The first 20 words are active. Word 20 is the one-past context cursor target,
not register state. The no-TrustZone/no-PAC M55 MPU restore consumes the final
four active words as `[PSP][PSPLIM][CONTROL][EXC_RETURN]`; it copies the basic
hardware frame through privileged context storage rather than keeping the
software frame on an unprivileged PSP stack.

Fiber freezes the same shape:

```text
FiberContext
    protected_context_cursor      Fiber adaptation of pxTopOfStack
    mair0                         FreeRTOS ulMAIR0
    mpu_regions[4 or 12]          FreeRTOS xRegionsSettings
    protected_context             FreeRTOS ulContext[21]
    runtime_flags                 Fiber adaptation of ulTaskFlags
    boot                          Fiber immutable metadata
```

`FiberPortProtectedContext` is exactly 84 bytes:

```text
word  0..7   r4..r11
word  8..15  copied basic hardware frame: r0..r3, r12, LR, PC, xPSR
word 16      PSP
word 17      PSPLIM
word 18      CONTROL
word 19      EXC_RETURN
word 20      cursor_limit, one-past target
```

There is no `xSecureContext` word, FP/MVE state, PAC-key state, or VPR slot in
this `C55M` cohort. The exact layout version and cohort symbol differ between
8- and 16-region manifests, so their private objects cannot be mixed later.

| MPU regions | Per-context RBAR/RLAR pairs | `protected_context` offset | `boot` offset | `sizeof(FiberContext)` |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 4 | 40 | 128 | 216 |
| 16 | 12 | 104 | 192 | 280 |

## MPU Region Mapping

The M55 FreeRTOS branch assigns hardware regions as follows:

```text
0  privileged flash
1  unprivileged flash
2  unprivileged syscall flash
3  privileged RAM
4  current fiber stack
5..N-1  configurable per-fiber regions
```

Fiber reserves the same `RNR 4` origin and 8/16 region geometry. The exact
current-slot aperture policy, linker boundaries, and per-context default image
are frozen by construction. The strict first SVC programs the four global
regions while the MPU is disabled; its naked restore then programs MAIR0 and
the selected context's RNR 4/8/12 pairs before the sole enable transition.

## Function And Macro Ledger

| FreeRTOS symbol or family | Fiber disposition |
| --- | --- |
| `portARCH_NAME`, M55 identity, byte alignment, BASEPRI traits | Implemented as selected-port manifest and trait facts. |
| `portTOTAL_NUM_REGIONS`, stack/configurable region range | Implemented as explicit 8/16-region type and macro contract. |
| `MPURegionSettings_t`, `ulMAIR0`, `xMPU_SETTINGS.ulContext`, `ulTaskFlags` | Implemented as `FiberPortMpuRegionRegisters`, `mair0`, `FiberPortProtectedContext`, and `runtime_flags`; Fiber adds immutable boot metadata. |
| `MAX_CONTEXT_SIZE == 21` | Implemented exactly as 20 active words plus `cursor_limit`. |
| `pxPortInitialiseStack()` | Implemented as `fiber_port_context_init()`: it seeds the protected image and sets `protected_context_cursor` to `cursor_limit`. |
| `vPortStoreTaskMPUSettings()` and global MPU setup | The fixed linker/global image and stack/current-slot pairs are implemented; first SVC programs the permanent four-region image. Configurable per-fiber regions remain deferred to an optional MPU policy ABI. |
| `vStartFirstTask()` / `vRestoreContextOfFirstTask()` | Implemented as `fiber_port_start_first_context()` and `fiber_port_restore_first_context_from_svc()`. The assembly preserves the MPU disable/MAIR0/RNR 4-8-12/enable and protected-frame copy ordering, with strict Fiber provenance and readback checks. |
| MPU `PendSV_Handler` | Implemented as the selected protected engine: exact 20-word save/copy/special-register image, reverse-ABI selection under BASEPRI, PRIMASK-protected MAIR0/context-pair replacement, and inverse restore. |
| `xIsPrivileged`, privilege transitions, syscall dispatch | Deferred with the optional MPU application policy ABI; no no-op public stubs exist. |
| `mpu_wrappers_v2_asm.c`, ACL, system-call stack | Deferred as optional wrapper functionality. |
| SecureContext, TF-M, FPU, MVE, PAC, BTI | Absent by construction; each requires a different profile or optional ABI. |

## Slice-5 Proof

The compile matrix proves:

```text
type-only C and C++ storage compiles without CMSIS
8- and 16-region exact manifests compile at -O2 and -Os
one exact C55M cohort symbol is emitted per manifest and the spellings differ
all context, boot, MPU pair, and cursor-limit offsets are static-asserted
sealed construction plus the complete protected runtime compile at -O2/-Os and normal/LTO synthetic ELF links
all linker boundaries and selected privileged/unprivileged sections are proven
a missing syscall boundary fails the linker contract
slots 11 and 14 retain exactly one strong SVC/PendSV handler; competing strong SVC/PendSV handlers fail link
M55 MPU first-start, activation, protected PendSV save, special-word save,
MPU replacement, and inverse restore are paired with FreeRTOS at -O2/-Os
Secure CMSE, missing MPU/VTOR, wrong core/selected profile, FPU, MVE, PAC/BTI,
invalid region count, runtime-selectable override, and selector mode fail closed
all eight forward ABI operations are defined exactly once; optional MPU application APIs remain absent
portable-application archive extraction, external cohort retention, and stale 8/16 archive rejection pass
```

PendSV preflights the running pointer, seal, live PSP frame, canary,
PSPLIM/CONTROL/EXC_RETURN state, and active MPU image before loading the mutable
cursor. Scheduler policy is called under BASEPRI through reverse ABI v1, with a
full CPU/MPU snapshot/readback around the callback. The selected MAIR0 and
RNR 4/8/12 context pairs are replaced only while PRIMASK protects the
MPU-disabled interval, then the exact inverse protected frame is restored.

The profile is build-selected only: it has no global selector route, optional
MPU policy, or board validation claim. The next work is MPU isolation hardware
validation or an explicitly requested optional configurable-region ABI; neither
requires changing the frozen frame geometry or handler ownership.

## Audit Corrections A02-A05

The protected layout generation is 2: `0x00020008u` for eight MPU regions and
`0x00020010u` for sixteen. Sizes, offsets, port IDs and both callable ABIs are
unchanged. Cleanly rebuild all selected components and allocating consumers.

The current-slot aperture must not overlap region 3 or any other enabled range.
For example, place the slot at `0x30000000..0x30000020` and begin privileged RW
SRAM at `0x30000020`. Contexts, MSP and protected data use the RW range. Startup
must also zero the separate slot section before any common/runtime access;
a BSS loop starting at the RW range does not initialize that earlier section.
The aperture remains RO/XN for both privilege levels. Publication remains inside
the PRIMASK-protected interval with the MPU disabled.

Exception entry clears SPSEL. EXC_RETURN establishes Thread/PSP return.
Fiber deliberately normalizes the saved scalar CONTROL to the canonical Thread
value 3 by setting SPSEL after reading live Handler CONTROL 1. Initial templates
and resumed images therefore have one representation. Unlike the pinned FreeRTOS
raw Handler save, this normalization supports Fiber's stricter image checks.
Post-write restore readback compares the written CONTROL value 3, not entry 1.

Save preflight checks live PSP and its complete frame against sealed bounds,
not against the historical image PSP. Restore accepts the exact owned post-yield
SVC continuation in syscall flash, but rejects other syscall PCs.

Focused offline regressions: `tools/test_v8_scalar_ntz_security.ps1` extracts and
executes actual C validators with register/map stubs, checks actual ARM codegen,
and links real CM33 handler/runtime archives with section GC and normal/LTO.
These checks do not claim target exception return or MPU hardware execution.

## A25: Architectural RBAR Shareability

`FAP-ARMV8M-RBAR-SH` deliberately corrects the pinned reference dictionary:
RBAR.SH Inner-shareable is 3, not reserved 1. The private encoder accepts raw
0/2/3 and rejects 1. Existing standard mappings use Non-shareable 0; context
layout, default MPU image and both callable ABIs are unchanged. Independent
numeric SH/AP/XN tests, not equality with the copied reference macro, are the
required regression oracle. See the global assembly-parity rationale.

## A32 Raw CPU Helper Closure

The non-inline boot/runtime helpers and existing port inlines already carry
the canonical sensitive and general-register bundles. The remaining CMSIS
register/priority calls are replaced by port-owned, inline-sensitive/GRO
ordinary-bank primitives: IPSR, CONTROL, PRIMASK, FAULTMASK, PSP, PSPLIM, WFE,
and byte-wide system-handler SHPR access for SVCall/PendSV only. No Secure-bank
alias, new register policy, additional callback, or barrier instruction is
introduced. The existing NVIC shifts/masks and caller sequencing are retained.

Only the macro-header CPU helper block and runtime call spellings change.
All six naked bodies per group, pre-existing r9/geometry inlines, boot sources,
seals, MPU images, type/linker layouts, cohort identities, callable ABI and
runtime-selectable policy remain unchanged.

Preserved pre-fix evidence:
`%TEMP%/fiber-sensitive-port-closure-c644f15689304aab8763ab766847d506/results.json`
has 12 passing O2 baseline cells and 12 failing raw cells across the four groups,
with no build errors or drift. This is a stronger raw-compiler protection gap,
not a demonstrated runtime failure under the prescribed counterflags.

Maintained proof is `tools/test_v8_mpu_raw_compiler.ps1` and its dedicated fixture.
`%TEMP%/fiber-v8-mpu-raw-87d4516c00fb4902a55c700c9ffe3778/results.json`
passes 360 cells and 1,872 controls: all four groups, 8/16 regions, scalar soft
or FP hard/softfp ABI, O0/Og/O2/Os/O3, baseline/raw, ordinary objects and genuinely
lowered sectioned/unsectioned slim LTO. The raw bundle enables instrumentation,
SSP, gcov, UBSAN, trace-PC and `-pg` without protective counterflags. Its 72
additional O2/Os controls remove only the nine new CPU-inline bundles, retain
GRO/non-inline bundles, and require an actual instrumentation leak, not a
build failure. The initial fixture-pattern failure remains separately preserved
at `%TEMP%/fiber-v8-mpu-raw-2cc31a6cde7d4306bc045cfaddc1f705`.

That full grid retains its pre-section-interior-fix classifier. A separate
current-classifier replay at
`%TEMP%/fiber-sensitive-port-closure-ead96695dd954df0ab22261c1aa45293/results.json`
passes 48 O2/Os cells and 240 controls for the default 8-region ABI configurations.
It does not retroactively extend the full grid to the newer section-interior
invariant or independently claim the parent's separate causal counterexample
test. Both receipts retain their exact classifier bytes and original completion
artifact manifests.

Pinned O2/Os ordered-mechanism evidence remains:
`%TEMP%/v8-mpu-owner-ordered-ad96588fcc2748f4aa9558796eb75c19/receipt.json`.
A retained temporary AST selector replays six unchanged maintained assertion
blocks and 24 configurations: 288 paired comparisons, zero input drift, with
full-tree pinned-reference identity checks before/after. This is not a
closed-body/global-parity or CPU-execution claim.

Ordinary cold common init/registration retains its explicit frozen exception;
the proof does not pretend all five common operations are sensitive. External
memory routines and integration callbacks are not supplied or qualified by
this relocatable-object gate. Normal imports stay classified and exact; no
private-helper or compiler-hook allowance is added. Existing mandatory
counterflags and separate state/MPU/FP/runtime/hardware gates are not waived.
