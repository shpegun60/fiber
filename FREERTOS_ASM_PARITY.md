# Generated Assembly Parity With FreeRTOS

This document defines the generated-code comparison required before a selected
port mechanism is accepted. The executable proof is
`tools/freertos_asm_parity.ps1` and is also invoked by the compile matrix.

## Reference

The only accepted reference checkout for this proof is the local FreeRTOS
Kernel commit:

```text
a50edad08b29052631aa469d4df6e6ec7ff68878
```

The parity script additionally verifies SHA-256 identities for every consumed
`port.c`, `portasm.c`, `portasm.h`, `portmacro.h`, and `portmacrocommon.h`.
A matching commit name with changed portable files therefore fails closed.

Both the FreeRTOS object and the Fiber object are compiled by the same
`arm-none-eabi-gcc`, with the same CPU, Thumb, FPU ABI, and optimization level.
The mandatory matrix repeats every pair at `-O2` and `-Os`, then reads both
objects with the same `objdump`. This covers the normal optimized validation
shape and the size-optimized Release shape; it is not a claim of byte identity.

## Two-Stage Optimization Coverage

The per-port acceptance gate remains the currently executable `-O2` and `-Os`
paired comparison plus that port's normal/LTO ELF, archive, ABI, cohort, and
negative-link proofs. Every new port must pass this gate before its
compile/assembly/ELF status is recorded.

After every required STM32 profile is implemented or explicitly excluded, one
separate final hardening cohort must expand the complete port set to:

```text
-O0
-Og
-O2
-Os
-O3
-O2 -flto final linked-ELF disassembly
-Os -flto final linked-ELF disassembly
```

"Complete port set" means every claimed exact build cohort, not one convenient
configuration per directory. Applicable CPU revision, hard/softfp ABI, FP/MVE
state, MPU 8/16-region layout, Secure/Non-secure/NTZ role, and architecture
errata policy variants must each enter the optimization grid when they change
generated context mechanics or cohort identity. Unsupported combinations stay
negative compile/link tests rather than being silently omitted.

The non-LTO modes compile the pinned FreeRTOS and Fiber mechanisms with the
same compiler, target, ABI, and optimization flags. The LTO modes inspect the
final linked ELF, not an intermediate LTO object or compiler-generated `.s`
file. Each mode must preserve the same ordered architecture operations and all
documented Fiber adaptations; byte identity remains neither required nor
expected.

This expanded cohort is intentionally a final cross-port freeze gate rather
than a requirement repeatedly added while the port inventory is incomplete.
Until it exists and passes, the repository may claim the current `-O2`/`-Os`
parity only, not all-optimization parity.

`CI_VALIDATION_PLAN.md` defines how the current per-port gate and this final
cohort become reproducible pull-request and release-blocking CI jobs, including
pinned inputs and retained proof artifacts.

## Comparison Rule

Binary equality is neither required nor useful. Fiber has different symbols,
extra validation branches, a user scheduler callback, and no FreeRTOS tick
kernel. Instead, each mechanism has two ordered instruction signatures:

```text
pinned FreeRTOS generated function
    ordered architecture operations

Fiber generated function
    corresponding ordered architecture operations
    plus explicitly justified hardening/adaptation operations
```

The signatures cover register save/restore geometry, EXC_RETURN handling,
PSP/MSP/PSPLIM/CONTROL writes, BASEPRI or PRIMASK envelopes, FP transfer order,
MPU replacement order, SVC entry, and exception return. A missing, reordered,
or newly unsupported operation fails the test.

Source similarity and compile success are not parity evidence. A source change
is accepted only when the generated object still passes the paired proof.

## Covered Ports

| Fiber port | FreeRTOS reference | Generated mechanisms covered |
| --- | --- | --- |
| `ARM_CM0` (M0 and M0+) | `GCC/ARM_CM0` | separate M0/no-VTOR and M0+/VTOR builds; first SVC request, first restore, PendSV save/mask/restore |
| `ARM_CM0_MPU` | `GCC/ARM_CM0`, `configENABLE_MPU=1` | first SVC request, protected Thumb-1 first restore, SVC task return/public yield, protected PendSV frame copy/PRIMASK/MPU replacement/restore |
| `ARM_CM3` | `GCC/ARM_CM3` | first SVC request, first restore, PendSV save/BASEPRI/restore |
| `ARM_CM4` | `GCC/ARM_CM4F` | first SVC request, first restore, conditional FP PendSV |
| `ARM_CM7/r0p1` | `GCC/ARM_CM7/r0p1` | first SVC request, first restore, FP PendSV and errata-safe BASEPRI |
| `ARM_CM23_NTZ/non_secure` | `GCC/ARM_CM23_NTZ/non_secure` | first SVC request, first restore, ten-word NTZ PendSV |
| `ARM_CM33_NTZ/non_secure` | `GCC/ARM_CM33_NTZ/non_secure` | first SVC request, full ten-word Mainline restore, PSPLIM-aware PendSV |
| `ARM_CM55_NTZ/non_secure` | `GCC/ARM_CM55_NTZ/non_secure` | no-FPU/no-MVE first SVC request, full ten-word ARMv8.1-M restore, PSPLIM-aware PendSV |
| `ARM_CM55F_NTZ/non_secure` | `GCC/ARM_CM55_NTZ/non_secure`, `configENABLE_FPU=1`, `configENABLE_MVE=0` | basic construction, strict first SVC/restore, and conditional scalar-FP `s16-s31` PSPLIM PendSV |
| `ARM_CM55_MVEF_NTZ/non_secure` | `GCC/ARM_CM55_NTZ/non_secure`, `configENABLE_FPU=1`, `configENABLE_MVE=1` | basic construction, integer-only strict first SVC/restore, and conditional MVE-FP `s16-s31` PSPLIM PendSV with no VPR software slot |
| `ARM_CM55_MPU/non_secure` | `GCC/ARM_CM55_NTZ/non_secure`, `configENABLE_MPU=1`, no FPU/MVE/TrustZone/PAC | slice-4 staged protected SVC/PendSV engine: first MPU activation/restore, 20-word frame copy, reverse-ABI selection under BASEPRI, atomic MAIR0/context-MPU replacement, and inverse restore for exact 8/16-region cohorts |
| `ARM_CM33_TFM/non_secure` | `ThirdParty/GCC/ARM_TFM` plus `GCC/ARM_CM33_NTZ/non_secure` | exact TF-M v2.0 adapter provenance; independent first SVC request, ten-word Mainline restore, and PSPLIM-aware PendSV proof |
| `ARM_CM33/non_secure` plus Secure companion | `GCC/ARM_CM33/non_secure` and `secure` | 19-word construction, PRIS/Secure init, SVC first start, Secure save/unload, lazy bounded allocation, Secure load, and segmented eleven-word PendSV save/restore |
| `ARM_CM33_MPU/non_secure` | `GCC/ARM_CM33_NTZ/non_secure`, MPU enabled | public SVC 70/71/72 route, protected first MPU activation/restore, protected PendSV frame copy, BASEPRI scheduler bridge, atomic MAIR0/context-MPU replacement, protected restore |
| `ARM_CM33F_NTZ/non_secure` | `GCC/ARM_CM33_NTZ/non_secure`, `configENABLE_FPU=1` | paired basic `pxPortInitialiseStack()` geometry, SVC first start, and FP-aware PSPLIM PendSV |
| `ARM_CM3_MPU` | `GCC/ARM_CM3_MPU` | SVC dispatch, first MPU restore, protected PendSV |
| `ARM_CM4_MPU` | `GCC/ARM_CM4_MPU` | SVC dispatch, first MPU/FP restore, protected FP PendSV |

The script derives the complete-runtime inventory from every
`fiber/port/**/fiber_port.c`; an explicitly listed staged source is checked
separately against only the mechanisms named in its ledger. Every directory must contain
`FREERTOS_PARITY.md`. A staged profile never inherits a complete runtime claim.
The script fails if a staged profile becomes selectable, is also listed as
complete parity, or a new complete port source is neither paired nor explicitly
staged. Adding a port source therefore cannot silently reduce coverage.

`ARM_CM55F_NTZ/non_secure` slices 1-4 use `fiber_port_boot.c`,
`fiber_port_svc.c`, and `fiber_port.c` as one complete scalar-FP runtime group.
Its dedicated matrix checks hard/softfp `-O2`/`-Os` FreeRTOS-shaped initial
construction, first-start/SVC, and scalar-FP PendSV instruction signatures.
The latter requires the FreeRTOS ordering of `vstmdb r0!, {s16-s31}`, the
ten-word PSPLIM/core image, scheduler BASEPRI bridge, and conditional
`vldmia r0!, {s16-s31}` restore. It also proves all eight forward operations,
strong SVC/PendSV ownership, exact reverse dependencies, normal/LTO archive
extraction, vector slots 11/14, external cohort retention, and
duplicate-handler failure. The profile remains build-selected only and
hardware-unvalidated.

`ARM_CM55_MVEF_NTZ/non_secure` slices 1-3 use `fiber_port_boot.c`,
`fiber_port_svc.c`, and `fiber_port.c` as one complete MVE-FP runtime group.
Its dedicated matrix checks hard/softfp `-O2`/`-Os` FreeRTOS-shaped initial
construction, integer-only first-start/SVC, and conditional MVE-FP PendSV
instruction signatures. The PendSV proof requires the FreeRTOS ordering of
`vstmdb r0!, {s16-s31}`, the ten-word PSPLIM/core image, scheduler BASEPRI
bridge, and conditional `vldmia r0!, {s16-s31}` restore. Both disassemblies
must omit a VPR software-frame transfer. It also proves all eight forward
operations, strong SVC/PendSV ownership, exact reverse dependencies,
normal/LTO archive extraction, vector slots 11/14, external cohort retention,
and duplicate-handler failure. The profile remains build-selected only and
hardware-unvalidated.

`ARM_CM55_MPU/non_secure` slice 4 owns a staged protected `fiber_port.c` with
strong SVC and PendSV handlers, but deliberately has no forward runtime ABI.
`fiber_port_boot.c` owns sealed protected construction and the linker-derived
global image. The runtime owns strict SVC provenance, private SVC 71 yield,
MPU disable/MAIR0/per-context RBAR-RLAR/enable transfer, and protected first
restore plus ordinary save/select/replace/restore. Its 8/16-region proof covers
no-CMSIS public storage, exact `C55M` cohort spelling, frozen protected
offsets, normal/LTO construction and runtime objects, synthetic linker isolation,
slots 11/14 vector ownership, duplicate-SVC/PendSV failure, selected-manifest
negatives, and paired protected PendSV generated assembly. The later activation
slice must add the eight forward operations plus archive/cohort proof before a
complete runtime is claimed here.

`ARM_CM33_MPU/non_secure` is a complete explicit build-selected runtime for the
pinned 8- and 16-region MPU reference configurations. Its public
`fiber_schedule()` path is the exact unprivileged SVC-yield veneer; strong
SVC/PendSV handlers, the protected scheduler bridge, and MPU replacement remain
selected-port-owned. The matrix additionally proves normal/LTO archive
extraction, exact cohort expectation, vector slots 11/14, and stale-cohort
rejection. It has no global auto-selector route, public heterogeneous-MPU API,
or hardware isolation claim.

`transitional_v8m` is intentionally excluded. It remains compile scaffolding
and is not a production FreeRTOS-parity port.

`ARM_CM0_MPU` now provides the complete eight-operation forward runtime ABI
when explicitly `FIBER_PORT_BUILD_SELECTED=1`. Its public `fiber_schedule()`
path is the unprivileged SVC-yield veneer, while strong SVC/PendSV handlers,
protected scheduler bridge, and MPU replacement remain selected-port-owned.
The matrix additionally proves normal/LTO archive extraction, exact cohort
expectation, linker MPU isolation, slots 11/14, and stale-cohort rejection.
The profile still has no auto-selector route or hardware isolation claim.

## Intentional Differences

Every difference ID referenced by the executable proof is normative. A new
difference requires a new ID and rationale before the generated-code check may
accept it.

### FAP-COMMON-START

FreeRTOS starts the task already stored in `pxCurrentTCB`. Fiber first obtains a
context from the configured user scheduler, publishes it through common-owned
runtime state, validates the CPU/start plan, clears stale PendSV, and enters a
dedicated first-start SVC. MSP/CONTROL writes are read back where the selected
architecture permits it. This changes setup code but not exception-return
geometry.

### FAP-COMMON-PROVENANCE

Fiber validates IPSR, incoming EXC_RETURN, stack origin/alignment, frame bounds,
stacked xPSR/PC, context seal, and selected-context state before relying on the
frame. FreeRTOS can trust its private kernel scheduler and TCBs and therefore
has shorter handlers. These extra branches must precede the corresponding
save or restore operation; they may not replace it.

### FAP-COMMON-SCHEDULER

`vTaskSwitchContext()` is replaced by the frozen Fiber scheduler bridge. The
bridge invokes the user callback, validates its result, and lets common runtime
publish the selected current context. The architecture-specific interrupt-mask
envelope must remain in the same position around that call.

### FAP-COMMON-MASK-RESTORE

Where FreeRTOS relies on a known scheduler mask state and clears or enables it,
Fiber preserves and validates the prior PRIMASK/BASEPRI state. This prevents a
port helper from accidentally opening an interrupt mask owned by its caller.

### FAP-CM0-STAGED-FRAME

ARMv6-M cannot directly transfer `r8-r11` with the Thumb-2 multiple-register
forms. Both implementations stage high registers through `r4-r7`. Fiber also
keeps EXC_RETURN in its explicit nine-word software frame and performs the
inverse staged restore inside its hardened SVC/PendSV handlers.

### FAP-CM3-EXC-RETURN

The pinned FreeRTOS CM3 first restore reconstructs Thread/PSP return by OR-ing
the handler LR. Fiber stores exact EXC_RETURN in every context and restores it
with `r4-r11`. This permits exact encoding validation and avoids manufacturing
return authority in the handler.

### FAP-FP-VALIDATION

CM4/CM7 Fiber retains the FreeRTOS EXC_RETURN-bit-4 conditional transfer of
`s16-s31`. It adds FP frame-extent, FPCA, CPACR, FPCCR, alignment, and context
validation. No extra FP register is treated as caller-saved scheduler state.

### FAP-CM7-ERRATA-PRIMASK

The pinned CM7 r0p1 FreeRTOS port uses `cpsid i`/`cpsie i` around BASEPRI writes
for erratum 837070. Fiber instead snapshots PRIMASK, disables interrupts,
writes and synchronizes BASEPRI, then restores the exact old PRIMASK. This is
strictly stronger when the incoming state was already masked.

### FAP-M23-PSPLIM-PLACEHOLDER

The NTZ Cortex-M23 layout retains the FreeRTOS PSPLIM-compatible reserved word,
although M23 cannot access PSPLIM. Initial construction seeds the placeholder;
ordinary PendSV saves zero and neither generated handler may emit a PSPLIM
instruction. The remaining EXC_RETURN and `r4-r11` geometry stays ten words.

### FAP-M33-FULL-FIRST-RESTORE

The CM33 port restores the full PendSV-shaped
`[PSPLIM, EXC_RETURN, r4-r11]` frame during first SVC instead of using the
shorter FreeRTOS first-task helper. It additionally reads back PSPLIM, CONTROL,
PSP, BASEPRI, and FAULTMASK. This guarantees that the initial frame already has
the exact shape consumed by PendSV.

### FAP-M33-PSPLIM-READBACK

The pinned FreeRTOS CM33 PendSV saves and restores PSPLIM as the first word of
the software frame. Fiber preserves the same ten-word geometry and additionally
requires live PSPLIM to match the current stack base before save, reads PSPLIM
back after restore, and validates PSP after its write. These checks add no
context word and do not change the reference register-transfer order.

### FAP-M55-FULL-FIRST-RESTORE

The no-FPU/no-MVE CM55 NTZ profile uses the same scalar
`[PSPLIM, EXC_RETURN, r4-r11]` software frame as the matching FreeRTOS branch.
Fiber restores the full PendSV-shaped frame during first SVC, then reads back
PSPLIM, CONTROL, PSP, BASEPRI, and FAULTMASK. This makes the initial frame the
same exact shape consumed by later PendSV without introducing an MVE, FP, MPU,
SecureContext, or PAC state slot.

### FAP-M55-PSPLIM-READBACK

The pinned no-feature CM55 FreeRTOS PendSV preserves PSPLIM as the first
software word. Fiber retains that ten-word scalar geometry, additionally
requires live PSPLIM to match the declared stack base before save, then reads
back PSPLIM and PSP after restore. The checks neither introduce vector/FPU
instructions nor alter the ordered scalar save/restore transfer.

### FAP-CM33F-CONSTRUCTION

FreeRTOS uses the same basic `pxPortInitialiseStack()` image whether
`configENABLE_FPU` is zero or one; high FP state exists only after an extended
exception frame is active. Fiber preserves the same 72-byte initial geometry
and six architecturally significant seed values, but additionally zeroes the
unspecified synthetic registers, preserves r9, seals immutable metadata, and
validates the completed frame. Neither generated constructor may touch FP
registers before runtime FPU setup. SVC and PendSV parity are separate proofs
under `FAP-CM33F-SVC-START` and `FAP-CM33F-FP-PENDSV`; neither is implied by
this construction difference ID.

### FAP-CM33-SECURE-CONTEXT-CONSTRUCTION

The pinned FreeRTOS `ARM_CM33/non_secure` TrustZone profile seeds nineteen
words: a zero SecureContext handle, PSPLIM, EXC_RETURN, r4-r11, and the basic
hardware frame. Fiber preserves that exact 76-byte geometry and field order.
It additionally zeroes unspecified synthetic registers, preserves r9, seals
the immutable boot record, and validates the completed frame. Construction,
Secure allocation/save/load, SVC, and PendSV are separate generated-code
proofs; hardware parity remains unclaimed without a suitable TrustZone board.

### FAP-CM33-SECURE-CONTEXT-ALLOCATOR

FreeRTOS accepts SecureContext allocation from any Handler mode while Secure
PSPLIM is zero, then obtains a dynamic stack from `secure_heap`. Fiber preserves
the generated IPSR-then-PSPLIM gate, narrows IPSR to exact exception 11
(`SVCall`) for first start or 14 (`PendSV`) for lazy first activation, and
delegates to a bounded manifest-sized static pool. Fiber rejects
zero/unaligned/oversized requests, duplicate owners, and pool exhaustion with
handle zero, retains the reference index-plus-one handle and two-word stack
seal, and intentionally has no free operation because Fiber contexts have
static lifetime.

### FAP-CM33-SECURE-CONTEXT-INITIALIZE

FreeRTOS splits one-shot TrustZone startup between
`SecureInit_DePrioritizeNSExceptions()` and `SecureContext_Init()`. Fiber
combines those operations in one versioned NSC gateway called only by the
controlled first-start SVC. It preserves the PRIS write, zero Secure
PSP/PSPLIM state, privileged Secure Thread/PSP policy, and pool reset. Fiber
narrows Handler mode to exact exception 11, rejects a second initialization,
reads back AIRCR/PSP/PSPLIM/CONTROL, and uses a bounded static pool instead of
the FreeRTOS global context array plus heap.

### FAP-CM33-SECURE-CONTEXT-LOAD

FreeRTOS validates a nonzero handle and owner before loading Secure PSPLIM and
PSP from the context record. Fiber preserves the same PSPLIM-before-PSP order,
but additionally requires exact SVCall or PendSV provenance, completed one-shot
initialization, zero pre-load PSP as well as PSPLIM, an exact opaque owner,
stack-seal-valid static metadata, barriers, and register readback. Handle zero
is an explicit successful no-context load only while both Secure stack
registers remain zero.

### FAP-CM33-SECURE-CONTEXT-SAVE

FreeRTOS records the live Secure PSP in the owned SecureContext, then clears
Secure PSPLIM and Secure PSP before another task can be selected. Fiber retains
that exact save-then-unload order, but accepts only exception 14 (`PendSV`),
requires the sealed record to belong to the exact `FiberContext`, proves stack
alignment and bounds, and reads back both cleared registers. Handle zero is
accepted only when no Secure stack state is live.

### FAP-CM33-SECURE-CONTEXT-FIRST-START

FreeRTOS initializes Secure state in its generic SVC dispatcher and restores
an initially zero SecureContext word through `vRestoreContextOfFirstTask()`;
tasks allocate SecureContext later through SVC 100. Fiber records attachment
before start, so its only accepted SVC 70 validates and initializes Secure
state, allocates the first attached context, stores the handle in frame word
zero, loads the owned Secure stack, and only then restores the exact eleven
software words. Fiber adds exact SVC opcode/provenance checks, special-register
readback, immutable-frame validation, and direct strong-handler ownership.

### FAP-CM33-SECURE-CONTEXT-LAZY-ALLOCATE

FreeRTOS allocates a task SecureContext through its user SVC before that task
needs Secure services. Fiber has a sealed static-lifetime attachment contract:
the first selected context is allocated from first-start SVC, while any other
attached never-run context is allocated once from PendSV after the current
Secure state has been saved and unloaded. The durable handle remains frame word
zero and one port-private live handle mirrors FreeRTOS `xSecureContext`.
PendSV preserves the reference order: Secure save, Non-secure register save,
scheduler selection under BASEPRI, special-word restore, next Secure load,
general-register restore, PSP publication, and exception return. Fiber adds
exact provenance, owner/seal checks, dynamic bounds, special-register readback,
and scheduler/CMSE CPU-state preservation checks.

### FAP-CM33F-SVC-START

The pinned FreeRTOS M33 NTZ FPU configuration enables CP10/CP11 and FPCCR
automatic/lazy preservation before restoring the first task through SVC. Fiber
keeps the same basic first-task frame and SVC transfer, but makes the selected
FPU policy explicit: CPACR/FPCCR writes have barriers and readback, LSPEN is
selected by `FIBER_FPU_LAZY`, and a start is rejected while `LSPACT` is active.
The Fiber SVC handler is intentionally narrower than FreeRTOS's generic
dispatcher: it accepts only the configured first-start immediate and exact
Non-secure Thread/MSP/basic provenance, validates the FPU policy again, clears
FPCA before transfer, and restores only an initial basic frame. The later
FP-aware PendSV proof is recorded separately.

### FAP-CM33F-FP-PENDSV

The pinned FreeRTOS non-MPU CM33 FPU path conditionally saves `s16-s31` before
its ten-word `[PSPLIM, EXC_RETURN, r4-r11]` software frame, and conditionally
restores those high FP registers after that core frame. Fiber retains that
order and the exact basic/extended EXC_RETURN distinction. It additionally
accepts only the selected Non-secure Thread/PSP provenance, validates current
context metadata before any context-field load, proves the dynamic basic or
extended hardware/software frame bounds, verifies live PSPLIM, calls the
frozen scheduler bridge under BASEPRI, validates the selected restore frame,
and reads PSPLIM/PSP back after restore. `LSPACT` is allowed in PendSV because
the first VFP instruction may complete legitimate lazy preservation; it
remains rejected during the one-shot first SVC start. These checks do not add
or reorder any saved context slot.

### FAP-M55F-CONSTRUCTION

The pinned scalar-FP M55 non-MPU configuration retains the same 72-byte basic
`pxPortInitialiseStack()` geometry as the no-FPU M55 profile. Fiber therefore
uses the same eighteen-word initial image, then independently freezes the
dynamic scalar-FP maximum at 212 bytes. It additionally zeroes unspecified
synthetic registers, preserves r9, seals boot metadata, validates the frame,
and prepares CP10/CP11 and FPCCR outside the constructor. Neither constructor
may issue a VFP or MVE instruction before the FPU policy is established.

### FAP-M55MVE-CONSTRUCTION

The pinned M55 non-MPU MVE-FP branch keeps the same 72-byte basic
`pxPortInitialiseStack()` geometry as scalar FP. MVE changes the
conditional `s16-s31` PendSV contract but does not add a VPR software-frame
slot. Its runtime reference is specifically the non-MPU PSP branch,
not the MPU branch that copies frames into privileged TCB storage. Fiber uses a
separate C55V cohort with the MVE trait set, preserves the same eighteen basic
seed words, and adds boot sealing and initial-frame validation. Neither
constructor may issue VFP or MVE instructions before the runtime policy and
transfer paths can use the extended state.

### FAP-M55MVE-SVC

The pinned M55 MVE-FP first-task transfer still restores the same basic
PSPLIM/core image through SVC as the scalar-FP configuration. Fiber preserves
the MSP, IRQ/fault-enable, `svc #70`, PSPLIM, CONTROL, PSP, BASEPRI, and
EXC_RETURN backbone while narrowing the handler to the one configured
first-start service. It adds exact SVC provenance, CPACR/FPCCR/LSPACT policy,
slot-11 and SVCall-priority readback, selected-context validation, and
scheduler CPU-state checks. No VFP or MVE transfer is permitted anywhere in
the basic SVC-stage call graph, including its boot-side helpers; conditional
`s16-s31` transfer belongs only to the MVE PendSV runtime.

### FAP-M55MVE-PENDSV

The pinned M55 non-MPU MVE-FP `PendSV_Handler` conditionally saves `s16-s31`
before `[PSPLIM, EXC_RETURN, r4-r11]`, invokes the scheduler under BASEPRI,
then restores the same words in reverse order. Fiber preserves that state order
and the basic/extended `EXC_RETURN` distinction. It adds selected Non-secure
Thread/PSP provenance, preflight before current metadata access, dynamic
software/hardware-frame bounds, xPSR padding, live PSPLIM validation,
scheduler CPU/FPU-state preservation, selected restore validation,
common-owned current publication, and PSPLIM/PSP readback. The explicit parity
proof rejects a VPR software-frame transfer in both FreeRTOS and Fiber. These
checks do not add, remove, or reorder a saved context slot.

### FAP-M55MPU-LAYOUT

The pinned FreeRTOS M55 MPU no-feature branch stores the active context in
privileged `xMPU_SETTINGS.ulContext[MAX_CONTEXT_SIZE == 21]`, rather than the
non-MPU PSP software frame. The active order is `r4-r11`, the copied basic
hardware frame, and `[PSP][PSPLIM][CONTROL][EXC_RETURN]`, followed by a
one-past cursor word. Fiber freezes exactly that layout under a separate C55M
cohort for 8- and 16-region MPU manifests.

The following construction slice mirrors the reference's protected initial
image: it keeps the basic hardware frame in privileged context storage, seeds
`PSP`, `PSPLIM`, `CONTROL`, and `EXC_RETURN`, builds the stack/current-slot
RBAR/RLAR pairs, and derives the four global regions from linker boundaries.
The synthetic ELF proof requires every protected output section and rejects a
missing boundary. It also preserves M55-only `RLAR.PXN` acceptance for a later
configurable-region ABI.

### FAP-M55MPU-STAGED-PENDSV

The staged protected engine preserves the pinned FreeRTOS M55 MPU backbone:
`vStartFirstTask` rewinds MSP and invokes SVC, while
`vRestoreContextOfFirstTask` disables the MPU, loads MAIR0, programs
RNR 4/8/12 RBAR/RLAR blocks, enables the MPU, restores
`[PSP][PSPLIM][CONTROL][EXC_RETURN]`, copies the basic hardware frame to PSP,
and restores `r4-r11`. Fiber uses SVC `#70` rather than FreeRTOS's configurable
immediate and adds exact vector/call-site/exc-return provenance, linker and
MPU readback, frame sealing, and register readback. It enables
`MPU_CTRL.ENABLE | PRIVDEFENA`, rather than only `ENABLE`, so selected-port
privileged code can retain the common current-slot aperture. Private SVC `#71`
is accepted only from the exact syscall-flash veneer and pends the selected
strong PendSV handler; it does not run scheduler policy.

### FAP-M55MPU-PENDSV-PREFLIGHT

FreeRTOS reads the current TCB cursor before saving its protected image. Fiber
first validates exact PendSV provenance, current pointer/seal, live PSP frame,
canary, special-register state, and active MPU image before any mutable cursor
load. The generated assembly check enforces that order; the 20 active words
remain in the pinned FreeRTOS save order.

### FAP-M55MPU-PENDSV-C-SWITCH

FreeRTOS replaces MAIR0 and RNR 4/8/12 context blocks inline in naked PendSV.
Fiber performs the same disabled-MPU replacement in a privileged C helper while
PRIMASK is asserted. It validates the selected restore image before writes and
reads back the complete active image before BASEPRI is released. This is a
deliberate integrity strengthening, not a frame-layout change.

### FAP-M55F-SVC-START

The pinned M55 FPU start transfer still starts a basic context through SVC.
Fiber preserves the MSP rewind, IRQ/fault enable, `svc #70`, PSPLIM, CONTROL,
PSP, BASEPRI, and exception-return backbone while narrowing the handler to the
one configured first-start immediate and exact Non-secure Thread/MSP/basic
provenance. CPACR/FPCCR/LSPACT policy, vector/priority wiring, frame metadata,
and register readback are Fiber checks around that transfer. No VFP/MVE register
transfer is valid in this initial basic-frame SVC path.

### FAP-M55F-FP-PENDSV

The pinned M55 non-MPU scalar-FP PendSV path conditionally saves
`s16-s31` before `[PSPLIM, EXC_RETURN, r4-r11]`, invokes the scheduler under
BASEPRI, then conditionally restores `s16-s31` after the core frame. Fiber
preserves that exact state order and basic/extended `EXC_RETURN` distinction.
It adds selected Non-secure Thread/PSP provenance, preflight before current
metadata access, dynamic software/hardware frame bounds, xPSR padding, live
PSPLIM validation, scheduler CPU/FPU-state preservation, selected restore
validation, common-owned current publication, and PSPLIM/PSP readback.
`LSPACT` is valid in PendSV because its first VFP operation may complete a
legitimate lazy preservation; first-start SVC still rejects it. These checks do
not add, remove, or reorder a saved context slot.

### FAP-MPU-SVC-NAMESPACE

FreeRTOS MPU ports multiplex kernel wrapper and privilege services. Fiber owns
only its compile-time-checked start, yield, and task-return SVC values. Unknown
or incorrectly originated services panic instead of falling through to a
generic kernel dispatcher.

### FAP-MPU-PROTECTED-FRAME

Like the pinned FreeRTOS MPU ports, Fiber copies the hardware frame from the
unprivileged PSP stack into privileged context storage. CONTROL, core state,
optional FP state, the hardware frame copy, and MPU descriptors are restored
from the protected `FiberContext`; no software authority frame is left on the
user stack.

### FAP-MPU-FIRST-ACTIVATION-SPLIT

FreeRTOS programs the first task's MPU image inside
`prvRestoreContextOfFirstTask()`. Fiber's validated SVC dispatcher first calls
the selected-port MPU activation helper and only then enters
`fiber_port_restore_first_context_from_svc()`. The executable proof checks this
cross-function order as well as the register restore performed by the helper;
splitting the functions may not omit or postpone MPU activation.

### FAP-CM33-MPU-RUNTIME

The M33 MPU profile owns strong SVC and PendSV handlers and exports the frozen
eight-function forward runtime ABI only through its explicit build-selected
manifest. Its SVC dispatcher proves vector and frame provenance, installs and
reads back the four linker-derived global regions while the MPU is disabled,
then passes and revalidates the original SVC `EXC_RETURN` in naked restore.
The restore writes MAIR0 and the selected context's RNR `4..N-1` pairs, enables
the exact `MPU_CTRL=ENABLE|PRIVDEFENA` image, validates the active image, and
only then restores PSP, PSPLIM, CONTROL, core registers, protected hardware
frame, and the selected context's final `EXC_RETURN`. FreeRTOS performs
equivalent first-task machinery across
`prvSetupMPU()` and `vRestoreContextOfFirstTask()`; Fiber keeps the split
explicit so the selected context and SVC origin remain independently checked.
SVC 71 is accepted only from the exact public ABI syscall-flash yield veneer
and only requests PendSV; it does not run scheduler policy. This difference
does not claim a heterogeneous public MPU API or hardware runtime support.

### FAP-CM33-MPU-CURRENT-SLOT-APERTURE

FreeRTOS reserves RNR 5 and later regions for task-configurable MPU pairs.
Fiber reserves RNR 5, the second per-context pair, for an exact 32-byte
current-context aperture. It overlays global privileged SRAM with read-only/XN
access for both privilege levels so the portable `fiber_current()` call graph
can read the common current identity from unprivileged Thread mode. ARMv8-M has
no privileged-RW plus unprivileged-RO access encoding, so the selected port
updates that one common slot only while `MPU_CTRL` is disabled under the already
protected context-image replacement interval. The frame, MAIR0 order, and
RNR 4/8/12 programming sequence remain unchanged; 8-region images retain two,
and 16-region images retain ten, future configurable pairs.

### FAP-CM33-MPU-PENDSV-PREFLIGHT

FreeRTOS directly reads the current TCB/cursor before saving its protected
frame. Fiber first calls a privileged C preflight that verifies exact PendSV
provenance, current-context pointer/seal, live PSP frame extent, canary,
CONTROL/PSPLIM/EXC_RETURN state, and the active MPU image. The generated
assembly proof requires that call before the first cursor load. The 20 active
saved-word order remains identical to the reference.

### FAP-CM33-MPU-PENDSV-C-SWITCH

FreeRTOS programs MAIR0 and RNR 4/8/12 alias blocks inline in naked PendSV.
Fiber keeps the same MPU disable, MAIR0, selected context-pair, enable, and
restore ordering but performs the replacement in a privileged C helper while
PRIMASK is asserted. The helper validates the selected image before writes and
reads back the complete active MPU image before BASEPRI is released. This is a
deliberate strengthening; it does not alter the protected frame layout or
selected hardware regions.

### FAP-MPU-ATOMIC-SWITCH

Fiber performs scheduler selection under the selected profile's scheduler mask,
then keeps the MPU replacement and restore authority atomic under PRIMASK. On
ARMv7-M/ARMv7E-M that means BASEPRI around scheduler selection followed by
PRIMASK for the short replacement interval. On ARMv6-M MPU there is no
BASEPRI: PendSV proves incoming PRIMASK is clear, raises PRIMASK before the
private scheduler bridge, validates the bridge did not alter handler CPU state
or any of the eight effective MPU RBAR addresses/RASR values, and re-enables it
only after the target MPU state has been read back. The pinned FreeRTOS paths program the same
architectural MPU registers but rely on kernel-private TCB state and a shorter
trust boundary.

## Non-Claims

Generated assembly parity proves compiler output shape for the tested flags. It
does not prove board vector routing, silicon errata behavior, memory-map linker
truth, interrupt priority readback, or long-run FP preservation. Those remain
separate ELF and hardware validation requirements. Hardware validation is an
independent evidence layer and may be explicitly deferred; a software freeze
does not create a hardware support claim.
