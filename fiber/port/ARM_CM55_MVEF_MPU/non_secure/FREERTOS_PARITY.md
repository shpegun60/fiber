# ARM_CM55_MVEF_MPU Non-secure FreeRTOS Parity Ledger

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

## Slices 1-4 Scope

This is the complete software runtime of the explicit build-selected
`ARM_CM55_MVEF_MPU/non_secure` Cortex-M55 MVE-FP MPU profile. It freezes
public storage, selected-port traits, the exact protected context geometry,
sealed construction, FPU policy helpers, linker boundaries, the exact context
cohort, strict SVC #70 first start, private SVC #72 task return, protected MPU
activation/basic restore, and strong `SVC_Handler` and `PendSV_Handler`
mechanics. Slice 4 activates the frozen eight-operation forward ABI: boot owns
`fiber_port_context_init()`, the mandatory SVC/runtime object owns the other
seven operations and public SVC #71 yield, and its private bundle anchor forces
the separately compiled PendSV component from a static archive.

The matrix proves the full selected runtime under hard-float and softfp
`-O2`/`-Os`, plus representative hard-float `-O2` LTO archive links. It also
proves exact cohort expectation, stale 8/16-region archive rejection,
privileged/unprivileged/syscall placement, vector slots 11/14, and duplicate
strong-handler failure. This profile deliberately has no global selector route,
optional heterogeneous MPU API, TrustZone/SecureContext or TF-M companion,
PAC/BTI policy, or hardware-support claim.

The selected manifest is:

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS=8 or 16
CMSIS __CORTEX_M=55
CMSIS __MPU_PRESENT=1
CMSIS __VTOR_PRESENT=1
CMSIS __FPU_PRESENT=1
CMSIS __FPU_USED=1
compiler=-march=armv8.1-m.main+mve.fp -mthumb -mfloat-abi=hard or softfp
```

`__ARM_FEATURE_MVE` must report both integer and FP MVE bits. Secure CMSE,
PAC, and BTI are rejected. `ARM_CM55F_MPU` and `ARM_CM55_MVEF_MPU` use
separate region-manifest macros and exact cohorts even though the protected
array geometry is the same.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
FreeRTOS CMake port: GCC_ARM_CM55_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM55_NTZ/non_secure
```

| Reference file | SHA-256 | Slice-1 disposition |
| --- | --- | --- |
| `portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` | M55 identity, MVE-FP compiler requirements, and selected traits are mapped. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | MPU region roles, RBAR/RLAR/MAIR facts, FP context geometry, and `xMPU_SETTINGS.ulContext` are mapped. |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | The `configENABLE_MPU=1`, `configENABLE_FPU=1`, `configENABLE_MVE=1` constructor branch is the construction reference. |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | Protected basic first restore is mapped by slice 2; protected MVE-FP PendSV copy order is mapped by slice 3; slice 4 adds only Fiber runtime composition around those paired mechanics. |

The exact reference configuration is:

```text
configENABLE_MPU=1
configENABLE_FPU=1
configENABLE_MVE=1
configENABLE_TRUSTZONE=0
configRUN_FREERTOS_SECURE_ONLY=0
configENABLE_PAC=0
configENABLE_BTI=0
configNUMBER_OF_CORES=1
configTOTAL_MPU_REGIONS=8 or 16
```

FreeRTOS gates its protected FP copies with
`configENABLE_FPU || configENABLE_MVE`. In this configuration both are one.
The reference does not allocate, save, or restore a VPR software word. Fiber
therefore records MVE in the exact cohort but keeps the same 54-word physical
protected image as scalar-FP `C55P`.

## Frozen Protected Context

FreeRTOS uses one `ulContext[MAX_CONTEXT_SIZE == 54]` backing array. Its basic
and extended views overlap deliberately:

```text
basic first-start image:
  words  0.. 7  r4..r11
  words  8..15  copied basic hardware frame r0..r3, r12, LR, PC, xPSR
  words 16..19  PSP, PSPLIM, CONTROL, EXC_RETURN
  word      20  one-past basic save cursor

extended MVE-FP saved image:
  words  0..15  s16..s31
  words 16..32  copied s0..s15, FPSCR
  words 33..40  r4..r11
  words 41..48  copied basic hardware frame r0..r3, r12, LR, PC, xPSR
  words 49..52  PSP, PSPLIM, CONTROL, EXC_RETURN
  word      53  one-past extended save cursor
  no VPR software slot
```

`FiberPortProtectedContext` is an exact 216-byte union. The constructor clears
all 54 words, fills only the basic view, and points
`protected_context_cursor` at `basic.cursor_limit`. Slice 3 overwrites this
same image after an extended save, moves the cursor to
`extended.cursor_limit`, and retains the pinned FreeRTOS save/restore order.

The generic selected-port geometry follows the same distinction: the basic
protected restore image is 20 words with `EXC_RETURN` at word 19, so its
logical initial image is 112 bytes including the basic hardware frame. The
extended image adds 33 privileged FP words (`s16-s31` and copied
`s0-s15/FPSCR`), so its logical maximum is 320 bytes. The protected context
stays in privileged SRAM. The user PSP stores only the hardware exception
frame, so construction requires a conservative 112-byte usable PSP range
rather than the 216-byte protected backing size.

## Fiber Mapping And Deliberate Differences

| FreeRTOS mechanism | Fiber mapping |
| --- | --- |
| `xMPU_SETTINGS.ulMAIR0` | `FiberContext.mair0` |
| `xMPU_SETTINGS.xRegionsSettings[]` | `FiberContext.mpu_regions[]` |
| `xMPU_SETTINGS.ulContext[54]` | overlapping `FiberPortProtectedContext` union |
| `xMPU_SETTINGS.ulTaskFlags` | `FiberContext.runtime_flags` |
| `pxPortInitialiseStack()` | `fiber_port_context_init()` |
| `prvSetupFPU()` | `fiber_port_fpu_prepare()` plus CPACR/FPCCR readback |
| MVE-FP compiler capability | `__ARM_FEATURE_MVE & 3 == 3` and `FIBER_PORT_HAS_MVE == 1` |
| no FreeRTOS VPR storage | no Fiber VPR storage or frame slot |
| FreeRTOS task-control-block ownership | sealed boot metadata and exact `C55W` cohort retention |

Fiber adds fail-closed linker-layout, context-storage, seal, Thumb entry, stack
range, and FPU policy checks. These checks use general registers only; no Fiber
VFP or MVE transfer can occur before CP10/CP11 and FPCCR policy readback
succeeds. GCC may use transient MVE stores while compiling the reference
constructor; those are checked separately from saved-context or VPR state.

## Slice-1 Construction Proof

For 8- and 16-region manifests, hard-float and softfp `-O2`/`-Os`, plus
hard-float `-O2` LTO, the matrix proves:

```text
type-only C and C++ public storage has no CMSIS dependency
construction retains the exact C55W cohort defined by the mandatory SVC/runtime object; it differs from C55P
54-word basic/extended offsets, sizes, alignment, and cursor positions match
construction itself has no PendSV or forward-runtime ABI ownership
the selected compiler requires MVE FP, not scalar FP or integer-only MVE
construction and FPU policy emit no VFP/MVE transfer or MPU register write
linker boundaries and protected/current-slot MPU image are present
invalid core/FPU/MVE/CMSE/region-manifest inputs fail closed
missing linker boundaries fail closed
```

The generated construction shape is compared against the pinned FreeRTOS
`configENABLE_MPU=1`, `configENABLE_FPU=1`, `configENABLE_MVE=1` constructor
branch. The MVE proof specifically rejects an accidental VPR software slot;
slice 3 separately proves that the protected PendSV mechanics retain that
absence while preserving the conditional FP copy order.

## Slice-2 Strict SVC Proof (Historical Checkpoint)

At the original Slice-2 checkpoint, the same 8- and 16-region manifests,
hard-float and softfp `-O2`/`-Os`, plus hard-float `-O2` LTO, proved:

```text
strict SVC source owned one exact C55W cohort and strong SVC_Handler only
the isolated Slice-2 fixture resolves slot 11 to SVC_Handler and deliberately leaves slot 14 zero
SVC #70 first start and private SVC #72 task return were emitted
SVC #71, PendSV, forward runtime ABI, and vector/MVE/VPR state transfer were absent from the Slice-2 object
FreeRTOS-shaped MPU disable, MAIR0/RBAR/RLAR installation, enable, and basic restore match
PSP, PSPLIM, CONTROL, BASEPRI, MPU, linker, vector, context, and FPU policies are checked
duplicate strong SVC definitions fail the synthetic link
```

The SVC first-restore assembly is compared against the pinned FreeRTOS
`vStartFirstTask()` and `vRestoreContextOfFirstTask()` mechanisms. Both use
the basic 20-word protected view and neither transfers high FP, low FP, MVE,
or VPR state. Fiber's additional checks, private task-return service, and
`PRIVDEFENA` policy are recorded in `FAP-M55MVE-MPU-SVC`.

## Slice-3 Protected MVE-FP PendSV Proof (Historical Checkpoint)

`fiber_port_pendsv.c` owns the protected MVE-FP switch mechanics for the same
54-word privileged backing image. Before its naked handler reads the mutable
save cursor, it validates the live current context, basic or extended hardware
frame, CPACR/FPCCR policy, and active MPU image. It then preserves the pinned
FreeRTOS move order:

```text
extended save:
  PSP + 32 -> copy s0-s15/FPSCR
  s16-s31 -> protected image
  r4-r11, copied basic hardware frame, PSP, PSPLIM, CONTROL, EXC_RETURN

extended restore:
  PSP, PSPLIM, CONTROL, EXC_RETURN
  copied basic hardware frame, r4-r11
  copied s0-s15/FPSCR, s16-s31
  no VPR software slot or VPR transfer
```

The saved cursor is exactly `basic.cursor_limit` for a basic return or
`extended.cursor_limit` for an extended return. Scheduler selection consumes
the frozen reverse ABI under BASEPRI and validates scheduler CPU/MPU state.
With PRIMASK asserted, Fiber disables the MPU, replaces MAIR0 and the selected
context RBAR/RLAR pairs, publishes the selected context through common-owned
state, reenables the MPU, validates the readback, then performs the inverse
restore.

At the Slice-3 checkpoint, the matrix proved the component for 8- and 16-region manifests, hard-float and
softfp `-O2`/`-Os`, with a hard-float `-O2` LTO synthetic ELF. It checks the
generated VFP copy instructions and their order, rejects VPR/MVE context state,
retains reverse-ABI/cohort identity, resolves strong `SVC_Handler` and
`PendSV_Handler` in slots 11 and 14 in the Slice-3 fixture, and rejects a
competing strong `PendSV_Handler`. At that checkpoint the component deliberately
had no forward ABI implementation, public SVC #71 yield, or archive-extraction
claim.

## Slice-4 Forward Runtime And Archive Proof

Slice 4 preserves the paired construction, first-start SVC, and protected
PendSV mechanics above. It adds only the frozen runtime composition:

```text
fiber_port_boot.c
  -> fiber_port_context_init()

fiber_port_svc.c
  -> runtime memory barrier, panic wait, scheduler-environment check,
     prepare/start/select runtime operations, public SVC #71 yield,
     strong SVC_Handler, cohort definition, and handler-bundle anchor

fiber_port_pendsv.c
  -> protected first-selection bridge and strong PendSV_Handler
```

The handler-bundle anchor calls the separately compiled PendSV component anchor,
so a weak startup alias cannot satisfy archive extraction. This changes neither
the 54-word protected layout nor the FreeRTOS-derived `s16-s31`/copied
`s0-s15/FPSCR` transfer order. The public yield veneer is a direct SVC #71
request; scheduler policy still runs only in the protected PendSV bridge.

The full runtime proof covers both 8- and 16-region cohorts:

```text
hard-float and softfp -O2/-Os:
  construction, SVC, and PendSV generated assembly against pinned FreeRTOS
  no VPR software slot or VPR transfer

hard-float -O2, softfp -Os, and hard-float -O2 LTO:
  exact eight-function forward ABI
  archive extraction of boot, SVC, and PendSV objects
  exact external cohort expectation and stale 8/16 archive rejection
  privileged/unprivileged/syscall placement
  strong SVC_Handler and PendSV_Handler in vector slots 11 and 14
  duplicate SVC_Handler and PendSV_Handler negative links
```

## Deferred Work

1. Optional heterogeneous MPU API.
2. TrustZone/SecureContext or TF-M companion, PAC, BTI, and hardware validation
   as separate work.

This profile is a complete software-selected runtime only. It remains
explicitly build-selected and makes no hardware claim.

## Audit Corrections (A01-A04, A06-A08, A12)

The corrected cohort is layout version 0x00020008 (8 MPU regions) or
0x00020010 (16 regions). Sizes, offsets, the overlapping 54-word image, and the
pinned FreeRTOS protected save/restore instruction backbone are unchanged.
The version change records saved-CONTROL semantics, not an ABI operation change.
Synthetic first start still uses CONTROL=3. Runtime PendSV saves actual Handler
CONTROL; EXC_RETURN identifies Thread/PSP and basic/extended frame state rather
than live Handler SPSEL or FPCA. Post-write restore readback checks all written
CONTROL bits; exception-entry state must not be confused with permanent RAZ.

The current slot is a separate, exactly 32-byte RO/XN region immediately below
privileged RW SRAM, not an Armv7-style overlay. For example, slot
0x30000000..0x30000020 pairs with privileged RW SRAM beginning at 0x30000020.
Startup must zero both the slot section and privileged BSS, even though the
mapped privileged-SRAM range excludes the slot. Publication remains restricted
to the existing MPU-disabled critical window.

Runtime SVC permits configured lazy preservation before FP materialization,
decodes the core frame at raw PSP with low FP state after it, and validates the
running cursor/live PSPLIM without reading an inactive basic union view.
PendSV proves the minimum core extent before reading xPSR. Restore permits the
exact owned yield continuation, not arbitrary syscall PCs.

The maintained source-derived host regression is
`tools/test_m55_fp_mpu_state.ps1`. Host register/MPU models and generated-code
checks are not target execution or electrical/hardware qualification.

## A25: Architectural RBAR Shareability

`FAP-ARMV8M-RBAR-SH` deliberately corrects the pinned reference dictionary:
RBAR.SH Inner-shareable is 3, not reserved 1. The private encoder accepts raw
0/2/3 and rejects 1. Existing standard mappings use Non-shareable 0; context
layout, default MPU image and both callable ABIs are unchanged. Independent
numeric SH/AP/XN tests, not equality with the copied reference macro, are the
required regression oracle. See the global assembly-parity rationale.

## Saved-Image Cursor Guard

The pinned `ARM_CM55_NTZ/non_secure/portasm.c` MPU/FPU save selects its
payload from EXC_RETURN.FType: 20 words for basic, 53 for extended. Neither
save writes trailing word 53. Basic cursor word 20 aliases extended S4 and
can retain that nonzero payload when a basic image is subsequently supplied.
Both saved forms therefore validate permanent trailing word 53, while the
cursor address still classifies the active representation. No FP payload is
required to be zero or erased. Initial-construction checks remain stricter.
No assembly, layout, cohort revision, or callable ABI changes are involved.

`tools/test_m55_fp_mpu_state.ps1` compiles actual validator bodies and a bounded
translation of the actual PendSV save instructions. Its same-context test
starts with a cold basic representation, supplies an extended frame with
nonzero S4, then supplies a basic frame without clearing the protected image.
It proves preservation, rejects corrupt word 53 in both forms and invalid
cursors, and kills the old word-20 guard and separate guard-removal mutants.
Actual ARM compilation/disassembly checks the unchanged save block under
hard-float and the classifier's numeric word-53 load offsets under hard/softfp
for 8/16 regions and `-O2`/`-Os`; host cases also cover `-O0` and both lazy
policies.

This is saved-representation qualification, not execution of exception/FPCA
teardown and not a claim that the five public operations can cause extended
to basic transition. Cessation of FP instructions does not clear FPCA, and
unprivileged MSR CONTROL cannot be used to clear it. Host-supplied frame tokens
are explicit test inputs, not an architectural reachability oracle.

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
