# ARM_CM55F_MPU Non-secure FreeRTOS Parity Ledger

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

This ledger covers all four implementation slices of the explicit
build-selected `ARM_CM55F_MPU/non_secure` Cortex-M55 scalar-FP MPU profile.
They freeze public storage, selected-port traits, exact protected context
geometry, sealed construction, FPU policy helpers, linker boundaries, and the
exact context cohort. Slice 2 adds strict protected first-start SVC and basic
protected restore. Slice 3 adds the strong protected `PendSV_Handler` with
the scalar-FP save/select/MPU-replacement/restore mechanics.

Slice 4 activates the frozen eight-operation runtime ABI without introducing a
generic `fiber_port.c`: `fiber_port_boot.c` continues to own
`fiber_port_context_init()`, while the mandatory SVC object owns the remaining
seven operations, strong SVC slot 11 ownership, and public SVC #71 yield. It
forces the separately compiled strong PendSV slot 14 object from an archive
through a private component anchor. This profile still has no global selector
route, optional heterogeneous MPU API, or hardware-support claim.

The selected manifest is:

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
FIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8 or 16
CMSIS __CORTEX_M=55
CMSIS __MPU_PRESENT=1
CMSIS __VTOR_PRESENT=1
CMSIS __FPU_PRESENT=1
CMSIS __FPU_USED=1
compiler=-march=armv8.1-m.main+fp -mthumb -mfloat-abi=hard or softfp
```

`-mcpu=cortex-m55 -mfpu=fpv5-sp-d16` is not a scalar-only target because this
GCC target exposes MVE. It belongs to a distinct MVE-FP cohort. Secure CMSE,
PAC, BTI, and MVE are rejected here rather than becoming runtime switches.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
FreeRTOS CMake port: GCC_ARM_CM55_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM55_NTZ/non_secure
```

| Reference file | SHA-256 | Disposition in this slice |
| --- | --- | --- |
| `portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` | M55 identity, scalar-FP compiler requirements, and selected traits are mapped. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | MPU region roles, RBAR/RLAR/MAIR facts, FP context geometry, and `xMPU_SETTINGS.ulContext` are mapped. |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | The `configENABLE_MPU=1`, `configENABLE_FPU=1`, no-MVE constructor branch is the construction reference. |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | `vStartFirstTask()` and the basic protected `vRestoreContextOfFirstTask()` are paired in slice 2. The MPU scalar-FP `PendSV_Handler` copy order is paired in slice 3. |

The exact reference configuration is:

```text
configENABLE_MPU=1
configENABLE_FPU=1
configENABLE_MVE=0
configENABLE_TRUSTZONE=0
configRUN_FREERTOS_SECURE_ONLY=0
configENABLE_PAC=0
configENABLE_BTI=0
configNUMBER_OF_CORES=1
configTOTAL_MPU_REGIONS=8 or 16
```

## Frozen Protected Context

FreeRTOS uses one `ulContext[MAX_CONTEXT_SIZE == 54]` backing array, not two
independent frames. The two views intentionally overlap:

```text
basic first-start image:
  words  0.. 7  r4..r11
  words  8..15  copied basic hardware frame r0..r3, r12, LR, PC, xPSR
  words 16..19  PSP, PSPLIM, CONTROL, EXC_RETURN
  word      20  one-past basic save cursor

extended scalar-FP saved image:
  words  0..15  s16..s31
  words 16..32  s0..s15, FPSCR
  words 33..40  r4..r11
  words 41..48  copied basic hardware frame r0..r3, r12, LR, PC, xPSR
  words 49..52  PSP, PSPLIM, CONTROL, EXC_RETURN
  word      53  one-past extended save cursor
```

`FiberPortProtectedContext` is an exact 216-byte union of those two views.
The constructor zeroes all 54 words, fills only the basic view, and points
`protected_context_cursor` at `basic.cursor_limit`. A later extended FP save
must overwrite the same backing array and move the cursor only to
`extended.cursor_limit`; it must never assume that the initial basic state
contains a separately initialized FP image.

The generic selected-port geometry follows the same distinction: the basic
protected restore image is 20 words with `EXC_RETURN` at word 19, so its
logical initial image is 112 bytes including the basic hardware frame. The
extended image adds 33 privileged FP words (`s16-s31` and copied
`s0-s15/FPSCR`). Its logical maximum is 320 bytes including the extended
hardware frame. This is separate from the physical PSP admission rule below.

`FiberContext` additionally holds the M55 MPU image, mutable runtime flags,
and sealed immutable boot metadata. The 8/16-region layout is intentionally
different and has separate exact cohort spellings:

| MPU regions | Per-context RBAR/RLAR pairs | protected image offset | boot offset | `sizeof(FiberContext)` |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 4 | 40 | 260 | 352 |
| 16 | 12 | 104 | 324 | 416 |

The protected image lives in privileged SRAM. The user PSP holds only the
hardware exception frame: 32 bytes for initial basic start and at most 108
bytes with scalar FP plus exception alignment padding. Context construction
therefore requires a conservative 112-byte usable PSP range, not 216 bytes.

## Fiber Mapping And Deliberate Differences

| FreeRTOS mechanism | Fiber mapping |
| --- | --- |
| `xMPU_SETTINGS.ulMAIR0` | `FiberContext.mair0` |
| `xMPU_SETTINGS.xRegionsSettings[]` | `FiberContext.mpu_regions[]` |
| `xMPU_SETTINGS.ulContext[54]` | overlapping `FiberPortProtectedContext` union |
| `xMPU_SETTINGS.ulTaskFlags` | `FiberContext.runtime_flags` |
| `pxPortInitialiseStack()` | `fiber_port_context_init()` |
| `prvSetupFPU()` | `fiber_port_fpu_prepare()` plus configuration/readiness readback |
| debug fill values | deterministic zero scratch values; `r9` is preserved for static-base ABI compatibility |
| FreeRTOS task control block ownership | Fiber adds sealed immutable boot metadata and exact-cohort retention |

The FPU policy preserves the reference CP10/CP11 and `FPCCR.ASPEN` model.
Fiber additionally reads policy back, makes `FIBER_FPU_LAZY` explicit
(`LSPEN=1` for lazy, `0` for eager), and rejects `LSPACT` before first start.
All three helpers are `general-regs-only`; no VFP or MVE instruction is valid
in construction or CPACR/FPCCR policy setup.

## Slice-1 Construction Proof

The compile matrix must prove, for 8 and 16 MPU-region manifests and both
hard-float and softfp `-O2`/`-Os` builds:

```text
type-only C/C++ storage has no CMSIS dependency
one exact C55P cohort is emitted for each manifest
the 8- and 16-region cohorts differ
all basic and extended union offsets are static-asserted
all constructor and FPU helpers remain privileged and emit no VFP/MVE transfer
the constructor owns only context_init, retains the runtime-defined cohort, and owns no handler
the construction linker proof retains all MPU boundaries and a compatible cohort relocation
missing linker boundaries and invalid FPU/MPU/core/MVE/CMSE manifests fail closed
```

`tools/freertos_asm_parity.ps1` compiles the same pinned FreeRTOS
`configENABLE_MPU=1`, `configENABLE_FPU=1`, no-MVE constructor at `-O2` and
`-Os`. The pairing records that both initial constructors seed a basic
protected image without VFP/MVE transfer instructions. Slice 3 separately
pairs the reference `vstmia`/`vldmia` copies of `s16-s31`, `s0-s15/FPSCR`,
the core image, and the copied hardware frame.

## Slice-2 Strict SVC Proof

`fiber_port_svc.c` adds the first-entry-only protected SVC mechanism:

```text
fiber_port_start_first_context(first)
  -> validates the selected first context and privileged start state
  -> rewinds MSP from the active vector table
  -> clears stale PendSV and enters SVC #70

SVC_Handler
  -> validates exact SVC provenance and the published common current context
  -> programs global MPU state while disabled
  -> calls fiber_port_restore_first_context_from_svc()
  -> restores the basic protected image and exception-returns to Thread/PSP
```

The restore preserves the FreeRTOS protected first-entry backbone: MPU disable,
MAIR0, RNR 4 and optionally 8/12 RBAR/RLAR pairs, MPU enable,
`[PSP][PSPLIM][CONTROL][EXC_RETURN]`, copied basic hardware frame, `r4-r11`,
cursor update, BASEPRI clear, and exception return. Both FreeRTOS and Fiber
must omit VFP/MVE transfer instructions here: the initial image is basic; the
extended scalar-FP representation is created only by the later PendSV save.

The matrix proves this for 8 and 16 regions, hard-float and softfp, `-O2` and
`-Os`, with an additional hard-float LTO synthetic ELF cohort. It proves one
strong `SVC_Handler` in vector slot 11 and rejects a competing strong SVC
handler. Slice 4 adds the seven non-construction forward operations here:
start preparation, protected first selection, first transfer, panic wait,
configuration validation, Thread-mode barrier, and the public SVC #71 schedule
veneer. `fiber_port_unprivileged_task_return()` remains the distinct private
SVC #72 return service.

### FAP-M55FMPU-SVC

FreeRTOS enters first start through its configurable SVC immediate and restores
the current TCB directly. Fiber uses fixed internal SVC #70, validates the
active vector slot, SVC opcode/call-site, masks, FPU state, linker placement,
MPU readback, sealed context, and common-published current context before the
same protected restore sequence. Fiber enables `MPU_CTRL.ENABLE | PRIVDEFENA`
instead of only `ENABLE`, because its selected privileged common runtime needs
the frozen current-context aperture during handler execution. These checks and
the SVC #72 task-return service add no context slot or scalar-FP transfer.

## Slice-3 Protected Scalar-FP PendSV Proof

`fiber_port_pendsv.c` owns the later runtime form of the same protected image.
Before it reads the mutable save cursor, its naked handler validates the live
current context, the basic or extended hardware frame, CPACR/FPCCR policy, and
the active MPU image. It then preserves the pinned FreeRTOS move order:

```text
extended save:
  PSP + 32 -> copy s0-s15/FPSCR
  s16-s31 -> protected image
  r4-r11, copied basic hardware frame, PSP, PSPLIM, CONTROL, EXC_RETURN

extended restore:
  PSP, PSPLIM, CONTROL, EXC_RETURN
  copied basic hardware frame, r4-r11
  copied s0-s15/FPSCR, s16-s31
```

The saved cursor is exactly `basic.cursor_limit` for the basic form or
`extended.cursor_limit` for the extended form. The scheduler is invoked through
the frozen reverse ABI under BASEPRI and must preserve the captured CPU and MPU
state. With PRIMASK asserted, Fiber disables the MPU, replaces MAIR0 and the
selected context's RBAR/RLAR pairs, publishes the next current context, then
reenables and reads the selected MPU image back before the inverse restore.

The matrix proves the handler for 8 and 16 regions, hard-float and softfp,
`-O2` and `-Os`, plus a hard-float LTO synthetic ELF. It checks the generated
VFP copy instructions, excludes MVE/VPR state, retains both the reverse ABI and
cohort identities, requires one strong handler in vector slot 14, and rejects a
competing strong `PendSV_Handler`. Slice 4 additionally proves that this
separate archive member is extracted by the mandatory SVC object's private
component-anchor call rather than by a startup weak handler alias.

## Slice-4 Runtime, Archive, And ELF Proof

The full runtime proof builds a static archive containing common runtime plus
the C55P boot, SVC, and PendSV objects. A portable application and the exact
cohort expectation are compiled outside that archive. For both 8- and
16-region manifests, it samples hard-float -O2, softfp -Os, and hard-float
-O2 LTO builds to prove:

- exactly one definition of each of the eight forward operations;
- strong SVC/PendSV handlers in vector slots 11 and 14;
- privileged, unprivileged, and syscall-flash placement of the runtime surface;
- extraction of boot, SVC, and PendSV archive members under section GC;
- external cohort retention and stale 8/16-region archive rejection; and
- failure for competing strong SVC or PendSV definitions.

The separate construction, SVC, and PendSV generated-code checks cover the
full hard-float/softfp -O2/-Os matrix. The archive proof is intentionally a
representative ABI/LTO cohort, not a claimed optimization cross-product.

SVC #71 is Fiber integration code, not a new FreeRTOS frame-layout claim. It
accepts only the exact syscall-flash veneer, validates the active protected
context, and requests PendSV; all protected frame movement remains the pinned
FreeRTOS-shaped SVC #70/PendSV logic described above.

## Deferred Work

The remaining work must not change this frozen layout:

1. optional heterogeneous MPU application policy only if explicitly requested;
2. MVE, SecureContext, TF-M, PAC, and BTI as different selected cohorts; and
3. matching M55F MPU execution and isolation hardware validation.

This profile has compile/assembly/archive/ELF evidence for its complete
build-selected runtime. It has no global auto-selection or hardware-support
claim.

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
