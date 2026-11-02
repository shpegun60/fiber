# ARM_CM33_MPU Non-secure FreeRTOS Parity Ledger

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

Slices 1-5 complete the explicit build-selected `ARM_CM33_MPU/non_secure`
no-FPU/no-TrustZone cohort. The selected port owns public storage and traits,
sealed construction, linker-derived global MPU images, strong `SVC_Handler` and
`PendSV_Handler`, the frozen eight-operation forward runtime ABI, and frozen
reverse ABI v1. It validates vector slots and SVC/PendSV provenance, installs
and reads back the four global MPU pairs while disabled, restores MAIR0 and the
selected RBAR/RLAR pairs, then restores `PSP`, `PSPLIM`, `CONTROL`, and the
protected basic frame before exception return. Its PendSV copies the complete
basic hardware frame into privileged context storage, invokes scheduler policy
under BASEPRI, and replaces the selected MPU image while PRIMASK protects the
disabled-MPU interval.

The profile is runtime-selectable only through its explicit build-selected
manifest; it does not enter global auto/profile selection. It exports no public
heterogeneous MPU-management API, SecureContext, TF-M, or hardware-support
claim. SVC 70 is first start, SVC 71 is the public `fiber_schedule()` syscall
veneer that only pends PendSV, and SVC 72 is task return. The original SVC
`EXC_RETURN` is passed explicitly from the C dispatcher into naked first
restore; the naked code revalidates the original `0xFFFFFFB8` SVC-origin token
before the selected context's own `EXC_RETURN` deliberately replaces `LR`. The
normal C call return address is never used as exception-return authority.

The reference is the no-TrustZone ARMv8-M Mainline source group, not the
TrustZone-capable `ARM_CM33/non_secure` source group. That distinction changes
the protected context layout.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
FreeRTOS CMake port: GCC_ARM_CM33_NTZ_NONSECURE
Reference directory: portable/GCC/ARM_CM33_NTZ/non_secure
```

| Reference file | SHA-256 | Fiber disposition through slice 5 |
| --- | --- | --- |
| `portmacro.h` | `F0D3FE9D1ADAA0894EE3A03F14152ADD4B115DF8AF144B5912FEA3EDD23FBE0B` | M33/Mainline identity and no-MVE policy mapped to the selected manifest. |
| `portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | MPU region roles, RBAR/RLAR/MAIR dictionary, `xMPU_SETTINGS`, and `MAX_CONTEXT_SIZE` audited. |
| `port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | `pxPortInitialiseStack()`, `vPortStoreTaskMPUSettings()`, and `prvSetupMPU()` adapted into sealed construction and in-memory global-image encoding. |
| `portasm.c` | `DFC14BD0E4CB5E504A9118292A4B0605ACEE1CFDD274BA33A55096914BAA45D5` | First restore plus PendSV save/program/restore order implemented and paired against generated assembly. |
| `mpu_wrappers_v2_asm.c` | `00B42952962E48F8C9421F5EC66BBCE9E02465760560728FEE2D743CE1706F3E` | Deferred to a future optional MPU-wrapper ABI. It is not copied as a stub. |

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

The Fiber selected manifest is deliberately equally narrow:

```text
FIBER_PORT_BUILD_SELECTED = 1
FIBER_PORT_ARMV8M_MAINLINE = 1
FIBER_PORT_CM33_MPU_TOTAL_REGIONS = 8 or 16
CMSIS __CORTEX_M = 33
CMSIS __MPU_PRESENT = 1
CMSIS __VTOR_PRESENT = 1
```

The profile rejects a Secure CMSE build, an FP register ABI, active FPU use,
MVE, PAC, and BTI. Those are distinct context cohorts, not toggles for this
layout.

## Frozen Storage And Frame

FreeRTOS uses this selected no-TrustZone configuration:

```text
xMPU_SETTINGS
    ulMAIR0
    xRegionsSettings[portTOTAL_NUM_REGIONS]
    ulContext[MAX_CONTEXT_SIZE == 21]
    ulTaskFlags
```

The first 20 context words are active. Word 20 is not SecureContext state;
it is the one-past cursor target returned by `pxPortInitialiseStack()`. The
reference no-TrustZone `portasm.c` consumes the final four active words with:

```text
ldmdb cursor!, {PSP, PSPLIM, CONTROL, EXC_RETURN}
```

The Fiber representation preserves that exact shape:

```text
FiberContext
    protected_context_cursor      Fiber adaptation of FreeRTOS pxTopOfStack
    mair0                         FreeRTOS ulMAIR0
    mpu_regions[4 or 12]          FreeRTOS xRegionsSettings
    protected_context             FreeRTOS ulContext[21]
    runtime_flags                 Fiber adaptation of ulTaskFlags
    boot                          Fiber immutable sealed metadata
```

`FiberPortProtectedContext` is exactly 84 bytes:

```text
word  0..7   r4..r11
word  8..15  copied basic hardware frame: r0..r3, r12, LR, PC, xPSR
word 16      PSP
word 17      PSPLIM
word 18      CONTROL
word 19      EXC_RETURN
word 20      cursor_limit, one-past save/restore target
```

There is no xSecureContext word in this no-TrustZone profile. A physical
SecureContext slot and any Secure companion remain separate future artifacts.

The context storage differs by MPU capacity but not by transfer semantics:

| MPU regions | Per-context RBAR/RLAR pairs | `protected_context` offset | `boot` offset | `sizeof(FiberContext)` |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 4 | 40 | 128 | 216 |
| 16 | 12 | 104 | 192 | 280 |

The exact layout version and retained context-cohort symbol differ between the
8- and 16-region manifests. Mixing their objects must therefore fail later
cohort/link checks rather than silently reusing incompatible offsets.
The immutable feature mask also includes the Non-secure execution role, as in
the existing ARM_CM23_NTZ and ARM_CM33_NTZ cohorts.

## MPU Region Mapping

The FreeRTOS ARMv8-M MPU region roles are retained:

```text
hardware RNR 0  privileged flash
hardware RNR 1  unprivileged flash
hardware RNR 2  unprivileged syscall flash
hardware RNR 3  privileged SRAM
hardware RNR 4  current fiber stack, stored at ctx->mpu_regions[0]
hardware RNR 5  current-context aperture, stored at ctx->mpu_regions[1]
hardware RNR 6..N-1  configurable pairs, stored at ctx->mpu_regions[2..]
```

Thus the per-context image has four RBAR/RLAR pairs for an 8-region MPU and
twelve pairs for a 16-region MPU. The selected port has separate macro names
for hardware region numbers and context-array indexes, preventing the invalid
`ctx->mpu_regions[4]` access that an ambiguous `STACK_REGION` name would cause
for the four-pair 8-region cohort.

The global in-memory image has exactly four pairs, indexed by hardware region
numbers `0..3`. The common `fiber_internal_runtime_current_context_slot` lies
at the start of an exact 32-byte aperture disjoint from privileged RW SRAM.
Each selected context owns the same `RNR 5` read-only/XN pair. Armv8-M forbids
overlapping enabled regions; region-number priority cannot implement an overlay.
This makes `fiber_current()` readable from unprivileged
Thread mode without an SVC round trip. The slot is written only while
`MPU_CTRL == 0` and PRIMASK protects the existing context-image replacement
interval.

This is a deliberate Fiber policy difference from FreeRTOS: the reference
keeps `RNR 5..N-1` available for task-configurable regions, whereas Fiber
reserves `RNR 5` for its portable direct `fiber_current()` API. Therefore the
8-region cohort retains two future configurable pairs (`RNR 6..7`) and the
16-region cohort retains ten (`RNR 6..15`). It does not change the FreeRTOS
protected frame, MAIR0 order, or `RNR 4/8/12` MPU programming sequence.

## Construction And Linker Policy

`fiber_port_context_init()` is the first frozen forward-ABI operation. It
constructs and seals a context but never touches live MPU registers. It
requires:

```text
FiberContext              fully contained in privileged SRAM
common current slot       exactly one disjoint 32-byte RO/XN SRAM aperture
raw task stack            fully contained in unprivileged RAM
task entry                Thumb address in unprivileged flash only
task return continuation  selected-port symbol in syscall flash only
```

The raw stack range must be non-empty and have 32-byte-aligned exclusive
boundaries. `fiber_port_mpu_try_encode_exact_region()` then emits an RBAR/RLAR
pair without rounding the caller's range outward. It encodes an exclusive end
as `(end - 1) & RLAR_ADDRESS_MASK`, after proving the endpoint is exactly
representable. This is intentionally stricter and less ambiguous than relying
on the reference linker's inclusive end-symbol convention.

Construction reserves the common red zone inside the raw stack mapping,
initializes `PSPLIM` to the usable `stack_base`, writes the canary when enabled,
and requires at least the physical 40-byte M33-MPU PSP frame budget. It fills
the exact 20 active protected words, places `protected_context_cursor` at the
final one-past `cursor_limit`, assigns MAIR0 (`normal=0xFF`, `device=0x04`),
enables the stack pair at context index zero, installs the fixed current-slot
pair at context index one, and disables all configurable pairs from index two.
The word layout is FreeRTOS-compatible, but Fiber intentionally seeds
scratch registers with zero instead of FreeRTOS debug marker values and copies
the live `r9` value rather than the reference's marker. This preserves a
platform/static-base ABI while keeping deterministic initial state; it does not
change the saved-word order or restore semantics. Immutable boot metadata,
MAIR0, and every RBAR/RLAR pair are sealed; the protected saved
registers/cursor and runtime flags remain mutable for the future protected
PendSV owner.

`fiber_port_mpu_build_global_regions()` builds, but does not write, these
four FreeRTOS-derived global images:

```text
image[0]  privileged flash, privileged read-only
image[1]  unprivileged flash, read-only
image[2]  unprivileged syscall flash, read-only
image[3]  privileged SRAM, privileged read-write and XN
```

`fiber_port_linker_contract.ld` is an application-owned assertion fragment.
It requires twelve exact boundaries for those four global regions, a disjoint
32-byte current-slot aperture, and unprivileged RAM. It rejects missing ranges,
non-32-byte MPU boundaries, a slot overlapping any fixed mapping, and every overlap
among the fixed code/RAM regions. It never chooses STM32 addresses itself. It
also requires protected code, unprivileged Thread helpers, syscall veneers,
protected data, and the current-slot output section to stay within their
respective ranges. The integration must place `fiber_panic()` in privileged
flash too; construction validates that exact target before accepting a layout.
First-start preparation also verifies that public Thread-mode entries
`fiber_current()` and `fiber_schedule()`, plus the local memory barrier, are
inside unprivileged flash. The internal current-slot load shares that linker
input section and is range-audited by the selected-profile synthetic ELF proof;
it is intentionally not exposed through this port's reverse C ABI.

## Function And Macro Ledger

| FreeRTOS symbol or family | Fiber disposition through slice 5 |
| --- | --- |
| `portARCH_NAME`, Mainline identity, byte alignment, BASEPRI traits | Implemented as selected-port manifest and trait facts. |
| `portTOTAL_NUM_REGIONS`, `portSTACK_REGION`, configurable region range | Implemented as the explicit 8/16-region type and macro contract. |
| `MPURegionSettings_t`, `ulMAIR0`, `xMPU_SETTINGS.ulContext`, `ulTaskFlags` | Implemented as `FiberPortMpuRegionRegisters`, `mair0`, `FiberPortProtectedContext`, and `runtime_flags`; Fiber adds sealed immutable boot metadata. |
| `MAX_CONTEXT_SIZE == 21` | Implemented exactly as 20 active words plus final `cursor_limit`. |
| `pxPortInitialiseStack()` | Implemented as `fiber_port_context_init()`: FreeRTOS-compatible no-TrustZone protected layout plus one-past cursor. Fiber deliberately uses zero scratch seeds and preserves live r9 instead of FreeRTOS debug markers. |
| `vPortStoreTaskMPUSettings()` | Implemented for the default Fiber policy: exact raw stack pair at context index 0, fixed current-slot aperture at index 1, and all configurable pairs disabled from index 2 until a future optional MPU API exists. |
| `prvSetupMPU()` | The construction helper `fiber_port_mpu_build_global_regions()` builds the four pairs. Slice 3 writes and reads them back in `fiber_port_mpu_program_global_image_while_disabled()` before naked per-context restore. |
| `vStartFirstTask()` | Implemented as `fiber_port_start_first_context()`: validates the direct SVC vector and initial MSP, clears stale PendSV, resets MSP, then invokes SVC 70. |
| `vRestoreContextOfFirstTask()` | Implemented as `fiber_port_restore_first_context_from_svc()`: MPU off, MAIR0, RNR 4/8/12 pair blocks, exact MPU enable, active-image readback, protected frame restore, and exception return. |
| `SVC_Handler` / `vPortSVCHandler_C()` | Implemented as the direct strong `SVC_Handler` plus fail-closed `fiber_port_svc_dispatch()`. SVC 70 is first start, SVC 71 is the public `fiber_schedule()` syscall veneer that only pends PendSV, and SVC 72 is task return. |
| MPU `PendSV_Handler` | Implemented as direct strong `PendSV_Handler`: preflight before cursor access, `r4-r11` plus complete basic-frame copy into privileged storage, BASEPRI scheduler bridge, PRIMASK-protected MAIR0/context-pair replacement, and inverse protected restore. |
| `xIsPrivileged`, `vRaisePrivilege`, `vResetPrivilege`, syscall dispatch | Deferred with the optional MPU application policy ABI; no no-op public stubs are exported. |
| `mpu_wrappers_v2_asm.c`, ACL, system-call stack | Deferred as optional MPU-wrapper functionality. The basic selected CPU profile does not pretend to implement FreeRTOS queue/wrapper policy. |
| SecureContext, TF-M, PAC, BTI, FPU, MVE | Absent by construction. Each needs a distinct selected-port or optional ABI cohort. |

## Slice-5 Proof

The compile matrix must prove all of the following before this slice is
accepted:

```text
type-only C and C++ storage compiles without CMSIS
the build-selected public facade resolves exactly this complete type
the full M33 MPU manifest compiles at -O2 and -Os for 8 and 16 regions
one exact cohort symbol is emitted per manifest and the two spellings differ
all context, boot, MPU pair, and cursor-limit offsets are static-asserted
hardware MPU region numbers and context-image indexes are distinct and pinned
sealed construction emits only port-private code in privileged code sections
the construction object has the exact linker-boundary/cohort dependency surface
synthetic 8/16-region linker images retain privileged, unprivileged, syscall,
current-slot, and stack sections with section GC enabled at -O2, -Os, and LTO
the linker fragment rejects a missing syscall-flash boundary
construction remains separate from runtime and emits no SVC, PendSV, `msr`, or
MPU-register write instruction
Secure CMSE, missing MPU/VTOR, FPU, MVE, PAC/BTI, wrong core, invalid region
count, a predeclared runtime-selectable override, and selector mode fail closed
the runtime has exactly one strong SVC handler and one strong PendSV handler,
defines exactly the eight frozen forward ABI operations, and no optional MPU API
the protected SVC/PendSV runtime compiles for 8 and 16 regions at `-O2`,
`-Os`, and LTO; it retains exactly the required strong symbols and code/data
sections under section GC
synthetic vectors retain strong SVC in slot 11 and strong PendSV in slot 14;
competing strong SVC and PendSV handlers each fail link
the full common-plus-port archive links only with an application-owned external
exact cohort expectation; 8- and 16-region stale complete archives each fail
that expectation under normal and LTO links
final normal and LTO ELFs prove the three code domains, the exact 32-byte
current-slot aperture, privileged FiberContext storage, unprivileged stacks,
strong vector slots 11/14, and the single selected cohort
generated assembly proves exact SVC 70/71/72 provenance, PendSV preflight
before the first current-cursor load, protected basic-frame copy, BASEPRI
scheduler bridge, PRIMASK-protected MPU replacement, and inverse restore
pinned FreeRTOS generated-assembly parity covers first start, MPU activation,
protected special/general/completion restore, and PendSV
save/program/restore at `-O2` and `-Os`
```

The generated-assembly claim is limited to the mechanisms listed above. It is
not a board claim: this profile remains compile, link, ELF, and generated-
assembly validated only.

## Remaining Work

The selected runtime is complete for this no-FPU/no-TrustZone cohort. It must
not change the sealed 20-active-word plus `cursor_limit` image, direct handler
ownership, or the protected MPU replacement sequence without repeating the
paired FreeRTOS assembly, archive/ELF, and available hardware evidence.

Remaining work is intentionally separate:

```text
hardware MPU-isolation and runtime validation on Cortex-M33 hardware
optional heterogeneous MPU application API and lifecycle module
FPU-enabled MPU cohort
TrustZone SecureContext companion or TF-M integration
MVE, PAC, and BTI cohorts
global auto/profile selection, if a product defines that policy explicitly
```

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
