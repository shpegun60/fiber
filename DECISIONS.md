# Fiber Decision Log

## 2026-08-28: Add Exact ARM_CM55_NTZ Scalar Non-Secure Profile

`ARM_CM55_NTZ/non_secure` is now a separate exact build-selected Cortex-M55
profile. It freezes the privileged, Non-secure, no-MPU, no-FPU, no-MVE,
no-SecureContext, no-TF-M, no-PAC, and no-BTI cohort under the distinct `C55N`
identity. It is not an alias for `ARM_CM33_NTZ`, despite the scalar frame
mechanics being the same.

The pinned FreeRTOS `ARM_CM55_NTZ/non_secure` `port.c`, `portasm.c`,
`portasm.h`, and `portmacrocommon.h` are byte-identical to the corresponding
CM33 NTZ artifacts. M55-specific selection lives in FreeRTOS `portmacro.h`:
it declares ARMv8.1-M minor version one and requires an explicit
`configENABLE_MVE` setting. Fiber deliberately represents that choice as a
concrete profile instead. This scalar profile rejects compiler MVE, FP,
PAC/BTI, Secure CMSE, and MPU configurations rather than accepting a runtime
feature toggle with a different context ABI.

The port owns the same ten-word `[PSPLIM][EXC_RETURN][r4-r11]` software frame,
the `0xFFFFFFB8` first-SVC provenance and `0xFFFFFFBC` PSP restore return, and
PSPLIM-aware PendSV save/select/restore sequence. Its M55 compiler contract is
`-mcpu=cortex-m55 -mthumb -mfloat-abi=soft` plus CMSIS `__CORTEX_M == 55`.
GCC may report `__ARM_ARCH_8M_MAIN__` for this soft-float target, so the
portmacro pairs the architecture result with the CMSIS core identity before
accepting it as ARMv8.1-M.

The matrix proves pinned provenance, `-O2`/`-Os` generated first-start,
first-restore, and PendSV parity, type-only C/C++ storage, exact cohort,
forward/reverse ABI, normal/LTO archive extraction, strong vector slots 11/14,
and wrong-core, FPU, MVE, PAC, BTI, CMSE, and MPU negative manifests. The
profile remains outside global selection and has no hardware claim. It does not
claim full STM32N6 support: M55F, MVE-FP, MPU, TrustZone/SecureContext or TF-M,
and PAC/BTI each require a separate exact selected profile and evidence.

## 2026-08-28: Add Exact ARM_CM33 TF-M Non-Secure Profile

`ARM_CM33_TFM/non_secure` is now a separate exact build-selected profile, not
an alias for plain `ARM_CM33_NTZ` and not the fiber-owned SecureContext port.
Its CPU frame, first-start SVC, and PSPLIM-aware PendSV mechanics intentionally
match the pinned FreeRTOS `GCC/ARM_CM33_NTZ/non_secure` port, while exact port
ID `C3TF` prevents a complete plain-NTZ archive from satisfying the TF-M build.
The unchanged ten-word frame keeps feature mask `0x82`; TF-M changes selected
integration identity, not saved context geometry.

The profile follows the pinned FreeRTOS `ThirdParty/GCC/ARM_TFM` split. The
external TF-M v2.0.0 Non-secure interface owns `tfm_ns_interface_init()` and
the PSA veneers. Fiber provides an idempotent `fiber_port_tfm_initialize()`
optional early entry and automatically requires the same initialization from
`fiber_port_runtime_prepare_start()` before CPU first-start setup. A retained
integration-bundle anchor forces the adapter object out of an ordinary static
archive. Missing TF-M interface code is an intentional link failure.

The exact TF-M v2.0.0 mutex surface is implemented without importing FreeRTOS
queues, semaphores, heap, ticks, or scheduler policy. One static owner-checked
mutex supports immediate acquisition for every timeout and cooperative retry
through `fiber_port_runtime_schedule()` only for `OS_WRAPPER_WAIT_FOREVER`.
A busy zero or finite timeout returns `OS_WRAPPER_ERROR`; the user scheduler
must eventually select the owner. Initialization and mutex operations validate
their Thread/mask role, and the external init call must preserve IPSR,
PRIMASK, BASEPRI, FAULTMASK, CONTROL, and PSPLIM.

Executable evidence pins both `ARM_TFM` artifacts by SHA-256, independently
compares C3TF first start/restore/PendSV with FreeRTOS at `-O2` and `-Os`, and
proves the exact external symbol surface, normal/LTO archive extraction,
strong vector slots 11/14, missing-interface and duplicate-handler failures,
exact cohort identity, and absence of fiber SecureContext symbols. This is
compile/assembly/archive/ELF evidence only. It does not claim a working TF-M
Secure image, PSA service, generated veneer set, or STM32 hardware runtime.

## 2026-08-28: Complete CM33 SecureContext Selected Runtime

`ARM_CM33/non_secure` now implements the complete build-selected no-MPU,
no-FPU TrustZone runtime around the exact pinned-FreeRTOS 19-word
companion-aware frame. The profile exposes one pre-start attach operation,
all eight mandatory forward runtime operations, and strong SVC/PendSV handler
ownership. It remains outside global auto/profile selection and makes no
hardware claim.

The paired Secure image provides four immutable identity veneers plus a
separate eight-function stateful v1 gateway. Initialization accepts only exact
SVCall and preserves the pinned FreeRTOS `AIRCR.PRIS`, zero Secure PSP/PSPLIM,
privileged Secure Thread/PSP, and pool-reset order. Save accepts only exact
PendSV, records live Secure PSP, proves owner/seal/alignment/bounds, then clears
and reads back Secure PSPLIM/PSP. Allocation/load accept only exact SVCall or
PendSV; load preserves PSPLIM-before-PSP and reads both back. Initialization
enters an irreversible intermediate state before destructive writes. Handle
zero remains an explicit no-context state only while no Secure stack is live.

SVC validates exact provenance/opcode/immediate, initializes the companion,
allocates and loads the first attached context, publishes the port-private live
handle, and restores `[handle, PSPLIM, EXC_RETURN, r4-r11]`. PendSV validates
current before metadata reads, saves/unloads Secure state before the scheduler,
saves the same eleven-word Non-secure frame, selects under BASEPRI, lazily
allocates an attached never-run context, restores PSPLIM, loads owned Secure
state, restores r4-r11/PSP, and returns through exact EXC_RETURN. The durable
handle remains frame word zero; one selected-port-private live handle mirrors
FreeRTOS `xSecureContext` and is never exposed to common runtime.

Matrix evidence covers `-O2`/`-Os` generated constructor,
initialization/allocation/save/load, segmented SVC/PendSV parity, exact
twelve-veneer CMSE import surface, all eight forward operations, strong vector
slots 11/14, assembly-load-only current slot, matching/missing companion and
optional lifecycle links, v1/v2 mismatch, duplicate handlers, Secure pool
placement, normal/LTO one-pass archive retention, and invalid manifests. The
always-linked mandatory object retains independent handler and attachment
bundle anchors because naked-asm helper references are opaque to the LTO
archive scanner. Lazy allocation validates the returned handle against the
Secure companion's nonzero capacity before publishing it in the software
frame. No board claim is inferred from this software evidence.

## 2026-08-26: Defer The Full Optimization Cohort Until Port Completion

Each port continues to enter the inventory only after paired pinned-FreeRTOS
generated-code parity at `-O2` and `-Os` plus its applicable normal/LTO ELF,
archive, ABI, cohort, and negative-link proofs. This remains the executable
per-port gate while new architecture profiles are still being implemented.

After every required STM32 profile is implemented or explicitly excluded, one
separate final hardening slice must run the complete port inventory at `-O0`,
`-Og`, `-O2`, `-Os`, and `-O3`. It must also compare the final linked-ELF
disassembly at `-O2 -flto` and `-Os -flto`; intermediate LTO assembly is not a
valid proof. The comparison requires equivalent ordered architecture
operations and documented Fiber adaptations, not byte-identical code.

The grid applies to every claimed exact build cohort, including applicable CPU
revision, hard/softfp ABI, FP/MVE state, MPU region count, security role, and
errata policy. Running one representative configuration per source directory
is insufficient when another supported configuration changes generated context
mechanics or cohort identity.

Hardware validation is tracked independently and is explicitly deferred for
the current port-completion phase. Missing board evidence does not block the
software freeze or later Context-interface extraction, but no affected profile
may be labeled hardware validated or hardware supported.

The proof will move into CI only through the two-level contract in
`CI_VALIDATION_PLAN.md`: the existing `-O2/-Os` per-port matrix is the
pull-request gate, while the complete optimization/final-LTO cohort is a
nightly, manually dispatchable, and release-blocking freeze gate. CI must pin
and record the compiler, CMSIS, FreeRTOS reference, workflow, runner, and Fiber
commit, then retain generated disassembly, ELF/map, symbol/section, and
negative-test artifacts. No CI workflow exists at this checkpoint.

## 2026-08-26: Add ARM_CM33 Secure Gateway ABI V1

`ARM_CM33/non_secure` slice 2 adds the smallest separately versioned Secure
companion artifact before any stateful SecureContext work. The paired
`ARM_CM33/secure` image exports four immutable `cmse_nonsecure_entry` NSC
identity functions: ABI version, context port ID, layout version, and feature
mask. Each symbol includes `v1`, so a missing or v2-only import library fails
the Non-secure link rather than silently entering an unrelated Secure image.

The matrix builds a real GCC Secure `-mcmse` image, emits its import library via
`--cmse-implib --out-implib`, links the matching Non-secure image, and proves
missing-import and v1/v2 mismatch failures at `-O2`, `-Os`, and `-O2 -flto`. The Secure
linker fixture gives `.gnu.sgstubs` a separate aligned NSC flash region, matching
the CubeIDE TrustZone linker model.

This historical checkpoint was intentionally gateway-only. It added no public
attach header, Secure allocation, Secure stack, SVC/PendSV operation, selected
runtime, or hardware claim. The 2026-08-28 construction/attachment/first-start
decision above supersedes that staged status and completes the separate
FreeRTOS-shaped PendSV save/load slice.

## 2026-08-26: Stage ARM_CM33 TrustZone SecureContext Layout

`ARM_CM33/non_secure` slice 1 is an explicit build-selected, non-MPU, no-FPU
TrustZone Non-secure type/layout cohort pinned to
`GCC/ARM_CM33/non_secure` plus its `secure/` companion reference group. It is
not a partial runtime and does not enter global selection.

The frozen software frame is eleven words:

```text
[xSecureContext][PSPLIM][EXC_RETURN][r4-r11]
```

This is intentionally distinct from the ten-word `ARM_CM33_NTZ` frame. The
public boot record reserves one sealed `secure_stack_bytes` pre-start request;
the live opaque SecureContext handle stays only in the saved frame's low word,
matching FreeRTOS `xSecureContext` ownership. No public attach header, Secure
gateway, SVC/PendSV implementation, or runtime claim exists in this slice.

The next implementation work must first introduce the separate optional common
pre-publication lifecycle guard and a versioned cross-image companion ABI. Only
then may the port add attachment, first-start allocation/load, and exact
PendSV SecureContext save/load mechanics. TF-M remains mutually exclusive with
the fiber-owned companion for this selected profile.

## 2026-08-26: Activate ARM_CM33_MPU As An Explicit Runtime Port

`ARM_CM33_MPU/non_secure` slice 5 activates the frozen eight-operation forward
ABI without adding a second switching path. It remains selectable only through
an explicit `FIBER_PORT_BUILD_SELECTED=1` manifest with the concrete
`ARM_CM33_MPU/non_secure` include/source group; generic ARMv8-M selection does
not infer MPU or privilege policy.

`fiber_start()` uses the existing common lifecycle sequence: the port prepares
the privileged Thread/MSP and MPU-disabled start environment, selects the first
context under the protected scheduler envelope, common publishes it, and the
existing SVC 70 path performs first MPU activation and restore. Public
`fiber_schedule()` now reaches the existing SVC 71 syscall veneer, which only
pends the selected strong PendSV handler. PendSV keeps the pinned FreeRTOS
save/select/MAIR0/context-pair/restore order; no protected frame word or naked
SVC/PendSV mechanism was redesigned during activation.

The public `fiber_current()` call is required to work in unprivileged Thread
mode. ARMv8-M offers no permission encoding for privileged-RW plus
unprivileged-RO, so Fiber deliberately reserves RNR5 as an exact 32-byte
read-only/XN current-slot aperture in every per-context MPU image. It overlays
global privileged SRAM by region priority. The next current pointer is written
only while `MPU_CTRL` is disabled under the already PRIMASK-protected context
replacement interval. This leaves two configurable pairs for 8-region builds
and ten for 16-region builds. It is a documented API-driven difference from
FreeRTOS, not an accidental loss of a task-configurable region.

The matrix proves paired FreeRTOS generated assembly at `-O2`/`-Os`, exact
8/16 cohorts, normal and LTO static-archive extraction, application-owned
cohort expectation, cross-region stale archive rejection, direct vector slots
11/14, section placement, exact current-slot aperture, and duplicate strong
handler failures. This is software evidence only. Cortex-M33 MPU runtime and
isolation hardware validation remain required before a support claim.

## 2026-08-26: Add ARM_CM33_MPU Protected PendSV

`ARM_CM33_MPU/non_secure` slice 4 adds the private protected PendSV engine to
the earlier no-FPU/no-TrustZone 8- and 16-region cohort. It keeps the exact
FreeRTOS `GCC/ARM_CM33_NTZ/non_secure` protected-image geometry: save
`r4-r11`, copy the complete basic hardware frame into privileged context
storage, save `PSP`/`PSPLIM`/`CONTROL`/`EXC_RETURN`, select under BASEPRI,
replace MAIR0 plus context MPU pairs while the MPU is disabled, and restore the
inverse image before exception return.

Fiber deliberately inserts fail-closed checks before those operations: PendSV
preflight validates the current pointer, seal, running PSP frame, canary,
special-register state, and active MPU image before it reads the mutable cursor;
the scheduler bridge snapshots and validates CPU/MPU state; and the MPU writer
runs with PRIMASK asserted and reads back the selected image. SVC 71 is an
exact private syscall-flash yield veneer that only pends the selected port's
strong PendSV handler. It is not yet the public `fiber_schedule()` operation.

This slice uses frozen reverse ABI v1, but it does not activate the eight
forward ABI operations, global selector routing, or a public MPU-management
API. It remains compile/link/ELF/generated-assembly validated only; hardware
MPU-isolation and runtime support are not claimed. The next slice may activate
the proven engine without changing this context geometry or handler ownership.

## 2026-08-26: Add ARM_CM33_MPU Protected SVC First Start

`ARM_CM33_MPU/non_secure` slice 3 adds exactly one behavior path: the protected
first transition from privileged Thread mode through strong direct `SVC_Handler`
to the selected unprivileged context. It remains outside the global selector and
the eight-function forward ABI, and it does not define `PendSV_Handler` or a
scheduler bridge.

The implementation follows pinned `GCC/ARM_CM33_NTZ/non_secure` MPU mechanics:
the SVC dispatcher disables PRIMASK, installs and reads back the four
linker-derived global region pairs with the MPU disabled, then naked restore
writes MAIR0 and the selected context pairs via RNR/RBAR/RLAR before enabling
the exact `ENABLE|PRIVDEFENA` control image. It validates the enabled image,
restores `PSP`, `PSPLIM`, `CONTROL`, core registers and copied hardware frame,
then exception-returns using the selected context's validated `EXC_RETURN`
token.

The original SVC `EXC_RETURN` is passed as an explicit C argument into naked
restore, moved back to `LR`, and revalidated before target-context restore
replaces `LR` with the selected context's token. A normal C call otherwise
replaces `LR` with its ordinary return address; treating that address as
`EXC_RETURN` would be a real first-start fault. The compile matrix now proves
this generated sequence at 8 and 16 MPU regions under `-O2`, `-Os`, and LTO,
as well as direct slot-11 vector ownership and duplicate-handler rejection.

PendSV save/select/MPU replacement, runtime-selectability, optional MPU API,
and hardware isolation remain separate future work.

## 2026-08-26: Construct ARM_CM33_MPU Protected Images Before Runtime

`ARM_CM33_MPU/non_secure` slice 2 adds only the exact construction and linker
boundary that the next SVC/PendSV slices will consume. It does not activate the
port through the global selector or the eight-function forward ABI.

The pinned FreeRTOS ARMv8-M mapping has two distinct number spaces. Hardware
MPU RNR `4` is the stack region, while the corresponding pair is stored in
`FiberContext::mpu_regions[0]`; RNR `5..N-1` maps to context indexes `1..`.
The selected port therefore has explicit `*_REGION_NUMBER` and
`*_CONTEXT_*_INDEX` macros. An ambiguous `STACK_REGION` macro could otherwise
write four entries past the four-pair 8-region context image.

The slice builds four global RBAR/RLAR pairs in memory: privileged flash,
unprivileged flash, syscall flash, and privileged SRAM. The common current
context slot stays as a precisely placed 32-bit object inside privileged SRAM,
not a separate MPU aperture. The linker contract owns twelve range boundaries,
requires all MPU ranges to be exact 32-byte exclusive intervals, and rejects
overlap among fixed global regions.

`fiber_port_context_init()` creates only an unprivileged Fiber context. It
requires context storage in privileged SRAM, the raw task stack in unprivileged
RAM, task entry in unprivileged flash, and the future task-return continuation
in syscall flash. It seals immutable boot metadata, MAIR0, and context MPU
pairs. It deliberately does not write an MPU register, define a handler, or
introduce a partial public runtime path.

## 2026-08-25: Stage ARM_CM33_MPU No-TrustZone Layout

`ARM_CM33_MPU/non_secure` starts as an explicit build-selected type and trait
cohort, not as a partial runtime. Its reference is
`GCC/ARM_CM33_NTZ/non_secure`, because the generic TrustZone-capable
`GCC/ARM_CM33/non_secure` group has a different protected-context contract.

For `configENABLE_MPU=1`, `configENABLE_TRUSTZONE=0`, no FPU/MVE/PAC/BTI, and
eight or sixteen total MPU regions, FreeRTOS reserves `ulContext[21]`. The
first twenty words are active: `r4-r11`, copied basic hardware frame, `PSP`,
`PSPLIM`, `CONTROL`, and `EXC_RETURN`. The final word is a one-past
save/restore cursor target, not `xSecureContext`. The Fiber profile preserves
that exact protected image behind `FiberPortProtectedContext`, with a separate
Fiber cursor, MAIR0, RBAR/RLAR pairs, mutable flags, and sealed boot metadata.

Slice 1 rejects Secure CMSE, FPU use, MVE, PAC, BTI, wrong CMSIS core, missing
MPU/VTOR, invalid region counts, selector mode, and a predeclared runtime
state. The matrix proves C/C++ type-only layout, selected facade, 8/16 cohort
separation, and the absence of runtime artifacts. It intentionally adds no
constructor, MPU write, SVC/PendSV handler, forward ABI, optional MPU API, or
hardware claim. The next slice is linker/global-image isolation plus sealed
construction; only then may first-start or PendSV code be introduced.

## 2026-08-25: Activate ARM_CM0_MPU As An Explicit Runtime Port

`ARM_CM0_MPU` slice 6 completes the frozen eight-operation forward ABI for the
exact ARMv6-M MPU profile. It is selectable only by an explicit
`FIBER_PORT_BUILD_SELECTED=1` manifest; `__MPU_PRESENT` never changes global
auto/profile selection because hardware capability cannot infer an application's
privilege policy.

The forward ABI deliberately composes the audited protected mechanism rather
than adding a second transfer path. `fiber_port_runtime_prepare_start()` checks
the privileged Thread/MSP environment, exact linker layout, vectors, priorities
and MPU-disabled initial state before the first scheduler callback.
`fiber_port_runtime_select_first()` runs that callback under the selected
PRIMASK envelope and validates the returned protected image. Common publishes
the result, then `fiber_port_runtime_start_first()` enters the existing SVC 70
first-start path. The naked first-start veneer no longer performs preparation.
The public `fiber_schedule()` path reaches the existing unprivileged SVC 71
yield veneer; PendSV remains the sole protected save/select/MPU-replace/restore
owner.

The matrix now proves the build-selected runtime as a static archive in normal
and LTO modes: all eight forward definitions, exact reverse ABI and cohort,
strong SVC/PendSV extraction over weak startup aliases, vector slots 11/14,
the port linker contract, privileged/unprivileged code and data placement,
duplicate-handler failure, and both directions of VTOR cohort mismatch. Paired
FreeRTOS generated assembly remains mandatory at `-O2` and `-Os`.

This activation creates no global selector route, public optional MPU API,
heterogeneous per-fiber MPU policy, or hardware support claim. Matching
Cortex-M0+ MPU hardware and isolation validation remain required.

## 2026-08-24: Freeze The Remaining STM32 Port Inventory

`STM32_PORT_FREEZE_INVENTORY.md` is the current planning ledger for the port
freeze required before Context extraction. The matrix passed from clean commit
`2743fc6401f551195f1d8896130715f05ecc4500`, including paired FreeRTOS
generated-assembly checks at `-O2` and `-Os` plus the active ELF, vector,
directional ABI, cohort, section-GC, LTO, and negative-link proofs.

Nine concrete parity-ledger profiles are present: privileged CM0/M0+, CM3,
CM4/F, CM7/r0p1, CM3 MPU, CM4/M7 MPU, CM23 NTZ, CM33 NTZ, and CM33F NTZ. This
count is software evidence only; it does not create a hardware claim for a
profile without a current board run.

The remaining full STM32 freeze scope is CM0 MPU, M33 MPU/FP, M33 TrustZone
Non-secure plus SecureContext, M33 TF-M integration, concrete M55/N6
FPU/MVE/MPU/TrustZone/security profiles, removal of `transitional_v8m`, and the
final available hardware checkpoints. ST now lists the preannounced STM32V8
Cortex-M85 family, so M85 is no longer classified as permanently non-STM32:
an all-announced-STM32 freeze must implement it, while a freeze that excludes
preannounced products must record that deferral explicitly.

The planning estimate is 10-16 remaining slices for basic privileged cores,
24-36 for full current STM32 coverage through M55/N6, and 32-48 when announced
M85/V8 is included. These are audit and implementation ranges, not support
claims or calendar commitments. The recommended order is CM0 MPU, M33 MPU, M33
TrustZone/SecureContext, M33 TF-M, M55/N6, optional M85/V8, transitional
removal, then the final software and available-hardware freeze.

This is documentation-only. It changes no current port, ABI, context cohort,
handler, frame, or generated code.

## 2026-08-25: Stage ARM_CM0_MPU linker isolation and global image

`ARM_CM0_MPU` slice 3 remains a build-selected, non-runtime source group. It
adds no selector route, forward runtime operation, SVC/PendSV handler, MPU
register write, or hardware claim. It only makes the memory-domain contract
required before a protected ARMv6-M first restore can exist.

The application linker owns all addresses and must include the port-owned
`fiber/port/ARM_CM0_MPU/fiber_port_linker_contract.ld` assertion fragment after
it defines ten exact privileged-code, unprivileged-code, privileged-data,
current-slot, and unprivileged-RAM boundaries. There is no weak fallback or
architecture guess. Global code/data ranges must be exact MPU regions, the raw
unprivileged-RAM envelope must be 256-byte aligned, and disallowed overlap
fails at link time.

Cortex-M0+ has a 256-byte MPU minimum region. Therefore global region 4 is one
exact 256-byte privileged-RW/unprivileged-RO/XN current-slot aperture, not the
32-byte aperture used by ARMv7-M MPU profiles. The common slot remains the sole
object in that output section, and the complete aperture must be zeroed by the
application startup path.

`fiber_port_mpu_build_global_regions()` now constructs in memory the exact
regions 4-7: current slot, unprivileged code, privileged code, and privileged
data. `fiber_port_context_init()` and the full seal check reject a context
outside privileged data, a raw stack outside unprivileged RAM, or an entry
outside unprivileged executable text before accepting the protected image.
This is deliberately only the pure layout/image portion of FreeRTOS
`prvSetupMPU()`: MPU type/control/fault policy, register writes, barriers, and
readback are deferred to the SVC start slice.

The matrix proves this at `-O2` and `-Os`, then repeats linker/ELF retention
under LTO: all linker-boundary relocations, section placement, one exact
256-byte current-slot output section, positive ELF placement, two negative
linker configurations, no runtime handler symbols, and no CPU-state instruction
in construction/global-image code. The next slice is strong SVC first start and
unprivileged service provenance, not selector activation.

## 2026-08-25: Stage ARM_CM0_MPU SVC First Start And MPU Activation

`ARM_CM0_MPU` slice 4 adds only the protected first-start half of the selected
runtime. The source group remains `FIBER_PORT_RUNTIME_SELECTABLE == 0`; it
still defines no `PendSV_Handler`, no public forward runtime ABI operation, and
no accepted yield route. This avoids an unsafe intermediate state where an
unprivileged fiber could pend a vector without the matching protected
save/select/MPU-replace/restore owner.

The selected port now owns a strong `SVC_Handler`, `svc #70` first start, and
`svc #72` unprivileged task return. It rejects the reserved yield service 71
and every foreign/mis-originated SVC after checking IPSR, EXC_RETURN, stack
origin/range, xPSR, instruction opcode/immediate, code domain, and exact
continuation address. The first start preserves the ARM_CM0 FreeRTOS policy of
not rewinding MSP, clears stale PendSV under PRIMASK, and enters SVC only after
the selected first image, SVC vector, and SVCall priority readback are valid.

Inside SVC, the port requires the exact eight-region MPU type and disabled
control state, programs all context/global regions, enables
`MPU_CTRL == ENABLE | PRIVDEFENA`, barriers, and reads every region back before
the unprivileged exception return. The restore keeps the FreeRTOS ARM_CM0 MPU
Thumb-1 `+20/-32/-48/-32/-16` protected-frame geometry and copied eight-word
hardware frame, while Fiber adds PSP/CONTROL/EXC_RETURN readback and seals the
complete first image, including live r9. The naked handler uses a literal
Thumb-address tail branch to the C dispatcher so LTO cannot make a narrow
Thumb-1 branch out of range.

The matrix proves this staged scope at `-O2`, `-Os`, and LTO: direct strong
slot-11 SVC vector ownership, exact first-start/restore assembly structure,
VTOR-present and VTOR-absent compilation, linker-section placement, exact
undefined surfaces, and absence of `PendSV_Handler`. It is compile/assembly/
ELF evidence only; it creates no Cortex-M0+ MPU hardware support claim.

## 2026-08-25: Add ARM_CM0_MPU Protected PendSV And Private Yield

`ARM_CM0_MPU` slice 5 completes the private ARMv6-M MPU execution mechanism
without activating the eight-operation forward runtime ABI.
`FIBER_PORT_RUNTIME_SELECTABLE` remains zero, the global selector still excludes
the profile, and no public MPU configuration API is introduced.

The selected port now owns strong direct `SVC_Handler` and `PendSV_Handler`
symbols, slot-11/slot-14 vector validation, SVCall priority zero, PendSV lowest
priority, stale-PendSV cleanup, and the closed `70` start / `71` private yield /
`72` task-return SVC namespace. Yield is accepted only from its exact
unprivileged continuation; it pends PendSV under PRIMASK and never performs
context selection itself.

PendSV keeps the pinned FreeRTOS ARM_CM0 MPU protected 20-word geometry:
Thumb-1 saves r4-r11, copies the complete eight-word hardware frame into
privileged context storage, saves PSP/CONTROL/EXC_RETURN, enters the
PRIMASK-protected scheduler bridge, atomically replaces the per-context MPU
image, and restores the selected frame. No ARMv7-M transfer form, BASEPRI, or
user-stack software frame is introduced.

Fiber hardens the reference sequence without changing its transfer geometry:

- current provenance, live PSP frame, active MPU image, and context cursor are
  checked before the first `current->protected_context_cursor` read;
- the scheduler callback must preserve PRIMASK, CONTROL, IPSR, PSP, vector
  source, SVC/PendSV priorities, pending-PendSV state, MPU control/selection,
  and all eight effective RBAR addresses/RASR values;
- returned context validation precedes common-owned publication;
- MPU replacement runs with PRIMASK asserted, changes only mutable regions
  0-3, preserves linker-derived global regions 4-7, and reads back the complete
  selected image;
- the exact eight-word protected hardware transfer rejects xPSR `STACKALIGN`
  padding rather than silently copying an unmodelled word.

The scheduler callback is a trusted privileged integration point. Before the
forward ABI is activated, its code and user object must be assigned to
privileged MPU domains by the concrete application linker policy. The port
proves that its direct reverse-ABI selector and publication callees are in
privileged code; it does not claim to infer or police an opaque user function
pointer at this staged boundary.

The compile matrix and generated-assembly parity proof cover `-O2`, `-Os`, and
LTO, direct slots 11/14, VTOR-present/absent cohorts, exact unresolved
surfaces, preflight-before-cursor ordering, Thumb-1 save/restore, PRIMASK
envelope, MPU replacement, and negative linker assertions. This remains
compile/assembly/ELF evidence only. Cortex-M0+ MPU hardware and isolation
validation are still required.

## 2026-08-24: Freeze Context, Fiber, And Kernel Layer Separation

The current five-function v2 runtime remains the active porting and validation
baseline. After the required Cortex-M ports and hardware checkpoints are
frozen, its CPU mechanics will be extracted behind a standardized Context
consumer surface. Existing selected ports become Context backends and retain
their FreeRTOS-derived SVC/PendSV implementation, exact context cohorts,
private feature state, and proof obligations.

The extraction gate is explicit: every architecturally distinct required STM32
profile must pass its applicable frame, save/restore, exception, feature-state,
compile/LTO, generated-assembly, ELF/vector, ABI/cohort, and negative proofs.
Profiles without matching boards remain compile/assembly/ELF validated only.
Context extraction cannot start while a known software gap remains in a
required profile.

After the mechanical extraction, the same generated-assembly, ELF/vector,
directional ABI/cohort, negative-link, and available hardware evidence must be
repeated against the stable pre-extraction checkpoint. The new baseline is not
accepted when that comparison exposes an unintended runtime behavior change.

Context owns opaque CPU execution state, current publication, one registered
dispatcher, first start, Thread-mode yield, the future ISR reschedule boundary,
and all CPU-specific validation. Fiber consumes Context and owns stackful
identity and execution lifetime. The C++ Task/Kernel layer owns ready, wait,
sleep, time, synchronization, and scheduler policy. Scheduler policies operate
on Tasks or Fibers and never inspect selected context fields.

After extraction, adding a processor or execution profile means implementing
one complete Context backend plus its build, ABI/cohort, generated-code, and
hardware evidence. It must not require a processor branch or source change in
Fiber, Task, SchedulerPolicy, synchronization, or service-adapter layers.

No public `context_switch(from, to)`, direct resume target, or manual first
target is permitted. First and later targets come only from the registered
dispatcher inside the selected port's protected envelope. A future host backend
may use Boost.Context for lifecycle and policy tests, but cannot claim Cortex-M
ISR, MPU, TrustZone, vector, or hardware behavior.

This is a documentation-only architectural decision. It changes no current
symbol, ABI, frame, handler, or generated assembly. The normative ownership,
execution flows, negative dependency rules, proofs, and mechanical migration
slices are in `CONTEXT_FIBER_ARCHITECTURE.md`.

## 2026-08-24: Freeze Future TrustZone SecureContext User Lifecycle

No current selected Fiber port implements TrustZone SecureContext support.
`ARM_CM23_NTZ`, `ARM_CM33_NTZ`, `ARM_CM33F_NTZ`, and `ARM_CM7/r0p1` therefore
export neither a SecureContext header nor a compatibility stub.

A full TrustZone profile implemented on the active v2 baseline keeps the
mandatory five-function public API and eight-function runtime ABI unchanged.
Its selected Non-secure port exposes a separate, profile-specific pre-start
attachment operation for a fiber that will use Secure services. The context is
attached after `fiber_init()` and before the first `fiber_start()`, then sealed
as selected-port metadata. PendSV, not application code, saves and restores
that fiber's Secure state through one matching versioned Secure companion
gateway. After the later Context/Fiber extraction, the same mechanics belong
to the selected Context backend and the security outcome does not change.

This intentionally differs from FreeRTOS's task-side
`portALLOCATE_SECURE_CONTEXT()` call. Fiber has a static sealed-context
lifecycle rather than a mutable TCB lifecycle, but preserves the relevant
outcome: only an attached fiber receives a private Secure stack/state, and a
fiber without an attachment cannot inherit it. TrustZone remains distinct from
MPU task isolation. TF-M is an alternative Secure provider and is mutually
exclusive with the fiber-owned SecureContext companion for one selected
profile. The full artifact and proof contract is in
`TRUSTZONE_SECURE_CONTEXT_CONTRACT.md`.

## 2026-08-24: Complete ARM_CM33F_NTZ FP-Aware Runtime

Slice 4 completes the exact build-selected `ARM_CM33F_NTZ/non_secure` runtime
without widening the no-FPU M33 profile or global selection. The strong
`PendSV_Handler` retains the pinned FreeRTOS non-MPU CM33 FPU order:
conditionally save `s16-s31`, save `[PSPLIM, EXC_RETURN, r4-r11]`, execute the
scheduler under BASEPRI, then restore the same core/FP state and return through
the selected EXC_RETURN. Basic and extended frames remain exactly 72 and up to
212 bytes respectively.

Fiber adds selected-context provenance, metadata/canary/frame bounds, live
PSPLIM, CPACR/FPCCR, scheduler-state, and post-restore readback checks without
changing the saved context words. `LSPACT` remains forbidden for the one-shot
first SVC start but is allowed during PendSV, where the first VFP operation may
complete legitimate lazy state preservation. The port now exposes all eight
forward ABI functions with strong SVC/PendSV handlers when explicitly
build-selected. Hard-float and softfp `-O2/-Os` generated assembly plus
normal/LTO archive/vector proofs are required; no M33F hardware claim exists
until a real Non-secure board passes basic and extended FP switching stress.

## 2026-08-24: Stage ARM_CM33F_NTZ FPU And SVC Start Before PendSV

Added build-selected `ARM_CM33F_NTZ/non_secure` slices 1-3 instead of widening
the no-FPU `ARM_CM33_NTZ` profile. The pinned FreeRTOS
`pxPortInitialiseStack()` path proves that `configENABLE_FPU=1` still starts on
the same basic `[PSPLIM, EXC_RETURN, r4-r11]` plus hardware frame. Fiber freezes
that 72-byte initial image and separately reserves the 212-byte dynamic maximum
for `s16-s31`, the extended hardware frame, and alignment padding.

The exact cohort uses port ID `C3FN`, layout v1, feature mask `0x83`, basic
`EXC_RETURN=0xFFFFFFBC`, and extended `EXC_RETURN=0xFFFFFFAC`. Hard-float and
softfp builds are accepted only when compiler, CMSIS, and silicon all report FP
use; soft/no-FP, MPU, MVE, PAC, BTI, wrong core, and Secure CMSE combinations
fail closed. Constructor code is `general-regs-only` and paired with the pinned
FreeRTOS generated frame at `-O2` and `-Os`. Its private boot constructor fills
the destination in place, so pre-FPU construction has no `memcpy` or `memset`
dependency outside the attribute-controlled port call graph.

The first behavior slice now owns CPACR/FPCCR setup with barriers/readback,
uses `FIBER_FPU_LAZY` only for the LSPEN policy, rejects active lazy state, and
starts the initial basic context through one strict strong `SVC_Handler`.
Normal/LTO archive proofs retain that handler in vector slot 11, leave slot 14
empty, and reject a competing strong SVC definition. This is still not a
runtime promotion: `FIBER_PORT_RUNTIME_SELECTABLE` remains zero and the port
defines neither `PendSV_Handler` nor `fiber_port_runtime_schedule`. FP-aware
PendSV remains a separate behavior-changing slice.

## 2026-08-24: Complete ARM_CM33_NTZ Non-MPU Runtime

Implementation slice 4 completes the exact build-selected
`ARM_CM33_NTZ/non_secure` non-MPU/no-FPU runtime. `PendSV_Handler` preserves the
pinned FreeRTOS ten-word `[PSPLIM][EXC_RETURN][r4-r11]` frame, replaces
`vTaskSwitchContext()` with the frozen user scheduler bridge under BASEPRI,
and adds exact exception provenance, frame bounds, scheduler CPU-state, PSPLIM,
PSP, CONTROL, and mask checks. `fiber_port_runtime_schedule()` is now the
eighth mandatory forward operation and `FIBER_PORT_RUNTIME_SELECTABLE` is one.

The generated FreeRTOS/Fiber pairs pass the same ordered first-start,
first-restore, and PendSV mechanism checks at `-O2` and `-Os`. The selected
runtime archive must expose both strong handlers, resolve synthetic vector
slots 11 and 14, survive section GC in normal and LTO links, and reject
competing strong handlers. Global auto/profile routing remains on
`transitional_v8m`; MPU, FPU, SecureContext, TF-M, and hardware support are
separate future claims.

## 2026-08-24: Make Generated FreeRTOS Assembly Parity Mandatory

The compile matrix now invokes `tools/freertos_asm_parity.ps1` as a mandatory
fail-closed cohort. The cohort verifies local FreeRTOS commit
`a50edad08b29052631aa469d4df6e6ec7ff68878` and SHA-256 identities for every
consumed portable artifact, then compiles the FreeRTOS and Fiber objects with
the same GCC, CPU/FPU ABI, Thumb mode, and optimization level. The mandatory
cohort runs every comparison at both `-O2` and `-Os`.
The script derives the production inventory from `fiber_port.c` files and
fails if a production directory lacks either a paired definition or its local
`FREERTOS_PARITY.md` record.

The paired `objdump` proof covers all mechanisms currently implemented by the
production selected ports: separate M0/no-VTOR and M0+/VTOR builds, M3, M4F,
M7 r0p1, M23 NTZ, the complete CM33 NTZ non-MPU runtime, CM3 MPU, and CM4 MPU. It
checks ordered SVC start, first restore, PendSV save/restore, scheduler mask,
FP transfer, PSPLIM, CONTROL, MPU replacement, and exception return.
`transitional_v8m` remains outside production parity.

Exact binary equality is not required because Fiber intentionally adds
validation and substitutes its user scheduler bridge for
`vTaskSwitchContext()`. Every accepted generated-code difference must instead
name a normative `FAP-*` rationale in `FREERTOS_ASM_PARITY.md`. An unpinned
reference, missing operation, reordered architecture transfer, undocumented
difference, or accidental premature handler now prevents the matrix from
passing.

## 2026-08-24: Add ARM_CM33_NTZ SVC First Start As A Separate Slice

The exact build-selected `ARM_CM33_NTZ/non_secure` profile now owns the
FreeRTOS-derived first-context transfer without pretending to be a complete
runtime port. The selected-port object implements startup preparation,
BASEPRI-protected `pick_next(NULL, user)`, restore validation, a naked SVC
entry, and one strong `SVC_Handler`. `FIBER_PORT_RUNTIME_SELECTABLE` remains
zero, `fiber_port_runtime_schedule()` and `PendSV_Handler` remain absent, and
the global selector is unchanged.

Every added port mechanism must carry two independent parity artifacts: an
explicit instruction/function mapping to the pinned local FreeRTOS port and a
generated-disassembly check of the emitted Fiber code. Compile-only or
source-token parity is not sufficient. For M33 first start, Fiber consumes the
same `[PSPLIM][EXC_RETURN][r4-r11]` software frame as the FreeRTOS non-MPU
PendSV restore, while adding exact SVC provenance, frame, vector, CPU-state,
and special-register readback checks.

## 2026-07-20: Construct The Exact ARM_CM33_NTZ Initial Context

Implementation slice 2 adds only the construction half of the exact
build-selected `ARM_CM33_NTZ/non_secure` profile. `fiber_port_boot.c` owns the
sealed immutable boot record, address-map and overlap checks, optional canary,
and exact initial-frame validation. `fiber_port.c` owns the one context-cohort
definition and the eighteen-word synthetic frame:

```text
[PSPLIM][EXC_RETURN][r4-r11][r0-r3,r12,LR,PC,xPSR]
```

The PSPLIM word is seeded from `stack_base`, matching the pinned non-MPU
FreeRTOS `pxPortInitialiseStack()` frame. Unlike M23, this value is a live
Mainline register state; a later M33 PendSV slice must save and restore it.
Fiber additionally preserves `r9`, seals and validates the boot metadata, and
validates every synthetic frame word before returning from
`fiber_port_context_init()`.

This does not activate a runtime profile. `FIBER_PORT_RUNTIME_SELECTABLE`
remains zero, global selection remains unchanged, and the profile defines no
SVC handler, PendSV handler, scheduler bridge, runtime-start operation, archive
activation, or hardware claim. The next behavior-changing slices are M33 SVC
first start and then the PSPLIM-aware PendSV path.

## 2026-07-20: Stage The Exact ARM_CM33_NTZ Layout

Implementation slice 1 adds a deliberately non-selectable
`fiber/port/ARM_CM33_NTZ/non_secure` profile derived from the pinned FreeRTOS
`GCC/ARM_CM33_NTZ/non_secure` source group. The exact manifest is ARMv8-M
Mainline Cortex-M33, single-core privileged non-MPU fiber execution in the
Non-secure domain, no SecureContext companion, and no FPU/MVE/PAC/BTI context.

The saved software frame is frozen as ten words:

```text
[PSPLIM][EXC_RETURN][r4-r11]
```

Unlike M23 NTZ, this profile has an accessible PSPLIM register. Therefore
`FIBER_PORT_HAS_PSPLIM_SLOT == 1` and
`FIBER_PORT_USES_PSPLIM_REGISTER == 1` are independent exact-cohort facts.
Initial `EXC_RETURN` is `0xFFFFFFBC`, the scheduler mask is BASEPRI, the
initial context is 72 bytes, and the maximum saved context is 76 bytes.

The new directory exports only type/layout/trait artifacts and a reference
parity ledger. It provides no runtime source, handler, archive, or hardware
claim and remains absent from global auto/profile selection. Construction, SVC,
PendSV, BASEPRI envelope, archive/ELF, and hardware evidence are separate
behavior-changing slices. An MPU-capable CPU does not activate an MPU ABI; an
FP-capable CPU must use a separate M33F context profile before it can compile
with an FP register ABI.

## 2026-07-20: Activate ARM_CM23_NTZ Build-Selected Runtime

Implementation slice 5 promotes the concrete `ARM_CM23_NTZ/non_secure` source
group to an exact build-selected runtime profile. Its manifest defines
`FIBER_PORT_BUILD_SELECTED=1` and `FIBER_PORT_ARMV8M_BASELINE=1`, places the
concrete private directory first on the include path, and compiles only
`fiber_port.c` plus `fiber_port_boot.c` with the common runtime. This does not
add an ARMv8-M auto/profile route: ordinary Cortex-M23 auto and explicit
architecture selection remain on `transitional_v8m` until a separate policy
decision promotes a concrete profile globally.

The matrix now links that source group as a static archive against an unchanged
portable application and an application-owned exact cohort expectation object.
It proves all eight forward ABI symbols, one exact cohort identity, strong
`SVC_Handler`/`PendSV_Handler`, vector slots 11 and 14, section-GC retention,
normal and LTO archive extraction, and deliberate duplicate-handler failure.
The cohort definition is explicitly link-visible under GCC LTO, so the external
expectation cannot be silently optimized into an unverified whole-archive link.

This is compile/link/ELF evidence only. The profile has no Cortex-M23 or STM32
hardware claim, and Secure, MPU, SecureContext, and TF-M roles remain separate
optional profile work.

## 2026-07-20: Add ARM_CM23_NTZ PendSV Switching Source

Implementation slice 4 completes the source-level non-MPU switching mechanics
for the build-selected, still non-selectable `ARM_CM23_NTZ/non_secure` profile.
The port now exposes all eight frozen forward-ABI operations and directly owns
both strong exception handlers. `fiber_port_runtime_schedule()` accepts only
privileged Thread/PSP execution with `PRIMASK == 0`, then requests PendSV.

The PendSV handler follows the pinned FreeRTOS NTZ non-MPU ten-word frame:
it validates exact PendSV/PSP `EXC_RETURN = 0xFFFFFFBC`, validates the running
context before reading its metadata, proves source bounds and stack-alignment
padding, saves `[0][EXC_RETURN][r4-r11]`, invokes the user scheduler under
PRIMASK, validates/publishes the selected target, and restores through the
reference `+24/-36` Thumb-1 geometry. Word 0 is the mandatory PSPLIM slot, but
ordinary Non-secure M23 saves write zero and restore deliberately skips it;
this profile emits no PSPLIM register access.

The source is intentionally not yet runtime-selectable. Archive extraction,
exact vector/ELF/LTO evidence, and Cortex-M23 Non-secure hardware validation
remain promotion requirements. Matrix coverage must prove the exact eight
forward operations, both strong handlers, scheduler/reverse dependencies,
save-before-metadata validation ordering, ten-word save/restore shape, and
absence of PSPLIM instructions. This is source/generated-code evidence only.

## 2026-07-18: Add ARM_CM23_NTZ SVC-only First Start

Implementation slice 3 adapts the pinned FreeRTOS Cortex-M23 NTZ first-task
restore without exposing an incomplete switching runtime. The build-selected,
non-selectable profile now defines seven frozen forward-ABI operations and one
strong `SVC_Handler`; `fiber_port_runtime_schedule` and `PendSV_Handler` remain
absent until the next slice.

The handler accepts only the exact Non-secure Thread/MSP/basic SVC origin
`0xFFFFFFB8`, validates the stacked MSP frame and start SVC instruction, invokes
the first scheduler selection under saved PRIMASK, validates the selected
context, sets and reads back `CONTROL = 2`, ignores the reserved PSPLIM word,
restores `r4-r11`, and returns through the context's exact `0xFFFFFFBC`.
SVCall priority and active VTOR slot 11 are written/read back before selection.
They are revalidated under PRIMASK after the user scheduler hook, and that mask
is retained into the naked start helper so no IRQ window exists before SVC.
The ARMv8-M `CONTROL.SPSEL` seed follows the reference first restore; exact
`EXC_RETURN` remains the authority for unstack and SVC provenance.

Matrix coverage requires the exact seven-operation surface, one strong SVC and
no PendSV, exact reverse dependencies, and generated Thumb-1 `+24/-36` restore
geometry. This is compile/generated-code evidence, not a Cortex-M23 hardware or
complete-runtime claim.

## 2026-07-18: Construct The Exact ARM_CM23_NTZ Initial Context

Implementation slice 2 adds a deliberately partial `fiber_port.c` and
`fiber_port_boot.c` to the non-selectable `ARM_CM23_NTZ/non_secure` profile.
The source group implements only `fiber_port_context_init` from the frozen
eight-function forward ABI. It owns boot metadata construction, seal/hash and
address-map checks, stack normalization, canary initialization, and the exact
18-word initial frame. It defines no SVC/PendSV handler or scheduling/startup
operation.

The FreeRTOS constructor initializes its reserved PSPLIM slot with the lower
stack bound even though the NTZ restore path does not write PSPLIM. Fiber does
the same: initial word 0 is `FiberPortBoot.stack_base`. The future PendSV save
path must follow the other reference branch and write zero into that slot.
This distinction replaces the earlier imprecise description of the slot as
always zero.

The matrix requires all frame assignments in exact order, one matching cohort,
only `fiber_port_context_init` from the forward ABI, the expected reverse and
integration dependencies, and no handler symbols. The profile remains absent
from global selection until all eight operations and handler/ELF proofs exist.

## 2026-07-18: Stage The Exact ARM_CM23_NTZ Layout

Implementation slice 1 adds a deliberately non-selectable
`fiber/port/ARM_CM23_NTZ/non_secure` profile derived from the pinned FreeRTOS
`GCC/ARM_CM23_NTZ/non_secure` source group. The exact manifest is ARMv8-M
Baseline Cortex-M23, privileged non-MPU fiber execution in the Non-secure
domain, no SecureContext companion, and no FPU/MVE/PAC/BTI.

The saved software frame is frozen as ten words:

```text
[PSPLIM placeholder][EXC_RETURN][r4-r11]
```

The PSPLIM slot is mandatory even though Non-secure Cortex-M23 cannot access a
Non-secure PSPLIM register. Therefore `FIBER_PORT_HAS_PSPLIM_SLOT == 1` and
`FIBER_PORT_USES_PSPLIM_REGISTER == 0` are independent exact-cohort facts.
Initial `EXC_RETURN` is `0xFFFFFFBC`, initial saved context is 72 bytes, and
saved SP remains 8-byte aligned. This intentionally differs from the nine-word
`transitional_v8m` baseline frame.

The new directory exports only type/layout/trait artifacts and a reference
parity ledger. It provides no runtime source, handler, archive, or hardware
claim and remains absent from global auto/profile selection. Context
construction, SVC, PendSV, startup, archive/ELF, and hardware evidence are
separate behavior-changing slices.

## 2026-07-18: Activate The ARM_CM4_MPU Build-Selected Runtime

Implementation slice 5 completes the exact `ARM_CM4_MPU` source group without
adding a global architecture selector route. A build selects the protected
profile through the private include path plus
`FIBER_PORT_BUILD_SELECTED=1`, `FIBER_PORT_ARMV7EM=1`, and an explicit
`FIBER_PORT_CM4_MPU_TOTAL_REGIONS` value of 8 or 16. MPU presence alone never
changes the privileged ARM_CM4 or ARM_CM7 profile selected by auto detection.

The port now implements all eight frozen forward runtime operations. Startup
validates privileged Thread/MSP state, exact linker and vector ownership,
implemented NVIC priority bits, PRIGROUP, fault policy, SVC/PendSV priorities,
stale PendSV state, CPACR/FPCCR, MPU-disabled preconditions, and the concrete
M4/M7 identity before scheduler selection. The first scheduler call remains
inside the port BASEPRI envelope; its CPU, MPU, vector, and FPU state is
snapshotted and checked before the selected context is validated and returned
to common for publication. First transfer then revalidates the published
context and uses the existing protected SVC restore.

The full integration proof links the unchanged portable application against a
static archive containing common plus selected-port runtime for M4F and M7F,
8 and 16 regions, with and without LTO. It requires all eight strong ABI
symbols, an exact external cohort match, strong vector slots 11 and 14,
privileged/unprivileged code and data placement, the isolated 32-byte current
slot, exact 2 KiB user stacks, section-GC retention, no dynamic stack use, and
duplicate-handler link failure. This activates a software build claim only;
M4F and M7F hardware, FP, MPU-fault, and isolation validation remain separate.

## 2026-07-17: Add The ARM_CM4_MPU Protected PendSV Slice

Implementation slice 4 completes the non-selectable profile's protected
switch path without activating the global selector or the remaining forward
runtime ABI. The strong `PendSV_Handler` validates exact Thread/PSP provenance,
the current seal/cursor/frame, active MPU image, CPACR/FPCCR policy, masks, and
CONTROL/FPCA before reading mutable context fields.

The handler follows the pinned FreeRTOS 53-word geometry: basic switches copy
CONTROL, `r4-r11`, EXC_RETURN, PSP, and the eight-word hardware frame into
privileged storage; extended switches prepend `s16-s31` and the 17 raw
`s0-s15/FPSCR` words copied from `PSP + 32`. Lazy FP preservation must complete
and clear `FPCCR.LSPACT` before scheduler publication. Restore performs the
inverse copy and never places a software frame below the unprivileged PSP.

Scheduler policy executes in privileged PendSV under the selected BASEPRI
threshold. The port snapshots masks, CONTROL, IPSR, PSP, VTOR, MPU state,
CPACR, and FPCCR around the user hook, validates the selected protected image,
then publishes it through the frozen reverse ABI. MPU replacement runs with
PRIMASK closed, reenables the exact selected image, and reads back every
per-context and global region before restore. Cortex-M7 BASEPRI writes retain
the stronger PRIMASK-preserving errata sequence.

Compile/link/ELF proofs cover M4F/M7F with 8 and 16 regions, eager and lazy FP
policy builds, exact undefined dependencies, load-only current-slot assembly,
six generated FP transfers, validator/save/scheduler/MPU/restore ordering,
strong vector slots 11 and 14, duplicate-handler failure, privileged section
placement, and continued selector isolation. Hardware behavior remains
unvalidated; the next slice is the eight-function forward ABI and exact
build-selection activation.

## 2026-07-17: Add The ARM_CM4_MPU Protected SVC Slice

Implementation slice 3 adds the exact profile's protected first-start path
without activating global selection or changing common runtime behavior. The
port now owns fixed SVC services 70/71/72, a strong `SVC_Handler`, an
unprivileged schedule veneer, and an unprivileged task-return veneer. Dispatch
accepts only exact Thread/MSP first-start or Thread/PSP basic/extended origins
and validates masks, frame shape, opcode, immediate, continuation provenance,
current context, linker isolation, and active MPU state before acting.

First start prepares and reads back CPACR/FPCCR, validates the concrete M4/M7
CPUID, installs all 8- or 16-region MPU register pairs, enables MemManage and
`MPU_CTRL.ENABLE|PRIVDEFENA`, then performs the FreeRTOS-style second MSP rewind
and protected basic-context restore. Cortex-M7 BASEPRI clear uses the existing
stronger PRIMASK-preserving errata sequence rather than unconditionally
enabling IRQs around `msr BASEPRI`.

The extended-FP SVC rule is explicit: PSP addresses the basic core frame and
the low FP extension follows at higher addresses. The handler never offsets
PSP before reading stacked PC/xPSR. Compile proofs cover M4F/M7F with 8 and 16
regions, exact service count and generated restore shape, strong vector slot
11, duplicate-handler failure, protection sections, linker boundaries, and
the deliberate absence of `PendSV_Handler`. The profile remains
non-selectable; the next slice owns protected FP-aware PendSV save, scheduler,
MPU replacement, and restore.

## 2026-07-17: Add ARM_CM4_MPU Context Construction

Implementation slice 2 adds the port-owned `fiber_port_boot.h/.c` construction
boundary without making `ARM_CM4_MPU` selectable. `fiber_port_context_init()`
now validates exact linker-owned privileged/unprivileged ranges, encodes the
stack supplied through the portable `fiber_init()` API, disables every unused
per-context region, seeds the FreeRTOS-compatible basic protected frame, and
seals all immutable boot and MPU fields. Each context therefore owns a distinct
RBAR/RASR image even though the future handler will reuse the same hardware MPU
register bank for whichever fiber is current.

The region encoder deliberately rejects non-power-of-two extents, insufficient
alignment, access encodings outside the selected policy, and any request that
would require widening a region. This is stricter than the reference helper,
which rounds a requested size upward. Context storage must be inside exact
privileged data, stacks inside exact unprivileged RAM, and entries inside exact
unprivileged executable text. The current-context aperture and the other three
global policy regions are also constructed from mandatory linker boundaries.

The construction source compiles and links for Cortex-M4F and Cortex-M7F with
both eight- and sixteen-region manifests. Matrix proofs require distinct exact
cohorts, privileged function placement, every linker-boundary relocation,
negative links for each missing boundary, no unexpected undefined symbol, and
no handler or forward-runtime definition. Protected SVC/PendSV switching,
MPU register programming/readback, FPU startup policy, exact selection, and
hardware support claims remain later slices.

## 2026-07-17: Stage ARM_CM4_MPU Protected Layout

Implementation slice 1 adds a deliberately non-selectable `ARM_CM4_MPU`
profile based on the pinned FreeRTOS GCC port. It freezes type-only protected
context storage, MPU region formulas, exact M4F/M7F and 8/16-region cohort
identities, and an exhaustive parity ledger. It adds no runtime source,
handler, forward ABI implementation, or global selector route.

The build must explicitly declare eight or sixteen MPU regions because that
choice changes `FiberContext`. The protected image retains the reference
53-word maximum: high FP, low FP/FPSCR, CONTROL/core registers, PSP/copied
hardware frame, and a one-past cursor target. FreeRTOS wrapper-v2 syscall
stacks, ACLs, and access metadata are classified as a future optional MPU ABI,
not silently copied into the mandatory base context.

## 2026-07-17: Freeze C++ Kernel Layer Direction

The portable C core remains a scheduler-neutral CPU transfer engine. A future
reference C++ kernel will provide compile-time cooperative round-robin and
preemptive fixed-priority policies over the same scheduler callback and port.
Synchronization and ISR-safe handoff belong to that layer; SysTick or another
ISR requests PendSV but does not embed scheduler policy in port assembly.

Source intended to move between both modes must synchronize shared mutable
state and must not assume execution continues uninterrupted until explicit
yield. lwIP integration remains an adapter above the kernel: raw/event-loop
integration for `NO_SYS=1`, or C `sys_arch` wrappers over C++ primitives for
`NO_SYS=0`. `CPP_KERNEL_ARCHITECTURE.md` is normative for this direction but
does not create an implementation or runtime claim.

## 2026-07-17: Close Third-Round Portability Proof Gaps

The third independent line-by-line comparison against the pinned local
FreeRTOS ports found no new save/restore, SVC, PendSV, BASEPRI, FPU-frame, or
MPU-region ordering defect in the production CM0, CM3, CM4, CM7, and
build-selected CM3_MPU source groups.

One initial-context portability gap was corrected in `ARM_CM3_MPU`: its
protected synthetic frame now seeds callee-saved `r9` from the live platform
value, matching the policy already used by the privileged ports. This retains
a process-wide static base for toolchain or platform ABIs that reserve `r9`,
instead of assuming that zero is always a valid initial value. The protected
20-word storage remains the audited FreeRTOS geometry: 19 active saved words
plus the explicit spare/one-past cursor word.

Because ordinary AAPCS permits GCC to use `r9` as a general callee-saved
register, the corresponding generated-code proof uses `-ffixed-r9`. It checks
the configuration in which `r9` actually has platform static-base semantics;
the ordinary ABI remains covered separately and does not assign that meaning
to the initial register value.

The compile matrix now also exercises M4F and M7F with the softfp calling
convention and lazy FP stacking enabled. This proves that FPU discovery,
extended-frame compilation, and the no-FP scheduler ABI do not accidentally
depend on hard-float-only predefined macros. The CM3_MPU source proof now
freezes both the live-r9 seed and its exact exception priority policy:
PendSV lowest, SVCall highest, with exact readback predicates.

`transitional_v8m` remains intentionally unchanged. These are software-side
proofs; CM0/CM3/CM4/CM3_MPU hardware claims and a refreshed CM7 run remain
separate.

## 2026-07-17: Close Second-Round Cortex-M Port Guards

The privileged CM0, CM3, CM4, and CM7 schedule-request paths now require exact
privileged Thread/PSP state (`CONTROL[1:0] == 0b10`) after current-context
ownership is established and before any mask read or direct `PENDSVSET` write.
This catches accidental privilege loss or MSP selection with panic `'l'`
instead of relying on a system-register or ICSR fault. FPCA remains dynamic and
is deliberately excluded from this two-bit check.

PendSV priority readback is now exact in all four production source groups.
CM0, CM3, and CM4 no longer accept the weaker `(read & lowest) == lowest`
predicate; setup and runtime validation both require the right-justified CMSIS
value to equal the selected lowest priority. The compile matrix freezes both
the CONTROL guard ordering and the two exact priority checks.

The CM3 MPU synthetic ELF proof now verifies that the concrete scheduler hook
is in privileged executable code and its application-owned `user` object is in
privileged data, in addition to the existing context/runtime placement checks.
This is a positive integration proof for the fixture, not a runtime validator
for arbitrary indirect call graphs; real MPU integrations retain responsibility
for equivalent linker placement of the hook, user state, and every callee.

The local FreeRTOS MPU comparison also confirms that temporarily disabling the
MPU while replacing task regions is reference behavior. Fiber keeps BASEPRI
raised and additionally holds PRIMASK across that interval. NMI and HardFault
remain architectural exceptions and their handlers are trusted integration
code, as in the reference model. `transitional_v8m` remains build-only and its
runtime behavior is unchanged.

This checkpoint has source, compile, link, and H7 Debug/Release ELF evidence.
Its new direct-schedule CONTROL trap still requires a future H7 hardware run;
no previous board result is promoted across this behavior change.

## 2026-07-17: Harden Privileged Cortex-M Port Parity

The privileged `ARM_CM0`, `ARM_CM3`, and `ARM_CM4` handlers now use the same
fail-closed exception provenance policy as the validated CM7 path. First-start
SVC checks IPSR, exact incoming EXC_RETURN, MSP frame alignment, xPSR Thumb and
Thread state, absence of unexpected alignment padding, stacked PC shape, SVC
opcode, and immediate. PendSV checks IPSR, accepted EXC_RETURN, PSP origin and
alignment, current context preflight, and complete save headroom before writing
the software frame.

PendSV save bounds now account for the optional xPSR `STACKALIGN` word on CM0,
CM3, and CM4. All production restore validators reject stacked PC values below
two even when switch-time address-map hooks are disabled. The staged CM3 MPU
SVC-frame validator follows the same cheap PC floor rule.

BASEPRI policy is now exact configuration identity. The context-cohort symbol
encodes `__NVIC_PRIO_BITS` and every bit of the selected threshold. CM3, CM4,
and CM3 MPU use threshold `2` for 8-bit NVIC implementations and reject bit 0;
CM0 rejects any nonzero BASEPRI setting because the register does not exist.
The compile matrix freezes handler ordering, `STACKALIGN` geometry, PC guards,
8-bit defaults, CM0 rejection, and distinct NVIC/BASEPRI cohort symbols.

The CM0, CM3, and CM4 parity ledgers are pinned to local FreeRTOS commit
`a50edad08b29052631aa469d4df6e6ec7ff68878` and classify the reference macro,
constant, function, tick, ISR, FPU, and MPU families. `transitional_v8m` remains
a build-only deletion target and receives no behavioral hardening in this
checkpoint.

## 2026-07-17: Activate Exact Build Selection For ARM_CM3_MPU

`ARM_CM3_MPU` is now a build-selectable compile/link-covered profile. Exact
selection follows the FreeRTOS model and requires the complete manifest:

```text
defines       FIBER_PORT_BUILD_SELECTED=1, FIBER_PORT_ARMV7M=1
include path  fiber/port/ARM_CM3_MPU
sources       ARM_CM3_MPU/fiber_port.c, ARM_CM3_MPU/fiber_port_boot.c
CPU ABI       -mcpu=cortex-m3 -mthumb -mfloat-abi=soft
hardware      __CORTEX_M=3, MPU and VTOR present, no FPU
linker        exact privileged/unprivileged ranges and 32-byte current slot
expectation   build-owned fiber_port_context_cohort_expectation.c plus KEEP
```

No exact generic port-ID macro is added. `FIBER_PORT_ARMV7M` remains only the
architecture compatibility gate; the selected include path, source group,
context cohort, and linker contract provide exact identity. Auto,
`FIBER_PORT_PROFILE_ARMV7M`, and force modes deliberately continue selecting
privileged `ARM_CM3`, even when `__MPU_PRESENT == 1`, because hardware
capability cannot infer application privilege policy.

The matrix proves the exact public facade, diagnostic name, protected context
layout, rejection without build-selected mode, and non-inference by auto mode,
in addition to the existing normal/LTO archive and exact MPU-linker proofs.
This activation is not a hardware claim. Cortex-M3 MPU execution, isolation,
MemManage faults, SVC/PendSV behavior, and board-specific MSP headroom remain
unvalidated until slice 8 runs on matching hardware.

## 2026-07-17: Complete The Non-Selectable ARM_CM3_MPU Software Integration

The exact `ARM_CM3_MPU` source group now implements all eight frozen
common-to-port runtime operations while remaining unreachable from the global
selector. Startup is fail-closed over privileged Thread/MSP state, all masks,
MPU type and disabled control, active VTOR and strong handlers, implemented
priority bits, PRIGROUP, fault policy, SVC/PendSV priorities, and stale PendSV.
The first scheduler callback runs inside the same selected BASEPRI policy as
later handler-side selection and must preserve the captured CPU/MPU state.

The minimal common Thread-callable chain uses the CPU-neutral
`.text.fiber_runtime_thread_functions` marker. Its `.text.*` name remains
compatible with existing non-MPU linker scripts, while an MPU linker extracts
it together with the unprivileged SVC veneers before the privileged catch-all.
This explicit marker is required because ordinary `-ffunction-sections` names
are not stable across whole-program LTO.

The compile matrix now links the unchanged portable five-function application
against common runtime and the complete MPU port from a static archive under
section GC, with and without library LTO. The synthetic exact-memory manifest
proves one eight-function ABI, reverse ABI v1, exact cohort expectation,
strong-handler extraction over weak startup aliases, slots 11/14, duplicate
strong-handler failure, code/data protection placement, aligned 2 KiB stacks,
the exact 32-byte current slot, and finite compiler stack-usage artifacts. The
portable application translation unit stays outside LTO in this proof so its
unprivileged entry section remains independently auditable; arbitrary
application entry placement remains an integration responsibility.

Conditional slice 5 remains omitted because the safe uniform policy does not
yet need heterogeneous MPU configuration. The profile remains
`FIBER_PORT_RUNTIME_SELECTABLE == 0`, has no hardware or STM32 support claim,
and may be exposed only by the separate selector slice after these proofs stay
green.

## 2026-07-17: Add The Non-Selectable ARM_CM3_MPU PendSV Slice

The staged exact `ARM_CM3_MPU` source group now implements slice 4 without
changing common runtime ABI or activating global selection. Its strong
`PendSV_Handler` follows the audited FreeRTOS 20-word protected-context
geometry: CONTROL, r4-r11, EXC_RETURN, original PSP, and a copy of the basic
hardware frame live in privileged `FiberContext` storage. No software frame is
written to the unprivileged stack.

Before the handler reads mutable context fields, privileged preflight validates
exact PendSV/EXC_RETURN/CONTROL/mask provenance, current context placement and
seal, live PSP bounds, hardware-frame structure and PC, the active eight-region
MPU image, MPU_CTRL, and MemManage enable. The scheduler then runs under the
selected BASEPRI threshold. The port snapshots and verifies PRIMASK, BASEPRI,
FAULTMASK, CONTROL, IPSR, PSP, VTOR, MPU_CTRL, and MemManage-enable state across
the user hook, validates the returned protected context, and publishes it
through reverse ABI v1.

Regions 0-3 are replaced for the selected context while BASEPRI remains raised
and PRIMASK closes the short interval in which MPU_CTRL is disabled or the
region image is partial. Regions 4-7 remain the sealed global policy. All eight
regions, MPU_CTRL, and MemManage enable are read back before restore. BASEPRI is
cleared while PRIMASK is still active, then the protected hardware frame is
copied to the selected PSP and CONTROL/r4-r11/EXC_RETURN are restored. Only the
live protected-context cursor is transitioned after restore.

The compile matrix now proves preflight-before-field access, exact protected
save/copy and restore instruction shapes, scheduler/BASEPRI/PRIMASK/MPU order,
strong privileged `PendSV_Handler`, slot-14 Thumb vector resolution, exact
undefined surfaces, and continued selector isolation. These are compile,
generated-code, link, and synthetic ELF proofs only. The profile remains
non-selectable and carries no hardware runtime claim.

## 2026-07-16: Add The Non-Selectable ARM_CM3_MPU SVC Slice

The staged `ARM_CM3_MPU` source group now implements its third mechanical
slice without changing common runtime ABI or activating global selection. The
port owns fixed SVC services 70/71/72 for first start, unprivileged yield, and
unprivileged task return. Its strong `SVC_Handler` validates exact exception
origin, frame shape, opcode, immediate, continuation provenance, current
context, and zero interrupt-mask state; every unknown or mismatched service
fails closed.

The first-start service programs and reads back the exact eight-region
Cortex-M3 MPU image, enables MemManage faults and `MPU_CTRL.ENABLE` with
`PRIVDEFENA`, copies the protected hardware frame onto PSP, restores CONTROL,
r4-r11 and EXC_RETURN, and enters unprivileged Thread/PSP by exception return.
Immediately before programming PSP it rewinds MSP from the active vector table
a second time. This deliberately discards the start-SVC hardware frame and the
C dispatcher call frame, matching the essential FreeRTOS first-restore rule.
The two unprivileged veneers contain only their SVC request and minimal return
or terminal-loop instruction. Only privileged handler code can write
`PENDSVSET` or reach the common task-return sink.

Global region 4 is repurposed from the broad FreeRTOS peripheral mapping into
an exact 32-byte privileged-RW/unprivileged-RO/XN aperture containing only the
common current-context slot. The slot has a standard `.bss.*` subsection so
ordinary non-MPU linker scripts remain compatible while an MPU linker manifest
can isolate it. The complete aperture remains part of startup BSS zeroing.
Region 7 remains privileged-only RW/XN. Therefore portable
`fiber_current()` can read current identity without exposing other contexts,
the scheduler hook, or runtime metadata to unprivileged Thread mode.

The compile matrix proves exact undefined symbols, protection-section
placement, generated veneer/start/handler instruction shape, assembly-only
current-slot loading, the second MSP rewind before PSP programming, exactly
three SVC instructions, strong slot-11 SVC vector ownership, and the deliberate
absence of PendSV and selector routing. The
profile remains non-selectable and has no runtime support claim. Slice 4 must
add protected PendSV save/switch/restore and per-context MPU replacement before
selection can be considered.

## 2026-07-15: Record The Corrected H7 Extended-FP Normal Run

The STM32H7 board passed `FIBER_VAL_NORMAL_RUN` after source commit
`7ffe1a9a139acd33dccb609856f0742d62fd3c68` corrected the extended-FP
hardware-frame geometry. The debugger snapshot recorded
`validation_flags = 0x1FF`, `validation_failures = 0`, and
`last_panic_code = 0` after approximately 2.47 million iterations per fiber.
The saved `f2` EXC_RETURN remained `0xFFFFFFED`, so the run repeatedly exercised
the real extended-FP save/validate/restore path rather than only the synthetic
basic startup frame.

The one-iteration counter skew is expected because the debugger stopped in the
middle of a cooperative round. The FP relationships remained exact for each
completed fiber iteration. This restores the H7 normal/extended-FP runtime
result for the corrected source. It does not complete the hardware checkpoint:
the startup and complete trap suite still require a fresh run before the full
H7 validation claim is active.

## 2026-07-15: Correct Cortex-M Extended FP Frame Geometry

An STM32H7 normal-mode run based on `a3d98c7` completed the first
`f2 -> f1 -> f3` cycle, then stopped with panic `'x'` while validating the
saved extended-FP frame for `f2`. The saved context provided the decisive
evidence: EXC_RETURN was `0xFFFFFFED`, while the old validator interpreted
word 49 (`FPSCR = 0x10`) as stacked PC and word 50 (the reserved FP word) as
stacked xPSR.

For the observed unpadded CM7 frame, the saved layout from `FiberContext.sp`
is:

```text
0..8    software r4-r11 and EXC_RETURN
9..24   software-saved s16-s31
25..32  hardware r0-r3, r12, LR, PC, xPSR
33..48  hardware-saved s0-s15
49      FPSCR
50      reserved
```

This matches the local FreeRTOS ARM_CM4_MPU reference, which advances the
hardware PSP by `0x20` bytes to reach `s0`: the basic core frame begins at PSP
and the low-FP extension follows it. The old fiber validator incorrectly added
the low-FP extension size before locating PC/xPSR. CM7 PendSV made the same
mistake when reading `xPSR.STACKALIGN` at `PSP + 100` for an extended frame;
the architectural xPSR offset is always `PSP + 28`.

All selected-port restore validators now distinguish core-frame offset from
total frame extent. A high-FP software save moves the hardware core frame; the
low-FP hardware extension increases only the required total extent. CM7
PendSV uses one xPSR offset for basic and extended frames. The external H7 trap
harness uses the same corrected geometry when corrupting stacked PC or xPSR.
The compile matrix rejects any port that moves PC/xPSR by
`FIBER_EXC_FP_EXT_BYTES` and rejects a second CM7 extended xPSR offset.

This is a behavior-changing frame-validation fix. The H7 runtime claim remains
suspended until normal mode, FP stress, and the complete trap suite pass on the
corrected revision.

## 2026-07-15: Integrate The Exact Cohort Expectation In H7 Manifests

The STM32H7 CubeIDE Debug and Release configurations now compile
`fiber/port/fiber_port_context_cohort_expectation.c` as an application-owned
translation unit outside the selected port archive. Both configurations define
`FIBER_PORT_BUILD_SELECTED=1` and `FIBER_PORT_ARMV7EM=1`, use the concrete
`ARM_CM7/r0p1` private include path, and exclude all non-CM7 port source groups,
the transitional v8-M fixture, legacy architecture folders, and `fiber/tools`
fixtures from managed-build source discovery.

The H7 linker script keeps `.fiber_port_context_cohort_expectation` in a
read-only FLASH output section. Fresh CubeIDE managed builds completed for
Debug and Release with zero errors and zero warnings. The expectation-object
and final-ELF audit for both configurations proved:

- exactly one `fiber_port_context_cohort_armv7em_*` definition;
- exactly one undefined expectation-object reference to that same symbol;
- a four-byte, four-byte-aligned, allocatable and non-writable expectation
  output section whose contents are the cohort-symbol pointer;
- exactly one strong `SVC_Handler` and one strong `PendSV_Handler`;
- vector slots 11 and 14 resolve to those handlers with the Thumb bit set.

This closes the whole-archive exact-cohort integration debt for the current H7
application manifests at library commit `3b05aa8`. The CubeIDE project and
linker script live in the host application tree outside this repository, so
this decision records their verified integration state but does not make them
part of the fiber repository commit. It is a build/link proof only: the active
H7 runtime claim remains suspended until the current normal, FPU, startup,
trap, VTOR, SVC, and PendSV hardware checklist passes on the board.

## 2026-07-15: Activate The Exact Selected-Port Context Cohort Guard

Every active selected-port source group now has one exact link identity. Its
mandatory runtime object defines a generated read-only symbol; the matching
boot and exception objects retain relocations from one-shot init/start paths.
The symbol spelling encodes the architecture profile, concrete port ID, layout
version, FPU/extended-frame state, BASEPRI/FAULTMASK/VTOR/PSPLIM capabilities,
stack alignment, scheduler mask class, FPCA and M7 errata policy, initial
EXC_RETURN, optional context slots, and MVE/PAC/BTI/security-domain facts. This
also distinguishes ARM_CM0 builds whose shared source has different M0/M0+
VTOR capability.

`fiber/port/fiber_port_context_cohort_expectation.c` is the independent
build-owned side of the guard. A production build compiles it through the
selected private include path, links it outside any precompiled port archive,
and keeps `.fiber_port_context_cohort_expectation` in a read-only output
section. Omitting that object or its linker `KEEP` rule invalidates the
whole-archive exact-cohort compatibility claim, although the three port objects
still detect internal mixtures. This identity guard is not a source-revision
fingerprint: revisions that deliberately preserve the same cohort identity
remain link-compatible.

The compile matrix requires one definition, two matching private-object
relocations, and one matching build expectation for every build-selected
profile. A real Cortex-M33 transitional source group is built in Secure-role
and Non-secure-role variants. Positive archives link; stale runtime, boot,
exception, and complete-archive combinations fail in both directions on the
exact missing cohort symbol, with section GC and with LTO. The transitional
v8-M trait outputs were normalized to literal tokens so source sharing cannot
hide profile identity.

This change adds only one-byte reads to one-shot context initialization and
startup validation. It does not alter synthetic frames, SVC/PendSV assembly,
save/restore order, or the switch hot path. The software
`common-core-freeze-v1` guards are now closed for the current source groups.
The later H7 manifest-integration checkpoint added the expectation object and
linker keep rule; the active H7 runtime claim still requires the already-pending
fresh board suite.

## 2026-07-15: Close The Reverse Runtime ABI V1 Proof Cohort

The compile matrix now combines every selected port's source group with a
relocatable link and requires one exact unresolved-symbol set. The set contains
only reverse runtime ABI v1, the explicitly classified RAM/code address-map
integration hooks, and the freestanding `memcpy`/`memset` toolchain
dependencies. A selected-port group that adds another common helper, scheduler
global, compiler helper, or accidental integration symbol fails the matrix.
The same group is forbidden to define the common-owned anchor, current slot,
scheduler bridge, task-return sink, or panic symbol.

The current-context slot is now protected at three levels. A source ownership
audit confines its selected-port spelling to the five mandatory runtime source
files. Negative C fixtures prove that the reverse header cannot read, assign,
or take the address of the slot. Build-selected generated assembly must contain
every slot reference only as an immediately adjacent `ldr reg, =slot` followed
by an `ldr reg, [reg]` pair; any alternate reference or store through the slot
address fails.

Synthetic v1 and v2 port/common cohorts prove runtime ABI versioning in both
directions. Matching cohorts link from static archives under
`--gc-sections`, with and without LTO. A v1 port with v2-only common and a v2
port with v1-only common both fail on the missing port-version anchor before
handler extraction can affect the result.

This proof-only checkpoint closed the reverse runtime ABI v1 cohort. The later
exact selected-profile/context cohort checkpoint closed its then-pending
stale-private-object guard. Refreshed H7 board validation remains separate.

## 2026-07-15: Activate Frozen Reverse Runtime ABI V1

The common-owned `fiber_runtime_port_abi.h` now exposes exactly the frozen
port-to-common v1 boundary: one version anchor, scheduler candidate selection,
current-context publication, the current-context lifecycle guard, task-return
sink, and canonical panic declaration. Selected ports no longer include
`fiber_runtime_state.h` or see scheduler hook/user storage and first-selection
state.

`fiber_internal_runtime_current_context_slot` replaces the transitional current
symbol. It has no declaration in the reverse header: selected-port inline
assembly may only materialize and load its exact symbol name, while only common
runtime C can publish it. All current port sources were moved together so no
old and new slot spelling can coexist.

Every selected `fiber_port.c` retains a real relocation to
`fiber_internal_runtime_port_abi_v1_anchor` through a one-shot volatile read in
`fiber_port_runtime_prepare_start()`. This keeps ABI-version retention out of
PendSV. Port calls to `fiber_panic()` are now strong references; the bundled
common implementation alone remains weak so one application strong override
still works.

The first-selection marker is fail-closed and one-way. Once the first scheduler
selection begins, hook replacement remains forbidden even before current
publication. A `NULL` scheduler result now terminates inside the common selector
with `'N'`, as required by reverse ABI ownership. Context validation and current
publication remain port-validated and ordered exactly as before. SVC/PendSV
assembly save/restore instructions, frame layout, scheduler critical envelopes,
and handler ownership are unchanged.

The compile matrix requires one active anchor relocation and one strong port
panic reference, exact strong reverse definitions and one weak fallback,
assembly-only slot references, absence of transitional symbols, and all current
CPU/profile selection modes. The larger mismatch/static-archive/GC/LTO proof
suite remains the next isolated slice.

## 2026-07-15: Activate The Frozen Eight-Function Forward ABI

Common runtime now calls exactly the eight operations declared by
`fiber_port_runtime_abi.h`. The displaced startup, scheduler-bridge, exception,
frame-validation, and handler declarations remain selected-port-private.
`fiber_port_scheduler_set_pick_next()` was removed: the selected port validates
the CPU environment, then common runtime performs the hook/user lifecycle store.

The active `fiber_start()` order is now the frozen order:

```text
common K/k lifecycle checks
selected-port startup preparation
port-protected first scheduler selection
common current-context publication
selected-port first-context validation and SVC transfer
```

Therefore `K/k` deliberately precede CPU-environment panic codes, and the first
context is published before the selected port performs its final first-restore
validation. Panic remains terminal, so a failed first start cannot resume with a
partially started runtime.

`fiber_schedule()` is a single common-to-port call. Each port implements the
complete `IPSR -> current -> PRIMASK -> BASEPRI -> FAULTMASK -> request` path in
one function, preserving existing failure order without adding a hot-path
adapter call. SVC/PendSV assembly, frame layout, scheduler critical sections,
and vector ownership are unchanged.

This checkpoint changes startup choreography and panic precedence. Compile/link
proofs do not renew the STM32H7 runtime claim; the normal, FPU, startup, and trap
suite must pass on hardware again.

## 2026-07-15: Stage Final Forward ABI Adapters Without Activating Them

CM0, CM3, CM4, CM7/r0p1, and the transitional v8-M fixture now define the five
new operations that complete the final eight-function forward ABI:

```text
fiber_port_require_scheduler_configuration_environment
fiber_port_runtime_prepare_start
fiber_port_runtime_select_first
fiber_port_runtime_start_first
fiber_port_runtime_schedule
```

Each is a thin composition of the existing validated environment, startup,
scheduler bridge, restore, and request helpers. `fiber_core.c` does not call
these adapters in this checkpoint. Therefore startup ordering, current-context
publication, SVC/PendSV assembly, panic precedence, and context layout remain
unchanged. The H7 linker removes the unreferenced adapter sections.

Every current port also owns a `fiber_port_private.h` containing its cross-file
save/restore, startup-MSP, scheduler-bridge, exception, and handler
declarations. Those declarations were removed from `fiber_portmacro.h` and
boot-record headers. The generic runtime ABI remains wider only because common
runtime still uses its transitional calls; narrowing and activation occur in a
separate behavior-changing checkpoint.

The compile matrix requires exactly one global definition of every adapter,
checks adapter composition and call order, proves that common runtime does not
reference them yet, and rejects leakage of private declarations back into
portmacro or boot headers.

## 2026-07-14: Close Pre-Porting ABI And Profile Gaps

A second contract audit against local FreeRTOS commit `a50edad` covered every
GCC Cortex-M source group: CM0 with and without MPU, CM3/CM3_MPU, CM4F,
CM4_MPU, CM7/r0p1, CM23/33/35P/52/55/85, all matching NTZ groups, SecureContext
companions, TF-M integration, MVE/PAC/BTI conditionals, and the single-core/SMP
split. No ninth mandatory common-to-port operation is required for the frozen
single-core static-lifetime cooperative scope.

The frozen `fiber_internal_runtime_port_abi_v1_anchor` target versions the whole
mandatory bidirectional runtime contract, not only reverse calls. Any
incompatible change to one of the eight forward functions, a reverse v1 symbol,
calling convention, required attribute, or normative semantic creates a new
anchor spelling. Both old-common/new-port and new-common/old-port mismatch links
are required negative tests. Context layout has its own independent versioned
relocation and mismatch proof.

When handlers are a separate archive object, the handler-bundle anchor also
versions that port-internal mandatory-object/handler-object pairing while still
remaining independent of common ABI versioning. A handler object that calls the
reverse ABI retains its own runtime-anchor relocation. Stale bundle combinations
and handler/common ABI mismatches are required negative links.

Current-context access, start, schedule, SVC, PendSV, scheduler-hook, and
reverse-helper call paths are compiler-sensitive. Their normative attributes
prevent instrumentation, profiling, sanitizers, stack protectors, implicit
FP/MVE use, and hidden LTO helpers in addition to enforcing the
general-registers-only ABI. Adversarial
generated-code checks are required; the scheduler hook's complete indirect call
graph remains an application integration obligation.

Architecture-class selection is not exact port identity. Production MPU,
unprivileged, Secure-only, Non-secure, TrustZone, NTZ, TF-M, MVE, PAC, and BTI
profiles require build-selected mode plus an exact manifest of selected header,
source group, compiler/toolchain identity and version, CPU/FPU/ABI flags,
feature/errata policy, context identity, and companion artifacts.
Auto/profile/force selection remains a convenience or bring-up path and cannot
create those production claims.

The final source layout follows concrete FreeRTOS profile directories. CM0+MPU
and M7+MPU are explicit roadmap profiles; the latter derives its parity baseline
from `ARM_CM4_MPU`, which contains Cortex-M7 r0p0/r0p1 CPUID checks and errata
837070 policy. CM35P, CM52, and CM85 remain reference-portability rows rather
than STM32 hardware claims. Generic `armv8m_*` directories are not the final
production layout. Initial production compiler scope is GNU Arm Embedded GCC;
other compilers need separate compiler-port evidence.

The exact profile/context relocation is also the selected-port object-cohort
guard. One always-linked mandatory port identity object defines it; every other
mandatory port object and one build-owned expectation object retain it. This
rejects stale private-object mixtures that the common runtime ABI anchor cannot
detect. The local FreeRTOS CMake graph also confirms that CM33/CM52/CM55/CM85
`_NTZ` CPU sources are reused by distinct non-TrustZone and TF-M profiles, so
shared source files never imply one profile identity.

The v8-M source directory is not the security role. Secure-only, Non-secure
with a fiber-owned SecureContext companion, Non-secure without that companion,
NTZ Non-secure, and TF-M are distinct exact manifests even when they reuse CPU
sources. MPU profiles also prove that unprivileged public calls cannot access
privileged state directly: yield and task return use distinct validated SVC
services, writable stacks are isolated from writable context/runtime state, and
an unprivileged entry return reaches the common task-return sink only through a
port-owned veneer.

This decision changes documentation and freeze requirements only. Runtime code,
assembly, and current support labels are unchanged.

## 2026-07-14: Freeze Reverse Port-to-Common ABI v1 Target

The mandatory reverse port-to-common boundary is frozen as the implementation
target for `common-core-freeze-v1`. One common-owned internal header,
`fiber_runtime_port_abi.h`, exposes only:

```text
fiber_internal_runtime_port_abi_v1_anchor
fiber_internal_runtime_current_context_slot
fiber_internal_runtime_select_scheduler_candidate
fiber_internal_runtime_publish_current_context
fiber_internal_runtime_require_current_context
fiber_internal_task_return
fiber_panic
```

The current-context slot is not declared as a C object to selected ports.
Selected inline assembly or `.S` code may load it through its frozen symbol
name, but port C may not redeclare it, take its address, or write it. Hook/user
storage, first-selection state, and all other lifecycle globals remain
common-private. The candidate-selection helper owns hook/lifecycle/NULL policy
while the port owns the CPU critical envelope and context validation. Only the
common-owned publication helper writes a validated candidate to the slot.

`fiber_internal_task_return()` is the common no-return sink, not necessarily
the literal LR seeded by every profile. Privileged profiles may seed it
directly. Unprivileged profiles seed a port-owned return-SVC veneer whose
validated Handler-mode dispatch invokes the common sink.

Port calls to `fiber_panic()` are strong references. The common fallback
definition remains weak for one application override, so omitting every panic
implementation is a link failure rather than a nullable weak call.

The v1 anchor is a required retained relocation from an object implementing a
mandatory ABI function referenced by common runtime. Its version covers the
complete mandatory bidirectional ABI even though common owns the anchor symbol.
It is independent of handler extraction. If strong handlers live in another
archive member, that object defines `fiber_port_handler_bundle_v1_anchor`, and
the always-linked mandatory object retains a strong relocation to it. Direct
references to generic handler names are not accepted as extraction proof when
startup weak aliases exist.

Exact undefined-symbol allowlists, a deliberate version-mismatch negative link,
current-slot C-access and generated-assembly store rejection, handler archive
extraction, section garbage collection, and LTO are required freeze proofs.
Address-map and fallback-MSP hooks are port/application integration ABI, not
reverse common ABI. TrustZone gateway symbols are a separately versioned
cross-image ABI.

## 2026-07-14: Keep Feature Extensions Outside the Mandatory Runtime ABI

The five-function `fiber_core.h` API and eight-function common-to-port runtime
ABI are sufficient for the CPU engine and remain the mandatory minimum for
every selected port.

MPU/unprivileged configuration, FreeRTOS-style SecureContext management, and
TF-M integration use separate selected-port extension headers and sources.
They are not included by `fiber_core.h` or `fiber_port_runtime_abi.h`, common
runtime code does not reference them, and unsupported ports provide no silent
stubs. These extension headers are profile-integration-facing by default, not a
second portable application API. Code that includes one intentionally accepts a
selected-port-specific dependency and belongs outside portable upper logic.

Every production profile supplies a safe complete default policy. Identical
application source that includes only `fiber_core.h` and calls only its five
functions must compile and link unchanged for privileged, MPU, SecureContext,
NTZ, and TF-M profiles without feature-specific pre-start calls. The build and
selected port automatically bind all CPU mechanics and required companions for
that default. Build-owned board, linker, Secure-image, or TF-M configuration may
complete the policy, but portable application source does not call it and the
default must not weaken the selected profile's declared isolation. A separate
matrix fixture proves this profile portability.

When fibers require heterogeneous MPU, privilege, or SecureContext policy, a
profile integration module may configure them through the optional extension
before scheduler publication. Common runtime cannot infer that intent. Such
configuration is deliberately non-portable and must not leak into the portable
application tier.

This decision abstracts execution mechanics, not external service semantics.
Direct PSA, TF-M, Secure gateway, or MPU-profile-only service calls remain
intentional platform dependencies. Portable business logic places such
operations behind its own service interface; selected-port extension ABIs are
not general application service APIs.

Context-mutating extensions reach common lifecycle through a separate optional
`fiber_runtime_context_configuration_abi.h` v1 and
`fiber_runtime_context_configuration.c`, not through the mandatory reverse ABI.
Its exact service is
`fiber_internal_runtime_require_context_configuration_open()` with a versioned
link anchor. Ports without such an extension do not include or build this
module.

The common lifecycle marker closes the configuration window immediately after
the existing `fiber_start()` scheduler/current checks and before selected-port
preparation. It never reopens. This preserves `'K'` then `'k'` panic precedence
while making a context-mutating extension fail closed as soon as startup begins.
The marker itself is common-private state, not a selected-port extension symbol;
the optional ABI source remains absent unless a feature source retains its v1
anchor.

MPU extensions configure same-image region, privilege, system-call-stack, and
initial CONTROL/frame policy. TrustZone SecureContext support additionally uses
a separately versioned cross-image gateway ABI and compatibility proof. TF-M
uses an NTZ-style Non-secure CPU port plus TF-M initialization and veneers; it
does not also compile the fiber-owned SecureContext companion.

The static-lifetime common lifecycle gains no destroy function. Dynamic context
or SecureContext deletion, if ever required, is a separate optional lifecycle
extension. Every enabled extension participates in context feature/layout
identity and must fail closed on header/object or cross-image mismatch.

A static-lifetime SecureContext profile binds or allocates its Secure storage
once during privileged pre-start configuration. Its companion may use a fixed
pool, application-provided Secure storage, or an explicitly selected allocator;
the mandatory fiber runtime does not require a heap.

The mandatory reverse ABI is fixed by the preceding decision. It does not
expand the eight-function common-to-port ABI or any optional feature ABI.

## 2026-07-14: Define CPU-Neutral Runtime Port Boundary

The final common-runtime to selected-port contract is frozen in
`V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md` before its mechanical implementation.
This is a documentation-only checkpoint; the current wider ABI and application
handler wrappers remain transitional code.

The stable public API remains the existing five functions. The final generic
common-to-port ABI contains exactly eight CPU-neutral operations:

```text
fiber_port_context_init
fiber_port_runtime_memory_barrier
fiber_port_panic_wait
fiber_port_require_scheduler_configuration_environment
fiber_port_runtime_prepare_start
fiber_port_runtime_select_first
fiber_port_runtime_start_first
fiber_port_runtime_schedule
```

Common runtime owns scheduler hook/user storage, current-context storage and
publication, scheduler lifecycle, policy invocation, NULL-result semantics, and
public panic precedence. Selected ports own context layout, save/restore,
critical envelopes, startup MSP state, exception mechanics, vector validation,
FPU/MPU/security policy, and architecture errata. Common-owned scheduler globals
will lose the misleading `port` component during a mechanical rename.

The normative `fiber_start()` order is:

```text
common lifecycle validation
port start preparation
port-protected first scheduler selection
common current-context publication
port SVC first start
```

Consequently, `'K'` and `'k'` precede CPU-environment panic codes. This is an
intentional public failure-order decision and requires trap coverage.

Each selected port will exclusively provide strong `SVC_Handler` and
`PendSV_Handler` symbols. Application/CubeMX competing strong handlers are
configuration errors, wrappers are removed, and wrapper/direct-vector settings
are deleted after the migration. Runtime vector-table patching is not part of
the default contract.

Compile, synthetic-link/ELF, and board proofs are separate. The linker proves
strong symbol exclusivity, archive extraction, vector relocations,
`--gc-sections` retention, and LTO retention. Board validation proves active
selected-port vector-source routing and actual SVC/PendSV execution after
startup or bootloader relocation. H7 validation specifically reads back
`SCB->VTOR`.

Implementation proceeds in isolated slices: narrow the ABI while adding private
port headers for every displaced declaration, rename common state, collapse
start/schedule choreography, move strong handlers, remove wrappers and mode
macros, expand matrix proofs, then rerun the full H7 hardware suite.

## 2026-07-13: Restore Integrity and Common Runtime Safety Baseline

The common runtime and selected ports now use the following non-negotiable
integrity boundary before additional Cortex-M ports are implemented:

- Common runtime C objects compile without CMSIS or selected context layout.
  Selected ports provide the CPU barrier and terminal panic-wait ABI, so the
  weak `fiber_panic()` fallback no longer depends on application `Error_Handler`.
- `fiber_start()` does not repair a nonzero BASEPRI or FAULTMASK value. Start
  preconditions fail closed; silently clearing an inherited critical section
  would violate the caller's interrupt contract.
- Startup MSP ownership is one runtime-wide selected-port plan built after
  start preconditions, never a stale field copied into every `FiberContext`.
- `fiber_init()` always validates context storage, PSP stack range, and entry
  code with integration address-map hooks before initializing memory. Before a
  restore validator reads a context or saved frame, it always checks pointer
  non-NULL, alignment, and extent. `FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1`
  additionally checks context/stack map plausibility before dereference and the
  dynamic stacked PC before exception return; the default `0` omits only these
  hot-path hooks. The Thread-mode request checks only current ownership and
  CPU mask preconditions, then publishes PendSV. Inside PendSV, before its
  first current-context field read, the selected port validates the current
  context seal, low-stack canary, and live PSP so assembly never reads
  unverified current metadata. When optional integration address-map hooks are
  enabled, the authoritative preflight snapshots and rechecks CPU mask/CONTROL
  state around them; the default map-off path omits those snapshots. It seals
  and fast-checks selected port
  identity, layout version, context size/alignment, feature mask, and initial
  EXC_RETURN. The default rehashes immutable boot metadata on every restore.
- Saved frame validation always proves the exact EXC_RETURN, stack bounds, xPSR
  state, and Thumb PC form before exception return. Full code-address-map
  plausibility is additionally checked when
  `FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1`.
- RAM/code plausibility hooks, scheduler bridges, and panic operations reachable
  from PendSV use the selected general-registers-only ABI. The safe default
  requires integration-defined address-map hooks during initialization; the
  permissive weak fallback is an explicit bring-up opt-out. When switch-time
  map validation is enabled, integration overrides must not execute FP/MVE,
  block, or alter selected CPU mask/CONTROL state.
- The compile matrix statically proves that every selected PendSV path invokes
  `fiber_port_context_validate_save_current()` before its first current stack
  metadata load, that no current-context field is accessed before that call,
  and that the untrusted `r1` pointer is used only for its null check,
  preservation across the C call, and transfer to the validator argument,
  and that map-enabled save/restore preflights retain their canary and CPU-state
  guard ordering. Rare MSP fallback hooks have their own local CPU-state guard.
- Startup MSP-plan validation remains on every restore. A per-context cached
  result would add port-private mutable ABI state, so it is intentionally
  deferred rather than silently weakening the first-restore safety invariant.
- Automatic local fiber stacks and the unused heap-only stack helper were
  removed. A context and its PSP stack require persistent application storage.

The H7 harness now includes a linker-backed saved-PC-address trap mode. H7
normal and complete trap validation must be rerun after this behavior-affecting
checkpoint before recording a current runtime-support claim.

## 2026-07-13: Complete Opaque Common Runtime Boundary

The current v2 source groups now implement the intended three-layer boundary:

```text
public API and selected storage type
    fiber_core.h + fiber_port_selected.h

common runtime callable ABI
    fiber_port_runtime_abi.h

selected complete CPU contract
    concrete fiber_portmacro.h and selected port sources
```

- `fiber_port_selected.h` is type-only. It completes `FiberContext` for
  application allocation but does not expose CMSIS, CPU traits, frame geometry,
  or selected-port register helpers to common runtime translation units.
- `fiber_core.c` and `fiber_runtime_state.c` use opaque `FiberContext *`
  pointers and the callable port runtime ABI. They do not dereference, size, or
  align the selected context and do not read CPU special registers.
- Common runtime owns hook lifecycle, first-selection lifecycle, hook
  invocation, and publication of the current context. The selected port owns
  the callback CPU-state snapshot, scheduler critical-section mechanics, and
  restore validation around each selected context.
- `fiber_port_geometry.h` is selected-port implementation data. It derives
  stack/frame constants from selected traits and is not a public core include.
- The public API remains exactly `fiber_init()`, `fiber_current()`,
  `fiber_scheduler_set_pick_next()`, `fiber_start()`, and `fiber_schedule()`.
  `fiber_yield()`, sleep, wake, timing, and task-state names describe a future
  application scheduler layer; they are not current fiber exports.

This is a source-boundary refactor. It does not widen hardware support claims;
the H7 runtime validation checklist must be rerun after the behavior-preserving
port-wrapper move.

## 2026-07-13: Normalize Concrete Classic Cortex-M Port Groups

The compile-covered classic ports now use the same selected-port source-group
shape as the concrete Cortex-M7 port:

```text
fiber/port/ARM_CM0/
fiber/port/ARM_CM3/
fiber/port/ARM_CM4/
fiber/port/ARM_CM7/r0p1/
```

- Each group owns `fiber_portmacro.h`, `fiber_port_types.h`,
  `fiber_port_boot_types.h`, `fiber_port_boot.h`, `fiber_port_boot.c`,
  `fiber_port.c`, `fiber_port_exception.c`, and `FREERTOS_PARITY.md`.
- `fiber_portmacro.h` is the selected CPU contract. It owns the CPU dictionary,
  feature traits, inline helpers, and callable port ABI declarations. Do not
  add an intermediate selected-port facade such as `fiber_port.h`.
- `FIBER_PORT_ARMV6M`, `FIBER_PORT_ARMV7M`, and `FIBER_PORT_ARMV7EM` remain
  selector facts only. They do not identify a source group: selection maps them
  to ARM_CM0, ARM_CM3, ARM_CM4, or ARM_CM7/r0p1 as appropriate.
- `fiber/port/transitional_v8m` remains an explicit compile-only bring-up
  fixture. It is not a common implementation layer or a production support
  claim for Cortex-M23, Cortex-M33, Cortex-M55, TrustZone, MVE, PAC, or BTI.
  It must be deleted once concrete v8-M Baseline, v8-M Mainline, and ARMv8.1-M
  source groups replace its compile-matrix coverage.
- The per-port parity records name the corresponding local FreeRTOS reference
  files and identify deliberately excluded scheduler, tick, MPU, and queue
  behavior.

This is a source-boundary and naming normalization. It does not intentionally
change PendSV, SVC, context-frame, or scheduler behavior. Hardware validation
status remains unchanged.

## 2026-07-13: Move Boot Records into Selected Ports

The opaque selected-port context boundary is now implemented for the current
source groups.

- Each selected port owns `fiber_port_boot_types.h`, `fiber_port_boot.h`, and
  `fiber_port_boot.c`. `FiberPortBoot` and `FiberPortMspPolicy_t` are local
  port types; the former root boot and metadata layers are removed.
- Each selected port owns boot-record construction, structural checks, hash
  computation, canary handling, stack geometry, first-start MSP preparation,
  CPU startup preparation, and restore validation. A future port may use a
  different boot layout or a hardware integrity engine without changing the
  common runtime.
- `fiber_core.c` and `fiber_runtime_state.c` operate on `FiberContext *` only.
  They do not dereference context or boot-record fields, and call the selected
  ABI for initialization, validation, start environment checks, runtime
  preparation, and first-context preparation.
- The current physical layout remains ABI-compatible with the historical
  `sp + boot-record` shape, but no common boot-record alias is exported. Each selected
  port exposes only its own `FiberPortBoot` record; it is not a common or
  cross-port record contract.
- The compile matrix requires exactly one selected definition for the full boot
  ABI, including construction, fast/full integrity checks, first-start MSP
  preparation, runtime preparation, and context validation.

This is a behavior-preserving ownership move by intent. Its H7 runtime claim is
pending the normal and trap validation rerun because boot and first-start code
now compile from the concrete port source group.

This decision supersedes the temporary root metadata ownership described by the
following historical entries.

## Historical 2026-07-13: Split Selected-Port Context Type Layer

This was the first mechanical opaque-context migration phase. Its temporary
root metadata layer was superseded by the selected-port boot ownership decision
above without changing context-switch, SVC, PendSV, scheduler, or startup
behavior.

- `fiber_api_types.h` now owns only CPU-neutral forward declarations and public
  callback types. `FiberEntryFn` is the named entry type; `entry_t` remains its
  source-compatible alias.
- The temporary root metadata header owned the previous common boot-record
  definition. Its per-context MSP fields and exact contents remained transitional.
- `fiber_port_selected.h` is the only global selector. It includes exactly one
  `fiber_portmacro.h`, and that selected portmacro includes its local public
  type-only `fiber_port_types.h`.
- Each current layout intentionally remains ABI-identical to the former
  `sp + boot-record` definition. `fiber_types.h` is now a compatibility facade,
  not the owner of that layout.
- Inactive port source files can compile beside the selected port in the matrix
  without re-defining `FiberContext`; their local type header is included only
  when that port is active.

The compile matrix builds each selected port type header without a generated
device header or CMSIS include path and asserts the transitional layout for
every profile. The forced STM32H7 Debug build remains
`text=10656`, `data=12`, and `bss=8000`.

This is not the final opaque common-core boundary: common `.c` files still
include `fiber_port_selected.h` and access the transitional layout. The next
mechanical phase introduces selected internal ABI token types and a callable
port ABI before common field access can move into selected ports.

## 2026-07-13: Move Privileged Schedule Requests Behind Selected Ports

`fiber_schedule()` remains the public cooperative trigger, but it no longer
reads CPU special registers or writes PendSV state itself. It invokes the
selected-port ABI in two steps:

- `fiber_port_require_schedule_environment()` validates the port-owned
  Thread-mode and interrupt-mask rules;
- `fiber_port_request_schedule()` performs the selected request mechanism.

At that checkpoint, the common runtime retained current-context lifecycle
ownership through `fiber_internal_require_schedule_current()`. The frozen
reverse ABI later replaced that helper with
`fiber_internal_runtime_require_current_context()` without changing the CM7
failure order `i -> G -> p -> b -> f -> PENDSVSET`.

The compile matrix now proves exactly one definition of both selected-port ABI
symbols and rejects CPU-specific access in the body of `fiber_schedule()`.
This is a source-boundary and generated-assembly checkpoint, not a renewed H7
hardware-runtime claim; normal and trap validation must be repeated on board.

## Historical 2026-07-13: Close Opaque-Port Portability Gaps

A contract-level source audit against local FreeRTOS commit `a50edad`, covering
classic, MPU, v8-M, NTZ, TF-M, and MVE/PAC port groups, confirms that the
selected-port-owned opaque context can represent every STM32-relevant Cortex-M
profile without adding CPU layout to the common core. This does not replace the
required line-by-line parity ledger for each implemented port.

This historical contract refinement preceded the selected-port boot move:

- `fiber_context_metadata_types.h` is the public type-only metadata layer;
  `internal/fiber_context_metadata.h` contains helper declarations;
- `fiber_port_context_init()` owns context alignment, extent-overflow, and
  context/stack overlap checks and performs them before its first write;
- `fiber_pendsv_init_lowest_priority()` is explicitly transitional diagnostic
  surface, not a sixth frozen public API function;
- `fiber_port_request_schedule()` is mechanism-neutral: privileged ports may
  pend PendSV directly, while unprivileged MPU ports must enter a validated
  port-owned SVC that pends PendSV from Handler mode;
- the existing CM7 Thread-mode register checks and direct PendSV publication
  now live behind the selected-port environment/request boundary; remaining
  common-runtime CPU access moves with the opaque-context transition;
- common scheduling code does not read CPU mask registers. Privileged ports
  validate them before direct PendSV publication; unprivileged ports validate
  safely observable state before SVC and the real mask state in Handler mode;
- every unprivileged restore guarantees zero PRIMASK and, where implemented,
  zero BASEPRI and FAULTMASK;
- selected-port configuration calls a common-owned lifecycle guard and never
  reads common scheduler/current globals directly;
- MPU ports must protect common runtime and context state from unprivileged
  writes and own CONTROL, PSPLIM, MPU, secure-context, PAC, and FP/MVE storage;
- Secure and TF-M integration is a matched companion component/artifact, not an
  additional cooperative scheduler port. It may live in a separate Secure
  target or be supplied by TF-M and never defines a second callable fiber runtime
  ABI in the same runtime image;
- separate Secure images expose a versioned gateway/service ABI and require a
  manifest or startup compatibility check because normal link relocations cannot
  validate two firmware images;
- every target tree includes the public type-only
  `fiber_context_metadata_types.h` layer;
- every configuration that changes context layout or saved-state meaning gets
  a distinct ABI identity and validation record.

This remains a documentation-only refinement. It proves that the architecture
can host the relevant FreeRTOS port families; it does not claim those ports are
implemented or hardware-validated.

## Historical 2026-07-13: Define Opaque Selected-Port Context ABI

Before production ports are added in bulk, the common runtime was planned to
move to the opaque selected-port context boundary defined in
`V2_OPAQUE_CONTEXT_CONTRACT.md`:

- the public API remains limited to `fiber_init()`, `fiber_current()`,
  `fiber_scheduler_set_pick_next()`, `fiber_start()`, and `fiber_schedule()`;
- application code receives the complete selected `FiberContext` type for
  static allocation but must treat all fields as private;
- common translation units see only `typedef struct FiberContext FiberContext`
  and must not dereference, size, align, or inspect the context;
- the selected port owns the complete context layout, construction, immutable
  port seal, dynamic restore validation, startup state, and SVC/PendSV transfer;
- common code owns scheduler semantics, callback storage, recursion and
  hot-swap policy, NULL handling, and current-context publication;
- CPU-neutral immutable metadata may be shared, but it is not a substitute for
  the selected port's final integrity seal;
- live saved-stack-pointer and FP/MVE state are validated dynamically and are
  not placed in an immutable hash by default;
- initial MSP rewind or validation is one port-runtime startup policy, not a
  permanent field required in every fiber context;
- selected internal type-only headers complete scheduler CPU-state tokens that
  common code may allocate and pass without inspecting;
- each context layout carries port identity, layout version, size, alignment,
  and feature identity, with a real link-time mismatch guard required before
  precompiled library objects are supported.

The first structural move must preserve the current scheduler critical-section
placement, frame layout, panic codes, assembly behavior, and temporary
per-context MSP behavior. Cleanup and ownership changes that affect behavior
remain separate commits with separate hardware validation.

This is a documentation-only decision. The current source still used the
transitional shared context/boot-record layout, and no runtime support
claim changes at this checkpoint. This decision supersedes older architectural
statements that require one common-known context or boot-record layout for all
ports.

## 2026-07-12: Close Startup and Scheduler-Hook State Gaps

The runtime now fails closed around startup side effects and the user scheduler
callback:

- `fiber_start()` validates privileged Thread mode on MSP before any SCB/NVIC
  priority write;
- every port exception initializer independently enforces privileged Thread/MSP
  preconditions, so a direct internal call cannot bypass the common check;
- the concrete `ARM_CM7/r0p1` port always owns and enables errata 837070
  handling. The old `FIBER_CORTEX_M7_R0P1_ERRATA_837070` integration switch is
  a compile error;
- existing CFSR/HFSR/DFSR evidence is preserved by default. Clearing it is an
  explicit `FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START=1` application policy;
- enabling available configurable faults remains the explicit conservative
  default through `FIBER_ENABLE_CONFIGURABLE_FAULTS=1`;
- scheduler callbacks must preserve `PRIMASK`, `FAULTMASK`, `BASEPRI`, and
  `CONTROL`. The runtime snapshots and validates those registers around both
  first selection and PendSV selection;
- the H7 harness has separate first/next mask-mutation trap modes;
- the compile matrix now runs a complete Cortex-M7F eight-priority-bit build,
  relocatable link, and six-symbol selected-port ABI audit.

The settings-only matrix passes. These runtime changes still require a fresh H7
normal run and all documented trap modes before restoring the hardware claim.

## 2026-07-12: Canonicalize Port Policy and Exact Stack Geometry

The selected-port contract is now the single source of CPU facts across every
compile-covered profile:

- common runtime code consumes only `FIBER_PORT_*` traits;
- `FIBER_PORT_TRAITS_LEGACY_BRIDGE`, old `FIBER_HAS_*` aliases, and
  `FIBER_USE_PSPLIM_REGISTER` are compile errors;
- CPACR setup, FPCA cleanup, EXC_RETURN, stack alignment, vector-bank choice,
  canary encoding, PendSV publication, and context-boundary DSB/ISB barriers
  are mandatory port/runtime behavior rather than application tuning;
- FPU context support requires agreement between compiler FP generation and
  CMSIS silicon capability. The library does not synthesize `__FPU_USED` and
  has no force-save override;
- the initial synthetic frame is built directly down from `stack_top`. After
  SVC restore, PSP equals `stack_top`, so the old independent top guard is
  unnecessary;
- minimum usable stack is exactly the selected port's maximum saved context,
  including high FP registers and the architectural alignment word. CM7F uses
  208 bytes, or 240 bytes including the default low red zone;
- initial context bytes, high-FP software bytes, exception alignment padding,
  maximum saved-context bytes, and saved-SP alignment are explicit mandatory
  selected-port traits rather than common Cortex-M assumptions;
- global UNALIGN_TRP and DIV_0_TRP choices moved to
  `fiber_platform_policy.h` because they affect the complete application;
- obsolete settings fail explicitly instead of being ignored;
- the compile matrix now contains negative probes for every remaining boolean,
  every removed setting/alias, vector mode, SVC immediate, red-zone alignment,
  and BASEPRI priority encoding.

The full compile/link matrix and STM32H7 Debug build pass. This changes initial
PSP geometry and therefore requires a fresh H7 normal/trap hardware run before
the current code can inherit an old runtime-validation claim.

## 2026-07-12: Make CM7 Settings and Saved Frames Fail-Closed (Superseded)

The top-guard and configurable-reserve decisions in this entry were superseded
later on the same date by exact stack geometry and canonical port ownership.

A second line-by-line comparison against local FreeRTOS commit `a50edad`
tightened the concrete `ARM_CM7/r0p1` contract without changing its
`r4-r11`/`EXC_RETURN`/FP save and restore order:

- CPU facts are selected-port-owned. The CM7 initial `EXC_RETURN`, security
  domain, FPCA policy, FPU presence, and saved-frame layout cannot be changed
  into another architecture by application settings;
- optional startup-validation switches were removed from the production CM7
  contract. Vector routing, priority readback, implemented-priority probing,
  PRIGROUP compatibility, CPUID, and errata checks are mandatory;
- `fiber_start()` validates privileged Thread/MSP and mask state before
  configuring PendSV/SVCall priorities, matching FreeRTOS scheduler-start
  ownership without allowing an uncontrolled privileged-register fault;
- the default scheduler `BASEPRI` accounts for the unavoidable subpriority bit
  when all eight NVIC priority bits are implemented. Compile-time and runtime
  checks reject incompatible thresholds;
- suspended contexts require an exact selected-port `EXC_RETURN`, complete
  software/hardware/FP frame bounds, valid `xPSR.T`, Thread-mode stacked IPSR,
  an even stacked PC, and any `xPSR.STACKALIGN` word;
- this superseded checkpoint still used a separate hardware-frame top guard.
  The current contract removes that guard and derives the minimum directly from
  the selected port's exact maximum saved context plus the low red zone;
- `FIBER_EXC_LEVELS_ON_PSP` and `FIBER_BOOT_EXTRA_BYTES` were removed. Nested
  handlers use MSP, and applications choose an actual stack size above the
  architectural minimum for their own call depth and local objects;
- boot-record, canary, scheduler bridge, and panic helpers reachable from
  PendSV use the general-registers-only compiler contract;
- the compile matrix includes expected-failure probes for invalid settings and
  a positive eight-priority-bit default probe.

These changes invalidate the active H7 hardware claim until `NORMAL_RUN` and
all documented trap modes, including the saved-xPSR/PC/alignment modes, pass on
the board. Compile and link coverage is not a substitute for that run.

## 2026-07-12: Make Port ABI and Restore Validation Non-Optional

The paranoid FreeRTOS comparison found several cases where object-only compile
coverage could pass while the selected runtime port was incomplete or safety
checks could be compiled away. The v2 contract is tightened as follows:

- Cortex-M4/M4F selects the generic `armv7em` implementation; Cortex-M7 selects
  the concrete `ARM_CM7/r0p1` implementation. They no longer share an
  ambiguous source guard.
- the STM32H7 embedding build includes the concrete CM7 source group and
  excludes all non-selected port source directories;
- `tools/compile_matrix.ps1` performs a relocatable link for every mode and
  uses `nm` to require exactly one definition of each mandatory port ABI
  symbol. Compiling unrelated source objects is no longer considered proof of
  a complete selected port;
- restore-context and current-context ownership checks are mandatory.
  `FIBER_VALIDATE_SCHEDULED_CONTEXT` and `FIBER_VALIDATE_CURRENT` are obsolete
  and now produce compile errors if defined;
- every just-saved current context and every selected restore target is checked
  before the scheduler bridge permits restore;
- saved `EXC_RETURN` accepts only the exact basic/extended encodings exported
  by the selected port. Broad signature or Thread/PSP-bit checks are not enough;
- the low-stack canary is written and checked even when PSPLIM is available, so
  the two mechanisms remain independent defenses;
- the fast boot-record path checks pointer ordering, stack alignment, available
  size, entry state, and MSP policy before canary or saved-frame dereferences;
- PendSV verifies that the complete live hardware exception frame, including
  an extended FP frame when active, remains below the declared `stack_top`;
- FPU enable policy now validates CPACR and FPCCR readback instead of merely
  reading and discarding those registers;
- transitional v8-M unsupported-feature gates run regardless of optional
  exception wiring diagnostics. Disabling diagnostics cannot turn an
  unvalidated profile into runtime support;
- the first scheduler call happens after common FPU/platform bootstrap. Every
  scheduler hook must use `FIBER_SCHEDULER_HOOK_ATTR` and must not execute FP or
  MVE instructions, because later calls execute in PendSV.

These changes affect runtime validation behavior. The previous H7 record stays
historical until normal mode and all trap modes, including canary, exact
`EXC_RETURN`, and short-frame traps, pass on the board again.

The heuristic device-header selection in the embedding `mcu_core.h` is outside
this checkpoint and is intentionally unchanged.

## 2026-07-12: Remove target Directory

The `fiber/target` source directory was removed.

The remaining target-level files moved out of `fiber/target`:

```text
fiber/target/fiber_panic.c    -> fiber/fiber_panic.c
fiber/target/fiber_panic.h    -> fiber/fiber_panic.h
fiber/target/fiber_settings.h -> fiber/port/fiber_settings.h
```

`fiber_panic` is a runtime-level fallback hook, not CPU-port policy.
`fiber_settings.h` is now a port-root configuration header because selected
ports consume those defaults while exporting the CPU contract.

## Historical 2026-07-12: Remove fiber_target.h Facade

This entry records the intermediate facade that replaced `fiber_target.h`.
Its complete-contract include behavior was superseded by the 2026-07-13 opaque
common-runtime boundary: `fiber_port_selected.h` is now public and type-only,
while common runtime uses the CPU-neutral callable ABI.

`fiber/target/fiber_target.h` was removed. The selected-port facade is now:

```text
fiber/port/fiber_port_selected.h
```

Public runtime headers include `port/fiber_port_selected.h` directly. The
selected port provides the CPU contract through its `fiber_portmacro.h`; the
facade then applies common post-port checks, stack alignment helpers,
exception-frame headroom constants, and feature-policy gates.

Important ownership rule:

```text
selected port owns CPU facts and low-level mechanics;
fiber_port_selected.h validates and exports the selected contract;
fiber_target.h must not be recreated as a CPU-policy layer.
```

`FIBER_SVC_START_NUMBER` is also port-owned now. Each selected
`fiber_portmacro.h` provides the default and checks that the value fits the
8-bit SVC immediate field.

## 2026-07-12: Move Exception Setup Into Selected Ports

PendSV/SVC exception setup is no longer owned by `fiber/target/fiber_irq.c`
and `fiber/target/fiber_irq.h`. It is also no longer a shared root
`fiber/port/fiber_port_exception.*` implementation.

Each concrete port source group now owns its exception setup file:

```text
fiber/port/ARM_CM0/fiber_port_exception.c
fiber/port/ARM_CM3/fiber_port_exception.c
fiber/port/ARM_CM4/fiber_port_exception.c
fiber/port/transitional_v8m/fiber_port_exception.c
fiber/port/ARM_CM7/r0p1/fiber_port_exception.c
```

The selected-port exception setup owns:

- PendSV priority programming and read-back validation;
- SVCall priority programming and read-back validation;
- direct/wrapper vector routing validation for SVC and PendSV;
- pending PendSV cleanup before first start;
- implemented NVIC priority-bit probing;
- scheduler BASEPRI threshold validation;
- AIRCR.PRIGROUP validation for BASEPRI ports;
- Cortex-M7 r0p0/r0p1 errata policy validation.

The public API names remain stable for now:

```c
void fiber_pendsv_init_lowest_priority(void);
void fiber_exception_runtime_check(void);
```

This is an ownership move, not a behavior change. The implementation consumes
selected-port traits and helpers, including `fiber_port_vectors_base_ptr()` and
`FIBER_PORT_SCHEDULER_BASEPRI`.

`fiber_port_exception.c` includes the selector guard first, then consumes the
selected CPU/platform contract through `fiber_portmacro.h`. It must not include
`fiber_target.h`, `fiber_compiler.h`, `fiber_panic.h`, FPU/PSPLIM/VTOR helpers,
or unvalidated feature-policy headers directly. If exception setup needs a CPU
fact, validation knob, compiler helper, CMSIS view, or diagnostic contract, the
selected port must expose it from `fiber_portmacro.h`.

## 2026-07-12: Move VTOR/Vector Policy Into Selected Ports

VTOR and vector-table access are no longer owned by
`fiber/target/fiber_vtor.h`. That target helper was removed.

The selected port now owns:

- whether the CPU/profile exposes `SCB->VTOR`;
- whether vector-table access targets the current bank or the Non-secure bank;
- the fallback vector base for profiles without VTOR;
- vector-table base masking/alignment before reads and writes;
- the initial MSP read used by boot/MSP rewind policy.

Common runtime code now calls:

```c
uintptr_t fiber_port_vectors_base_addr(void);
const uint32_t *fiber_port_vectors_base_ptr(void);
uint32_t fiber_port_read_initial_msp(void);
void fiber_port_set_vectors_base_addr(uintptr_t base);
```

Ports without VTOR expose an explicit `0x00000000` vector-base fallback.
ARMv7-M, ARMv7E-M, ARM_CM7/r0p1, and v8-M mainline-capable ports read/write
the selected VTOR bank inside their own port header.

## 2026-07-12: Move PSPLIM Policy Into Selected Ports

PSPLIM register policy is no longer owned by `fiber/target/fiber_pslim.h`.
That target helper was removed.

The selected port now owns:

- whether the CPU/security state has a PSPLIM register;
- whether this selected runtime is allowed to write that register;
- whether the saved context layout has a PSPLIM slot;
- whether PSPLIM access targets the current security bank or the Non-secure
  bank;
- the C API used by common startup code:
  `fiber_port_psplim_read()`, `fiber_port_psplim_write()`, and
  `fiber_port_psplim_config()`;
- the asm restore macro used by port code: `FBR_ASM_MSR_PSPLIM()`.

Ports without PSPLIM expose explicit disabled/no-op definitions. The
transitional v8-M port owns the temporary `psplim` / `psplim_ns` bank selection
until concrete v8-M production ports replace it.

Common runtime code only consumes `FIBER_PORT_USES_PSPLIM_REGISTER` and the
selected port API; it no longer includes a target-wide PSPLIM helper.

## 2026-07-12: Move FPU Policy Into Selected Ports

FPU capability detection and FP-context policy are no longer owned by
`fiber/target/fiber_fpu.h`.

The selected port now owns:

- whether the toolchain is building FP instructions;
- whether the silicon exposes an FPU;
- whether CMSIS reports `__FPU_USED`;
- whether the port supports scalar FPU use;
- whether the port saves/restores extended FP context;
- whether first start must clear or validate `CONTROL.FPCA`;
- how early FPU enable is applied through `fiber_port_fpu_enable_early()`.

The root `fiber_fpu.h` / `fiber_fpu.c` pair was removed. Common runtime code
now calls the selected-port API `fiber_port_fpu_enable_early()`. Ports without
FPU provide a no-op implementation; FPU-capable ports own CPACR/FPCCR setup,
lazy/eager policy application, barriers, and read-back checks.

This matches the v2 direction: selected ports export the CPU interface, while
common runtime code only consumes that interface.

## 2026-07-11: H7 Normal Run After SVC Dispatch Hardening

The STM32H7 / Cortex-M7 board passed `FIBER_VAL_NORMAL_RUN` after the current
SVC dispatch hardening checkpoint:

```text
208be61157ee3f06ba4b4bfc3be700b37d78eea5
```

Observed snapshot:

- `validation_flags = 0x000001FF`;
- `validation_failures = 0`;
- `last_panic_code = 0`;
- `validation_mode_seen = 0`;
- counters reached `1246134`, `1246135`, and `1246134`;
- FP accumulator relationships remained valid.

The debugger stopped the CPU during `fiber_schedule()` / `fiber_pendsv()`, so
the one-count counter skew is expected for that snapshot.

This is a normal-run validation record only. The H7 runtime-validation claim for
this exact checkpoint remains partial until the trap modes in
`H7_RUNTIME_VALIDATION.md` are rerun after the SVC dispatch hardening.

## 2026-07-11: SVC-Only First Start

The direct boot trampoline path was removed.

Current runtime startup has one path:

- `fiber_start()` asks the scheduler hook for the first context with
  `current == NULL`;
- the returned context is validated and seeded as the runtime-owned current
  context;
- the selected port enters the first fiber through SVC and exception return.

The old non-SVC start selector was deleted. There is no direct-start
configuration path left in the runtime.

This intentionally narrows the active support claim:

- ARMv7E-M remains the active runtime-supported port;
- ARMv6-M, ARMv7-M, and transitional v8-M now have compile-covered SVC
  first-start symbols, but they are not runtime-supported until hardware
  validation is recorded for each profile;
- the compile matrix now builds SVC wrapper and direct-vector modes for every
  selected profile instead of keeping a fallback-start fence.

This is behavior-affecting. The STM32H7 validation label must stay downgraded
until the SVC-only build passes `H7_RUNTIME_VALIDATION.md` again on hardware.

## 2026-07-11: Scheduler-Selected First Context

`fiber_start()` no longer accepts a direct first `FiberContext`.

The first context is now selected through the same scheduler ownership model as
later switches:

- application code installs a scheduler hook before start;
- `fiber_start()` requires the hook and a clear current-context slot;
- `fiber_start()` calls the hook once with `current == NULL`;
- the returned first context must be non-NULL, initialized, sealed, aligned, and
  valid for restore;
- only after that validation does the runtime publish the current context and enter
  the selected port first-start path.

This keeps direct task selection out of the core API. It mirrors the FreeRTOS
ownership idea that the scheduler owns the current task pointer, while keeping
the runtime cooperative and user-scheduler-driven.

This is behavior-affecting. The previous H7 validation result remains
historical until the normal and trap modes are rerun with this API shape.

The H7 validation harness splits first-start scheduler result traps from later
PendSV scheduler result traps:

- `FIBER_VAL_TRAP_NULL_FIRST` and `FIBER_VAL_TRAP_BAD_FIRST` exercise
  `pick_next(NULL, user)`;
- `FIBER_VAL_TRAP_NULL_NEXT` and `FIBER_VAL_TRAP_BAD_NEXT` exercise
  `pick_next(current, user)` after the first fiber has already entered.

## 2026-07-11: Start Real Port Common Helpers

The `fiber/port` helper-root convention is now reserved for reusable helper
code such as compiler, diagnostics, and static-assert ABI headers.

PRIMASK save/restore is intentionally not a root helper. The selected port owns
its local PRIMASK implementation and exposes only the generic
`fiber_port_scheduler_critical_enter()` /
`fiber_port_scheduler_critical_exit()` contract around the scheduler hook.
PendSV request publication itself is not wrapped in PRIMASK.

## 2026-07-12: Move BASEPRI Policy Into Selected Ports

`fiber/target/fiber_basepri.h` is removed. BASEPRI is no longer a target-wide
helper or selector-inferred CPU policy.

Each selected port now owns:

- whether BASEPRI exists;
- the scheduler BASEPRI threshold;
- C read/write helpers exposed as `fiber_port_basepri_read()` and
  `fiber_port_basepri_write()`;
- naked-asm scheduler critical-section snippets;
- Cortex-M7 r0p0/r0p1 errata handling when applicable.

Ports without BASEPRI provide no-op BASEPRI helpers and use saved PRIMASK for
the scheduler bridge. Common runtime code may only call the selected-port API.

## 2026-07-11: Rename Transitional v8-M Fallback

The temporary v8-M fallback directory was moved out of the `fiber/port` helper
root into `port/transitional_v8m`.

This is intentionally a naming-only boundary cleanup:

- `transitional_v8m` is not a real shared helper layer;
- it remains compile-covered and runtime-gated;
- it must be split into concrete v8-M ports before any FreeRTOS-level runtime
  support claim is made;
- the future `fiber/port` helper-root convention is reserved for reusable
  helper code, not selected-port fallback behavior.

## 2026-07-11: Transitional v8-M Port Split

Architecture fallback code for v8-M profiles that are not concrete v2 ports yet
lives in `fiber/port/transitional_v8m`.

This is a boundary cleanup:

- `fiber_core.c` no longer owns PendSV assembly or synthetic software-frame
  construction for any selected port;
- `fiber_core.c` also delegates switch-publication masking to the selected
  port boundary;
- `fiber/port/fiber_port_selected.h` includes
  `transitional_v8m/fiber_port_transitional_v8m.h` only for profiles that do
  not yet have a concrete selected port header;
- `port/transitional_v8m` remains transitional and runtime-gated. It is not a
  FreeRTOS-level support claim for v8-M Baseline/Mainline or ARMv8.1-M.

Historical note: at this checkpoint the H7 path still shared the former
ARMv7E-M source group. The selected-port decision above supersedes that layout:
H7 now uses `port/ARM_CM7/r0p1`, while `port/ARM_CM4` serves M4/M4F.

## 2026-07-11: ARMv7-M Port Split Checkpoint

The Cortex-M3 / ARMv7-M path now lives in
`fiber/port/ARM_CM3/fiber_port.c`.

This is a focused port-layout step:

- ARMv7-M uses the mainline software frame order `[r4..r11][LR]`;
- the scheduler bridge is protected with the BASEPRI policy used by mainline
  Cortex-M ports;
- ARMv7-M has no high-FP, PSPLIM, MVE, PAC, or BTI handling in this port;
- `fiber_core.c` no longer defines `fiber_pendsv()` or
  `fiber_port_init_context_frame()` for ARMv7-M;
- the remaining transitional fallback is now limited to runtime-gated v8-M
  transitional profiles.

This does not create a runtime validation claim for STM32F1/Cortex-M3 class
targets. ARMv7-M remains compile-only until hardware tests exist.

## 2026-07-11: Direct-Vector Compile Coverage

After the H7 SVC/PendSV validation checkpoint, the next step is intentionally a
stabilization change, not a port refactor. The compile matrix now covers:

- wrapper vector mode with `FIBER_PENDSV_WIRED=1`;
- wrapper SVC mode on ARMv7E-M with `FIBER_SVC_WIRED=1`;
- PendSV direct-vector mode with `FIBER_PENDSV_VECTOR_DIRECT=1`;
- ARMv7E-M PendSV+SVC direct-vector mode with
  `FIBER_PENDSV_VECTOR_DIRECT=1` and `FIBER_SVC_VECTOR_DIRECT=1`.

This does not change the validated H7 wrapper-vector runtime path. Direct-vector
mode is compile-covered only until a board run records that exact wiring.

## 2026-07-11: H7 SVC/PendSV Runtime Validation Pass

The STM32H7 / Cortex-M7 v2 ARMv7E-M path passed the current scheduler-driven
hardware validation set after the SVC first-start and PendSV source-save
corrections.

Observed normal run:

- `validation_flags = 0x000001FF`;
- `validation_failures = 0`;
- `last_panic_code = 0`;
- all three counters progressed equally into multi-million switch counts;
- FP accumulator relationships stayed valid.

Observed trap runs:

- no scheduler hook trapped with `'K'`;
- `NULL` scheduler hook trapped with `'K'`;
- scheduler hook hot-swap after start trapped with `'k'`;
- `fiber_schedule()` under `PRIMASK` trapped with `'p'`;
- `fiber_schedule()` under `BASEPRI` trapped with `'b'`;
- scheduler hook returning `NULL` trapped with `'N'`;
- scheduler hook returning a context with `sp == NULL` trapped with `'P'`;
- `fiber_schedule()` under `FAULTMASK` trapped with `'f'`.

Two defects were found during the SVC migration and are now documented as
port-contract rules:

- SVC first-start must not rely on writing `CONTROL.SPSEL` from Handler mode.
  Thread-mode PSP selection comes from `EXC_RETURN`, matching the FreeRTOS
  first-task start model.
- PendSV must validate the active interrupted stack by inspecting
  `LR`/`EXC_RETURN` bit 2. `CONTROL.SPSEL` is not a sufficient proof inside
  Handler mode after an exception-entry path.

The same defect class was checked in the other current switch implementations:

- ARMv6-M and transitional v8-M PendSV paths were audited for the same
  source-stack proof. After the SVC-only first-start decision, those profiles
  are no longer runtime-startable until they grow their own SVC start path.

This restores the H7 runtime-validation claim for the active ARMv7E-M SVC
start plus scheduler-driven PendSV path. It does not validate M0/M23/M33/M55
hardware or ARMv8-M security/MVE/PAC/BTI behavior.

## 2026-07-10: ARMv7E-M SVC First-Start Checkpoint

The ARMv7E-M port now starts the first fiber through SVC by default:

- That checkpoint predates the current scheduler-selected first-context API and
  the later SVC-only first-start decision.
  The current API selects the first context through the scheduler hook before
  entering the port first-start helper.
- The first-start helper forces privileged Thread/MSP state, clears FPCA by
  clearing `CONTROL`, optionally rewinds MSP through the sealed boot plan,
  verifies MSP read-back, clears any pending PendSV while interrupts are still
  masked, enables IRQ and fault exceptions, executes
  `svc #FIBER_SVC_START_NUMBER`, and panics with `'y'` if SVC returns to the
  helper.
- `fiber_svc()` rejects SVC entry from PSP or an unaligned SVC MSP frame with
  `'l'`, validates the SVC opcode and immediate, traps with `'u'` on mismatch,
  clears `BASEPRI` like the
  FreeRTOS SVC first-task handler, validates the published current context,
  restores the synthetic software frame, sets PSP, verifies `CONTROL.FPCA` when
  configured, and enters the first fiber by exception return. The SVC handler
  does not set `CONTROL.SPSEL` from Handler mode; Thread PSP selection comes
  from `EXC_RETURN`, matching the FreeRTOS first-task start pattern.
- `fiber_pendsv_init_lowest_priority()` sets SVCall to the highest priority
  when SVC first-start is enabled, and runtime validation traps with `'w'` if
  SVCall does not read back as highest priority.
- The direct boot trampoline existed at this checkpoint, but it has since been
  removed by the SVC-only first-start decision.
- The STM32H7 application must wire `SVC_Handler()` as a naked branch to
  `fiber_svc()`. That wrapper lives in the embedding application tree, outside
  this repository.

This brings the ARMv7E-M first-start model closer to FreeRTOS while keeping the
runtime cooperative. It is behavior-affecting and must pass
`H7_RUNTIME_VALIDATION.md` before the v2 H7 path regains the previous hardware
validation claim.

## 2026-07-10: ARMv6-M Port Split Checkpoint

The Cortex-M0/M0+ Thumb-1 PendSV path now lives in
`fiber/port/ARM_CM0/fiber_port.c`.

This is a mechanical port-layout step:

- ARMv6-M uses the FreeRTOS Cortex-M0 non-MPU software frame order:
  `[LR][r4][r5][r6][r7][r8][r9][r10][r11]`.
- The saved stack pointer is published only after the full software frame is
  stored. This is stricter than the FreeRTOS CM0 ordering, which writes the TCB
  top-of-stack slot before completing the staged high-register stores.
- ARMv6-M still uses saved `PRIMASK` around the scheduler bridge because the
  profile has no `BASEPRI`.
- `fiber_core.c` no longer defines `fiber_pendsv()` when `FIBER_PORT_ARMV6M`
  is selected.
- ARMv8-M Baseline/Mainline fallback code still remains in `fiber_core.c` until
  those dedicated port files are split.
- This does not create a runtime validation claim for STM32F0/G0/C0/L0/U0
  class targets. ARMv6-M remains compile-only until hardware tests exist.

## 2026-07-10: H7 Validation Gate After 775648c

Commit `775648c` is a behavior-affecting v2 checkpoint. It is larger than a
feature-policy-only change: it carries the scheduler-driven execution model,
the pure scheduler port ABI, ARMv7E-M PendSV selection through the scheduler
bridge, handler-side critical sections, exception setup validation, and
unvalidated v8-M/MVE/TrustZone/PAC/BTI runtime gates.

Compile matrix and STM32H7 build success are necessary, but they do not preserve
the older H7 runtime-validated claim by themselves. The v2 ARMv7E-M path must
pass `H7_RUNTIME_VALIDATION.md` on hardware before this branch claims the same
runtime validation level as the previous H7 path.

## 2026-07-10: v8-M Feature Policy Gates

The v2 runtime now has explicit policy gates for Cortex-M profiles whose
FreeRTOS ports carry extra context state that the current generic fiber context
does not save yet:

- `fiber/port/fiber_feature_policy.h` consumes the canonical
  `FIBER_PORT_HAS_EXTENDED_FP_CONTEXT`, `FIBER_PORT_USES_PSPLIM_REGISTER`,
  `FIBER_PORT_HAS_PAC`, and `FIBER_PORT_HAS_BTI` traits.
- MVE-FP follows the extended FP save/restore model. MVE without scalar FP is
  rejected by runtime policy validation because the current assembly does not
  implement an MVE-only register save path.
- PSPLIM register access is no longer implied only by the architecture family.
  `FIBER_PORT_USES_PSPLIM_REGISTER` is the actual access gate, keeping
  M23/security variants from accidentally writing an unsupported or wrong-bank
  PSPLIM.
- ARMv8-M Baseline, ARMv8-M Mainline, ARMv8.1-M, TrustZone/Non-secure bank
  targeting, MVE, and PAC/BTI runtime use all require explicit
  `FIBER_ALLOW_UNVALIDATED_*` opt-in until the matching FreeRTOS-style context
  layout and hardware validation exist.

New policy panic codes:

- `'2'`: ARMv8-M Baseline runtime attempted without explicit unvalidated opt-in.
- `'3'`: ARMv8-M Mainline runtime attempted without explicit unvalidated opt-in.
- `'8'`: ARMv8.1-M runtime attempted without explicit unvalidated opt-in.
- `'v'`: MVE is present without scalar FP support for the current save/restore
  path.
- `'V'`: MVE runtime attempted without explicit unvalidated opt-in.
- `'z'`: TrustZone/Non-secure policy runtime attempted without explicit
  unvalidated opt-in.
- `'J'`: PAC/BTI-capable runtime attempted without explicit unvalidated opt-in.

This does not claim FreeRTOS parity for M23/M33/M55. It closes the dangerous
silent-success path: compile-only support can continue, but unsupported runtime
features now fail early and explicitly.

## 2026-07-10: FreeRTOS-Level Exception Setup Hardening

The v2 runtime now checks exception setup before the first fiber starts:

- `fiber_exception_runtime_check()` is called by
  `fiber_pendsv_init_lowest_priority()` and again by `fiber_start()`.
- PendSV priority must read back as the lowest priority.
- PendSV and SVC vector entries must point at the expected handler symbols.
- The default PendSV model expects an application `PendSV_Handler()` wrapper.
  That wrapper must branch to `fiber_pendsv()` without clobbering
  LR/EXC_RETURN. A normal C wrapper that emits `bl fiber_pendsv` is invalid.
  Direct vectoring to `fiber_pendsv()` is supported with
  `FIBER_PENDSV_VECTOR_DIRECT=1`.
- The default ARMv7E-M SVC model expects an application `SVC_Handler()` wrapper
  that branches to `fiber_svc()` without clobbering LR/EXC_RETURN. Direct
  vectoring to `fiber_svc()` is supported with `FIBER_SVC_VECTOR_DIRECT=1`.
  SVC vector validation is mandatory because SVC is mandatory for first start.
- `FIBER_SCHEDULER_BASEPRI` is validated against the hardware-implemented NVIC
  priority bits using a FreeRTOS-style write/readback probe.
- `AIRCR.PRIGROUP` is validated with the same FreeRTOS-style rule used by the
  Cortex-M ports: scheduler `BASEPRI` assumes priority bits are not split into
  an unsafe subpriority configuration.
- Cortex-M7 r0p0/r0p1 CPUID values are accepted only by the concrete port whose
  errata workaround is always enabled.

New panic codes:

- `'Y'`: PendSV vector entry mismatch.
- `'y'`: SVC vector entry mismatch.
- `'Q'`: scheduler BASEPRI masks no implemented priority bits.
- `'q'`: scheduler BASEPRI contains unimplemented priority bits.
- `'g'`: priority grouping or 8-bit priority threshold is incompatible with
  the scheduler BASEPRI policy.
- `'7'`: affected Cortex-M7 r0p0/r0p1 core without the BASEPRI errata gate.

At that checkpoint the portable defaults used conservative switch knobs. Those
knobs were later removed: PendSV publication is unmasked, matching FreeRTOS
yield, while the selected port always emits its required DSB/ISB barriers.

## 2026-07-10: Pure Scheduler Port ABI Checkpoint

The v2 core no longer exposes a direct target-switch API:

- `fiber_switch(from, to)` and `fiber_yield_to(to)` were removed from the public
  API.
- `fiber_internal_port_switch_from_slot` and
  `fiber_internal_port_switch_to_slot` were removed from port state.
- PendSV no longer receives a preselected target from Thread mode.
- Every port path derives the source from the runtime-owned current context,
  calls the scheduler bridge, and restores only the returned context.
- The validation application now provides its own scheduler hook to reproduce
  the previous f2 -> f1 -> f3 -> f2 execution order.

This keeps the context-switch core policy-free. Sleep, wait, wake, round-robin
order, idle selection, and future yield APIs belong to the scheduler layer, not
to the CPU port.

## 2026-07-10: ARMv7E-M Scheduler-Driven PendSV Checkpoint

The ARMv7E-M port now has a scheduler-driven PendSV path:

- `fiber_scheduler_set_pick_next()` installs a stable C scheduler hook.
- Scheduler hook installation is a Thread-mode, pre-start operation. Passing a
  `NULL` hook panics with `'K'`; changing the hook after the current context is
  seeded panics with `'k'`.
- `fiber_schedule()` requests a scheduler-driven PendSV switch without
  publishing a target slot.
- ARMv7E-M PendSV saves the runtime-owned current context, enters the
  handler-side scheduler critical section, calls
  `fiber_port_scheduler_pick_next_from_pendsv()`, and restores the returned
  context.
- PendSV refuses to save a source context unless Thread mode is already using
  PSP. A spurious PendSV before the first PSP context is active traps with panic
  code `'j'` instead of overwriting `ctx->sp` with a pre-start stack state.
- PendSV also checks live PSP source-save headroom before writing the software
  frame. If the core or high-FP save would cross the current fiber stack base,
  it traps with panic code `'d'` before modifying memory below the stack.
- The scheduler bridge validates current context, configured hook, returned
  context, sealed boot state, saved stack pointer alignment (`ctx->sp % 8 == 4`
  for the saved 36-byte software frame), stack bounds, software-frame plus
  hardware exception-frame headroom, EXC_RETURN signature and Thread/PSP bits,
  and FP extended-frame headroom before restore.
- A missing hook panics with `'K'`; a `NULL` returned context panics with `'N'`;
  a missing saved stack pointer panics with `'P'`; an invalid restore frame can
  panic with `'A'`, `'U'`, `'T'`, `'X'`, or `'x'`; a corrupt boot seal uses the
  existing boot-check panic codes such as `'m'`, `'v'`, `'g'`, `'G'`, `'s'`, and
  `'h'`.
- The previous legacy/manual target-slot path has been removed.

The ARMv7E-M scheduler path follows the FreeRTOS handler critical-section model:

- `FIBER_SCHEDULER_BASEPRI` defaults to the highest non-zero hardware priority
  threshold derived from `__NVIC_PRIO_BITS`.
- Startup validates the active `AIRCR.PRIGROUP` against the FreeRTOS
  preemption-priority-only assumption for BASEPRI-protected scheduler sections.
- PendSV snapshots previous `BASEPRI`, writes scheduler `BASEPRI`, calls the
  bridge, restores previous `BASEPRI`, then restores the selected context.
- `BASEPRI` is not saved as part of `FiberContext`.
- Ports without `BASEPRI` wrap the handler-side scheduler bridge with a saved
  `PRIMASK` critical section, matching the FreeRTOS Cortex-M0 PendSV model.
- The concrete `ARM_CM7/r0p1` port always emits a FreeRTOS-style errata 837070
  guard around handler-side `BASEPRI` writes on affected Cortex-M7 r0p1 parts.
  The fiber helper is stricter than the FreeRTOS minimum: it preserves and
  restores the previous `PRIMASK` instead of unconditionally re-enabling IRQs.
- The compile matrix now builds Cortex-M7 and Cortex-M7F with that errata gate
  enabled, but real r0p1 hardware validation is still required before claiming
  FreeRTOS CM7/r0p1 parity.

## 2026-07-10: v2 Scheduler Hook State Checkpoint

Commit `cf610cc` prepares the v2 scheduler-driven port boundary:

- `fiber_runtime_state.h` now owns the internal scheduler hook state:
  current context, pick-next function pointer, and user context pointer.
- The port state layer provides a stable C bridge for future PendSV/SVC
  scheduler selection.
- The bridge validates the hook and returned context before restore.
- The public scheduler API is intentionally not exposed yet. `fiber_core.h`
  still exposes the low-level/current API only, because the ARMv7E-M PendSV path
  has not migrated to scheduler-driven selection yet.

The same checkpoint also changes the validated ARMv7E-M `FiberContext.sp`
invariant:

- `FiberContext.sp` now follows the FreeRTOS `pxTopOfStack` model.
- A non-running context stores the last saved software-frame pointer.
- While a fiber is running, the live stack pointer is CPU PSP.
- The port updates `ctx->sp` when saving a context as the switch source.
- The port no longer moves the target `ctx->sp` forward after restore.

This invariant is cleaner and better aligned with FreeRTOS, but it is a
behavior-affecting change in the STM32H7/Cortex-M7 validated path. Compile
checks and H7 build passed for this checkpoint, but the H7 runtime validation
must be repeated before this v2 path carries the previous H7 runtime-validated
claim.

## 2026-07-04: Context Switch Hardening

Status: historical. The direct-switch API, configurable EXC_RETURN, force-FPU
mode, and switch mask/barrier knobs described below were removed by the v2
canonical selected-port contract. Keep the measurements as history only; use
the 2026-07-12 decisions and `FIBER_SETTINGS.md` for current behavior.

The earlier direct-switch implementation was treated as a FreeRTOS-style
cooperative PendSV switcher for STM32 Cortex-M projects.

Validated baseline for STM32H7 / Cortex-M7:

- Save and restore `r4-r11`.
- Preserve `LR` as the `EXC_RETURN` value.
- Run tasks on PSP.
- Request switching through PendSV.
- Keep PendSV at the lowest interrupt priority.
- Save and restore `s16-s31` only when `EXC_RETURN` reports an extended FP frame.
- Use eager FP stacking by default with `FIBER_FPU_LAZY = 0`.

Observed STM32H7 hardware validation:

- A normal runtime run reached `validation_flags = 0x000001FF` with
  `validation_failures = 0` and `last_panic_code = 0`.
- A long run exceeded 8 million visits per fiber while FP accumulators kept the
  expected 1x/2x/3x relationship.
- Forced real switch while `PRIMASK != 0` trapped with panic code `'p'`.
- Forced real switch while `BASEPRI != 0` trapped with panic code `'b'`.
- A performance-mode H7 run with `FIBER_FPU_LAZY = 1`,
  `FIBER_SWITCH_MASK_IRQS = 0`, and `FIBER_SWITCH_STRICT_BARRIERS = 0`
  exceeded 18 million visits per fiber with `validation_flags = 0x000001FF`,
  `validation_failures = 0`, `last_panic_code = 0`, and the expected FP
  accumulator relationship.

Hardening decisions:

- The synthetic exception frame stores `PC` with bit 0 clear. Thumb state comes
  from `xPSR.T`, matching the FreeRTOS initial stack pattern.
- The initial `EXC_RETURN` is configurable through `FIBER_INITIAL_EXC_RETURN`.
  The default stays `0xFFFFFFFDu` for M3/M4/M7 and secure-only style builds.
- ARMv8-M Non-secure projects can set `FIBER_RUN_NONSECURE = 1` to select
  `0xFFFFFFBCu`, or override `FIBER_INITIAL_EXC_RETURN` directly.
- The validated privileged CM7 request path rejects a real scheduler jump when
  `PRIMASK`, BASEPRI, or FAULTMASK is nonzero, because a pending PendSV delayed
  past a critical section is unsafe. This behavior is preserved by the selected
  port environment/request boundary; it is not a requirement for common code
  to read privileged registers.
- Future unprivileged MPU request paths enter a validated yield SVC instead.
  Handler mode validates the real mask state before publishing PendSV, and
  every unprivileged restore guarantees zero PRIMASK and, where implemented,
  zero BASEPRI and FAULTMASK.
- The first-start path clears `CONTROL.FPCA` before entering the first fiber
  when an FPU context exists. On the current ARMv7E-M v2 path this happens
  through SVC first-start.
- The preferred low-level runtime API is `fiber_start()` plus
  `fiber_schedule()`. Higher-level yield/sleep/wait APIs should update scheduler
  state and then call `fiber_schedule()`.
- `fiber_start()` asks the scheduler hook for the first context with
  `current == NULL`, seeds that validated context as runtime-owned current, and
  the scheduler bridge updates it during every scheduler-driven switch. This
  mirrors the FreeRTOS `pxCurrentTCB` ownership model without exposing direct
  target selection to the core API.
- The scheduler-driven ARMv7E-M branch writes `BASEPRI` around the scheduler
  bridge and has an explicit Cortex-M7 r0p1 errata gate.
- The old H7 performance-mode measurements remain historical evidence only.
  Lazy FP is the sole surviving performance policy; switch masking and barrier
  disable knobs no longer exist.

Known limits:

- STM32H7 / Cortex-M7 is the primary validation target and has the strongest
  historical hardware evidence; the latest behavior changes require a fresh
  checklist run.
- ARMv8-M Non-secure remains a transitional compile-only scenario selected by
  `FIBER_TRANSITIONAL_V8M_RUN_NONSECURE`; EXC_RETURN is selected-port-owned and
  cannot be overridden by common application settings.
- Cortex-M23 PSPLIM behavior is intentionally not enabled by the generic
  baseline path. FreeRTOS has context slots for PSPLIM, but its Non-secure M23
  port does not program a non-secure PSPLIM register.
- Cortex-M55 / MVE needs a concrete port-owned context layout and hardware
  validation. There is no force-save override; a production port must derive
  and implement every required FP/MVE context slot from compiler and CPU facts.
- There is no v2 public API for starting from a caller-provided common
  boot record. Ports without hardware validation are not runtime-supported.
- `tools/compile_matrix.ps1` provides the compile-only sanity matrix. It does
  not replace hardware tests, but it must stay green before widening support
  claims beyond STM32H7/Cortex-M7.

## 2026-07-15: Activate sensitive compiler ABI and strong handlers

- `fiber_api_attributes.h` is the single public definition point for the
  sensitive compiler bundle. It includes no-instrumentation, no-stack-
  protector, no-sanitizer, no-profile/coverage, `noipa`, no-clone, and no-ICF
  mappings where GNU Arm Embedded GCC supports them.
- `fiber_current()`, `fiber_start()`, `fiber_schedule()`, both runtime ABI
  directions, and the scheduler hook use the canonical sensitive plus
  general-registers-only contract.
- Selected-port compiler mappings import that bundle instead of independently
  defining the scheduler-hook ABI.
- CMSIS force-inline helpers cannot inherit all caller attributes. A build that
  globally enables instrumentation, stack protection, profiling, coverage, or
  sanitizers must apply the selected-port counter-flags documented in
  `V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md`.
- Every current selected port directly defines strong naked `SVC_Handler` and
  `PendSV_Handler` symbols in the same object as mandatory runtime ABI
  functions. Application wrappers and wrapper/direct routing macros are gone.
- The matrix rejects obsolete routing macros, requires one strong handler pair
  per profile, and proves CM7 archive extraction, vector slots 11/14,
  duplicate-strong failure, section-GC retention, LTO retention, and
  adversarial generated-code hygiene.
- The H7 host application no longer defines SVC/PendSV wrappers. Its current
  Debug ELF resolves both vector slots directly to selected-port handlers.
- This is behavior-affecting exception ownership. Compile/ELF evidence is
  complete for the implemented slice, but a fresh H7 normal/FPU/trap/VTOR run
  is still required before restoring the current hardware-validation claim.

## 2026-07-16: Clarify private port and optional feature ownership

- `fiber_port_private.h` is the internal declaration surface shared only by the
  runtime, boot/frame, exception, and assembly files of one exact selected
  profile. It is not selected by `fiber_port_selected.h`, exported to common
  runtime, or exposed as a user feature API.
- `fiber_port_selected.h` selects only the public type-completion header, while
  `fiber_core.c` reaches the selected CPU engine exclusively through the frozen
  eight-function `fiber_port_runtime_abi.h` boundary.
- Profile-mandatory CPU mechanics remain private behind those eight operations.
  An MPU profile owns MPU/CONTROL state and its yield-SVC path; a TrustZone
  profile owns its security context mechanics and matched Secure companion; a
  TF-M profile owns the matching NTZ runtime and TF-M veneers.
- Capable variants are separate exact profile directories and context
  identities. A privileged `ARM_CM3` build does not conditionally become
  `ARM_CM3_MPU`, and neither profile includes the other's private header.
- Optional `fiber_port_<feature>_abi.h` files exist only for deliberate,
  non-portable profile-policy customization. They do not contain mandatory
  safety mechanics, are not called by common runtime, and are not required by
  portable application code using only `fiber_core.h`.

## 2026-07-16: Freeze the ARM_CM3_MPU reference audit

- The exact pre-implementation parity ledger is
  `fiber/port/ARM_CM3_MPU/FREERTOS_PARITY.md`, referenced to local FreeRTOS
  commit `a50edad08b29052631aa469d4df6e6ec7ff68878` with hashes for
  `portmacro.h`, `port.c`, and `mpu_wrappers_v2_asm.c`.
- `ARM_CM3_MPU` is a separate selected profile and context cohort, not a
  conditional extension of privileged `ARM_CM3`.
- Mandatory profile state includes protected CONTROL/core/hardware-frame
  storage, four per-context MPU region pairs, safe global MPU regions,
  unprivileged yield SVC, return SVC, and privileged PendSV restore mechanics.
- FreeRTOS kernel API veneers, generic privileged Thread-mode system calls,
  SysTick, kernel-object ACLs, nested public critical sections, and FromISR APIs
  are explicit exclusions rather than omitted inventory.
- The safe default does not grant blanket peripheral access. Linker and MPU
  proofs must keep writable stacks/application data outside writable privileged
  context, scheduler, hook, and runtime state even after MPU size rounding.
- Implementation proceeds in exact-profile slices and may not change common
  runtime choreography or widen the frozen five/eight-function ABI.

## 2026-07-16: Freeze the ARM_CM3_MPU type and layout cohort

- Slice 1 adds only `fiber_port_types.h`, `fiber_port_boot_types.h`, and a
  compile-only `fiber_portmacro.h` under `fiber/port/ARM_CM3_MPU`. There are no
  runtime sources, selector route, handlers, or support claim.
- `FiberContext` is an 8-byte-aligned 200-byte GCC Cortex-M3 type containing a
  protected cursor, four contiguous RBAR/RASR pairs, a 20-word protected CPU
  image, and an 80-byte immutable boot record.
- Exact assertions freeze every saved-register, region, context, and boot-field
  offset. The boot identity includes initial CONTROL and four-region policy;
  the exact port/layout/feature tuple is `CM3M` / `0x00010001` / `0x00001C04`.
- The build proof is Cortex-M3, Thumb, soft-float, MPU-present, VTOR-present,
  and FPU-absent. Type-only C/C++ compilation requires no CMSIS; the private
  trait/cohort probe consumes the established shared compiler contract.
- Negative probes reject Cortex-M4, `__MPU_PRESENT == 0`, and a non-M3 CMSIS
  identity. Source audits keep the new profile absent from global selection and
  require that this slice contain no runtime source files.

## 2026-07-16: Add the ARM_CM3_MPU construction slice

- Slice 2 adds port-private MPU/linker helpers and the frozen
  `fiber_port_context_init()` implementation, but no selector route, switch
  engine, exception source, or handler symbol.
- The linker owns ten exact code/data/RAM/current-slot boundaries with no weak fallback.
  Programmed code/data ranges must be exact power-of-two aligned MPU regions;
  code and RAM cannot overlap, privileged data is disjoint from unprivileged
  RAM, and only a complete privileged-code overlay inside the unprivileged code
  range is permitted.
- Per-context regions 0-2 are disabled by default. Global region 4 is an exact
  32-byte unprivileged-RO/XN current-slot aperture rather than a blanket
  peripheral map. Regions 5-7 provide unprivileged RO code, privileged RO code,
  and privileged-only RW/XN data. Region 3 maps only an exact
  power-of-two/aligned raw stack as RW/XN.
- The safe default rejects stack widening instead of accepting a rounded region
  that could expose another stack or application object. Portable API calls do
  not change; an MPU linker integration must provide the required placement.
- Initial contexts are unprivileged (`CONTROL == 3`). Protected core and copied
  hardware-frame state remains in privileged `FiberContext` storage; PSP
  reserves the hardware frame in the unprivileged stack and LR targets the
  future unprivileged return veneer.
- The immutable hash covers boot/ABI fields, CONTROL policy, region count, and
  all four MPU register pairs. Dynamic saved registers and the live cursor are
  excluded. Full validation proves privileged context extent before the first
  context-field read.
- Matrix evidence includes an exact undefined-symbol allowlist, privileged-text
  section proof, a positive synthetic linker manifest, a missing-boundary
  negative link, selector isolation, and absence of SVC/PendSV symbols.
