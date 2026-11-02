# STM32 Port Freeze Inventory

## Status

The current extraction scope is the
[bounded F0/G0/G4/H7/H7S baseline](CONTEXT_REFACTOR_BASELINE.md). It supersedes
this document's earlier universal pre-extraction completion requirement, not
the retained catalog or per-profile evidence obligations.

This document is the current planning ledger for completing the selected-port
baseline before the Context/Fiber extraction defined in
`CONTEXT_FIBER_ARCHITECTURE.md`.

It is not a support claim and it does not replace a per-port
`FREERTOS_PARITY.md` ledger. A profile is complete only when its own ledger,
generated-code proof, link/ELF proof, and applicable hardware evidence agree.

Inventory snapshot:

```text
fiber branch:          v2
audited tree:          ARM_CM55 scalar, scalar-FP, MVE-FP, no-FPU MPU, scalar-FP MPU, and MVE-FP MPU runtimes
FreeRTOS reference:    a50edad08b29052631aa469d4df6e6ec7ff68878
toolchain:             GNU Arm Embedded GCC from STM32CubeIDE 2.0.0
matrix result:         PASS
assembly parity:       PASS at -O2 and -Os
```

These recorded PASS labels are the pre-correction validation snapshot reviewed
in `PORT_ARCHITECTURE_AUDIT.md`. That snapshot coexisted with A01-A21; it is not
evidence of correct target execution. A refreshed full-matrix result must be
reported separately from focused correction tests and hardware evidence.

The 2026-11-01 A01-A21 repair tree subsequently passed the complete refreshed
matrix, including the maintained audit regressions and all original checks.
`PORT_ARCHITECTURE_AUDIT.md` records that working-tree qualification and its
hash-backed source/evidence snapshot. This closes those software findings, not
the remaining profile inventory, global optimization/CI gate, or board proof.

The later A22-A24/C55S private-pool checkpoint also passed the full matrix with
explicit QEMU execution. Its separate snapshot in `PORT_ARCHITECTURE_AUDIT.md`
supersedes earlier software receipts for the affected sources, without
transferring their PASS to later edits or claiming complete handler execution.

The later unchanged 559-input checkpoint combines private companion binding,
ISA admission and staged startup/attachment evidence. A29 then exposed a
constructor-only reverse-ABI GC gap not covered by that checkpoint. Its cold
constructor repair and new link controls require their own fresh aggregate
receipt before the working tree is software-qualified again. See the exact
status and source archives in `PORT_ARCHITECTURE_AUDIT.md`.

This inventory snapshot accompanies the exact build-selected CM55 scalar,
scalar-FP, MVE-FP, no-feature MPU, scalar-FP MPU, and MVE-FP MPU runtimes. It
does not claim M55 MPU hardware isolation, TrustZone, TF-M, PAC/BTI, or hardware
roles required by a full STM32N6 image.

## Scope Rule

The freeze covers architecturally distinct STM32 Cortex-M execution profiles,
not every compiler directory carrying equivalent CPU mechanics.

GCC is the initial production compiler cohort. IAR and Arm Compiler directories
are not separate CPU profiles when they implement the same saved-state and
exception contract. A compiler-specific port becomes separate work only when
its ABI or generated context mechanics materially differ.

The word profile includes every feature that changes context state or protected
execution mechanics:

```text
core architecture and revision
FPU and extended FP state
MPU and privilege state
TrustZone security role and banked registers
SecureContext companion state
PSPLIM
MVE
PAC/BTI
architecture errata
```

## Concrete Profiles Already Present

Twenty-one recorded complete runtime profiles currently have selected-port source
groups and pinned FreeRTOS parity ledgers:

| Fiber profile | Main covered mechanics | Current claim |
| --- | --- | --- |
| `ARM_CM0` | M0 and M0+ privileged Thumb-1 start/save/restore, separate VTOR traits | compile/assembly/ELF validated |
| `ARM_CM0_MPU` | build-selected M0+ protected context, MPU replacement, unprivileged yield/return | compile/assembly/ELF validated; hardware isolation pending |
| `ARM_CM3` | privileged ARMv7-M SVC/PendSV and BASEPRI path | compile/assembly/ELF validated |
| `ARM_CM4` | privileged M4/M4F conditional FP context | compile/assembly/ELF validated |
| `ARM_CM7/r0p1` | privileged M7/M7F conditional FP context and errata 837070 policy | compile/assembly/ELF validated; refreshed H7 run pending |
| `ARM_CM3_MPU` | protected context, MPU replacement, unprivileged yield/return | compile/assembly/ELF validated |
| `ARM_CM4_MPU` | M4F/M7F protected FP context, MPU replacement, M7 errata policy | compile/assembly/ELF validated |
| `ARM_CM23_NTZ/non_secure` | exact non-MPU Baseline NTZ frame and ignored PSPLIM slot | compile/assembly/ELF validated; reference-portability profile |
| `ARM_CM33_NTZ/non_secure` | exact non-MPU/no-FPU Mainline NTZ frame with PSPLIM | compile/assembly/ELF validated |
| `ARM_CM33/non_secure` plus `ARM_CM33/secure` | no-MPU/no-FPU TrustZone companion frame, exact construction, sealed attach, twelve versioned identity/init/allocation/save/load veneers, static Secure pool, all eight forward operations, and strong SVC/PendSV | compile/assembly/cohort/CMSE/vector/LTO validated only; exact private Secure-object binding and ISA admission now have separate focused and 559-input combined evidence; no hardware claim |
| `ARM_CM33_TFM/non_secure` | exact no-MPU/no-FPU NTZ CPU frame plus TF-M v2.0.0 initialization and cooperative mutex adapter; no fiber SecureContext | compile/assembly/archive/ELF validated only; TF-M/PSA/hardware integration pending |
| `ARM_CM33_MPU/non_secure` | no-FPU protected Mainline MPU frame, direct current-slot aperture, protected SVC/PendSV | compile/assembly/ELF validated; hardware isolation pending |
| `ARM_CM33F_NTZ/non_secure` | exact non-MPU FP Mainline NTZ frame with PSPLIM | compile/assembly/ELF validated |
| `ARM_CM55_NTZ/non_secure` | exact ARMv8.1-M scalar Non-secure ten-word PSPLIM frame; FPU/MVE/MPU/CMSE/PAC/BTI rejected | compile/assembly/ELF validated; M55 hardware and feature cohorts pending |
| `ARM_CM55F_NTZ/non_secure` | scalar-FP ARMv8.1-M Non-secure frame with conditional `s16-s31` state | compile/assembly/ELF validated; M55 hardware and feature cohorts pending |
| `ARM_CM55_MVEF_NTZ/non_secure` | MVE-FP ARMv8.1-M Non-secure frame with conditional `s16-s31` and no VPR software slot | compile/assembly/ELF validated; M55 hardware and protected cohorts pending |
| `ARM_CM55_MPU/non_secure` | no-FPU C55M protected frame, 8/16-region image, public SVC-71 yield, and protected PendSV | compile/assembly/archive/ELF/vector/cohort validated; hardware isolation pending |
| `ARM_CM55F_MPU/non_secure` | scalar-FP MPU C55P protected frame, 8/16-region image, public SVC-71 yield, and protected FP PendSV | compile/assembly/archive/ELF/vector/cohort validated; hardware isolation pending |
| `ARM_CM55_MVEF_MPU/non_secure` | MVE-FP MPU C55W 54-word protected frame, public SVC-71 yield, protected `s16-s31`/copied-low-FP PendSV, 8/16-region image, and no VPR software slot | compile/assembly/archive/ELF/vector/cohort validated; hardware isolation pending |
| `ARM_CM33F_MPU/non_secure` | scalar-FP MPU C3FP 54-word protected frame, explicit 8/16-region manifests, protected first selection and SVC/PendSV, complete eight-operation provider | complete-group and post-selectable six-gate software qualification; r8 QEMU execution, r16 compile/link only; separate current-code parity receipts; no hardware claim |
| `ARM_CM55_TFM/non_secure` | scalar M55 NTZ CPU frame plus separate TF-M initializer/cooperative mutex adapter, complete eight-operation provider | post-selectable target/host/actual-M55 dual-r9/object-role qualification plus separate assembly parity; actual TF-M Secure-image/PSA and hardware integration pending |

`ARM_CM55/non_secure` is a deliberately staged `C55S` TrustZone SecureContext
layout dictionary, not another complete runtime profile. It freezes the
eleven-word Non-secure frame and scalar M55/CMSE manifest. The paired
`ARM_CM55/secure` Slice-2/4 artifact provides eight immutable cohort-named
identity/capacity NSC veneers and a manifest-budgeted, retained Secure-only
pool with real CMSE import/negative-link and section-placement proof. Slice 4
adds private one-shot pool memory initialization, static allocation, and owned
lookup without changing those NSC exports. Slice 5 adds a ninth, guarded
one-shot NSC CPU/pool initializer; the existing eight query names and pool
layout are unchanged. Slice 6 adds guarded NSC allocation/load/save, making
twelve imports with the same context identity/layout and pool geometry. Its
new execution/negative qualification is separate from the preceding 467-input
initializer checkpoint. Slice 8 adds sealed NS construction and pre-start
attachment, separately qualified by the maintained 892-launch gate and the
559-input combined checkpoint. Port runtime, handlers and archive/vector
runtime proof remain pending. No hardware claim
or complete C55S runtime follows from these staged artifacts.

The CM33 scalar-FP MPU profile is now the twentieth recorded complete runtime,
documented in `ARM_CM33F_MPU/non_secure/FREERTOS_PARITY.md`. Its C3FP identity
covers the 54-word protected FP image and explicit 8/16-region manifests.
Post-selectable manifest, constructor, first-start codegen/execution, running
component and actual common-runtime gates pass separately. The complete-group
gate records 9,349 checks and 161 AN505 executions; sixteen-region images remain
compile/link-only. It remains explicitly build-selected, without a global auto
route. The maintained immutable pinned-reference parity has its own receipt;
fresh combined-tree and final all-optimization qualification remain required.

The current matrix pairs every complete runtime source group against the pinned
FreeRTOS reference where applicable and separately tests the paired CM33
companion layout/gateway. It passes the existing directional ABI, exact cohort,
vector, archive, section-GC, LTO, CMSE import-library, and negative-link proofs.

`ARM_CM0_MPU` is complete only as an explicit build-selected profile. It is not
inferred from `__MPU_PRESENT` and remains outside global auto/profile routing;
hardware execution and MPU isolation remain unvalidated.

This does not promote the profiles without current board evidence to
`hardware validated`.

`ARM_CM55_MPU/non_secure` slice 5 now counts as a complete explicit
build-selected `C55M` no-FPU/no-MVE protected runtime. It freezes the
8/16-region storage and exact cohort identity, sealed construction,
linker-boundary validation, global MPU image, all eight forward operations,
strong slots 11/14, public SVC 71 yield, protected PendSV
save/select/MPU-replace/restore, normal/LTO archive extraction, external
cohort expectation, and stale 8/16 archive rejection. It has no global
auto-selector, optional MPU API, or hardware claim.

## Remaining Port-Freeze Work

### 1. ARM_CM0 MPU

The pinned FreeRTOS `GCC/ARM_CM0` directory contains a distinct optional
MPU/unprivileged branch. The current `ARM_CM0` profile intentionally implements
only the privileged branch.

`ARM_CM0_MPU` slices 1-6 freeze an exact build-selected type/layout/trait
and cohort contract, port-owned construction/seal, strict MPU encoder, linker
isolation, global MPU image, strong SVC first start, unprivileged task return,
public `fiber_schedule()` yield, protected PendSV save/select/MPU-replace/
restore, full MPU readback, the reference-derived Thumb-1 first/ordinary
restore, and all eight frozen forward runtime ABI operations.
It preserves the reference raw 20-word protected image while
deliberately replacing broad unprivileged peripheral access with one exact
256-byte current-context aperture, leaving three configurable regions plus the
stack. The default image disables regions 0-2, uses region 3 for the exact raw
stack RW/XN range, and builds regions 4-7 from ten required linker boundaries.

The profile remains build-selected only and exposes no public optional MPU
configuration ABI. Its `-O2`/`-Os` and normal/LTO archive proof covers direct
slots 11/14, exact first and ordinary protected restores, public yield
provenance, first activation and ordinary MPU replacement/readback,
VTOR-present/absent cohorts, current preflight ordering, linker isolation, and
both stale archive/expectation cohort failures. It is software evidence only,
not a hardware support claim.

Remaining work is Cortex-M0+ MPU hardware and isolation validation, followed by
the optional heterogeneous-MPU feature only if a product needs it.

### 2. Cortex-M33 MPU Cohorts

The existing M33 and M33F profiles are NTZ and non-MPU. Complete M33 coverage
still needs exact protected no-FPU and FP cohorts with:

```text
CONTROL and PSPLIM ownership
per-context MPU image
basic and extended FP protected frame variants
first activation and PendSV replacement/readback
unprivileged yield and return services
MPU linker isolation and stale-cohort rejection
```

`ARM_CM33_MPU/non_secure` slice 5 completes the first protected M33 cohort as
an explicit build-selected GCC profile. It is pinned to FreeRTOS
`GCC/ARM_CM33_NTZ/non_secure` with MPU enabled and TrustZone, FPU, MVE, PAC,
and BTI disabled. The profile owns the exact 8- or 16-region MPU storage
layout, 20 active protected words plus a final one-past cursor target, exact
cohort identity, all eight forward ABI operations, and reverse ABI v1.
Construction uses strict 32-byte RBAR/RLAR encoding, the default stack pair,
a fixed current-slot pair, disabled future configurable pairs, MAIR0, and
linker-derived global images. Strong SVC first start and PendSV preflight/save/
select/replace/restore are complete. SVC 71 is the public unprivileged
`fiber_schedule()` veneer and only pends the selected PendSV.

The common current slot is a separate 32-byte SRAM aperture, mapped as RNR5
read-only/XN for both privilege levels. Its enabled MPU range is disjoint from
the privileged-RW SRAM mapping and every other enabled region; Armv8-M must not
use an overlapping higher-priority overlay. The physical SRAM allocation remains
board-owned. The linker gives the slot its own section, and startup must zero
that section separately from ordinary privileged SRAM before runtime use.
ARMv8-M cannot encode privileged-RW plus unprivileged-RO. The port publishes
the next pointer only in the existing PRIMASK-protected MPU-disabled replacement
interval. This intentionally reserves RNR5: 8-region builds keep two, and
16-region builds keep ten, future configurable pairs. The profile has no global
selector route, optional MPU API, or hardware claim. Public MPU policy and
hardware MPU-isolation validation remain later work.

### 3. Cortex-M33 TrustZone And SecureContext

`ARM_CM33/non_secure` slices 1-6 plus the paired Secure companion complete the separate companion-aware
Non-secure public layout from `GCC/ARM_CM33/non_secure`: the 11-word
`[xSecureContext, PSPLIM, EXC_RETURN, r4-r11]` software frame and sealed
pre-start `secure_stack_bytes` request. It now constructs the exact 19-word
initial frame and exports the sealed profile-specific attach API. The paired
Secure artifact exports four immutable identity queries plus four capacity
queries and initialization/allocation/save/load operations,
backed by a manifest-budgeted Secure-only pool with exact FreeRTOS two-word
stack seals. Strong SVC 70 initializes PRIS/Secure Thread state, allocates and
loads an attached first context, validates the mutated frame, and restores all
eleven software words. Strong PendSV saves/unloads current Secure state,
selects under BASEPRI, lazily allocates an attached never-run context, loads
owned Secure state, and restores the selected Non-secure frame. It passes
`-O2`/`-Os` construction/init/allocation/save/load/SVC/PendSV parity, real GNU
CMSE image/import-library links, missing import/lifecycle ABI, v1/v2 mismatch,
duplicate-handler rejection, exact twelve-veneer surface, slots 11/14,
Secure-RAM placement, and normal/LTO manifests. Independent handler and
attachment bundle anchors prove ordinary one-pass archive extraction despite
naked-asm helper calls, and lazy handles are capacity-checked before frame
publication. This is complete software evidence, not a hardware support claim.

The A17 owner regression compiles the entire three-source Secure companion,
including every reachable pool helper, with canonical sensitive/general-register
annotations and mandatory build counterflags. It checks adversarial `-O0`,
`-O2`, `-Os`, `-O2 -flto`, and `-Os -flto` linked CMSE images for forbidden
dependencies and call-graph edges. The profiling, stack-check, and trace-pc
probes also use `-fno-profile`, `-fno-stack-check`, and
`-fno-sanitize-coverage=trace-pc` after their enabling options. An intentionally
contaminated object only qualifies the detector; it is not executed and does not
establish a runtime defect outside supported counterflags. This is codegen/link
evidence only. `tools/test_owner_guards.ps1` also replays the five production
Secure parity checks against the pin at actual `-O2` and `-Os`.

A fiber without an attached SecureContext must retain the ordinary Non-secure
switch path. A fiber with an attachment must save and load the matching Secure
state without inheriting another fiber's state.

### 4. Cortex-M33 TF-M Integration

`ARM_CM33_TFM/non_secure` now completes the software profile for the pinned
TF-M v2.0.0 contract. TF-M remains an alternative Secure provider, not another
copy of the scheduler port: C3TF uses the matching NTZ-style ten-word CPU frame
and strong SVC/PendSV mechanics, then binds an explicit initialization/mutex
artifact. It must not be linked with the fiber-owned SecureContext companion.

The optional `fiber_port_tfm_initialize()` call is idempotent and may run early;
`fiber_start()` also requires it automatically before CPU preparation. The
external `tfm_ns_interface_init()` and generated PSA/NSC veneer artifacts remain
TF-M-owned and deliberately unresolved by the library. One static cooperative
mutex implements the exact v2.0 OS-wrapper symbol surface; only wait-forever
retries through the user scheduler. The matrix proves pinned provenance,
`-O2`/`-Os` CPU assembly parity, exact external dependencies, normal/LTO archive
extraction, direct vectors, missing-TF-M failure, and SecureContext exclusion.

Remaining evidence is integration/runtime only: build a matching TF-M v2.0
Secure image, generated Non-secure interface and `s_veneers.o`, exercise PSA
calls concurrently from multiple fibers, and validate the security/vector/
PSPLIM behavior on matching hardware. No such claim is active now.

### 5. Cortex-M55 / STM32N6

`ARM_CM55_NTZ/non_secure` now provides the exact scalar M55 baseline: one
privileged Non-secure, no-MPU, no-FPU, no-MVE, no-SecureContext, no-TF-M,
no-PAC, no-BTI frame and runtime. Its `C55N` cohort and explicit M55 CMSIS
identity prevent an M33 archive or feature-enabled M55 build from satisfying
this profile. `-O2`/`-Os` generated assembly parity, normal/LTO archive,
vector, ABI, cohort, and negative-manifest proofs pass. It is software evidence
only and remains outside global selection.

`ARM_CM55F_NTZ/non_secure` is a distinct complete build-selected `C55F`
scalar-FP layout cohort. Slices 1-4 freeze the 72-byte basic and 212-byte
bounded extended-FP geometry, FPU/PSPLIM/BASEPRI traits, and the no-MVE compiler
contract (`-march=armv8.1-m.main+fp`); they reject MVE, MPU, Secure CMSE, PAC,
and BTI. `fiber_port_boot.c` owns sealed boot/context construction and
CPACR/FPCCR policy. `fiber_port_svc.c` owns strict first SVC start and strong
slot-11 ownership. `fiber_port.c` owns the eighth forward operation, strong
slot-14 ownership, and basic/extended scalar-FP PendSV save/select/restore.
Hard/softfp `-O2`/`-Os` FreeRTOS-shaped construction/SVC/PendSV parity plus
normal/LTO archive, vector, exact-cohort, and duplicate-handler proof apply.
It remains outside global selector routing and has no hardware-support claim.

`ARM_CM55_MVEF_NTZ/non_secure` is the matching non-selectable `C55V`
`configENABLE_FPU=1`, `configENABLE_MVE=1` runtime. It owns sealed 72-byte
basic and bounded 212-byte extended construction, CPACR/FPCCR policy, strict
integer-only first SVC start, strong slots 11/14, and conditional `s16-s31`
PSPLIM PendSV with no VPR software slot. Hard/softfp `-O2`/`-Os` FreeRTOS
construction/SVC/PendSV parity plus normal/LTO archive, vector, exact-cohort,
reverse-surface, and duplicate-handler proofs pass. It has no global selector
route or hardware-support claim.

`ARM_CM55_MPU/non_secure` is the separate explicit build-selected `C55M`
no-FPU/no-MVE protected role. Slice 5 freezes MAIR0, 8/16-region per-context
RBAR/RLAR storage, the 20-active-word plus one-past cursor image, exact M55
MPU cohort identity, sealed construction, linker MPU boundaries, and the
global image. `fiber_port_boot.c` supplies construction; `fiber_port.c`
supplies the seven remaining forward operations, strict first-start SVC,
public SVC 71 yield, protected MPU activation/restore, and protected PendSV
switching in the pinned FreeRTOS order. PendSV preflights the live image before
cursor access, selects through reverse ABI v1 under BASEPRI, replaces
MAIR0/context regions while PRIMASK is set, publishes current while MPU access
is disabled, and restores the inverse protected frame. Normal/LTO archive,
external-cohort, stale 8/16 archive, vector, and duplicate-handler proofs pass.
It has no global selector, optional heterogeneous-MPU API, or hardware claim.

`ARM_CM55F_MPU/non_secure` is a distinct complete build-selected `C55P`
scalar-FP MPU cohort, not a feature switch on `C55M` or `C55F`. Slices 1-4
freeze the pinned FreeRTOS
54-word privileged protected backing store with its required overlap: the
basic first-start view occupies words 0-20 while a later extended FP save
occupies words 0-53 in the same array. It also fixes the scalar-FP compiler
manifest, FPU policy/readback helpers, MAIR0 and 8/16-region storage, sealed
construction, linker checks, and distinct exact cohort identity. Its strong
SVC #70 path validates and restores the basic protected image; private SVC #72
handles a task return. Its separate strong PendSV handler validates the live
frame before cursor access, preserves the exact scalar-FP copy order, selects
through reverse ABI v1 under BASEPRI, and replaces the MPU image under PRIMASK.
Boot owns construction, while the mandatory SVC object owns the other seven
forward operations, public SVC #71 yield, and a private anchor that forces the
separate PendSV archive component into the final link. Generated checks cover
hard/softfp -O2/-Os; archive proof samples hard-float -O2, softfp -Os, and
hard-float -O2 LTO, plus external-cohort, stale archive, vector, placement, and
duplicate-handler checks. It has no global selector, optional MPU API, or
hardware claim.

`ARM_CM55_MVEF_MPU/non_secure` is a separate complete explicit build-selected
`C55W` MVE-FP MPU runtime cohort, not an option on `C55P`. Slice 1 freezes the
pinned FreeRTOS MPU+FPU+MVE 54-word protected backing image for 8- and
16-region manifests: basic first-start state uses words 0-20 and later extended
FP/MVE state uses words 0-53 of the same privileged array. The manifest binds
`-march=armv8.1-m.main+mve.fp`, records MVE in the exact cohort, and rejects
scalar-FP, integer-only MVE, CMSE, PAC, and BTI. Slice 2 adds strict SVC #70
first start, private SVC #72 task return, a strong slot-11 handler, and the
pinned basic MPU restore. Slice 3 adds the strong slot-14 handler and protected
MVE-FP PendSV copy/select/MAIR0-plus-context-MPU-replacement/restore mechanics;
the generated proof retains `s16-s31` plus copied `s0-s15/FPSCR` order and no
VPR software state. Slice 4 adds the remaining seven forward operations,
public SVC #71 yield, a private bundle anchor that extracts the separate PendSV
archive member, and normal/LTO whole-runtime proof. Hard/softfp `-O2`/`-Os`
SVC/PendSV parity, external cohort, stale 8/16 archive, placement, vector, and
duplicate-handler evidence pass. Hardware isolation remains pending.

`transitional_v8m` now provides compile-only bring-up coverage only for the
unported ARMv8-M/ARMv8.1-M roles. It is not a Cortex-M55 production port.

The remaining concrete STM32N6 feature profiles must own and prove:

```text
M55 MPU hardware isolation state
TrustZone banked state
SecureContext or TF-M integration
PSPLIM
PAC/BTI policy when enabled by the exact target cohort
target vector, priority, linker, and hardware behavior
```

STM32N6 is an Arm Cortex-M55 STM32 with FPU, MVE, MPU, and TrustZone. It is
therefore a major context-family implementation, not a direct rename of the
existing M33 port.

Official references:

- <https://www.st.com/en/microcontrollers-microprocessors/stm32n6-series.html>
- <https://www.st.com/en/microcontrollers-microprocessors/stm32n655z0.html>

### 6. Cortex-M85 / STM32V8 Scope

The previous roadmap treated Cortex-M85 as a non-STM32 reference row. That is
no longer sufficient: ST now lists STM32V8 as the first STM32 Cortex-M85
series, while the current portfolio presentation marks it as preannouncement.

If the freeze means all announced STM32 execution profiles, it must include an
exact M85 cohort with MVE, MPU, TrustZone, PAC/BTI, double-precision FPU policy,
SecureContext/TF-M integration, and the corresponding FreeRTOS generated-code
proofs.

If STM32V8 is deliberately deferred until its production hardware/toolchain
contract is stable, that exclusion must be explicit in the freeze checkpoint.

Official references:

- <https://www.st.com/content/st_com/en/arm-32-bit-microcontrollers/arm-cortex-m85.html>
- <https://www.st.com/resource/en/product_presentation/stm32v8-presentation.pdf>

### 7. Final Cleanup And Software Freeze

After concrete v8-M/v8.1-M ports replace its remaining test roles:

```text
delete transitional_v8m
expand every paired port proof to -O0/-Og/-O2/-Os/-O3
compare final linked-ELF disassembly at -O2 -flto and -Os -flto
rerun the complete compile and assembly matrix
run the pinned release-blocking CI job against the exact freeze commit
retain the version manifest, ELF, disassembly, map, and negative-test artifacts
record current hardware validation as passed, failed, or explicitly deferred
freeze a branch with no known software gap
```

Hardware evidence is independent of compile, assembly, host, emulator, and ELF
evidence. It is not a prerequisite for the software freeze in this roadmap. A
profile without a matching board run may be frozen as
`compile/assembly/ELF validated`, but never as `hardware validated`.

## Planning Estimate

The following ranges count focused implementation, audit, matrix, and
documentation slices. They are planning ranges, not support claims or calendar
commitments.

| Freeze boundary | Estimated remaining slices |
| --- | ---: |
| Basic privileged CPU cores | 10-16 |
| Full current STM32 coverage through Cortex-M55 / STM32N6 | 24-36 |
| Full announced STM32 coverage including Cortex-M85 / STM32V8 | 32-48 |

At the demonstrated staged-port pace, the software work is approximately four
to seven focused weeks through M55, or six to ten focused weeks including M85.
Board availability, toolchain defects, silicon errata, and cross-image security
integration can extend elapsed time independently of source implementation.

CM23 Secure/MPU expansion is additional reference-portability work unless a
matching STM32 target is explicitly added to the product scope. The existing
CM23 NTZ profile remains useful assembly and ABI evidence but does not create an
STM32 hardware claim.

## Recommended Execution Order

The source-group and exact-manifest reconciliation is maintained in
[`STM32_PROFILE_BACKLOG.md`](STM32_PROFILE_BACKLOG.md). It distinguishes the
twenty-one recorded runtime profiles from staged C55S and lists missing FP, MPU,
SecureContext, Secure-only, and TF-M cohorts without treating directory reuse
as implementation or silently excluding unresolved feature combinations.

```text
ARM_CM55 feature cohorts/STM32N6
  -> optional ARM_CM85/STM32V8
  -> delete transitional_v8m
  -> full -O0/-Og/-O2/-Os/-O3 and final-LTO disassembly cohort
  -> final software freeze
```

Each arrow is a checkpoint. A port family is not followed by Context extraction
until its applicable parity ledger, generated-code proof, ELF/ABI/cohort proof,
negative tests, and available hardware tests are complete.

## Exit Gate Before Context Extraction

Context extraction may start only when:

1. Every required STM32 profile is implemented or explicitly excluded.
2. Every included profile has no known software gap in frame layout,
   save/restore, SVC/PendSV, feature state, ABI/cohort, or generated code.
3. `tools/compile_matrix.ps1` passes from a clean tree.
4. Every claimed exact CPU/ABI/FPU/MVE/MPU/security/errata cohort passes the
   final optimization grid at `-O0`, `-Og`, `-O2`, `-Os`, and `-O3`, and its
   final linked-ELF disassembly passes at `-O2 -flto` and `-Os -flto`.
5. Every profile without current board evidence is explicitly labeled
   `hardware validation deferred` and has no hardware support claim.
6. The pinned release-blocking CI job passes against the exact pre-extraction
   commit and retains the evidence defined in `CI_VALIDATION_PLAN.md`.
7. The stable pre-extraction commit is recorded.

After extraction, the same generated-assembly, ELF/vector, ABI/cohort,
negative-link, and full optimization/LTO suites are repeated against that
stable checkpoint. Available hardware suites remain a separate evidence layer.
The extracted baseline is accepted only when no unintended software behavior
change is found.
