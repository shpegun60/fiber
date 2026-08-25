# STM32 Port Freeze Inventory

## Status

This document is the current planning ledger for completing the selected-port
baseline before the Context/Fiber extraction defined in
`CONTEXT_FIBER_ARCHITECTURE.md`.

It is not a support claim and it does not replace a per-port
`FREERTOS_PARITY.md` ledger. A profile is complete only when its own ledger,
generated-code proof, link/ELF proof, and applicable hardware evidence agree.

Inventory snapshot:

```text
fiber branch:          v2
audited tree:          2743fc6401f551195f1d8896130715f05ecc4500
FreeRTOS reference:    a50edad08b29052631aa469d4df6e6ec7ff68878
toolchain:             GNU Arm Embedded GCC from STM32CubeIDE 2.0.0
matrix result:         PASS
assembly parity:       PASS at -O2 and -Os
```

The inventory commit is documentation-only. It does not change the runtime,
frame layout, SVC/PendSV handlers, selected-port ABI, or generated code.

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

Nine complete parity profiles currently have selected-port source groups and
pinned FreeRTOS parity ledgers:

| Fiber profile | Main covered mechanics | Current claim |
| --- | --- | --- |
| `ARM_CM0` | M0 and M0+ privileged Thumb-1 start/save/restore, separate VTOR traits | compile/assembly/ELF validated |
| `ARM_CM3` | privileged ARMv7-M SVC/PendSV and BASEPRI path | compile/assembly/ELF validated |
| `ARM_CM4` | privileged M4/M4F conditional FP context | compile/assembly/ELF validated |
| `ARM_CM7/r0p1` | privileged M7/M7F conditional FP context and errata 837070 policy | compile/assembly/ELF validated; refreshed H7 run pending |
| `ARM_CM3_MPU` | protected context, MPU replacement, unprivileged yield/return | compile/assembly/ELF validated |
| `ARM_CM4_MPU` | M4F/M7F protected FP context, MPU replacement, M7 errata policy | compile/assembly/ELF validated |
| `ARM_CM23_NTZ/non_secure` | exact non-MPU Baseline NTZ frame and ignored PSPLIM slot | compile/assembly/ELF validated; reference-portability profile |
| `ARM_CM33_NTZ/non_secure` | exact non-MPU/no-FPU Mainline NTZ frame with PSPLIM | compile/assembly/ELF validated |
| `ARM_CM33F_NTZ/non_secure` | exact non-MPU FP Mainline NTZ frame with PSPLIM | compile/assembly/ELF validated |

The current matrix pairs all nine source groups against the pinned FreeRTOS
reference where applicable and passes the existing directional ABI, exact
cohort, vector, archive, section-GC, LTO, and negative-link proofs.

`ARM_CM0_MPU` is additionally present as an explicit non-selectable staged
profile. It has its own pinned ledger and slice-local generated-assembly/ELF
proof, but it is intentionally outside the complete-profile count until its
protected PendSV and eight-operation runtime ABI are implemented together.

This does not promote the profiles without current board evidence to
`hardware validated`.

## Remaining Port-Freeze Work

### 1. ARM_CM0 MPU

The pinned FreeRTOS `GCC/ARM_CM0` directory contains a distinct optional
MPU/unprivileged branch. The current `ARM_CM0` profile intentionally implements
only the privileged branch.

`ARM_CM0_MPU` slices 1-4 now freeze an exact build-selected type/layout/trait
and cohort contract, port-owned construction/seal, strict MPU encoder, linker
isolation, global MPU image, strong SVC first start, unprivileged task return,
one-time MPU activation/readback, and the reference-derived Thumb-1 first
restore. It preserves the reference raw 20-word protected image while
deliberately replacing broad unprivileged peripheral access with one exact
256-byte current-context aperture, leaving three configurable regions plus the
stack. The default image disables regions 0-2, uses region 3 for the exact raw
stack RW/XN range, and builds regions 4-7 from ten required linker boundaries.

The profile remains non-selectable and has no `PendSV_Handler`, accepted yield
service, or forward runtime ABI. Its `-O2`/`-Os` and LTO proof covers direct
slot-11 SVC vector ownership, exact first restore, first activation/readback,
VTOR-present and VTOR-absent cohorts, and linker isolation. It is software
evidence only, not a hardware support claim.

Remaining work is the protected PendSV save/copy/scheduler/MPU-replace/restore
path, then the eight forward runtime ABI operations and archive/ELF negative
proofs, followed by hardware validation.

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

### 3. Cortex-M33 TrustZone And SecureContext

The TrustZone-capable Non-secure scheduler profile is distinct from the current
NTZ profile. It needs the matching security-domain EXC_RETURN, banked register
policy, vector source, NSACR/CPACR policy, and the versioned SecureContext
companion defined in `TRUSTZONE_SECURE_CONTEXT_CONTRACT.md`.

A fiber without an attached SecureContext must retain the ordinary Non-secure
switch path. A fiber with an attachment must save and load the matching Secure
state without inheriting another fiber's state.

### 4. Cortex-M33 TF-M Integration

TF-M is an alternative Secure provider, not another copy of the scheduler port.
It uses the matching NTZ-style CPU mechanics plus an explicit TF-M integration
artifact. It must not be linked with the fiber-owned SecureContext companion for
the same profile.

### 5. Cortex-M55 / STM32N6

`transitional_v8m` currently provides compile-only bring-up coverage. It is not
a Cortex-M55 production port.

The concrete STM32N6 profile must own and prove:

```text
ARMv8.1-M Mainline first start and PendSV
FPU and MVE context state
MPU and privilege state
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

### 7. Final Cleanup And Hardware Checkpoints

After concrete v8-M/v8.1-M ports replace its remaining test roles:

```text
delete transitional_v8m
rerun the complete compile and assembly matrix
rerun current H7 normal/FPU/trap/vector validation
record every unavailable board proof explicitly
freeze a branch with no known software gap
```

Hardware evidence is independent of compile, assembly, host, emulator, and ELF
evidence. A profile without a matching board may be frozen as
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

```text
ARM_CM0_MPU
  -> ARM_CM33_MPU
  -> ARM_CM33 TrustZone/SecureContext
  -> ARM_CM33 TF-M integration
  -> ARM_CM55/STM32N6
  -> optional ARM_CM85/STM32V8
  -> delete transitional_v8m
  -> final software and available hardware freeze
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
4. Hardware-unavailable profiles are labeled without a hardware claim.
5. The stable pre-extraction commit is recorded.

After extraction, the same generated-assembly, ELF/vector, ABI/cohort,
negative-link, and available hardware suites are repeated against that stable
checkpoint. The extracted baseline is accepted only when no unintended runtime
behavior change is found.
