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
| `ARM_CM33_MPU/non_secure` (staged) | `GCC/ARM_CM33_NTZ/non_secure`, MPU enabled | protected SVC 70/71/72 provenance, first MPU activation/restore, protected PendSV frame copy, BASEPRI scheduler bridge, atomic MAIR0/context-MPU replacement, protected restore |
| `ARM_CM33F_NTZ/non_secure` | `GCC/ARM_CM33_NTZ/non_secure`, `configENABLE_FPU=1` | paired basic `pxPortInitialiseStack()` geometry, SVC first start, and FP-aware PSPLIM PendSV |
| `ARM_CM3_MPU` | `GCC/ARM_CM3_MPU` | SVC dispatch, first MPU restore, protected PendSV |
| `ARM_CM4_MPU` | `GCC/ARM_CM4_MPU` | SVC dispatch, first MPU/FP restore, protected FP PendSV |

The script derives the port inventory from every `fiber/port/**/fiber_port.c`.
The inventory must exactly match either a paired profile above or an explicit
non-selectable staged runtime profile, and every directory must contain
`FREERTOS_PARITY.md`. A staged profile may implement only the mechanisms named
in its own record; it never inherits a complete runtime claim. The script fails
if a staged profile becomes selectable, is also listed as complete parity, or a
new port source is neither paired nor explicitly staged. Adding a port source
therefore cannot silently reduce coverage.

The staged `ARM_CM33_MPU/non_secure` profile is compiled against the pinned
8- and 16-region MPU reference configurations at both optimization levels. Its
executable proof covers the protected first SVC transition and the private
PendSV save/select/MAIR0-plus-MPU-replace/restore engine. It remains staged and
is intentionally not counted as a complete runtime profile until the frozen
forward ABI/archive cohort is activated in a later isolated slice.

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

### FAP-CM33-MPU-STAGED-SVC

The staged M33 MPU profile owns strong SVC and PendSV handlers but deliberately
does not export the forward runtime ABI. Its SVC dispatcher proves vector and
frame provenance, installs and reads back the four linker-derived global
regions while the MPU is disabled, then passes and revalidates the original
SVC `EXC_RETURN` in naked restore.
The restore writes MAIR0 and the selected context's RNR `4..N-1` pairs, enables
the exact `MPU_CTRL=ENABLE|PRIVDEFENA` image, validates the active image, and
only then restores PSP, PSPLIM, CONTROL, core registers, protected hardware
frame, and the selected context's final `EXC_RETURN`. FreeRTOS performs
equivalent first-task machinery across
`prvSetupMPU()` and `vRestoreContextOfFirstTask()`; Fiber keeps the split
explicit so the selected context and SVC origin remain independently checked.
SVC 71 is accepted only from the exact private syscall-flash yield veneer and
only requests PendSV; it does not run scheduler policy. This difference does
not claim public MPU API, selected-port runtime activation, or hardware
runtime support.

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
separate ELF and hardware validation requirements.
