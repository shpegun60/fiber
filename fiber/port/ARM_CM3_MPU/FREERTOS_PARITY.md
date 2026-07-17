# ARM_CM3_MPU FreeRTOS Parity Record

## Status

This is the frozen reference audit and staged implementation record for the
exact `ARM_CM3_MPU` profile. Slice 7 makes the complete source group selectable
through an exact build-selected manifest. It remains compile/link-covered only
and creates no runtime or STM32 hardware support claim.

Implementation slices 1 through 4, slice 6, and the slice-7 exact selection
contract are compile/link-covered. Slice 5 remains intentionally absent because
the current safe uniform policy needs no heterogeneous pre-start MPU
configuration API. The directory owns the public type-only context, port-owned
boot type, private `fiber_portmacro.h`
dictionary, exact trait values, context-cohort identity, exhaustive 32-bit
layout assertions, validated MPU encoding, the exact linker memory contract,
safe default region construction, initial protected context construction, and
immutable sealing. It now also owns the exact three-service SVC namespace,
strong SVC dispatcher, first-context MPU activation and restore, unprivileged
yield veneer, unprivileged task-return veneer, strong protected PendSV
save/switch/restore engine, and all eight frozen forward runtime operations.
`fiber_port_select.h` and its architecture-class profiles deliberately remain
unchanged. Exact selection comes from the build-owned include path and source
group, while `fiber_port_selected.h` resolves `fiber_port_types.h` through that
path.

The audit is intentionally completed before copying or adapting implementation
logic. Every reference file, public macro family, port function, saved-context
field, SVC service class, linker dependency, and excluded FreeRTOS kernel API is
accounted for below.

## Slice 1 Frozen Layout

The compile-only build manifest is exact and fail-closed:

```text
CPU                         Cortex-M3 / ARMv7-M
compiler ABI                GCC-compatible, Thumb, soft-float
CMSIS core                  __CORTEX_M == 3
MPU                         __MPU_PRESENT == 1
VTOR                        __VTOR_PRESENT == 1
FPU                         absent and unused
NVIC priority bits          4 in the frozen compile manifest
selection                   FIBER_PORT_BUILD_SELECTED == 1
runtime-selectable          no at the slice-1 checkpoint
```

The public type-only header remains CMSIS-free and compiles as C and C++. The
private compile dictionary consumes the shared compiler/settings contract and
defines the exact future assembly layout:

```text
FiberContext offset 0       protected-context cursor
FiberContext offset 4       four contiguous RBAR/RASR pairs (32 bytes)
FiberContext offset 36      20-word protected context image (80 bytes)
FiberContext offset 116     immutable FiberPortBoot record (80 bytes)
FiberContext size/alignment 200 bytes / 8 bytes
```

The protected image freezes every word offset for CONTROL, r4-r11,
EXC_RETURN, PSP, copied r0-r3/r12/LR/PC/xPSR, and the one-past cursor-limit
slot. The boot record additionally seals initial CONTROL policy and the exact
four-region count. Port identity `0x434D334D` (`CM3M`), layout version
`0x00010001`, and feature identity `0x00001C04` are distinct from privileged
`ARM_CM3`.

The feature bits are explicit: `0x00000004` is the CONTROL slot,
`0x00000400` is the MPU register image, `0x00000800` is protected hardware
frame storage, and `0x00001000` is unprivileged-context support.

`tools/compile_matrix.ps1` proves the standalone type layout, exact cohort
symbol, C/C++ header compatibility, and rejection of Cortex-M4, absent MPU, or
wrong CMSIS core identity. It also proves that no switch/handler source and no
global selector route exists in this slice.

## Slice 2 MPU Construction Contract

Slice 2 adds `fiber_port_boot.h` and `fiber_port_boot.c` without adding
`fiber_port.c`, `fiber_port_exception.c`, `SVC_Handler`, `PendSV_Handler`, or a
global selector route. It implements the already frozen
`fiber_port_context_init()` operation but the profile cannot be selected by a
normal build yet.

The selected linker script must define all ten boundaries below. They are
addresses, not C objects, and there are no weak or inferred defaults:

```text
__fiber_mpu_unprivileged_code_start__
__fiber_mpu_unprivileged_code_end__
__fiber_mpu_privileged_code_start__
__fiber_mpu_privileged_code_end__
__fiber_mpu_privileged_data_start__
__fiber_mpu_privileged_data_end__
__fiber_mpu_current_context_slot_start__
__fiber_mpu_current_context_slot_end__
__fiber_mpu_unprivileged_ram_start__
__fiber_mpu_unprivileged_ram_end__
```

The four programmed global ranges must each be a non-empty, power-of-two MPU
region of at least 32 bytes with an exactly aligned base. Code and RAM ranges
may not overlap. A privileged code range may be disjoint from or wholly nested
inside the broader unprivileged executable range because higher-numbered MPU
region 6 overrides region 5; partial overlap is rejected. Privileged data and
the unprivileged RAM envelope must be disjoint.

Safe global policy is exact:

```text
region 4  exact 32-byte current-slot aperture, unprivileged read-only and XN
region 5  unprivileged read-only executable code
region 6  privileged read-only executable code
region 7  privileged-only read-write execute-never data
```

Region 4 replaces the broad FreeRTOS peripheral mapping. The common-owned
current slot lives in its standard `.bss.fiber_runtime_current_context_slot`
subsection; the MPU linker manifest must place that one object in an exact
32-byte aperture and must not place hook, context, scheduler, or other runtime
state there. Startup must zero the complete 32-byte aperture as part of its BSS
initialization; a stale nonzero slot also fails the common pre-start lifecycle
check. This lets portable `fiber_current()` read current identity while
region 7 keeps all other privileged runtime metadata unreadable and unwritable
from unprivileged Thread mode.
The active vector table's initial MSP must be 8-byte aligned, and the complete
start-SVC hardware frame must lie inside this privileged-data range.
Before selection is enabled, the integration proof must also reserve and verify
enough privileged MSP headroom for the deepest SVC/PendSV validation and
scheduler call graph. Frame placement alone is not a sufficient MSP proof.

Safe per-context policy is also exact:

```text
regions 0-2  disabled
region 3     the complete raw stack allocation, unprivileged RW and XN
CONTROL      0x00000003 (Thread/PSP, unprivileged)
```

The initial implementation deliberately rejects stack-region widening. The raw
stack allocation must itself be a power of two, at least 32 bytes, and aligned
to its complete size. This prevents MPU rounding from exposing an adjacent
fiber stack or application object. A build can satisfy this without changing
portable API calls by placing each stack input section at the required linker
alignment. `FiberContext` storage must be wholly inside privileged data, the
raw stack wholly inside unprivileged RAM, and the entry/return veneer wholly
inside unprivileged executable code but outside privileged code.

The initial protected image follows the audited FreeRTOS 20-word storage
geometry: 19 active words hold CONTROL, r4-r11, EXC_RETURN, PSP, and the copied
basic hardware frame; the final word is the explicit spare/one-past cursor
target. The PSP reserves one complete basic hardware frame on the
unprivileged stack. The stacked PC is Thumb-normalized, xPSR.T is set, LR
targets the slice-3 port-owned unprivileged return veneer, and r9 is seeded
from the live platform value so a process-wide static-base ABI is preserved
when the integration toolchain reserves r9 for that role. Under the ordinary
AAPCS configuration r9 remains a general callee-saved register and its initial
value has no platform-static-base meaning.

The boot hash seals all immutable boot/ABI fields, initial CONTROL policy, the
four-region count, and all four RBAR/RASR pairs. It intentionally excludes the
protected saved-register image and live cursor because PendSV will mutate them.
Full construction validation proves privileged context placement before the
first context dereference, exact stack derivation, canary, code provenance,
disabled default regions, exact stack encoding, and the final seal.

At the slice-2 checkpoint, the compile matrix proved:

```text
construction object compiles for Cortex-M3/soft-float only
undefined surface is limited to linker symbols, panic, cohort, and return veneer
all construction functions live in privileged text
synthetic exact-memory ELF links with --gc-sections
missing any required linker boundary fails the link
no SVC_Handler, PendSV_Handler, or runtime schedule symbol is introduced
global selectors still cannot reach ARM_CM3_MPU
```

This proof does not execute the encoder or program a hardware MPU. Runtime
register programming/readback, SVC/PendSV, MemManage faults, and board behavior
remain later slices.

## Slice 3 Unified SVC And First Activation Contract

Slice 3 adds `fiber_port_private.h` and `fiber_port.c`, but deliberately adds no
`PendSV_Handler` and no selector route. The exact port-owned service namespace
is part of the CPU ABI and cannot be overridden by the application:

```text
70  first-context start
71  unprivileged schedule/yield request
72  unprivileged task return
```

Compile-time checks prove that all services fit the SVC imm8 encoding and are
pairwise distinct. The strong `SVC_Handler` derives the hardware frame from
active `EXC_RETURN`, loads the common-owned current slot through the frozen
assembly-only load sequence, and tail-branches to the privileged dispatcher.
The dispatcher validates Handler identity, zero PRIMASK/BASEPRI/FAULTMASK,
and exact F9/FD EXC_RETURN before dereferencing the selected frame. It then
validates frame alignment, xPSR.T, stacked IPSR, absence of alignment padding, the
`0xDFxx` opcode, exact immediate, origin stack, current context, and the exact
post-SVC continuation label. Unknown, wrongly originated, or forged services
fail closed.

First start is accepted only from privileged Thread/MSP with `EXC_RETURN` F9
and CONTROL 0. The naked start path validates masks, rewinds MSP from the active
VTOR table, clears stale PendSV, and invokes service 70. The dispatcher then:

```text
validates the selected restore context and immutable MPU image
requires an eight-region unified Cortex-M3 MPU
disables the MPU with ordering barriers
programs per-context regions 0-3 and global regions 4-7
enables MemManage faults
enables MPU with PRIVDEFENA
reads back all eight regions, MPU_CTRL, and SHCSR
rewinds MSP again to discard the start-SVC frame and C dispatcher stack
copies the protected hardware frame to PSP
restores CONTROL, r4-r11, EXC_RETURN, and the live context cursor
returns to unprivileged Thread/PSP through exception return
```

The unprivileged schedule veneer contains only `svc 71` followed by `bx lr`.
Only privileged SVC code writes `PENDSVSET`. The unprivileged return veneer
contains only `svc 72` and a non-returning local loop; validated service 72
reaches the common task-return sink from privileged Handler mode. The exact
continuation symbols are provenance markers, not callable public functions.

The compile matrix proves the exact SVC object undefined-symbol surface,
privileged/unprivileged section ownership, three and only three generated SVC
instructions, instruction shape of both unprivileged veneers, MSP/VTOR/stale
PendSV setup in the start path, the second FreeRTOS-style MSP rewind before PSP
restore, assembly-only current-slot loading, a strong SVC symbol, and vector
slot 11 with the Thumb bit set in a synthetic exact-map ELF. The same ELF proves
one 32-byte current-slot output section containing the exact common slot symbol.
It also proves that no `PendSV_Handler` exists and that global selection still
cannot reach this profile.

These are compile, generated-code, link, and ELF proofs only. No SVC service,
MPU register programming, unprivileged execution, or fault path has yet run on
hardware. The profile cannot become selectable until the later complete
ABI/archive/LTO proof and integration slices pass.

## Slice 4 Protected PendSV Contract

Slice 4 adds the strong `PendSV_Handler` to the same privileged `fiber_port.c`
object as SVC, matching the FreeRTOS `port.c` ownership model. It still adds no
global selector route and does not activate the generic forward runtime ABI.

The handler accepts only the exact unprivileged Thread/PSP basic-frame state:

```text
IPSR       14 (PendSV)
EXC_RETURN 0xFFFFFFFD
CONTROL    0x00000003
PRIMASK    0
BASEPRI    0 before the scheduler envelope
FAULTMASK  0
PSP        exact live hardware-frame address inside current stack
MPU        enabled with PRIVDEFENA and the sealed current/global image active
```

Before reading the current context cursor, privileged C preflight validates the
complete context extent, immutable seal, canary, protected running-state cursor,
PSP bounds, basic hardware frame, executable PC, MPU type/control, MemManage
enable, all four current regions, and all four global regions. A direct or
foreign PendSV therefore fails closed before mutable context fields are used.

The generated save sequence preserves the exact reference 20-word geometry:

```text
protected words 0..9    CONTROL, r4-r11, EXC_RETURN
protected word 10       original PSP after hardware exception stacking
protected words 11..18  copied r0-r3, r12, LR, PC, xPSR
word 19 address         one-past restore cursor target
```

No software frame is placed on the unprivileged stack. The basic hardware frame
already created by exception entry is copied into privileged context storage,
and the live cursor advances from `control` to `cursor_limit`.

The matrix separately freezes the initial live-r9 seed, compiles and inspects a
`-ffixed-r9` generated-code probe for the reserved static-base ABI, and freezes
the exact exception priority contract used by this profile: PendSV is
written/read back at the lowest implemented priority and SVCall at priority
zero.

The scheduler bridge executes in privileged PendSV under the exact selected
`BASEPRI`. In addition to the common candidate lifecycle, this port snapshots
and validates PRIMASK, BASEPRI, FAULTMASK, CONTROL, IPSR, PSP, VTOR, MPU_CTRL,
and MemManage-enable state across the user hook. It validates the returned
protected context before common publishes the next current identity.

Per-context regions 0-3 are then replaced while both BASEPRI and PRIMASK are
active. FreeRTOS disables the MPU while writing these pairs; fiber additionally
uses PRIMASK for the short disabled/partial-image interval so no configurable
interrupt observes it. Regions 4-7 remain global, MPU and MemManage state are
re-enabled and read back, and all eight regions are checked before restore.
BASEPRI is cleared while PRIMASK still blocks preemption.

Restore copies the selected protected hardware frame back to its newly mapped
PSP, restores CONTROL/r4-r11/EXC_RETURN, transitions only the live cursor back
to `control`, re-enables interrupts, and exception-returns. It does not rewrite
the selected saved register image after restore.

The compile matrix proves the strong slot-14 handler, exact current-slot load,
preflight-before-context-field ordering, protected save/copy instruction
geometry, scheduler-before-MPU ordering, PRIMASK around MPU replacement,
BASEPRI clear only after replacement, protected restore order, and slot 14
Thumb-vector resolution in the synthetic exact-map ELF. These remain software
proofs only.

## Slice 6 Forward ABI And Integration Contract

Slice 6 activates all eight mandatory common-to-port operations inside the
still non-selectable profile. Startup now validates privileged Thread/MSP,
zero interrupt masks, an exact disabled eight-region MPU, VTOR and strong
handler ownership, implemented NVIC priority bits, PRIGROUP, fault policy,
PendSV/SVC priority readback, and stale-PendSV clearing. The first scheduler
selection runs inside the selected BASEPRI envelope, validates CPU-state
preservation and the returned protected context, then restores BASEPRI before
the first SVC transfer.

The minimal common call chain that may execute from unprivileged Thread mode is
explicitly marked with `.text.fiber_runtime_thread_functions`. The selected MPU
linker extracts that section together with the port yield/return veneers into
unprivileged RX before its privileged `.text*` catch-all. The `.text.*` prefix
keeps ordinary non-MPU linker scripts compatible. Arbitrary unprivileged
application entry placement remains an application linker/build responsibility;
the synthetic LTO proof deliberately compiles the unchanged portable
application fixture as a separate non-LTO translation unit so its per-function
sections remain auditable.

The matrix now links the unchanged five-function portable application against
common runtime plus the complete MPU port from a static archive in normal and
LTO modes with section GC. It proves exactly one eight-function ABI, reverse
ABI v1 resolution, one exact cohort and external expectation relocation,
strong SVC/PendSV extraction over startup weak aliases, vector slots 11/14,
duplicate-strong failure, privileged/unprivileged code placement, privileged
context storage, exact aligned unprivileged stacks, the 32-byte current slot,
and finite compiler stack-usage artifacts. These are synthetic software proofs;
they neither execute the MPU nor establish concrete-board MSP headroom.

Global selection remains deliberately disabled. Slice 7 is the only step that
may expose this source group as compile-covered, and slice 8 still requires the
complete hardware suite before any runtime or STM32 support claim.

## Slice 7 Exact Build Selection Contract

Slice 7 exposes the already complete source group only through the exact
FreeRTOS-style build manifest:

```text
defines:
  FIBER_PORT_BUILD_SELECTED=1
  FIBER_PORT_ARMV7M=1

include path before fiber/port:
  fiber/port/ARM_CM3_MPU

selected sources:
  fiber/port/ARM_CM3_MPU/fiber_port.c
  fiber/port/ARM_CM3_MPU/fiber_port_boot.c

build-owned cohort expectation:
  fiber/port/fiber_port_context_cohort_expectation.c
```

The integration must also provide every exact linker boundary and retain the
cohort expectation section described below. `FIBER_PORT_ARMV7M` is only an
architecture compatibility gate. No `FIBER_PORT_ID_*` or MPU auto-detection
route is introduced: auto, explicit architecture-profile, and force modes
continue to select privileged `ARM_CM3`, even when CMSIS reports an MPU.

The matrix now compiles the public `fiber_core.h` facade through the exact MPU
include path and proves its 200-byte, 8-byte-aligned protected context and
exact `ARM_CM3_MPU` diagnostic name. It separately proves that ARMv7-M auto
selection with `__MPU_PRESENT == 1` still exposes privileged `ARM_CM3`, and
that directly compiling the MPU dictionary without build-selected mode fails.
The existing normal/LTO archive, exact-map ELF, vector, section, cohort, and
duplicate-handler proofs remain mandatory.

This changes selection eligibility, not runtime validation status. Slice 8 is
still required before claiming a working Cortex-M3 MPU target or STM32 family.

## Frozen Reference

The local reference is FreeRTOS Kernel commit:

```text
a50edad08b29052631aa469d4df6e6ec7ff68878
```

Exact reference files:

| File | Lines | SHA-256 |
| --- | ---: | --- |
| `portable/GCC/ARM_CM3_MPU/portmacro.h` | 395 | `ff720aedbe44344752224173b3bba316d675ad47c44103bbc8cab984b0a98a68` |
| `portable/GCC/ARM_CM3_MPU/port.c` | 1593 | `b94311759d4b807017f56669bde818215076a20c301a10d3c9dae3d736676` |
| `portable/GCC/ARM_CM3_MPU/mpu_wrappers_v2_asm.c` | 2067 | `6b5110e0c14ba78c20d43c1edf17e5ac2311a6af0413d6aaab5df59edb2655c2` |

FreeRTOS CMake selects `port.c` and `mpu_wrappers_v2_asm.c` as the source
group and adds the directory as the include path for `portmacro.h`. The source
group also depends on kernel-owned artifacts that are outside the directory:

| FreeRTOS dependency | Fiber decision |
| --- | --- |
| `FreeRTOS.h`, `task.h` | Replaced by the five-function public fiber API, selected public context type, and frozen runtime ABI. |
| `mpu_syscall_numbers.h` | Not imported. The selected fiber port owns a small compile-time-checked SVC namespace for start, yield, return, and explicitly enabled extension services. |
| `portable/Common/mpu_wrappers_v2.c` | Excluded. Fiber does not expose FreeRTOS kernel APIs or its system-call implementation table. |
| `queue.h`, `timers.h`, `event_groups.h`, `stream_buffer.h`, `mpu_prototypes.h` | Excluded. Those are FreeRTOS kernel service APIs, not CPU context-switch mechanics. |
| `pxCurrentTCB`, `xTaskGetMPUSettings()` | Replaced by common-owned current-context publication and the selected port's private `FiberContext` layout. |
| `vTaskSwitchContext()` | Replaced by the protected user scheduler bridge. |
| `xTaskIncrementTick()` | Excluded. Tick, sleep, wake, and time policy remain scheduler-owned. |
| FreeRTOS privileged/syscall/flash/RAM linker symbols | Replaced by an explicit fiber MPU linker contract and exact build manifest. No permissive inferred memory map is accepted. |

## Scope Decision

The port adapts the FreeRTOS Cortex-M3 MPU CPU engine, not the FreeRTOS kernel.
The mandatory fiber surface remains:

```text
five public fiber functions
eight common-to-port runtime functions
reverse runtime ABI v1
```

MPU mechanics required to run the selected profile are mandatory and private.
They do not become optional calls from portable application code. A separate
`fiber_port_mpu_abi.h` may expose pre-start policy configuration to deliberate
profile-integration code, but it is not required for the profile's safe default
and is never included by `fiber_core.h`.

The following FreeRTOS facilities are outside the current fiber scope:

```text
FreeRTOS task, queue, timer, event-group, and stream-buffer API wrappers
kernel-object ACLs
generic privileged Thread-mode system-call execution
SysTick ownership and preemptive tick scheduling
public nested critical-section API
FromISR scheduler API
dynamic task deletion and scheduler shutdown
```

They remain documented exclusions. They must not silently reappear as partial
stubs or as hidden dependencies of the CPU port.

## Non-Negotiable Architecture Findings

The reference proves that `ARM_CM3_MPU` is not the privileged `ARM_CM3` port
with MPU register writes appended:

1. The saved `CONTROL`, r4-r11, EXC_RETURN, PSP, and a copy of the basic
   hardware exception frame live in privileged task metadata, not solely on the
   unprivileged PSP stack.
2. PendSV copies the hardware frame from the unprivileged stack into protected
   context storage on save and copies it back before exception return.
3. Four task-specific MPU regions are restored on every switch: one stack
   region and three configurable regions. Four global regions are programmed at
   startup for the exact current-slot aperture, unprivileged code, privileged
   code, and privileged data.
4. `CONTROL.nPRIV` is context state. An unprivileged restore must not inherit
   privilege or mask state from another fiber.
5. Unprivileged Thread mode requests a switch with SVC. It must never write
   `SCB->ICSR` or read privileged mask state as proof before entering Handler
   mode.
6. The scheduler hook executes in privileged PendSV context. Its code, user
   state, current-context slot, and complete call graph are privileged runtime
   assets. The synthetic ELF proof checks the concrete fixture hook and user
   object; each real integration must provide the same linker placement proof.
7. Writable stacks and application data cannot share an MPU region with
   writable context, scheduler, or port state. Region-size rounding must not
   widen a stack region over privileged metadata.
8. A returned unprivileged fiber cannot branch directly to privileged common
   text. Its synthetic LR targets an unprivileged port veneer that raises the
   dedicated return SVC; only validated Handler mode reaches
   `fiber_internal_task_return()`.
9. The MPU profile is a different context cohort, port ID, layout version,
   build manifest, linker contract, and hardware-validation claim from
   privileged `ARM_CM3`.

## Native Source Group

The implementation target follows the established concrete-port role layout:

```text
fiber/port/ARM_CM3_MPU/
  FREERTOS_PARITY.md
  fiber_port_types.h
  fiber_port_boot_types.h
  fiber_port_boot.h
  fiber_portmacro.h
  fiber_port_private.h
  fiber_port.c
  fiber_port_boot.c
  optional fiber_portasm.h / fiber_portasm.c if separation improves auditing
  optional fiber_port_mpu_abi.h / fiber_port_mpu.c for non-default policy
```

Like the audited FreeRTOS GCC port, `fiber_port.c` owns both strong exception
handlers. A separate exception source is not required for this profile.

Mandatory MPU programming remains in private selected-port files even if it is
split into an additional clearly named private source. The optional MPU ABI
contains only profile-policy configuration; it does not own the save/restore
engine.

## Saved Context And MPU Layout Mapping

| FreeRTOS `xMPU_SETTINGS` field | Fiber ownership | Decision |
| --- | --- | --- |
| `xRegion[4]` | Port-private region register image | Adopt the four RBAR/RASR pairs required by the v7-M restore sequence. Keep them privileged-writable and validate region numbers, enable bits, alignment, size, permissions, overlap, and overflow before sealing. |
| `xRegionSettings[4]` | Optional policy-validation metadata | Adapt only if the optional buffer-access policy needs software range checks. It is not needed by the base switch engine. |
| `ulContext[20]` | Port-private protected saved context | Adopt the semantic layout: CONTROL, r4-r11, EXC_RETURN, PSP, and copied r0-r3/r12/LR/PC/xPSR. Freeze exact offsets with static assertions and assembly probes. |
| `ulTaskFlags` privileged bit | Immutable selected-context privilege policy | Adapt as an explicit sealed policy value. Do not expose a writable application flag after publication. |
| `ulTaskFlags` stack-padding bit | System-call-stack bookkeeping | Exclude while generic Thread-mode system-call enter/exit is excluded. Normal exception-frame padding is still validated dynamically. |
| `xSystemCallStackInfo` | Generic FreeRTOS syscall state | Exclude from the base profile. Dedicated start/yield/return SVC services execute in Handler mode and do not need a privileged Thread-mode syscall stack. |
| kernel-object ACL | FreeRTOS kernel policy | Exclude. A future object-capability layer requires its own application-level abstraction and audit. |

The initial fiber implementation must not reuse the privileged `ARM_CM3`
`sp + FiberPortBoot` layout. The selected public type may remain complete for
storage allocation, but all fields that control restore, MPU programming, or
scheduler ownership must be inaccessible to unprivileged writes.

## `portmacro.h` Audit: Types And Generic Kernel Policy

| FreeRTOS item | Fiber mapping | Decision |
| --- | --- | --- |
| `PORTMACRO_H` | Profile-specific fiber include guard | Replace with the concrete selected-port header guard. |
| `portCHAR`, `portFLOAT`, `portDOUBLE`, `portLONG`, `portSHORT` | Fixed-width C types | Excluded compatibility aliases. |
| `portSTACK_TYPE`, `StackType_t` | `uint32_t` words in selected private context/frame code | Adapt without exporting FreeRTOS types. |
| `portBASE_TYPE`, `BaseType_t`, `UBaseType_t` | Explicit `uint32_t`, `uintptr_t`, `size_t`, and bool-like values | Adapt without kernel-wide aliases. |
| `TickType_t`, `portMAX_DELAY`, `portTICK_TYPE_IS_ATOMIC`, `configTICK_TYPE_WIDTH_IN_BITS` | User scheduler time policy | Excluded from CPU port. |
| `portSTACK_GROWTH` | Selected stack/frame geometry | Adopt downward PSP stack semantics. |
| `portTICK_PERIOD_MS` | User scheduler | Excluded. |
| `portBYTE_ALIGNMENT` | Selected context and exception-frame alignment plus MPU-region requirements | Adopt 8-byte ABI minimum; MPU region base alignment is stricter and validated separately. |
| `portDONT_DISCARD` | Canonical sensitive/used compiler attributes | Adapt through `fiber_compiler.h`. |
| `portTASK_FUNCTION_PROTO`, `portTASK_FUNCTION` | `entry_t` | Replace with plain fiber entry function type. |
| `configUSE_PORT_OPTIMISED_TASK_SELECTION`, `ucPortCountLeadingZeros`, `portRECORD_READY_PRIORITY`, `portRESET_READY_PRIORITY`, `portGET_HIGHEST_PRIORITY` | User scheduler implementation | Exclude from core. A selected CLZ helper may be added only as an optional scheduler utility. |
| `portNOP`, `portINLINE`, `portFORCE_INLINE` | Selected compiler helpers | Adapt only where required by port code. |
| `portMEMORY_BARRIER` | Canonical compiler barrier and explicit DMB/DSB/ISB at architectural boundaries | Adapt and strengthen. |

## `portmacro.h` Audit: MPU Constants And Types

| FreeRTOS item | Fiber mapping | Decision |
| --- | --- | --- |
| `portUSING_MPU_WRAPPERS` | Exact `ARM_CM3_MPU` profile identity | Replace with build-selected profile identity; hardware capability alone never selects it. |
| `portPRIVILEGE_BIT` | Sealed per-context privilege policy | Adapt semantics; do not overload entry-address bits in the public API. |
| `portMPU_REGION_READ_WRITE` | Selected MPU permission encoding | Adopt privately with static value checks. |
| `portMPU_REGION_PRIVILEGED_READ_ONLY` | Selected MPU permission encoding | Adopt privately. |
| `portMPU_REGION_READ_ONLY` | Selected MPU permission encoding | Adopt privately. |
| `portMPU_REGION_PRIVILEGED_READ_WRITE` | Selected MPU permission encoding | Adopt privately. |
| `portMPU_REGION_PRIVILEGED_READ_WRITE_UNPRIV_READ_ONLY` | Selected MPU permission encoding | Adopt privately where the exact policy requires it. |
| `portMPU_REGION_CACHEABLE_BUFFERABLE` | Selected memory-attribute policy | Adopt the audited encoding in this exact profile. A device requiring different memory attributes needs a distinct manifest/profile and hardware proof; this value is not a universal STM32 claim. |
| `portMPU_REGION_EXECUTE_NEVER` | Selected MPU XN encoding | Adopt and require XN for writable stack/data/peripheral regions. |
| `portSTACK_REGION` | Task-specific MPU region slot 3 | Adopt reference slot role unless the exact implementation proves an equivalent mapping. |
| `portGENERAL_PERIPHERALS_REGION` | Global MPU region slot 4 | Replace with an exact 32-byte unprivileged-RO/XN aperture containing only the common current-context slot. Do not grant blanket peripheral access. |
| `portUNPRIVILEGED_FLASH_REGION` | Global unprivileged executable region slot 5 | Adapt through exact linker boundaries and executable policy. |
| `portPRIVILEGED_FLASH_REGION` | Global privileged executable region slot 6 | Adopt through privileged text linker boundaries. |
| `portPRIVILEGED_RAM_REGION` | Global privileged data region slot 7 | Adopt through exact runtime/context linker boundaries as privileged-only RW and XN. Portable `fiber_current()` uses the isolated region-4 aperture instead. |
| `portFIRST_CONFIGURABLE_REGION`, `portLAST_CONFIGURABLE_REGION`, `portNUM_CONFIGURABLE_REGIONS` | Three integration-configurable MPU regions | Adopt as the initial exact profile capacity. |
| `portTOTAL_NUM_REGIONS_IN_TCB` | Stack plus three configurable register pairs | Adopt as four protected per-context region pairs. |
| `xMPU_REGION_REGISTERS` | Private RBAR/RASR pair type | Reimplement in selected type-only form with exact size/alignment assertions. |
| `xMPU_REGION_SETTINGS` | Optional software authorization metadata | Exclude from mandatory switch layout unless buffer-policy support is implemented. |
| `configUSE_MPU_WRAPPERS_V1` | FreeRTOS wrapper-version selector | Exclude. Fiber defines one native SVC contract rather than two FreeRTOS compatibility modes. |
| `configSYSTEM_CALL_STACK_SIZE`, `xSYSTEM_CALL_STACK_INFO` | FreeRTOS generic privileged Thread syscall stack | Exclude from the base profile. |
| `MAX_CONTEXT_SIZE` | Exact protected context-word count | Reimplement as a selected private layout constant, not a public generic macro. |
| `portACL_ENTRY_SIZE_BITS`, `ulAccessControlList` | FreeRTOS kernel-object ACL | Exclude. |
| `portSTACK_FRAME_HAS_PADDING_FLAG` | FreeRTOS syscall frame-copy bookkeeping | Exclude; retain independent hardware-frame padding validation. |
| `portTASK_IS_PRIVILEGED_FLAG` | Sealed context privilege policy | Adapt without exposing mutable FreeRTOS-style flags. |
| `xMPU_SETTINGS` | Complete selected `FiberContext` private MPU/context state | Replace with the exact fiber-owned layout and seal identity. |

## `portmacro.h` Audit: SVC, Yield, Interrupts, And Privilege

| FreeRTOS item | Fiber mapping | Decision |
| --- | --- | --- |
| `portSVC_START_SCHEDULER` | Selected first-start service | Adopt role with a fiber-owned compile-time-checked immediate. |
| `portSVC_YIELD` | Selected unprivileged yield service | Adopt role. Handler validates SVC opcode, immediate, origin frame, Thread/PSP provenance, current lifecycle, and real privileged mask state before pending PendSV. |
| `portSVC_RAISE_PRIVILEGE` | Generic privilege elevation | Do not expose. Privilege is entered only through a specific validated service. |
| `portSVC_SYSTEM_CALL_EXIT` | FreeRTOS generic syscall return | Exclude while generic privileged Thread system calls are excluded. |
| `portYIELD()` | `fiber_schedule()` to selected unprivileged SVC request | Adapt. No pre-SVC SCB write or privileged-register proof. |
| `portYIELD_WITHIN_API()` | Handler-side PendSV publication | Adapt privately after SVC validation. |
| `portNVIC_INT_CTRL_REG`, `portNVIC_PENDSVSET_BIT` | Selected ICSR request helper | Adopt only in privileged Handler/start code. |
| `portEND_SWITCHING_ISR`, `portYIELD_FROM_ISR` | Future scheduler ISR API | Exclude from current runtime. |
| `vPortEnterCritical`, `vPortExitCritical`, `portENTER_CRITICAL`, `portEXIT_CRITICAL` | No public fiber critical API | Exclude. Scheduler bridge critical masking remains private. |
| `portSET_INTERRUPT_MASK_FROM_ISR`, `portCLEAR_INTERRUPT_MASK_FROM_ISR` | Future ISR-safe scheduler policy | Exclude from current API. |
| `portDISABLE_INTERRUPTS`, `portENABLE_INTERRUPTS` | Private BASEPRI helpers | Adapt only inside privileged selected-port paths. |
| `portASSERT_IF_INTERRUPT_PRIORITY_INVALID` | Startup priority proof; future ISR-call validation if an ISR API is added | Adapt startup portion. No dormant ISR API claim. |
| `xIsPrivileged`, `portIS_PRIVILEGED` | Private CONTROL.nPRIV query | Adapt as a sensitive selected-port helper where needed. |
| `vResetPrivilege`, `portRESET_PRIVILEGE` | Private drop-to-unprivileged operation | Adapt only during controlled first restore or explicit privileged integration. |
| `portRAISE_PRIVILEGE` | Unscoped SVC elevation | Exclude. Every service has a distinct immediate and policy. |
| `vPortSwitchToUserMode`, `portSWITCH_TO_USER_MODE` | Pre-start context policy configuration | Replace with sealed per-context policy; no post-publication mutation. |
| `xPortIsTaskPrivileged`, `portIS_TASK_PRIVILEGED` | Selected-context privilege query | Keep private or expose only through optional integration policy if a real use exists. |
| `xPortIsInsideInterrupt` | Selected IPSR checks | Adapt in private environment validation. |
| `vPortRaiseBASEPRI`, `ulPortRaiseBASEPRI`, `vPortSetBASEPRI` | Private scheduler critical envelope | Adapt with synchronized writes, saved prior state, and readback/CPU-state validation. |
| `configALLOW_UNPRIVILEGED_CRITICAL_SECTIONS` | FreeRTOS compatibility policy | Exclude. Fiber does not allow an unprivileged caller to request an unscoped critical section. |
| `configENFORCE_SYSTEM_CALLS_FROM_KERNEL_ONLY` | FreeRTOS wrapper-v1 provenance policy | Exclude with wrapper-v1. Fiber validates every enabled SVC service provenance unconditionally. |

## `port.c` Constant And Global-State Audit

| FreeRTOS item | Fiber mapping | Decision |
| --- | --- | --- |
| `MPU_WRAPPERS_INCLUDED_FROM_API_FILE` | none | Excluded FreeRTOS include remapping control. |
| `configSYSTICK_CLOCK_HZ`, `portNVIC_SYSTICK_CLK`, `portNVIC_SYSTICK_CTRL_REG`, `portNVIC_SYSTICK_LOAD_REG`, `portNVIC_SYSTICK_CURRENT_VALUE_REG` | User scheduler/platform | Excluded. |
| `portNVIC_SHPR2_REG`, `portNVIC_SHPR3_REG` | Selected exception setup | Adapt and verify SVC/PendSV readback; do not claim SysTick. |
| `portNVIC_SYS_CTRL_STATE_REG`, `portNVIC_MEM_FAULT_ENABLE` | MemManage fault policy | Adopt with mandatory readback. |
| `portMPU_TYPE_REG` | MPU capability validation | Adopt and require an exact unified eight-region v7-M MPU for this profile. |
| `portMPU_REGION_BASE_ADDRESS_REG`, `portMPU_REGION_ATTRIBUTE_REG`, `portMPU_CTRL_REG` | Selected MPU register helpers | Adopt privately with DMB/DSB/ISB ordering and readback probes. |
| `portEXPECTED_MPU_TYPE_VALUE` | Exact profile gate | Adopt semantics and fail closed before enabling unprivileged execution. |
| `portMPU_ENABLE`, `portMPU_BACKGROUND_ENABLE` | MPU control policy | Adopt. Background mapping remains privileged-only; unprivileged access must come from explicit regions. |
| `portPRIVILEGED_EXECUTION_START_ADDRESS` | unused reference constant | Exclude unless a concrete linker proof needs an equivalent boundary. |
| `portMPU_REGION_VALID`, `portMPU_REGION_ENABLE` | RBAR/RASR encodings | Adopt privately. |
| `portPERIPHERALS_START_ADDRESS`, `portPERIPHERALS_END_ADDRESS` | Broad FreeRTOS peripheral region | Do not adopt as the safe default. Peripheral access is exact profile integration policy. |
| `portNVIC_SYSTICK_INT`, `portNVIC_SYSTICK_ENABLE`, `portNVIC_SYSTICK_PRI` | SysTick policy | Exclude. |
| `portMIN_INTERRUPT_PRIORITY`, `portNVIC_PENDSV_PRI` | PendSV priority setup | Adapt through implemented-priority-bit probing and readback. |
| `portINITIAL_XPSR` | Initial xPSR.T | Adopt with exact frame validation. |
| `portINITIAL_EXC_RETURN` | Initial Thread/PSP exception return | Adopt `0xFFFFFFFD` for this non-FP ARMv7-M profile. |
| `portINITIAL_CONTROL_IF_UNPRIVILEGED`, `portINITIAL_CONTROL_IF_PRIVILEGED` | Initial CONTROL policy | Adopt SPSEL plus exact nPRIV policy; seal and validate allowed bits. |
| `portSCB_VTOR_REG`, `portVECTOR_INDEX_SVC`, `portVECTOR_INDEX_PENDSV` | Active vector-source validation | Adapt to strong selected handlers and mandatory runtime readback. |
| `portFIRST_USER_INTERRUPT_NUMBER`, `portNVIC_IP_REGISTERS_OFFSET_16`, `portAIRCR_REG`, `portMAX_8_BIT_VALUE`, `portTOP_BIT_OF_BYTE`, `portMAX_PRIGROUP_BITS`, `portPRIORITY_GROUP_MASK`, `portPRIGROUP_SHIFT` | Priority-bit and PRIGROUP validation | Adapt from the current paranoid ARM_CM3 exception implementation. |
| `portPSR_STACK_PADDING_MASK`, `portOFFSET_TO_LR`, `portOFFSET_TO_PC`, `portOFFSET_TO_PSR` | SVC frame decoding | Adopt exact offsets; validate xPSR.T, IPSR, STACKALIGN extent, PC form, and opcode before dispatch. |
| `portSTART_ADDRESS_MASK` | Stacked entry PC | Adopt clear-bit-0 PC plus xPSR.T. |
| `portIS_ADDRESS_WITHIN_RANGE`, `portIS_AUTHORIZED`, `portUINT32_MAX`, `portADD_UINT32_WILL_OVERFLOW` | Optional MPU policy argument validation | Reimplement with overflow-safe half-open ranges if optional buffer authorization is added. |
| `uxCriticalNesting` | FreeRTOS public critical API state | Exclude. |
| `xSchedulerRunning` | Common runtime lifecycle | Replace with common-owned start/select state; do not duplicate in port. |
| `ucMaxSysCallPriority`, `ulMaxPRIGROUPValue`, `pcInterruptPriorityRegisters` | Selected startup/ISR priority proof | Adapt required startup values privately; retain no unused global solely for excluded ISR APIs. |

## `port.c` Function Audit

| FreeRTOS function/path | Fiber function/path | Decision |
| --- | --- | --- |
| `pxPortInitialiseStack()` | `fiber_port_context_init()` plus private frame/MPU builders | Adapt. Build protected CONTROL/core/hardware state, automatic stack region, safe default regions, return-SVC LR, immutable seal, and exact context cohort. Do not write the final restore authority only onto unprivileged stack memory. |
| `vPortSVCHandler()` wrapper-v1 and wrapper-v2 variants | Strong selected `SVC_Handler()` | Replace both modes with one native dispatcher. It owns start, yield, return, and explicitly enabled extension services; unknown or invalid calls panic. |
| `vSVCHandler_C()` | Private validated SVC dispatcher | Adapt and strengthen provenance, frame, immediate, privilege, lifecycle, and mask validation. |
| `vSystemCallEnter()` | none in base profile | Exclude generic privileged Thread-mode syscall execution and frame migration to a system-call stack. |
| `vRequestSystemCallExit()` | none in base profile | Exclude with generic syscall execution. |
| `vSystemCallExit()` | none in base profile | Exclude with generic syscall execution. |
| `xPortIsTaskPrivileged()` | Private selected-context policy check | Adapt only if required by port/integration logic. |
| `prvRestoreContextOfFirstTask()` | `fiber_port_runtime_start_first()` plus private SVC restore | Adapt. Program validated per-context MPU regions before restoring CONTROL and exception-return state. |
| `xPortStartScheduler()` | `fiber_start()` choreography plus `fiber_port_runtime_prepare_start()` | Split. Configure/validate vectors, priorities, MPU type, global regions, MemManage fault, masks, and first context; do not configure ticks. |
| `vPortEndScheduler()` | none | Exclude for static bare-metal runtime. |
| `vPortEnterCritical()`, `vPortExitCritical()` | none public | Exclude nested application critical API. |
| `xPortPendSVHandler()` | Strong selected `PendSV_Handler()` | Adapt core geometry exactly: save CONTROL/r4-r11/EXC_RETURN and copy the basic hardware frame into protected context, call scheduler under BASEPRI, program the next four MPU region pairs, copy its hardware frame back to PSP, restore CONTROL/core state, and exception-return. Add mandatory pointer, seal, bounds, frame, region, mask, and CPU-state validation. |
| `vTaskSwitchContext()` call | Protected fiber scheduler bridge | Replace. Validate returned context before any MPU programming or restore, then publish current through reverse ABI v1. |
| `xPortSysTickHandler()` | user scheduler/platform | Exclude. |
| `vPortSetupTimerInterrupt()` | user scheduler/platform | Exclude. |
| `prvSetupMPU()` | Private startup MPU preparation | Adapt and strengthen. Validate exact MPU type, linker regions, alignment/size/overflow/non-overlap, permissions, XN, MemManage enable, MPU control, and register readback. Do not default to all-peripheral unprivileged access. |
| `prvGetMPURegionSizeSetting()` | Private validated region encoder | Replace the permissive round-up helper with exact nonzero, power-of-two, representability, overflow, and base-alignment validation. Safe-default stack construction rejects widening entirely. |
| `xIsPrivileged()` | Private CONTROL.nPRIV helper | Adapt as sensitive general-registers-only code. |
| `vResetPrivilege()` | Private controlled privilege drop | Adapt with ISB and postcondition validation. It is not a public elevation/de-elevation API. |
| `vPortSwitchToUserMode()` | Optional pre-start context policy operation | Replace with sealed context configuration guarded by the optional common lifecycle ABI. |
| `vPortStoreTaskMPUSettings()` | Mandatory default MPU builder plus optional `fiber_port_mpu_abi` context configuration | Adapt. Always configure the stack safely; validate every custom region; reseal context; reject changes after scheduler publication/start. |
| `xPortIsAuthorizedToAccessBuffer()` | future service-level argument validator | Exclude from base runtime. Add only with an actual unprivileged service API and exact permission metadata. |
| `vPortValidateInterruptPriority()` | Selected startup priority/PRIGROUP checks | Adapt startup proof. ISR-call-site validation remains pending until an ISR-safe fiber API exists. |
| `vPortGrantAccessToKernelObject()`, `vPortRevokeAccessToKernelObject()` | none | Exclude FreeRTOS kernel-object ACL mutation. |
| `xPortIsAuthorizedToAccessKernelObject()` | none | Exclude FreeRTOS kernel-object ACL lookup. |

## PendSV Geometry That Must Be Preserved

The reference protected context consists of 20 words:

```text
word  0     CONTROL
words 1-8   r4-r11
word  9     EXC_RETURN
word 10     PSP pointing at the basic hardware frame
words 11-18 copied r0-r3, r12, LR, PC, xPSR
word 19     saved-context cursor/top invariant used by the TCB
```

The fiber layout need not preserve FreeRTOS C member names, but its assembly
must preserve equivalent semantics. Static assertions and generated-assembly
probes must freeze every offset. The implementation must additionally prove:

```text
current context is privileged-valid before any metadata load
live PSP points to a complete basic frame inside the declared stack
copied xPSR has T set and stacked IPSR zero
copied PC is structurally valid and optionally address-map valid
EXC_RETURN is the exact ARMv7-M Thread/PSP value
CONTROL contains only the selected SPSEL/nPRIV policy
next MPU region image is sealed and validated before MPU disable
MPU disable/program/enable uses mandatory DMB/DSB/ISB ordering
next hardware frame is copied only to its own writable PSP stack
unprivileged restore leaves PRIMASK, BASEPRI, and FAULTMASK at zero
```

## MPU Region Policy

The initial exact profile follows the reference eight-region split but applies
stricter defaults:

| Region role | Ownership | Required policy |
| --- | --- | --- |
| 0-2 | Per-context configurable | Disabled by safe default unless exact profile integration supplies validated regions. |
| 3 | Per-context stack | Mandatory RW, XN, exact power-of-two/aligned coverage of only the selected stack allocation in the safe default. |
| 4 | Global current identity | Exact 32-byte privileged-RW/unprivileged-RO/XN aperture containing only `fiber_internal_runtime_current_context_slot`; no blanket peripheral access. |
| 5 | Global unprivileged code | RO executable, exact linker-provided range covering application code, the unprivileged public `fiber_current()`/`fiber_schedule()` call graphs, and the two SVC veneers. |
| 6 | Global privileged runtime code | Privileged RO executable, covering handlers, context/MPU mechanics, scheduler bridge and hook call graph, common return/panic sinks, and integration helpers. It may be a higher-priority region nested inside region 5. |
| 7 | Global privileged runtime data | Privileged-only RW and XN, covering contexts, hook state, port state, and scheduler policy data outside the isolated current-slot aperture. |

The linker contract must reject a build where writable unprivileged stack/data
overlaps writable privileged context/runtime state after MPU power-of-two size
encoding. A convenient C object layout is not evidence of MPU isolation.

## `mpu_wrappers_v2_asm.c` Audit

The file implements one repeated FreeRTOS kernel veneer pattern:

```text
read CONTROL.nPRIV
privileged caller -> branch directly to MPU_<API>Impl
unprivileged caller -> issue that API's SYSTEM_CALL_* SVC
```

Fiber adopts the architectural pattern only for its own narrow services. It
does not copy this file, `NUM_SYSTEM_CALLS`, the implementation table, or any
FreeRTOS API veneer. Every function below is deliberately excluded from the CPU
port because fiber has no corresponding kernel service:

### Task API veneers

```text
MPU_eTaskGetState
MPU_pvTaskGetThreadLocalStoragePointer
MPU_ulTaskGenericNotifyTake
MPU_ulTaskGenericNotifyValueClear
MPU_ulTaskGetIdleRunTimeCounter
MPU_ulTaskGetIdleRunTimePercent
MPU_ulTaskGetRunTimeCounter
MPU_ulTaskGetRunTimePercent
MPU_uxTaskGetNumberOfTasks
MPU_uxTaskGetStackHighWaterMark
MPU_uxTaskGetStackHighWaterMark2
MPU_uxTaskGetSystemState
MPU_uxTaskPriorityGet
MPU_vTaskDelay
MPU_vTaskGetInfo
MPU_vTaskResume
MPU_vTaskSetApplicationTaskTag
MPU_vTaskSetThreadLocalStoragePointer
MPU_vTaskSetTimeOutState
MPU_vTaskSuspend
MPU_xTaskAbortDelay
MPU_xTaskCheckForTimeOut
MPU_xTaskDelayUntil
MPU_xTaskGenericNotifyEntry
MPU_xTaskGenericNotifyStateClear
MPU_xTaskGenericNotifyWaitEntry
MPU_xTaskGetApplicationTaskTag
MPU_xTaskGetCurrentTaskHandle
MPU_xTaskGetIdleTaskHandle
MPU_xTaskGetSchedulerState
MPU_xTaskGetTickCount
```

### Queue and semaphore veneers

```text
MPU_pcQueueGetName
MPU_uxQueueMessagesWaiting
MPU_uxQueueSpacesAvailable
MPU_vQueueAddToRegistry
MPU_vQueueUnregisterQueue
MPU_xQueueAddToSet
MPU_xQueueGenericSend
MPU_xQueueGetMutexHolder
MPU_xQueueGiveMutexRecursive
MPU_xQueuePeek
MPU_xQueueReceive
MPU_xQueueSelectFromSet
MPU_xQueueSemaphoreTake
MPU_xQueueTakeMutexRecursive
```

### Timer veneers

```text
MPU_pcTimerGetName
MPU_pvTimerGetTimerID
MPU_uxTimerGetReloadMode
MPU_vTimerSetReloadMode
MPU_vTimerSetTimerID
MPU_xTimerGenericCommandFromTaskEntry
MPU_xTimerGetExpiryTime
MPU_xTimerGetPeriod
MPU_xTimerGetReloadMode
MPU_xTimerGetTimerDaemonTaskHandle
MPU_xTimerIsTimerActive
```

### Event-group veneers

```text
MPU_uxEventGroupGetNumber
MPU_vEventGroupSetNumber
MPU_xEventGroupClearBits
MPU_xEventGroupSetBits
MPU_xEventGroupSync
MPU_xEventGroupWaitBitsEntry
```

### Stream-buffer veneers

```text
MPU_xStreamBufferBytesAvailable
MPU_xStreamBufferIsEmpty
MPU_xStreamBufferIsFull
MPU_xStreamBufferNextMessageLengthBytes
MPU_xStreamBufferReceive
MPU_xStreamBufferSend
MPU_xStreamBufferSetTriggerLevel
MPU_xStreamBufferSpacesAvailable
```

The associated one-to-one `SYSTEM_CALL_*` numbers are excluded with the
veneers. Future sleep, wait, wake, queue, or secure-service APIs belong above
the CPU port and require their own explicit service contracts; they cannot
inherit FreeRTOS syscall numbers accidentally.

### Wrapper compile-gate inventory

The reference wrapper source conditionally emits veneers through the exact
configuration identifiers below. They are audited here even though the fiber
CPU port excludes all of the corresponding kernel veneers:

```text
configGENERATE_RUN_TIME_STATS
configNUM_THREAD_LOCAL_STORAGE_POINTERS
configQUEUE_REGISTRY_SIZE
configRUN_TIME_COUNTER_TYPE
configSTACK_DEPTH_TYPE
configUSE_APPLICATION_TASK_TAG
configUSE_EVENT_GROUPS
configUSE_MPU_WRAPPERS_V1
configUSE_MUTEXES
configUSE_QUEUE_SETS
configUSE_RECURSIVE_MUTEXES
configUSE_STREAM_BUFFERS
configUSE_TASK_NOTIFICATIONS
configUSE_TIMERS
configUSE_TRACE_FACILITY
INCLUDE_eTaskGetState
INCLUDE_uxTaskGetStackHighWaterMark
INCLUDE_uxTaskGetStackHighWaterMark2
INCLUDE_uxTaskPriorityGet
INCLUDE_vTaskDelay
INCLUDE_vTaskSuspend
INCLUDE_xSemaphoreGetMutexHolder
INCLUDE_xTaskAbortDelay
INCLUDE_xTaskDelayUntil
INCLUDE_xTaskGetCurrentTaskHandle
INCLUDE_xTaskGetIdleTaskHandle
INCLUDE_xTaskGetSchedulerState
```

None of these identifiers selects native fiber CPU mechanics. A future
application-level scheduler or service layer may define analogous policy, but
must not make the selected port depend on FreeRTOS configuration names.

### Excluded FreeRTOS system-call identifiers

The following exact identifiers are referenced by the audited wrapper source.
Every one is deliberately excluded together with its FreeRTOS API veneer:

```text
SYSTEM_CALL_eTaskGetState
SYSTEM_CALL_pcQueueGetName
SYSTEM_CALL_pcTimerGetName
SYSTEM_CALL_pvTaskGetThreadLocalStoragePointer
SYSTEM_CALL_pvTimerGetTimerID
SYSTEM_CALL_ulTaskGenericNotifyTake
SYSTEM_CALL_ulTaskGenericNotifyValueClear
SYSTEM_CALL_ulTaskGetIdleRunTimeCounter
SYSTEM_CALL_ulTaskGetIdleRunTimePercent
SYSTEM_CALL_ulTaskGetRunTimeCounter
SYSTEM_CALL_ulTaskGetRunTimePercent
SYSTEM_CALL_uxEventGroupGetNumber
SYSTEM_CALL_uxQueueMessagesWaiting
SYSTEM_CALL_uxQueueSpacesAvailable
SYSTEM_CALL_uxTaskGetNumberOfTasks
SYSTEM_CALL_uxTaskGetStackHighWaterMark
SYSTEM_CALL_uxTaskGetStackHighWaterMark2
SYSTEM_CALL_uxTaskGetSystemState
SYSTEM_CALL_uxTaskPriorityGet
SYSTEM_CALL_uxTimerGetReloadMode
SYSTEM_CALL_vEventGroupSetNumber
SYSTEM_CALL_vQueueAddToRegistry
SYSTEM_CALL_vQueueUnregisterQueue
SYSTEM_CALL_vTaskDelay
SYSTEM_CALL_vTaskGetInfo
SYSTEM_CALL_vTaskResume
SYSTEM_CALL_vTaskSetApplicationTaskTag
SYSTEM_CALL_vTaskSetThreadLocalStoragePointer
SYSTEM_CALL_vTaskSetTimeOutState
SYSTEM_CALL_vTaskSuspend
SYSTEM_CALL_vTimerSetReloadMode
SYSTEM_CALL_vTimerSetTimerID
SYSTEM_CALL_xEventGroupClearBits
SYSTEM_CALL_xEventGroupSetBits
SYSTEM_CALL_xEventGroupSync
SYSTEM_CALL_xEventGroupWaitBits
SYSTEM_CALL_xQueueAddToSet
SYSTEM_CALL_xQueueGenericSend
SYSTEM_CALL_xQueueGetMutexHolder
SYSTEM_CALL_xQueueGiveMutexRecursive
SYSTEM_CALL_xQueuePeek
SYSTEM_CALL_xQueueReceive
SYSTEM_CALL_xQueueSelectFromSet
SYSTEM_CALL_xQueueSemaphoreTake
SYSTEM_CALL_xQueueTakeMutexRecursive
SYSTEM_CALL_xStreamBufferBytesAvailable
SYSTEM_CALL_xStreamBufferIsEmpty
SYSTEM_CALL_xStreamBufferIsFull
SYSTEM_CALL_xStreamBufferNextMessageLengthBytes
SYSTEM_CALL_xStreamBufferReceive
SYSTEM_CALL_xStreamBufferSend
SYSTEM_CALL_xStreamBufferSetTriggerLevel
SYSTEM_CALL_xStreamBufferSpacesAvailable
SYSTEM_CALL_xTaskAbortDelay
SYSTEM_CALL_xTaskCheckForTimeOut
SYSTEM_CALL_xTaskDelayUntil
SYSTEM_CALL_xTaskGenericNotify
SYSTEM_CALL_xTaskGenericNotifyStateClear
SYSTEM_CALL_xTaskGenericNotifyWait
SYSTEM_CALL_xTaskGetApplicationTaskTag
SYSTEM_CALL_xTaskGetCurrentTaskHandle
SYSTEM_CALL_xTaskGetIdleTaskHandle
SYSTEM_CALL_xTaskGetSchedulerState
SYSTEM_CALL_xTaskGetTickCount
SYSTEM_CALL_xTimerGenericCommandFromTask
SYSTEM_CALL_xTimerGetExpiryTime
SYSTEM_CALL_xTimerGetPeriod
SYSTEM_CALL_xTimerGetReloadMode
SYSTEM_CALL_xTimerGetTimerDaemonTaskHandle
SYSTEM_CALL_xTimerIsTimerActive
```

The inventory is intentionally exact: adding or removing a wrapper in the
frozen FreeRTOS reference requires an explicit parity-record update rather than
being silently absorbed by a broad "all system calls excluded" statement.

## Fiber-Native SVC Namespace

The selected profile requires at least these collision-free services:

```text
first start
unprivileged schedule/yield
unprivileged fiber return
```

Rules:

- service numbers are selected-port constants with pairwise static assertions;
- optional service numbers participate in the same uniqueness proof;
- first start is accepted only from the privileged startup path and expected
  MSP frame;
- yield is accepted only from unprivileged Thread/PSP execution of the selected
  veneer;
- return is accepted only from the port-owned unprivileged return veneer;
- the handler validates `0xDFxx`, stacked PC, immediate, xPSR, EXC_RETURN,
  origin stack, current context, and service-specific provenance;
- unknown, disabled, nested, or wrongly originated services panic;
- only privileged Handler mode writes ICSR, programs MPU, invokes common
  scheduler state, or reaches the common return sink.

## Paranoid Differences From FreeRTOS

Fiber intentionally strengthens or narrows the reference behavior:

```text
FreeRTOS: configASSERT gates several vector, priority, and MPU checks.
Fiber: production profile performs mandatory startup checks and readbacks.

FreeRTOS: unknown SVC values fall through without a defined fatal action.
Fiber: every unknown or invalid SVC fails closed.

FreeRTOS: global peripheral region grants unprivileged RW access broadly.
Fiber: safe default grants no blanket peripheral access.

FreeRTOS: region builder assumes integration supplies valid base alignment and
          rounds size to the next MPU power of two.
Fiber: validates size, base alignment, overflow, widened coverage, overlap,
       permissions, XN, and privileged-boundary isolation before sealing.

FreeRTOS: TCB/kernel ownership is trusted by construction.
Fiber: validates scheduler-selected context identity, immutable seal, protected
       storage placement, saved frame, MPU image, and hook CPU-state preservation.

FreeRTOS: generic MPU wrappers can execute many kernel APIs in privileged
          Thread mode using a per-task system-call stack.
Fiber: base profile exposes only start, yield, and return services. Optional
       services require separate reviewed ABIs and argument validation.

FreeRTOS: unprivileged task return uses its kernel task lifecycle.
Fiber: return enters a port-owned SVC veneer and terminates through the common
       panic sink because static fibers have no delete operation.
```

## Required Build And Link Proofs

Before the source group may be selected in production, the matrix must prove:

1. The exact build-selected profile compiles with `-mcpu=cortex-m3`, Thumb,
   soft-float, general-registers-only sensitive paths, and the selected MPU
   manifest.
2. The common portable application fixture includes only `fiber_core.h` and
   links unchanged against privileged `ARM_CM3` and `ARM_CM3_MPU`.
3. Exactly one eight-function runtime ABI, reverse ABI v1 cohort, strong SVC,
   and strong PendSV pair exists.
4. Privileged and MPU context cohort symbols differ; stale runtime, boot,
   exception, type expectation, and complete archive combinations fail to link.
5. Generated unprivileged schedule and return veneers contain no privileged
   register access, writable common-state access, hidden compiler runtime call,
   FP instruction, or direct PendSV publication before SVC.
6. SVC service immediates are unique and every unknown/disabled service reaches
   the fatal path.
7. PendSV offsets exactly match the protected context and MPU region image.
8. Context/runtime/hook objects map to privileged-only writable memory; the
   exact 32-byte current-identity aperture is unprivileged-read-only and contains
   no other state; stack/application writable
   regions cannot cover privileged writable state.
9. MPU type, global regions, per-context regions, MemManage enable, MPU enable,
   CONTROL, priorities, PRIGROUP, handlers, and active vector slots have startup
   readback proofs.
10. Section GC, static archives, LTO, instrumentation, stack protector,
    sanitizer, profiling, and coverage cannot remove handlers or inject unsafe
    code into sensitive paths.
11. Duplicate strong handlers, unsupported optional MPU API use, invalid linker
    boundaries, misaligned/unrepresentable stack regions, and context/stack
    overlap fail at compile or link time where possible and otherwise at
    privileged pre-start validation.
12. Compiler stack-usage artifacts and the concrete linker/startup manifest
    prove sufficient privileged MSP headroom for first-start SVC, PendSV
    validation, the scheduler hook call graph, and terminal panic handling.

## Hardware Validation Required

Compile/link evidence is not a runtime claim. A matching Cortex-M3 MPU target
must pass:

```text
unprivileged first context
unprivileged round-robin switching
privileged-context tests only if a later optional MPU policy enables that mode
MPU region replacement across every switch
CONTROL.nPRIV/SPSEL restoration
unprivileged direct ICSR/common/context write fault tests
unprivileged current-slot read succeeds while adjacent runtime metadata reads fault
stack and configurable-region access allow/deny tests
code/data/XN and privileged-boundary fault tests
yield-SVC and return-SVC provenance traps
unknown-SVC and foreign-PendSV traps
corrupted protected-context and MPU-image traps
MemManage handler/fault-status validation
long-run scheduler and stack-integrity stress
```

No STM32 family support claim is made until a concrete STM32 device manifest,
linker map, MPU implementation, vector source, and board result are recorded.

## Implementation Slices

The implementation proceeds in independently reviewable checkpoints:

1. **Complete:** add the compile-only exact profile manifest, type-only context
   layout, port traits, cohort identity, and exhaustive offset proofs without
   enabling runtime selection.
2. **Complete:** add validated exact MPU region encoding, fail-closed linker
   boundaries, safe default global/per-context policy, protected context
   construction, and immutable sealing without enabling runtime selection.
3. **Complete:** add the unified strong SVC dispatcher, first-start MPU
   activation/restore, yield veneer, return veneer, fail-closed dispatch checks,
   and generated-code/link/vector proofs without enabling runtime selection.
4. **Complete:** add PendSV protected-frame copy, MPU region switch, CONTROL
   restore, user scheduler bridge, and generated-assembly offset/order proofs.
5. **Conditionally omitted:** add optional pre-start `fiber_port_mpu_abi`
   configuration and the versioned common context-configuration lifecycle
   guard only if heterogeneous policy is implemented in this profile.
6. **Complete:** add full compile/link/archive/cohort/LTO/MPU-linker proof
   cohorts and all eight forward runtime adapters without enabling selection.
7. **Complete:** enable exact build selection as compile/link-covered only,
   without adding an architecture auto-selection route or hardware claim.
8. Promote to runtime support only after the complete hardware suite.

Common runtime choreography and the five/eight-function ABI are frozen during
all slices. Any discovered need for a ninth mandatory operation is an audit
failure and must be justified against the complete reference inventory before
changing common code.
