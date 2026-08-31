# V2 Selected Port Traits Contract

This document defines the selected port's compile-time CPU contract. It is
modeled after the FreeRTOS selected `portmacro.h` plus one matching port source
group, but scheduler policy remains application-owned and cooperative.

`V2_OPAQUE_CONTEXT_CONTRACT.md` defines the opaque context boundary and
`V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md` defines the final CPU-neutral callable
ABI. Common translation units consume only opaque context pointers and the
approved eight callable port operations. They do not allocate selected CPU
state tokens. Frame-layout traits remain selected-port implementation and
compile-validation facts.

## Non-Negotiable Rules

1. The build selects exactly one Cortex-M port.
2. The selected `fiber_portmacro.h` is the only source of CPU facts.
3. Only selected-port code and compile-time contract validators consume CPU and
   frame-layout `FIBER_PORT_*` traits after the opaque-context migration.
4. A CPU fact is never an application performance knob.
5. Exactly one selected port source group defines every external port ABI
   symbol.
6. Unsupported security/context state fails closed at compile time or startup.
7. Compile coverage is not a hardware support claim.

The removed `FIBER_PORT_TRAITS_LEGACY_BRIDGE` and all old `FIBER_HAS_*`
aliases are compile errors. There is no bidirectional compatibility bridge.

## Selection Workflow

The preferred production workflow mirrors FreeRTOS:

1. The build adds the selected port directory to the include path.
2. The build defines `FIBER_PORT_BUILD_SELECTED=1`.
3. The public `fiber_port_selected.h` includes only that directory's
   `fiber_port_types.h`. Selected port sources include their local
   `fiber_portmacro.h` directly through the selected include path.
4. Each runtime image compiles exactly one matching runtime port source group.
   If the profile needs Secure or TF-M integration, the build graph binds the
   runtime image to one matching companion component or artifact. That companion
   may be built as a separate Secure target or supplied by TF-M; it must not
   define a second callable fiber runtime ABI in the same runtime image.

The architecture result macro validates the CPU class only. The production
manifest additionally records the exact selected include path, source group,
compiler/toolchain identity and version, CPU/FPU/ABI flags, MPU/privilege policy,
security-domain role,
FP/MVE/PAC/BTI policy, errata policy, optional companion artifacts, and context
layout identity. Profiles that differ in any layout-affecting item are distinct
selected configurations even when they share implementation files.

Build-selected mode is mandatory for production MPU, unprivileged, Secure-only,
Non-secure, TrustZone, NTZ, TF-M, MVE, PAC, and BTI profiles. Auto/profile/force
selection may compile-test an architecture class but cannot supply those facts
or create a runtime-support claim.

The same build selection feeds separate public-type, internal ABI, and
implementation boundaries. Only selected port sources and compile-contract
probes include `fiber_portmacro.h`; common runtime sources include the
CPU-neutral callable ABI instead.

`fiber_port_select.h` remains an auto-detection and test convenience. Forced or
profile selection is validated against compiler architecture macros unless the
explicit mismatch escape hatch is enabled for a controlled compile probe.

## Include Boundary

The public selected-type facade is:

```c
#include "port/fiber_port_selected.h"
```

It performs strict selection and includes exactly one public type-only
`fiber_port_types.h`. It must not expose the selected complete
`fiber_portmacro.h`, CMSIS, register helpers, or inline assembly.

The implemented public/common split and the frozen target boundary are:

```text
public fiber_core.h
    -> API forward declarations
    -> selected public type-only header that completes FiberContext
    -> public API declarations

common runtime .c
    -> API forward declarations
    -> CPU-neutral callable port ABI with incomplete FiberContext pointers

selected port .c
    -> selected complete context type
    -> fiber_portmacro.h and port-private implementation headers
    -> CPU implementation helpers
```

Common runtime translation units must not include the selected complete context
type and must not be able to use `sizeof(FiberContext)`, field access, frame
offsets, CMSIS registers, or inline port assembly.

There is no global `fiber_port_abi_types_selected.h` or selected internal-type
facade in the frozen design. Declarations displaced while narrowing the callable
ABI stay inside each concrete port's `fiber_portmacro.h`, `fiber_portasm.h`,
boot header, or another explicitly port-private header. Common runtime never
selects or includes those headers.

A selected port may depend on:

- CMSIS through `mcu_core.h`;
- `fiber_compiler.h` for compiler attributes and barriers;
- `fiber_settings.h` for genuine shared user policy;
- the selected public type-only header for its private `FiberContext` layout;
- CPU-neutral metadata helpers that do not impose a context offset;
- `fiber_panic.h` for mandatory validation failures.

It must not depend on scheduler implementation details, queues, timing policy,
or application task types. Its public type-only header must not include CMSIS,
`mcu_core.h`, register helpers, `fiber_portmacro.h`, or inline assembly.

## Required CPU Traits

Every selected port defines these macros before `fiber_port_traits.h` runs:

```text
FIBER_PORT_NAME
FIBER_PORT_STACK_ALIGNMENT

FIBER_PORT_HAS_BASEPRI
FIBER_PORT_HAS_FAULTMASK
FIBER_PORT_HAS_VTOR
FIBER_PORT_HAS_PSPLIM
FIBER_PORT_HAS_FPU
FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
FIBER_PORT_BOOT_CLEARS_FPCA
FIBER_PORT_HAS_MVE
FIBER_PORT_HAS_PAC
FIBER_PORT_HAS_BTI
FIBER_PORT_USES_PSPLIM_REGISTER

FIBER_PORT_INITIAL_EXC_RETURN
FIBER_PORT_SCHEDULER_MASK_KIND
FIBER_PORT_SCHEDULER_BASEPRI

FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND
FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND

FIBER_PORT_IS_V8M
FIBER_PORT_HAS_SECURITY_EXT
FIBER_PORT_RUNS_NONSECURE
FIBER_PORT_TARGETS_NS_BANK
FIBER_PORT_HAS_CONTROL_SLOT
FIBER_PORT_HAS_PSPLIM_SLOT
FIBER_PORT_HAS_SECURE_CONTEXT_SLOT
FIBER_PORT_HAS_PAC_KEY_SLOT

FIBER_PORT_CONTEXT_ABI_PORT_ID
FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION
FIBER_PORT_CONTEXT_ABI_FEATURE_MASK

FIBER_PORT_EXC_BASE_BYTES
FIBER_PORT_EXC_FP_EXT_BYTES
FIBER_PORT_EXC_PER_LEVEL_BYTES
FIBER_PORT_SOFTWARE_FRAME_WORDS
FIBER_PORT_SOFTWARE_FRAME_BYTES
FIBER_PORT_EXC_RETURN_WORD_INDEX
FIBER_PORT_HIGH_FP_SOFTWARE_BYTES
FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES
FIBER_PORT_INITIAL_CONTEXT_BYTES
FIBER_PORT_MAX_SAVED_CONTEXT_BYTES
FIBER_PORT_SAVED_SP_MOD8
```

`FIBER_PORT_SCHEDULER_BASEPRI` is required only for a BASEPRI scheduler mask.
Every boolean is normalized to exactly `0` or `1` and statically validated.
Application/build flags must not predefine canonical selected-port traits; they
are port outputs, and such a predefinition is a compile error.

`FIBER_PORT_HIGH_FP_SOFTWARE_BYTES` names the incremental selected-port
software state required by an extended FP context. On ordinary PSP-resident
ports this is normally only `s16-s31`. A protected-context port may also copy
`s0-s15/FPSCR` into privileged context storage, so its value must cover all
words added to the basic software restore image. It is a geometry trait, not a
claim that those bytes are all high VFP registers.

The context ABI identifier and layout version must be nonzero and stable for one
selected source group. Increment the layout version whenever a field offset,
saved-frame format, required alignment, initial EXC_RETURN semantics, or enabled
context slot changes. The feature mask records the selected layout facts and may
legitimately be zero for a minimal port.

The combined port identifier, layout version, and feature mask must also
distinguish every compiler-port ABI setting that can change context alignment,
calling convention, FP/MVE use, or generated save/restore assumptions. This
does not require another generic selector macro; it is part of the exact
selected-profile manifest and context mismatch guard.

These traits describe the current selected-port contract and remain useful for
port-local static assertions and compile probes. They do not authorize common
runtime code to inspect context fields after the opaque-context migration.

## Trait Consistency

The compile-time selected-port trait validator enforces at least these
relationships:

- stack alignment is a power of two and at least 8 bytes;
- extended FP context requires an FPU;
- FPCA cleanup requires an FPU;
- PSPLIM register use requires PSPLIM support;
- BASEPRI scheduler masking requires BASEPRI support;
- PRIMASK scheduler masking is used only by ports without BASEPRI;
- an enabled M7 r0p1 workaround requires port support;
- exception frame sizes are internally consistent and 8-byte aligned;
- software frame bytes equal words times four;
- the EXC_RETURN slot is inside the software frame;
- initial and maximum saved-context sizes equal the selected port's declared
  frame components;
- initial EXC_RETURN selects Thread mode, PSP, and a basic frame;
- saved EXC_RETURN accepts only the selected port's exact basic encoding and,
  when supported, the corresponding exact extended-FP encoding.
- the context ABI identifier and layout version are nonzero before any context
  can be sealed.

## Stack Geometry

The selected port owns every software and hardware frame component and exports
the exact initial and maximum saved-context sizes. The required identities are:

```text
initial context = software frame + base hardware frame

maximum saved context =
    software frame
  + maximum hardware frame
  + high FP s16-s31 area when supported
  + one architectural alignment word
```

The synthetic initial frame is built directly down from `stack_top`. After SVC
restores it, PSP equals `stack_top`. There is no independent top guard and no
user `FIBER_BOOT_EXTRA_BYTES` override.

The raw minimum is the port maximum saved context plus the configured low red
zone, subject to extra bytes lost while normalizing unaligned raw addresses.

## FPU Contract

An FPU port derives context support from two independent facts:

```text
compiler emits FP instructions
CMSIS says the selected silicon has an FPU
```

Both must be true. If CMSIS defines `__FPU_USED`, it must agree with compiler FP
generation. The library never synthesizes `__FPU_USED` and never provides a
force-save override.

Before first start, an FPU port:

1. enables CP10/CP11;
2. serializes the write;
3. verifies CPACR readback;
4. applies ASPEN/LSPEN policy;
5. verifies FPCCR readback;
6. clears FPCA through the port start path.

`FIBER_FPU_LAZY` is the only shared FP performance policy. It does not change
the saved-context ABI.

## Scheduler Critical Section

PendSV saves the current context before calling the common scheduler bridge.
The selected port protects that call:

- BASEPRI-capable ports save old BASEPRI, set the validated scheduler
  threshold, call the hook, and restore old BASEPRI;
- BASEPRI-less ports save PRIMASK, disable interrupts, call the hook, and
  restore the exact previous PRIMASK value.

The CM7 r0p1 port preserves PRIMASK around every BASEPRI write required by ARM
errata 837070. Its naked-assembly synchronized write macros clobber `r12`; no
live context state may be kept there across those macros.

Common `fiber_schedule()` validates only common lifecycle/current ownership and
delegates CPU-state validation plus the request mechanism to the selected port.
The selected port must make that validation privilege-aware:

- a privileged direct-PendSV path validates Thread mode and every readable mask
  invariant before publishing `PENDSVSET`;
- an unprivileged MPU path performs only checks safely observable from
  unprivileged Thread mode, then issues a port-owned yield SVC;
- the yield SVC validates instruction/service provenance and the real privileged
  CPU mask state before publishing `PENDSVSET` from Handler mode;
- a port that restores an unprivileged context guarantees zero PRIMASK and,
  where implemented, zero BASEPRI and FAULTMASK as restore invariants. It must
  not depend on an unprivileged pre-SVC read to prove those values.

Every actual ICSR publication, whether direct or from the SVC handler, is
followed by mandatory DSB/ISB serialization. Scheduler selection still occurs
only in PendSV after the outgoing context has been saved.

## Required Callable Interface

The common runtime sees the final callable ABI below and no selected layout,
CMSIS, frame, CPU-state token, or CPU-register detail. Selected-port-local FPU,
BASEPRI/PRIMASK, PSPLIM, vector, frame, validator, SVC, and PendSV helpers remain
implementation details.

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

The sensitive/general-registers-only attributes frozen in
`V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md` are part of these callable signatures.
Changing a required attribute, calling convention, or semantic requires the
same mandatory bidirectional ABI version bump as changing a parameter list.

The selected source group defines every mandatory external ABI symbol exactly
once. Port-private helpers are not part of this global ABI allowlist. The final
matrix also proves strong selected-port `SVC_Handler` and `PendSV_Handler`
ownership, archive extraction, vector relocations, duplicate-handler failure,
`--gc-sections` retention, and LTO retention. Every callable ABI addition or
removal updates the audited symbol list in the same structural commit.

Every context layout also defines immutable port identity, layout version,
size, alignment, and feature identity. A real versioned-symbol relocation or
equivalent negative link probe is required before separately compiled or
precompiled library objects are claimed safe against header/object layout
mismatch.

That relocation identifies the complete selected-profile object cohort, not
only the public structure size. One guaranteed always-linked mandatory port
identity object defines it without compatibility aliases. Every other
independently compiled mandatory port object retains it, as does one build-owned
expectation object compiled through the selected public type header. Any
exact-profile or context-ABI change uses a new symbol spelling so stale port
object mixtures fail to link.

The active implementation is `fiber_port_context_cohort.h`. Port ID and layout
version must be nonzero single preprocessing tokens, not arithmetic
expressions. Every fact encoded into the symbol must likewise normalize to a
single literal token. The identity includes profile, concrete port, layout,
CPU exception capabilities, stack alignment, scheduler mask class, initial
EXC_RETURN, FP/context slots, security role, and MVE/PAC/BTI policy. Shared
source paths do not imply shared identity; for example ARM_CM0 M0/M0+ builds
are distinguished when their VTOR capability differs.

The runtime object defines the symbol. Boot and exception objects retain it
from one-shot paths. A production manifest additionally compiles
`fiber_port_context_cohort_expectation.c` outside any precompiled port archive
and applies `KEEP(*(.fiber_port_context_cohort_expectation))`. Matrix fixtures
prove positive and stale-object links with section GC and LTO.

## Source Layout

The FreeRTOS mapping is:

```text
FreeRTOS portmacro.h      -> fiber_portmacro.h
FreeRTOS port.c           -> fiber_port.c and fiber_port_exception.c
FreeRTOS portasm.*        -> port-local assembly source/header when needed
FreeRTOS secure_context.* -> future port-local v8-M secure context files
```

Splitting exception setup into `fiber_port_exception.c` is organizational only;
it remains part of the selected port source group and parity ledger.

## Transitional v8-M Policy

`port/transitional_v8m` exists only to keep M23/M33/M55 selection and ABI
compile-covered while native ports are implemented. It may use:

```text
FIBER_TRANSITIONAL_V8M_RUN_NONSECURE
FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK
FIBER_ALLOW_UNVALIDATED_*
```

It is not production support. Missing CONTROL, PSPLIM, secure-context, MVE,
PAC-key, or BTI policy remains fail-closed at startup. Each future native port
must replace transitional traits with a profile-specific frame layout and a
FreeRTOS parity ledger.

## Port Completion Checklist

For each new concrete STM32 Cortex-M port or exact feature profile:

1. Identify the exact FreeRTOS reference directory and commit.
2. Inventory every macro, helper, handler, context slot, erratum, and security
   conditional in the reference port.
3. Record each item as adopted, renamed, intentionally omitted, or hardened.
4. Record the exact selected-profile manifest, including toolchain identity and
   version, compiler flags, privilege/security role, enabled context features,
   companion artifacts, and context ABI identity.
5. Define all canonical traits without legacy aliases.
6. Implement SVC first-start and scheduler-driven PendSV.
7. Define strong selected-port `SVC_Handler` and `PendSV_Handler` symbols.
8. Add build-selected source-group coverage.
9. Relocatable-link and verify one ABI definition per symbol, both directions of
   the mandatory bidirectional ABI mismatch, handler archive
   extraction, stale mandatory/handler bundle mismatch, handler/common ABI
   mismatch where applicable, vector slots 11/14, duplicate-handler failure,
   GC retention, and LTO retention.
10. Build adversarial instrumentation/SSP/sanitizer/profile configurations and
    inspect generated code for context order plus a hidden-call-free, FP/MVE-free
    sensitive start/SVC/PendSV/scheduler-hook call graph.
11. Run the selected-context header/object mismatch negative-link probe for
    every layout-affecting configuration, plus stale selected-port object
    mixture probes for the complete source group.
12. For an unprivileged profile, prove collision-free start/yield/return SVC
    dispatch, return through the selected veneer, and MPU/linker isolation of
    writable stacks from context/runtime state.
13. For a SecureContext or TF-M profile, prove the separately versioned
    cross-image gateway and companion manifest before startup.
14. Run profile-specific hardware normal, FP, mask, frame-corruption, and
    vector-routing tests.
15. Only then promote the profile from compile-covered to runtime-supported.
