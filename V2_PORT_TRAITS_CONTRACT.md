# V2 Selected Port Traits Contract

This document defines the selected port's compile-time CPU contract. It is
modeled after the FreeRTOS selected `portmacro.h` plus one matching port source
group, but scheduler policy remains application-owned and cooperative.

`V2_OPAQUE_CONTEXT_CONTRACT.md` defines the final common-runtime boundary. The
current source still consumes some traits directly while the context layout is
shared. After the opaque-context migration, common translation units consume
only opaque context pointers, selected internal ABI token types, and callable
port operations. Frame-layout traits remain selected-port implementation and
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
3. `fiber_port_selected.h` includes that directory's `fiber_portmacro.h`.
4. Each runtime image compiles exactly one matching runtime port source group.
   If the profile needs Secure or TF-M integration, the build graph binds the
   runtime image to one matching companion component or artifact. That companion
   may be built as a separate Secure target or supplied by TF-M; it must not
   define a second callable fiber runtime ABI in the same runtime image.

Step 3 describes the current transitional facade. After the opaque-context
split, the same selection result feeds separate selected public-type, internal
ABI-type, and implementation facades. Only selected port sources include
`fiber_portmacro.h`; common runtime sources include the callable ABI instead.

`fiber_port_select.h` remains an auto-detection and test convenience. Forced or
profile selection is validated against compiler architecture macros unless the
explicit mismatch escape hatch is enabled for a controlled compile probe.

## Include Boundary

The current transitional facade is:

```c
#include "port/fiber_port_selected.h"
```

It includes shared user settings, compiler support, selection, the selected
port contract, trait validation, and fail-closed feature policy in that order.

The target boundary splits that facade into:

```text
public fiber_core.h
    -> API forward declarations
    -> selected public type-only header that completes FiberContext
    -> public API declarations

common runtime .c
    -> API forward declarations
    -> selected internal ABI type-only header
    -> callable port ABI

selected port .c
    -> selected complete context type
    -> fiber_portmacro.h and CPU implementation helpers
```

Common runtime translation units must not include the selected complete context
type and must not be able to use `sizeof(FiberContext)`, field access, frame
offsets, CMSIS registers, or inline port assembly.

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

The current transitional selected header provides inline CPU helpers for FPU,
BASEPRI/PRIMASK, PSPLIM, vector access, stack-frame construction, and PendSV
publication. Those helpers remain selected-port-owned during migration; they are
not the final common-runtime interface.

The target common callable ABI accepts opaque context pointers:

```text
fiber_port_context_init
fiber_port_context_validate_restore
fiber_port_context_prepare_first_start
fiber_port_require_start_environment
fiber_port_require_schedule_environment
fiber_port_runtime_prepare
fiber_port_runtime_validate
fiber_port_scheduler_state_capture
fiber_port_scheduler_state_validate
fiber_port_scheduler_critical_enter
fiber_port_scheduler_critical_exit
fiber_port_start_first_context
fiber_port_request_schedule
fiber_svc
fiber_pendsv
```

The selected internal type-only ABI header must complete the private scheduler
CPU-state and C critical-state token types. Common code may allocate and pass
those types, but it must not inspect their fields. An incomplete token cannot be
instantiated and is not a valid interface.

The selected source group defines every mandatory external ABI symbol exactly
once. The compile matrix performs a relocatable link and uses `nm` to prove that
property. As the opaque ABI replaces transitional symbols, the audited symbol
list must be updated in the same structural commit.

Every context layout also defines immutable port identity, layout version,
size, alignment, and feature identity. A real versioned-symbol relocation or
equivalent negative link probe is required before separately compiled or
precompiled library objects are claimed safe against header/object layout
mismatch.

The current transitional external symbol set is:

```text
fiber_port_init_context_frame
fiber_exception_runtime_check
fiber_pendsv_init_lowest_priority
fiber_port_start_first_context
fiber_svc
fiber_pendsv
```

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

For each new concrete STM32 Cortex-M port:

1. Identify the exact FreeRTOS reference directory and commit.
2. Inventory every macro, helper, handler, context slot, erratum, and security
   conditional in the reference port.
3. Record each item as adopted, renamed, intentionally omitted, or hardened.
4. Define all canonical traits without legacy aliases.
5. Implement SVC first-start and scheduler-driven PendSV.
6. Add wrapper and direct-vector compile modes.
7. Add build-selected source-group coverage.
8. Relocatable-link and verify one ABI definition per symbol.
9. Inspect generated assembly for context order and FP-free scheduler bridges.
10. Run profile-specific hardware normal, FP, mask, frame-corruption, and
    vector-routing tests.
11. Only then promote the profile from compile-covered to runtime-supported.
