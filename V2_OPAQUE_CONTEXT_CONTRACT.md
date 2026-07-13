# V2 Opaque Selected-Port Context Contract

## Status

This document defines the target common-core boundary that must be completed
before adding production Cortex-M ports in bulk.

It supersedes every older v2 statement that requires one shared, common-known
`FiberContext` or boot-record layout for all ports. The selected-port context
and boot ownership phase is implemented: `fiber_api_types.h`, the single
`fiber_port_selected.h` facade, and per-port `fiber_port_types.h`,
`fiber_port_boot_types.h`, `fiber_port_boot.h`, and `fiber_port_boot.c` files
now exist. Every current port deliberately preserves an ABI-compatible
`sp + FiberPortBoot` physical layout, while `fiber_types.h` is only a
compatibility facade.

`fiber_core.c`, `fiber_runtime_state.c`, and the default `fiber_panic.c` now
use only `FiberContext *` and the callable selected-port ABI. They compile
without CMSIS or a selected complete port header. They do not dereference, size,
align, or inspect the context or its boot record. The selected port owns
construction, record sealing, hash selection, dynamic restore validation,
startup MSP planning, CPU barriers, terminal panic waiting, and first-start
preparation. This structural move requires a fresh hardware validation run; it
does not itself expand runtime support claims.

The reference model is the local FreeRTOS Cortex-M port set. Classic CM3, CM4F,
and CM7 ports primarily switch through a saved stack pointer. MPU and v8-M ports
add port-defined MPU settings, PSPLIM, CONTROL, SecureContext, PAC, and FP/MVE
state. A single common context layout cannot represent those profiles honestly.

## Freeze Goal

After this contract is implemented and validated:

```text
application
    knows sizeof(FiberContext)
    treats every field as private

common core
    owns the five public APIs
    owns scheduler semantics and current-context publication
    sees only FiberContext pointers

selected port
    owns the complete FiberContext layout
    owns CPU context construction and validation
    owns CPU-state guards
    owns runtime startup and SVC/PendSV transfer
```

New ports must be addable by providing selected types, selected implementation,
build selection, parity documentation, and validation evidence. Adding a port
must not require new EXC_RETURN, PSPLIM, CONTROL, MPU, PAC, or MVE branches in
`fiber_core.c` or the common scheduler bridge.

## Freeze Scope

The common-core freeze covers:

- single-core cooperative Cortex-M execution;
- Thread mode on PSP;
- exactly one selected port per build;
- static-lifetime contexts and stacks;
- no context deletion or runtime shutdown;
- no common scheduler queues, lists, priorities, or timing policy;
- MPU, TrustZone, PAC, and MVE through port-private layout and optional APIs;
- GCC/Clang-compatible selected-port implementations.

Dynamic secure-context cleanup, context deletion, SMP, migration between cores,
or a new scheduler lifecycle may require an explicit common API extension. Such
an extension is outside this freeze and must not be smuggled into a CPU port.

## Public API

The public cooperative API remains:

```c
void fiber_init(FiberContext *ctx,
                void *stack_begin,
                void *stack_end,
                FiberEntryFn entry,
                void *arg);

FiberContext *fiber_current(void);

FIBER_API_NORETURN
void fiber_start(void);

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                   void *user);

void fiber_schedule(void);
```

No public direct target-switch API is added. The scheduler hook selects the first
context when `current == NULL` and every later context from PendSV.

`FiberEntryFn` is the target collision-resistant spelling for the current
`entry_t` callback type. The structural move must keep `entry_t` as a
source-compatible alias. Removing that alias is a separate public API decision,
not part of the opaque-context migration.

```c
typedef void (*FiberEntryFn)(void *arg);
typedef FiberEntryFn entry_t;
```

## Type Visibility

`FiberContext` is opaque by compilation boundary to common code and private by
contract to application code. It is not an actually anonymous C type.

The common declaration is:

```c
typedef struct FiberContext FiberContext;
```

The selected public type header completes the tagged structure so an application
can use static storage:

```c
struct FiberContext {
    FiberContextMetadata port_private_common;
    FiberArmCm7ContextPrivate port_private_cpu;
};
```

Private field names are intentionally explicit. Application code may allocate
objects, take their addresses, and compare pointers to them. It must not copy an
initialized object or directly inspect or modify its fields.

An `unsigned char opaque[SIZE]` representation is not the initial design. It
would add alignment, effective-type, strict-aliasing, C++, and debugger costs
without improving the common-core compilation boundary.

## Header Layers

The target include structure is:

```text
fiber/
  fiber_api_types.h
  fiber_api_attributes.h
  fiber_api_decl.h
  fiber_core.h
  fiber_runtime_state.h

  port/
    fiber_port_selected.h
    fiber_port_runtime_abi.h
    fiber_port_geometry.h

    ARM_CM7/r0p1/
      fiber_port_types.h
      fiber_port_boot_types.h
      fiber_port_boot.h
      fiber_portmacro.h
      fiber_port.c
      fiber_port_boot.c
      fiber_port_exception.c
      FREERTOS_PARITY.md
```

`fiber_api_types.h` contains only forward declarations and callback types. It
must not include CMSIS or a selected port. `FiberEntryFn` is the named entry
type and `entry_t` remains a source-compatible alias.

`fiber_api_attributes.h` contains public compiler attributes such as the
noreturn declaration and `FIBER_SCHEDULER_HOOK_ATTR`. It may detect compiler
capabilities but must not include CMSIS, CPU feature traits, register helpers,
or inline assembly.

There is no common complete boot-record type. Each selected port's
`fiber_port_boot_types.h` owns the concrete boot metadata embedded by its
`fiber_port_types.h`; it remains type-only and CMSIS-free. The matching
`fiber_port_boot.c` owns construction, integrity sealing, hash selection, stack
geometry, and startup policy. A future port may use a different record layout
or hardware-backed integrity operation without changing common runtime code.

`fiber_port_selected.h` is the single global public-type selector. It selects
one local `fiber_port_types.h` and completes `FiberContext` for application
storage. It does not include the selected complete `fiber_portmacro.h`.

`fiber_port_types.h` is a public type-only selected-port header. It completes
`FiberContext` but must not include `mcu_core.h`, SCB/NVIC definitions, CMSIS
intrinsics, `fiber_portmacro.h`, register helpers, or inline assembly.
It may include standard integer/size types, `fiber_api_types.h`,
compiler-neutral alignment declarations, and port-local type-only boot,
MPU, or security records under the same restrictions.

The selected public type header exposes only storage facts required by
application allocation. It does not expose software-frame offsets, EXC_RETURN
slots, or register-save geometry. Those remain private implementation and
compile-audit facts in the selected complete `fiber_portmacro.h` and its
selected helpers.

`fiber_port_runtime_abi.h` declares callable selected-port operations using
pointers to incomplete `FiberContext` objects. It must not expose context fields,
CPU traits, CMSIS registers, or frame offsets. It is the only selected-port
header included by common runtime implementation files.

Common runtime code gets its ordering barrier and terminal panic wait through
this callable ABI. It must not reintroduce CMSIS intrinsics, device headers, or
special-register declarations merely to implement those two operations.

`fiber_core.h` is the public umbrella. It includes the API types, public
attributes, selected complete context type, and public declarations.

Common `.c` files include the API declarations, internal runtime declarations,
and callable port ABI. They do not include the selected complete context type.
Therefore these expressions must fail to compile in common code:

```c
ctx->port_private_cpu;
sizeof(FiberContext);
_Alignof(FiberContext);
offsetof(FiberContext, any_field);
```

## Port-Owned Boot Metadata

There is deliberately no common boot-record type or context-metadata record. Each
selected port defines its own `FiberPortBoot` inside
`fiber_port_boot_types.h` and stores it at a private offset in `FiberContext`.
The current ports retain equivalent fields for mechanical compatibility, but
that is not a cross-port ABI promise.

The selected port owns its corresponding construction and validation helpers in
`fiber_port_boot.c`, including the integrity algorithm. A future port may use a
different record, omit irrelevant fields, or use a hardware hash/CRC unit as
part of its integrity policy. Common runtime code obtains no metadata accessor,
does not calculate any boot hash, and never learns the boot-record offset.

An integrity check is an accidental-corruption check, not a security
authentication primitive and not the final proof that a context is restorable.

## Port-Private Integrity Seal

Every production port owns final context sealing and restore validation:

```c
void fiber_port_context_seal(FiberContext *ctx);
void fiber_port_context_validate_seal(const FiberContext *ctx);
void fiber_port_context_validate_restore(const FiberContext *ctx);
```

The immutable port seal covers at least:

- the selected-port boot-record integrity value;
- effective stack bounds and alignment;
- selected port identifier and context layout version;
- context size and feature mask;
- immutable frame-layout policy;
- initial EXC_RETURN policy;
- configured MPU regions and privilege policy where applicable;
- initial PSPLIM/CONTROL policy where applicable;
- SecureContext, PAC, and MVE configuration descriptors where applicable.

The live saved SP and live register/FP/MVE contents change during switching and
must not be included in an immutable hash unless a port deliberately reseals on
every save. The normal design validates live saved-SP alignment, bounds, frame
shape, EXC_RETURN, xPSR, and dynamic context slots separately before restore.

Every immutable seal present must be checked before a validator dereferences
untrusted saved-frame addresses. A port may use one final hash over common and
private immutable fields or two independently checked seals.

Current selected ports seal and fast-check a nonzero port identity, layout
version, `sizeof(FiberContext)`, alignment, feature mask, and initial
EXC_RETURN in addition to stack and boot metadata. A context from a different
selected port, layout revision, or incompatible feature configuration therefore
fails closed before its saved frame is read.

The conservative default recomputes the immutable boot-record hash before every
restore. An integration may explicitly select the fast structural-only path,
but that is a performance trade-off, not a safety-equivalent default. Both paths
must validate the context identity, stack bounds, canary, saved-frame shape,
EXC_RETURN, xPSR, and Thumb-PC form before exception return. The optional
`FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1` policy additionally validates the
dynamic context/stack and saved-PC addresses against the linker map.

## Runtime MSP Ownership

Initial MSP rewind or validation is port-runtime startup policy, not a mandatory
property of every future fiber context.

Per-context state may include PSP bounds, PSPLIM, CONTROL, MPU settings,
SecureContext, PAC keys, EXC_RETURN, and FP/MVE state. The initial MSP source and
rewind/validate decision apply once to the complete runtime.

The selected port owns:

- how the initial MSP source is obtained;
- whether MSP is rewound or the current MSP is validated;
- VTOR/vector-table interpretation;
- startup MSP stability and RAM plausibility checks;
- non-overlap between startup MSP and the selected first context;
- transfer of the prepared MSP into the private naked SVC-start assembly.

Common code calls port startup operations but never sees VTOR, `__get_MSP()`, an
MSP address, or `FIBER_REWIND_MSP`.

The initial selected ports keep the plan in port-private runtime state, not in
`FiberPortBoot`. The plan is created once by `fiber_port_runtime_prepare()`
after start preconditions are checked and before the first scheduler callback.
For `FIBER_REWIND_MSP=1`, the vector-table source is sampled twice and checked
again before transfer. For `FIBER_REWIND_MSP=0`, the selected port preserves
the current MSP and uses a startup-time geometry check instead of comparing
against a stale context-init snapshot. The contract does not require MSP fields
in any context layout.

## Scheduler Ownership

Common runtime owns:

- scheduler hook and user pointer storage;
- `current == NULL` first-selection semantics;
- recursion and hot-swap guards;
- missing-hook failure and hook invocation;
- publication of the new current context;
- ordering barriers around common runtime state.

The selected port owns:

- first-selection and PendSV scheduler wrapper entry points;
- scheduler critical-section mechanics;
- CPU-state snapshot and validation around the user hook;
- restore validation of the source and returned contexts;
- BASEPRI or PRIMASK policy and M7 errata handling;
- additional state such as CONTROL, PSPLIM, security-bank state, or future
  port-specific registers.

The port wrapper calls the common hook-invocation helper and the common
current-context publication helper. It does not choose a fiber, reinterpret a
NULL hook result, own hook lifecycle, or implement the recursion policy.

The mechanical split preserves critical-section placement:

- first selection enters and exits through the selected port C critical-section
  API;
- PendSV enters and exits through selected-port assembly;
- selected-port CPU-state capture does not add a second interrupt-mask layer.

CPU snapshot and critical-state records are private local selected-port data.
Common C neither allocates nor interprets them.

## Callable Port Boundary

The target callable boundary is approximately:

```c
void fiber_port_context_init(FiberContext *ctx,
                             void *stack_begin,
                             void *stack_end,
                             FiberEntryFn entry,
                             void *arg);
void fiber_port_context_validate_restore(FiberContext *ctx);
void fiber_port_context_validate_save_current(const FiberContext *ctx);
uintptr_t fiber_port_context_prepare_first_start(FiberContext *ctx);

FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void);
FIBER_API_NORETURN FIBER_GENERAL_REGS_ONLY
void fiber_port_panic_wait(void);

void fiber_port_require_start_environment(void);
void fiber_port_require_start_interrupt_state(void);
void fiber_port_runtime_prepare(void);
void fiber_port_require_schedule_environment(void);
void fiber_port_request_schedule(void);

void fiber_port_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                         void *user);
FiberContext *fiber_port_scheduler_pick_first_from_start(void);
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(
        FiberContext *current);

void fiber_exception_runtime_check(void);
void fiber_pendsv_init_lowest_priority(void);
FIBER_API_NORETURN
void fiber_port_start_first_context(uintptr_t msp_top);
void fiber_svc(void);
void fiber_pendsv(void);
```

Exact internal names may evolve during the mechanical split. The ownership and
the prohibition on common context layout knowledge are frozen.

The reverse port-to-common boundary is also explicit. After saving the current
CPU context, PendSV calls the selected-port
`fiber_port_scheduler_pick_next_from_pendsv()` wrapper. That wrapper applies
selected CPU-state and restore validation, then calls the common
general-registers-only helpers:

```c
FiberContext *fiber_internal_scheduler_invoke_pick_next(FiberContext *current);
void fiber_internal_scheduler_commit_current_context(FiberContext *next);
```

The common helpers invoke the application hook and publish the selected current
context. The selected wrapper rejects invalid restore targets before invoking
the common publication helper.

## Common Runtime Flow

The common API flow is frozen at the ownership level even if internal function
names change.

`fiber_init()` delegates all argument checks, context writes, stack
normalization, frame construction, sealing, and final validation to
`fiber_port_context_init()`. The selected port is the only implementation that
can safely validate selected context storage and frame geometry.

`fiber_port_context_init()` owns every selected-storage check. Before its first
write through `ctx` or into the supplied stack, it must:

1. validate selected-context alignment;
2. compute the context storage extent through `uintptr_t` and reject addition
   overflow;
3. reject overlap between `[ctx, ctx + sizeof(*ctx))` and the raw stack range;
4. validate every selected-port stack alignment and minimum-size precondition
   needed before construction.

Only after those checks pass may the port normalize stack bounds, construct the
initial frame, initialize metadata, seal the context, or write a canary.

Before `fiber_port_context_validate_restore()` reads `ctx->sp` or any boot
field, it must validate the context pointer itself: non-NULL, alignment, and
overflow-free `sizeof(*ctx)` extent. `fiber_init()` always applies the
integration RAM/code plausibility policy to context storage, supplied stack, and
entry. `FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1` additionally applies RAM
plausibility to an incoming runtime context before dereference and to its
declared stack after structural boot validation. `FIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1`
is an explicit bring-up opt-out that enables weak accept-any fallbacks; it is
not a production claim.

The selected Thread-mode schedule path validates only Thread mode, runtime
current-context ownership, and applicable interrupt-mask preconditions before
publishing `PENDSVSET`. PendSV owns the one authoritative save preflight before
its first current-context field access, so an externally pended PendSV also
fails closed. The preflight validates the runtime-owned current pointer, sealed
boot record, low-stack canary, and live PSP bounds. It deliberately does not
read `ctx->sp`, because that field names an older saved frame while the context
is executing. The selected port captures
`PRIMASK`, `CONTROL`, and every implemented priority/fault mask before this
preflight and validates the exact values again after it completes.

After saving the outgoing context, PendSV does not run a redundant restore
validation on it. The scheduler bridge validates exactly the returned `next`
context before publishing it as current and restoring it. Restore validation
retains startup MSP-plan validation because a scheduler can select a context
that has not previously run; save validation omits it because the running
context necessarily passed restore validation before it entered Thread mode.

With `FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1`,
`fiber_addr_plausible_ram()` and `fiber_addr_plausible_code()` can run from the
PendSV save/restore path. Their declarations and every override must use the
selected general-registers-only ABI and must not execute FP, MVE, allocation,
blocking, or scheduler-recursive code. They must preserve `PRIMASK`, `BASEPRI`
where present, `FAULTMASK` where present, and `CONTROL` exactly. Save and
restore preflights enforce that contract with `'r'`, `'B'`, `'t'`, and `'l'`
before continuing. In that mode the code hook validates each saved stacked PC
after the architectural xPSR/Thumb checks and before exception return.

`fiber_scheduler_set_pick_next()` accepts one non-NULL hook before start,
rejects replacement while selecting or running, and publishes the hook and user
pointer with the required common ordering barriers.

`fiber_start()` is one-shot and does not return:

1. validate common lifecycle and selected-port start preconditions;
2. prepare and validate port runtime state before invoking user scheduler code;
3. call the selected-port first-selection wrapper, which enters its C critical
   section, captures callback CPU state, invokes `pick_next(NULL, user)`, and
   validates the returned context;
4. leave the exact previous selected critical state restored;
5. prepare the selected first context and port-owned startup MSP state;
6. publish the selected context as current;
7. transfer through the selected port's mandatory SVC first-start path.

`fiber_schedule()` delegates environment validation and the request through
`fiber_port_require_schedule_environment()` and
`fiber_port_request_schedule()`. Common code owns only current-context
lifecycle validation and does not read IPSR, CONTROL, PRIMASK, BASEPRI,
FAULTMASK, SCB, or NVIC state. CPU preconditions and the request mechanism are
selected-port policy:

- a privileged non-MPU path validates Thread mode and every readable mask
  invariant, then may publish `PENDSVSET` directly with mandatory barriers;
- an unprivileged or MPU path validates only state safely observable from
  unprivileged Thread mode and issues a port-owned SVC;
- the yield SVC validates the instruction, service number, stacked-frame
  provenance, allowed origin, and real privileged CPU mask state before
  publishing `PENDSVSET` from Handler mode with mandatory barriers.

Neither request path selects a context or invokes the scheduler hook. The
scheduler bridge still runs only from PendSV after the current CPU context is
saved.

PendSV performs this sequence:

1. the selected port saves the current CPU context into its private layout;
2. the selected port enters its handler-side scheduler critical section;
3. the selected-port scheduler wrapper validates callback CPU state and the
   selected context, calls the common hook helper, and publishes current exactly
   once through the common runtime helper;
4. the selected port restores the exact previous critical state;
5. the selected port restores the returned context and exception-returns.

The structural opaque-context move must preserve this ordering, barriers, panic
semantics, and critical placement. Any later unification of first-selection and
PendSV callback wrappers is a separate behavior-changing decision.

## Context ABI Identity

Each selected context layout has immutable identity data:

```text
port identifier
layout version
context size
context alignment
feature mask
```

The port seal stores and validates this identity before restore. Layout identity
changes whenever field layout, enabled context slots, or required alignment
changes.

A declaration such as this is not by itself a link-time guard:

```c
extern const char fiber_port_context_abi_cm7_r0p1_v1;
```

The implementation must force a relocation to a versioned symbol, use a
versioned internal API symbol, or provide an equivalent link-time mismatch
failure. The compile matrix must include a negative mismatched-header/object
probe. This guard is mandatory before distributing precompiled library objects.
Source-integrated builds must compile all library and application translation
units with the same selected port and configuration until that guard exists.

## Optional Port Configuration

The default lifecycle is:

```text
fiber_init()
optional selected-port context configuration
make the context visible to the user scheduler
fiber_scheduler_set_pick_next()
fiber_start()
```

Each selected-port configuration function must:

1. call a common-owned internal lifecycle guard before touching port-private
   state;
2. validate context magic, port identity, and layout;
3. reject a running, runtime-started, or immutable context;
4. apply the private configuration;
5. rebuild any initial frame affected by CONTROL, PSPLIM, MPU, security, FP,
   MVE, PAC, or BTI policy;
6. rebuild the port-private seal;
7. leave the context fully restorable or explicitly unready.

The lifecycle guard may have a name such as
`fiber_internal_context_configuration_require_open()`. Its exact name is not
frozen, but its ownership is: selected ports must not inspect common current,
scheduler-hook, or runtime-state globals directly.

The library cannot observe when an application inserts a pointer into its own
scheduler data structure. The application must not mutate a context after making
it visible to the scheduler. Restore validation is the final fail-closed defense,
not a synchronization API.

Possible optional APIs include MPU region configuration, privilege/security
policy, and secure-context allocation. They are selected-port APIs and do not
expand the five-function common surface.

## MPU And Unprivileged Runtime Rules

The opaque selected-port scheme supports MPU ports, but opaque layout alone is
not sufficient. Every production MPU port must also enforce these rules:

- context construction, optional MPU/security configuration, scheduler-hook
  installation, and `fiber_start()` are privileged pre-start operations;
- `fiber_current()`, common `fiber_schedule()`, and the Thread-mode schedule
  request stub are executable from unprivileged code. They may read only state
  mapped as unprivileged-read-only and must not touch privileged-only data or
  registers before SVC;
- an unprivileged `fiber_schedule()` reaches privileged code through a
  port-owned SVC and never writes SCB/NVIC state directly;
- the yield SVC validates its instruction, service number, frame provenance,
  allowed origin, and privileged CPU state before pending PendSV;
- every restore of an unprivileged context guarantees PRIMASK is zero and,
  where implemented, BASEPRI and FAULTMASK are zero. Unprivileged reads of
  those registers are not accepted as proof of the restored state, and the port
  must not rely on SVC to repair mask state that could prevent or fault
  exception entry;
- the scheduler callback and current-context publication remain common-owned
  and execute only after PendSV has saved the complete outgoing context;
- common runtime state, scheduler-hook state, immutable context metadata, and
  port-private context state reside in privileged or unprivileged-read-only
  memory. Unprivileged fibers must not be able to modify them directly;
- the scheduler hook, its user state, and the complete hook call graph are
  trusted privileged code because PendSV invokes them in Handler mode. A port
  must not call untrusted fiber code while privileged;
- selected-port context layout owns MPU regions, privilege/CONTROL state,
  system-call state, PSPLIM, secure-context handles, PAC keys, and FP/MVE state
  required by that profile;
- static-lifetime secure context is compatible with this freeze. Dynamic secure
  context deletion remains outside the five-function lifecycle.

`fiber_current()` may return an identity pointer to unprivileged code, but the
selected public type contract and MPU mapping must prevent writable access to
its private fields. A C cast is not a security boundary.

## FreeRTOS Cortex-M Port Coverage Proof

The local FreeRTOS GCC port set at commit `a50edad` confirms that no additional
common context field is required. Each STM32-relevant family maps to
selected-port-private state:

| FreeRTOS reference family | STM32-relevant role | Selected-port ownership |
| --- | --- | --- |
| `ARM_CM0` | M0/M0+ | Thumb-1 frame, PRIMASK policy, SVC/PendSV assembly |
| `ARM_CM3` | M3 non-MPU | saved PSP and general-register frame |
| `ARM_CM3_MPU` | M3 MPU/unprivileged | MPU regions, CONTROL/system-call state, SVC yield |
| `ARM_CM4F` | M4/M4F non-MPU | saved PSP, EXC_RETURN, optional high FP state |
| `ARM_CM4_MPU` | M4/M4F MPU | MPU regions, CONTROL, FP state, SVC yield |
| `ARM_CM7/r0p1` | M7/M7F | FP state, BASEPRI policy, errata 837070 handling |
| `ARM_CM23` and `ARM_CM23_NTZ` | v8-M Baseline profiles | PSPLIM/CONTROL, optional MPU and SecureContext policy |
| `ARM_CM33`, `ARM_CM33_NTZ`, and TF-M companion | M33/M33F profiles | PSPLIM/CONTROL, MPU, security-domain and optional FP state |
| `ARM_CM55`, `ARM_CM55_NTZ`, and TF-M companion | M55/MVE profiles | PSPLIM/CONTROL, MPU, MVE/FP, PAC/BTI and security state |

FreeRTOS secure directories provide companion components, not independent
cooperative schedulers. Each runtime image selects exactly one runtime port
source group. When required, its build graph binds a matching Secure companion
artifact that may be produced by a separate security-domain target, or uses the
matching TF-M integration while TF-M supplies the Secure firmware. The companion
does not define a second callable fiber runtime ABI in the same runtime image.
Every configuration that changes `FiberContext` layout or saved-state meaning
gets a distinct layout/feature identity and participates in the ABI mismatch
guard.

When the companion is a separate firmware image, an ordinary relocation-based
link guard cannot prove cross-image compatibility. The selected security profile
must define a versioned gateway ABI and a build-manifest or startup compatibility
check covering the SecureContext contract, feature identity, and expected
service numbers before `fiber_start()` can succeed.

This proves architectural capacity, not implementation or hardware validation.
Each family still requires its own line-by-line parity ledger, compile/link
matrix, generated-assembly audit, trap tests, and board evidence. Dual-core STM32
devices are supported as one independent single-core fiber runtime per build;
SMP and cross-core migration remain outside this freeze.

## Mechanical Migration Sequence

### Commit 1: Documentation

`Define opaque selected-port context ABI`

- add this contract;
- supersede the old stable shared `FiberContext` layout;
- define header layering, seals, runtime MSP ownership, and ABI identity;
- make no source or runtime behavior changes.

### Commit 2: Structural Opaque Move

- add API/type and internal ABI headers;
- move the complete CM7 `FiberContext` into its selected type header;
- make common translation units unable to dereference or size the context;
- move context construction and restore validation entry points into CM7;
- preserve frame layout, assembly, panic codes, scheduler critical placement,
  current publication, and per-context MSP behavior;
- run the full compile/link matrix and STM32H7 build.

### Commit 3: Common Hardening Cleanup

- schedule-time IPSR, PRIMASK, BASEPRI, FAULTMASK, SCB, and direct-PendSV
  access now live behind `fiber_port_require_schedule_environment()` and
  `fiber_port_request_schedule()`; remaining non-schedule common CPU access
  moves with the opaque context transition;
- preserve the generated CM7 direct-request sequence and every existing CM7
  panic code while keeping the common current-owner guard between the IPSR and
  mask checks in the selected CM7 port;
- compare ranges through `uintptr_t`;
- validate context alignment before the first write;
- reject overlap between context storage and its own stack;
- remove the unsafe automatic local-stack macro;
- remove the dead heap-only `fiber_stack.c` helpers;
- make weak panic autonomous from application `Error_Handler`;
- move startup-only MSP policy out of per-context state;
- add forbidden-header and forbidden-symbol isolation probes;
- compile the common runtime without CMSIS or CPU special-register helpers and
  reject any common object that references SCB, NVIC, SVC, PendSV, or CPU mask
  access symbols;
- keep each behavior change small enough to diagnose independently.

### Commit 4: Hardware Freeze Validation

- H7 normal long run;
- every documented trap mode;
- pre-start and switching FPU stress;
- scheduler mask/control mutation traps;
- context alignment and overlap traps;
- first/next context corruption traps;
- stack canary and frame corruption traps;
- generated CM7 assembly comparison against the last validated checkpoint.

Only after this evidence passes may the project record a
`common-core-freeze-v1` architectural checkpoint and port CM0, CM3, CM4, CM23,
CM33, and CM55 without modifying common context logic.

## Validation Requirements

The compile matrix must prove:

- exactly one selected context type and runtime source group in each runtime
  image;
- any required Secure/TF-M companion is identity-matched, may be a separate
  artifact/target, and defines no second callable fiber runtime ABI in that
  runtime image;
- a separate Secure artifact exposes a versioned gateway ABI and fails build or
  startup compatibility validation when its manifest/service identity differs;
- exactly one definition of every mandatory callable port ABI symbol;
- common core compiles with incomplete `FiberContext`;
- forbidden common includes of selected complete type headers fail review/probes;
- selected public type headers compile without CMSIS;
- the public metadata type header remains type-only and no public selected type
  header includes an `internal/` header;
- port context size/alignment/layout identity is self-consistent;
- negative context alignment, extent-overflow, and context/stack-overlap probes
  fail before any context or stack byte is modified;
- unprivileged MPU profiles compile a yield-SVC request path and do not publish
  PendSV directly from Thread mode;
- the unprivileged schedule call graph has no privileged register access or
  writeable access to privileged runtime/context state before SVC;
- unprivileged restore validation proves zero PRIMASK and, where implemented,
  zero BASEPRI and FAULTMASK, while Handler-side yield-SVC tests reject
  corrupted privileged mask state;
- mismatched context header/object ABI fails before precompiled-object support is
  claimed;
- all source and documentation remain ASCII-only.

Compile coverage does not create a hardware support claim. Every production port
still needs its own runtime, FP/MVE, security, and errata evidence as applicable.
