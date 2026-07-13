# V2 Opaque Selected-Port Context Contract

## Status

This document defines the target common-core boundary that must be completed
before adding production Cortex-M ports in bulk.

It supersedes every older v2 statement that requires one shared, common-known
`FiberContext` or `FiberBoot` layout for all ports. The current source tree still
uses that transitional layout; this document describes the migration target, not
the behavior of the current checkpoint.

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
  fiber_context_metadata_types.h
  fiber_core.h

  internal/
    fiber_core_internal.h
    fiber_context_metadata.h
    fiber_runtime_state.h

  port/
    fiber_port_types_selected.h
    fiber_port_abi_types_selected.h
    fiber_port_abi.h

    ARM_CM7/r0p1/
      fiber_port_types.h
      fiber_port_abi_types.h
      fiber_portmacro.h
      fiber_port.c
      fiber_port_exception.c
      FREERTOS_PARITY.md
```

`fiber_api_types.h` contains only forward declarations and callback types. It
must not include CMSIS or a selected port.

`fiber_api_attributes.h` contains public compiler attributes such as the
noreturn declaration and `FIBER_SCHEDULER_HOOK_ATTR`. It may detect compiler
capabilities but must not include CMSIS, CPU feature traits, register helpers,
or inline assembly.

`fiber_context_metadata_types.h` is a public type-only utility header. It
contains the complete CPU-neutral metadata type because a selected public
`fiber_port_types.h` may embed that type. It contains no metadata helper
functions, selected-port policy, CMSIS dependency, register helper, or inline
assembly. `internal/fiber_context_metadata.h` declares the common helper
operations that initialize and validate the type.

`fiber_port_types.h` is a public type-only selected-port header. It completes
`FiberContext` but must not include `mcu_core.h`, SCB/NVIC definitions, CMSIS
intrinsics, `fiber_portmacro.h`, register helpers, or inline assembly.
It may include standard integer/size types, `fiber_api_types.h`, CPU-neutral
metadata types, compiler-neutral alignment declarations, and port-local
type-only MPU/security records under the same restrictions.

The selected public type header also exposes only the storage facts required by
application allocation, such as context alignment, stack alignment, and minimum
stack bytes. It does not expose software-frame offsets, EXC_RETURN slots, or
register-save geometry. Those remain private implementation and compile-audit
facts.

`fiber_port_abi_types.h` is an internal type-only selected-port header. It may
complete private token types that common code must allocate without interpreting,
such as scheduler CPU-state snapshots or critical-section tokens. It must not
complete `FiberContext` for common translation units.

`fiber_port_abi.h` declares callable selected-port operations using pointers to
the incomplete `FiberContext`. It must not expose context fields or frame offsets.

`fiber_core.h` is the public umbrella. It includes the API types, public
attributes, selected complete context type, and public declarations.

Common `.c` files include the API declarations, internal runtime declarations,
selected internal ABI types, and callable port ABI. They do not include the
selected complete context type. Therefore these expressions must fail to compile
in common code:

```c
ctx->port_private_cpu;
sizeof(FiberContext);
_Alignof(FiberContext);
offsetof(FiberContext, any_field);
```

## Common Context Metadata

CPU-neutral immutable inputs may use one shared utility type declared in
`fiber_context_metadata_types.h`:

```c
typedef struct FiberContextMetadata {
    uintptr_t raw_stack_begin;
    uintptr_t raw_stack_end;
    FiberEntryFn entry;
    void *arg;

    uint32_t magic;
    uint16_t version;
    uint16_t sealed;
    uint32_t hash;
} FiberContextMetadata;
```

CPU-neutral helpers declared by `internal/fiber_context_metadata.h` may
initialize and validate this object:

```c
void fiber_metadata_init(FiberContextMetadata *metadata,
                         void *stack_begin,
                         void *stack_end,
                         FiberEntryFn entry,
                         void *arg);

void fiber_metadata_validate(const FiberContextMetadata *metadata);
```

The selected port embeds the metadata at any private offset and calls the common
helpers. Common runtime code does not request a metadata accessor and does not
learn that offset.

The common metadata hash is an accidental-corruption check, not a security
authentication primitive and not the final proof that a context is restorable.

## Port-Private Integrity Seal

Every production port owns final context sealing and restore validation:

```c
void fiber_port_context_seal(FiberContext *ctx);
void fiber_port_context_validate_seal(const FiberContext *ctx);
void fiber_port_context_validate_restore(const FiberContext *ctx);
```

The immutable port seal covers at least:

- the common metadata hash;
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

The first mechanical opaque-context commit may temporarily retain current
per-context MSP fields to preserve generated behavior. Those fields are
transitional and are moved to port-owned startup state in a later, separately
validated behavior-changing commit. The contract does not require MSP fields in
future context layouts.

## Scheduler Ownership

Common runtime owns:

- scheduler hook and user pointer storage;
- `current == NULL` first-selection semantics;
- recursion and hot-swap guards;
- missing-hook and NULL-result failures;
- calling selected-port restore validation;
- publication of the new current context;
- ordering barriers around common runtime state.

The selected port owns:

- scheduler critical-section mechanics;
- CPU-state snapshot and validation around the user hook;
- BASEPRI or PRIMASK policy;
- M7 errata handling for BASEPRI writes;
- additional state such as CONTROL, PSPLIM, security-bank state, or future
  port-specific registers.

The port must not choose a fiber, reinterpret NULL, publish current, or implement
the recursion policy.

For the structural migration, preserve the current critical-section placement:

- first selection enters and exits through the existing C critical-section API;
- PendSV enters and exits through the existing selected-port assembly;
- state capture and validation do not add a second interrupt-mask layer.

Do not introduce `fiber_port_call_scheduler_guarded()` in the mechanical move.
Unifying callback invocation and critical-section ownership is a separate
behavior-changing decision.

Incomplete scheduler snapshot and critical-state types cannot be instantiated
by common C. The selected internal type-only ABI header must provide complete
private types:

```c
typedef struct FiberPortSchedulerCpuState {
    uintptr_t port_private_words[/* selected-port constant */];
} FiberPortSchedulerCpuState;

typedef struct FiberPortSchedulerCriticalState {
    uintptr_t port_private_words[/* selected-port constant */];
} FiberPortSchedulerCriticalState;

void fiber_port_scheduler_state_capture(FiberPortSchedulerCpuState *state);
void fiber_port_scheduler_state_validate(
        const FiberPortSchedulerCpuState *state);

void fiber_port_scheduler_critical_enter(
        FiberPortSchedulerCriticalState *state);
void fiber_port_scheduler_critical_exit(
        const FiberPortSchedulerCriticalState *state);
```

The exact selected types may use private named fields instead of word arrays.
Common code may allocate and pass them but must not inspect them. The C critical
token is used by first selection. PendSV may keep the equivalent token in its
port-local assembly frame; this does not create a second critical section.

## Callable Port Boundary

The target callable boundary is approximately:

```c
void fiber_port_context_init(FiberContext *ctx,
                             void *stack_begin,
                             void *stack_end,
                             FiberEntryFn entry,
                             void *arg);

void fiber_port_context_validate_restore(const FiberContext *ctx);
void fiber_port_context_prepare_first_start(const FiberContext *ctx);

void fiber_port_require_start_environment(void);
void fiber_port_require_schedule_environment(void);
void fiber_port_runtime_prepare(void);
void fiber_port_runtime_validate(void);

void fiber_port_scheduler_state_capture(FiberPortSchedulerCpuState *state);
void fiber_port_scheduler_state_validate(
        const FiberPortSchedulerCpuState *state);
void fiber_port_scheduler_critical_enter(
        FiberPortSchedulerCriticalState *state);
void fiber_port_scheduler_critical_exit(
        const FiberPortSchedulerCriticalState *state);

FIBER_API_NORETURN
void fiber_port_start_first_context(FiberContext *first);

void fiber_port_request_schedule(void);
void fiber_svc(void);
void fiber_pendsv(void);
```

Exact internal names may evolve during the mechanical split. The ownership and
the prohibition on common context layout knowledge are frozen.

The reverse port-to-common boundary is also explicit. PendSV calls one stable,
general-registers-only common scheduler bridge after saving the current CPU
context and entering the selected-port critical section:

```c
FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_scheduler_pick_next_from_pendsv(
        FiberContext *current);
```

The bridge invokes the application hook, validates callback CPU-state
preservation, rejects NULL or corrupt results, publishes the selected current
context, and returns the same opaque pointer to the port for restore. The port
does not publish current or reinterpret scheduler results.

## Common Runtime Flow

The common API flow is frozen at the ownership level even if internal function
names change.

`fiber_init()` performs CPU-neutral argument checks and delegates all context
writes, stack normalization, frame construction, sealing, and final validation
to `fiber_port_context_init()`. Common code checks only facts available without
a complete context type: a non-NULL context pointer, raw stack range monotonicity
through `uintptr_t`, a non-NULL entry point, and common lifecycle preconditions.

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

`fiber_scheduler_set_pick_next()` accepts one non-NULL hook before start,
rejects replacement while selecting or running, and publishes the hook and user
pointer with the required common ordering barriers.

`fiber_start()` is one-shot and does not return:

1. validate common lifecycle and selected-port start preconditions;
2. prepare and validate port runtime state before invoking user scheduler code;
3. enter the port C critical section and capture callback CPU state;
4. call `pick_next(NULL, user)`, validate preserved CPU state and the returned
   context, then leave the exact previous critical state restored;
5. prepare the selected first context and port-owned startup MSP state;
6. publish the selected context as current;
7. transfer through the selected port's mandatory SVC first-start path.

`fiber_schedule()` validates only common running/current ownership and calls
`fiber_port_request_schedule()`. Common code does not read IPSR, CONTROL,
PRIMASK, BASEPRI, FAULTMASK, SCB, or NVIC state. CPU preconditions and the
request mechanism are selected-port policy:

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
3. the common scheduler bridge calls `pick_next(current, user)`, validates the
   callback and selected context, and publishes current exactly once;
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

- replace common-core IPSR, CONTROL, PRIMASK, BASEPRI, FAULTMASK, SCB, and
  direct-PendSV access with `fiber_port_request_schedule()`;
- preserve the generated CM7 direct-request sequence and every existing CM7
  panic code while moving that sequence into the selected CM7 port;
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
