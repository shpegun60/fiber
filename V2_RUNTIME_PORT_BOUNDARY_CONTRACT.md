# V2 CPU-Neutral Runtime Port Boundary Contract

## Status

This document defines the normative target for the final common-runtime to
selected-port boundary. It is a documentation-only architecture checkpoint.
It does not claim that the current source tree already implements every rule.

The current tree is transitional:

- `fiber_port_runtime_abi.h` still exposes more than the final eight functions;
- `fiber_start()` still coordinates port-private startup stages and transports
  an MSP value through common code;
- application-owned SVC and PendSV wrappers are still supported;
- wrapper/direct-vector configuration macros still exist;
- common-owned scheduler globals still contain `port` in their names.

Those facts are migration debt, not alternative long-term contracts. Every
mechanical slice below must reduce that debt without silently changing context
layout, save/restore order, critical-section placement, or panic behavior.

## Goal

The five-function public cooperative API remains stable while the common
runtime becomes CPU-neutral and each selected port becomes a complete CPU
engine.

Common code owns scheduler semantics and lifecycle. A selected port owns every
CPU mechanism required to construct, start, save, select under a protected
envelope, restore, and exception-return a context.

The boundary is intentionally narrower than the current implementation. Common
code must not transport or interpret MSP, PSP, PSPLIM, EXC_RETURN, CONTROL,
BASEPRI, VTOR, vector slots, frame offsets, or selected context fields.

## Stable Public API

The public API remains exactly:

```c
void fiber_init(FiberContext *ctx,
                void *stack_begin,
                void *stack_end,
                entry_t entry,
                void *arg);

FiberContext *fiber_current(void);

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                   void *user);

FIBER_API_NORETURN
void fiber_start(void);

void fiber_schedule(void);
```

No public API accepts a direct `from`, `to`, or first-context target. The
scheduler hook owns selection from the first context onward.

## Final Common-to-Port ABI

The complete generic callable ABI exported by one selected port is:

```c
void fiber_port_context_init(
        FiberContext *ctx,
        void *stack_begin,
        void *stack_end,
        entry_t entry,
        void *arg);

FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void);

FIBER_API_NORETURN FIBER_GENERAL_REGS_ONLY
void fiber_port_panic_wait(void);

void fiber_port_require_scheduler_configuration_environment(void);

void fiber_port_runtime_prepare_start(void);

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_runtime_select_first(void);

FIBER_API_NORETURN
void fiber_port_runtime_start_first(FiberContext *first);

void fiber_port_runtime_schedule(void);
```

These declarations are CPU-neutral. The generic ABI must not expose:

- an MSP value or startup-MSP record;
- a saved-SP or frame offset;
- SVC or PendSV implementation symbols;
- vector-routing mode flags;
- context save/restore validators;
- exception-priority setup helpers;
- CPU critical-state tokens;
- CMSIS register types or selected-port traits.

All other port helpers are private to the selected port. They may be split
across C, inline assembly, dedicated assembly, boot, exception, FPU, MPU,
security, or errata files without expanding this ABI.

## ABI Function Semantics

### `fiber_port_context_init`

Constructs and seals one selected-port `FiberContext`. The port owns all
argument checks, context layout, synthetic frame construction, stack geometry,
initial EXC_RETURN, optional FP/MVE state, and final restore validation.

### `fiber_port_runtime_memory_barrier`

Provides the ordering barrier used by common-owned scheduler state. It is safe
from every common call site and uses the selected CPU/compiler requirements.

### `fiber_port_panic_wait`

Provides the terminal port wait used after common panic reporting. It never
returns and must not depend on application error handlers.

### `fiber_port_require_scheduler_configuration_environment`

Validates only the CPU environment in which the public scheduler hook may be
installed. It does not store the hook, inspect scheduler policy, or mutate
common lifecycle state. Common code performs the actual one-time store.

### `fiber_port_runtime_prepare_start`

Validates and reconciles all port-owned one-shot startup state. This includes,
as applicable:

- Thread/Handler mode and privilege preconditions;
- PRIMASK, BASEPRI, and FAULTMASK preconditions;
- exclusive exception-handler integration evidence;
- active vector-table routing validation;
- SVC and PendSV priorities and implemented priority bits;
- stale PendSV cleanup;
- FPU, MPU, security-domain, and architecture-errata policy;
- startup MSP planning, validation, and port-private storage.

It does not invoke the scheduler hook and does not publish current context.
Link-time exclusivity of strong handlers is proved by the linker and matrix;
runtime preparation verifies the active vector table and CPU state.

### `fiber_port_runtime_select_first`

Creates the port-owned CPU critical envelope for the first scheduler call,
invokes the common scheduler policy with `current == NULL` through the reverse
internal boundary, restores the exact previous CPU critical state, validates
the returned context, and returns it. It neither publishes current nor starts
the context.

### `fiber_port_runtime_start_first`

Consumes the already selected and common-published first context. The port
revalidates every dynamic first-restore invariant it requires, performs the
mandatory SVC first-start transfer, and never returns. Startup MSP state remains
private to the port.

### `fiber_port_runtime_schedule`

Implements one cooperative scheduler request. It owns CPU call-mode and mask
validation plus the selected direct-PendSV or privileged yield-SVC mechanism.
It does not choose a context. Selection occurs only after the current CPU
context has been saved in PendSV.

Where historical panic precedence requires the common current-owner check
between port CPU checks, the port calls the approved reverse common guard at
that exact point. The mechanical ABI collapse does not silently change existing
`fiber_schedule()` panic precedence.

## Common Ownership

Common runtime exclusively owns:

- the five public API functions;
- scheduler hook storage;
- scheduler user-pointer storage;
- current-context storage and publication;
- scheduler configured/selecting/running lifecycle;
- hook replacement and recursion policy;
- scheduler policy invocation;
- NULL scheduler-result semantics;
- current-context publication ordering;
- public panic-code precedence.

Common-owned globals and helpers must not use `port` in their names. The target
state names are shaped like:

```text
fiber_internal_current_context
fiber_internal_scheduler_pick_next
fiber_internal_scheduler_user
```

The rename is mechanical. It does not move scheduler ownership into a port or
change assembly publication order.

## Selected-Port Ownership

The selected port exclusively owns:

- complete context and boot-record layout;
- synthetic initial frame construction;
- save and restore assembly;
- dynamic save/restore validation;
- scheduler callback CPU critical envelope;
- first-context start mechanics;
- cooperative yield mechanism;
- SVC and PendSV handlers;
- exception priority setup and readback validation;
- active vector wiring validation;
- MSP, PSP, PSPLIM, CONTROL, and EXC_RETURN policy;
- FPU, MVE, MPU, TrustZone, and security-domain policy;
- CPU revision checks and architecture errata.

The port may call a small reverse internal common boundary to invoke scheduler
policy, validate common lifecycle, and publish current context. Those calls do
not give the port ownership of scheduler policy.

## Reverse Port-to-Common Boundary

The reverse boundary remains internal and CPU-neutral. It provides operations
equivalent to:

```text
begin first selection lifecycle
end first selection lifecycle
invoke pick-next policy
require a current context for scheduling
commit or seed current context
load current context with required ordering
query whether the scheduler hook is configured
```

Exact internal helper names may change. The selected port must not directly
reinterpret the common lifecycle flags or duplicate NULL/hot-swap policy.

## Normative `fiber_start()` Order

`fiber_start()` is one-shot and does not return. Its order is normative:

```text
1. Common lifecycle validation
   - scheduler configured
   - current == NULL

2. Port start preparation
   - CPU environment
   - interrupt masks
   - exception ownership and active vector wiring
   - exception priorities
   - CPU feature and errata policy
   - startup MSP plan

3. Port-protected first scheduler selection

4. Common current-context publication

5. Port first-context start through SVC
```

The public panic precedence is therefore:

```text
'K' or 'k' before CPU-environment panic codes
```

This is intentional. Invalid common lifecycle state fails before any port-owned
CPU configuration is changed. Trap tests must freeze this precedence.

The target common flow is equivalent to:

```c
FIBER_API_NORETURN
void fiber_start(void)
{
    FIBER_REQUIRE(fiber_internal_scheduler_is_configured() != 0u, 'K');
    FIBER_REQUIRE(fiber_current() == NULL, 'k');

    fiber_port_runtime_prepare_start();

    FiberContext *const first = fiber_port_runtime_select_first();
    fiber_internal_runtime_seed_current_context(first);

    fiber_port_runtime_start_first(first);
    FIBER_API_UNREACHABLE();
}
```

This pseudocode freezes ownership and order, not the spelling of private common
helpers.

## Exception Handler Ownership

The selected port exclusively defines strong symbols:

```c
void SVC_Handler(void);
void PendSV_Handler(void);
```

The selected handler may contain the naked assembly body directly or branch to
a port-private assembly label. `fiber_svc()` and `fiber_pendsv()` are not part
of the final generic ABI.

The application must not define competing strong SVC or PendSV handlers.
Duplicate strong definitions are intentional link-time configuration failures.
CubeMX-generated strong definitions must be removed or excluded from the build;
they must not remain as another wrapper layer.

The final contract has no wrapper/direct selection:

- remove `FIBER_SVC_VECTOR_DIRECT`;
- remove `FIBER_PENDSV_VECTOR_DIRECT`;
- remove `FIBER_SVC_WIRED`;
- remove `FIBER_PENDSV_WIRED`;
- remove application SVC/PendSV branch wrappers.

These names may remain only during the mechanical migration. They are not
supported alternatives after every selected port owns its handlers.

Runtime vector-table patching is not part of the default contract. A future
dynamic-vector policy would be an explicit, separately validated integration
mode with clear ownership and rollback rules.

## Static Archive and Dead-Code Rules

A startup-file weak alias alone may not extract a handler object from a static
archive. The selected port must create a strong relocation from an always-used
port object to its handler object, or place the handlers in an object that is
already required by the runtime ABI.

The build proof must cover:

- a static archive;
- `--gc-sections`;
- LTO where supported;
- startup weak aliases;
- no application handler wrappers.

The selected strong handlers must remain in the final ELF and must satisfy the
active vector-table relocations.

## Validation Proofs

### Common Compile Proof

Every common runtime translation unit must:

- compile without CMSIS;
- compile without a selected complete context or selected-port header;
- include only public common headers and the approved generic runtime ABI;
- have no direct SCB, NVIC, IPSR, CONTROL, MSP, PSP, PSPLIM, BASEPRI,
  FAULTMASK, SVC, PendSV, or architecture-intrinsic dependency;
- reference no port symbols except the approved eight generic ABI functions.

Undefined references to the approved generic ABI are expected until the
selected port is linked.

### Synthetic Link and ELF Proof

For every selected port, the matrix must prove:

- exactly one definition of each of the eight generic ABI functions;
- one strong `SVC_Handler` definition;
- one strong `PendSV_Handler` definition;
- no application wrappers are required;
- a deliberate competing strong handler fails to link;
- handler archive members are extracted;
- synthetic vector slots 11 and 14 resolve to the expected selected-port
  handler symbols;
- `--gc-sections` does not discard required handlers;
- LTO does not discard or merge away required handler ownership;
- no removed transitional ABI symbol is referenced by common objects.

### Board Runtime Proof

The board validation must prove the runtime state after startup and any
bootloader relocation:

```text
the selected port identifies the expected active vector-table source
slot 11 resolves to selected-port SVC_Handler
slot 14 resolves to selected-port PendSV_Handler
priority readback matches selected-port policy
stale PendSV state is cleared before first start
the first SVC reaches the selected-port handler
a later PendSV reaches the selected-port handler
```

When VTOR is implemented, the selected port must read back the applicable
`SCB->VTOR` bank and prove that it names the expected active table. When VTOR
is not implemented, the port must validate the architecture/platform-defined
vector base, normally address zero, together with any required memory-remap
policy. STM32H7 validation always includes direct `SCB->VTOR` readback.

The synthetic ELF proof and board proof are complementary. Linker evidence
cannot prove that a bootloader did not change the active vector source or
platform remapping at runtime.

## Mechanical Migration Slices

Each slice is independently compile/link checked. Runtime behavior changes are
not mixed with unrelated layout work.

1. Narrow `fiber_port_runtime_abi.h` to the eight generic functions while
   adding private selected-port headers for the displaced declarations.
2. Rename common-owned scheduler globals and update exact assembly references
   without changing publication order.
3. Collapse start preparation, first selection, first start, and schedule
   request choreography behind the new generic functions.
4. Add strong selected-port `SVC_Handler` and `PendSV_Handler` definitions while
   preserving the existing validated assembly bodies.
5. Remove CubeMX/application wrappers and delete wrapper/direct configuration
   switches.
6. Add common compile-isolation and synthetic link/ELF proofs, including the
   static-archive extraction and duplicate-handler negative tests.
7. Run the full H7 normal, FPU, startup, trap, active-VTOR, SVC, and PendSV
   hardware validation suite.

Strong handler ownership is intentionally after ABI narrowing and private
header creation. This keeps symbol ownership, lifecycle choreography, and
exception wiring from changing in one undiagnosable step.

## Freeze Conditions

The common runtime boundary is frozen only when:

- the public API still contains exactly five functions;
- the common-to-port ABI contains exactly the eight functions in this document;
- common runtime objects pass the CMSIS-free symbol allowlist;
- common code transports no CPU register value or frame geometry;
- common scheduler state has CPU-neutral names and remains common-owned;
- every selected port provides strong exclusive SVC and PendSV handlers;
- wrapper/direct macros and application wrappers are gone;
- synthetic archive/link/vector/LTO proofs pass for every compiled port;
- H7 board validation passes after the final handler migration;
- existing panic ordering is preserved except for the documented
  `fiber_start()` precedence change;
- port parity ledgers record the final exception ownership model.

Only after these conditions pass may this checkpoint be used as the stable
base for porting the remaining FreeRTOS STM32 Cortex-M profiles.
