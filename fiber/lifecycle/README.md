# Fiber V1 Lifecycle

This static-storage consumer adds Fiber lifecycle and scheduling policy above
the Context-owned runtime. It does not introduce another execution engine,
current slot, dispatcher, port ABI or CPU context representation. The Context
ownership checkpoint and separate pure/mixed consumer qualification precede
this publication; backend, feature and hardware qualification remain separate.

## Surface

| Operation | Responsibility |
| --- | --- |
| `fiber_v1_init` | Construct contained Context with the original user entry/arg |
| `fiber_v1_current` | Return Fiber identity only, NULL before Context start |
| `fiber_v1_set_scheduler` | Register the consumer adapter, then commit policy fields |
| `fiber_v1_start` | Delegate one-shot startup to Context; never return |
| `fiber_v1_yield` | Delegate the Thread-mode request, not an ISR request |

`FiberV1` contains the existing `CtxrtContextV1` at offset zero and one private
lifecycle word. It is a distinct object type, not a new spelling for the old
`FiberContext` CPU object. The old five-call API is untouched. Context still
owns the only current slot, dispatcher registration, first-selection latch,
configuration gate and publication. `FiberRuntimeV1` contains just a selector
and user pointer, supplied to Context as its dispatcher user. There is no
process-global Fiber policy or current pointer.

Use caller-owned static objects initialized in both C and C++ as follows:

```c
static FiberV1 worker = FIBER_V1_INITIALIZER;
static FiberRuntimeV1 runtime = FIBER_RUNTIME_V1_INITIALIZER;
```

Within a selected Context storage cohort, the caller-owned `FiberV1` and
`FiberRuntimeV1` layouts, the five `fiber_v1_*` operations and their lifecycle
semantics are the frozen v1 contract. Fields remain private by contract despite
being complete for static allocation. Do not silently add/reorder fields or
change storage, state interpretation or API semantics under the same v1 names.
Incompatible evolution requires a new versioned storage/API contract. Changing
the selected backend still requires its matching Context storage cohort.

Storage and stacks have static lifetime. Initialization requires zero/EMPTY
storage. Once initialized, neither Fiber nor contained Context may be copied,
moved, reclaimed or reinitialized. The complete Fiber object, including its
lifecycle tail and padding, must not overlap its stack. Extent arithmetic is
checked for uintptr_t overflow before dereferencing metadata. This does not
prove arbitrary pointer/RAM validity: every non-NULL Fiber or Runtime pointer
must designate a valid, correctly aligned, caller-owned object accessible to
the privileged caller. This is a precondition, not a promise that arbitrary
bogus/misaligned pointers reach a controlled panic. Context's prefix map hooks
cannot establish the validity of the lifecycle tail or Runtime policy fields.
Actual Context construction still owns all its normal
address-map checks. Runtime storage must be disjoint from every execution stack;
without a registry that remains a caller contract.

Runtime's fields are private by contract;
change policy only through `fiber_v1_set_scheduler` before Context begins first
selection. Installation calls Context before changing either field, so a failed
hot replacement cannot change the active policy. NULL selection is passed as
NULL dispatch for Context's existing `K` rejection. NULL selection results are
returned untouched for Context's existing `N` rejection.

Exactly one consumer owns the Context dispatcher. Do not mix this adapter with
direct Context or legacy scheduler registration, or dispatch raw Contexts that
are not contained in valid, fixed-address Fibers. Startup/registration is
serialized; there is no supported concurrent startup or ISR registration.

## Static Round Robin

Run `app_start_fibers` once during privileged startup after board/HAL
initialization. Port-owned runtime setup stays inside `fiber_v1_start` through
Context; do not call private bootstrap helpers manually. Both Fibers, both
stacks and the runtime have static
storage and must stay disjoint. The selector owns no second current pointer:
NULL selects the first Fiber, and each subsequent yield selects the other.
With automatic M4/M7 selection, include the board's CMSIS/device header before
`fiber_v1.h`; an explicit build-selected integration supplies the matching type
header and selection definitions instead.

```c
#include "fiber/lifecycle/fiber_v1.h"

static FiberV1 first = FIBER_V1_INITIALIZER;
static FiberV1 second = FIBER_V1_INITIALIZER;
static FiberRuntimeV1 runtime = FIBER_RUNTIME_V1_INITIALIZER;
static uint32_t first_stack[256] __attribute__((aligned(32)));
static uint32_t second_stack[256] __attribute__((aligned(32)));

static FIBER_V1_SELECT_ATTR
FiberV1 *select_next(FiberV1 *current, void *user)
{
    (void)user;
    return current == &first ? &second : &first;
}

static void worker(void *arg)
{
    (void)arg;
    for (;;) {
        /* Do one bounded unit of application work, then cooperate. */
        fiber_v1_yield();
    }
}

CTXRT_API_NORETURN void app_start_fibers(void)
{
    fiber_v1_init(&first, first_stack, first_stack + 256, worker, NULL);
    fiber_v1_init(&second, second_stack, second_stack + 256, worker, NULL);
    fiber_v1_set_scheduler(&runtime, select_next, NULL);
    fiber_v1_start();
}
```

This GCC C/C++ example uses the classic scalar baseline. Size stacks for the
actual workload and selected backend; 1024 bytes is not a universal sizing
guarantee. The worker receives NULL, not a pointer to privileged Fiber metadata.
The selector and every callee require `FIBER_V1_SELECT_ATTR`; application work
belongs in the worker, not the privileged selector.

## Build

The portable sources are the Context engine/state/panic providers, its optional
configuration provider (required by this consumer), and `fiber_v1.c`. Obtain the
current exact source list from the repository root without adding the legacy
shim:

```powershell
$repo = (Get-Location).Path
. ./tools/runtime_sources.ps1
$portable = @(Get-RuntimeSourcePaths -RepositoryRoot $repo -Roles @(
    'engine', 'state', 'panic', 'optional_configuration', 'facade_bridge'
)) + @((Join-Path $repo 'fiber/lifecycle/fiber_v1.c'))
```

Compile `$portable` and the application translation unit above with exactly one
concrete backend's complete source group. Preserve that backend's CPU/FPU ABI
flags, selected-port definitions, private include directory, CMSIS/device header,
startup/vector ownership, memory hooks and linker contract. Compile the
build-owned `fiber/port/fiber_port_context_cohort_expectation.c` through that
same private include directory and retain its expectation section as required
by the backend. The repository root is an include directory for the public
header shown above. Add `fiber/fiber_core.c` only when actual legacy five-call
consumers also need it; never register a second dispatcher alongside this one.

## Privilege And Lifetime

Construction, registration, all metadata access, and the complete selector call
graph require privileged execution. For a portable static setup, perform
construction and configuration during privileged startup. Context protects the
dispatcher envelope; selectors and all their callees must use
`FIBER_V1_SELECT_ATTR` and obey its sensitive general-registers-only contract.

The adapter accepts INITIALIZED or STARTED targets, marking INITIALIZED as
STARTED before returning the contained Context. STARTED means **selected for
execution**, not that the entry ran. The backend can subsequently reject the
target or fail restoring it; that is terminal, without lifecycle rollback.
Outgoing non-NULL Fibers must already be STARTED. Other states are rejected
with `L`. `fiber_v1_init(NULL, ...)` rejects with `n`, as does
`fiber_v1_set_scheduler(NULL, non_null_selector, user)` before Context
registration. A NULL selector instead delegates a NULL dispatcher to Context:
`fiber_v1_set_scheduler(NULL, NULL, user)` reaches its existing environment and
lifecycle guards first, then rejects with `K` when those guards permit cold
registration. It is not an unconditional `n`; an earlier Context guard retains
its own rejection precedence.

There is no entry trampoline. The original user entry and arg go directly to
Context construction, and the existing entry-return `R` panic is unchanged.
Entry `arg` and selector `user` are retained pointers, not copied values. Their
pointees must outlive every use. Default startup rewinds MSP, so startup-local
C++ state cannot safely back these pointers merely because start never returns.
The arg must already satisfy the selected profile's application-memory rules;
it is not implicitly a pointer to privileged Fiber storage. No COMPLETED or
FAILED tracking, completion callback, queue, tick or ISR API is claimed.

Current/yield never read a Fiber or Runtime object. Current uses only the
asserted first-member pointer mapping; an unprivileged caller may compare the
returned opaque identity but must not dereference privileged metadata. There
is no public state-query operation. `fiber_v1_privileged.h` provides only an
optional contained-Context identity accessor for privileged integration.
Optional feature APIs and the global Context configuration-open guard remain
mandatory; INITIALIZED does not permit configuration after Context closes it.

## Optional Context Services

Init explicitly selects `context/context_configuration_abi.h`, retains its v1
anchor and calls the real configuration-open guard before Context construction
or the INITIALIZED write. A NULL current slot does not prove that this gate is
open: failed startup or first selection can irreversibly close it. This is an
optional Context integration service which is **mandatory when using this Fiber
consumer**, not a ninth mandatory port operation or another latch. Pure Context
consumers do not require the configuration object and do not select it by
including or using the five-operation Context API. Link exactly one compatible
configuration provider when linking this Fiber consumer's initialization path.

Panic is declared through Context-owned `context/context_panic.h`. Its retained
historical symbol spelling is `fiber_panic`; this consumer adds no replacement
panic hook or fallback and preserves the existing application override.

Registration uses Context's existing environment and pre-first-selection
checks. It is privileged and serialized, and Context registration must succeed
before Runtime policy fields change. No additional global registration guard
or fabricated Context argument is required. Initialization and selected
optional-feature configuration still obey the configuration-open service.

## Maintained Qualification

The maintained gate is `tools/test_fiber_lifecycle.ps1`, with its exact scope
documented in `tools/fixtures/fiber_lifecycle/README.md`. Run from the repository
root with explicit ARM GCC and CMSIS paths:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_fiber_lifecycle.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC -CmsisCore $env:CMSIS_CORE_INCLUDE `
  -HostGcc C:/msys64/ucrt64/bin/gcc.exe
```

Host processes execute the production Fiber consumer with the actual
role-selected Context/common implementation, singleton state and optional
configuration service. Only the eight forward CPU operations are mocked;
private engine state is neither replaced nor reset. Fresh-process scenarios
and compiled causal controls cover lifecycle transitions, registration failure
before policy mutation, configuration closure, direct entry/arg forwarding,
identity-only current/yield and complete-Fiber stack disjointness.

Actual classic port sources and CMSIS are used for synthetic ELF compilation
and linkage, including section GC/native LTO, selected storage-identity
dependencies and Thread-versus-privileged placement checks. These links do not
execute the target CPU constructor or exception transfer, or prove MPU
enforcement, board behavior or arbitrary user-policy safety. Constructor R9
execution evidence belongs to its separately maintained gate.

Receipts identify the runtime ownership phase and admitted consumer cohorts.
An old-owner/additive-bridge receipt does not qualify ownership inversion.
The Context-owner checkpoint and both mixed-legacy and Context/Fiber-only
cohorts have been accepted independently. Publication changes comments and
documentation only, not the five operations or their implementation. Receipts
remain tied to their exact captured bytes; rerun the maintained gate for changed
source/documentation bytes rather than relabeling an earlier receipt.
