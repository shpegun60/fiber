# Context V1 Migration Surface

This directory introduces the versioned execution-context interface. It is an
additive migration checkpoint, not completed Context/Fiber separation.

`context_api_decl.h` exposes only opaque types and callable declarations;
`context.h` additionally selects complete caller-owned backend storage and its
existing storage-cohort guard. Neither imports a Fiber lifecycle representation.

| Operation | Contract |
| --- | --- |
| `ctxrt_v1_init` | Construct one context in caller-owned storage |
| `ctxrt_v1_current` | Return the current context identity, or NULL before start |
| `ctxrt_v1_set_dispatcher` | Install policy and user data before first selection |
| `ctxrt_v1_start` | Validate, select the first context and start; never return |
| `ctxrt_v1_yield` | Request dispatch from Thread mode, not an ISR |

The dispatcher definition and its complete call graph must obey
`CTXRT_DISPATCH_ATTR`. A NULL input denotes first selection; every result must
be a non-null initialized context of the selected cohort. Registration may be
replaced before first selection, but not after it begins. Contexts and stacks
have static lifetime. Returning from an entry still panics with `R`; there is
no completion, reclamation, direct-target transfer, tick or ISR API in v1.

## Transitional Build

Compile `fiber/fiber_context_compat.c` alongside the existing common runtime
sources and exactly one concrete backend. It implements the five new exported
functions as one-way calls into the existing engine. Legacy and Context callers
share the same dispatcher, current slot, panic override and lifecycle latches.
Do not create a second runtime or compile an alternative state implementation.

`CtxrtContextV1` names the existing CPU-storage tag, not a second struct. Legacy
`FiberContext` pointers and callbacks are type-compatible without casts. The
selected backend still owns layout, optional features and cohort identity.
There are deliberately no generic optional-feature stubs.

The compiler-policy header and selected public storage selector retain their
old physical paths temporarily. These are explicit migration dependencies.
Ownership inversion must next make the old API call the Context engine, move
the actual orchestration/state implementation and leave exactly one provider
of every frozen reverse-v1 symbol. Only then can a genuine Fiber lifecycle
consumer be added above this interface. The facade alone does not satisfy that
later architecture gate.

See `CONTEXT_REFACTOR_BASELINE.md` and `CONTEXT_FIBER_ARCHITECTURE.md` in the
repository root for acceptance scope and the retained qualification backlog.

## Qualified Facade Scope

`tools/test_context_facade.ps1` compiles the actual existing engine and bridge.
The maintained gate covers mixed C/C++ consumers and host-mock lifecycle
execution, plus real-backend synthetic ELF links for CM0, CM0+ with/without
VTOR, hard-FP CM4 and hard-FP CM7. Link checks use O2/Os with ordinary/native
LTO, direct objects and archives. Facade-body attribute probes additionally
use O0/Og/O2/Os/O3 and raw hostile compiler flags, with causal controls.

These checks do not execute target context switching or certify transitive raw
closure through the deliberately ordinary legacy cold wrappers. They do not
replace pinned FreeRTOS parity, final all-optimization qualification, a combined
matrix result or board evidence. The fixture README specifies exact admission
and diagnostic controls.
