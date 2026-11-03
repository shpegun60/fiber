# Context V1 Runtime

This directory owns the portable execution-context engine. The versioned API
does not know a Fiber lifecycle object or a scheduler-policy implementation.
Qualification of the owning implementation is distinct from the earlier
additive facade qualification recorded below.

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

The entry `arg` and dispatcher `user` are retained pointers; their pointees are
not copied. Keep them valid at fixed addresses for their entire use. The default
start policy rewinds MSP, so startup-local objects must not back retained state
even though `ctxrt_v1_start()` never returns.

## Build

Compile exactly these mandatory portable providers and one concrete backend:

```text
context/context_core.c
context/context_runtime_state.c
context/context_panic.c
```

The optional `context/context_configuration.c` supplies the configuration-open
service used by context-mutating extensions and the Fiber lifecycle consumer.
The five Context operations alone do not require this optional provider.

To use the separate Fiber v1 consumer, additionally compile
`fiber/lifecycle/fiber_v1.c` and the configuration provider. Its public storage,
five operations, callback contract and static setup example are documented in
`fiber/lifecycle/README.md`. Do not install a second dispatcher through the
Context or legacy registration API while that consumer owns dispatch.

Add `fiber/fiber_core.c` only for legacy five-call consumers. It is a one-way
compatibility shim into Context, not a second engine. Do not compile the removed
old state/panic/configuration providers or the former additive bridge. The proof
source inventory in `tools/runtime_sources.json` records these roles explicitly;
it is not a runtime selector or a substitute for a correct application build.

Use the selected backend's required settings, include path, source group,
linker contract and expectation object. The Context refactor does not remove
its existing frame/storage/cohort, vector, MPU or optional integration contracts.
For automatic M4/M7 selection, include the board's CMSIS/device header before
`context/context.h` so `__CORTEX_M` identifies the concrete backend. Explicit
build-selected integrations instead supply the matching public type header and
selection definitions through the build; no runtime CPU probing is introduced.

`CtxrtContextV1` names the existing CPU-storage tag, not a second struct. Legacy
`FiberContext` pointers and callbacks are type-compatible without casts. The
selected backend still owns layout, optional features and cohort identity.
There are deliberately no generic optional-feature stubs.

Context owns exactly one current slot, dispatcher/user pair, first-selection
latch, configuration latch, publication path and fallback panic definition.
The eight forward operations and reverse-v1 symbol names are unchanged. The
assembly-visible current-slot symbol remains C-private; backend assembly may
load it, never publish a new value. Legacy declarations forward to canonical
Context declarations and preserve the same underlying storage identity.

The compiler-policy header and selected public storage selector retain their
old physical paths temporarily. These are explicit physical migration debts,
not dependencies on Fiber lifecycle logic. The three TF-M integration adapters
use the canonical Context current-identity API and do not require the legacy
shim. Their maintained pure-Context links exclude both the shim and optional
configuration provider; compiled legacy-dependency controls fail explicitly.
This proves the optional adapter boundary, not actual Secure TF-M execution.

See `CONTEXT_REFACTOR_BASELINE.md` and `CONTEXT_FIBER_ARCHITECTURE.md` in the
repository root for acceptance scope and the retained qualification backlog.

## Owning Implementation Qualification

The maintained `tools/test_context_facade.ps1` now checks the actual Context
providers in separate pure-Context and mixed-legacy cohorts. Pure links omit
the legacy shim and optional configuration provider; injected dependencies on
either are negative controls. Normal and native-LTO ELF checks prove one
current slot, the existing reverse anchor, selected storage identity and strong
handler/vector ownership. Host execution uses the real Context implementation
with a labelled mock CPU port, not simulated exception transfer.

`PORT_ARCHITECTURE_AUDIT.md` records the post-inversion receipts separately from
the historical additive-facade results below. The targeted classic backend
objects and moved state/panic/configuration objects also have independent
native-object comparisons. None of these results is a whole-image identity,
global all-optimization FreeRTOS equivalence or board-runtime claim.

## Historical Facade Scope

The earlier additive implementation was qualified through
`tools/test_context_facade.ps1`. The gate covers mixed C/C++ consumers and
host-mock lifecycle execution, plus real-backend synthetic ELF links for CM0, CM0+ with/without
VTOR, hard-FP CM4 and hard-FP CM7. Link checks use O2/Os with ordinary/native
LTO, direct objects and archives. Facade-body attribute probes additionally
use O0/Og/O2/Os/O3 and raw hostile compiler flags, with causal controls.

Those receipts do not qualify the subsequent ownership inversion. These checks
do not execute target context switching or certify transitive raw closure
through ordinary cold registration helpers. Sensitive attributes protect the
canonical init/setter bodies; they do not themselves establish transitive
protection of all cold callees. The checks do not
replace pinned FreeRTOS parity, final all-optimization qualification, a combined
matrix result or board evidence. The fixture README specifies exact admission
and diagnostic controls.
