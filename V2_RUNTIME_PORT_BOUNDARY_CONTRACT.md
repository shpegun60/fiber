# V2 CPU-Neutral Runtime Port Boundary Contract

## Status

This document defines the normative target for the final common-runtime to
selected-port boundary. The architecture was frozen before implementation; the
status below distinguishes staged adapters from the active runtime path.

The current tree is transitional:

- `fiber_port_runtime_abi.h` still exposes more than the final eight functions;
- every current port defines the five new final runtime adapters, but common
  runtime deliberately does not call them before the choreography checkpoint;
- cross-file save/restore, MSP, scheduler-bridge, exception, and handler
  declarations now live in each port's `fiber_port_private.h`, outside
  `fiber_portmacro.h` and boot-record headers;
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

## Stable Portable Common API

The portable common API exported by `fiber_core.h` remains exactly:

```c
void fiber_init(FiberContext *ctx,
                void *stack_begin,
                void *stack_end,
                entry_t entry,
                void *arg);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_current(void);

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                   void *user);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_start(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
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

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_panic_wait(void);

void fiber_port_require_scheduler_configuration_environment(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_prepare_start(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_runtime_select_first(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_start_first(FiberContext *first);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
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

The attributes above are part of the ABI, not optional decoration. The public
`fiber_current()`, `fiber_start()`, and `fiber_schedule()` entry points use the
same sensitive, general-registers-only contract. `fiber_current()` needs it so
an unprivileged MPU profile does not acquire hidden privileged instrumentation.
So do every common reverse helper and private
port helper reachable after start reconciliation, from SVC/PendSV, or between a
schedule-request precondition check and the architectural request. Those paths
must not acquire function instrumentation, profiling callbacks, sanitizers,
stack-protector calls, implicit FP/MVE use, or LTO-generated helper calls.
The public sensitive bundle includes `noipa`/no-clone/no-ICF protection, or the
toolchain's verified equivalent, whenever available; `noinline` alone is not an
LTO boundary.

The initial production freeze is limited to GNU Arm Embedded GCC. Every later
compiler port requires independent attribute mappings, generated-code audits,
LTO/section-GC proofs, and hardware evidence; evidence from one GCC version or
compiler family is not inherited automatically by another toolchain.

`FIBER_SCHEDULER_HOOK_ATTR` includes both `FIBER_API_ATTR_SENSITIVE` and
`FIBER_GENERAL_REGS_ONLY`. Because an indirect function-pointer type does not
propagate target attributes, the application must compile the complete hook
call graph under the same restrictions. Port/application integration hooks
that can run from these paths expose and use an equivalent selected-port
sensitive hook attribute. A plain `FIBER_GENERAL_REGS_ONLY` declaration is not
sufficient evidence.

`fiber_api_attributes.h` is the single definition point for the public
`FIBER_SCHEDULER_HOOK_ATTR` and common ABI attribute bundles. A selected
`fiber_compiler.h` may provide port-private mappings, but must not independently
redefine the public macro. This prevents include order from silently changing
the scheduler callback ABI.

## Optional Selected-Port Extension ABIs

The eight functions above are the complete mandatory common-to-port ABI. They
are sufficient for every privileged, static-lifetime cooperative CPU port and
remain unconditional for every selected port.

MPU, unprivileged execution, FreeRTOS-style SecureContext management, and TF-M
integration may require configuration or gateway operations that have no
meaning for a classic privileged port. Those operations use separate optional
selected-port extension ABIs. They are not a ninth mandatory runtime function,
are never declared by `fiber_port_runtime_abi.h`, and are never called by
common runtime code.

The portable application surface remains the five functions in
`fiber_core.h`. Optional extension ABIs are integration-facing by default; they
are not an additional portable application tier. A production selected profile
must provide a safe complete profile policy that can initialize and run fibers
when the application includes only `fiber_core.h` and calls only those five
functions. That policy may be completed by build-owned board, linker, Secure
image, or TF-M integration, but it must not require a feature-specific call from
portable application source and must not silently weaken the selected profile's
declared isolation. The same portable application source must compile and link
unchanged for privileged, MPU, SecureContext, NTZ, and TF-M profiles.

The API has three intentionally separate portability tiers:

1. Portable application code includes only `fiber_core.h`, contains no
   feature-specific `#if`, type, macro, or extension call, and is portable
   between all production profiles whose platform services it otherwise uses.
2. Profile integration code may include a selected-port extension header to
   replace the profile default policy or configure profile-specific resources.
   This code is deliberately non-portable and belongs beside the build manifest,
   linker policy, Secure image, or board integration rather than in upper
   application logic.
3. Cross-image companion code implements a versioned Secure gateway or TF-M
   veneer contract and is never visible through `fiber_core.h`.

Header exposure enforces the tiers. `fiber_core.h` may transitively include the
selected `fiber_port_types.h` only to complete opaque `FiberContext` storage;
that type header exports no feature operation, service declaration, or policy
macro. Concrete port directories and extension headers are private include
paths for port/profile integration targets and are not exported by the portable
application target. Accessing one requires an explicit integration dependency,
so an accidental optional-ABI dependency cannot arrive through normal public
includes.

Examples of integration artifacts are:

```text
ARM_CM3_MPU/
  fiber_port_mpu_abi.h
  fiber_port_mpu.c

ARM_CM33_NTZ/
  fiber_port_mpu_abi.h
  fiber_port_mpu.c
  fiber_port_tfm_abi.h        # only when explicit integration-facing TF-M setup exists
  fiber_port_tfm.c

ARM_CM33/
  fiber_port_mpu_abi.h
  fiber_port_mpu.c
  fiber_port_secure_context_abi.h
  fiber_port_secure_context.c
  secure/
    fiber_secure_gateway_abi.h
    fiber_secure_gateway.c
```

Names may be specialized by a concrete port, but the ownership rules are
normative:

- `fiber_core.h` does not include optional extension headers;
- common runtime objects reference no optional extension symbol;
- portable application translation units include no optional extension header
  and reference no optional extension symbol;
- every production profile supplies a safe default policy and remains runnable
  without an application reference to an optional extension;
- hardware capability alone does not enable an extension: the selected port
  profile must implement and advertise that exact extension;
- the build includes an extension source only for a selected port/profile that
  implements it;
- a port that does not implement an extension provides neither a silent no-op
  stub, an empty compatibility header, a placeholder symbol, nor a false
  capability declaration;
- including or linking an unsupported extension fails at compile or link time;
- profile integration opts into a non-default implemented extension policy by
  explicitly including its selected-port extension header and linking its
  matching source or companion artifact; code that does so is intentionally
  outside the portable application tier;
- an extension that changes context layout, privilege, CONTROL, PSPLIM, MPU
  regions, SecureContext state, PAC keys, or frame construction updates the
  selected context feature/layout identity and rebuilds its immutable seal;
- pre-start context configuration uses the common-owned lifecycle guard and is
  rejected after the context becomes running or immutable;
- any extension callable from an unprivileged fiber enters privileged port code
  only through a validated port-owned SVC service;
- mandatory start, unprivileged yield, unprivileged task-return, and optional
  extension service numbers share one selected-port SVC dispatch namespace and
  are checked for uniqueness at compile time. Unsupported services have no
  dispatch entry, and an unknown immediate fails closed.

The base CPU port still owns all mechanics required to run the profile. For
example, an MPU profile always saves/restores its MPU and privilege state, and
an MVE profile always saves/restores its architectural extended context. The
optional integration header exposes only configuration or lifecycle operations
that profile integration may deliberately request. It is not required by the
portable application and is not a mechanism for common runtime code to discover
hardware at runtime.

Abstraction cannot infer heterogeneous policy. If every fiber in a profile uses
the same MPU, privilege, or SecureContext policy, the selected profile applies
that policy automatically. If fibers require different policies, profile
integration must provide that mapping through a selected-port extension before
the contexts become scheduler-visible. Such heterogeneous policy is an explicit
non-portable integration concern; it cannot leak feature-specific calls into the
portable upper layer and cannot be guessed safely by common runtime code.

The portability guarantee covers fiber execution mechanics, not arbitrary
platform services. A fiber that directly calls PSA, TF-M, a Secure gateway, or
an MPU-profile-only service has an intentional dependency on that service even
though its scheduling code remains portable. Applications that need the same
business operation on profiles with different service providers define their
own service-level interface above fiber and select a PSA, TF-M, Secure companion,
software, or unsupported backend in platform integration. Selected-port feature
ABIs configure execution policy; they do not become a general secure-service API.

A concrete port with no MPU, Security Extension, SecureContext, or TF-M role
does not implement the corresponding extension functions. No conditional call
to those functions exists in common code. A distinct capable profile, such as
an MPU or Non-secure profile for the same CPU family, owns its different
`FiberContext` layout and provides the additional API files itself.

The resulting build model is explicit:

| Selected profile | Mandatory runtime ABI | Reverse ABI v1 | Optional integration artifact |
| --- | --- | --- | --- |
| CM0/CM3/CM4/CM7 privileged | required | required | none |
| CM0/CM3/CM4/M7 MPU profile | required | required | MPU mechanics are profile-mandatory; optional non-default policy API |
| ARM_CM23/33/35P/52/55/85 Secure-only runtime | required | required | profile-mandatory MPU/security mechanics; optional policy API; no cross-image companion |
| ARM_CM23/33/35P/52/55/85 Non-secure with fiber SecureContext | required | required | matched Secure companion is profile-mandatory; optional MPU/SecureContext policy API |
| ARM_CM23/33/35P/52/55/85 Non-secure without SecureContext | required | required | profile-mandatory MPU mechanics when selected; optional policy API; no Secure companion |
| ARM_CM23/33/35P/52/55/85 NTZ Non-secure | required | required | profile-mandatory MPU/NTZ mechanics; optional policy API; no fiber Secure companion |
| ARM_CM33/52/55/85 NTZ source group with TF-M | required | required | TF-M integration and veneers are profile-mandatory; optional policy API; no fiber Secure companion |

This table describes profile ownership, not an automatic hardware probe. A
future port adds another row/profile rather than making common runtime branch on
CPU capabilities.

The local FreeRTOS build deliberately reuses each applicable `_NTZ` CPU source
group for two exact profiles: a non-TrustZone Non-secure build and, for CM33,
CM52, CM55, and CM85, a TrustZone-enabled TF-M build with an additional TF-M
wrapper. Reusing source files does not make those profiles ABI-equivalent. Their
build manifests, configuration values, integration artifacts, and context
feature identities remain distinct.

When an optional selected-port API mutates a context, it needs one
common-owned lifecycle decision without gaining access to common scheduler
globals. That dependency uses a separate optional reverse-extension module:

```text
profile integration
  includes selected-port fiber_port_<feature>_abi.h

selected-port fiber_port_<feature>.c
  includes internal fiber_runtime_context_configuration_abi.h

optional common fiber_runtime_context_configuration.c
  implements the lifecycle guard
```

The first optional reverse-extension ABI is frozen as:

```c
#define FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_VERSION 1u

extern const unsigned char
fiber_internal_runtime_context_configuration_abi_v1_anchor;

FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_context_configuration_open(
        const FiberContext *ctx);
```

This helper rejects NULL, a running/started runtime, and selection-time
reconfiguration. It does not validate or mutate selected-port context fields.
After it returns, the feature implementation validates its private layout,
applies the change, rebuilds affected synthetic state, and reseals the context.
The application contract still forbids mutation after publishing the context
to its own scheduler data structure because common code cannot observe that
publication.

The optional common source and selected-port feature source are linked only
when that feature module is enabled. A port without such an API does not include
the optional reverse header, does not retain its anchor, and does not build
either source. This optional ABI therefore does not add a symbol to the base
reverse v1 allowlist or a function to `fiber_core.h`.

The three extension classes have different boundaries:

1. An MPU/unprivileged extension is a profile-integration-to-selected-port ABI
   in the same runtime image. It may replace the safe profile default for
   regions, privilege, system-call stack, and the initial CONTROL/frame policy.
2. A FreeRTOS-style TrustZone SecureContext extension has a Non-secure selected
   port side and a separately built Secure companion. Their cross-image gateway
   ABI is versioned independently from the eight-function runtime ABI and needs
   a build-manifest or startup compatibility proof.
3. A TF-M profile normally uses the matching NTZ-style Non-secure CPU port plus
   TF-M veneers and initialization. It must not also compile the fiber-owned
   SecureContext companion. If user-visible TF-M setup is required, it lives in
   its own selected-port integration header; otherwise it remains private to
   `fiber_port_runtime_prepare_start()`.

Static-lifetime fibers do not require a mandatory destroy operation. A
fiber-owned SecureContext profile allocates or binds its Secure stack/context
once during privileged pre-start configuration and stores only the resulting
handle in selected-port-private context state. The Secure companion may use a
fixed pool, application-provided Secure storage, or another explicitly selected
allocator; the mandatory fiber runtime neither requires nor exports a heap.
A future dynamic SecureContext free operation or context-deletion feature must
define its own optional lifecycle ABI and cannot be smuggled into a CPU port or
the frozen five-function common lifecycle.

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

The reverse boundary is internal, CPU-neutral, and mandatory for every selected
CPU port. It is not an optional MPU or security extension. Its
`common-core-freeze-v1` spelling is declared by one common-owned header:

```text
fiber/fiber_runtime_port_abi.h
```

The v1 boundary contains exactly this symbol set. The header declares the
anchor and callable functions. The current-context slot is intentionally listed
as an assembly-visible symbol without a C object declaration:

```c
#define FIBER_RUNTIME_PORT_ABI_VERSION 1u

extern const unsigned char
fiber_internal_runtime_port_abi_v1_anchor;

/* Assembly-visible only; deliberately no C lvalue declaration here:
 * fiber_internal_runtime_current_context_slot
 */

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_runtime_select_scheduler_candidate(
        FiberContext *current);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_publish_current_context(FiberContext *next);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_current_context(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_task_return(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code);
```

The canonical `fiber_panic()` declaration may remain physically owned by
`fiber_panic.h`, but `fiber_runtime_port_abi.h` must make that declaration
available. A selected port includes this one reverse header instead of
redeclaring common callable symbols locally. The current-slot C declaration is
kept in a common-private state header that selected ports cannot include.

An application strong override of `fiber_panic()` must include the canonical
declaration and preserve its exact noreturn, sensitive, and
general-registers-only contract through the complete override call graph. A
matching symbol name alone is not sufficient. The generated-code matrix must
exercise an application override and reject hidden instrumentation, sanitizer,
stack-protector, profiler, FP, MVE, or returning behavior on that path.

The exact semantics are:

- `fiber_internal_runtime_port_abi_v1_anchor` is the link-time version guard for
  the complete mandatory bidirectional runtime contract: the eight
  common-to-port functions, the reverse v1 symbols, their calling conventions,
  required attributes, and normative semantics. Its declaration lives on the
  reverse boundary because the common runtime defines it and every selected
  port must reference it; its version scope is not reverse-only. An object that
  implements at least one mandatory common-to-port ABI function and is therefore
  referenced by common runtime must retain a relocation to this exact symbol.
  The relocation must not depend on handler archive extraction. Any incompatible
  signature, semantic, calling-convention, or required-attribute change in
  either direction creates a new anchor spelling and removes the old spelling
  from that ABI generation. Old-common/new-port and new-common/old-port links
  must both fail, including under section garbage collection or LTO.
- `fiber_internal_runtime_current_context_slot` is common-owned storage exposed
  to selected ports only by its frozen assembly symbol name. Selected inline
  assembly or `.S` code may load the slot to obtain the context being saved or
  restored. Selected-port C has no declaration, may not redeclare it, take its
  address, or write it. Only common-private C may access it as an lvalue, and
  only the common-owned publication helper may write it.
- `fiber_internal_runtime_select_scheduler_candidate(current)` is the only
  selected-port entry into scheduler policy. `current == NULL` means first
  selection. Common code owns configured-hook checks, the first-selection
  lifecycle guard, hot-swap rejection, hook/user loading, policy invocation,
  and NULL-result panic semantics. The port owns the CPU critical envelope and
  validates the returned context before publication.
- `fiber_internal_runtime_publish_current_context(next)` rejects NULL and
  publishes only a port-validated candidate with the required ordering. It is
  used by common first-start choreography and by the selected PendSV path.
- `fiber_internal_runtime_require_current_context()` implements the common
  lifecycle precondition used by the port's Thread-mode schedule request. It
  does not inspect CPU masks or registers.
- `fiber_internal_task_return()` is the common no-return sink for an entry
  function that returns and reports panic code `'R'`. A privileged profile may
  seed it directly into the synthetic frame. An unprivileged profile must seed
  a port-owned unprivileged return veneer instead; that veneer issues the
  selected return SVC, and the validated privileged SVC dispatch calls this
  common sink. Unprivileged Thread mode never branches directly into privileged
  common text. This is private port mechanics and does not add a ninth
  common-to-port operation.
- `fiber_panic()` is the no-return diagnostic escape used by port C and naked
  assembly. Port callers hold a strong reference. The common fallback definition
  is weak so an application may replace it with one strong definition, but a
  missing effective implementation remains a link failure. Its calling
  convention and no-return/general-registers-only contract are part of this
  reverse ABI.

No other common scheduler symbol is visible to a selected port. In particular,
the hook pointer, user pointer, first-selection flag, and direct storage/update
helpers remain private to common runtime translation units. A selected port
must not call the five-function public API from SVC/PendSV as a substitute for
this internal bridge.

Port-owned application integration hooks are a different boundary and are not
added to the reverse ABI. The current examples are:

```c
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end);
int fiber_addr_plausible_code(uintptr_t address);
uintptr_t fiber_fallback_initial_msp(void);
```

Future selected profiles may add similarly port-owned integration hooks, such
as a PAC-key generator, Secure-storage provider, or platform vector-remap
validator. Those hooks are not common reverse ABI. Their exact declarations,
trust level, sensitive-function attributes, override rules, and state-preservation
proofs live in the concrete port manifest and parity ledger.

Their weak defaults, override policy, CPU-state preservation checks, and linker
map semantics belong to the selected port/integration contract. Secure gateway
symbols similarly belong to a separately versioned cross-image ABI. Neither
category may be admitted by the reverse common-symbol allowlist accidentally.

The compile/link matrix must prove all of the following for every selected
port:

1. The mandatory selected-port runtime source group's undefined common-symbol
   set is exactly the base v1 reverse allowlist, plus explicitly classified
   toolchain/runtime dependencies. No scheduler global or common private helper
   appears.
2. The port defines none of the common-owned reverse symbols.
3. The common runtime defines one strong anchor, one current-context slot, and
   one strong definition of each non-overridable reverse function. It also
   provides exactly one effective weak-or-application-strong `fiber_panic()`.
4. A guaranteed always-linked mandatory ABI object, independently of the
   handler object, retains the relocation to
   `fiber_internal_runtime_port_abi_v1_anchor`. Both mismatch directions are
   negative-link tests: a v1 port with a v2-only common fixture, and a v2-only
   port fixture with a v1 common runtime. Both must fail before handler
   extraction is considered.
5. The reverse header does not make the current slot a C lvalue. A negative
   selected-port C fixture that attempts to read, assign, or take its address
   without a forbidden redeclaration must fail to compile. A source audit
   rejects every selected-port C declaration or address escape of the symbol.
   Generated assembly audits permit only the exact slot-address/load sequence
   and reject every store through that address. Only the common runtime object
   may emit stores to the slot.
6. The same checks pass with section garbage collection and LTO enabled.
7. Optional port-extension objects, application integration hooks, and Secure
   gateway objects are checked against their own explicit allowlists and never
   make the base reverse ABI appear larger.
8. A negative fixture that includes or links an unsupported optional extension
   fails; a supported extension fixture links only when its matching selected
   port source/companion, optional common lifecycle object, and ABI identities
   are present.
9. Adversarial builds with function instrumentation, stack protection,
   profiling, sanitizers, and LTO prove that the sensitive current/start/schedule,
   scheduler-hook, reverse-helper, SVC, and PendSV call graph contains no hidden
   instrumentation/runtime calls and no FP/MVE instructions.
10. One guaranteed always-linked mandatory port identity object defines the
    exact selected-profile/context ABI anchor. Every other independently
    compiled object in the mandatory selected-port source group and the
    application/build expectation object retain relocations to it. Negative
    links reject stale object mixtures even when their generic callable symbols
    and the common runtime ABI version still match.

The reverse ABI is deliberately smaller than the current transitional
`fiber_runtime_state.h` surface. Mechanical migration collapses begin/end first
selection, hook invocation, and NULL handling into
`fiber_internal_runtime_select_scheduler_candidate()`, renames the current
slot, and removes every displaced declaration after all ports use the v1
header.

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
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_start(void)
{
    FIBER_REQUIRE(fiber_internal_scheduler_is_configured() != 0u, 'K');
    FIBER_REQUIRE(fiber_current() == NULL, 'k');

    fiber_port_runtime_prepare_start();

    FiberContext *const first = fiber_port_runtime_select_first();
    fiber_internal_runtime_publish_current_context(first);

    fiber_port_runtime_start_first(first);
    FIBER_API_UNREACHABLE();
}
```

This pseudocode freezes ownership and order. Private common checks may be
refactored, but the shown v1 publication symbol is fixed.

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
archive. A direct reference to `SVC_Handler` or `PendSV_Handler` is also not a
sufficient extraction guard when an already-linked startup object provides a
weak definition with the same name.

The selected port must use one of these two layouts:

1. Define both strong handlers in an object that also implements at least one
   mandatory common-to-port ABI function referenced by common runtime.
2. Define both strong handlers and one unique strong
   `fiber_port_handler_bundle_v1_anchor` in a separate handler object. A
   guaranteed always-linked mandatory ABI object retains a strong relocation to
   that unique anchor, forcing archive extraction independently of startup weak
   aliases.

The handler-bundle anchor is port-owned and is not part of either directional
runtime ABI. Exactly one selected handler object may define it. The common ABI
version anchor and the handler extraction anchor are independent proofs and may
not be combined into one relocation.

The `v1` suffix also identifies the selected port's internal mandatory-object
to handler-object bundle contract. If their private calling convention, helper
symbols, frame assumptions, or handler semantics become incompatible, the
mandatory object must reference a new bundle-anchor spelling and the new handler
object must define it. This is port-internal versioning, not common ABI
versioning. A separately compiled handler object that calls any reverse/common
ABI symbol must additionally retain its own relocation to the matching
`fiber_internal_runtime_port_abi_vN_anchor`; extraction through the bundle anchor
does not prove common ABI compatibility.

The build proof must cover:

- a static archive;
- `--gc-sections`;
- LTO where supported;
- startup weak aliases;
- no application handler wrappers.
- stale mandatory-object/new-handler and new-mandatory-object/stale-handler
  negative-link fixtures;
- a handler-object/common-runtime ABI mismatch negative-link fixture whenever
  the handler object calls the reverse ABI.

The selected strong handlers must remain in the final ELF and must satisfy the
active vector-table relocations. A negative archive fixture with startup weak
aliases must prove that removing the handler-bundle relocation prevents the
expected handler extraction, while the production fixture must resolve slots 11
and 14 to the selected strong handlers.

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
- one retained relocation from an always-linked mandatory port object to the
  matching bidirectional runtime ABI anchor, with both version-mismatch
  directions failing to link;
- one exact selected-profile/context ABI definition in an always-linked
  mandatory port identity object, with matching relocations from every other
  independently compiled mandatory port object and from the build-owned
  expectation object;
- stale selected-port object mixtures fail to link even when the common runtime
  ABI generation is unchanged;
- one strong `SVC_Handler` definition;
- one strong `PendSV_Handler` definition;
- no application wrappers are required;
- a deliberate competing strong handler fails to link;
- handler archive members are extracted;
- a separate handler object, when used, is extracted through
  `fiber_port_handler_bundle_v1_anchor`, not through reliance on generic handler
  names;
- a separately compiled handler object is version-matched both to its mandatory
  selected-port object through the bundle anchor and to common runtime through
  its own runtime ABI relocation when it calls reverse symbols;
- synthetic vector slots 11 and 14 resolve to the expected selected-port
  handler symbols;
- `--gc-sections` does not discard required handlers;
- LTO does not discard or merge away required handler ownership;
- generated code for every sensitive start/SVC/PendSV-reachable function is
  free of instrumentation, sanitizer, stack-protector, profiler, FP, and MVE
  calls/instructions;
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
   adding private selected-port headers for the displaced declarations. Make
   `fiber_api_attributes.h` the only public scheduler-hook attribute definition
   and apply the frozen sensitive/general-registers-only attributes to the
   public and mandatory ABI declarations in the same slice.
2. Add common-owned `fiber_runtime_port_abi.h`, implement its exact v1 symbols
   and link anchor, then rename common-owned scheduler globals and update exact
   assembly references without changing publication order. Keep the current
   slot out of the selected-port C declaration surface. Make the port-side
   `fiber_panic()` declaration strong while retaining only the common fallback
   definition as weak.
3. Delete the wider `fiber_runtime_state.h` port surface and add reverse-symbol,
   slot-load-only, integration-hook, section-GC, and LTO allowlist proofs.
4. Collapse start preparation, first selection, first start, and schedule
   request choreography behind the new generic functions.
5. Add strong selected-port `SVC_Handler` and `PendSV_Handler` definitions while
   preserving the existing validated assembly bodies. Co-locate them with a
   mandatory ABI definition or add the unique handler-bundle extraction anchor.
6. Remove CubeMX/application wrappers and delete wrapper/direct configuration
   switches.
7. Add common compile-isolation and synthetic link/ELF proofs, including the
   static-archive extraction and duplicate-handler negative tests.
8. Run the full H7 normal, FPU, startup, trap, active-VTOR, SVC, and PendSV
   hardware validation suite.

Strong handler ownership is intentionally after ABI narrowing and private
header creation. This keeps symbol ownership, lifecycle choreography, and
exception wiring from changing in one undiagnosable step.

## Freeze Conditions

The common runtime boundary is frozen only when:

- the portable common API in `fiber_core.h` still contains exactly five
  functions;
- the common-to-port ABI contains exactly the eight functions in this document;
- common runtime objects pass the CMSIS-free symbol allowlist;
- common code transports no CPU register value or frame geometry;
- common scheduler state has CPU-neutral names and remains common-owned;
- `fiber_runtime_port_abi.h` exposes exactly the v1 reverse symbols listed in
  this document, and no selected port includes the transitional runtime-state
  header;
- every selected port retains the v1 link-anchor relocation and passes exact
  bidirectional-version, reverse-symbol, application-hook, section-GC, and LTO
  allowlist proofs;
- one exact selected-profile/context cohort anchor is defined by the mandatory
  identity object and retained by every other mandatory port object plus the
  build-owned expectation object; stale mixtures fail to link;
- every sensitive current, start, schedule, scheduler-hook, SVC, and PendSV call path
  passes the no-instrumentation, no-stack-protector, no-sanitizer, no-profiler,
  no-FP, and no-MVE generated-code proof;
- an application `fiber_panic()` override passes the same canonical declaration
  and generated-code proof;
- selected ports have no C declaration or address escape for the common current
  slot, and generated assembly passes the load-only/no-store proof;
- every selected port provides strong exclusive SVC and PendSV handlers;
- separately archived handlers are forced into the link through the unique
  handler-bundle anchor rather than startup handler names, and pass stale
  mandatory/handler bundle mismatch tests;
- separately compiled handler objects that call reverse symbols retain the
  matching runtime ABI relocation themselves;
- wrapper/direct macros and application wrappers are gone;
- optional MPU, SecureContext, and TF-M extension ABIs remain outside
  `fiber_core.h` and the mandatory eight-function runtime ABI;
- the feature-blind `tools/fixtures/portable_application.c` fixture includes
  only `fiber_core.h`, compiles and links unchanged against every production
  profile, references no extension symbol, and needs no feature-specific
  pre-start call;
- the portable fixture's dependency output contains no optional extension
  header, and the exported portable include target exposes no concrete-port
  integration directory;
- each production profile is closed under its safe default policy: selecting it
  pulls in all mandatory mechanics and companion artifacts required to reach
  `fiber_start()` without an optional application call;
- profile-integration fixtures separately prove each supported non-default MPU,
  SecureContext, or TF-M policy and are labelled non-portable;
- unsupported ports do not provide silent extension stubs;
- context-mutating extensions use the versioned optional context-configuration
  lifecycle ABI, while profiles without them build neither optional source;
- every exact v8-M security role and every layout/privilege-affecting feature
  combination has its own build manifest and profile/context identity;
- unprivileged profiles have collision-free start/yield/return/extension SVC
  dispatch, a return-SVC veneer, and MPU/linker proof that writable stacks cannot
  modify context or common runtime state;
- Secure companions and TF-M artifacts pass their separately versioned
  cross-image gateway/build-manifest compatibility proof;
- synthetic archive/link/vector/LTO proofs pass for every compiled port;
- H7 board validation passes after the final handler migration;
- existing panic ordering is preserved except for the documented
  `fiber_start()` precedence change;
- port parity ledgers record the final exception ownership model.

Only after these conditions pass may this checkpoint be used as the stable
base for porting the remaining FreeRTOS STM32 Cortex-M profiles.
