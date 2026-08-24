# Fiber v2 Port Contract

## Purpose

`v2` is the branch for turning `fiber` into a FreeRTOS-style cooperative
Cortex-M context-switch core.

The goal is to reuse the proven CPU-port discipline from FreeRTOS while keeping
the library small and explicit:

- manual cooperative yield only;
- no FreeRTOS scheduler policy;
- no queues, semaphores, timers, heap, or FreeRTOS API surface;
- no preemptive tick switching unless it is added later as a separate feature;
- context switch robustness at the same level as FreeRTOS ports where support is
  claimed.

This branch may change internal layout and port boundaries. `main` remains the
stable STM32H7/Cortex-M7 validated branch.

## Target Outcome

The long-term target is a stable, auditable, FreeRTOS-style cooperative
Cortex-M context-switch core for STM32 projects.

This means:

- use the same CPU-port discipline that makes FreeRTOS reliable on Cortex-M:
  explicit port selection, exact exception-frame ownership, PSP-based Thread
  mode execution, PendSV/SVC ownership, target-aware EXC_RETURN, FPU/MVE policy,
  PSPLIM/security-domain policy, and per-port validation evidence;
- keep the runtime cooperative: the user decides when to yield;
- keep the library much smaller than FreeRTOS by excluding FreeRTOS priority
  scheduler policy, queues, semaphores, timers, event groups, streams, and
  heaps;
- keep safety defaults at least as conservative as v1 unless a target-specific
  validation record justifies faster settings;
- add stronger paranoid checks where they improve failure mode quality without
  hiding timing bugs, for example Thread-mode guards, current-context
  validation, interrupt-mask guards, strict publication ordering, and explicit
  unsupported-target failures;
- treat FreeRTOS as the reference for CPU-port behavior, not as an API surface
  to clone.

The desired end state is not "it compiles for many cores". The desired end state
is: every claimed STM32 Cortex-M profile has a selected port, documented CPU
contract, known limitations, and validation level that matches the claim.

## Design Rules

1. Split by ARM core and architectural feature profile, not by STM32 marketing
   series.
2. Keep common runtime state and public API outside architecture-specific
   assembly.
3. Keep each port responsible for its own exception return, saved register
   layout, stack-limit policy, FPU/MVE policy, and security-domain policy.
4. Keep unsupported feature profiles explicit. A port that compiles is not
   automatically validated.
5. Keep safety mechanics mandatory. Genuine performance policy, such as lazy
   FP stacking, is opt-in per target after hardware validation.
6. Prefer readable, auditable C plus small, isolated assembly blocks.
7. Do not copy FreeRTOS source code silently. If code is copied or closely
   adapted, keep the required MIT license notice.
8. Select exactly one active port at compile time. Ambiguous, missing, or
   conflicting port selection must fail with a clear compile-time error.
9. Normalize every canonical `FIBER_PORT_*` architecture feature gate to `0`
   or `1` before use. Legacy feature aliases are compile errors.
10. Separate mechanical file moves from behavior changes. A refactor commit that
    only changes layout must keep the generated code path equivalent enough to
    pass the same compile matrix and the same H7 runtime validation checklist.
11. Never weaken `main` safety defaults as part of a portability refactor. Faster
    settings must stay target-local, documented, and validated before promotion.

## Selected Port Traits

The detailed selected-port trait contract lives in
`V2_PORT_TRAITS_CONTRACT.md`.

The layout-free common-core boundary lives in `V2_OPAQUE_CONTEXT_CONTRACT.md`.
It supersedes older statements in this document that require one shared,
common-known `FiberContext` or boot-record layout. The current selected ports
own their `FiberPortBoot` record and callable boot ABI; a fresh hardware run is
still required before this structural change renews any runtime claim.

The final CPU-neutral callable ABI, normative `fiber_start()` order, and
exclusive selected-port SVC/PendSV handler ownership live in
`V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md`. That document supersedes older
wrapper/direct-vector alternatives and wider callable ABI examples in this
contract.

The FreeRTOS reference policy lives in
`V2_FREERTOS_PORT_REFERENCE_POLICY.md`. FreeRTOS `portable/` is treated as the
CPU-port reference, not as the default compiled backend for `fiber`.
Every selected port must keep a FreeRTOS parity record: each relevant FreeRTOS
CPU-port macro, helper, function, assembly label, config gate, and errata policy
must be adopted, adapted, replaced, excluded with a reason, or deferred with a
tracked TODO. Nothing relevant may disappear silently during a port rewrite.
Every implementation slice that adds or changes first-start, save, restore,
masking, privilege, security, or exception-transfer instructions must also
compare the emitted Fiber disassembly with the pinned local FreeRTOS assembly.
The parity ledger records both matching instruction order and every intentional
divergence; the compile matrix checks the generated code. Source similarity or
a successful compile alone is not an acceptable parity proof.

`FREERTOS_ASM_PARITY.md` is the normative cross-port generated-code ledger.
`tools/freertos_asm_parity.ps1` compiles both the pinned FreeRTOS artifact and
the selected Fiber artifact with the same compiler, CPU/FPU ABI, and
optimization flags. Every pair is checked at both `-O2` and `-Os`. A
difference is accepted only through a documented
`FAP-*` rationale ID. `transitional_v8m` is excluded from production parity,
and an incomplete profile is checked only for the mechanisms it actually owns.

Selected ports are the source of CPU facts. Selected-port implementation and
compile-time validators consume those traits; layout-free common runtime code
uses the callable port ABI and must not infer CPU policy globally. The old
`fiber/target` directory has been removed; CPU capability policy must live
behind the selected-port contract.

## Non-Goals

`v2` is not a FreeRTOS clone.

The following are out of scope for the core port contract:

- FreeRTOS task API compatibility;
- priority scheduling;
- tick interrupt scheduling;
- queues;
- semaphores;
- event groups;
- stream buffers;
- software timers;
- heap implementations;
- MPU task isolation as a scheduler feature.

Some CPU features used by FreeRTOS ports, such as MPU, TrustZone, PSPLIM, MVE,
PAC, and BTI, may still affect context-switch correctness. Those features are
in scope only at the CPU context and exception-return layer.

## Proposed Layout

The target direction is governed by `V2_OPAQUE_CONTEXT_CONTRACT.md`:

The implemented structural boundary contains `fiber_api_types.h`, the single
`fiber_port_selected.h` facade, and one port-owned set of
`fiber_port_types.h`, `fiber_port_boot_types.h`, `fiber_port_boot.h`, and
`fiber_port_boot.c` files per current port. The selected `fiber_portmacro.h`
includes its local type contract. Common runtime translation units use only
the callable ABI and no longer inspect complete context or boot-record fields.

```text
fiber/
  fiber_api_types.h
  fiber_api_attributes.h
  fiber_api_decl.h
  fiber_core.c
  fiber_core.h
  fiber_platform_policy.h
  fiber_panic.c
  fiber_panic.h
  fiber_runtime_port_abi.h
  fiber_runtime_state.c
  fiber_runtime_state.h
  port/
    fiber_settings.h
    fiber_port_select.h
    fiber_port_selected.h
    fiber_port_runtime_abi.h
    fiber_port_geometry.h
    fiber_static_assert.h
    fiber_diagnostics.h
    fiber_compiler.h
    fiber_feature_policy.h
    fiber_port_traits.h
    # Selected ports expose fiber_port_vectors_* helpers directly.
    # Selected ports own fiber_port_exception.c directly.
    ARM_CM0/
      fiber_port_types.h
      fiber_port_boot_types.h
      fiber_port_boot.h
      fiber_portmacro.h
      fiber_port_private.h
      fiber_port.c
      fiber_port_boot.c
      fiber_port_exception.c
      fiber_portasm.h
      fiber_portasm.c
      optional integration-only fiber_port_mpu_abi.h and fiber_port_mpu.c
    ARM_CM3/
      fiber_port_types.h
      fiber_port_boot_types.h
      fiber_port_boot.h
      fiber_portmacro.h
      fiber_port_private.h
      fiber_port.c
      fiber_port_boot.c
      fiber_port_exception.c
      fiber_portasm.h
      fiber_portasm.c
    ARM_CM3_MPU/
      # Same role-file pattern plus any integration-only MPU policy ABI/source.
      fiber_port_types.h
      fiber_port_boot_types.h
      fiber_port_boot.h
      fiber_portmacro.h
      fiber_port_private.h
      fiber_port.c
      fiber_port_boot.c
      fiber_port_exception.c
      fiber_portasm.h
      fiber_portasm.c
      fiber_port_mpu_abi.h
      fiber_port_mpu.c
    ARM_CM4/
      fiber_port_types.h
      fiber_port_boot_types.h
      fiber_port_boot.h
      fiber_portmacro.h
      fiber_port_private.h
      fiber_port.c
      fiber_port_boot.c
      fiber_port_exception.c
      fiber_portasm.h
      fiber_portasm.c
    ARM_CM4F/
      # Final FreeRTOS-parity non-MPU profile; same selected role-file pattern.
    ARM_CM4_MPU/
      # Exact M4/M7 MPU profile plus the selected MPU extension ABI/source.
    ARM_CM23_NTZ/
      non_secure/
        # Slices 1-4 provide exact types/traits, first start, and PendSV source.
        fiber_port_types.h
        fiber_port_boot_types.h
        fiber_portmacro.h
        fiber_port_boot.h
        fiber_port_private.h
        fiber_port.c
        fiber_port_boot.c
        FREERTOS_PARITY.md
    ARM_CM33_NTZ/
      non_secure/
        # Exact no-FPU NTZ runtime.
        fiber_port_types.h
        fiber_port_boot_types.h
        fiber_portmacro.h
        fiber_port_boot.h
        fiber_port_private.h
        fiber_port.c
        fiber_port_boot.c
        FREERTOS_PARITY.md
    ARM_CM33F_NTZ/
      non_secure/
        # Exact build-selected FPU runtime with SVC and FP-aware PendSV.
        fiber_port_types.h
        fiber_port_boot_types.h
        fiber_portmacro.h
        fiber_port_boot.h
        fiber_port_private.h
        fiber_port.c
        fiber_port_boot.c
        FREERTOS_PARITY.md
    ARM_CM7/
      r0p1/
        fiber_port_types.h
        fiber_port_boot_types.h
        fiber_port_boot.h
        fiber_portmacro.h
        fiber_port_private.h
        fiber_port.c
        fiber_port_boot.c
        fiber_port_exception.c
        FREERTOS_PARITY.md
    transitional_v8m/
      fiber_port_types.h
      fiber_port_boot_types.h
      fiber_port_boot.h
      fiber_portmacro.h
      fiber_port_private.h
      fiber_port_transitional_v8m.h
      fiber_port_transitional_v8m.c
      fiber_port_boot.c
      fiber_port_exception.c
    ARM_CMxx/
      # One exact directory for each ARM_CM23, ARM_CM33, ARM_CM35P,
      # ARM_CM52, ARM_CM55, and ARM_CM85 reference profile.
      non_secure/
        fiber_port_types.h
        fiber_port_boot_types.h
        fiber_port_boot.h
        fiber_portmacrocommon.h
        fiber_portmacro.h
        fiber_port_private.h
        fiber_port.c
        fiber_port_boot.c
        fiber_port_exception.c
        fiber_portasm.h
        fiber_portasm.c
        optional integration-only selected feature ABI/source files
      secure/
        # Present only for the matching fiber-owned SecureContext companion.
        fiber_secure_context.h
        fiber_secure_context.c
        fiber_secure_context_port.c
        fiber_secure_init.h
        fiber_secure_init.c
        selected Secure-storage provider; no mandatory heap contract
    ARM_CMxx_NTZ/
      # One exact directory for each matching NTZ reference profile.
      non_secure/
        same selected runtime role-file pattern
        no fiber-owned secure companion
      profile-mandatory TF-M companion/veneers and optional integration policy API
```

`ARM_CMxx` above is notation for six concrete directories, not one generic
runtime directory. The final tree must not implement production v8-M profiles
through a single architecture-class folder. Shared implementations may be
factored or mechanically synchronized, but every concrete profile keeps its
own selected `fiber_portmacro.h`, exact build manifest, context identity,
feature policy, and `FREERTOS_PARITY.md` ledger. The current `ARM_CM4` and
`transitional_v8m` directories remain migration artifacts; they do not replace
the final `ARM_CM4F`/`ARM_CM4_MPU` and exact v8-M/v8.1-M profile groups.

An `_NTZ` source directory may be reused by more than one exact build profile,
as FreeRTOS does for non-TrustZone Non-secure and selected TF-M targets. Those
profiles still have different manifests, configuration values, companion
artifacts, and context feature identities. Source reuse is not profile
identity.

This mirrors the FreeRTOS split conceptually:

```text
FreeRTOS portmacro.h       -> fiber_portmacro.h
FreeRTOS portmacrocommon.h -> fiber_portmacrocommon.h or fiber/port root helpers
FreeRTOS port.c            -> fiber_port.c
FreeRTOS portasm.h/.c      -> fiber_portasm.h/.c
FreeRTOS secure_context.*  -> fiber_secure_context.*
FreeRTOS mpu_wrappers*     -> fiber_mpu_wrappers* only if MPU task isolation
                              becomes an explicit feature
fiber-only private declarations -> fiber_port_private.h; no public FreeRTOS
                                   contract counterpart
```

Every production port directory must provide its selected public context type,
its callable ABI implementation, private CPU-state validation, and its parity
ledger. The profile name belongs to the directory. Current concrete
source groups use the role names `fiber_port.c`, `fiber_port_boot.c`, and
`fiber_port_exception.c`. The selected `fiber_portmacro.h` is the only
port-wide CPU-contract facade; do not add a second selected-port header such as
`fiber_port.h`. `fiber_port_private.h` is not a facade or selected include: it
is included only by the concrete port's implementation files to share private
cross-file declarations. Behavior must not change during a pure file-layout
split.

The private header connects that profile's runtime, boot/frame, exception, and
optional assembly role files. It may declare profile-mandatory CPU helpers such
as save/restore validation, first-start preparation, MPU/CONTROL restoration,
or SecureContext dispatch when those mechanics belong to the selected profile.
It must not be used as an application-facing feature API. MPU, SecureContext,
and TF-M profiles are separate exact port identities with their own private
headers and context layouts; any non-default integration policy is exposed by a
separate `fiber_port_<feature>_abi.h`, never by widening common runtime or the
privileged profile beside it.

The first FreeRTOS-style source-group workflow is:

```text
fiber/port/ARM_CM7/r0p1
```

It is compared against the FreeRTOS `portable/GCC/ARM_CM7/r0p1` reference for
Cortex-M7 and forces the M7 r0p1 BASEPRI errata gate in build-selected matrix
runs. The fiber tree omits the extra `GCC/` directory level because v2 selected
ports are currently GCC/clang-asm only. Its
`fiber_portmacro.h` owns the selected-port CPU contract, and its `fiber_port.c`
owns the native first-start/PendSV implementation for this selected source
group. The selected `fiber_portmacro.h` should be CPU-contract-focused, like a
FreeRTOS `portmacro.h`: local constants, traits, and low-level inline assembly
helpers without including scheduler implementation details. It includes
`port/fiber_settings.h` only for genuine shared user policy and may include
`port/fiber_compiler.h` directly for compiler attributes, barriers,
diagnostics, and static-assert ABI. The selected `fiber_port.c` includes the
selected complete context type and the internal declarations it actually uses.
Common runtime translation units include only the incomplete public API type and
the callable port runtime ABI. Selected-port CPU snapshots are private local
implementation data. No selected file may inherit CPU facts from shared
settings; those facts are defined directly as canonical port traits. Its
`FREERTOS_PARITY.md` is the required audit record for
this port.

Selected ports should use a FreeRTOS-like naming split:

```text
fiber_portXXX
  selected-port CPU constants and low-level helper macros that correspond to
  FreeRTOS portXXX names.

FIBER_PORT_XXX
  selected-port CPU traits consumed by port code and compile-time validators.
  Layout-free common runtime code uses the callable port ABI instead.

FIBER_XXX
  user/build configuration.
```

Do not export raw FreeRTOS `portXXX` names. Use `fiber_portXXX` when the symbol
is intentionally shaped like a FreeRTOS portmacro item.

## FreeRTOS-Style Port Ownership Model

The target architecture is a FreeRTOS-style port boundary:

- `fiber_core.c` owns public cooperative runtime semantics only;
- `fiber_core.c` must not own CPU exception-handler assembly;
- `fiber_core.c` must not own architecture-specific synthetic frame layout;
- `fiber_core.c` must not contain a fallback PendSV implementation once the
  v2 split is complete;
- common code may own CPU-neutral immutable metadata helpers but does not own a
  complete boot-record or context layout;
- each selected port owns its complete context layout, port-private boot data,
  final integrity seal, and dynamic restore validation;
- first-context CPU startup, SVC startup, CONTROL writes, PSP/MSP programming,
  and exception-return mechanics are port-owned;
- exception setup such as PendSV/SVC priority, vector wiring validation,
  implemented-priority-bit probing, and M7 errata policy is port-owned;
- selected-port `fiber_port_exception.c` consumes CPU facts, validation
  defaults, CMSIS view, compiler helpers, and panic/require diagnostics through
  `fiber_portmacro.h`, not through target-wide headers;
- support helpers such as FPU, PSPLIM, VTOR, and fault hygiene may be shared,
  but the selected port owns the policy for when and how they are used.
- BASEPRI read/write helpers, scheduler threshold, asm snippets, and M7 r0p1
  errata policy are selected-port-owned.
- if a common helper would need architecture policy `#if` branches, prefer
  duplicating that logic inside the selected port.

In the final v2 shape each concrete port exports a public type-only context
header and implements the frozen callable port ABI. Public code gets the
selected complete context type through `fiber_core.h`. Common runtime
translation units compile with an incomplete `FiberContext` and cannot include
the selected complete type header or branch into architecture-specific
implementation logic. The `fiber_port_selected.h` type-only split, exact
eight-function `fiber_port_runtime_abi.h` boundary, and frozen reverse
`fiber_runtime_port_abi.h` v1 boundary are implemented. Every
displaced declaration lives in the concrete port's private `fiber_portmacro.h`,
`fiber_portasm.h`, boot header, or `fiber_port_private.h`. Selected ports no
longer include the common-private `fiber_runtime_state.h`; their only common
call surface is reverse ABI v1, while assembly may only load the frozen current
slot symbol. Strong handler ownership, wrapper/direct-vector removal, exact
reverse-symbol allowlists, current-slot load-only checks, and bidirectional
runtime-ABI mismatch links are active. The exact selected-profile/context
object-cohort anchor is also active: mandatory private objects retain one exact
identity, and the build-owned expectation source rejects a complete archive
from a different exact cohort when its dedicated section is kept by the linker.
The identity encodes `__NVIC_PRIO_BITS` and the complete effective scheduler
BASEPRI value bit-for-bit. Ports without BASEPRI encode a zero threshold and
must reject any nonzero public BASEPRI setting rather than silently ignoring it.
It is not a source-revision fingerprint. Refreshed hardware evidence remains
separate. No global selected internal-type facade is part of the frozen design.

Temporary transitional fallback code is allowed only while splitting ports. It
must live under an explicitly transitional directory such as
`port/transitional_v8m`, be clearly marked, be compile-covered, and be tracked
as debt. A port cannot be claimed as FreeRTOS-level while it depends on a
transitional PendSV or frame builder. Delete this directory when concrete v8-M
Baseline, v8-M Mainline, and ARMv8.1-M source groups replace its coverage.

The `fiber/port` helper-root convention is reserved for reusable helper code, not selected-port
fallback behavior.

## Port Selection Contract

Port selection must be deterministic and auditable.

Required rules:

- support automatic selection from compiler-provided architecture macros for
  small-library convenience;
- support explicit architecture-class selection through `FIBER_PORT_PROFILE`
  for compile tests, bring-up, and unambiguous classic profiles;
- support build-system selected production mode through
  `FIBER_PORT_BUILD_SELECTED=1`, where the build defines exactly one
  `FIBER_PORT_ARMV*` result macro and includes only the matching source group;
- verify explicit `FIBER_PORT_PROFILE` against compiler `__ARM_ARCH_*` macros
  when those macros are available;
- verify build-selected `FIBER_PORT_ARMV*` results against compiler
  `__ARM_ARCH_*` macros when those macros are available;
- allow selection mismatch only behind a named opt-in escape hatch for
  nonstandard toolchains;
- reserve `FIBER_FORCE_PORT_*` for unusual toolchains and compatibility, and do
  not allow it to be mixed with `FIBER_PORT_PROFILE`;
- do not allow `FIBER_PORT_BUILD_SELECTED` to be mixed with
  `FIBER_PORT_PROFILE` or `FIBER_FORCE_PORT_*`;
- produce exactly one internal `FIBER_PORT_*` selection macro;
- fail the build if no supported port matches;
- fail the build if more than one port matches;
- derive normalized aggregate gates such as `FIBER_PORT_IS_BASELINE`,
  `FIBER_PORT_IS_MAINLINE`, and `FIBER_PORT_IS_V8M`;
- prefer ARMv8.1-M Mainline over ARMv8-M Mainline if a future toolchain exposes
  both architecture macros;
- treat enabled MVE as ARMv8.1-M Mainline selection input when the toolchain
  exposes MVE but still reports only `__ARM_ARCH_8M_MAIN__`;
- keep STM32 family names out of the low-level switch logic;
- expose a diagnostic `FIBER_PORT_NAME` for the selected internal port;
- keep all canonical `FIBER_PORT_*` feature traits normalized to `0` or `1` in
  the selected port before any common runtime source uses them.

STM32 series mapping belongs in documentation and board integration examples.
CPU context switching belongs to the ARM profile port.

Explicit profile names currently cover architecture classes, not every exact
FreeRTOS port directory:

```c
FIBER_PORT_PROFILE_AUTO
FIBER_PORT_PROFILE_ARMV6M
FIBER_PORT_PROFILE_ARMV7M
FIBER_PORT_PROFILE_ARMV7EM
FIBER_PORT_PROFILE_ARMV8M_BASELINE
FIBER_PORT_PROFILE_ARMV8M_MAINLINE
FIBER_PORT_PROFILE_ARMV81M_MAINLINE
```

Future splits may add more specific profiles, for example a Cortex-M7 r0p1
profile or ARMv8-M Secure/Non-secure profiles, when the implementation needs a
separate source path rather than only a policy gate.

`FIBER_PORT_SELECTION_ALLOW_MISMATCH` exists only for unusual toolchains or
bring-up experiments where compiler architecture macros are missing or known to
be wrong. Normal production builds should leave it disabled. The older
`FIBER_PORT_PROFILE_ALLOW_MISMATCH` spelling is kept as a compatibility alias.

`FIBER_PORT_BUILD_SELECTED` is the planned FreeRTOS-like production path. In
that mode the build chooses the port instead of asking `fiber_port_select.h` to
auto-detect it:

```text
compiler/include path:
  exposes the selected port interface

build defines:
  FIBER_PORT_BUILD_SELECTED=1
  exactly one FIBER_PORT_ARMV*=1

build sources:
  exactly one selected runtime port source group per runtime image
  matched Secure/TF-M companion component may be a separate target/artifact
  no second callable fiber runtime ABI exists in the same runtime image
```

The selected `FIBER_PORT_ARMV*` result is only an architecture-class
compatibility check. It is not the exact port identity. Exact production
identity is the tuple:

```text
selected fiber_portmacro.h include path
selected runtime source group
compiler/toolchain identity and version plus CPU/FPU/ABI flags
privilege and MPU configuration
Secure-only, Non-secure, TrustZone, NTZ, or TF-M role
FP, MVE, PAC, BTI, PSPLIM, and errata policy
matching mandatory companion artifacts and optional integration extensions
context layout/feature ABI identity
```

Every production build records that tuple as an auditable build manifest and
links only its matching objects. This does not require another generic
`FIBER_PORT_ID_*` selector: the exact selected header/source path, immutable
context identity, and ABI mismatch guards provide the identity. Architecture
auto-detection cannot infer MPU enablement, privilege model, security-domain
role, SecureContext versus TF-M ownership, or PAC/BTI policy.

Therefore `FIBER_PORT_BUILD_SELECTED=1` is mandatory for every production MPU,
unprivileged, Secure-only, Non-secure, TrustZone, NTZ, TF-M, MVE, PAC, or BTI
profile, and for every profile whose context layout differs under the same
architecture macro. `AUTO`, `FIBER_PORT_PROFILE`, and `FIBER_FORCE_PORT_*` are
compile-matrix, bring-up, or unambiguous classic-profile conveniences only.
They cannot establish a production support claim for those exact profiles.
Failing to provide an exact manifest is a configuration error, not permission
to route silently to a generic privileged port.

During the v2 migration, `fiber_port_select.h` still validates and normalizes
that build-selected result. The long-term selected `fiber_portmacro.h` provides
the CPU interface directly to selected port sources. Public headers consume only
the selected type-only facade, and common runtime sources consume only the
CPU-neutral callable ABI. `fiber_port_select.h` can then remain a development
convenience rather than a required production dependency.

For Cortex-M7 build-selected matrix runs, the selected group is currently:

```text
defines:
  FIBER_PORT_BUILD_SELECTED=1
  FIBER_PORT_ARMV7EM=1

include path:
  fiber/port/ARM_CM7/r0p1

source:
  fiber/port/ARM_CM7/r0p1/fiber_port.c
```

This matches the FreeRTOS rule that `GCC_ARM_CM7` routes to the r0p1-safe port.

For the compile/link-covered Cortex-M3 MPU profile, the exact build-selected
manifest is:

```text
defines:
  FIBER_PORT_BUILD_SELECTED=1
  FIBER_PORT_ARMV7M=1

include path:
  fiber/port/ARM_CM3_MPU

sources:
  fiber/port/ARM_CM3_MPU/fiber_port.c
  fiber/port/ARM_CM3_MPU/fiber_port_boot.c

required integration:
  exact privileged/unprivileged linker boundaries
  exact 32-byte current-context aperture
  separately compiled context-cohort expectation plus linker KEEP
```

`FIBER_PORT_ARMV7M` does not identify privileged versus MPU execution. The
include path, source group, immutable cohort, and linker manifest provide that
identity. Auto/profile/force selection remains on privileged `ARM_CM3`; it
must never infer an unprivileged policy from `__MPU_PRESENT`.

## Core Profiles

The port split is based on architectural behavior:

| Profile | Typical STM32 families | Main concerns |
| --- | --- | --- |
| ARMv6-M | STM32F0, STM32G0, STM32C0, STM32L0, STM32U0, STM32WB0 | Thumb-1 assembly, no BASEPRI, no FPU, no mainline registers |
| ARMv7-M | STM32F1, selected STM32F2 class parts | Mainline PendSV path, no FP high-register context |
| ARMv7E-M | STM32F3, STM32F4, STM32G4, STM32L4, STM32F7, STM32H7, STM32WB | Mainline path, optional FPU, M7 errata policy |
| ARMv8-M Baseline | Cortex-M23 reference profile; no current STM32 MCU product claim | Baseline path, security state, PSPLIM access gates |
| ARMv8-M Mainline | STM32L5, STM32U5, STM32H5, STM32WBA | TrustZone, Non-secure EXC_RETURN, PSPLIM, optional FPU |
| ARMv8.1-M Mainline | STM32N6 class targets | MVE, PAC, BTI, PSPLIM, extended context policy |

The table is a routing aid, not a validation claim.

## FreeRTOS Parity Backlog

The current v2 selection layer covers the main STM32 Cortex-M architecture
classes. That does not mean every FreeRTOS Cortex-M port scenario is implemented
or validated.

Current boundary:

```text
Port selection for STM32 Cortex-M classes:
  implemented for auto and explicit profile modes

Full FreeRTOS-level port behavior for every STM32 Cortex-M scenario:
  not complete yet
```

Backlog required before stronger parity claims:

| Area | Current v2 status | Required future work |
| --- | --- | --- |
| Cortex-M7 r0p0/r0p1 | Concrete `ARM_CM7/r0p1` sources own frame/SVC/PendSV/exception mechanics and always compile the errata workaround. Runtime startup validates the M7 CPUID and immutable port trait. | Re-run current H7 validation and validate on an affected r0p0/r0p1 core before claiming hardware errata parity. |
| ARMv8-M Baseline / M23 | Exact build-selected `ARM_CM23_NTZ/non_secure` slices 1-5 define the Non-secure PSPLIM-slot policy, sealed frame, strong SVC first start, and exact non-MPU PendSV save/select/restore plus `runtime_schedule`. Its static archive, external cohort expectation, vector, section-GC, normal/LTO, and duplicate-handler proofs pass. Auto/profile selection remains deliberately transitional. | Validate the concrete Non-secure profile on hardware before any support claim. Secure, MPU, and companion roles remain separate profiles. |
| ARMv8-M Mainline / M33 | Exact build-selected `ARM_CM33_NTZ/non_secure` slices 1-4 freeze the privileged non-MPU/no-FPU NTZ layout and traits and implement sealed construction, strong fail-closed SVC/PendSV handlers, exact live-PSPLIM save/restore, all eight forward operations, paired generated-assembly parity, and normal/LTO archive/vector/ELF proofs. It deliberately provides no global auto-selection or hardware claim. | Validate the concrete NTZ runtime on Cortex-M33 hardware. SecureContext, TF-M, MPU, and M33F remain distinct exact profiles. |
| ARMv8-M Mainline / M33F | Exact build-selected `ARM_CM33F_NTZ/non_secure` slices 1-4 freeze the FPU cohort independently from `ARM_CM33_NTZ`: FPU/compiler/CMSIS agreement, exact basic/extended EXC_RETURN set, 72-byte initial frame, 212-byte maximum, distinct `C3FN` identity, sealed construction, CPACR/FPCCR prepare/readback, strict first-start SVC, and FreeRTOS-shaped FP PendSV (`s16-s31`, ten-word PSPLIM/core frame, scheduler BASEPRI bridge, restore). Paired hard-float/softfp construction/SVC/PendSV generated-code checks plus normal/LTO archive/vector proofs retain both strong handlers in slots 11/14, all eight forward operations, and reject competing handler ownership. `FIBER_PORT_RUNTIME_SELECTABLE` is one only when this exact profile is explicitly build-selected. | Validate FPU first-start, basic/extended FP switching, vector/priority readback, and long-run stress on concrete Non-secure hardware before support. |
| ARMv8.1-M / M55 / MVE | Selection can detect MVE and route to the ARMv8.1-M profile; transitional SVC/PendSV/frame code is compile-covered, but MVE/PAC/BTI policy is not FreeRTOS-level. | Implement MVE-only and PAC/BTI policy where applicable, stack-frame implications, and validation beyond scalar FP stress tests. |
| Source layout | ARMv6-M, ARMv7-M, Cortex-M4 ARMv7E-M, concrete CM7, M23 NTZ, M33 NTZ, and M33F NTZ have separate runtime source groups. Global v8-M auto/profile routing and unported M55/security roles still use `transitional_v8m`. | Replace remaining transitional v8-M roles with one concrete runtime source group per runtime-image security/profile ABI and bind its identity-matched Secure artifact or TF-M component where required. |
| Hardware evidence | H7/M7 has the strongest historical hardware evidence, but the latest mandatory-validation hardening is pending a fresh board run. Other profiles are unsupported unless separately ported and recorded. | Promote each profile only after board-level smoke/runtime/FPU/security/performance validation as appropriate. |

Do not describe a profile as FreeRTOS-level only because it has selection logic.
Every runtime-selected profile has compile/link-covered SVC/PendSV symbols;
the concrete M33 NTZ profile now has the same software-side proof boundary but
remains build-selected and hardware-unvalidated.
Transitional v8-M runtime remains fail-closed without explicit bring-up opt-in.
Passing compile checks does not prove exception return,
security-domain behavior, FPU/MVE context behavior, or
real interrupt-mask timing on hardware.

## Common Runtime Contract

The common runtime owns:

- public API;
- current-fiber ownership;
- switch publication state and ordering;
- CPU-neutral scheduler lifecycle preconditions;
- public panic reporting and panic-code precedence;
- diagnostics;
- integration validation-hook declarations;
- documentation-visible settings.

The common runtime does not own:

- physical exception frame layout;
- software-frame size, saved-SP modulo, and EXC_RETURN word index;
- assembly save/restore sequences;
- security-domain register access;
- PSPLIM/MSPLIM register access;
- FPU/MVE lazy-stacking register policy;
- SVC instruction encoding or SVC handler dispatch.

The current public API has this exact shape:

```c
void fiber_init(FiberContext *ctx,
                void *stack_begin,
                void *stack_end,
                entry_t entry,
                void *arg);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
FiberContext *fiber_current(void);
void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                   void *user);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void fiber_schedule(void);
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_start(void);
```

Direct target selection from Thread mode is not part of the core API.
`fiber_yield()`, `fiber_sleep_until()`, `fiber_wake()`, wait APIs, ticks, and
task-state types are not current library exports. They are future application
scheduler-layer design names only.

The low-level primitive that enters the scheduler-driven PendSV path should not
own yield/sleep/wait policy. Its working name is `fiber_schedule()`; a name such
as `fiber_jump_scheduler()` is also acceptable if it makes the boundary clearer.
This primitive only requests entry into the scheduler/port path.

Common scheduler-jump preconditions:

- `fiber_schedule()` is a Thread-mode API;
- a runtime-owned current context must already be seeded;
- every restored fiber context requires `PRIMASK == 0`, `BASEPRI == 0` where
  implemented, and `FAULTMASK == 0` where implemented;
- privileged direct-PendSV paths validate those masks before the ICSR write;
- unprivileged MPU paths do not trust pre-SVC reads of privileged mask state.
  They issue the port-owned yield SVC, whose Handler-mode dispatch validates the
  real masks before the ICSR write;
- the unprivileged `fiber_current()`/`fiber_schedule()` call graph and
  Thread-mode request stub are executable without privileged register or
  privileged-write access. Required common state is mapped read-only;
- unprivileged context return uses a port-owned return-SVC veneer; it never
  branches directly from Thread mode into the privileged common task-return
  sink;
- writable fiber stacks and application data do not share an MPU region with
  writable context metadata, scheduler state, or port-private runtime state;
- the scheduler hook must return a real initialized `FiberContext`;
- the scheduler hook is exception-path code and must be declared with
  `FIBER_SCHEDULER_HOOK_ATTR`, which includes sensitive-function and
  general-registers-only restrictions; it must not use FP, MVE, allocation,
  blocking, exceptions, or recursive fiber scheduling;
- the scheduler hook must preserve PRIMASK, FAULTMASK, BASEPRI, and CONTROL;
- `fiber_start()` calls the scheduler hook once with `current == NULL` to select
  the first context;
- that first hook call must use the same port scheduler critical-section policy
  as PendSV scheduler calls.

Future scheduler integrations may expose `fiber_yield()` and sleep/wait APIs.
Until then, application scheduler code calls `fiber_schedule()` after it has
updated its own policy state.

For example, a future application scheduler may update its state before
requesting the core scheduler jump:

```text
fiber_yield()
  mark current task READY
  fiber_schedule()

fiber_sleep_until(tick)
  mark current task SLEEPING
  record wake_tick
  fiber_schedule()

fiber_wait(object, timeout)
  mark current task WAITING
  record wait object and timeout
  fiber_schedule()
```

The core scheduler jump does not know why scheduling was requested. It simply
enters PendSV/SVC so the scheduler hook can choose the next context.

## Scheduler Layering Contract

The scheduler-driven design must keep three layers separate:

```text
port/asm core
  save current CPU context
  enter scheduler critical section
  call the stable scheduler bridge
  restore the returned context

scheduler bridge
  call the configured pick-next hook
  validate the just-saved current and returned FiberContext unconditionally
  panic on NULL or invalid context
  update runtime-owned current context

user scheduler policy
  own task states
  own ready/sleep/wait lists
  own ticks, deadlines, wait objects, events, and wake rules
  decide which real FiberContext runs next
```

The port/asm core must stay policy-free. It must not know whether scheduling was
requested because of `fiber_yield()`, `fiber_sleep_until()`, a wait timeout, an
event wake, or an ISR-side wake request.

The scheduler bridge is the only boundary between CPU context switching and
application scheduling policy. This keeps the core small and allows the
application to provide a C or C++ scheduler without rewriting architecture
assembly.

## Future Cooperative Round-Robin Scheduler Contract

This section specifies a possible future application scheduler, not behavior
implemented by the current `fiber` API. Its goal is a deterministic cooperative
round-robin policy, not a FreeRTOS priority scheduler.

Required behavior:

- no priority scheduling;
- no preemptive tick switching;
- no tick time slicing;
- no automatic switch only because a periodic tick fired;
- switches occur only at explicit yield, block, wake/reschedule, start, or
  validation-defined points;
- scheduling order is stable task registration/list order;
- `fiber_yield()` means "give the CPU to the next runnable task in list order",
  not "give the CPU to the highest priority task";
- the picker starts after the current task and scans forward through the list;
- tasks that are not runnable are skipped;
- if no user task is runnable, the scheduler must run a documented idle task or
  return to the current task only if that is explicitly safe for the current
  state.

The minimum task states are:

```text
RUNNING
READY
SLEEPING
WAITING
SUSPENDED
```

State rules:

- `RUNNING` is the current task.
- `READY` is eligible for selection.
- `SLEEPING` is skipped until its wake tick has expired or it is explicitly
  woken.
- `WAITING` is skipped until its wait object is signaled or its timeout expires.
- `SUSPENDED` is skipped until an explicit resume/wake policy makes it ready.

Sleep and wake rules:

- `fiber_sleep_until(tick)` marks the current task `SLEEPING`, records
  `wake_tick`, and requests a reschedule.
- `fiber_sleep_for(delta)` is a convenience wrapper around
  `fiber_sleep_until(now + delta)` and must use wrap-safe tick math.
- When the picker reaches a sleeping task, it must compare the current tick with
  `wake_tick` using wrap-safe arithmetic. If the wake time has not arrived, the
  task stays sleeping and is skipped.
- If the wake time has arrived, the task becomes `READY` and may be selected in
  its normal list position.
- `fiber_wake(task)` may make a sleeping or waiting task `READY` before its
  timeout expires. Explicit wake wins over the recorded sleep timeout.
- Waking an already `READY` or `RUNNING` task must be harmless and documented as
  a no-op or diagnostic event.

Wait rules:

- A waiting task records the wait object and optional timeout.
- A signaled wait object makes matching waiting tasks `READY` according to the
  documented wake policy.
- If a waiting task also has a timeout, timeout expiry makes it `READY` with a
  timeout result.
- The scheduler must not select a task whose wait condition is still false and
  whose timeout has not expired.

Tick rules:

- The tick source is an input to the scheduler, not a preemption mechanism by
  itself.
- A tick update may move expired sleeping/waiting tasks to `READY`.
- A tick ISR may request PendSV if it makes a task ready, but it must not create
  preemptive time slicing by accident.
- The tick counter width and wrap behavior must be documented before timeouts
  are exposed as stable API.

This scheduler still uses the same port discipline as FreeRTOS: the scheduler
owns task state and ready/sleep/wait lists, while the port owns CPU context
save/restore. If the final design calls scheduler selection from PendSV or SVC,
that handler-side scheduler section must use the port's interrupt-priority
critical-section policy, including the Cortex-M7 r0p1 `BASEPRI` workaround when
that path writes `BASEPRI`.

Yield policy, time-based sleep, wait objects, timeout expiry, and wake decisions
belong to the scheduler layer. The port must not inspect ticks, sleep deadlines,
wait objects, task states, or event state. The port only saves the current
context, enters the scheduler critical section, asks the scheduler bridge for the
next `FiberContext`, validates that result, and restores it.

## Custom Scheduler Hook Contract

`fiber` allows the scheduling policy to be supplied by the application.
This keeps the library focused on context switching while allowing a C or C++
application to implement its own ready/sleep/wait model.

The current public shape is:

```c
typedef FiberContext *(*FiberSchedulerPickNextFn)(FiberContext *current,
                                                  void *user);

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                   void *user);
```

The exact names may change, but the boundary should not:

- architecture assembly saves the current CPU context;
- architecture assembly calls one stable C bridge, not an arbitrary user
  function pointer directly;
- the C bridge calls the configured scheduler hook;
- the hook returns the `FiberContext` to restore next;
- architecture assembly restores only the returned context.

In the scheduler-driven path, `from/to` publication slots are not part of the
PendSV ABI. The port does not receive a preselected target from Thread mode.
PendSV/SVC derives the source from the runtime-owned current context, saves it,
calls the scheduler bridge, and restores the returned context.

The normal scheduler-driven port state should be reduced to:

```c
FiberContext *volatile current_context;
FiberSchedulerPickNextFn pick_next;
void *pick_next_user;
```

Optional request/debug flags may be added, but the normal path must have one
source of truth for the next context: the scheduler hook result.

The expected scheduler-driven PendSV flow is:

```text
panic if Thread mode is not already using PSP
current = current_context
panic if live PSP cannot hold the source software frame
save current context
enter port scheduler critical section
next = fiber_port_scheduler_pick_next_from_pendsv(current)
panic if next == NULL
panic if next is not a valid restore target
current_context = next
exit port scheduler critical section
restore next context
```

`fiber_runtime_state.h` is common-private scheduler state. Selected-port C must
include `fiber_runtime_port_abi.h` instead and cannot see the hook pointer, user
pointer, first-selection marker, or current slot as a C lvalue. Selected
assembly may only load the exact current-slot symbol. Do not reintroduce
`from/to` slots as a competing switch mechanism.

The selected-port scheduler wrapper has this shape:

```c
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(
        FiberContext *current);
```

The selected wrapper and common runtime helpers jointly enforce validation around
the user hook:

- the hook must be configured before the scheduler starts;
- `fiber_start()` must select the first context by calling the hook with
  `current == NULL`;
- the first-start hook call must be protected with the same port scheduler
  critical-section policy as handler-side scheduler calls;
- changing the hook while fibers are running is forbidden unless a future API
  defines a sealed, synchronized replacement protocol;
- hook installation must be rejected after the runtime-owned current context has
  been seeded;
- the default hook pointer is `NULL`;
- explicitly installing a `NULL` hook is invalid;
- a scheduler-driven PendSV/SVC path must panic if no hook is configured;
- the hook must return a non-NULL context for every real scheduler-driven
  switch;
- a `NULL` returned context must always panic;
- idle must be represented by a real initialized `FiberContext`, selected by
  the scheduler hook like any other runnable context;
- the returned context must be initialized, sealed, and eligible for restore;
- the bridge must validate the returned context before architecture assembly
  restores it: non-NULL `sp`, boot seal, stack bounds, saved-frame alignment
  (`sp % 8 == 4` for the current 36-byte software frame), software-frame
  plus hardware exception-frame headroom, EXC_RETURN signature and Thread/PSP
  bits, and any port-specific extended-frame headroom such as `s16-s31` plus
  the hardware FP extension frame;
- before saving a source context, PendSV must prove from the active
  `EXC_RETURN` value that the interrupted Thread context used PSP. If this is
  false, the handler must panic instead of saving an unrelated pre-start or
  foreign MSP stack state;
- before writing the source software frame, PendSV must prove that the live PSP
  is inside the current context bounds and has enough headroom for the core
  software frame plus any port-specific high-FP frame. If this is false, the
  handler must panic before modifying memory below `stack_base`;
- returning the current context is allowed only when the scheduler contract says
  staying on the current task is safe.

If the hook is called from PendSV or SVC, it is a Handler-mode scheduler hook,
not a normal application callback. The port must call it only inside a
port-defined scheduler critical section.

Critical-section requirements:

- on cores that implement `BASEPRI`, protect the scheduler bridge/hook with a
  `BASEPRI` threshold suitable for scheduler-aware ISRs;
- validate that the configured scheduler `BASEPRI` uses only hardware-implemented
  NVIC priority bits and still masks at least one implemented priority level;
- validate `AIRCR.PRIGROUP` so the scheduler `BASEPRI` policy is not undermined
  by an unexpected subpriority split, following the FreeRTOS Cortex-M port rule;
- do not save `BASEPRI` as part of `FiberContext`;
- restore the previous `BASEPRI` value after the scheduler bridge returns;
  no-return panic paths may stop before restore because execution does not
  continue;
- on Cortex-M7 r0p1, any handler-side `BASEPRI` write must use the documented
  errata 837070 workaround before that path can be considered supported;
- on cores without `BASEPRI`, protect the handler-side scheduler bridge with a
  saved `PRIMASK` critical section, matching the FreeRTOS Cortex-M0 discipline;
- ISR-side wake/tick APIs for no-BASEPRI ports still need an explicit API-level
  policy before they are exposed;
- ISRs above the configured scheduler priority threshold must not call
  scheduler-aware fiber APIs directly.

Hook restrictions:

- bounded execution time;
- no blocking;
- no `fiber_yield()`, `fiber_sleep_*()`, or wait API calls from inside the hook;
- no `malloc()`/`free()` or heap-dependent C++ allocation;
- no locks that can wait for another fiber;
- no `HAL_Delay()` or polling loops without a fixed short bound;
- no user callbacks;
- no throwing C++ exceptions across the C ABI boundary;
- define the callback with `FIBER_SCHEDULER_HOOK_ATTR`;
- do not compile the callback or any callee with function instrumentation,
  profiling, sanitizers, stack protectors, or hidden FP/MVE runtime helpers;
- no floating-point, MVE, or other extended-context instructions;
- return with `PRIMASK`, `FAULTMASK`, `BASEPRI`, and `CONTROL` exactly equal to
  their entry values. The common bridge validates this after every callback;
- the complete hook call graph must obey the same register and bounded-runtime
  restrictions;
- no direct edits to port-owned switch slots or CPU context frames.

The application may implement the scheduler in C++ by storing a pointer to a C++
object in the `user` argument and using an `extern "C"` or static thunk:

```c
static FIBER_SCHEDULER_HOOK_ATTR
FiberContext *pick_next_thunk(FiberContext *current, void *user)
{
    return ((MyScheduler *)user)->pick_next(current);
}
```

The hook API must remain C-callable so that assembly and C ports do not depend
on C++ ABI details.

## Port ABI Contract

The final callable boundary is defined in
`V2_RUNTIME_PORT_BOUNDARY_CONTRACT.md` and the opaque type boundary is defined
in `V2_OPAQUE_CONTEXT_CONTRACT.md`. Common code uses opaque context pointers;
frame sizes, offsets, CPU-state tokens, validators, and exception mechanics are
port-private implementation facts:

```c
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_init(FiberContext *ctx,
                             void *stack_begin,
                             void *stack_end,
                             entry_t entry,
                             void *arg);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_panic_wait(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
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

The eight generic ABI names above are frozen. Port-private helper names may
change, but ownership must not:

- `fiber_api_types.h` owns only tagged forward declarations and callback types;
- the selected public type-only header completes `FiberContext` for application
  allocation but is not included by common runtime translation units;
- selected private headers may complete scheduler CPU-state tokens, but common
  code never allocates, sizes, or interprets those tokens;
- the selected port embeds any CPU-neutral metadata at a private offset and
  owns the final immutable context seal plus dynamic restore checks;
- mutable saved SP, EXC_RETURN, FP/MVE, and security state is validated
  dynamically rather than included in a fixed hash by default;
- `fiber/port/fiber_port_select.h` owns strict compile-time profile selection only;
- the selected public type-only facade, CPU-neutral callable ABI, and
  port-private implementation headers have separate include boundaries;
- the callable ABI must not expose context fields, frame offsets, or MSP
  addresses to common code;
- common code decides lifecycle and scheduler-policy preconditions, while the
  selected port owns privilege-aware CPU mode/mask validation across the direct
  request path, yield-SVC Handler path, and context-restore boundary;
- common code publishes the current context and installs the scheduler hook before a
  scheduler-driven switch can run;
- common code owns the current-context policy;
- common code checks current ownership and calls the selected-port schedule
  request boundary. It does not read IPSR, CONTROL, PRIMASK, BASEPRI, FAULTMASK,
  SCB, or NVIC state;
- `fiber_port_runtime_schedule()` owns the complete privilege-aware
  architecture-specific request
  mechanism. Privileged non-MPU ports may directly publish PendSV with mandatory
  barriers after validating Thread/mask state. Unprivileged or MPU ports perform
  only safely observable pre-SVC checks and issue a port-owned yield SVC, whose
  validated Handler-mode dispatch checks the real privileged mask state and
  publishes PendSV;
- ports that restore unprivileged fibers guarantee zero PRIMASK and, where
  implemented, zero BASEPRI and FAULTMASK before exception return. Handler
  validation is defense in depth, not a repair path for a mask state that could
  block or fault SVC entry;
- neither the direct nor SVC request path selects a context. Scheduler selection
  remains inside PendSV after the outgoing context is saved;
- the selected port owns the PRIMASK or BASEPRI critical section used only
  around the scheduler hook inside first selection and PendSV;
- selected-port state capture and validation checks PRIMASK, FAULTMASK,
  BASEPRI, CONTROL, and any profile-specific state around every hook call;
- common code owns callback invocation, recursion/hot-swap policy, NULL-result
  handling, and current publication; the selected port privately validates every
  save and restore target around that common policy call;
- the structural opaque-context move preserves the current critical-section
  placement and must not introduce a second BASEPRI/PRIMASK layer;
- port code performs CPU-specific save, restore, and exception return;
- port code must not decide scheduler/runtime semantics;
- port code owns the physical stack frame layout;
- port code owns SVC first-start mechanics;
- a runtime-supported port must provide SVC first-start; non-SVC fallback start
  paths are not part of the active v2 contract;
- port code owns Thread/Handler mode preconditions that depend on CONTROL,
  IPSR, PSP, MSP, PRIMASK, BASEPRI, or FAULTMASK;
- port code owns PendSV/SVC priority programming and vector routing validation;
- port code owns BASEPRI/PRIMASK critical-section assembly used inside PendSV;
- port code owns Cortex-M7 r0p0/r0p1 errata policy when BASEPRI writes exist in
  the handler path;
- port code owns feature gates that depend on architecture state.

Common code may provide small helpers for hashing, range checks, alignment,
diagnostics, and user-facing API validation. Those helpers must not hide a CPU
context layout decision. A CPU-neutral metadata hash is not a replacement for
the selected port's final integrity seal.

The selected port's private saved-stack-pointer field follows the FreeRTOS
`pxTopOfStack` invariant: it points to the last saved software frame for a
context that is not currently running. While a fiber is running, the live stack
pointer is CPU PSP. A port updates its private saved pointer when saving that
context and must not move the target saved pointer forward after restore.

The port ABI hides architecture-specific storage from common code and treats it
as private for users. Scheduler hook/user storage and current-context semantics
remain common-owned; selected CPU-state tokens and runtime startup state remain
port-owned. Initial MSP rewind/validation is one runtime startup policy and is
not a mandatory field in every future context.

Each selected context layout has a port identifier, layout version, size,
alignment, and feature identity. The immutable seal validates this identity.
Before precompiled library objects are supported, the build must also force a
real versioned-symbol relocation or equivalent link-time mismatch failure; an
unused `extern` declaration is not sufficient.

Avoid a port-level function shaped like `fiber_port_request_switch(from, to)`.
Passing `from` and `to` to the port makes it too easy for the port to start
owning runtime policy. The required boundary is: common code requests a
scheduler jump, then the port enters the architecture-specific scheduler switch
path and restores only the context returned by the scheduler bridge.

Port entry points must document whether they are callable from Thread mode,
Handler mode, or both. Undefined call mode is not acceptable for start/switch
primitives.

## Stack Frame Contract

Every port must document and test its initial stack frame.

Required invariants:

- fiber stacks are at least 8-byte aligned at exception return;
- the synthetic frame sets `xPSR.T`;
- the synthetic stacked `PC` stores the entry address with bit 0 clear;
- Thumb state comes from `xPSR.T`, not from stacked `PC` bit 0;
- the initial `LR`/`EXC_RETURN` value is selected-port-owned. A production port
  fixes or validates it as part of its ABI; transitional bring-up inputs do not
  make it an application tuning option;
- stack growth direction is explicit;
- stack limit metadata is either implemented for the port or explicitly unused;
- invalid stack bounds trap before the first switch;
- no user entry runs on MSP unless a port explicitly documents that policy.

The layout used by `fiber_port_context_init()` is part of the selected port ABI.
Changing it requires updating the port audit note, layout identity, link guard,
and compile/runtime validation.

Selected-port validation proves stack bounds, saved-SP alignment, frame shape,
and `EXC_RETURN` sanity. Common code may validate CPU-neutral API inputs but
must not inspect frame traits or hard-code a universal software frame size such
as 36 bytes. ARMv6-M and ARMv7E-M currently both use a 9-word software frame,
but ARMv8-M security, PSPLIM, MVE, PAC, or BTI support may need different
context slots. New ports publish and validate their private layout before a
runtime support claim is made.

## PendSV Contract

All ports that use PendSV must preserve the FreeRTOS-style invariants:

- save and restore callee-saved core registers required by the ABI;
- preserve `LR` as the active `EXC_RETURN` value when needed;
- run fibers on PSP;
- keep PendSV at the lowest priority unless a port documents a stronger rule;
- update current-fiber ownership exactly once per real switch;
- keep publication of source and target contexts ordered before PendSV can read
  them;
- never allow a real cooperative switch to be silently delayed by interrupt
  masks.
- prove that the interrupted Thread context used PSP from the active
  `LR`/`EXC_RETURN` bit 2 before saving the source context. Handler-mode reads
  of `CONTROL.SPSEL` are not a sufficient proof for SVC-started fibers.

PendSV must not call arbitrary user code directly. A scheduler-driven path may
call the configured pick-next hook only through the stable scheduler bridge and
only inside the port-defined scheduler critical section. After a context is
selected and validated, PendSV restores only that context and returns through
the architecture-defined exception-return path.

If a port uses SVC and PendSV together, their shared state ownership must be
documented. The first-start SVC path must not create a second current-context
owner beside PendSV/common state.

## Handler Wiring Contract

The final selected-port model uses exclusive static handler ownership.

Required rules:

- every selected port defines strong `SVC_Handler` and `PendSV_Handler` symbols;
- the application must not define competing strong handlers;
- duplicate strong definitions are intentional link-time configuration errors;
- CubeMX-generated strong handler definitions are removed or excluded, not
  retained as wrappers;
- the selected strong handler either contains the naked assembly body or branches
  to a port-private assembly label without losing LR/EXC_RETURN;
- `fiber_svc` and `fiber_pendsv` have been removed; selected ports directly
  own strong `SVC_Handler` and `PendSV_Handler` symbols;
- wrapper/direct switches and `FIBER_*_WIRED` integration claims are removed
  after the mechanical migration;
- static archive, `--gc-sections`, and LTO proofs must retain both handlers;
- vector-table relocation and security-domain vector selection must be explicit
  for ARMv8-M targets;
- runtime validation proves that slots 11 and 14 in the selected port's active
  vector-table source resolve to the strong handlers and that both paths execute
  on hardware;
- a VTOR-capable port validates the applicable `SCB->VTOR` bank; a port without
  VTOR validates its architecture/platform vector base and remap policy.

If another RTOS, bootloader, monitor, or debug framework owns SVC or PendSV,
`fiber` must require explicit integration instead of assuming ownership.
Runtime vector-table patching and handler chaining are not default integration
paths. Either feature requires a separate explicit contract and validation
record.

## First-Fiber Start Contract

`main` used a direct boot trampoline as an earlier STM32H7/Cortex-M7
first-start path. Current `v2` intentionally removed that fallback. A
runtime-supported port must start the first context through SVC.

The current ARMv7E-M SVC path:

- enters the first fiber through exception return;
- centralizes first-start CPU flag setup before and inside the handler path;
- requires privileged Thread/MSP state before issuing SVC;
- optionally rewinds MSP through the sealed boot plan and verifies MSP
  read-back;
- clears any pending PendSV while interrupts are still masked before issuing
  SVC;
- requires SVCall to run at highest priority;
- uses `svc #FIBER_SVC_START_NUMBER` as the dispatch key;
- rejects SVC entry from PSP;
- validates the SVC MSP-frame alignment, opcode, and immediate before restoring
  the first context;
- validates the published current `FiberContext` before PSP is restored;
- clears BASEPRI in the SVC handler before the first context is restored;
- sets PSP before exception return; the active `EXC_RETURN` selects and proves
  the stack used for unstacking. A port must not infer the interrupted stack
  from Handler-mode `CONTROL.SPSEL`. An ARMv8-M port may additionally seed
  `CONTROL.SPSEL` for the post-return Thread state when its reference ABI
  requires it; that write does not replace exact `EXC_RETURN` validation;
- clears and verifies `CONTROL.FPCA` when the selected port has an FP context;
- panics if the SVC instruction returns to the start helper.

This is deliberately more paranoid than the minimum FreeRTOS first-task start.
It is still cooperative: it does not introduce tick scheduling or priority
scheduling by accident.

The SVC path must keep defining:

- one compile-time-checked service namespace for first start, unprivileged
  yield, unprivileged task return, and every enabled optional MPU/security
  service. Service numbers must be unique and unknown services fail closed;
- whether it requires privileged Thread mode before start;
- how it selects Thread PSP by `EXC_RETURN`, and how it sets or preserves
  `CONTROL.nPRIV` and `CONTROL.FPCA`;
- how it selects Secure or Non-secure handler state on ARMv8-M;
- how an unprivileged entry-function return reaches the common no-return sink
  through a validated port-owned SVC veneer;
- how it fails when SVC is already owned by another component.

There is no direct trampoline validation path anymore. Adding a new runtime port
means adding and validating that port's SVC first-start path.

## FPU and Extended Context Contract

For FPU-capable ports:

- save `s16-s31` only when the active `EXC_RETURN` reports an extended FP frame;
- keep `FIBER_FPU_LAZY = 0` as the portable safety default;
- allow `FIBER_FPU_LAZY = 1` only as an opt-in performance setting after target
  validation;
- clear `CONTROL.FPCA` before starting the first fiber when an FP context exists;
- keep MVE targets explicit, because MVE may need broader extended-context
  handling than classic scalar FP tests reveal.

Each FPU/MVE port must state:

- whether compiler flags use soft, softfp, or hard FP ABI;
- whether the target exposes classic scalar FP, MVE, or both;
- how `FIBER_PORT_HAS_FPU` and
  `FIBER_PORT_HAS_EXTENDED_FP_CONTEXT` are derived from compiler and silicon
  facts;
- how FPCCR lazy-stacking bits are configured or intentionally left untouched;
- whether pre-start FP code is part of the validation case.

Current v2 policy:

- `FIBER_PORT_HAS_EXTENDED_FP_CONTEXT` requires both scalar FP compiler
  generation and a CMSIS silicon FPU declaration.
- MVE-FP is treated as an extended FP/MVE context candidate, but runtime use is
  gated until hardware validation.
- MVE without scalar FP is rejected by runtime policy validation because the
  current assembly does not implement a separate MVE-only save path.

Do not infer MVE safety from a scalar double-accumulator test alone.

## ARMv8-M Security and PSPLIM Contract

ARMv8-M support must separate three ideas:

1. whether a context layout has a PSPLIM slot;
2. whether the current security domain exposes a PSPLIM register that this code
   may access;
3. whether the target has been validated in Secure, Non-secure, or secure-only
   mode.

Do not enable PSPLIM register access only because the architecture profile name
contains ARMv8-M.

Required gates:

- an explicit selected-port initial `EXC_RETURN` policy;
- explicit Non-secure EXC_RETURN policy;
- explicit PSPLIM register-access policy;
- explicit vector-domain policy for SVC and PendSV;
- explicit FP access policy for CPACR/NSACR when applicable.

Current v2 policy:

- `FIBER_PORT_USES_PSPLIM_REGISTER` is the actual PSPLIM access gate.
- ARMv8-M Baseline/Mainline, ARMv8.1-M, TrustZone/Non-secure bank targeting,
  MVE, and PAC/BTI runtime use is blocked by default unless the matching
  `FIBER_ALLOW_UNVALIDATED_*` opt-in is set for bring-up.
- The opt-in only allows experiments; it does not add the FreeRTOS-style
  CONTROL/PSPLIM/secure-context/PAC-key context slots.

ARMv8-M support claims must name the exact domain:

- Secure-only;
- Secure firmware starting Non-secure fibers;
- Non-secure application only;
- mixed Secure/Non-secure integration.

A port validated in one domain is not automatically validated in another.

## Cortex-M7 r0p1 Errata Policy

FreeRTOS has a Cortex-M7 r0p1 workaround around `BASEPRI` writes in PendSV for
ARM errata 837070.

FreeRTOS routes `GCC_ARM_CM7` to a dedicated `portable/GCC/ARM_CM7/r0p1` port
instead of sharing Cortex-M7 with the Cortex-M4 port.

The ARMv7E-M scheduler-driven PendSV path writes `BASEPRI` around the scheduler
bridge. The concrete `ARM_CM7/r0p1` port always emits an errata-safe `BASEPRI`
write sequence around the scheduler raise, restore, and first-start clear paths.
The sequence follows
the FreeRTOS intent but is stricter: it preserves and restores the previous
`PRIMASK` instead of unconditionally re-enabling IRQs.

The errata-safe asm snippets use `r12` as scratch while preserving `PRIMASK`.
Any port asm block that uses those snippets must treat `r12` as clobbered and
must not keep live context state in `r12` across the macro expansion.

This port-owned policy is compile-covered by the matrix for Cortex-M7 and
Cortex-M7F. Runtime startup also checks CPUID and the immutable port trait. This
is still not a hardware validation claim.
Affected Cortex-M7 r0p0/r0p1 hardware must pass runtime scheduler-switch
validation before parity with the FreeRTOS CM7/r0p1 port can be claimed.

If this policy grows beyond a guarded `BASEPRI` sequence, the Cortex-M7 source
path must remain separate from ARM_CM4 rather than hiding behavior behind shared
ARMv7E-M conditionals.

## FreeRTOS Sync Policy

FreeRTOS is used as a reference for CPU-port behavior, not as an API target.

For each port, keep a short audit note with:

- the FreeRTOS Kernel commit or release used for comparison;
- the FreeRTOS port files reviewed;
- the matching behavior copied conceptually;
- intentional differences;
- unsupported FreeRTOS CPU-port features;
- validation status.

If source code or close code structure is copied or adapted from FreeRTOS, keep
the required MIT notice in the relevant file or in `THIRD_PARTY_NOTICES.md`.
Purely independent code that follows the same ARM architectural rules does not
need to pretend it is copied code.

Renaming FreeRTOS identifiers or changing formatting does not make copied code
independent. When in doubt, treat close source-level adaptation as MIT-covered
third-party code and document it.

Do not copy FreeRTOS comments verbatim unless the relevant license notice is
kept. Prefer fresh comments that explain the local `fiber` contract.

## Regression Policy

Before a port refactor can be treated as equivalent to the previous H7 path:

- the compile matrix must pass;
- `git diff --check` must pass;
- source and docs must remain ASCII-only unless a file explicitly opts out;
- the STM32H7 runtime validation checklist must still pass;
- panic codes used by validation must remain documented;
- performance-mode results must not be used to justify changing portable
  defaults.

A file-layout-only split must pass the same validation level as the source path
before support claims are preserved. If the source H7 path was
`fpu-validated` or `performance-validated`, the moved H7 port must repeat that
validation before carrying the same claim.

Behavior-changing commits should be small enough that a failed board validation
can be traced to one decision.

Changing a selected port's private saved-stack-pointer save/restore invariant is
a behavior-changing commit, even when the new invariant is more FreeRTOS-like.
Such a change must repeat the relevant board runtime validation before
inheriting an earlier runtime-validated support label.

## Validation Levels

Use these support labels consistently:

- `unsupported`: code is not intended to work for this profile;
- `compile-only`: representative compiler flags pass, no hardware claim;
- `smoke-tested`: boots and switches on real hardware with simple integer
  fibers;
- `runtime-validated`: stress test passes on real hardware, including current
  tracking and mask guards;
- `fpu-validated`: runtime validation includes FP save/restore and pre-boot FP
  hygiene;
- `security-validated`: ARMv8-M Secure/Non-secure behavior is validated in the
  claimed domain;
- `performance-validated`: opt-in faster settings are validated on the specific
  target.

A release claim must not use a stronger label than the weakest required test for
that feature profile.

Minimum evidence for stronger labels:

- `compile-only`: compile matrix entry, target flags, and warnings recorded;
- `security-compile-only`: ARMv8-M/ARMv8.1-M
  `FIBER_TRANSITIONAL_V8M_RUN_NONSECURE=1` and Secure-to-Non-secure bank
  scenarios compile with the selected toolchain, without claiming runtime
  security-domain behavior;
- `smoke-tested`: board name, core, clock/config summary, and basic switch proof
  recorded;
- `runtime-validated`: long run counters, current tracking, scheduler hook
  result validation, and PRIMASK/BASEPRI policy checks where applicable;
- `fpu-validated`: all runtime checks plus pre-start FP use and FP accumulator
  integrity;
- `security-validated`: exact Secure/Non-secure ownership and vector-domain
  setup recorded;
- `performance-validated`: exact settings, target, runtime duration or counter
  threshold, and failure state recorded.

## v2 Initial Milestones

1. Create this contract on the `v2` branch.
2. Add deterministic port-selection and feature-normalization headers.
3. Add the selected-port facade and internal runtime state.
4. Add an ARMv7E-M port file shell with no behavior change.
5. Move the current STM32H7/Cortex-M7 implementation into the ARMv7E-M port
   boundary without changing behavior.
6. Keep the existing compile matrix green.
7. Add vector wiring validation hooks for PendSV and SVC where possible. Done
   for active vector-table routing. ARMv7E-M SVC-start dispatch also validates
   the SVC immediate in the handler.
8. Make SVC first-start mandatory for selected ports. Done for ARMv6-M,
   ARMv7-M, ARMv7E-M, and transitional v8-M compile-covered paths.
9. Validate the SVC start path on STM32H7 after every behavior change.
10. Split ARMv6-M and ARMv7-M support from the transitional fallback path.
    Done for Cortex-M0/M0+ and Cortex-M3 source layouts, including SVC
    first-start. Remaining v8-M code lives under `port/transitional_v8m`, not
    `fiber_core.c`, and must be split into concrete v8-M ports before support
    claims are upgraded.
11. Add conservative ARMv8-M/ARMv8.1-M feature policy gates. Done for compile
    selection, PSPLIM register access, MVE, TrustZone opt-in, and PAC/BTI
    rejection.
12. Move schedule-time CPU access behind the selected-port request ABI. The
    historical split into `fiber_port_require_schedule_environment()` and
    `fiber_port_request_schedule()` completed CPU isolation for current
    privileged ports. The final boundary collapses those calls into
    `fiber_port_runtime_schedule()` while preserving check order. A validated
    yield-SVC path is still required before an MPU or unprivileged support
    claim.
13. Add full ARMv8-M Baseline/Mainline PSPLIM and security-domain context
    layout before claiming runtime support.
14. Add full ARMv8.1-M/MVE/PAC/BTI context policy before claiming STM32N6-class
    support.
15. Keep `main` stable until a `v2` path passes the same STM32H7 validation.

## Implementation Strategy

Do not try to close every FreeRTOS parity gap in one step. The safe path is to
port the known-good H7/M7 behavior into the v2 architecture first, then expand
profile by profile.

Priority order:

```text
P0: ARMv7E-M / STM32H7-M7
  Concrete ARM_CM7/r0p1 frame/SVC/PendSV/exception sources are selected.
  Keep the compile/link symbol audit green.
  Re-run H7 runtime, trap, and FPU validation after current hardening before
  restoring the active hardware-validation claim.

P1: ARMv7-M / Cortex-M3
  Add or split a mainline non-FPU path.
  Require compile matrix plus smoke validation on real hardware before
  promoting beyond compile-only.

P2: ARMv6-M / Cortex-M0/M0+
  Isolate the Thumb-1 baseline save/restore path.
  Keep the software frame in FreeRTOS CM0 non-MPU order:
  [LR][r4][r5][r6][r7][r8][r9][r10][r11].
  Publish the saved stack pointer only after the complete software frame is
  stored.
  Validate no BASEPRI/FPU assumptions.
  Record MSP rewind and VTOR caveats per target.

P3: ARMv8-M Baseline / Cortex-M23
  Non-secure NTZ PSPLIM-slot, SVC first-start, and exact PendSV/runtime_schedule
  source policy are implemented without enabling PSPLIM register access.
  Exact archive/ELF/LTO activation evidence is complete for the build-selected
  profile; keep auto/profile routing transitional until a separate promotion.
  Validate the concrete Non-secure profile on hardware before a support claim.
  Keep Secure/MPU ownership separate before any FreeRTOS-level claim.

P4: ARMv8-M Mainline / Cortex-M33
  The exact no-FPU NTZ runtime is software-covered but hardware-unvalidated.
  The separate M33F NTZ profile now has exact construction, FPU setup, strict
  SVC first start, dynamic basic/extended FP PendSV, and archive/ELF proof.
  Validate both exact profiles on real hardware before promotion. Keep Secure,
  SecureContext, MPU, and TF-M as distinct selected profiles.

P5: ARMv8.1-M / Cortex-M55 / MVE
  Runtime policy gates exist.
  Define MVE-only save/restore if needed.
  Define PAC/BTI context save/restore where applicable.
  Validate beyond scalar FP accumulator tests.
```

Each phase should leave the tree in a working state. Mechanical source moves,
new feature policy, and behavior changes should be separate commits whenever
possible.

## Definition of Done

`v2` can claim FreeRTOS-style cooperative STM32 Cortex-M port support only when:

- each claimed core profile has its own documented port behavior;
- representative compile profiles pass;
- claimed hardware profiles have real board validation;
- H7/M7 remains at least as validated as `main`;
- ARMv8-M claims distinguish Secure, Non-secure, and secure-only behavior;
- MVE/PAC/BTI claims are explicit for ARMv8.1-M targets;
- docs, source comments, and compile gates describe the same support level;
- exactly one port is selected for every supported compile target;
- unsupported compile targets fail clearly instead of building a wrong port;
- each selected port exclusively provides strong SVC/PendSV handlers and
  competing strong definitions fail the link;
- the mandatory SVC first-start path and later PendSV path have separate
  hardware evidence;
- any copied or closely adapted FreeRTOS code carries the required MIT notice.
