# V2 Port Traits Contract

## Purpose

This document defines the selected-port traits contract for the v2 fiber
runtime.

The selected port must be the source of truth for CPU facts and port policy.
Common runtime and port helper code must consume selected-port traits instead
of guessing CPU behavior from global `__ARM_ARCH_*`, `__CORTEX_M`, toolchain,
or CMSIS macros.

The architectural model is:

```text
selected port:
  defines CPU facts
  defines context-frame policy
  defines exception-start policy
  defines scheduler critical-section policy

fiber/port root helpers:
  provides compiler/static-assert/diagnostics ABI and tightly scoped helpers
  consumes selected-port traits

fiber core:
  owns portable runtime semantics
  does not know CPU mechanics

target:
  owns configuration, panic fallback, and platform glue only
```

This follows the same boundary idea used by FreeRTOS ports: a concrete port
defines the architecture facts first, and shared helper code consumes those
facts later.

The v2 fiber runtime is not a FreeRTOS clone. It only uses FreeRTOS-style port
boundaries to keep context switching, first start, exception validation, and
CPU feature policy explicit.

## Non-goals

This contract does not define a scheduler, queues, semaphores, timers, blocking
APIs, or preemptive RTOS behavior.

This contract does not promote compile-covered ports to runtime-supported
ports.

This contract does not make ARMv8-M, TrustZone, MVE, PAC, BTI, or PSPLIM
production-supported. Those require selected-port-owned context policy and
hardware validation.

Runtime restore validation consumes these traits unconditionally. The selected
port's initial `EXC_RETURN` is an exact domain/stack/mode encoding; the common
validator may permit only that basic-frame value and, when the port declares an
extended FP context, the corresponding value with only the frame-type bit
changed. A profile may not weaken this to a broad signature test.

The build must also select exactly one source group. Compile coverage is not
sufficient: the validation matrix relocatably links every configuration and
requires one global definition for each mandatory SVC/PendSV/frame/exception
port ABI symbol.

## Layer Ownership

### Root Runtime

The root runtime owns portable fiber semantics:

```text
fiber_core.c/.h
fiber_boot.c/.h
fiber_stack.c/.h
```

The root runtime may own:

```text
fiber_init()
fiber_start()
fiber_schedule()
fiber_current()
FiberBoot construction and sealing
generic stack range math
generic restore-context validation entry points
```

The root runtime must not own:

```text
PendSV assembly
SVC assembly
CONTROL/PSP/MSP mechanics
BASEPRI/PRIMASK scheduler policy
PSPLIM policy
FPU high-register save/restore policy
EXC_RETURN layout policy
NVIC priority policy
vector wiring policy
ARMv8-M security-domain policy
MVE/PAC/BTI policy
```

### Target Layer

The target layer is limited to panic, CMSIS glue, and project configuration.

Allowed long-term:

```text
fiber_panic.h/.c
mcu_core.h
fiber_settings.h
```

Allowed temporarily:

```text
thin compatibility forwarding headers that do not own CPU policy
```

Not allowed long-term:

```text
CPU capability policy
selected-port feature detection
BASEPRI ownership
PSPLIM ownership
VTOR ownership
exception priority policy
SVC/PendSV vector policy
ARMv8-M/MVE/PAC/BTI runtime gates
```

`fiber_target.h` was removed. `fiber_port_selected.h` is the selected-port
facade and must not be replaced by a new target-level CPU-policy layer.

### Port Helper Layer

The port helper layer owns reusable Cortex-M helper primitives at the root of fiber/port.

It may provide helpers for:

```text
fiber_static_assert.h compile-time assert ABI
fiber_diagnostics.h compile-time diagnostics ABI
fiber_compiler.h compiler/attribute ABI
VTOR/vector access
NVIC priority helpers
exception setup helpers
PSPLIM register access helpers
trait-neutral FPU register helpers, only if a later port needs them
fault-status hygiene helpers
```

The port helper layer must not decide whether a selected port supports a
feature.

Rule:

```text
fiber/port root helper headers provide tools;
the selected port decides whether those tools are valid.
```

PRIMASK save/restore is port-private. Common runtime code calls only the
selected-port switch mask contract:

```c
uint32_t fiber_port_switch_mask_enter(void);
void fiber_port_switch_mask_exit(uint32_t state);
```

The selected port decides whether those functions use PRIMASK directly, wrap a
different CPU-local mechanism, or are later replaced by a port-specific
specialization. The root helper layer must not be required for this path.

BASEPRI read/write is also port-private. Common runtime code calls only:

```c
uint32_t fiber_port_basepri_read(void);
void fiber_port_basepri_write(uint32_t value);
```

Ports without BASEPRI provide no-op implementations returning zero. Ports with
BASEPRI own the register spelling, scheduler threshold, naked-asm snippets, and
Cortex-M7 r0p0/r0p1 errata sequence.

### Selected Port Layer

Each selected port owns CPU-specific runtime mechanics and policy.

A selected port owns:

```text
software frame layout
EXC_RETURN word location
SVC first-start implementation
PendSV save/restore implementation
scheduler critical-section policy
BASEPRI/PRIMASK selection
switch-publication mask implementation
FPU enable and FPCA policy
FPU high-register save/restore policy
PSPLIM policy
SVC/PendSV vector expectations
exception priority expectations
CPU errata gates
runtime support claim level
```

## Include-order Contract

The selected-port traits must be available before fiber/port root helpers and
before common runtime code consumes CPU policy.

`fiber_port_selected.h` must not include `fiber_target.h`; that facade no
longer exists.

Recommended include order:

```c
#ifndef FIBER_FIBER_PORT_SELECTED_H_
#define FIBER_FIBER_PORT_SELECTED_H_

#include "fiber_settings.h"
#include "fiber_compiler.h"
#include "mcu_core.h"

#include "fiber_port_select.h"   /* development selector, optional long-term */
#include "../fiber_types.h"

#define FIBER_PORT_MASK_PRIMASK 1
#define FIBER_PORT_MASK_BASEPRI 2

#if FIBER_PORT_ARMV6M
# include "armv6m/fiber_port_armv6m.h"
#elif FIBER_PORT_ARMV7M
# include "armv7m/fiber_port_armv7m.h"
#elif FIBER_PORT_ARMV7EM
# include "armv7em/fiber_port_armv7em.h"
#else
# include "transitional_v8m/fiber_port_transitional_v8m.h"
#endif

#include "fiber_port_traits.h"
#include "fiber_feature_policy.h"

#endif
```

The production direction is FreeRTOS-like build selection:

```text
build-selected mode:
  FIBER_PORT_BUILD_SELECTED=1
  exactly one FIBER_PORT_ARMV*=1
  exactly one selected port source group compiled
  selected fiber_portmacro.h provides the CPU trait interface
```

In that final shape, `fiber_port_select.h` is allowed to remain as a
development convenience for AUTO/profile matrix builds, but it must not be a
hard dependency of the core runtime API. The core should consume the selected
port facade and trait macros only.

A selected port header may include only:

```text
fiber_settings.h
port/fiber_static_assert.h
port/fiber_diagnostics.h
port/fiber_compiler.h
mcu_core.h
fiber_types.h
local selected-port headers
strictly trait-neutral helper probe headers
```

Do not reference `../target/mcu_core.h` unless a real target wrapper with that
path exists. The current project includes `mcu_core.h` through the configured
include path.

A selected port header must not include:

```text
fiber_target.h
fiber/port root helpers that already require validated traits
global feature policy headers that decide selected-port behavior
```

Long-term, selected-port traits may be split into separate files:

```text
armv6m/fiber_port_armv6m_traits.h
armv7m/fiber_port_armv7m_traits.h
armv7em/fiber_port_armv7em_traits.h
transitional_v8m/fiber_port_transitional_v8m_traits.h
```

This split is optional for the first migration step.

## Trait Representation Rule

Selected-port traits must be preprocessor macros.

Do not define required traits as `enum` constants if they must be checked with
`#ifndef`, `#if`, or used by preprocessor conditionals.

Correct:

```c
#define FIBER_PORT_SOFTWARE_FRAME_WORDS 9u
#define FIBER_PORT_SOFTWARE_FRAME_BYTES (FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX 8u
```

Avoid for required preprocessor traits:

```c
enum {
    FIBER_PORT_SOFTWARE_FRAME_WORDS = 9u
};
```

`enum` constants are valid C identifiers, but the preprocessor cannot test
their existence with `#ifndef`.

## Required Selected-port Traits

Every selected port must export the following effective traits before
`fiber_port_traits.h` validates them.

### Identity

```c
#define FIBER_PORT_NAME "armv7em"
```

Examples:

```text
"armv6m"
"armv7m"
"armv7em"
"transitional_v8m"
```

Future production ports may use:

```text
"armv7em_m7_r0p1"
"armv8m_baseline"
"armv8m_mainline"
"armv81m_mainline"
```

### CPU Capability Traits

```c
#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1
#define FIBER_PORT_HAS_VTOR 1
#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_HAS_FPU 1
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 1
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
```

`FIBER_PORT_HAS_FPU` means the port recognizes scalar FPU availability and may
need FPU setup or FPCA hygiene.

`FIBER_PORT_HAS_EXTENDED_FP_CONTEXT` means the port saves/restores high FP
context state, such as `s16-s31`, when required by the exception frame.

These are different policies and must not be collapsed into one trait.

Selected ports that support FPU-aware builds also own the detection bridge used
by their port-local early-enable implementation:

```c
#define FIBER_PORT_TOOLCHAIN_HAS_FP 1
#define FIBER_PORT_SILICON_HAS_FPU 1
#define FIBER_PORT_CMSIS_FPU_USED 1
```

Those macros are port facts. `fiber_port_fpu_enable_early()` consumes them to
enable CPACR/FPCCR early when the selected port supports FPU. No root
`fiber_fpu.*` implementation may decide whether a CPU profile has FPU support.

### Boot and FP Policy Traits

```c
#define FIBER_PORT_BOOT_CLEARS_FPCA 1
#define FIBER_PORT_INITIAL_EXC_RETURN 0xFFFFFFFDu
```

`FIBER_PORT_BOOT_CLEARS_FPCA` means the first-start path must clear or verify
`CONTROL.FPCA` before entering the first fiber when FP context exists.

`FIBER_PORT_INITIAL_EXC_RETURN` is the effective EXC_RETURN value used in
synthetic initial frames.

If user override is supported, the selected port may provide a default only
when the macro is not already defined:

```c
#ifndef FIBER_PORT_INITIAL_EXC_RETURN
# define FIBER_PORT_INITIAL_EXC_RETURN 0xFFFFFFFDu
#endif
```

### Scheduler Critical-section Traits

```c
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_BASEPRI
```

Allowed values:

```c
#define FIBER_PORT_MASK_PRIMASK 1
#define FIBER_PORT_MASK_BASEPRI 2
```

`FIBER_PORT_MASK_PRIMASK` means the scheduler bridge is protected by
saved/restored PRIMASK.

`FIBER_PORT_MASK_BASEPRI` means the scheduler bridge is protected by
saved/restored BASEPRI.

BASEPRI ports must also expose an effective scheduler threshold. During
migration this may alias the legacy `FIBER_SCHEDULER_BASEPRI` setting:

```c
#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
# ifndef FIBER_PORT_SCHEDULER_BASEPRI
#  define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI
# endif
#endif
```

Long-term, BASEPRI threshold policy belongs to the selected port, not to a
global target helper.

### PSPLIM Traits

```c
#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
```

`FIBER_PORT_HAS_PSPLIM` means the CPU/security state has a PSPLIM register
available.

`FIBER_PORT_USES_PSPLIM_REGISTER` means this selected port actively
writes/restores PSPLIM in its startup or switch policy.

`FIBER_PORT_HAS_PSPLIM_SLOT` means the saved context layout has a PSPLIM slot.

A port must not set `FIBER_PORT_USES_PSPLIM_REGISTER` unless
`FIBER_PORT_HAS_PSPLIM` is also true.

A port that writes PSPLIM must also define where the per-context PSPLIM value
comes from. A production v8-M port may use a software-frame slot, like
FreeRTOS. A fixed-stack fiber port may use a sealed `FiberBoot` stack-limit
source instead. The chosen source must be explicit in the selected port
documentation before runtime support is claimed.

### ARMv8-M and Security Traits

All selected ports must define these traits, even when they are zero:

```c
#define FIBER_PORT_IS_V8M 0
#define FIBER_PORT_HAS_SECURITY_EXT 0
#define FIBER_PORT_RUNS_NONSECURE 0
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0
```

For ARMv7-M and ARMv7E-M ports, these are normally zero.

For future ARMv8-M ports, these traits must describe the actual context policy,
not just the compiler architecture.

Security extension presence, runtime domain, and target bank policy are separate
facts:

```text
FIBER_PORT_HAS_SECURITY_EXT: CPU/project exposes the security extension.
FIBER_PORT_RUNS_NONSECURE: this runtime executes as Non-secure code.
FIBER_PORT_TARGETS_NS_BANK: Secure code targets the Non-secure register bank.
```

Do not define `FIBER_PORT_HAS_SECURITY_EXT` as a synonym for
`FIBER_PORT_RUNS_NONSECURE`.

When a port needs to derive `FIBER_PORT_TARGETS_NS_BANK`, do not hide
`defined()` inside a macro body. Use preprocessor branching:

```c
#ifndef FIBER_PORT_TARGETS_NS_BANK
# if defined(FIBER_TZ_NS) && (FIBER_TZ_NS + 0)
#  define FIBER_PORT_TARGETS_NS_BANK 1
# else
#  define FIBER_PORT_TARGETS_NS_BANK 0
# endif
#endif
```

### M7 Errata Traits

Do not represent Cortex-M7 r0p0/r0p1 errata policy as a single ambiguous
boolean.

Use separate support and enable traits:

```c
#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 1
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0
```

`FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND` means the selected port has an
implementation path that can use the workaround.

`FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND` means the workaround is enabled
for this build.

Runtime CPUID validation for affected Cortex-M7 r0p0/r0p1 cores must check the
enabled trait, not only the support trait.

### Frame Layout Traits

Frame layout traits must be macros:

```c
#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES \
    (FIBER_PORT_HAS_EXTENDED_FP_CONTEXT ? (18u * 4u) : 0u)
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
    (FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES)

#define FIBER_PORT_SOFTWARE_FRAME_WORDS 9u
#define FIBER_PORT_SOFTWARE_FRAME_BYTES (FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX 8u
```

These values define the hardware exception-frame headroom and saved software
frame expected by:

```text
fiber_port_init_context_frame()
fiber_svc()
fiber_pendsv()
fiber_internal_validate_restore_context()
fiber_init()
fiber_boot_prepare_msp_for_start()
```

The selected port is the source of truth. The common core may expose legacy
aliases such as `FIBER_EXC_BASE_BYTES`, but it must not derive these values
directly from architecture macros.

## Trait Validation Header

The contract validation header is:

```text
fiber/port/fiber_port_traits.h
```

It must validate that required traits exist and are internally consistent.

Recommended structure:

```c
#ifndef FIBER_PORT_FIBER_PORT_TRAITS_H_
#define FIBER_PORT_FIBER_PORT_TRAITS_H_

#ifndef FIBER_PORT_NAME
# error "[fiber]: selected port must define FIBER_PORT_NAME"
#endif

#ifndef FIBER_PORT_HAS_BASEPRI
# error "[fiber]: selected port must define FIBER_PORT_HAS_BASEPRI"
#endif

#ifndef FIBER_PORT_HAS_FAULTMASK
# error "[fiber]: selected port must define FIBER_PORT_HAS_FAULTMASK"
#endif

#ifndef FIBER_PORT_HAS_VTOR
# error "[fiber]: selected port must define FIBER_PORT_HAS_VTOR"
#endif

#ifndef FIBER_PORT_HAS_PSPLIM
# error "[fiber]: selected port must define FIBER_PORT_HAS_PSPLIM"
#endif

#ifndef FIBER_PORT_HAS_FPU
# error "[fiber]: selected port must define FIBER_PORT_HAS_FPU"
#endif

#ifndef FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
# error "[fiber]: selected port must define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT"
#endif

#ifndef FIBER_PORT_BOOT_CLEARS_FPCA
# error "[fiber]: selected port must define FIBER_PORT_BOOT_CLEARS_FPCA"
#endif

#ifndef FIBER_PORT_HAS_MVE
# error "[fiber]: selected port must define FIBER_PORT_HAS_MVE"
#endif

#ifndef FIBER_PORT_HAS_PAC
# error "[fiber]: selected port must define FIBER_PORT_HAS_PAC"
#endif

#ifndef FIBER_PORT_HAS_BTI
# error "[fiber]: selected port must define FIBER_PORT_HAS_BTI"
#endif

#ifndef FIBER_PORT_USES_PSPLIM_REGISTER
# error "[fiber]: selected port must define FIBER_PORT_USES_PSPLIM_REGISTER"
#endif

#ifndef FIBER_PORT_INITIAL_EXC_RETURN
# error "[fiber]: selected port must define FIBER_PORT_INITIAL_EXC_RETURN"
#endif

#ifndef FIBER_PORT_SCHEDULER_MASK_KIND
# error "[fiber]: selected port must define FIBER_PORT_SCHEDULER_MASK_KIND"
#endif

#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
# ifndef FIBER_PORT_SCHEDULER_BASEPRI
#  error "[fiber]: BASEPRI scheduler ports must define FIBER_PORT_SCHEDULER_BASEPRI"
# endif
FIBER_STATIC_ASSERT(FIBER_PORT_SCHEDULER_BASEPRI != 0u,
                 "[fiber]: scheduler BASEPRI threshold must be non-zero");
FIBER_STATIC_ASSERT(FIBER_PORT_SCHEDULER_BASEPRI <= 255u,
                 "[fiber]: scheduler BASEPRI threshold must fit in 8 bits");
#endif

#ifndef FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND
# error "[fiber]: selected port must define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND"
#endif

#ifndef FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND
# error "[fiber]: selected port must define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND"
#endif

#ifndef FIBER_PORT_IS_V8M
# error "[fiber]: selected port must define FIBER_PORT_IS_V8M"
#endif

#ifndef FIBER_PORT_HAS_SECURITY_EXT
# error "[fiber]: selected port must define FIBER_PORT_HAS_SECURITY_EXT"
#endif

#ifndef FIBER_PORT_RUNS_NONSECURE
# error "[fiber]: selected port must define FIBER_PORT_RUNS_NONSECURE"
#endif

#ifndef FIBER_PORT_TARGETS_NS_BANK
# error "[fiber]: selected port must define FIBER_PORT_TARGETS_NS_BANK"
#endif

#ifndef FIBER_PORT_HAS_CONTROL_SLOT
# error "[fiber]: selected port must define FIBER_PORT_HAS_CONTROL_SLOT"
#endif

#ifndef FIBER_PORT_HAS_PSPLIM_SLOT
# error "[fiber]: selected port must define FIBER_PORT_HAS_PSPLIM_SLOT"
#endif

#ifndef FIBER_PORT_HAS_SECURE_CONTEXT_SLOT
# error "[fiber]: selected port must define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT"
#endif

#ifndef FIBER_PORT_HAS_PAC_KEY_SLOT
# error "[fiber]: selected port must define FIBER_PORT_HAS_PAC_KEY_SLOT"
#endif

#ifndef FIBER_PORT_EXC_BASE_BYTES
# error "[fiber]: selected port must define FIBER_PORT_EXC_BASE_BYTES"
#endif

#ifndef FIBER_PORT_EXC_FP_EXT_BYTES
# error "[fiber]: selected port must define FIBER_PORT_EXC_FP_EXT_BYTES"
#endif

#ifndef FIBER_PORT_EXC_PER_LEVEL_BYTES
# error "[fiber]: selected port must define FIBER_PORT_EXC_PER_LEVEL_BYTES"
#endif

#ifndef FIBER_PORT_SOFTWARE_FRAME_WORDS
# error "[fiber]: selected port must define FIBER_PORT_SOFTWARE_FRAME_WORDS"
#endif

#ifndef FIBER_PORT_SOFTWARE_FRAME_BYTES
# error "[fiber]: selected port must define FIBER_PORT_SOFTWARE_FRAME_BYTES"
#endif

#ifndef FIBER_PORT_EXC_RETURN_WORD_INDEX
# error "[fiber]: selected port must define FIBER_PORT_EXC_RETURN_WORD_INDEX"
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_BASEPRI == 0) ||
                 (FIBER_PORT_HAS_BASEPRI == 1),
                 "[fiber]: FIBER_PORT_HAS_BASEPRI must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_FAULTMASK == 0) ||
                 (FIBER_PORT_HAS_FAULTMASK == 1),
                 "[fiber]: FIBER_PORT_HAS_FAULTMASK must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_VTOR == 0) ||
                 (FIBER_PORT_HAS_VTOR == 1),
                 "[fiber]: FIBER_PORT_HAS_VTOR must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_PSPLIM == 0) ||
                 (FIBER_PORT_HAS_PSPLIM == 1),
                 "[fiber]: FIBER_PORT_HAS_PSPLIM must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_FPU == 0) ||
                 (FIBER_PORT_HAS_FPU == 1),
                 "[fiber]: FIBER_PORT_HAS_FPU must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 0) ||
                 (FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 1),
                 "[fiber]: FIBER_PORT_HAS_EXTENDED_FP_CONTEXT must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_BOOT_CLEARS_FPCA == 0) ||
                 (FIBER_PORT_BOOT_CLEARS_FPCA == 1),
                 "[fiber]: FIBER_PORT_BOOT_CLEARS_FPCA must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_MVE == 0) ||
                 (FIBER_PORT_HAS_MVE == 1),
                 "[fiber]: FIBER_PORT_HAS_MVE must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_PAC == 0) ||
                 (FIBER_PORT_HAS_PAC == 1),
                 "[fiber]: FIBER_PORT_HAS_PAC must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_BTI == 0) ||
                 (FIBER_PORT_HAS_BTI == 1),
                 "[fiber]: FIBER_PORT_HAS_BTI must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_USES_PSPLIM_REGISTER == 0) ||
                 (FIBER_PORT_USES_PSPLIM_REGISTER == 1),
                 "[fiber]: FIBER_PORT_USES_PSPLIM_REGISTER must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND == 0) ||
                 (FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND == 1),
                 "[fiber]: M7 r0p1 workaround support trait must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND == 0) ||
                 (FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND == 1),
                 "[fiber]: M7 r0p1 workaround enable trait must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_IS_V8M == 0) ||
                 (FIBER_PORT_IS_V8M == 1),
                 "[fiber]: FIBER_PORT_IS_V8M must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_SECURITY_EXT == 0) ||
                 (FIBER_PORT_HAS_SECURITY_EXT == 1),
                 "[fiber]: FIBER_PORT_HAS_SECURITY_EXT must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_RUNS_NONSECURE == 0) ||
                 (FIBER_PORT_RUNS_NONSECURE == 1),
                 "[fiber]: FIBER_PORT_RUNS_NONSECURE must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_TARGETS_NS_BANK == 0) ||
                 (FIBER_PORT_TARGETS_NS_BANK == 1),
                 "[fiber]: FIBER_PORT_TARGETS_NS_BANK must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_CONTROL_SLOT == 0) ||
                 (FIBER_PORT_HAS_CONTROL_SLOT == 1),
                 "[fiber]: FIBER_PORT_HAS_CONTROL_SLOT must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_PSPLIM_SLOT == 0) ||
                 (FIBER_PORT_HAS_PSPLIM_SLOT == 1),
                 "[fiber]: FIBER_PORT_HAS_PSPLIM_SLOT must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 0) ||
                 (FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 1),
                 "[fiber]: FIBER_PORT_HAS_SECURE_CONTEXT_SLOT must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_PAC_KEY_SLOT == 0) ||
                 (FIBER_PORT_HAS_PAC_KEY_SLOT == 1),
                 "[fiber]: FIBER_PORT_HAS_PAC_KEY_SLOT must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_USES_PSPLIM_REGISTER == 0) ||
                 (FIBER_PORT_HAS_PSPLIM == 1),
                 "[fiber]: PSPLIM register use requires PSPLIM support");

FIBER_STATIC_ASSERT((FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 0) ||
                 (FIBER_PORT_HAS_FPU == 1),
                 "[fiber]: extended FP context requires FPU support");

FIBER_STATIC_ASSERT((FIBER_PORT_BOOT_CLEARS_FPCA == 0) ||
                 (FIBER_PORT_HAS_FPU == 1),
                 "[fiber]: FPCA clearing requires FPU support");

FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_PRIMASK) ||
                 (FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI),
                 "[fiber]: invalid scheduler mask kind");

FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_MASK_KIND != FIBER_PORT_MASK_BASEPRI) ||
                 (FIBER_PORT_HAS_BASEPRI == 1),
                 "[fiber]: BASEPRI scheduler mask requires BASEPRI support");

FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_MASK_KIND != FIBER_PORT_MASK_PRIMASK) ||
                 (FIBER_PORT_HAS_BASEPRI == 0),
                 "[fiber]: PRIMASK scheduler mask is expected only on ports without BASEPRI");

FIBER_STATIC_ASSERT((FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND == 0) ||
                 (FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND == 1),
                 "[fiber]: M7 r0p1 workaround cannot be enabled unless the port supports it");

FIBER_STATIC_ASSERT((FIBER_PORT_EXC_BASE_BYTES % 8u) == 0u,
                 "[fiber]: port base exception frame must be 8-byte aligned");

FIBER_STATIC_ASSERT((FIBER_PORT_EXC_FP_EXT_BYTES % 8u) == 0u,
                 "[fiber]: port extended FP exception frame must be 8-byte aligned");

FIBER_STATIC_ASSERT(FIBER_PORT_EXC_PER_LEVEL_BYTES ==
                 (FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES),
                 "[fiber]: port per-level exception frame size mismatch");

FIBER_STATIC_ASSERT((FIBER_PORT_EXC_PER_LEVEL_BYTES % 8u) == 0u,
                 "[fiber]: port per-level exception headroom must be 8-byte aligned");

FIBER_STATIC_ASSERT((FIBER_PORT_SOFTWARE_FRAME_BYTES ==
                 (FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)),
                 "[fiber]: software frame words/bytes mismatch");

FIBER_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX < FIBER_PORT_SOFTWARE_FRAME_WORDS,
                 "[fiber]: EXC_RETURN index must point inside software frame");

#endif
```

## Legacy Alias Policy

During migration, old global macros may remain.

The long-term direction must be:

```text
selected port trait -> legacy macro alias
```

Not:

```text
global target macro -> selected port behavior
```

Allowed long-term alias direction:

```c
#ifndef FIBER_HAS_BASEPRI
# define FIBER_HAS_BASEPRI FIBER_PORT_HAS_BASEPRI
#endif

#ifndef FIBER_HAS_PSPLIM
# define FIBER_HAS_PSPLIM FIBER_PORT_HAS_PSPLIM
#endif

#ifndef FIBER_USE_PSPLIM_REGISTER
# define FIBER_USE_PSPLIM_REGISTER FIBER_PORT_USES_PSPLIM_REGISTER
#endif

#ifndef FIBER_HAS_FPU
# define FIBER_HAS_FPU FIBER_PORT_HAS_FPU
#endif

#ifndef FIBER_HAS_EXTENDED_FP_CONTEXT
# define FIBER_HAS_EXTENDED_FP_CONTEXT FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
#endif

#ifndef FIBER_BOOT_CLEAR_FPCA
# define FIBER_BOOT_CLEAR_FPCA FIBER_PORT_BOOT_CLEARS_FPCA
#endif

#ifndef FIBER_INITIAL_EXC_RETURN
# define FIBER_INITIAL_EXC_RETURN FIBER_PORT_INITIAL_EXC_RETURN
#endif

#ifndef FIBER_CORTEX_M7_R0P1_ERRATA_837070
# define FIBER_CORTEX_M7_R0P1_ERRATA_837070 \
         FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND
#endif
```

Common runtime code must consume `FIBER_PORT_HAS_FAULTMASK` directly. The
selector must not infer FAULTMASK support and must not export a legacy
`FIBER_HAS_FAULTMASK` alias; the selected port is the single source of truth.
Defining the obsolete alias is a compile-time error so a stale integration
setting cannot be silently ignored.

### Transitional Exception

During Step 1, any selected port may mirror old global macros to define
`FIBER_PORT_*` traits.

This is allowed only when explicitly marked:

```c
#define FIBER_PORT_TRAITS_LEGACY_BRIDGE 1
```

Example transitional bridge:

```c
#define FIBER_PORT_HAS_FPU FIBER_HAS_FPU
#define FIBER_PORT_HAS_PSPLIM FIBER_HAS_PSPLIM
#define FIBER_PORT_USES_PSPLIM_REGISTER FIBER_USE_PSPLIM_REGISTER
```

This is temporary and must not become the final ownership direction.
It must be removed when ownership is inverted and legacy macros consume
selected-port traits.

A file must not create a macro cycle where:

```text
FIBER_PORT_HAS_PSPLIM -> FIBER_HAS_PSPLIM
FIBER_HAS_PSPLIM -> FIBER_PORT_HAS_PSPLIM
```

in the same migration phase.

## Current Port Trait Map

### ARMv6-M

Applies to Cortex-M0/M0+ style ports.

```c
#define FIBER_PORT_NAME "armv6m"

#define FIBER_PORT_HAS_BASEPRI 0
#define FIBER_PORT_HAS_FAULTMASK 0
#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_HAS_FPU 0
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#define FIBER_PORT_BOOT_CLEARS_FPCA 0
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0

#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN 0xFFFFFFFDu
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_PRIMASK

#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0

#define FIBER_PORT_IS_V8M 0
#define FIBER_PORT_HAS_SECURITY_EXT 0
#define FIBER_PORT_RUNS_NONSECURE 0
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0
```

ARMv6-M VTOR support must be derived carefully inside the ARMv6-M selected
port, not globally:

```c
#ifndef FIBER_PORT_HAS_VTOR
# if defined(SCB_VTOR_TBLOFF_Msk) || \
     (defined(__VTOR_PRESENT) && ((__VTOR_PRESENT + 0) != 0))
#  define FIBER_PORT_HAS_VTOR 1
# else
#  define FIBER_PORT_HAS_VTOR 0
# endif
#endif
```

### ARMv7-M

Applies to Cortex-M3 style ports.

```c
#define FIBER_PORT_NAME "armv7m"

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1
#define FIBER_PORT_HAS_VTOR 1
#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_HAS_FPU 0
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#define FIBER_PORT_BOOT_CLEARS_FPCA 0
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0

#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN 0xFFFFFFFDu
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_BASEPRI
#define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI

#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0

#define FIBER_PORT_IS_V8M 0
#define FIBER_PORT_HAS_SECURITY_EXT 0
#define FIBER_PORT_RUNS_NONSECURE 0
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0
```

### ARMv7E-M

Applies to Cortex-M4/M4F/M7/M7F style ports.

```c
#define FIBER_PORT_NAME "armv7em"

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1
#define FIBER_PORT_HAS_VTOR 1
#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0

#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN 0xFFFFFFFDu
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_BASEPRI
#define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI

#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 1

#define FIBER_PORT_IS_V8M 0
#define FIBER_PORT_HAS_SECURITY_EXT 0
#define FIBER_PORT_RUNS_NONSECURE 0
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0
```

During migration, ARMv7E-M may derive FPU traits from the existing FPU detection
helper:

```c
#define FIBER_PORT_TRAITS_LEGACY_BRIDGE 1
#define FIBER_PORT_HAS_FPU FIBER_HAS_FPU
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT FIBER_HAS_FPU
#define FIBER_PORT_BOOT_CLEARS_FPCA FIBER_BOOT_CLEAR_FPCA
```

During migration, M7 errata enablement may mirror the existing build macro:

```c
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND \
        FIBER_CORTEX_M7_R0P1_ERRATA_837070
```

Long-term, affected Cortex-M7 r0p0/r0p1 may become a separate selected profile:

```text
armv7em_m7_r0p1
```

### Transitional v8-M

The transitional v8-M port is not a production support claim.

It may temporarily use `FIBER_PORT_TRAITS_LEGACY_BRIDGE=1` while old global
v8-M feature policy is being removed.

Minimum traits:

```c
#define FIBER_PORT_NAME "transitional_v8m"
#define FIBER_PORT_TRAITS_LEGACY_BRIDGE 1

#define FIBER_PORT_IS_V8M 1

#define FIBER_PORT_HAS_BASEPRI (!FIBER_PORT_IS_BASELINE)
#define FIBER_PORT_HAS_FAULTMASK (!FIBER_PORT_IS_BASELINE)

#define FIBER_PORT_HAS_PSPLIM FIBER_HAS_PSPLIM
#define FIBER_PORT_USES_PSPLIM_REGISTER FIBER_USE_PSPLIM_REGISTER
#define FIBER_PORT_HAS_FPU FIBER_HAS_FPU
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT FIBER_HAS_EXTENDED_FP_CONTEXT
#define FIBER_PORT_BOOT_CLEARS_FPCA FIBER_BOOT_CLEAR_FPCA
#define FIBER_PORT_HAS_MVE FIBER_HAS_MVE
#define FIBER_PORT_HAS_PAC FIBER_HAS_PAC
#define FIBER_PORT_HAS_BTI FIBER_HAS_BTI

#define FIBER_PORT_INITIAL_EXC_RETURN FIBER_INITIAL_EXC_RETURN

#define FIBER_PORT_SCHEDULER_MASK_KIND \
    (FIBER_PORT_IS_BASELINE ? FIBER_PORT_MASK_PRIMASK : FIBER_PORT_MASK_BASEPRI)

#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
# define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI
#endif

#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0
```

`FIBER_PORT_HAS_VTOR` must not default to `1` for every transitional v8-M
profile. ARMv8-M Mainline has VTOR, while Baseline/M23 policy must be explicit
or derived inside the selected v8-M bridge:

```c
#ifndef FIBER_PORT_HAS_VTOR
# if FIBER_PORT_IS_MAINLINE
#  define FIBER_PORT_HAS_VTOR 1
# elif defined(SCB_VTOR_TBLOFF_Msk) || \
       (defined(__VTOR_PRESENT) && ((__VTOR_PRESENT + 0) != 0))
#  define FIBER_PORT_HAS_VTOR 1
# else
#  define FIBER_PORT_HAS_VTOR 0
# endif
#endif
```

Security/context traits must be explicit, even if transitional:

```c
#ifndef FIBER_PORT_HAS_SECURITY_EXT
# if defined(__ARM_FEATURE_CMSE) && ((__ARM_FEATURE_CMSE + 0) >= 3)
#  define FIBER_PORT_HAS_SECURITY_EXT 1
# else
#  define FIBER_PORT_HAS_SECURITY_EXT 0
# endif
#endif

#define FIBER_PORT_RUNS_NONSECURE FIBER_RUN_NONSECURE

#ifndef FIBER_PORT_TARGETS_NS_BANK
# if defined(FIBER_TZ_NS) && (FIBER_TZ_NS + 0)
#  define FIBER_PORT_TARGETS_NS_BANK 1
# else
#  define FIBER_PORT_TARGETS_NS_BANK 0
# endif
#endif

#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0
```

The zero slot traits are intentional. They state that the transitional
implementation does not yet own full FreeRTOS-level ARMv8-M security/context
state.

## Future Production v8-M Ports

The transitional v8-M port must eventually split into real selected ports:

```text
armv8m_baseline
armv8m_mainline
armv81m_mainline
armv8m_shared
```

### ARMv8-M Baseline

Applies to Cortex-M23 class ports.

Expected traits:

```text
PRIMASK scheduler bridge
no BASEPRI
TrustZone policy explicit
PSPLIM/security policy explicit
not mixed with ARMv6-M
```

### ARMv8-M Mainline

Applies to Cortex-M33/M35P class ports.

Expected traits:

```text
BASEPRI scheduler bridge
PSPLIM policy owned by port
CONTROL/EXC_RETURN security policy owned by port
TrustZone bank policy owned by port
```

### ARMv8.1-M Mainline

Applies to Cortex-M55/M85/N6 class ports.

Expected traits:

```text
BASEPRI scheduler bridge
PSPLIM/security policy owned by port
MVE policy owned by port
PAC/BTI policy owned by port
extended context state explicit
```

These ports must not be treated as "almost M33". They require their own context
policy.

## Common Helper Migration Targets

### BASEPRI

BASEPRI is selected-port-private. Do not create a root helper that hides CPU
policy behind common macros.

Each selected port must provide:

```text
FIBER_PORT_HAS_BASEPRI
FIBER_PORT_SCHEDULER_BASEPRI when BASEPRI is used
FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND when applicable
fiber_port_basepri_read()
fiber_port_basepri_write()
port-local naked-asm scheduler critical-section snippets
```

The synchronized BASEPRI ASM snippets use `r12` as scratch on the M7 r0p1
errata path. Any naked port assembly that expands those snippets must treat
`r12` as clobbered.

### VTOR and Vectors

VTOR and vector-table helpers are selected-port-owned. They must not live in a
global target helper because VTOR availability and security-bank selection are
CPU/profile-specific.

The selected port must own:

```text
FIBER_PORT_HAS_VTOR
vector bank policy
direct-vector policy
SVC/PendSV wiring expectations
```

The selected port must expose:

```c
uintptr_t fiber_port_vectors_base_addr(void);
const uint32_t *fiber_port_vectors_base_ptr(void);
uint32_t fiber_port_read_initial_msp(void);
void fiber_port_set_vectors_base_addr(uintptr_t base);
```

Ports without VTOR must return the architectural fallback base `0x00000000`
from `fiber_port_vectors_base_addr()` and ignore vector-base writes.

Common vector helpers may validate vector entries, but only according to
selected-port traits.

### Exception Setup

Moved from:

```text
fiber/target/fiber_irq.c/.h
```

to each selected port source group:

```text
fiber/port/<profile>/fiber_port_exception.c
```

Common exception setup may provide:

```text
PendSV priority setup
SVCall priority setup
vector entry validation
BASEPRI priority mask probing
AIRCR.PRIGROUP validation
M7 r0p1 CPUID validation
pending PendSV cleanup
```

But rules must come from selected-port traits.

`fiber_port_exception.c` is selected-port implementation code. Its active
implementation must enter through the selected `fiber_portmacro.h`; it must not
pull `fiber_target.h`, compiler helpers, panic/require headers, or FPU/PSPLIM/
VTOR helpers directly. Those are part of the selected port contract. A
transitional v8-M port may include the root feature-policy defaults after
including its selected `fiber_portmacro.h`, until concrete v8-M ports replace
it.

The public facade may remain:

```c
void fiber_pendsv_init_lowest_priority(void);
void fiber_exception_runtime_check(void);
```

The implementation is selected-port code. There is no shared root
`fiber/port/fiber_port_exception.*` implementation.

### PSPLIM

PSPLIM register helpers are selected-port-owned. They must not live in a
global target helper because register availability, security bank selection,
and context-slot ownership are port-specific.

The selected v8-M port must own:

```text
FIBER_PORT_HAS_PSPLIM
FIBER_PORT_USES_PSPLIM_REGISTER
FIBER_PORT_HAS_PSPLIM_SLOT
per-context PSPLIM restore source
PSPLIM bank/security policy
whether PSPLIM is part of saved/restored context
```

The selected port must expose:

```c
uint32_t fiber_port_psplim_read(void);
void fiber_port_psplim_write(uint32_t limit);
void fiber_port_psplim_config(uint32_t stack_low_addr);
```

and the port-asm restore macro:

```c
FBR_ASM_MSR_PSPLIM(reg)
```

Ports without PSPLIM must still provide explicit disabled/no-op definitions so
common runtime code never needs to know which CPU class is active.

### FPU

FPU policy and early FPU enable are selected-port-owned.

The root `fiber_fpu.h` / `fiber_fpu.c` files are removed. Common runtime code
calls:

```c
void fiber_port_fpu_enable_early(void);
```

The selected port decides whether that function is a no-op or programs
CPACR/FPCCR and TrustZone FP access registers.

The selected port must own:

```text
FIBER_PORT_TOOLCHAIN_HAS_FP
FIBER_PORT_SILICON_HAS_FPU
FIBER_PORT_CMSIS_FPU_USED
FIBER_PORT_HAS_FPU
FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
FIBER_PORT_BOOT_CLEARS_FPCA
fiber_port_fpu_enable_early()
whether high FP context is saved/restored
whether lazy stacking is allowed
whether MVE changes context requirements
```

Toolchain/silicon detection may be duplicated per selected port. Hidden common
macro policy is not preferred here; an explicit selected-port decision is easier
to audit against the matching FreeRTOS port.

### Feature Policy

The global file:

```text
fiber/port/fiber_feature_policy.h
```

must disappear long-term.

Its contents should split into:

```text
selected-port traits
v8-M common policy
transitional_v8m runtime gates
production v8-M port policies
```

Unsupported features must fail through selected-port validation, not global
guessing.

## Migration Order

### Step 1: Add selected port trait contract

Commit name:

```text
Add selected port trait contract
```

Scope:

```text
add V2_PORT_TRAITS_CONTRACT.md
add fiber_port_traits.h
add FIBER_PORT_* traits to existing selected port headers
convert required frame traits from enum constants to macros
validate traits
do not move target files
do not change asm
do not change runtime behavior
```

Required checks:

```text
tools/compile_matrix.ps1 PASS
H7 Debug build PASS
git diff --check PASS
ASCII-only PASS
```

### Step 2: Make legacy feature macros consume port traits

Commit name:

```text
Map legacy feature macros to port traits
```

Scope:

```text
define FIBER_HAS_BASEPRI from FIBER_PORT_HAS_BASEPRI
define FIBER_HAS_PSPLIM from FIBER_PORT_HAS_PSPLIM
define FIBER_USE_PSPLIM_REGISTER from FIBER_PORT_USES_PSPLIM_REGISTER
define FIBER_HAS_FPU from FIBER_PORT_HAS_FPU
define FIBER_HAS_EXTENDED_FP_CONTEXT from FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
define FIBER_BOOT_CLEAR_FPCA from FIBER_PORT_BOOT_CLEARS_FPCA
define FIBER_INITIAL_EXC_RETURN from FIBER_PORT_INITIAL_EXC_RETURN
keep user overrides where explicitly supported
avoid macro cycles
```

No runtime behavior should change.

### Step 3: Move BASEPRI helpers into selected ports

Commit name:

```text
Move BASEPRI policy into selected ports
```

Scope:

```text
delete fiber/target/fiber_basepri.h
move BASEPRI read/write helpers into selected port headers
move BASEPRI/PRIMASK naked-asm scheduler snippets into selected port headers
common code uses fiber_port_basepri_read/write only
exception validation consumes FIBER_PORT_SCHEDULER_BASEPRI
```

No runtime behavior should change.

### Step 4: Move vector helpers into port root helpers

Commit name:

```text
Move vector helpers into selected ports
```

Scope:

```text
fiber_vtor.h removed
selected ports expose fiber_port_vectors_* helpers
common vector entry validation consumes port traits
selected port owns VTOR/vector policy
```

No runtime behavior should change.

### Step 5: Move exception setup into port root helpers

Commit name:

```text
Move exception setup into selected ports
```

Scope:

```text
fiber_irq.c/h -> per-port fiber_port_exception.c
priority/vector validation consumes port traits
feature/runtime validation stops living in target
```

This touches startup validation. At minimum, run H7 normal runtime after this
step.

### Step 6: Move PSPLIM/FPU/security policy out of target

Commit names:

```text
Move PSPLIM policy into v8-M port layer
Move FPU policy into selected ports
Move v8-M feature gates into transitional policy
```

These must be separate commits.

### Step 7: Split transitional v8-M into real ports

Commit names:

```text
Add ARMv8-M Baseline selected port
Add ARMv8-M Mainline selected port
Add ARMv8.1-M Mainline selected port
```

These are compile-coverage steps first. Runtime support requires hardware
validation per profile.

## Validation Policy

Compile coverage is not runtime support.

A selected port may be described as compile-covered when:

```text
compile matrix passes for its profile
wrapper vector mode compiles
direct vector mode compiles
relevant feature-gated variants compile
```

A selected port may be described as runtime-supported only when:

```text
hardware validation exists
normal long run passes
trap modes pass
SVC/PendSV wiring is validated
scheduler result validation is tested
interrupt-mask trap behavior is tested
FPU/PSPLIM/security policy is tested when applicable
```

For ARMv7E-M/H7, after any change touching:

```text
SVC first-start
PendSV save/restore
scheduler critical section
BASEPRI/PRIMASK behavior
exception setup
vector validation
context frame layout
restore-context validation
```

the H7 runtime validation label must be downgraded until hardware tests pass
again.

## H7 Validation Set

For current ARMv7E-M/H7 runtime support, the required validation modes are:

```text
NORMAL_RUN
NO_HOOK      -> K
NULL_HOOK    -> K
HOT_SWAP     -> k
NULL_FIRST   -> N
BAD_FIRST    -> P
NULL_NEXT    -> N
BAD_NEXT     -> P
PRIMASK      -> p
BASEPRI      -> b
FAULTMASK    -> f
```

Normal run pass criteria:

```text
validation_flags == 0x000001FF
validation_failures == 0
last_panic_code == 0
counter1/counter2/counter3 progress
fiber_current() matches the running fiber
FP accumulator relationship remains valid when FP test is enabled
```

## Documentation Rules

Every behavior-changing port commit must update:

```text
DECISIONS.md
V2_PORT_CONTRACT.md or this document
H7_RUNTIME_VALIDATION.md when runtime label changes
FREERTOS_SUPPORT_PLAN.md when FreeRTOS comparison changes
README.md only if user-facing behavior changes
```

Every compile-only support expansion must clearly say:

```text
compile-covered only
not runtime-supported
hardware validation required
```

Every transitional implementation must clearly say:

```text
transitional
not production support
not FreeRTOS-level parity
must be split before support claim
```

## Design Rule Summary

Selected port is the source of CPU truth.

port helper code consumes selected-port traits.

Target code does not decide CPU capability.

Core code does not know CPU mechanics.

Required traits are preprocessor macros, not enum-only constants.

Transitional legacy bridges must be marked and removed.

Compile matrix does not replace hardware validation.

A port cannot be FreeRTOS-level while it depends on hidden global feature
guessing.
