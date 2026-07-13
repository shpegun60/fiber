# Fiber

Small cooperative fiber switcher for STM32/Cortex-M projects.

The context switch is requested from Thread mode with `fiber_schedule()` and is
performed by PendSV through an application-provided scheduler hook. The
application must wire `PendSV_Handler()` so it branches to `fiber_pendsv()`
without clobbering LR/EXC_RETURN. The active v2 runtime start is FreeRTOS-like:
`fiber_start()` enters the first context through SVC and an exception return, so
the application must also wire `SVC_Handler()` to branch to `fiber_svc()`.

## Architecture Direction

The five-function cooperative API is intended to remain stable while CPU
context storage is selected-port-owned. `fiber_core.h` completes `FiberContext`
through one selected public type-only port header, and `FiberEntryFn` is the
named entry type with `entry_t` kept as a compatible alias. Each current port
owns its `FiberPortBoot` record, hash implementation, stack geometry, restore
validation, and first-start preparation. The current physical layout remains
`sp + FiberPortBoot` for compatibility, but `fiber_core.c` and the common
scheduler bridge use only callable port ABI functions and do not dereference
that layout. A future port may therefore change its boot record or use a
hardware-backed integrity implementation without changing the common core.
See `V2_OPAQUE_CONTEXT_CONTRACT.md` for the frozen boundary and migration
sequence.

## Project Setup

Add the repository root to the include path, then include the public API:

```c
#include "fiber/fiber_core.h"
```

Compile the common runtime sources into the application:

```text
fiber/fiber_core.c
fiber/fiber_stack.c
fiber/fiber_runtime_state.c
fiber/fiber_panic.c
```

Then compile exactly one matching port source pair:

```text
Cortex-M0/M0+: fiber/port/armv6m/fiber_port_armv6m.c
               fiber/port/armv6m/fiber_port_boot.c
               fiber/port/armv6m/fiber_port_exception.c
Cortex-M3:     fiber/port/armv7m/fiber_port_armv7m.c
               fiber/port/armv7m/fiber_port_boot.c
               fiber/port/armv7m/fiber_port_exception.c
Cortex-M4/F:   fiber/port/armv7em/fiber_port_armv7em.c
               fiber/port/armv7em/fiber_port_boot.c
               fiber/port/armv7em/fiber_port_exception.c
Cortex-M7/F:   fiber/port/ARM_CM7/r0p1/fiber_port.c
               fiber/port/ARM_CM7/r0p1/fiber_port_boot.c
               fiber/port/ARM_CM7/r0p1/fiber_port_exception.c
v8-M bring-up: fiber/port/transitional_v8m/fiber_port_transitional_v8m.c
               fiber/port/transitional_v8m/fiber_port_boot.c
               fiber/port/transitional_v8m/fiber_port_exception.c
```

Do not add every port source directory to a production target. The compile
matrix deliberately compiles selector-guarded alternatives to audit selection,
then relocatably links the result to prove a single complete port ABI.

The port header boundary is split in two layers: `fiber/port/fiber_port_select.h`
only selects the Cortex-M profile, while `fiber/port/fiber_port_selected.h`
includes the concrete selected `fiber_portmacro.h` interface and its
port-owned frame traits. Public runtime code should use `fiber/fiber_core.h`;
exception wiring or low-level port integration should include the selected
port-specific header or `fiber/port/fiber_port_selected.h`.
The v2 target is FreeRTOS-style ownership: each concrete `arm*` port exports
the complete CPU interface for frame setup, first start, PendSV/SVC handlers,
exception setup, FPU traits, and architecture-specific critical-section policy.
Common runtime files should not keep architecture-specific fallback switch
assembly or CPU capability decisions for ports that are claimed as supported.
Configuration ownership, selected-port integration values, and global fault
policy from `fiber/fiber_platform_policy.h` are documented in
`FIBER_SETTINGS.md`.

Port selection defaults to automatic detection from compiler ARM architecture
macros. Production builds may select the profile explicitly, for example:

```c
#define FIBER_PORT_PROFILE FIBER_PORT_PROFILE_ARMV7EM
```

The selectable profile names are `FIBER_PORT_PROFILE_ARMV6M`,
`FIBER_PORT_PROFILE_ARMV7M`, `FIBER_PORT_PROFILE_ARMV7EM`,
`FIBER_PORT_PROFILE_ARMV8M_BASELINE`, `FIBER_PORT_PROFILE_ARMV8M_MAINLINE`, and
`FIBER_PORT_PROFILE_ARMV81M_MAINLINE`. Leave `FIBER_PORT_PROFILE` undefined for
auto-detection. When compiler ARM architecture macros are available, an
explicit profile must match them. `FIBER_PORT_SELECTION_ALLOW_MISMATCH` is only
for unusual toolchains or bring-up experiments where the compiler macros are
missing or known to be wrong. After the direct trampoline removal, every
selected profile must provide an SVC first-start symbol. STM32H7/Cortex-M7 is
the primary hardware-observed path and now builds through the concrete
`ARM_CM7/r0p1` source group. The current hardening changes still require the
documented board rerun; every other profile remains compile/link-covered only
until its own hardware validation is recorded.

`fiber_start()` initializes and validates PendSV/SVCall priority automatically.
The current transitional selected-port integration also exposes the idempotent
diagnostic below for early bring-up checks. It is not part of the frozen
five-function cooperative API and will be replaced by the internal selected-port
runtime prepare/validate boundary. A direct transitional call requires
privileged Thread mode on MSP with PRIMASK, BASEPRI, and FAULTMASK clear:

```c
fiber_pendsv_init_lowest_priority();
```

## Basic Example

```c
#include "app_core.h"
#include "main.h"

#include "fiber/fiber_core.h"

enum { STACK_SZ = 1024 };

__attribute__((aligned(8))) static uint8_t stack1[STACK_SZ];
__attribute__((aligned(8))) static uint8_t stack2[STACK_SZ];
__attribute__((aligned(8))) static uint8_t stack3[STACK_SZ];

static FiberContext f1;
static FiberContext f2;
static FiberContext f3;

static uint32_t counter1 = 0;
static uint32_t counter2 = 0;
static uint32_t counter3 = 0;

static FIBER_SCHEDULER_HOOK_ATTR
FiberContext *pick_next(FiberContext *current, void *)
{
	if (current == NULL) {
		return &f1;
	}

	if (current == &f1) {
		return &f2;
	}

	if (current == &f2) {
		return &f3;
	}

	if (current == &f3) {
		return &f1;
	}

	return &f1;
}

void fiber1_entry(void*)
{
	for (;;) {
		counter1++;
		fiber_schedule();
	}
}

void fiber2_entry(void*)
{
	for (;;) {
		counter2++;
		fiber_schedule();
	}
}

void fiber3_entry(void*)
{
	for (;;) {
		counter3++;
		fiber_schedule();
	}
}

void app_main(void)
{
	fiber_init(&f1, stack1, stack1 + sizeof(stack1), fiber1_entry, (void*)1);
	fiber_init(&f2, stack2, stack2 + sizeof(stack2), fiber2_entry, (void*)2);
	fiber_init(&f3, stack3, stack3 + sizeof(stack3), fiber3_entry, (void*)3);

	fiber_scheduler_set_pick_next(pick_next, NULL);

	fiber_start();

	for (;;) {
	}
}
```

`fiber_scheduler_set_pick_next()` must be called from Thread mode before
`fiber_start()`. A `NULL` hook traps with `'K'`; changing the hook after the
runtime-owned current context is seeded traps with `'k'`. `fiber_start()`
requires a configured hook and calls it once with `current == NULL`; the hook
must return the first initialized `FiberContext`. A missing hook traps with
`'K'`, and a `NULL` first context traps with `'N'`.

The scheduler callback is part of the exception-handler ABI. Define every hook
with `FIBER_SCHEDULER_HOOK_ATTR`. The first call runs from Thread mode before
SVC; later calls run from PendSV on MSP. A hook must not execute floating-point,
MVE, or other extended-context instructions, because the indirect function
pointer cannot make GCC propagate `general-regs-only` automatically. The hook
must also remain bounded, non-blocking, non-allocating, non-throwing, and must
not call `fiber_schedule()` recursively. It may use a critical section only if
it restores `PRIMASK`, `FAULTMASK`, `BASEPRI`, and `CONTROL` exactly before
returning; the runtime snapshots and validates those registers around every
first and PendSV scheduler call. The same restrictions apply to every function
reachable from the hook, not only to the top-level thunk.

`fiber_start()` first verifies privileged Thread mode on MSP, then configures
and validates PendSV/SVCall,
asks the scheduler for the first context, validates it, seeds the runtime-owned
current context, prepares the platform, and does not return. The first scheduler
hook call is protected with
the same port scheduler critical-section policy as PendSV: BASEPRI on
BASEPRI-capable ports, or saved PRIMASK on baseline ports. `fiber_start()`
resets the first-start CPU state to privileged Thread/MSP, optionally rewinds
MSP, executes
`svc #FIBER_SVC_START_NUMBER`, and the SVC handler enters the first fiber by
exception return on PSP. The helper clears any pending PendSV immediately before
enabling interrupts for SVC, so a stale scheduler exception cannot run before
the first PSP context exists. There is no direct trampoline fallback.

`fiber_current()` returns the runtime-owned current fiber. `fiber_schedule()`
does not choose a task by itself. It enters PendSV, saves the current context,
calls the configured scheduler bridge under the port critical section, and
restores the returned context. A missing hook, `NULL` returned context,
uninitialized context, corrupted boot seal, out-of-bounds saved stack pointer,
invalid EXC_RETURN, or insufficient software/hardware restore-frame headroom
traps through `FIBER_REQUIRE`. Idle must be represented by a real initialized
`FiberContext`, not by returning `NULL`.

Restore-target validation is mandatory and has no performance-disable switch.
It checks the current context after save and every scheduler-selected target
before restore. `EXC_RETURN` must match one of the exact encodings allowed by
the selected port; checking only the Thread/PSP bits is not sufficient. The
saved hardware frame must also contain `xPSR.T`, stacked Thread-mode IPSR state,
a PC with bit 0 clear, and enough space for the optional `xPSR.STACKALIGN` word.
When `FIBER_STACK_CANARY=1`, the low-stack canary is checked on every scheduler
selection independently of PSPLIM availability. Even when full per-switch boot
hashing is disabled, the fast check validates boot-record guards and structural
relationships before any canary or saved-frame memory is read.

The concrete CM7 PendSV verifies Handler identity and the complete active
`EXC_RETURN` encoding before saving a source context. If the interrupted Thread
context did not use PSP, or any other exception-return encoding is present, a
pre-start or foreign PendSV traps with `'j'` instead of saving invalid state.

Before writing the source software frame, PendSV also checks that the live PSP
is inside the current fiber stack bounds and has enough headroom for the core
frame plus any high-FP save. If not, it traps with `'d'` before writing below
`stack_base`.

## FPU Stress Example

Use floating-point work only when you explicitly want to test FPU save/restore
and the build is configured with the expected FPU compiler flags.

```c
void fiber_fpu_stress_entry(void*)
{
	volatile double acc = 0.0;

	for (;;) {
		acc += 1.0;
		fiber_schedule();
	}
}
```

## Exception Handlers

In `stm32xxx_it.c`:

```c
#include "fiber/fiber_core.h"

FIBER_ATTR_NAKED_ASM
void PendSV_Handler(void)
{
	__ASM volatile("b fiber_pendsv");
}

FIBER_ATTR_NAKED_ASM
void SVC_Handler(void)
{
	__ASM volatile("b fiber_svc");
}
```

For wrapper mode, define these after the handlers are wired in the embedding
application:

```c
#define FIBER_PENDSV_WIRED 1
#define FIBER_SVC_WIRED 1
```

`fiber_pendsv()` is a naked exception handler body. It must see the original
handler LR value, which is the hardware `EXC_RETURN`. Do not use a normal C
wrapper that emits `bl fiber_pendsv`; that overwrites LR with a function return
address. Direct vectoring to `fiber_pendsv()` is also valid when
`FIBER_PENDSV_VECTOR_DIRECT=1` is set.

`fiber_svc()` is also a naked handler body. The ARMv7E-M SVC start path checks
that SVC arrived from MSP, verifies the MSP frame alignment, decodes the SVC
opcode plus configured immediate, validates the seeded current context, switches
to PSP, and returns through the synthetic exception frame. A normal C wrapper is
not valid for the same LR/EXC_RETURN
reason. Direct vectoring to `fiber_svc()` is valid when
`FIBER_SVC_VECTOR_DIRECT=1` is set.

## Safety Defaults

- `FIBER_FPU_LAZY = 0`
- `FIBER_STACK_CANARY = 1`
- `FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH = 0`
- `FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START = 0`
- `FIBER_ENABLE_CONFIGURABLE_FAULTS = 1`
- SVC first-start is mandatory for runtime-supported ports
- DSB/ISB context and PendSV-request barriers are mandatory port behavior
- FPU ports enable and read back CP10/CP11 before first start
- stack alignment, EXC_RETURN, FPCA handling, and canary encoding are
  selected-port/runtime facts, not user settings

`FIBER_VALIDATE_SCHEDULED_CONTEXT` and `FIBER_VALIDATE_CURRENT` were removed.
Defining either obsolete switch is a compile error because current ownership
and restore-context validation are mandatory invariants.

`fiber_schedule()` is a Thread-mode API. Calling it from an interrupt traps
through `FIBER_REQUIRE`. A real scheduler jump requires `PRIMASK == 0`, so the
switch cannot be silently delayed out of a masked interrupt region. On cores
with BASEPRI, a real scheduler jump also requires `BASEPRI == 0`. On cores with
FAULTMASK, `FAULTMASK` must also be clear.

The transitional `fiber_pendsv_init_lowest_priority()` diagnostic and the public
`fiber_start()` entry run the runtime exception setup check by default. The
diagnostic is not part of the frozen five-function cooperative API. The check
verifies:

- PendSV priority reads back as the lowest priority;
- SVCall priority reads back as highest priority;
- vector table entries route PendSV and SVC to the expected handlers;
- the selected port scheduler BASEPRI threshold matches the implemented NVIC
  priority bits;
- `AIRCR.PRIGROUP` is compatible with the scheduler `BASEPRI` threshold;
- affected Cortex-M7 r0p0/r0p1 cores require
  the always-enabled workaround owned by the concrete `ARM_CM7/r0p1` port;
- unvalidated v8-M Baseline/Mainline, v8.1-M, TrustZone bank targeting, MVE,
  and PAC/BTI scenarios require an explicit `FIBER_ALLOW_UNVALIDATED_*` opt-in
  before runtime use.

The default vector check expects application wrappers named `PendSV_Handler()`
and `SVC_Handler()`. Each wrapper must be a naked branch/tail branch that
preserves LR/EXC_RETURN. If the vector table points directly to
`fiber_pendsv()`, define `FIBER_PENDSV_VECTOR_DIRECT=1`. If it points directly
to `fiber_svc()`, define `FIBER_SVC_VECTOR_DIRECT=1`. SVC vector validation is
enabled by default because SVC is the only first-start path. The SVC start path
also checks at runtime that the instruction is the configured
`SVC #FIBER_SVC_START_NUMBER`; a wrong SVC dispatch traps with `'u'`, and an
SVC that returns to `fiber_port_start_first_context()` traps with `'y'`.

The handler-side scheduler bridge follows FreeRTOS-style critical-section
discipline: BASEPRI-capable ports raise `BASEPRI` around the hook, while
BASEPRI-less ports save `PRIMASK`, disable interrupts, call the hook, and
restore `PRIMASK`. Returning with changed `PRIMASK`, `FAULTMASK`, `BASEPRI`, or
`CONTROL` is a panic condition.

The v8-M feature policy remains intentionally strict for future ports. After the
direct trampoline removal, M23/M33/M55/MVE-FP profiles have compile-covered SVC
first-start mechanics, but runtime use remains policy-gated until the extra
context state their FreeRTOS ports require is implemented and validated:

```c
#define FIBER_ALLOW_UNVALIDATED_ARMV8M_BASELINE_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_ARMV8M_MAINLINE_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_ARMV81M_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_TRUSTZONE_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_MVE_RUNTIME 1
#define FIBER_ALLOW_UNVALIDATED_PACBTI_RUNTIME 1
```

Use those only for bring-up experiments after the selected port policy is
understood. They do not add FreeRTOS-level PSPLIM/CONTROL/secure-context/PAC-key
handling.

## H7 Lazy-FPU Mode

The STM32H7 / Cortex-M7 validation app previously passed long-running
switch/FPU stress with lazy stacking enabled:

```c
#define FIBER_FPU_LAZY 1
```

This remains an opt-in performance policy. Context barriers and PendSV request
serialization cannot be disabled. Re-run board validation after changing FPU
policy or compiler FP options.

## Portability Notes

The STM32H7 / Cortex-M7 path is the primary validation target. The core switch
matches the FreeRTOS PendSV pattern: save `r4-r11`, preserve `EXC_RETURN`, run
on PSP, and conditionally save `s16-s31` when an extended FP frame is active.
Auto selection maps STM32H7/Cortex-M7 to
`FIBER_PORT_NAME == "ARM_CM7/r0p1"`; Cortex-M4/M4F uses the separate generic
`armv7em` source group.

FreeRTOS routes Cortex-M7 through a dedicated `ARM_CM7/r0p1` port. The concrete
fiber CM7 scheduler-driven PendSV path raises `BASEPRI` around the scheduler
bridge, then restores the previous `BASEPRI` value before restoring the selected
fiber. The concrete port always enables a FreeRTOS-style guard around
handler-side `BASEPRI` writes for affected Cortex-M7 r0p1 parts. The
fiber helper preserves and restores the previous `PRIMASK` instead of blindly
executing `cpsie i`, so SVC/start critical sections stay closed while the
errata-safe `BASEPRI` write is serialized. Runtime startup checks that CPUID is
Cortex-M7 and keeps the affected r0p0/r0p1 policy fail-closed. The compile matrix
builds this branch, but real affected hardware validation is still required
before claiming r0p1 parity.

The initial synthetic exception frame stores `PC` with bit 0 clear. Thumb state
is carried by `xPSR.T`.

The ARMv7E-M first-start path enters that synthetic frame through SVC, not a
direct branch. It
requires a configured scheduler hook, requires no active interrupt masks,
verifies MSP setup, validates the restore context, checks SVC provenance,
exact incoming `EXC_RETURN`, stacked Thread/Thumb state, MSP-frame alignment,
and opcode/immediate value. It clears pending PendSV before opening interrupts
for SVC, enables IRQ and fault exceptions, clears BASEPRI in the SVC handler,
then restores PSP and returns through the selected context's `EXC_RETURN`.

The concrete CM7 port fixes its initial `EXC_RETURN` at `0xFFFFFFFDu`; it is not
an application override. The non-production v8-M fallback uses explicitly
scoped `FIBER_TRANSITIONAL_V8M_*` bring-up inputs, which do not provide
production TrustZone or Non-secure support.

Cortex-M23, Cortex-M33, Cortex-M55, MVE, TrustZone/Non-secure, and PAC/BTI
scenarios are unsupported until their FreeRTOS-style context layout is
implemented and hardware-validated. `FIBER_PORT_USES_PSPLIM_REGISTER`
separates PSPLIM register access from the broader architecture profile so M23
security-domain variants cannot accidentally write a missing or wrong-bank
PSPLIM register when those ports are implemented.

On Cortex-M0/M0+, `FIBER_REWIND_MSP` may need to be disabled unless the platform
provides a reliable initial MSP source.

## Validation

Run the compile-only Cortex-M matrix after changing target gates or assembly:

```powershell
.\tools\compile_matrix.ps1
```

This compiles and relocatable-links every selected profile and verifies exactly
one definition of each port ABI symbol. It covers selector and build-selected
modes, wrapper/direct vectors, v8-M bring-up scenarios, and negative settings
contracts. Compile coverage does not replace hardware tests or promote a
transitional profile to a runtime-supported port.

See `FIBER_SETTINGS.md` for settings ownership, `DECISIONS.md` for the current
context-switch decision log,
`H7_RUNTIME_VALIDATION.md` for the STM32H7 hardware validation checklist, and
`FREERTOS_SUPPORT_PLAN.md` for the roadmap toward FreeRTOS-style Cortex-M
CPU-port support.
