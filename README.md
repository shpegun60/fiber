# Fiber

Small cooperative fiber switcher for STM32/Cortex-M projects.

The context switch is requested from Thread mode with `fiber_switch()` and is
performed by PendSV. The application must wire `PendSV_Handler()` to
`fiber_pendsv()`.

## Project Setup

Add the repository root to the include path, then include the public API:

```c
#include "fiber/fiber_core.h"
```

Compile the runtime sources into the application:

```text
fiber/fiber_core.c
fiber/fiber_boot.c
fiber/fiber_stack.c
fiber/port/fiber_port_state.c
fiber/port/armv7em/fiber_port_armv7em.c
fiber/target/fiber_fpu.c
fiber/target/fiber_irq.c
fiber/target/fiber_panic.c
```

Port selection defaults to automatic detection from compiler ARM architecture
macros. Production builds may select the profile explicitly, for example:

```c
#define FIBER_PORT_PROFILE FIBER_PORT_PROFILE_ARMV7EM
```

The currently supported profile names are `FIBER_PORT_PROFILE_ARMV6M`,
`FIBER_PORT_PROFILE_ARMV7M`, `FIBER_PORT_PROFILE_ARMV7EM`,
`FIBER_PORT_PROFILE_ARMV8M_BASELINE`, `FIBER_PORT_PROFILE_ARMV8M_MAINLINE`, and
`FIBER_PORT_PROFILE_ARMV81M_MAINLINE`. Leave `FIBER_PORT_PROFILE` undefined for
auto-detection. When compiler ARM architecture macros are available, an
explicit profile must match them. `FIBER_PORT_SELECTION_ALLOW_MISMATCH` is only
for unusual toolchains or bring-up experiments where the compiler macros are
missing or known to be wrong.

Before starting fibers, initialize PendSV priority:

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

void fiber1_entry(void*)
{
	for (;;) {
		counter1++;
		fiber_yield_to(&f3);
	}
}

void fiber2_entry(void*)
{
	for (;;) {
		counter2++;
		fiber_yield_to(&f1);
	}
}

void fiber3_entry(void*)
{
	for (;;) {
		counter3++;
		fiber_yield_to(&f2);
	}
}

void app_main(void)
{
	fiber_pendsv_init_lowest_priority();

	fiber_init(&f1, stack1, stack1 + sizeof(stack1), fiber1_entry, (void*)1);
	fiber_init(&f2, stack2, stack2 + sizeof(stack2), fiber2_entry, (void*)2);
	fiber_init(&f3, stack3, stack3 + sizeof(stack3), fiber3_entry, (void*)3);

	fiber_start(&f1);

	for (;;) {
	}
}
```

`fiber_start()` seeds the runtime-owned current context, checks the environment,
prepares the platform, switches Thread mode to PSP, and tail-calls the selected
fiber entry. It does not return.

`fiber_current()` returns the runtime-owned current fiber. `fiber_yield_to(to)`
uses it as the source context. The lower-level `fiber_switch(from, to)` API is
kept for advanced/manual integrations, but normal application code should prefer
`fiber_yield_to()`.

## FPU Stress Example

Use floating-point work only when you explicitly want to test FPU save/restore
and the build is configured with the expected FPU compiler flags.

```c
void fiber_fpu_stress_entry(void*)
{
	volatile double acc = 0.0;

	for (;;) {
		acc += 1.0;
		fiber_yield_to(&f2);
	}
}
```

## PendSV Handler

In `stm32xxx_it.c`:

```c
#include "fiber/fiber_core.h"

void PendSV_Handler(void)
{
	fiber_pendsv();
}
```

## Safety Defaults

- `FIBER_SWITCH_STRICT_BARRIERS = 1`
- `FIBER_SWITCH_MASK_IRQS = 1`
- `FIBER_FPU_LAZY = 0`

`fiber_switch()` is a Thread-mode API. Calling it from an interrupt traps through
`FIBER_REQUIRE`. The `from` context must be non-NULL; `to == NULL` is treated as
a no-op. A real switch also requires `PRIMASK == 0`, so the switch cannot be
silently delayed out of a masked interrupt region. On cores with BASEPRI, a real
switch also requires `BASEPRI == 0`. When current tracking is active,
`FIBER_VALIDATE_CURRENT = 1` rejects real switches whose `from` argument is not
the runtime-owned current context.

## H7 Performance Mode

The STM32H7 / Cortex-M7 validation app also passed a long-running switch/FPU
stress run with the faster settings below:

```c
#define FIBER_FPU_LAZY 1
#define FIBER_SWITCH_MASK_IRQS 0
#define FIBER_SWITCH_STRICT_BARRIERS 0
```

Use these as opt-in performance settings after target validation. The portable
bring-up defaults remain the conservative safety settings above.

## Portability Notes

The STM32H7 / Cortex-M7 path is the primary validated target. The core switch
matches the FreeRTOS PendSV pattern: save `r4-r11`, preserve `EXC_RETURN`, run
on PSP, and conditionally save `s16-s31` when an extended FP frame is active.
Auto selection maps STM32H7/Cortex-M7 to `FIBER_PORT_NAME == "armv7em"`.

FreeRTOS routes Cortex-M7 through a dedicated `ARM_CM7/r0p1` port. The current
`fiber` PendSV path does not write `BASEPRI`, so the FreeRTOS r0p1 workaround
around handler-side `BASEPRI` writes is not needed by the current
implementation. If a future v2 port writes `BASEPRI` from PendSV, SVC, or a
handler-side scheduler section, Cortex-M7/r0p1 must become an explicit policy
or source split before claiming parity with the FreeRTOS CM7 port.

The initial synthetic exception frame stores `PC` with bit 0 clear. Thumb state
is carried by `xPSR.T`.

`FIBER_INITIAL_EXC_RETURN` defaults to `0xFFFFFFFDu`, which is correct for
M3/M4/M7 and secure-only style builds. ARMv8-M Non-secure projects can define
`FIBER_RUN_NONSECURE = 1` to select `0xFFFFFFBCu`, or override
`FIBER_INITIAL_EXC_RETURN` directly.

Cortex-M23 and Cortex-M55/MVE are not yet validated targets. Keep
`FIBER_FORCE_SAVE_FPU = 1` in mind for MVE experiments if the toolchain does not
make the extended FP context visible through the usual FPU macros.

On Cortex-M0/M0+, `FIBER_REWIND_MSP` may need to be disabled unless the platform
provides a reliable initial MSP source.

## Validation

Run the compile-only Cortex-M matrix after changing target gates or assembly:

```powershell
.\tools\compile_matrix.ps1
```

This checks representative M0/M0+/M3/M4/M4F/M7/M7F/M23/M33/M33F/M55/M55F/M55
MVE-FP builds. It does not replace hardware tests and does not promote
M23/M33/M55/MVE to validated targets.

See `DECISIONS.md` for the current context-switch decision log and
`FREERTOS_SUPPORT_PLAN.md` for the roadmap toward FreeRTOS-style Cortex-M
CPU-port support.
