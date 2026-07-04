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
		fiber_switch(&f1, &f3);
	}
}

void fiber2_entry(void*)
{
	for (;;) {
		counter2++;
		fiber_switch(&f2, &f1);
	}
}

void fiber3_entry(void*)
{
	for (;;) {
		counter3++;
		fiber_switch(&f3, &f2);
	}
}

void app_main(void)
{
	fiber_pendsv_init_lowest_priority();

	fiber_init(&f1, stack1, stack1 + sizeof(stack1), fiber1_entry, (void*)1);
	fiber_init(&f2, stack2, stack2 + sizeof(stack2), fiber2_entry, (void*)2);
	fiber_init(&f3, stack3, stack3 + sizeof(stack3), fiber3_entry, (void*)3);

	fiber_boot(&f1.boot);

	for (;;) {
	}
}
```

`fiber_boot()` checks the environment, prepares the platform, switches Thread
mode to PSP, and tail-calls the selected fiber entry. It does not return.

## FPU Stress Example

Use floating-point work only when you explicitly want to test FPU save/restore
and the build is configured with the expected FPU compiler flags.

```c
void fiber_fpu_stress_entry(void*)
{
	volatile double acc = 0.0;

	for (;;) {
		acc += 1.0;
		fiber_switch(&f1, &f2);
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
switch also requires `BASEPRI == 0`.

## Portability Notes

The STM32H7 / Cortex-M7 path is the primary validated target. The core switch
matches the FreeRTOS PendSV pattern: save `r4-r11`, preserve `EXC_RETURN`, run
on PSP, and conditionally save `s16-s31` when an extended FP frame is active.

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

See `DECISIONS.md` for the current context-switch decision log and
`FREERTOS_SUPPORT_PLAN.md` for the roadmap toward FreeRTOS-style Cortex-M
CPU-port support.
