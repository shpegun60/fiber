#include "fiber/fiber_core.h"
#include "fiber/port/fiber_port_runtime_abi.h"

static FiberContext context;
static unsigned char stack[2048] __attribute__((aligned(8)));

static void task(void *argument)
{
    (void)argument;
    for (;;) { __asm volatile("wfe"); }
}

/* Link-only root. Never executed as board firmware. */
void Reset_Handler(void)
{
    fiber_init(&context, stack, stack + sizeof(stack), task, 0);
#if FIBER_REVERSE_CONSTRUCTOR_START
    fiber_port_runtime_prepare_start();
#endif
    for (;;) { __asm volatile("wfe"); }
}
