#include "fiber_core.h"
static FiberContext context;
static uint32_t stack[256] __attribute__((aligned(8)));
static void entry(void *arg) { (void)arg; for (;;) {} }
#ifdef __cplusplus
extern "C"
#endif
void Reset_Handler(void)
{
    fiber_init(&context, stack, stack + 256, entry, 0);
    for (;;) {}
}
