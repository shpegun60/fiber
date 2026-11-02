/* Compiled as both C and C++; no CMSIS or private runtime header. */
#include "fiber_core.h"
static FiberContext contexts[2];
static uint32_t stacks[2][256] __attribute__((aligned(8)));
__attribute__((used, section(".proof_roots")))
static const uintptr_t public_operation_roots[] = {
    (uintptr_t)fiber_init, (uintptr_t)fiber_current, (uintptr_t)fiber_start,
    (uintptr_t)fiber_scheduler_set_pick_next, (uintptr_t)fiber_schedule
};
static void entry(void *arg) { (void)arg; for (;;) fiber_schedule(); }
static FiberContext *pick(FiberContext *current, void *user)
{
    (void)user;
    return current == &contexts[0] ? &contexts[1] : &contexts[0];
}
#ifdef __cplusplus
extern "C"
#endif
void Reset_Handler(void)
{
    fiber_init(&contexts[0], stacks[0], stacks[0] + 256, entry, 0);
    fiber_init(&contexts[1], stacks[1], stacks[1] + 256, entry, 0);
    fiber_scheduler_set_pick_next(pick, 0);
    (void)fiber_current();
    fiber_start();
}
