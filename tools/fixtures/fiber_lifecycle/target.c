/* Actual classic-port link and placement only, NOT executed on a CPU/model. */
#include <stddef.h>
#include <stdint.h>
#include "fiber/lifecycle/fiber_v1_privileged.h"
#include "mixed_api.h"
static FiberV1 a = FIBER_V1_INITIALIZER, b = FIBER_V1_INITIALIZER;
static FiberRuntimeV1 runtime = FIBER_RUNTIME_V1_INITIALIZER;
static unsigned char stack_a[1024] __attribute__((aligned(32)));
static unsigned char stack_b[1024] __attribute__((aligned(32)));
static void entry(void *arg) { (void)arg; for (;;) fiber_v1_yield(); }
static FIBER_V1_SELECT_ATTR FiberV1 *policy(FiberV1 *current, void *user)
{ (void)user; return current == &a ? &b : &a; }
void Reset_Handler(void)
{
    fiber_v1_init(&a, stack_a, stack_a + sizeof(stack_a), entry, &a);
    fiber_v1_init(&b, stack_b, stack_b + sizeof(stack_b), entry, &b);
    fiber_v1_set_scheduler(&runtime, policy, &runtime);
    (void)fiber_v1_current(); (void)fiber_v1_context_privileged(&a);
    fiber_v1_yield(); fiber_v1_start();
}
void Default_Handler(void) { for (;;) __asm volatile("wfe"); }
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
__attribute__((used, section(".isr_vector"), aligned(256)))
const uintptr_t vectors[48] = {
    [0] = 0x20010000u, [1] = (uintptr_t)Reset_Handler,
    [11] = (uintptr_t)SVC_Handler, [14] = (uintptr_t)PendSV_Handler
};
FIBER_SCHEDULER_HOOK_ATTR
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{ return begin >= 0x20000000u && end <= 0x20010000u && end > begin; }
FIBER_SCHEDULER_HOOK_ATTR
int fiber_addr_plausible_code(uintptr_t address)
{ return address >= 0x08000000u && address < 0x08100000u; }
FIBER_SCHEDULER_HOOK_ATTR __attribute__((externally_visible))
void *memcpy(void *out, const void *in, size_t size)
{ unsigned char *d = out; const unsigned char *s = in; while (size--) *d++ = *s++; return out; }
FIBER_SCHEDULER_HOOK_ATTR __attribute__((externally_visible))
void *memset(void *out, int value, size_t size)
{ unsigned char *d = out; while (size--) *d++ = (unsigned char)value; return out; }
