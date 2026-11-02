/* Link/codegen only: never executed as an architecture fixture. */
#include <stddef.h>
#include <stdint.h>
#include "context/context.h"
#include "fiber/fiber_core.h"
#include "consumer.h"
static unsigned char stack_a[1024] __attribute__((aligned(32)));
static unsigned char stack_b[1024] __attribute__((aligned(32)));
static volatile unsigned start_choice;
static void entry(void *arg) { (void)arg; for (;;) { ctxrt_v1_yield(); fiber_schedule(); } }
CTXRT_DISPATCH_ATTR
static CtxrtContextV1 *dispatch(CtxrtContextV1 *current, void *arg)
{
    (void)arg;
    return current == modern_context() ? legacy_context() : modern_context();
}
void Reset_Handler(void)
{
    modern_init(stack_a, stack_a + sizeof(stack_a), entry, NULL);
    legacy_init(stack_b, stack_b + sizeof(stack_b), entry, NULL);
    modern_set(dispatch, NULL);
    legacy_set(dispatch, NULL);
    (void)modern_current(); (void)legacy_current();
    modern_yield(); legacy_yield();
    if (start_choice) modern_start(); else legacy_start();
    for (;;) { __asm volatile("wfe"); }
}
void Default_Handler(void) { for (;;) { __asm volatile("wfe"); } }
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
__attribute__((used, section(".isr_vector"), aligned(256)))
const uintptr_t vectors[48] = {
    [0] = UINT32_C(0x20010000), [1] = (uintptr_t)Reset_Handler,
    [11] = (uintptr_t)SVC_Handler, [14] = (uintptr_t)PendSV_Handler
};
FIBER_SCHEDULER_HOOK_ATTR
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{ return begin >= 0x20000000u && end <= 0x20010000u && end > begin; }
FIBER_SCHEDULER_HOOK_ATTR
int fiber_addr_plausible_code(uintptr_t address)
{ return address >= 0x08000000u && address < 0x08100000u; }
FIBER_SCHEDULER_HOOK_ATTR __attribute__((externally_visible))
void *memcpy(void *out, const void *in, size_t count)
{
    unsigned char *d = out; const unsigned char *s = in;
    while (count--) *d++ = *s++;
    return out;
}
FIBER_SCHEDULER_HOOK_ATTR __attribute__((externally_visible))
void *memset(void *out, int value, size_t count)
{
    unsigned char *d = out;
    while (count--) *d++ = (unsigned char)value;
    return out;
}
