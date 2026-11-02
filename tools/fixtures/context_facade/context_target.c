/* Context-only link fixture; not executable Cortex-M startup qualification. */
#include <stddef.h>
#include <stdint.h>
#include "context/context.h"
#include "consumer.h"

static unsigned char stack[1024] __attribute__((aligned(32)));

static void entry(void *arg)
{
    (void)arg;
    for (;;) { ctxrt_v1_yield(); }
}

CTXRT_DISPATCH_ATTR
static CtxrtContextV1 *dispatch(CtxrtContextV1 *current, void *user)
{
    (void)current;
    (void)user;
    return modern_context();
}

void Reset_Handler(void)
{
    modern_init(stack, stack + sizeof(stack), entry, NULL);
    modern_set(dispatch, NULL);
    (void)modern_current();
    modern_yield();
    modern_start();
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

CTXRT_DISPATCH_ATTR
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{ return begin >= 0x20000000u && end <= 0x20010000u && end > begin; }

CTXRT_DISPATCH_ATTR
int fiber_addr_plausible_code(uintptr_t address)
{ return address >= 0x08000000u && address < 0x08100000u; }

CTXRT_DISPATCH_ATTR __attribute__((externally_visible))
void *memcpy(void *out, const void *in, size_t count)
{
    unsigned char *d = out;
    const unsigned char *s = in;
    while (count--) *d++ = *s++;
    return out;
}

CTXRT_DISPATCH_ATTR __attribute__((externally_visible))
void *memset(void *out, int value, size_t count)
{
    unsigned char *d = out;
    while (count--) *d++ = (unsigned char)value;
    return out;
}
