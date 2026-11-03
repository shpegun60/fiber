/* Link roots only: no firmware from this suite is executed. */
#include <stddef.h>
#include <stdint.h>
#include "context/context.h"
#include "context/context_panic.h"
#define STOP CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
#define SAFE CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY

extern unsigned char __freeze_text_begin[], __freeze_text_end[];
extern unsigned char __freeze_ram_begin[], __freeze_ram_end[];
volatile uint32_t freeze_failure;

STOP void freeze_fail_stop(uint32_t reason)
{
    freeze_failure = reason;
    for (;;) { __asm volatile("udf #90" ::: "memory"); }
}
STOP void freeze_reset_forbidden(void) { freeze_fail_stop(0x52535400u); }
STOP void freeze_fault_forbidden(void) { freeze_fail_stop(0x4641554Cu); }
STOP void fiber_panic(char reason) { freeze_fail_stop((uint32_t)(unsigned char)reason); }
SAFE int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
    return begin >= (uintptr_t)__freeze_ram_begin && end > begin &&
            end <= (uintptr_t)__freeze_ram_end;
}
SAFE int fiber_addr_plausible_code(uintptr_t address)
{
    address &= ~(uintptr_t)1u;
    return address >= (uintptr_t)__freeze_text_begin && address < (uintptr_t)__freeze_text_end;
}
SAFE __attribute__((externally_visible))
void *memcpy(void *destination, const void *source, size_t count)
{
    volatile unsigned char *out = (volatile unsigned char *)destination;
    const volatile unsigned char *in = (const volatile unsigned char *)source;
    for (size_t i = 0; i < count; ++i) { out[i] = in[i]; }
    return destination;
}
SAFE __attribute__((externally_visible))
void *memset(void *destination, int value, size_t count)
{
    volatile unsigned char *out = (volatile unsigned char *)destination;
    for (size_t i = 0; i < count; ++i) { out[i] = (unsigned char)value; }
    return destination;
}

struct FreezeRoots {
    void (*init)(CtxrtContextV1 *, void *, void *, CtxrtEntryFnV1, void *);
    CtxrtContextV1 *(*current)(void);
    void (*dispatcher)(CtxrtDispatchFnV1, void *);
    void (*start)(void);
    void (*yield)(void);
};
__attribute__((used, externally_visible, section(".freeze_roots")))
const struct FreezeRoots freeze_context_roots = {
    ctxrt_v1_init, ctxrt_v1_current, ctxrt_v1_set_dispatcher, ctxrt_v1_start, ctxrt_v1_yield
};
