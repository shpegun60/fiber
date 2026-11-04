/* Valid static Context consumer, linked but never executed by this pilot. */
#include <stddef.h>
#include <stdint.h>
#include "context/context.h"
#include "context/context_panic.h"

extern unsigned char __pilot_text_begin[], __pilot_text_end[];
extern unsigned char __pilot_ram_begin[], __pilot_ram_end[];
static CtxrtContextV1 worker;
static uint32_t worker_stack[256] __attribute__((aligned(32)));
static uint32_t worker_argument;

static void entry(void *argument)
{
    if (argument != &worker_argument) {
        fiber_panic('A');
    }
    for (;;) {
        if (ctxrt_v1_current() != &worker) {
            fiber_panic('G');
        }
        ctxrt_v1_yield();
    }
}

static CTXRT_DISPATCH_ATTR
CtxrtContextV1 *dispatch(CtxrtContextV1 *current, void *user)
{
    if (user != &worker || (current != NULL && current != &worker)) {
        fiber_panic('G');
    }
    return &worker;
}

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void pilot_main(void)
{
    ctxrt_v1_init(&worker, worker_stack, worker_stack + 256, entry, &worker_argument);
    ctxrt_v1_set_dispatcher(dispatch, &worker);
    ctxrt_v1_start();
}

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void pilot_fault(void)
{
    for (;;) {
        __asm volatile("udf #90" ::: "memory");
    }
}

CTXRT_DISPATCH_ATTR
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
    return begin >= (uintptr_t)__pilot_ram_begin && end > begin && end <= (uintptr_t)__pilot_ram_end;
}

CTXRT_DISPATCH_ATTR
int fiber_addr_plausible_code(uintptr_t address)
{
    address &= ~(uintptr_t)1u;
    return address >= (uintptr_t)__pilot_text_begin && address < (uintptr_t)__pilot_text_end;
}

CTXRT_DISPATCH_ATTR __attribute__((externally_visible))
void *memcpy(void *destination, const void *source, size_t count)
{
    volatile unsigned char *out = (volatile unsigned char *)destination;
    const volatile unsigned char *in = (const volatile unsigned char *)source;
    for (size_t i = 0; i < count; ++i) {
        out[i] = in[i];
    }
    return destination;
}

CTXRT_DISPATCH_ATTR __attribute__((externally_visible))
void *memset(void *destination, int value, size_t count)
{
    volatile unsigned char *out = (volatile unsigned char *)destination;
    for (size_t i = 0; i < count; ++i) {
        out[i] = (unsigned char)value;
    }
    return destination;
}

struct PilotRoots {
    void (*init)(CtxrtContextV1 *, void *, void *, CtxrtEntryFnV1, void *);
    CtxrtContextV1 *(*current)(void);
    void (*set_dispatcher)(CtxrtDispatchFnV1, void *);
    void (*start)(void);
    void (*yield)(void);
};

__attribute__((used, externally_visible, section(".pilot_roots")))
const struct PilotRoots pilot_context_roots = {
    ctxrt_v1_init, ctxrt_v1_current, ctxrt_v1_set_dispatcher, ctxrt_v1_start, ctxrt_v1_yield
};
