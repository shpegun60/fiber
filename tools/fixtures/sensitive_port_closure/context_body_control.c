#include <stdint.h>
#include "context/context_api_types.h"
#include "context/context_api_attributes.h"

#ifndef CLOSURE_CONTEXT_POISON
#define CLOSURE_CONTEXT_POISON 0
#endif
#ifndef CLOSURE_HOT_TO_CONTEXT_SETTER
#define CLOSURE_HOT_TO_CONTEXT_SETTER 0
#endif

#define CONTROL_ORDINARY FIBER_API_NOINLINE FIBER_API_NOIPA FIBER_API_USED CTXRT_GENERAL_REGS_ONLY
#define CONTROL_CANONICAL CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
#if CLOSURE_CONTEXT_POISON == 1
#define SETTER_ATTRIBUTES CONTROL_ORDINARY
#else
#define SETTER_ATTRIBUTES CONTROL_CANONICAL
#endif
#if CLOSURE_CONTEXT_POISON == 2
#define INIT_ATTRIBUTES CONTROL_ORDINARY
#else
#define INIT_ATTRIBUTES CONTROL_CANONICAL
#endif

static volatile uint32_t closure_context_value;

/* Same exact cold identity as the actual registration helper, not a global
 * allowance: the hot-through-setter variant must still reject its hooks. */
CONTROL_ORDINARY
void fiber_internal_scheduler_store_pick_next(CtxrtDispatchFnV1 dispatch, void *user)
{
    closure_context_value += (dispatch != 0) + (user != 0);
}

SETTER_ATTRIBUTES
void ctxrt_v1_set_dispatcher(CtxrtDispatchFnV1 dispatch, void *user)
{
    fiber_internal_scheduler_store_pick_next(dispatch, user);
}

INIT_ATTRIBUTES
void ctxrt_v1_init(CtxrtContextV1 *context, void *begin, void *end, CtxrtEntryFnV1 entry, void *arg)
{
    (void)begin;
    (void)end;
    (void)entry;
    (void)arg;
    closure_context_value += context != 0;
}

CONTROL_CANONICAL
CtxrtContextV1 *ctxrt_v1_current(void)
{
#if CLOSURE_HOT_TO_CONTEXT_SETTER
    ctxrt_v1_set_dispatcher(0, 0);
#endif
    return 0;
}
