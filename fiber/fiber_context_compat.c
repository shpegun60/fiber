/* Temporary additive bridge. Runtime state and orchestration still belong to
 * the existing engine; ownership inversion is a separate migration step. */
#include "../context/context_api_decl.h"
#include "fiber_api_decl.h"

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void ctxrt_v1_init(CtxrtContextV1 *context,
        void *stack_begin,
        void *stack_end,
        CtxrtEntryFnV1 entry,
        void *arg)
{
    fiber_init(context, stack_begin, stack_end, entry, arg);
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
CtxrtContextV1 *ctxrt_v1_current(void)
{
    return fiber_current();
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void ctxrt_v1_set_dispatcher(CtxrtDispatchFnV1 dispatch, void *user)
{
    fiber_scheduler_set_pick_next(dispatch, user);
}

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void ctxrt_v1_start(void)
{
    fiber_start();
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
void ctxrt_v1_yield(void)
{
    fiber_schedule();
}
