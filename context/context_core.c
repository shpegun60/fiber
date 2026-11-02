/* Context-owned orchestration over the frozen eight-operation CPU port ABI.
 * Sensitive attributes protect these bodies, not the ordinary cold legacy
 * wrappers or registration helper transitively. */
#include "context_api_decl.h"
#include "context_panic.h"
#include "context_runtime_port_abi.h"
#include "context_runtime_state.h"
#include "context_port_abi.h"

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_task_return(void)
{
    fiber_panic('R');
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void ctxrt_v1_init(CtxrtContextV1 *context,
        void *stack_begin,
        void *stack_end,
        CtxrtEntryFnV1 entry,
        void *arg)
{
    fiber_port_context_init(context, stack_begin, stack_end, entry, arg);
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
CtxrtContextV1 *ctxrt_v1_current(void)
{
    return fiber_internal_runtime_load_current_context();
}

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void ctxrt_v1_start(void)
{
    FIBER_REQUIRE(fiber_internal_scheduler_is_configured() != 0u, 'K');
    FIBER_REQUIRE(ctxrt_v1_current() == 0, 'k');
    fiber_internal_runtime_close_context_configuration();
    fiber_port_runtime_prepare_start();

    CtxrtContextV1 *const first = fiber_port_runtime_select_first();
    fiber_internal_runtime_publish_current_context(first);

    fiber_port_runtime_start_first(first);
    FIBER_API_UNREACHABLE();
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void ctxrt_v1_set_dispatcher(CtxrtDispatchFnV1 dispatch, void *user)
{
    fiber_port_require_scheduler_configuration_environment();
    fiber_internal_scheduler_store_pick_next(dispatch, user);
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
void ctxrt_v1_yield(void)
{
    fiber_port_runtime_schedule();
}
