/* Legacy five-operation compatibility surface over Context v1.
 * Cold init/registration bodies keep their existing ordinary attributes;
 * Context entry attributes do not protect these wrappers transitively. */

#include "fiber_api_decl.h"
#include "../context/context_api_decl.h"
void fiber_init(FiberContext* const ctx, void* const stack_begin, void* const stack_end,
		const entry_t entry, void* const arg)
{
	ctxrt_v1_init(ctx, stack_begin, stack_end, entry, arg);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
FiberContext* fiber_current(void)
{
	return ctxrt_v1_current();
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_start(void)
{
	ctxrt_v1_start();
}

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next, void *user)
{
	ctxrt_v1_set_dispatcher(pick_next, user);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void fiber_schedule(void)
{
	ctxrt_v1_yield();
}
