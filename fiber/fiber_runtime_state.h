/*
 * fiber_runtime_state.h
 *
 * Internal runtime state shared by common runtime and port code.
 */

#ifndef FIBER_FIBER_RUNTIME_STATE_H_
#define FIBER_FIBER_RUNTIME_STATE_H_

#include "fiber_api_attributes.h"
#include "fiber_api_types.h"
#include "port/fiber_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Scheduler-driven v2 state.
 *
 * The port owns CPU save/restore. The scheduler hook owns the policy that
 * chooses the next context. A NULL hook or NULL hook result is a panic condition
 * in the scheduler-driven PendSV/SVC path.
 */
extern FiberContext *volatile fiber_internal_port_current_context;
extern FiberSchedulerPickNextFn volatile fiber_internal_port_scheduler_pick_next;
extern void *volatile fiber_internal_port_scheduler_user;

void fiber_internal_scheduler_store_pick_next(FiberSchedulerPickNextFn pick_next,
		void *user);

void fiber_internal_scheduler_begin_first_selection(void);
void fiber_internal_scheduler_end_first_selection(void);

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_scheduler_invoke_pick_next(FiberContext *current);

void fiber_internal_scheduler_commit_current_context(FiberContext *next);

/* Common-owned lifecycle guard used by selected ports before they request a
 * scheduler exception. Ports must call this helper instead of inspecting the
 * current-context global directly. */
FIBER_GENERAL_REGS_ONLY
void fiber_internal_require_schedule_current(void);

__STATIC_FORCEINLINE FiberContext *fiber_internal_runtime_load_current_context(void)
{
	__COMPILER_BARRIER();
	return fiber_internal_port_current_context;
}

__STATIC_FORCEINLINE void fiber_internal_runtime_seed_current_context(FiberContext *ctx)
{
	__DMB();
	fiber_internal_port_current_context = ctx;
	__DMB();
}

__STATIC_FORCEINLINE uint32_t fiber_internal_scheduler_is_configured(void)
{
	__COMPILER_BARRIER();
	return (fiber_internal_port_scheduler_pick_next != 0) ? 1u : 0u;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_RUNTIME_STATE_H_ */
