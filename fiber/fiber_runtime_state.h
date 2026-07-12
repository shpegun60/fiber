/*
 * fiber_runtime_state.h
 *
 * Internal runtime state shared by common runtime and port code.
 */

#ifndef FIBER_FIBER_RUNTIME_STATE_H_
#define FIBER_FIBER_RUNTIME_STATE_H_

#include "fiber_types.h"
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

void fiber_internal_port_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                                 void *user);

void fiber_internal_validate_restore_context(FiberContext *ctx);

FiberContext *fiber_internal_scheduler_pick_first_from_start(void);

FiberContext *fiber_internal_scheduler_pick_next_from_pendsv(FiberContext *current);

__STATIC_FORCEINLINE FiberContext *fiber_port_load_current_context(void)
{
	__COMPILER_BARRIER();
	return fiber_internal_port_current_context;
}

__STATIC_FORCEINLINE void fiber_port_seed_current_context(FiberContext *ctx)
{
	__DMB();
	fiber_internal_port_current_context = ctx;
	__DMB();
}

__STATIC_FORCEINLINE void fiber_port_set_scheduler_pick_next(FiberSchedulerPickNextFn pick_next,
                                                             void *user)
{
	fiber_internal_port_scheduler_set_pick_next(pick_next, user);
}

__STATIC_FORCEINLINE uint32_t fiber_port_scheduler_is_configured(void)
{
	__COMPILER_BARRIER();
	return (fiber_internal_port_scheduler_pick_next != 0) ? 1u : 0u;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_RUNTIME_STATE_H_ */
