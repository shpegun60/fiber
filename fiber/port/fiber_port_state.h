/*
 * fiber_port_state.h
 *
 * Internal runtime state shared by common runtime and port code.
 */

#ifndef FIBER_PORT_FIBER_PORT_STATE_H_
#define FIBER_PORT_FIBER_PORT_STATE_H_

#include "fiber_port_types.h"

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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_FIBER_PORT_STATE_H_ */
