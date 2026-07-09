/*
 * fiber_port_state.h
 *
 * Internal runtime state shared by common runtime and port code.
 */

#ifndef FIBER_PORT_FIBER_PORT_STATE_H_
#define FIBER_PORT_FIBER_PORT_STATE_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FiberContext FiberContext;

typedef FiberContext *(*FiberSchedulerPickNextFn)(FiberContext *current, void *user);

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

FiberContext *fiber_internal_scheduler_pick_next_from_pendsv(FiberContext *current);

/*
 * Legacy publication slots used by the current fiber_switch(from, to) path.
 * TODO(v2): remove these from the normal PendSV ABI after the ARMv7E-M port
 * migrates to current_context + scheduler bridge + pick_next hook.
 */
extern FiberContext *volatile fiber_internal_port_switch_from_slot;
extern FiberContext *volatile fiber_internal_port_switch_to_slot;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_FIBER_PORT_STATE_H_ */
