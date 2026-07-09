/*
 * fiber_port_state.c
 *
 * Runtime-owned port/scheduler state used by PendSV ports.
 */

#include "fiber_port_state.h"
#include "../fiber_core.h"

FiberContext *volatile fiber_internal_port_current_context = 0;
FiberSchedulerPickNextFn volatile fiber_internal_port_scheduler_pick_next = 0;
void *volatile fiber_internal_port_scheduler_user = 0;

void fiber_internal_port_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                                 void *user)
{
	__DMB();
	fiber_internal_port_scheduler_user = user;
	__DMB();
	fiber_internal_port_scheduler_pick_next = pick_next;
	__DMB();
}

FiberContext *fiber_internal_scheduler_pick_next_from_pendsv(FiberContext *current)
{
	FiberSchedulerPickNextFn const pick_next = fiber_internal_port_scheduler_pick_next;

	FIBER_REQUIRE(pick_next != 0, 'K');

	FiberContext *const next = pick_next(current, fiber_internal_port_scheduler_user);

	FIBER_REQUIRE(next != 0, 'N');
	FIBER_REQUIRE(next->sp != 0, 'P');
	FIBER_REQUIRE(next->boot.sealed != 0u, 'S');

	return next;
}

FiberContext *volatile fiber_internal_port_switch_from_slot = 0;
FiberContext *volatile fiber_internal_port_switch_to_slot = 0;
