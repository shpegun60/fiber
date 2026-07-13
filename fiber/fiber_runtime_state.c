/*
 * fiber_runtime_state.c
 *
 * Runtime-owned port/scheduler state used by PendSV ports.
 */

#include "fiber_runtime_state.h"
#include "fiber_panic.h"

FiberContext *volatile fiber_internal_port_current_context = 0;
FiberSchedulerPickNextFn volatile fiber_internal_port_scheduler_pick_next = 0;
void *volatile fiber_internal_port_scheduler_user = 0;
static volatile uint32_t fiber_internal_port_scheduler_selecting = 0;

void fiber_internal_scheduler_store_pick_next(FiberSchedulerPickNextFn pick_next,
		void *user)
{
	FIBER_REQUIRE(fiber_internal_port_current_context == 0, 'k');
	FIBER_REQUIRE(fiber_internal_port_scheduler_selecting == 0u, 'k');
	FIBER_REQUIRE(pick_next != 0, 'K');

	__DMB();
	fiber_internal_port_scheduler_user = user;
	__DMB();
	fiber_internal_port_scheduler_pick_next = pick_next;
	__DMB();
}

void fiber_internal_scheduler_begin_first_selection(void)
{
	FIBER_REQUIRE(fiber_internal_port_current_context == 0, 'k');
	FIBER_REQUIRE(fiber_internal_port_scheduler_selecting == 0u, 'k');
	FIBER_REQUIRE(fiber_internal_port_scheduler_pick_next != 0, 'K');

	__DMB();
	fiber_internal_port_scheduler_selecting = 1u;
	__DMB();
}

void fiber_internal_scheduler_end_first_selection(void)
{
	__DMB();
	fiber_internal_port_scheduler_selecting = 0u;
	__DMB();
}

FIBER_GENERAL_REGS_ONLY
void fiber_internal_require_schedule_current(void)
{
	__COMPILER_BARRIER();
	FIBER_REQUIRE(fiber_internal_port_current_context != 0, 'G');
	__COMPILER_BARRIER();
}

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_scheduler_invoke_pick_next(FiberContext *current)
{
	FiberSchedulerPickNextFn const pick_next = fiber_internal_port_scheduler_pick_next;
	__DMB();
	void *const user = fiber_internal_port_scheduler_user;

	FIBER_REQUIRE(pick_next != 0, 'K');
	return pick_next(current, user);
}

void fiber_internal_scheduler_commit_current_context(FiberContext *next)
{
	FIBER_REQUIRE(next != 0, 'N');

	__DMB();
	fiber_internal_port_current_context = next;
	__DMB();
}
