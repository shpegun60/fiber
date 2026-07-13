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

	fiber_port_runtime_memory_barrier();
	fiber_internal_port_scheduler_user = user;
	fiber_port_runtime_memory_barrier();
	fiber_internal_port_scheduler_pick_next = pick_next;
	fiber_port_runtime_memory_barrier();
}

void fiber_internal_scheduler_begin_first_selection(void)
{
	FIBER_REQUIRE(fiber_internal_port_current_context == 0, 'k');
	FIBER_REQUIRE(fiber_internal_port_scheduler_selecting == 0u, 'k');
	FIBER_REQUIRE(fiber_internal_port_scheduler_pick_next != 0, 'K');

	fiber_port_runtime_memory_barrier();
	fiber_internal_port_scheduler_selecting = 1u;
	fiber_port_runtime_memory_barrier();
}

void fiber_internal_scheduler_end_first_selection(void)
{
	fiber_port_runtime_memory_barrier();
	fiber_internal_port_scheduler_selecting = 0u;
	fiber_port_runtime_memory_barrier();
}

FIBER_GENERAL_REGS_ONLY
void fiber_internal_require_schedule_current(void)
{
	fiber_port_runtime_memory_barrier();
	FIBER_REQUIRE(fiber_internal_port_current_context != 0, 'G');
	fiber_port_runtime_memory_barrier();
}

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_scheduler_invoke_pick_next(FiberContext *current)
{
	FiberSchedulerPickNextFn const pick_next = fiber_internal_port_scheduler_pick_next;
	fiber_port_runtime_memory_barrier();
	void *const user = fiber_internal_port_scheduler_user;

	FIBER_REQUIRE(pick_next != 0, 'K');
	return pick_next(current, user);
}

void fiber_internal_scheduler_commit_current_context(FiberContext *next)
{
	FIBER_REQUIRE(next != 0, 'N');

	fiber_port_runtime_memory_barrier();
	fiber_internal_port_current_context = next;
	fiber_port_runtime_memory_barrier();
}
