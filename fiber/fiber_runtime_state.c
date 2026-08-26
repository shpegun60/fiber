/*
 * fiber_runtime_state.c
 *
 * Common-owned scheduler state and frozen reverse ABI implementation.
 */

#include "fiber_runtime_state.h"
#include "fiber_panic.h"
#include "fiber_runtime_port_abi.h"

const unsigned char fiber_internal_runtime_port_abi_v1_anchor =
		(unsigned char)FIBER_RUNTIME_PORT_ABI_VERSION;

/* Keep the slot in a standard .bss subsection. Ordinary linker scripts still
 * collect and zero it through .bss*, while MPU profiles can isolate this one
 * object in an exact unprivileged-read-only region. An MPU linker manifest
 * must keep the complete aperture in its startup zero-initialization span. */
FiberContext *volatile fiber_internal_runtime_current_context_slot
		__attribute__((section(".bss.fiber_runtime_current_context_slot"))) = 0;

static FiberSchedulerPickNextFn volatile
fiber_internal_runtime_scheduler_pick_next = 0;
static void *volatile fiber_internal_runtime_scheduler_user = 0;
static volatile uint32_t
fiber_internal_runtime_scheduler_first_selection_started = 0;
static volatile uint32_t
fiber_internal_runtime_context_configuration_closed = 0;

void fiber_internal_scheduler_store_pick_next(FiberSchedulerPickNextFn pick_next,
		void *user)
{
	FIBER_REQUIRE(fiber_internal_runtime_current_context_slot == 0, 'k');
	FIBER_REQUIRE(
			fiber_internal_runtime_scheduler_first_selection_started == 0u,
			'k');
	FIBER_REQUIRE(pick_next != 0, 'K');

	fiber_port_runtime_memory_barrier();
	fiber_internal_runtime_scheduler_user = user;
	fiber_port_runtime_memory_barrier();
	fiber_internal_runtime_scheduler_pick_next = pick_next;
	fiber_port_runtime_memory_barrier();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
FiberContext *fiber_internal_runtime_load_current_context(void)
{
	fiber_port_runtime_memory_barrier();
	return fiber_internal_runtime_current_context_slot;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_runtime_select_scheduler_candidate(
		FiberContext *current)
{
	const uint32_t first_selection = (current == 0) ? 1u : 0u;
	if (first_selection != 0u) {
		FIBER_REQUIRE(fiber_internal_runtime_current_context_slot == 0, 'k');
		FIBER_REQUIRE(
				fiber_internal_runtime_scheduler_first_selection_started == 0u,
				'k');
		FIBER_REQUIRE(fiber_internal_runtime_scheduler_pick_next != 0, 'K');

		fiber_port_runtime_memory_barrier();
		fiber_internal_runtime_scheduler_first_selection_started = 1u;
		fiber_port_runtime_memory_barrier();
	}

	FiberSchedulerPickNextFn const pick_next =
			fiber_internal_runtime_scheduler_pick_next;
	fiber_port_runtime_memory_barrier();
	void *const user = fiber_internal_runtime_scheduler_user;

	FIBER_REQUIRE(pick_next != 0, 'K');
	FiberContext *const next = pick_next(current, user);
	FIBER_REQUIRE(next != 0, 'N');

	return next;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_publish_current_context(FiberContext *next)
{
	FIBER_REQUIRE(next != 0, 'N');

	fiber_port_runtime_memory_barrier();
	fiber_internal_runtime_current_context_slot = next;
	fiber_port_runtime_memory_barrier();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_current_context(void)
{
	fiber_port_runtime_memory_barrier();
	FIBER_REQUIRE(fiber_internal_runtime_current_context_slot != 0, 'G');
	fiber_port_runtime_memory_barrier();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_internal_scheduler_is_configured(void)
{
	fiber_port_runtime_memory_barrier();
	return (fiber_internal_runtime_scheduler_pick_next != 0) ? 1u : 0u;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_close_context_configuration(void)
{
	fiber_port_runtime_memory_barrier();
	FIBER_REQUIRE(fiber_internal_runtime_context_configuration_closed == 0u,
			'k');
	fiber_internal_runtime_context_configuration_closed = 1u;
	fiber_port_runtime_memory_barrier();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_internal_runtime_context_configuration_is_open(void)
{
	fiber_port_runtime_memory_barrier();
	const uint32_t open =
			(fiber_internal_runtime_context_configuration_closed == 0u) &&
			(fiber_internal_runtime_current_context_slot == 0) &&
			(fiber_internal_runtime_scheduler_first_selection_started == 0u);
	fiber_port_runtime_memory_barrier();

	return open ? 1u : 0u;
}
