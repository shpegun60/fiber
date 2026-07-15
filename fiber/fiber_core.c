/* fiber_core.c - common cooperative fiber runtime.
 *
 * CPU-specific context-frame layout, first-start mechanics, and PendSV assembly
 * live behind the selected port boundary. This file owns the portable API
 * preconditions and delegates architecture behavior to fiber/port.
 */

#include "fiber_api_decl.h"
#include "fiber_panic.h"
#include "fiber_runtime_state.h"
#include "port/fiber_port_runtime_abi.h"

/* Safety net if a task ever returns from its entry function */
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE
void fiber_internal_task_return(void) { fiber_panic('R'); }

/* The selected port owns the complete context layout, boot record, stack
 * geometry, integrity seal, and synthetic frame construction. */
void fiber_init(FiberContext* const ctx, void* const stack_begin, void* const stack_end,
		const entry_t entry, void* const arg)
{
	fiber_port_context_init(ctx, stack_begin, stack_end, entry, arg);
}

FiberContext* fiber_current(void)
{
	return fiber_internal_runtime_load_current_context();
}

FIBER_API_NORETURN
void fiber_start(void)
{
	FIBER_REQUIRE(fiber_internal_scheduler_is_configured() != 0u, 'K');
	FIBER_REQUIRE(fiber_current() == 0, 'k');
	fiber_port_runtime_prepare_start();

	FiberContext *const first = fiber_port_runtime_select_first();
	fiber_internal_runtime_seed_current_context(first);

	fiber_port_runtime_start_first(first);
	FIBER_API_UNREACHABLE();
}

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next, void *user)
{
	fiber_port_require_scheduler_configuration_environment();
	fiber_internal_scheduler_store_pick_next(pick_next, user);
}

/* --------------------------------------------------------------------------
 * fiber_schedule: common cooperative scheduler trigger
 *
 * Common code owns only runtime-current ownership. The selected port owns
 * Thread-mode/mask validation and the architecture-specific request mechanism.
 * Keeping those CPU details out of this translation unit is required before
 * MPU/unprivileged ports can replace a direct PendSV request with yield SVC.
 * -------------------------------------------------------------------------- */

void fiber_schedule(void)
{
	fiber_port_runtime_schedule();
}
