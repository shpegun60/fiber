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

#ifndef FIBER_VALIDATE_SCHEDULED_CONTEXT
# define FIBER_VALIDATE_SCHEDULED_CONTEXT 1
#endif

#define FIBER_PORT_SW_FRAME_BYTES      (9u * 4u)
#define FIBER_PORT_HIGH_FP_FRAME_BYTES (16u * 4u)

void fiber_internal_validate_restore_context(FiberContext *ctx)
{
#if FIBER_VALIDATE_SCHEDULED_CONTEXT
	FIBER_REQUIRE(ctx != 0, 'N');
	FIBER_REQUIRE(ctx->sp != 0, 'P');
	fiber_boot_simple_check(&ctx->boot);

	const uintptr_t sp = (uintptr_t)ctx->sp;
	/* Saved SW frame is 36 bytes below an 8-byte aligned HW exception frame. */
	FIBER_REQUIRE((sp & 7u) == 4u, 'A');
	FIBER_REQUIRE(sp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE(sp < ctx->boot.stack_top, 'T');
	uintptr_t required_bytes = (uintptr_t)FIBER_PORT_SW_FRAME_BYTES
			+ (uintptr_t)FIBER_EXC_BASE_BYTES;
	FIBER_REQUIRE((ctx->boot.stack_top - sp) >= required_bytes, 'X');

	const uint32_t *const words = (const uint32_t *)sp;
# if FIBER_PORT_IS_BASELINE
	const uint32_t exc_return = words[0];
# else
	const uint32_t exc_return = words[8];
# endif

	FIBER_REQUIRE((exc_return & 0xFF000000u) == 0xFF000000u, 'x');
	FIBER_REQUIRE((exc_return & 0x0Cu) == 0x0Cu, 'x');
# if !FIBER_HAS_EXTENDED_FP_CONTEXT
	FIBER_REQUIRE((exc_return & 0x10u) != 0u, 'x');
# endif

# if FIBER_HAS_EXTENDED_FP_CONTEXT
	if ((exc_return & 0x10u) == 0u) {
		required_bytes += (uintptr_t)FIBER_PORT_HIGH_FP_FRAME_BYTES
				+ (uintptr_t)FIBER_EXC_FP_EXT_BYTES;
	}
# endif

	FIBER_REQUIRE((ctx->boot.stack_top - sp) >= required_bytes, 'X');
#else
	(void)ctx;
#endif
}

void fiber_internal_port_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                                 void *user)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(fiber_internal_port_current_context == 0, 'k');
	FIBER_REQUIRE(pick_next != 0, 'K');

	__DMB();
	fiber_internal_port_scheduler_user = user;
	__DMB();
	fiber_internal_port_scheduler_pick_next = pick_next;
	__DMB();
}

FiberContext *fiber_internal_scheduler_pick_next_from_pendsv(FiberContext *current)
{
	FiberSchedulerPickNextFn const pick_next = fiber_internal_port_scheduler_pick_next;
	__DMB();
	void *const user = fiber_internal_port_scheduler_user;

	FIBER_REQUIRE(current != 0, 'C');
	FIBER_REQUIRE(pick_next != 0, 'K');

	FiberContext *const next = pick_next(current, user);

	fiber_internal_validate_restore_context(next);

	__DMB();
	fiber_internal_port_current_context = next;
	__DMB();

	return next;
}

#undef FIBER_PORT_HIGH_FP_FRAME_BYTES
#undef FIBER_PORT_SW_FRAME_BYTES
