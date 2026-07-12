/*
 * fiber_runtime_state.c
 *
 * Runtime-owned port/scheduler state used by PendSV ports.
 */

#include "fiber_runtime_state.h"
#include "fiber_boot.h"
#include "port/fiber_port_selected.h"

FiberContext *volatile fiber_internal_port_current_context = 0;
FiberSchedulerPickNextFn volatile fiber_internal_port_scheduler_pick_next = 0;
void *volatile fiber_internal_port_scheduler_user = 0;
static volatile uint32_t fiber_internal_port_scheduler_selecting = 0;

#ifndef FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH
# define FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH 0
#endif

#if (FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH != 0) && \
		(FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH != 1)
# error "[fiber]: FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH must be 0 or 1"
#endif

#define FIBER_PORT_HIGH_FP_FRAME_BYTES (16u * 4u)

static void fiber_internal_validate_stack_canary(const FiberContext *ctx)
{
#if FIBER_STACK_CANARY
	const uintptr_t begin = (uintptr_t)ctx->boot.begin;
	const uintptr_t canary_cell = fiber_word_align_up(begin);

	FIBER_REQUIRE(canary_cell >= begin, 'c');
	FIBER_REQUIRE(canary_cell <= (UINTPTR_MAX - sizeof(uint32_t)), 'c');
	FIBER_REQUIRE((canary_cell + sizeof(uint32_t)) <= ctx->boot.stack_base, 'c');
	FIBER_REQUIRE(*(const volatile uint32_t *)canary_cell == FIBER_CANARY_VALUE, 'c');
#else
	(void)ctx;
#endif
}

FIBER_GENERAL_REGS_ONLY
void fiber_internal_validate_restore_context(FiberContext *ctx)
{
	FIBER_REQUIRE(ctx != 0, 'N');
	FIBER_REQUIRE(((uintptr_t)ctx & ((uintptr_t)_Alignof(FiberContext) - 1u)) == 0u,
			'A');
	FIBER_REQUIRE(ctx->sp != 0, 'P');
#if FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH
	fiber_boot_record_check(&ctx->boot);
#else
	fiber_boot_record_fast_check(&ctx->boot);
#endif
	fiber_internal_validate_stack_canary(ctx);

	const uintptr_t sp = (uintptr_t)ctx->sp;
	/* Saved SW frame alignment is selected-port specific. */
	FIBER_REQUIRE((sp & 7u) == (uintptr_t)FIBER_PORT_SAVED_SP_MOD8, 'A');
	FIBER_REQUIRE(sp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE(sp < ctx->boot.stack_top, 'T');
	uintptr_t required_bytes = (uintptr_t)FIBER_PORT_SOFTWARE_FRAME_BYTES
			+ (uintptr_t)FIBER_EXC_BASE_BYTES;
	FIBER_REQUIRE((ctx->boot.stack_top - sp) >= required_bytes, 'X');

	const uint32_t *const words = (const uint32_t *)sp;
	const uint32_t exc_return = words[FIBER_PORT_EXC_RETURN_WORD_INDEX];

	FIBER_REQUIRE(fiber_port_exc_return_is_valid(exc_return) != 0u, 'x');

#if FIBER_HAS_EXTENDED_FP_CONTEXT
	if ((exc_return & 0x10u) == 0u) {
		required_bytes += (uintptr_t)FIBER_PORT_HIGH_FP_FRAME_BYTES
				+ (uintptr_t)FIBER_EXC_FP_EXT_BYTES;
	}
#endif

	FIBER_REQUIRE((ctx->boot.stack_top - sp) >= required_bytes, 'X');
}

void fiber_internal_port_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                                 void *user)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(fiber_internal_port_current_context == 0, 'k');
	FIBER_REQUIRE(fiber_internal_port_scheduler_selecting == 0u, 'k');
	FIBER_REQUIRE(pick_next != 0, 'K');

	__DMB();
	fiber_internal_port_scheduler_user = user;
	__DMB();
	fiber_internal_port_scheduler_pick_next = pick_next;
	__DMB();
}

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_scheduler_pick_first_from_start(void)
{
	FiberSchedulerPickNextFn const pick_next = fiber_internal_port_scheduler_pick_next;
	__DMB();
	void *const user = fiber_internal_port_scheduler_user;

	FIBER_REQUIRE(pick_next != 0, 'K');

	__DMB();
	fiber_internal_port_scheduler_selecting = 1u;
	__DMB();

	const uint32_t critical_state = fiber_port_scheduler_critical_enter();
	FiberContext *const first = pick_next(0, user);

	fiber_internal_validate_restore_context(first);
	fiber_port_scheduler_critical_exit(critical_state);

	__DMB();
	fiber_internal_port_scheduler_selecting = 0u;
	__DMB();

	return first;
}

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_scheduler_pick_next_from_pendsv(FiberContext *current)
{
	FiberSchedulerPickNextFn const pick_next = fiber_internal_port_scheduler_pick_next;
	__DMB();
	void *const user = fiber_internal_port_scheduler_user;

	FIBER_REQUIRE(current != 0, 'C');
	FIBER_REQUIRE(pick_next != 0, 'K');
	fiber_internal_validate_restore_context(current);

	FiberContext *const next = pick_next(current, user);

	fiber_internal_validate_restore_context(next);

	__DMB();
	fiber_internal_port_current_context = next;
	__DMB();

	return next;
}

#undef FIBER_PORT_HIGH_FP_FRAME_BYTES
