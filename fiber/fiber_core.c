/* fiber_core.c - common cooperative fiber runtime.
 *
 * CPU-specific context-frame layout, first-start mechanics, and PendSV assembly
 * live behind the selected port boundary. This file owns the portable API
 * preconditions and delegates architecture behavior to fiber/port.
 */

#include "fiber_core.h"
#include "fiber_boot.h"
#include "fiber_runtime_state.h"
#include "port/fiber_port_selected.h"

FIBER_STATIC_ASSERT(offsetof(FiberContext, sp) == 0, "sp must be at offset 0");

/* Safety net if a task ever returns from its entry function */
FIBER_NORETURN FIBER_ATTR_SENSITIVE void fiber_internal_task_return(void) { fiber_panic('R'); }

/* ---------------- Paranoid seed builder ----------------
 * Common code validates inputs and stack bounds. The selected port owns the
 * actual CPU software-frame layout under the synthetic hardware exception frame.
 */
void fiber_init(FiberContext* const ctx, void* const stack_begin, void* const stack_end,
		const entry_t entry, void* const arg)
{
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* -------- basic nullness and monotonicity -------- */
	FIBER_REQUIRE(ctx         != NULL, 'C');
	FIBER_REQUIRE(stack_begin != NULL, 'B');
	FIBER_REQUIRE(stack_end   != NULL, 'T');
	FIBER_REQUIRE(entry       != NULL, 'E');
	FIBER_REQUIRE(stack_end > stack_begin, 'N');

	/* -------- entry must be Thumb and plausibly executable -------- */
	{
		const uintptr_t ea = (uintptr_t)entry;
		FIBER_REQUIRE((ea & 1u) == 1u, 'e');  /* Thumb bit */
		FIBER_REQUIRE(fiber_addr_plausible_code(ea & ~(uintptr_t)1u) != 0, 'c');
	}

	/* -------- obtain sealed boot plan from your existing factory -------- */
	ctx->boot = fiber_create_boot(stack_begin, stack_end, entry, arg);

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* -------- top must satisfy the selected port and AAPCS alignment -------- */
	FIBER_REQUIRE((((uintptr_t)ctx->boot.stack_top) &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'a');

	/* -------- ensure enough space for the synthetic initial context -------- */
	{
		const size_t need_seed = (size_t)FIBER_PORT_INITIAL_CONTEXT_BYTES;
		FIBER_REQUIRE(ctx->boot.avail >= need_seed, 'Z');
	}

#if FIBER_STACK_CANARY
	/* Keep the software canary as an independent check even when PSPLIM exists. */
	{
		const uintptr_t canary_cell = fiber_word_align_up((uintptr_t)ctx->boot.begin);
		((volatile uint32_t*)canary_cell)[0] =
				FIBER_INTERNAL_STACK_CANARY_VALUE;
		{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	}
#endif

	fiber_port_init_context_frame(ctx);

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* Intentionally expect sp % 8 == 4 after placing SW area.
	 * After removing SW area in PendSV, PSP will be 8-byte aligned exactly at HW frame. */
	FIBER_REQUIRE((((uintptr_t)ctx->sp) & 7u) == (uintptr_t)FIBER_PORT_SAVED_SP_MOD8, 'A');

	/* The initial saved context includes one basic hardware exception frame. */
	FIBER_REQUIRE((uintptr_t)ctx->sp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE((uintptr_t)ctx->sp <=
			ctx->boot.stack_top - (uintptr_t)FIBER_EXC_BASE_BYTES, 'S');

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
}

FiberContext* fiber_current(void)
{
	return fiber_port_load_current_context();
}

FIBER_NORETURN
void fiber_start(void)
{
	fiber_env_check();

	FIBER_REQUIRE(fiber_port_scheduler_is_configured() != 0u, 'K');
	FIBER_REQUIRE(fiber_current() == NULL, 'k');
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
#if FIBER_PORT_HAS_BASEPRI
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
#endif
#if FIBER_PORT_HAS_FAULTMASK
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
#endif

	/* FreeRTOS-style ownership: first start configures and validates its handlers. */
	fiber_pendsv_init_lowest_priority();

	fiber_platform_bootstrap();

	FiberContext *const first = fiber_internal_scheduler_pick_first_from_start();

	fiber_boot_check(&first->boot);

#if FIBER_PORT_USES_PSPLIM_REGISTER
	fiber_port_psplim_config((uint32_t)first->boot.stack_base);
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	FIBER_REQUIRE(fiber_port_psplim_read() == (uint32_t)first->boot.stack_base, 'L');
#endif

	const uintptr_t msp_top = fiber_boot_prepare_msp_for_start(&first->boot);
	fiber_internal_validate_restore_context(first);

	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
#if FIBER_PORT_HAS_BASEPRI
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
#endif
#if FIBER_PORT_HAS_FAULTMASK
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
#endif

	fiber_port_seed_current_context(first);
	fiber_port_start_first_context(msp_top);
	FIBER_UNREACHABLE();
}

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next, void *user)
{
	fiber_port_set_scheduler_pick_next(pick_next, user);
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
	/* The selected port invokes the common current-owner guard in historical
	 * failure order between its Thread-mode and interrupt-mask checks. */
	fiber_port_require_schedule_environment();
	fiber_port_request_schedule();
}
#if !FIBER_PENDSV_VECTOR_DIRECT
# ifndef FIBER_PENDSV_WIRED
FIBER_DIAG_WARN("[fiber]: user must wire PendSV_Handler to branch to fiber_pendsv without clobbering LR; define FIBER_PENDSV_WIRED=1 after you do it");
# endif /* FIBER_PENDSV_WIRED */
#endif /* !FIBER_PENDSV_VECTOR_DIRECT */
