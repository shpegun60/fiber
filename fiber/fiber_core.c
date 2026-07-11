/* fiber_core.c - common cooperative fiber runtime.
 *
 * CPU-specific context-frame layout, first-start mechanics, and PendSV assembly
 * live behind the selected port boundary. This file owns the portable API
 * preconditions and delegates architecture behavior to fiber/port.
 */

#include "fiber_core.h"
#include "fiber_boot.h"
#include "port/fiber_port.h"

BT_STATIC_ASSERT(offsetof(FiberContext, sp) == 0, "sp must be at offset 0");

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

	/* -------- top must be 8-byte aligned (AAPCS) -------- */
	FIBER_REQUIRE((((uintptr_t)ctx->boot.stack_top) & 7u) == 0u, 'a');

	/* -------- ensure enough space for seed frames --------
	 * We require:
	 *   - FIBER_EXC_PER_LEVEL bytes headroom (one full HW exception level as defined by your platform)
	 *   - one "real" HW frame we build (always base 8 regs = FIBER_EXC_BASE_BYTES)
	 *   - port-owned software frame
	 */
	{
		const size_t need_seed = (size_t)FIBER_EXC_PER_LEVEL
				+ (size_t)FIBER_EXC_BASE_BYTES
				+ (size_t)FIBER_PORT_SOFTWARE_FRAME_BYTES;
		FIBER_REQUIRE(ctx->boot.avail >= need_seed, 'Z');
	}

#if defined(FIBER_STACK_CANARY) && !FIBER_USE_PSPLIM_REGISTER
	/* Write a canary at the low PSP bound if PSPLIM is unavailable on this core. */
	{
		const uintptr_t canary_cell = fiber_word_align_up((uintptr_t)ctx->boot.begin);
		((volatile uint32_t*)canary_cell)[0] = FIBER_CANARY_VALUE;
		{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	}
#endif

	fiber_port_init_context_frame(ctx);

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* Intentionally expect sp % 8 == 4 after placing SW area.
	 * After removing SW area in PendSV, PSP will be 8-byte aligned exactly at HW frame. */
	FIBER_REQUIRE((((uintptr_t)ctx->sp) & 7u) == (uintptr_t)FIBER_PORT_SAVED_SP_MOD8, 'A');

	/* Ensure PSP is inside declared PSP region [stack_base, stack_top - HW_headroom] */
	FIBER_REQUIRE((uintptr_t)ctx->sp >= ctx->boot.stack_base, 'U');
	FIBER_REQUIRE((uintptr_t)ctx->sp <= ctx->boot.stack_top - (uintptr_t)FIBER_EXC_PER_LEVEL, 'S');

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
}

FiberContext* fiber_current(void)
{
	return fiber_port_load_current_context();
}

FIBER_NORETURN
void fiber_start(FiberContext* const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(ctx->boot.sealed != 0u, 's');
	FIBER_REQUIRE(fiber_port_scheduler_is_configured() != 0u, 'K');
	FIBER_REQUIRE(fiber_current() == NULL, 'k');

	fiber_exception_runtime_check();

#if FIBER_START_USE_SVC
	fiber_env_check();
	fiber_boot_check(&ctx->boot);
	fiber_platform_bootstrap();

# if FIBER_USE_PSPLIM_REGISTER
	fiber_psplim_config((uint32_t)ctx->boot.stack_base);
	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
	FIBER_REQUIRE(fiber_get_psplim() == (uint32_t)ctx->boot.stack_base, 'L');
# endif

	const uintptr_t msp_top = fiber_boot_prepare_msp_for_start(&ctx->boot);
	fiber_internal_validate_restore_context(ctx);

	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
# if FIBER_HAS_BASEPRI
	FIBER_REQUIRE(__get_BASEPRI() == 0u, 'b');
# endif
# if FIBER_HAS_FAULTMASK
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
# endif

	fiber_port_seed_current_context(ctx);
	fiber_port_start_first_context(msp_top);
#else
	fiber_port_seed_current_context(ctx);

	fiber_boot(&ctx->boot);
#endif
	FIBER_UNREACHABLE();
}

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next, void *user)
{
	fiber_port_set_scheduler_pick_next(pick_next, user);
}

/* --------------------------------------------------------------------------
 * fiber_schedule: robust cooperative scheduler trigger
 *
 * Goals:
 *  - Enter only from Thread mode.
 *  - Require a seeded runtime-owned current context.
 *  - Reject calls that would silently defer PendSV behind interrupt masks.
 *  - Keep scheduler policy outside the core; PendSV calls the configured bridge.
 *  - Keep barriers conservative to avoid reordering surprises
 * -------------------------------------------------------------------------- */

#ifndef FIBER_SWITCH_MASK_IRQS
/* 0 = do not touch PRIMASK; 1 = mask IRQs during slot update */
# define FIBER_SWITCH_MASK_IRQS 1
#endif

void fiber_schedule(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');  /* fiber_schedule is a Thread-mode API */
	FIBER_REQUIRE(fiber_current() != NULL, 'G');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p'); /* do not defer the scheduler jump */
#if FIBER_HAS_BASEPRI
	FIBER_REQUIRE(__get_BASEPRI() == 0u, 'b'); /* do not defer PendSV behind BASEPRI */
#endif
#if FIBER_HAS_FAULTMASK
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f'); /* do not defer PendSV behind FAULTMASK */
#endif

#if FIBER_SWITCH_MASK_IRQS
	const uint32_t pm = fiber_port_primask_save_disable();
#endif

	fiber_port_pend_switch();

#if FIBER_SWITCH_MASK_IRQS
	fiber_port_primask_restore(pm);
#else
	{ __DSB(); __ISB(); }
#endif
}
#if !FIBER_PENDSV_VECTOR_DIRECT
# ifndef FIBER_PENDSV_WIRED
FIBER_DIAG_WARN("[fiber]: user must wire PendSV_Handler to branch to fiber_pendsv without clobbering LR; define FIBER_PENDSV_WIRED=1 after you do it");
# endif /* FIBER_PENDSV_WIRED */
#endif /* !FIBER_PENDSV_VECTOR_DIRECT */
