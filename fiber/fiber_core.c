/* pendvswitch.c - FreeRTOS-style cooperative PendSV with PSPLIM and robust FPU gates
 *
 * This file implements a FreeRTOS-like PendSV context switch for STM32/Cortex-M
 * targets, with STM32H7/Cortex-M7 as the primary validated path. See README.md
 * and FREERTOS_SUPPORT_PLAN.md for the current support matrix.
 * Design goals:
 *   - Correct stack math for v6-M, v7-M, v7E-M and v8-M Mainline paths.
 *   - Extended FP gates: save/restore S16..S31 only when an extended frame is present (LR bit4 == 0).
 *   - PSPLIM update only when the selected security policy allows PSPLIM register access.
 *   - v8-M Baseline/Mainline security variants and MVE/PAC/BTI are runtime-gated until validated.
 *   - Paranoid runtime checks in fiber_init() to catch configuration errors early.
 *
 * Code comments are intentionally exhaustive and in English.
 */

#include "fiber_core.h"
#include "fiber_boot.h"
#include "port/fiber_port.h"

BT_STATIC_ASSERT(offsetof(FiberContext, sp) == 0, "sp must be at offset 0");

/* Safety net if a task ever returns from its entry function */
FIBER_NORETURN FIBER_ATTR_SENSITIVE void fiber_internal_task_return(void) { fiber_panic('R'); }

/*
 * Transitional fallback for ports whose frame builder has not been moved into a
 * concrete port source yet. ARMv7E-M and ARMv6-M already own this in their port
 * files. This block should shrink as v2 ports become real FreeRTOS-style units.
 */
#if !FIBER_PORT_ARMV7EM && !FIBER_PORT_ARMV6M
void fiber_port_init_context_frame(FiberContext * const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_boot_check(&ctx->boot);

	uint32_t *sp = (uint32_t *)(ctx->boot.stack_top - (uintptr_t)FIBER_EXC_PER_LEVEL);

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	*(--sp) = fiber_port_initial_xpsr();
	*(--sp) = fiber_port_stacked_pc((uintptr_t)ctx->boot.entry);
	*(--sp) = ((uint32_t)(uintptr_t)&fiber_internal_task_return) | 1u;
	*(--sp) = 0u; /* R12 */
	*(--sp) = 0u; /* R3  */
	*(--sp) = 0u; /* R2  */
	*(--sp) = 0u; /* R1  */
	*(--sp) = (uint32_t)(uintptr_t)ctx->boot.arg;

#if FIBER_PORT_IS_BASELINE
	/* v8-M Baseline transitional layout, low to high: [LR][r4..r7][r8..r11]. */
	*(--sp) = 0u;                    /* r11 */
	*(--sp) = 0u;                    /* r10 */
	*(--sp) = fiber_port_read_r9();  /* r9  */
	*(--sp) = 0u;                    /* r8  */
	*(--sp) = 0u;                    /* r7  */
	*(--sp) = 0u;                    /* r6  */
	*(--sp) = 0u;                    /* r5  */
	*(--sp) = 0u;                    /* r4  */
	*(--sp) = FIBER_INITIAL_EXC_RETURN;
#else
	/* Mainline transitional layout, low to high: [r4..r11][LR]. */
	*(--sp) = FIBER_INITIAL_EXC_RETURN;
	*(--sp) = 0u;                    /* r11 */
	*(--sp) = 0u;                    /* r10 */
	*(--sp) = fiber_port_read_r9();  /* r9  */
	*(--sp) = 0u;                    /* r8  */
	*(--sp) = 0u;                    /* r7  */
	*(--sp) = 0u;                    /* r6  */
	*(--sp) = 0u;                    /* r5  */
	*(--sp) = 0u;                    /* r4  */
#endif

	ctx->sp = sp;

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
}
#endif /* !FIBER_PORT_ARMV7EM && !FIBER_PORT_ARMV6M */

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

#if FIBER_SWITCH_MASK_IRQS
static inline uint32_t fiber_primask_save_disable_local(void)
{
	uint32_t pm;
	__ASM volatile(
			"mrs %0, primask \n"
			"cpsid i         \n"
			: "=r"(pm)
			:
			: "memory");
	{ __DSB(); __ISB(); }
	return pm;
}

static inline void fiber_primask_restore_local(uint32_t pm)
{
	{ __DSB(); __ISB(); }
	__ASM volatile("msr primask, %0" :: "r"(pm) : "memory");
	{ __DSB(); __ISB(); }
}
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
	const uint32_t pm = fiber_primask_save_disable_local();
#endif

	fiber_port_pend_switch();

#if FIBER_SWITCH_MASK_IRQS
	fiber_primask_restore_local(pm);
#else
	{ __DSB(); __ISB(); }
#endif
}




/* --------- PendSV: FreeRTOS pattern + PSPLIM update on v8-M ---------
 * Every line is commented to make instruction intent obvious during audits.
 */

/* Safe constant for "to->boot.stack_base" offset in ASM (avoid nested-designator offsetof) */
enum {
	OFF_TO_PSLIM = offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_base),
	OFF_TO_STACK_TOP = offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_top)
};

BT_STATIC_ASSERT(OFF_TO_PSLIM < 4096, "OFF_TO_PSLIM must fit Thumb-2 LDR imm12");
BT_STATIC_ASSERT(OFF_TO_STACK_TOP < 4096, "OFF_TO_STACK_TOP must fit Thumb-2 LDR imm12");

#if !FIBER_PORT_ARMV7EM && !FIBER_PORT_ARMV6M
FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void)
{
#if FIBER_PORT_IS_BASELINE
	/* ------------------------ Cortex-M0/M0+ / v8-M Baseline ------------------------ */
	__ASM volatile(
			".syntax unified                         \n"

			/* ----------------------------------------------------------------------
			 * Prologue: get PSP and sync pipeline
			 * ---------------------------------------------------------------------- */
			"mrs   r0, psp                          \n" /* r0 = PSP */
#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"  /* (optional) serialize before branch */
#else
			"dmb                                    \n"
#endif /* FIBER_SWITCH_STRICT_BARRIERS */
			"isb                                    \n" /* sync pipeline before touching stack memory */

			/* ----------------------------------------------------------------------
			 * Load runtime-owned current context.
			 * ---------------------------------------------------------------------- */
			/* Transitional baseline fallback: use active EXC_RETURN bit 2,
			 * not CONTROL.SPSEL, to prove the interrupted Thread used PSP.
			 */
			"movs  r2, #4                           \n"
			"mov   r3, lr                           \n"
			"tst   r3, r2                           \n" /* interrupted Thread context must use PSP */
			"beq   6f                               \n" /* foreign/pre-start PendSV used MSP */

			"ldr   r1, =fiber_internal_port_current_context \n" /* r1 = &current context */
			"ldr   r1, [r1]                         \n" /* r1 = current context */
			"cmp   r1, #0                           \n" /* Thumb-1 safe null check */
			"beq   5f                               \n" /* no current is a fatal port state */

			"ldr   r2, [r1, %c[offsb]]              \n" /* r2 = current->boot.stack_base */
			"cmp   r0, r2                           \n"
			"blo   7f                               \n" /* PSP is already below stack base */
			"mov   r3, r0                           \n"
			"subs  r3, #36                          \n" /* core software frame */
			"bcc   7f                               \n"
			"cmp   r3, r2                           \n"
			"blo   7f                               \n" /* software frame would cross stack base */
			"ldr   r2, [r1, %c[offtop]]             \n" /* r2 = current->boot.stack_top */
			"cmp   r0, r2                           \n"
			"bhi   7f                               \n" /* PSP above declared stack top */

			/* ----------------------------------------------------------------------
			 * Save current context.
			 * SW layout low->high: [LR][r4..r7][r8..r11]
			 * ARMv6-M lacks STMDB, so do manual pre-decrement + STMIA.
			 * ---------------------------------------------------------------------- */
			/* Reserve SW area (9 words = 36 bytes): [LR][r4..r7][r8..r11] */
			"subs  r0, #36                          \n" /* r0 = base of SW area */
			"mov   r2, r0                           \n" /* r2 = base until publication */

			/* Save LR(EXC_RETURN) and r4..r7 at [base+0..20). */
			"mov   r3, lr                           \n"
			"stmia r0!, {r3-r7}                     \n" /* r0 now points to [base+20] */

			/* Stage and save r8..r11 at [base+20..36). */
			"mov   r4, r8                           \n"
			"mov   r5, r9                           \n"
			"mov   r6, r10                          \n"
			"mov   r7, r11                          \n"
			"stmia r0!, {r4-r7}                     \n" /* r0 now points to HW frame */

			/* current->sp = base (publish only after the full SW frame is stored). */
			"str   r2, [r1]                         \n"

			FBR_ASM_ENTER_SCHEDULER_CRITICAL
			/* Ask the scheduler bridge for the next context. */
			"mov   r0, r1                           \n" /* arg0 = current */
			"bl    fiber_internal_scheduler_pick_next_from_pendsv \n"
			FBR_ASM_EXIT_SCHEDULER_CRITICAL
			"mov   r2, r0                           \n" /* r2 = selected next context */

			/* ----------------------------------------------------------------------
			 * Restore selected context: [LR][r4..r7][r8..r11]
			 * ---------------------------------------------------------------------- */
			"ldr   r0, [r2]                         \n" /* r0 = target->sp (base) */
			"adds  r0, #20                          \n" /* move to staged high regs */
			"ldmia r0!, {r4-r7}                     \n" /* restore staged r8..r11 */
			"mov   r8,  r4                          \n"
			"mov   r9,  r5                          \n"
			"mov   r10, r6                          \n"
			"mov   r11, r7                          \n"

			/* r0 is now base+36, the target HW frame. */
			"msr   psp, r0                          \n" /* PSP := start of HW frame for 'to' */
			"subs  r0, #36                          \n" /* move back to saved LR/r4-r7 */
			"ldmia r0!, {r3-r7}                     \n" /* r3 = EXC_RETURN; r4-r7 restored */
			"mov   lr, r3                           \n"

			/* ----------------------------------------------------------------------
			 * Keep to->sp pointing at the saved SW frame. It is updated only when
			 * that context is saved as the source, like FreeRTOS pxTopOfStack.
			 * This generic baseline path does not program PSPLIM; M23
			 * PSPLIM/security variants are not validated yet.
			 * ---------------------------------------------------------------------- */
			"isb                                    \n" /* sync before exception return */

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"  /* (optional) serialize before branch */
#else
			"dmb                                    \n"
#endif /* FIBER_SWITCH_STRICT_BARRIERS */

			"isb                                    \n" /* synchronize */

			/* ----------------------------------------------------------------------
			 * Return from exception using EXC_RETURN in LR
			 * ---------------------------------------------------------------------- */
			"bx    lr                               \n" /* exception return */

			/* ----------------------------------------------------------------------
			 * Fatal port state: scheduler path entered without a current context.
			 * ---------------------------------------------------------------------- */
			"5:                                     \n"
			"movs  r0, #67                          \n" /* 'C' */
			"bl    fiber_panic                      \n"
			"b     5b                               \n"

			"6:                                     \n"
			"movs  r0, #106                         \n" /* 'j' */
			"bl    fiber_panic                      \n"
			"b     6b                               \n"

			"7:                                     \n"
			"movs  r0, #100                         \n" /* 'd' */
			"bl    fiber_panic                      \n"
			"b     7b                               \n"
			:
			: [offsb] "I" (OFF_TO_PSLIM),
			  [offtop] "I" (OFF_TO_STACK_TOP)
			: "memory","cc"
	);
#else
	/* ------------------------ Non-ARMv7E-M Mainline fallback ---------------------- */
	__ASM volatile(
			".syntax unified                         \n"

			/* ----------------------------------------------------------------------
			 * Prologue: get PSP and sync pipeline
			 * ---------------------------------------------------------------------- */
			"mrs   r0, psp                          \n" /* r0 = PSP */

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"  /* (optional) serialize before branch */
#else
			"dmb                                    \n"
#endif /* FIBER_SWITCH_STRICT_BARRIERS */
			"isb                                    \n" /* synchronize */

			/* ----------------------------------------------------------------------
			 * Load runtime-owned current context.
			 * ---------------------------------------------------------------------- */
			/* Transitional mainline fallback: use active EXC_RETURN bit 2,
			 * not CONTROL.SPSEL, to prove the interrupted Thread used PSP.
			 */
			"tst   lr, #4                           \n" /* interrupted Thread context must use PSP */
			"beq   6f                               \n" /* foreign/pre-start PendSV used MSP */

			"ldr   r1, =fiber_internal_port_current_context \n" /* r1 = &current context */
			"ldr   r1, [r1]                         \n" /* r1 = current context */
			"cmp   r1, #0                           \n"
			"beq   5f                               \n" /* no current is a fatal port state */

			"ldr   r2, [r1, %c[offsb]]              \n" /* r2 = current->boot.stack_base */
			"cmp   r0, r2                           \n"
			"blo   7f                               \n" /* PSP is already below stack base */
			"mov   r3, r0                           \n"
#if FIBER_HAS_EXTENDED_FP_CONTEXT
			"tst   lr, #0x10                        \n" /* extended FP save needs 64 more bytes */
			"bne   8f                               \n"
			"subs  r3, #64                          \n"
			"bcc   7f                               \n"
			"8:                                     \n"
#endif /* FIBER_HAS_EXTENDED_FP_CONTEXT */
			"subs  r3, #36                          \n" /* core software frame */
			"bcc   7f                               \n"
			"cmp   r3, r2                           \n"
			"blo   7f                               \n" /* software frame would cross stack base */
			"ldr   r2, [r1, %c[offtop]]             \n" /* r2 = current->boot.stack_top */
			"cmp   r0, r2                           \n"
			"bhi   7f                               \n" /* PSP above declared stack top */

			/* ----------------------------------------------------------------------
			 * Save current context.
			 * Save r4..r11 and EXC_RETURN; optionally save S16..S31 if extended FP frame
			 * ---------------------------------------------------------------------- */
#if FIBER_HAS_EXTENDED_FP_CONTEXT
			/* SAVE high FP regs S16..S31 iff extended frame present (LR.bit4 == 0) */
			"tst   lr, #0x10                        \n" /* 1 => base frame only, 0 => extended present */
			"bne   2f                               \n" /* if bit4==1 then skip FP save */
			"vstmdb r0!, {s16-s31}                  \n" /* push S16..S31 */
			"2:                                     \n" /* label: skip-fpu-save */
#endif /* FIBER_HAS_EXTENDED_FP_CONTEXT */

			"stmdb r0!, {r4-r11, r14}               \n" /* push r4..r11 and LR(EXC_RETURN) */
			"str   r0, [r1]                         \n" /* current->sp = r0 */

			FBR_ASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n" /* arg0 = current */
			"bl    fiber_internal_scheduler_pick_next_from_pendsv \n"
			FBR_ASM_EXIT_SCHEDULER_CRITICAL
			"mov   r2, r0                           \n" /* r2 = selected next context */

			/* ----------------------------------------------------------------------
			 * Restore selected context: [r4..r11][r14]
			 * ---------------------------------------------------------------------- */
			"ldr   r0, [r2]                         \n" /* r0 = target->sp */
			"ldmia r0!, {r4-r11, r14}               \n" /* pop r4..r11 and LR(EXC_RETURN) */

#if FIBER_USE_PSPLIM_REGISTER
			/* ----------------------------------------------------------------------
			 * Program PSPLIM on v8-M Mainline (protect PSP lower bound)
			 * ---------------------------------------------------------------------- */
			"ldr   r3, [r2, %c[offsb]]              \n" /* r3 = to->boot.stack_base */
			FBR_ASM_MSR_PSPLIM("r3")                    /* write PSPLIM */
			"dsb                                    \n" /* ensure memory effects complete */
			"isb                                    \n" /* synchronize pipeline */
#endif /* FIBER_USE_PSPLIM_REGISTER */

#if FIBER_HAS_EXTENDED_FP_CONTEXT
			/* RESTORE high FP regs if target wants extended FP frame (LR bit4 == 0) */
			"tst   r14, #0x10                       \n" /* check target EXC_RETURN */
			"bne   3f                               \n" /* if bit4==1 then skip FP restore */
			"vldmia r0!, {s16-s31}                  \n" /* pop S16..S31 */
			"3:                                     \n" /* label: skip-fpu-restore */
#endif /* FIBER_HAS_EXTENDED_FP_CONTEXT */

			/* ----------------------------------------------------------------------
			 * Program PSP to target HW frame.
			 * Keep to->sp pointing at the saved SW frame, FreeRTOS pxTopOfStack style.
			 * It is updated only when that context is saved as the source.
			 * ---------------------------------------------------------------------- */
			"msr   psp, r0                          \n" /* PSP := start of HW frame for 'to' */
			"isb                                    \n" /* synchronize before exception return */

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"  /* (optional) serialize before branch */
#else
			"dmb                                    \n"
#endif /* FIBER_SWITCH_STRICT_BARRIERS */

			"isb                                    \n" /* synchronize */

			/* ----------------------------------------------------------------------
			 * Return from exception using EXC_RETURN in r14
			 * ---------------------------------------------------------------------- */
			"bx    r14                              \n" /* exception return to Thread mode via PSP */

			/* ----------------------------------------------------------------------
			 * Fatal port state: scheduler path entered without a current context.
			 * ---------------------------------------------------------------------- */
			"5:                                     \n"
			"movs  r0, #67                          \n" /* 'C' */
			"bl    fiber_panic                      \n"
			"b     5b                               \n"

			"6:                                     \n"
			"movs  r0, #106                         \n" /* 'j' */
			"bl    fiber_panic                      \n"
			"b     6b                               \n"

			"7:                                     \n"
			"movs  r0, #100                         \n" /* 'd' */
			"bl    fiber_panic                      \n"
			"b     7b                               \n"
			:
			: [offsb] "I" (OFF_TO_PSLIM),
			  [offtop] "I" (OFF_TO_STACK_TOP),
			  [sched_basepri] "i" (FIBER_SCHEDULER_BASEPRI)
			  : "memory","cc"
	);
#endif

}
#endif /* !FIBER_PORT_ARMV7EM */

#if !FIBER_PENDSV_VECTOR_DIRECT
# ifndef FIBER_PENDSV_WIRED
FIBER_DIAG_WARN("[fiber]: user must wire PendSV_Handler to branch to fiber_pendsv without clobbering LR; define FIBER_PENDSV_WIRED=1 after you do it");
# endif /* FIBER_PENDSV_WIRED */
#endif /* !FIBER_PENDSV_VECTOR_DIRECT */
