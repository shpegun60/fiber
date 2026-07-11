/*
 * fiber_port_armv7m.c
 *
 * ARMv7-M PendSV port.
 *
 * This file owns the Cortex-M3 mainline PendSV implementation. The port is
 * compile-covered only; hardware validation is still required before claiming
 * runtime support on a specific STM32 ARMv7-M target.
 */

#include "../fiber_port.h"

#if FIBER_PORT_ARMV7M

enum {
	FBR_OFF_STACK_BASE = offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_base),
	FBR_OFF_STACK_TOP = offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_top)
};

BT_STATIC_ASSERT(FBR_OFF_STACK_BASE < 4096, "FBR_OFF_STACK_BASE must fit Thumb-2 LDR imm12");
BT_STATIC_ASSERT(FBR_OFF_STACK_TOP < 4096, "FBR_OFF_STACK_TOP must fit Thumb-2 LDR imm12");

void fiber_port_init_context_frame(FiberContext * const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_boot_record_check(&ctx->boot);

	uint32_t *sp = (uint32_t *)(ctx->boot.stack_top - (uintptr_t)FIBER_EXC_PER_LEVEL);

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }

	/* Hardware exception frame, low address after software frame restore. */
	*(--sp) = fiber_port_initial_xpsr();
	*(--sp) = fiber_port_stacked_pc((uintptr_t)ctx->boot.entry);
	*(--sp) = ((uint32_t)(uintptr_t)&fiber_internal_task_return) | 1u;
	*(--sp) = 0u; /* R12 */
	*(--sp) = 0u; /* R3  */
	*(--sp) = 0u; /* R2  */
	*(--sp) = 0u; /* R1  */
	*(--sp) = (uint32_t)(uintptr_t)ctx->boot.arg;

	/* ARMv7-M software frame, low to high: [r4..r11][LR(EXC_RETURN)]. */
	*(--sp) = FIBER_INITIAL_EXC_RETURN;
	*(--sp) = 0u;                    /* r11 */
	*(--sp) = 0u;                    /* r10 */
	*(--sp) = fiber_port_read_r9();  /* r9  */
	*(--sp) = 0u;                    /* r8  */
	*(--sp) = 0u;                    /* r7  */
	*(--sp) = 0u;                    /* r6  */
	*(--sp) = 0u;                    /* r5  */
	*(--sp) = 0u;                    /* r4  */

	ctx->sp = sp;

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
}

/*
 * ARMv7-M PendSV implementation.
 *
 * Cortex-M3 is mainline without high FP context. It uses the same FreeRTOS-style
 * BASEPRI-protected scheduler bridge discipline as other BASEPRI-capable ports.
 */
FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void)
{
	__ASM volatile(
			".syntax unified                         \n"

			/* ----------------------------------------------------------------------
			 * Prologue: get PSP and sync pipeline.
			 * ---------------------------------------------------------------------- */
			"mrs   r0, psp                          \n" /* r0 = PSP */

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"
#else
			"dmb                                    \n"
#endif /* FIBER_SWITCH_STRICT_BARRIERS */
			"isb                                    \n"

			/* ----------------------------------------------------------------------
			 * Load runtime-owned current context.
			 * ---------------------------------------------------------------------- */
			/* In Handler mode, EXC_RETURN is the source of truth for the
			 * interrupted stack. Do not use CONTROL.SPSEL as the PendSV proof.
			 */
			"tst   lr, #4                           \n" /* interrupted Thread context must use PSP */
			"beq   91f                              \n" /* foreign/pre-start PendSV used MSP */

			"ldr   r1, =fiber_internal_port_current_context \n"
			"ldr   r1, [r1]                         \n" /* r1 = current context */
			"cmp   r1, #0                           \n"
			"beq   90f                              \n" /* no current is fatal */

			"ldr   r2, [r1, %c[offsb]]              \n" /* r2 = current->boot.stack_base */
			"cmp   r0, r2                           \n"
			"blo   92f                              \n" /* PSP is already below stack base */
			"mov   r3, r0                           \n"
			"subs  r3, #%c[swbytes]                 \n" /* core software frame */
			"bcc   92f                              \n"
			"cmp   r3, r2                           \n"
			"blo   92f                              \n" /* software frame would cross stack base */
			"ldr   r2, [r1, %c[offtop]]             \n" /* r2 = current->boot.stack_top */
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n" /* PSP above declared stack top */

			/* ----------------------------------------------------------------------
			 * Save current context: [r4..r11][LR(EXC_RETURN)].
			 * ---------------------------------------------------------------------- */
			"stmdb r0!, {r4-r11, r14}               \n"
			"str   r0, [r1]                         \n" /* current->sp = complete SW frame */

			FBR_ASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n" /* arg0 = current */
			"bl    fiber_internal_scheduler_pick_next_from_pendsv \n"
			FBR_ASM_EXIT_SCHEDULER_CRITICAL

			"mov   r2, r0                           \n" /* r2 = selected next */

			/* ----------------------------------------------------------------------
			 * Restore selected context.
			 * ---------------------------------------------------------------------- */
			"ldr   r0, [r2]                         \n" /* r0 = target->sp */
			"ldmia r0!, {r4-r11, r14}               \n"

			"msr   psp, r0                          \n" /* PSP = target HW frame */
			"isb                                    \n"

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"
#else
			"dmb                                    \n"
#endif /* FIBER_SWITCH_STRICT_BARRIERS */
			"isb                                    \n"

			"bx    r14                              \n" /* exception return */

			/* ----------------------------------------------------------------------
			 * Fatal port states.
			 * ---------------------------------------------------------------------- */
			"90:                                    \n"
			"movs  r0, #67                          \n" /* 'C' */
			"bl    fiber_panic                      \n"
			"b     90b                              \n"

			"91:                                    \n"
			"movs  r0, #106                         \n" /* 'j' */
			"bl    fiber_panic                      \n"
			"b     91b                              \n"

			"92:                                    \n"
			"movs  r0, #100                         \n" /* 'd' */
			"bl    fiber_panic                      \n"
			"b     92b                              \n"
			:
			: [sched_basepri] "i" (FIBER_SCHEDULER_BASEPRI),
			  [swbytes] "I" (FIBER_PORT_SOFTWARE_FRAME_BYTES),
			  [offsb] "I" (FBR_OFF_STACK_BASE),
			  [offtop] "I" (FBR_OFF_STACK_TOP)
			: "memory","cc"
	);
}

#endif /* FIBER_PORT_ARMV7M */
