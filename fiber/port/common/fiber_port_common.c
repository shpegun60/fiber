/*
 * fiber_port_common.c
 *
 * Transitional fallback implementation for Cortex-M profiles whose dedicated
 * FreeRTOS-style port split is not finished yet.
 *
 * This file is intentionally not a production support claim. It exists to keep
 * CPU-specific assembly out of the common runtime while v8-M ports are split
 * into concrete profile-owned sources.
 */

#include "../fiber_port.h"

#if FIBER_PORT_ARMV8M_BASELINE || FIBER_PORT_ARMV8M_MAINLINE || FIBER_PORT_ARMV81M_MAINLINE

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

FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void)
{
#if FIBER_PORT_IS_BASELINE
	__ASM volatile(
			".syntax unified                         \n"

			"mrs   r0, psp                          \n"
#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"
#else
			"dmb                                    \n"
#endif
			"isb                                    \n"

			"movs  r2, #4                           \n"
			"mov   r3, lr                           \n"
			"tst   r3, r2                           \n"
			"beq   6f                               \n"

			"ldr   r1, =fiber_internal_port_current_context \n"
			"ldr   r1, [r1]                         \n"
			"cmp   r1, #0                           \n"
			"beq   5f                               \n"

			"ldr   r2, [r1, %c[offsb]]              \n"
			"cmp   r0, r2                           \n"
			"blo   7f                               \n"
			"mov   r3, r0                           \n"
			"subs  r3, #36                          \n"
			"bcc   7f                               \n"
			"cmp   r3, r2                           \n"
			"blo   7f                               \n"
			"ldr   r2, [r1, %c[offtop]]             \n"
			"cmp   r0, r2                           \n"
			"bhi   7f                               \n"

			"subs  r0, #36                          \n"
			"mov   r2, r0                           \n"

			"mov   r3, lr                           \n"
			"stmia r0!, {r3-r7}                     \n"

			"mov   r4, r8                           \n"
			"mov   r5, r9                           \n"
			"mov   r6, r10                          \n"
			"mov   r7, r11                          \n"
			"stmia r0!, {r4-r7}                     \n"

			"str   r2, [r1]                         \n"

			FBR_ASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n"
			"bl    fiber_internal_scheduler_pick_next_from_pendsv \n"
			FBR_ASM_EXIT_SCHEDULER_CRITICAL
			"mov   r2, r0                           \n"

			"ldr   r0, [r2]                         \n"
			"adds  r0, #20                          \n"
			"ldmia r0!, {r4-r7}                     \n"
			"mov   r8,  r4                          \n"
			"mov   r9,  r5                          \n"
			"mov   r10, r6                          \n"
			"mov   r11, r7                          \n"

			"msr   psp, r0                          \n"
			"subs  r0, #36                          \n"
			"ldmia r0!, {r3-r7}                     \n"
			"mov   lr, r3                           \n"

			"isb                                    \n"

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"
#else
			"dmb                                    \n"
#endif

			"isb                                    \n"

			"bx    lr                               \n"

			"5:                                     \n"
			"movs  r0, #67                          \n"
			"bl    fiber_panic                      \n"
			"b     5b                               \n"

			"6:                                     \n"
			"movs  r0, #106                         \n"
			"bl    fiber_panic                      \n"
			"b     6b                               \n"

			"7:                                     \n"
			"movs  r0, #100                         \n"
			"bl    fiber_panic                      \n"
			"b     7b                               \n"
			:
			: [offsb] "I" (FBR_OFF_STACK_BASE),
			  [offtop] "I" (FBR_OFF_STACK_TOP)
			: "memory","cc"
	);
#else
	__ASM volatile(
			".syntax unified                         \n"

			"mrs   r0, psp                          \n"

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"
#else
			"dmb                                    \n"
#endif
			"isb                                    \n"

			"tst   lr, #4                           \n"
			"beq   6f                               \n"

			"ldr   r1, =fiber_internal_port_current_context \n"
			"ldr   r1, [r1]                         \n"
			"cmp   r1, #0                           \n"
			"beq   5f                               \n"

			"ldr   r2, [r1, %c[offsb]]              \n"
			"cmp   r0, r2                           \n"
			"blo   7f                               \n"
			"mov   r3, r0                           \n"
#if FIBER_HAS_EXTENDED_FP_CONTEXT
			"tst   lr, #0x10                        \n"
			"bne   8f                               \n"
			"subs  r3, #64                          \n"
			"bcc   7f                               \n"
			"8:                                     \n"
#endif
			"subs  r3, #36                          \n"
			"bcc   7f                               \n"
			"cmp   r3, r2                           \n"
			"blo   7f                               \n"
			"ldr   r2, [r1, %c[offtop]]             \n"
			"cmp   r0, r2                           \n"
			"bhi   7f                               \n"

#if FIBER_HAS_EXTENDED_FP_CONTEXT
			"tst   lr, #0x10                        \n"
			"bne   2f                               \n"
			"vstmdb r0!, {s16-s31}                  \n"
			"2:                                     \n"
#endif

			"stmdb r0!, {r4-r11, r14}               \n"
			"str   r0, [r1]                         \n"

			FBR_ASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n"
			"bl    fiber_internal_scheduler_pick_next_from_pendsv \n"
			FBR_ASM_EXIT_SCHEDULER_CRITICAL
			"mov   r2, r0                           \n"

			"ldr   r0, [r2]                         \n"
			"ldmia r0!, {r4-r11, r14}               \n"

#if FIBER_USE_PSPLIM_REGISTER
			"ldr   r3, [r2, %c[offsb]]              \n"
			FBR_ASM_MSR_PSPLIM("r3")
			"dsb                                    \n"
			"isb                                    \n"
#endif

#if FIBER_HAS_EXTENDED_FP_CONTEXT
			"tst   r14, #0x10                       \n"
			"bne   3f                               \n"
			"vldmia r0!, {s16-s31}                  \n"
			"3:                                     \n"
#endif

			"msr   psp, r0                          \n"
			"isb                                    \n"

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"
#else
			"dmb                                    \n"
#endif

			"isb                                    \n"

			"bx    r14                              \n"

			"5:                                     \n"
			"movs  r0, #67                          \n"
			"bl    fiber_panic                      \n"
			"b     5b                               \n"

			"6:                                     \n"
			"movs  r0, #106                         \n"
			"bl    fiber_panic                      \n"
			"b     6b                               \n"

			"7:                                     \n"
			"movs  r0, #100                         \n"
			"bl    fiber_panic                      \n"
			"b     7b                               \n"
			:
			: [offsb] "I" (FBR_OFF_STACK_BASE),
			  [offtop] "I" (FBR_OFF_STACK_TOP),
			  [sched_basepri] "i" (FIBER_SCHEDULER_BASEPRI)
			  : "memory","cc"
	);
#endif
}

#endif /* FIBER_PORT_ARMV8M_BASELINE || FIBER_PORT_ARMV8M_MAINLINE || FIBER_PORT_ARMV81M_MAINLINE */
