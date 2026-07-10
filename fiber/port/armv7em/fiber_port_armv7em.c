/*
 * fiber_port_armv7em.c
 *
 * ARMv7E-M PendSV port.
 *
 * This file owns the moved STM32H7/Cortex-M7 PendSV implementation. The move is
 * intended to preserve the validated save/restore behavior while putting the
 * CPU-specific path behind the v2 port boundary.
 */

#include "../fiber_port.h"
#include "../../fiber_core.h"

#if FIBER_PORT_ARMV7EM

#define FBR_STRINGIFY2(x) #x
#define FBR_STRINGIFY(x) FBR_STRINGIFY2(x)

enum {
	FBR_OFF_STACK_BASE = offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_base),
	FBR_OFF_STACK_TOP = offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_top)
};

BT_STATIC_ASSERT(FBR_OFF_STACK_BASE < 4096, "FBR_OFF_STACK_BASE must fit Thumb-2 LDR imm12");
BT_STATIC_ASSERT(FBR_OFF_STACK_TOP < 4096, "FBR_OFF_STACK_TOP must fit Thumb-2 LDR imm12");

void fiber_port_init_context_frame(FiberContext * const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_boot_check(&ctx->boot);

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

	/* ARMv7E-M software frame, low to high: [r4..r11][LR(EXC_RETURN)]. */
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

#if FIBER_START_USE_SVC
FIBER_NORETURN
FIBER_ATTR_NAKED_ASM
void fiber_port_start_first_context(uintptr_t msp_top)
{
	__ASM volatile(
			".syntax unified                         \n"

			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"

			"movs  r3, #0                           \n"
			"msr   control, r3                      \n" /* privileged Thread/MSP, clear FPCA */
			"isb                                    \n"
			"mrs   r3, control                      \n"
			"tst   r3, #7                           \n"
			"bne   9f                               \n"

			"cmp   r0, #0                           \n"
			"beq   1f                               \n"
			"lsrs  r0, r0, #3                       \n"
			"lsls  r0, r0, #3                       \n"
			"msr   msp, r0                          \n"
			"isb                                    \n"
			"mrs   r3, msp                          \n"
			"cmp   r3, r0                           \n"
			"bne   9f                               \n"

			"1:                                     \n"
			"ldr   r3, =0xE000ED04                  \n" /* SCB->ICSR */
			"ldr   r2, =0x08000000                  \n" /* PENDSVCLR */
			"str   r2, [r3]                         \n"
			"dsb                                    \n"
			"isb                                    \n"
			"cpsie i                                \n"
			"cpsie f                                \n"
			"dsb                                    \n"
			"isb                                    \n"

			"svc   #" FBR_STRINGIFY(FIBER_SVC_START_NUMBER) " \n"

			"movs  r0, #121                         \n" /* 'y': SVC did not transfer control */
			"bl    fiber_panic                      \n"
			"b     .                                \n"

			"9:                                     \n"
			"movs  r0, #108                         \n" /* 'l': first-start CPU state rejected */
			"bl    fiber_panic                      \n"
			"b     9b                               \n"
			:
			:
			: "memory","cc"
	);
}

FIBER_ATTR_NAKED_ASM
void fiber_svc(void)
{
	__ASM volatile(
			".syntax unified                         \n"

			"tst   lr, #4                           \n"
			"bne   93f                              \n" /* first-start SVC must arrive from MSP */
			"mrs   r0, msp                          \n" /* r0 = SVC stacked frame */
			"ldr   r3, [r0, #24]                    \n" /* stacked PC */
			"subs  r3, #2                           \n" /* SVC instruction address */
			"ldrb  r3, [r3]                         \n" /* SVC immediate */
			"cmp   r3, #" FBR_STRINGIFY(FIBER_SVC_START_NUMBER) " \n"
			"bne   94f                              \n"

			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
#if FIBER_HAS_BASEPRI
			"movs  r0, #0                           \n"
			"msr   basepri, r0                      \n"
			"dsb                                    \n"
			"isb                                    \n"
#endif

			"ldr   r0, =fiber_internal_port_current_context \n"
			"ldr   r0, [r0]                         \n"
			"cmp   r0, #0                           \n"
			"beq   90f                              \n"

			"push  {r0, lr}                         \n"
			"bl    fiber_internal_validate_restore_context \n"
			"pop   {r2, lr}                         \n" /* r2 = current context */

			"ldr   r0, [r2]                         \n" /* r0 = current->sp */
			"ldmia r0!, {r4-r11, r14}               \n" /* restore core SW frame */

#if FIBER_HAS_EXTENDED_FP_CONTEXT
			"tst   r14, #0x10                       \n"
			"bne   1f                               \n"
			"vldmia r0!, {s16-s31}                  \n"
			"1:                                     \n"
#endif /* FIBER_HAS_EXTENDED_FP_CONTEXT */

			"msr   psp, r0                          \n"
			"isb                                    \n"

			"mrs   r3, control                      \n"
#if FIBER_HAS_FPU && FIBER_BOOT_CLEAR_FPCA
			"bic   r3, r3, #4                       \n"
#endif
			"orr   r3, r3, #2                       \n"
			"msr   control, r3                      \n"
			"isb                                    \n"
			"mrs   r3, control                      \n"
			"tst   r3, #2                           \n"
			"beq   95f                              \n"
#if FIBER_HAS_FPU && FIBER_BOOT_CLEAR_FPCA
			"tst   r3, #4                           \n"
			"bne   95f                              \n"
#endif

			"dsb                                    \n"
			"isb                                    \n"
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    r14                              \n"

			"90:                                    \n"
			"movs  r0, #67                          \n" /* 'C' */
			"bl    fiber_panic                      \n"
			"b     90b                              \n"

			"93:                                    \n"
			"movs  r0, #108                         \n" /* 'l' */
			"bl    fiber_panic                      \n"
			"b     93b                              \n"

			"94:                                    \n"
			"movs  r0, #117                         \n" /* 'u' */
			"bl    fiber_panic                      \n"
			"b     94b                              \n"

			"95:                                    \n"
			"movs  r0, #106                         \n" /* 'j' */
			"bl    fiber_panic                      \n"
			"b     95b                              \n"
			:
			:
			: "memory","cc"
	);
}
#endif /* FIBER_START_USE_SVC */

/*
 * ARMv7E-M PendSV implementation.
 *
 * PendSV saves the runtime-owned current context, calls the scheduler bridge
 * under BASEPRI, then restores the returned context. The port never receives a
 * preselected target from Thread mode.
 */
FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void)
{
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
			 * Scheduler-driven path.
			 * Save runtime-owned current context, call the scheduler bridge under the
			 * port BASEPRI critical section, and restore the returned context.
			 * ---------------------------------------------------------------------- */
			"mrs   r3, control                      \n"
			"tst   r3, #2                           \n" /* Thread mode must already use PSP */
			"beq   91f                              \n" /* direct-start window or foreign PendSV */

			"ldr   r1, =fiber_internal_port_current_context \n" /* r1 = &current context */
			"ldr   r1, [r1]                         \n" /* r1 = current context */
			"cmp   r1, #0                           \n"
			"beq   90f                              \n" /* no current is a fatal port state */

			"ldr   r2, [r1, %c[offsb]]              \n" /* r2 = current->boot.stack_base */
			"cmp   r0, r2                           \n"
			"blo   92f                              \n" /* PSP is already below stack base */
			"mov   r3, r0                           \n"
#if FIBER_HAS_EXTENDED_FP_CONTEXT
			"tst   lr, #0x10                        \n" /* extended FP save needs 64 more bytes */
			"bne   8f                               \n"
			"subs  r3, #64                          \n"
			"bcc   92f                              \n"
			"8:                                     \n"
#endif /* FIBER_HAS_EXTENDED_FP_CONTEXT */
			"subs  r3, #36                          \n" /* core software frame */
			"bcc   92f                              \n"
			"cmp   r3, r2                           \n"
			"blo   92f                              \n" /* software frame would cross stack base */
			"ldr   r2, [r1, %c[offtop]]             \n" /* r2 = current->boot.stack_top */
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n" /* PSP above declared stack top */

#if FIBER_HAS_EXTENDED_FP_CONTEXT
			"tst   lr, #0x10                        \n" /* 1 => base frame only, 0 => extended present */
			"bne   2f                               \n" /* if bit4==1 then skip FP save */
			"vstmdb r0!, {s16-s31}                  \n" /* push S16..S31 */
			"2:                                     \n" /* scheduler skip-fpu-save */
#endif /* FIBER_HAS_EXTENDED_FP_CONTEXT */

			"stmdb r0!, {r4-r11, r14}               \n" /* push r4..r11 and LR(EXC_RETURN) */
			"str   r0, [r1]                         \n" /* current->sp = r0 */

			FBR_ASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n" /* arg0 = current */
			"bl    fiber_internal_scheduler_pick_next_from_pendsv \n"
			FBR_ASM_EXIT_SCHEDULER_CRITICAL

			"mov   r2, r0                           \n" /* r2 = selected next context */

			/* ----------------------------------------------------------------------
			 * Restore selected context. Current ownership was already published by
			 * the scheduler bridge before returning here.
			 * ---------------------------------------------------------------------- */
			"ldr   r0, [r2]                         \n" /* r0 = target->sp */
			"ldmia r0!, {r4-r11, r14}               \n" /* pop r4..r11 and LR(EXC_RETURN) */

#if FIBER_HAS_EXTENDED_FP_CONTEXT
			"tst   r14, #0x10                       \n" /* 1 => base frame only, 0 => extended present */
			"bne   22f                              \n" /* if bit4==1 then skip FP restore */
			"vldmia r0!, {s16-s31}                  \n" /* pop S16..S31 */
			"22:                                    \n" /* skip-fpu-restore */
#endif /* FIBER_HAS_EXTENDED_FP_CONTEXT */

			"msr   psp, r0                          \n" /* PSP := start of target HW frame */
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
			  [offsb] "I" (FBR_OFF_STACK_BASE),
			  [offtop] "I" (FBR_OFF_STACK_TOP)
			: "memory","cc"
	);
}

#undef FBR_STRINGIFY
#undef FBR_STRINGIFY2

#endif /* FIBER_PORT_ARMV7EM */
