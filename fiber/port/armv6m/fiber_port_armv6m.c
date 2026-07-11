/*
 * fiber_port_armv6m.c
 *
 * ARMv6-M PendSV port.
 *
 * This file owns the Cortex-M0/M0+ Thumb-1 SVC first-start and PendSV
 * implementation. The port is compile-covered; hardware validation is still
 * required before claiming runtime support on a specific STM32 ARMv6-M target.
 */

#include "../fiber_port.h"

#if FIBER_PORT_ARMV6M

#define FBR_STRINGIFY2(x) #x
#define FBR_STRINGIFY(x) FBR_STRINGIFY2(x)

enum {
	FBR_OFF_STACK_BASE = offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_base),
	FBR_OFF_STACK_TOP = offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_top)
};

BT_STATIC_ASSERT(FBR_OFF_STACK_BASE <= 124, "FBR_OFF_STACK_BASE must fit Thumb-1 LDR word offset");
BT_STATIC_ASSERT(FBR_OFF_STACK_TOP <= 124, "FBR_OFF_STACK_TOP must fit Thumb-1 LDR word offset");

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

	/* ARMv6-M software frame, low to high: [LR][r4..r7][r8..r11]. */
	*(--sp) = 0u;                    /* r11 */
	*(--sp) = 0u;                    /* r10 */
	*(--sp) = fiber_port_read_r9();  /* r9  */
	*(--sp) = 0u;                    /* r8  */
	*(--sp) = 0u;                    /* r7  */
	*(--sp) = 0u;                    /* r6  */
	*(--sp) = 0u;                    /* r5  */
	*(--sp) = 0u;                    /* r4  */
	*(--sp) = FIBER_INITIAL_EXC_RETURN;

	ctx->sp = sp;

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
}

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
			"msr   control, r3                      \n" /* privileged Thread/MSP */
			"isb                                    \n"
			"mrs   r3, control                      \n"
			"movs  r2, #3                           \n"
			"tst   r3, r2                           \n"
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

			"movs  r2, #4                           \n"
			"mov   r3, lr                           \n"
			"tst   r3, r2                           \n"
			"bne   93f                              \n" /* first-start SVC must arrive from MSP */
			"mrs   r0, msp                          \n"
			"movs  r2, #7                           \n"
			"mov   r3, r0                           \n"
			"tst   r3, r2                           \n"
			"bne   93f                              \n" /* first-start MSP frame must be 8-byte aligned */
			"ldr   r3, [r0, #24]                    \n" /* stacked PC */
			"subs  r3, #2                           \n"
			"ldrb  r2, [r3, #1]                     \n"
			"cmp   r2, #0xDF                        \n"
			"bne   94f                              \n"
			"ldrb  r3, [r3]                         \n"
			"cmp   r3, #" FBR_STRINGIFY(FIBER_SVC_START_NUMBER) " \n"
			"bne   94f                              \n"

			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"

			"ldr   r0, =fiber_internal_port_current_context \n"
			"ldr   r0, [r0]                         \n"
			"cmp   r0, #0                           \n"
			"beq   90f                              \n"

			"push  {r0, lr}                         \n"
			"bl    fiber_internal_validate_restore_context \n"
			"pop   {r2, r3}                         \n" /* r2 = current context, r3 = handler LR */
			"mov   lr, r3                           \n"

			"ldr   r0, [r2]                         \n" /* r0 = current->sp */
			"adds  r0, #20                          \n" /* move to staged r8-r11 */
			"ldmia r0!, {r4-r7}                     \n"
			"mov   r8,  r4                          \n"
			"mov   r9,  r5                          \n"
			"mov   r10, r6                          \n"
			"mov   r11, r7                          \n"

			"msr   psp, r0                          \n" /* PSP = hardware frame */
			"subs  r0, #36                          \n"
			"ldmia r0!, {r3-r7}                     \n" /* r3 = EXC_RETURN; restore low regs */
			"mov   lr, r3                           \n"

			"dsb                                    \n"
			"isb                                    \n"
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    lr                               \n"

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
			:
			:
			: "memory","cc"
	);
}

/*
 * ARMv6-M PendSV implementation.
 *
 * ARMv6-M has no BASEPRI, no FPU, and no Thumb-2 STMDB/LDMIA high-register
 * convenience path. The scheduler bridge is protected with saved PRIMASK
 * through FBR_ASM_ENTER_SCHEDULER_CRITICAL.
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
			/* Thumb-1 safe EXC_RETURN bit-2 check. CONTROL.SPSEL is not a
			 * reliable Handler-mode proof of the interrupted Thread stack.
			 */
			"movs  r2, #4                           \n"
			"mov   r3, lr                           \n"
			"tst   r3, r2                           \n" /* interrupted Thread context must use PSP */
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
			 * Save current context.
			 *
			 * SW layout low->high:
			 *   [LR][r4][r5][r6][r7][r8][r9][r10][r11]
			 *
			 * ARMv6-M cannot push high registers directly here, so r8-r11 are staged
			 * through r4-r7 and stored manually.
			 * ---------------------------------------------------------------------- */
			"subs  r0, #%c[swbytes]                 \n" /* reserve software frame */
			"mov   r2, r0                           \n" /* keep base until publication */

			"mov   r3, lr                           \n"
			"stmia r0!, {r3-r7}                     \n" /* save EXC_RETURN and low regs */

			"mov   r4, r8                           \n"
			"mov   r5, r9                           \n"
			"mov   r6, r10                          \n"
			"mov   r7, r11                          \n"
			"stmia r0!, {r4-r7}                     \n" /* save staged high regs */

			"str   r2, [r1]                         \n" /* current->sp = complete SW frame */

			FBR_ASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n" /* arg0 = current */
			"bl    fiber_internal_scheduler_pick_next_from_pendsv \n"
			FBR_ASM_EXIT_SCHEDULER_CRITICAL

			"mov   r2, r0                           \n" /* r2 = selected next */

			/* ----------------------------------------------------------------------
			 * Restore selected context.
			 * ---------------------------------------------------------------------- */
			"ldr   r0, [r2]                         \n" /* r0 = target->sp */
			"adds  r0, #20                          \n" /* move to staged r8-r11 */
			"ldmia r0!, {r4-r7}                     \n" /* staged r8-r11 */
			"mov   r8,  r4                          \n"
			"mov   r9,  r5                          \n"
			"mov   r10, r6                          \n"
			"mov   r11, r7                          \n"

			"msr   psp, r0                          \n" /* PSP = target HW frame */
			"subs  r0, #%c[swbytes]                 \n" /* move to saved EXC_RETURN and low regs */
			"ldmia r0!, {r3-r7}                     \n" /* r3 = EXC_RETURN; restore low regs */
			"mov   lr, r3                           \n"

			"isb                                    \n"

#if FIBER_SWITCH_STRICT_BARRIERS
			"dsb                                    \n"
#else
			"dmb                                    \n"
#endif /* FIBER_SWITCH_STRICT_BARRIERS */
			"isb                                    \n"

			"bx    lr                               \n" /* exception return */

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
			: [swbytes] "I" (FIBER_PORT_SOFTWARE_FRAME_BYTES),
			  [offsb] "I" (FBR_OFF_STACK_BASE),
			  [offtop] "I" (FBR_OFF_STACK_TOP)
			: "memory","cc"
	);
}

#undef FBR_STRINGIFY
#undef FBR_STRINGIFY2

#if !FIBER_SVC_VECTOR_DIRECT
# ifndef FIBER_SVC_WIRED
FIBER_DIAG_WARN("[fiber]: user must wire SVC_Handler to branch to fiber_svc without clobbering LR; define FIBER_SVC_WIRED=1 after you do it");
# endif /* FIBER_SVC_WIRED */
#endif /* !FIBER_SVC_VECTOR_DIRECT */

#endif /* FIBER_PORT_ARMV6M */
