/*
 * fiber_port.c
 *
 * ARM_CM7 r0p1 selected port.
 *
 * This file owns the Cortex-M7 r0p1/r0p0-safe first-start and PendSV path for
 * build-selected FreeRTOS-style integrations. It uses the same core
 * save/restore sequence as FreeRTOS, with fiber-owned scheduler and validation
 * policy.
 */

#include "mcu_core.h"
#include "../../fiber_port_select.h"

#if FIBER_PORT_BUILD_SELECTED || \
		(FIBER_PORT_ARMV7EM && (__CORTEX_M == 7))

#ifndef FIBER_CORTEX_M7_R0P1_ERRATA_837070
# define FIBER_CORTEX_M7_R0P1_ERRATA_837070 1
#endif

#include "../../../fiber_boot.h"
#include "../../../fiber_runtime_state.h"
#include "fiber_portmacro.h"
#include "../../fiber_port_traits.h"

FIBER_NORETURN
void fiber_internal_task_return(void);

#if !FIBER_CORTEX_M7_R0P1_ERRATA_837070
# error "[fiber]: ARM_CM7/r0p1 source requires FIBER_CORTEX_M7_R0P1_ERRATA_837070=1"
#endif

#define fiber_portSTRINGIFY2(x) #x
#define fiber_portSTRINGIFY(x) fiber_portSTRINGIFY2(x)

/*-----------------------------------------------------------
 * Initial context frame setup.
 *----------------------------------------------------------*/

enum {
	fiber_portOFFSET_STACK_BASE =
		offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_base),
	fiber_portOFFSET_STACK_TOP =
		offsetof(FiberContext, boot) + offsetof(FiberBoot, stack_top)
};

FIBER_STATIC_ASSERT(fiber_portOFFSET_STACK_BASE < 4096,
		"fiber_portOFFSET_STACK_BASE must fit Thumb-2 LDR imm12");
FIBER_STATIC_ASSERT(fiber_portOFFSET_STACK_TOP < 4096,
		"fiber_portOFFSET_STACK_TOP must fit Thumb-2 LDR imm12");

void fiber_port_init_context_frame(FiberContext * const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_boot_record_check(&ctx->boot);

	uint32_t *sp = (uint32_t *)(ctx->boot.stack_top -
			(uintptr_t)fiber_portEXC_PER_LEVEL);

	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}

	/* Hardware exception frame, low address after software frame restore. */
	*(--sp) = fiber_portINITIAL_XPSR;
	*(--sp) = fiber_arm_cm7_r0p1_stacked_pc((uintptr_t)ctx->boot.entry);
	*(--sp) = ((uint32_t)(uintptr_t)&fiber_internal_task_return) | 1u;
	*(--sp) = 0u; /* R12 */
	*(--sp) = 0u; /* R3  */
	*(--sp) = 0u; /* R2  */
	*(--sp) = 0u; /* R1  */
	*(--sp) = (uint32_t)(uintptr_t)ctx->boot.arg;

	/* ARM_CM7 r0p1 software frame, low to high: [r4..r11][LR(EXC_RETURN)]. */
	*(--sp) = fiber_portINITIAL_EXC_RETURN;
	*(--sp) = 0u;                    /* r11 */
	*(--sp) = 0u;                    /* r10 */
	*(--sp) = fiber_arm_cm7_r0p1_read_r9();  /* r9  */
	*(--sp) = 0u;                    /* r8  */
	*(--sp) = 0u;                    /* r7  */
	*(--sp) = 0u;                    /* r6  */
	*(--sp) = 0u;                    /* r5  */
	*(--sp) = 0u;                    /* r4  */

	ctx->sp = sp;

	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
}

/*-----------------------------------------------------------
 * First context start.
 *
 * FreeRTOS starts the first task through SVC. Fiber does the same, but the
 * scheduler hook has already selected and validated the first context.
 *----------------------------------------------------------*/

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
			"ldr   r2, =%c[pendsvclr]               \n"
			"str   r2, [r3]                         \n"
			"dsb                                    \n"
			"isb                                    \n"
			"cpsie i                                \n"
			"cpsie f                                \n"
			"dsb                                    \n"
			"isb                                    \n"

			"svc   #" fiber_portSTRINGIFY(FIBER_SVC_START_NUMBER) " \n"

			"movs  r0, #121                         \n" /* 'y': SVC did not transfer control */
			"bl    fiber_panic                      \n"
			"b     .                                \n"

			"9:                                     \n"
			"movs  r0, #108                         \n" /* 'l': first-start CPU state rejected */
			"bl    fiber_panic                      \n"
			"b     9b                               \n"
			:
			: [pendsvclr] "i" (fiber_portNVIC_PENDSVCLEAR_BIT)
			: "memory","cc"
	);
}

/*-----------------------------------------------------------
 * SVC handler.
 *----------------------------------------------------------*/

FIBER_ATTR_NAKED_ASM
void fiber_svc(void)
{
	__ASM volatile(
			".syntax unified                         \n"

			"tst   lr, #4                           \n"
			"bne   93f                              \n" /* first-start SVC must arrive from MSP */
			"mrs   r0, msp                          \n" /* r0 = SVC stacked frame */
			"tst   r0, #7                           \n"
			"bne   93f                              \n" /* first-start MSP frame must be 8-byte aligned */
			"ldr   r3, [r0, #24]                    \n" /* stacked PC */
			"subs  r3, #2                           \n" /* SVC instruction address */
			"ldrb  r2, [r3, #1]                     \n" /* SVC opcode high byte */
			"cmp   r2, #0xDF                        \n"
			"bne   94f                              \n"
			"ldrb  r3, [r3]                         \n" /* SVC immediate */
			"cmp   r3, #" fiber_portSTRINGIFY(FIBER_SVC_START_NUMBER) " \n"
			"bne   94f                              \n"

			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
#if FIBER_PORT_HAS_BASEPRI
			"movs  r0, #0                           \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
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

#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
			"tst   r14, #0x10                       \n"
			"bne   1f                               \n"
			"vldmia r0!, {s16-s31}                  \n"
			"1:                                     \n"
#endif /* FIBER_PORT_HAS_EXTENDED_FP_CONTEXT */

			"msr   psp, r0                          \n"
			"isb                                    \n"

			/*
			 * Do not set CONTROL.SPSEL from Handler mode. FreeRTOS-style first
			 * start selects PSP through EXC_RETURN in r14. The Thread-mode
			 * pre-SVC path already cleared CONTROL.FPCA and verified privileged
			 * Thread/MSP state before entering SVC.
			 */
#if FIBER_PORT_BOOT_CLEARS_FPCA
			"mrs   r3, control                      \n"
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

/*-----------------------------------------------------------
 * GCC ARM_CM7 r0p1 PendSV implementation.
 *
 * PendSV saves the runtime-owned current context, calls the scheduler bridge
 * under BASEPRI, then restores the returned context. The port never receives a
 * preselected target from Thread mode.
 *----------------------------------------------------------*/
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
			/* In Handler mode, EXC_RETURN is the source of truth for the
			 * interrupted stack. Do not use CONTROL.SPSEL as the PendSV proof.
			 */
			"tst   lr, #4                           \n" /* interrupted Thread context must use PSP */
			"beq   91f                              \n" /* foreign/pre-start PendSV used MSP */

			"ldr   r1, =fiber_internal_port_current_context \n" /* r1 = &current context */
			"ldr   r1, [r1]                         \n" /* r1 = current context */
			"cmp   r1, #0                           \n"
			"beq   90f                              \n" /* no current is a fatal port state */

			"ldr   r2, [r1, %c[offsb]]              \n" /* r2 = current->boot.stack_base */
			"cmp   r0, r2                           \n"
			"blo   92f                              \n" /* PSP is already below stack base */
			"mov   r3, r0                           \n"
#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
			"tst   lr, #0x10                        \n" /* extended FP save needs 64 more bytes */
			"bne   8f                               \n"
			"subs  r3, #64                          \n"
			"bcc   92f                              \n"
			"8:                                     \n"
#endif /* FIBER_PORT_HAS_EXTENDED_FP_CONTEXT */
			"subs  r3, #%c[swbytes]                 \n" /* core software frame */
			"bcc   92f                              \n"
			"cmp   r3, r2                           \n"
			"blo   92f                              \n" /* software frame would cross stack base */
			"ldr   r2, [r1, %c[offtop]]             \n" /* r2 = current->boot.stack_top */
			"subs  r2, #%c[hwbase]                  \n" /* account for the core HW frame */
			"bcc   92f                              \n"
#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
			"tst   lr, #0x10                        \n"
			"bne   81f                              \n"
			"subs  r2, #%c[hwfp]                    \n" /* extended FP HW frame */
			"bcc   92f                              \n"
			"81:                                    \n"
#endif
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n" /* HW frame crosses declared stack top */

#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
			"tst   lr, #0x10                        \n" /* 1 => base frame only, 0 => extended present */
			"bne   2f                               \n" /* if bit4==1 then skip FP save */
			"vstmdb r0!, {s16-s31}                  \n" /* push S16..S31 */
			"2:                                     \n" /* scheduler skip-fpu-save */
#endif /* FIBER_PORT_HAS_EXTENDED_FP_CONTEXT */

			"stmdb r0!, {r4-r11, r14}               \n" /* push r4..r11 and LR(EXC_RETURN) */
			"str   r0, [r1]                         \n" /* current->sp = r0 */

			fiber_portASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n" /* arg0 = current */
			"bl    fiber_internal_scheduler_pick_next_from_pendsv \n"
			fiber_portASM_EXIT_SCHEDULER_CRITICAL

			"mov   r2, r0                           \n" /* r2 = selected next context */

			/* ----------------------------------------------------------------------
			 * Restore selected context. Current ownership was already published by
			 * the scheduler bridge before returning here.
			 * ---------------------------------------------------------------------- */
			"ldr   r0, [r2]                         \n" /* r0 = target->sp */
			"ldmia r0!, {r4-r11, r14}               \n" /* pop r4..r11 and LR(EXC_RETURN) */

#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
			"tst   r14, #0x10                       \n" /* 1 => base frame only, 0 => extended present */
			"bne   22f                              \n" /* if bit4==1 then skip FP restore */
			"vldmia r0!, {s16-s31}                  \n" /* pop S16..S31 */
			"22:                                    \n" /* skip-fpu-restore */
#endif /* FIBER_PORT_HAS_EXTENDED_FP_CONTEXT */

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
			: [sched_basepri] "i" (FIBER_PORT_SCHEDULER_BASEPRI),
			  [swbytes] "I" (FIBER_PORT_SOFTWARE_FRAME_BYTES),
			  [hwbase] "I" (FIBER_PORT_EXC_BASE_BYTES),
#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
			  [hwfp] "I" (FIBER_PORT_EXC_FP_EXT_BYTES),
#endif
			  [offsb] "I" (fiber_portOFFSET_STACK_BASE),
			  [offtop] "I" (fiber_portOFFSET_STACK_TOP)
			: "memory","cc"
	);
}

#undef fiber_portSTRINGIFY
#undef fiber_portSTRINGIFY2

#if !FIBER_SVC_VECTOR_DIRECT
# ifndef FIBER_SVC_WIRED
FIBER_DIAG_WARN("[fiber]: user must wire SVC_Handler to branch to fiber_svc without clobbering LR; define FIBER_SVC_WIRED=1 after you do it");
# endif /* FIBER_SVC_WIRED */
#endif /* !FIBER_SVC_VECTOR_DIRECT */

#endif /* FIBER_PORT_BUILD_SELECTED */
