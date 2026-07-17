/*
 * fiber_port.c
 *
 * ARM_CM4 Cortex-M4/M4F port.
 *
 * Cortex-M7 uses the concrete ARM_CM7/r0p1 source group. This implementation
 * owns the concrete M4/M4F frame, SVC, and PendSV path and remains
 * compile/link-covered until profile-specific hardware validation is recorded.
 */

#include "mcu_core.h"
#include "../fiber_port_select.h"

#if FIBER_PORT_ARMV7EM && defined(__CORTEX_M) && (__CORTEX_M == 4)

#include "../../fiber_runtime_port_abi.h"
#include "fiber_port_private.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void)
{
	__DMB();
	__COMPILER_BARRIER();
}

FIBER_NORETURN FIBER_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_panic_wait(void)
{
	__DSB();
	__ISB();
	for (;;) {
		__WFE();
	}
}

/*
 * Frozen forward-ABI implementation.
 *
 * Common runtime calls only these CPU-neutral operations. Port-private helpers
 * retain the established validation and first-start mechanics below.
 */
void fiber_port_require_scheduler_configuration_environment(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_prepare_start(void)
{
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	fiber_port_require_start_environment();
	fiber_port_require_start_interrupt_state();
	fiber_pendsv_init_lowest_priority();
	fiber_port_runtime_prepare();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_runtime_select_first(void)
{
	return fiber_port_scheduler_pick_first_from_start();
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_start_first(FiberContext *first)
{
	const uintptr_t msp_top = fiber_port_context_prepare_first_start(first);

	fiber_port_require_start_interrupt_state();
	fiber_port_start_first_context(msp_top);
	FIBER_API_UNREACHABLE();
}

#define fiber_portSTRINGIFY2(x) #x
#define fiber_portSTRINGIFY(x) fiber_portSTRINGIFY2(x)

enum {
	fiber_portOFF_STACK_BASE = offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_base),
	fiber_portOFF_STACK_TOP = offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_top),
	fiber_portOFFSET_STACKED_XPSR = 7u * 4u
};

FIBER_STATIC_ASSERT(fiber_portOFF_STACK_BASE < 4096, "fiber_portOFF_STACK_BASE must fit Thumb-2 LDR imm12");
FIBER_STATIC_ASSERT(fiber_portOFF_STACK_TOP < 4096, "fiber_portOFF_STACK_TOP must fit Thumb-2 LDR imm12");

void fiber_port_init_context_frame(FiberContext * const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_boot_record_check(&ctx->boot);

	uint32_t *sp = (uint32_t *)ctx->boot.stack_top;

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
	*(--sp) = FIBER_PORT_INITIAL_EXC_RETURN;
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

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_schedule(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	fiber_internal_runtime_require_current_context();
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
#if FIBER_PORT_HAS_BASEPRI
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
#endif
#if FIBER_PORT_HAS_FAULTMASK
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
#endif
	fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVSET_BIT;
	__DSB();
	__ISB();
}

/* The selected port owns the CPU-state contract around the user scheduler.
 * Common runtime owns only hook lifecycle and current-context publication. */
typedef struct FiberPortSchedulerCpuState {
	uint32_t primask;
	uint32_t control;
#if FIBER_PORT_HAS_BASEPRI
	uint32_t basepri;
#endif
#if FIBER_PORT_HAS_FAULTMASK
	uint32_t faultmask;
#endif
} FiberPortSchedulerCpuState;

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY void
fiber_port_capture_scheduler_cpu_state(FiberPortSchedulerCpuState *state)
{
	FIBER_REQUIRE(state != 0, 'C');
	__COMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->control = __get_CONTROL();
#if FIBER_PORT_HAS_BASEPRI
	state->basepri = fiber_port_basepri_read();
#endif
#if FIBER_PORT_HAS_FAULTMASK
	state->faultmask = __get_FAULTMASK();
#endif
	__COMPILER_BARRIER();
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY void
fiber_port_validate_scheduler_cpu_state(const FiberPortSchedulerCpuState *before)
{
	FIBER_REQUIRE(before != 0, 'C');
	__COMPILER_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'r');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
#if FIBER_PORT_HAS_BASEPRI
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'B');
#endif
#if FIBER_PORT_HAS_FAULTMASK
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 't');
#endif
	__COMPILER_BARRIER();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_first_from_start(void)
{
	const uint32_t critical_state = fiber_port_scheduler_critical_enter();
	FiberPortSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const first =
			fiber_internal_runtime_select_scheduler_candidate(0);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(first);
	fiber_port_scheduler_critical_exit(critical_state);
	return first;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current)
{
	FIBER_REQUIRE(current != 0, 'C');
	FiberPortSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const next =
			fiber_internal_runtime_select_scheduler_candidate(current);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	/* PendSV preflight validated and saved current. Validate only the context
	 * selected for restore; this also covers next == current. */
	fiber_port_context_validate_restore(next);
	fiber_internal_runtime_publish_current_context(next);
	return next;
}

FIBER_NORETURN
FIBER_ATTR_NAKED_ASM
void fiber_port_start_first_context(
		uintptr_t msp_top FIBER_ATTR_UNUSED_PARAM)
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

			"svc   #" fiber_portSTRINGIFY(FIBER_SVC_START_NUMBER) " \n"

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
void SVC_Handler(void)
{
	__ASM volatile(
			".syntax unified                         \n"

			"mrs   r3, ipsr                         \n"
			"cmp   r3, #11                          \n"
			"bne   93f                              \n" /* must execute as SVCall */
			"mvn   r3, #6                           \n" /* 0xFFFFFFF9: Thread/MSP/basic */
			"cmp   lr, r3                           \n"
			"bne   93f                              \n"
			"tst   lr, #4                           \n"
			"bne   93f                              \n" /* first-start SVC must arrive from MSP */
			"mrs   r0, msp                          \n" /* r0 = SVC stacked frame */
			"tst   r0, #7                           \n"
			"bne   93f                              \n" /* first-start MSP frame must be 8-byte aligned */
			"ldr   r2, [r0, #28]                    \n" /* stacked xPSR */
			"tst   r2, #0x01000000                  \n"
			"beq   93f                              \n" /* stacked Thread state must be Thumb */
			"tst   r2, #0x200                       \n"
			"bne   93f                              \n" /* validated pre-SVC MSP cannot require padding */
			"ubfx  r2, r2, #0, #9                   \n"
			"cmp   r2, #0                           \n"
			"bne   93f                              \n" /* stacked IPSR must describe Thread mode */
			"ldr   r3, [r0, #24]                    \n" /* stacked PC */
			"cmp   r3, #2                           \n"
			"blo   94f                              \n"
			"tst   r3, #1                           \n"
			"bne   93f                              \n" /* Thumb state belongs in xPSR, not PC bit 0 */
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

			"ldr   r0, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r0, [r0]                         \n"
			"cmp   r0, #0                           \n"
			"beq   90f                              \n"

			"push  {r0, lr}                         \n"
			"bl    fiber_port_context_validate_restore \n"
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

/*
 * ARMv7E-M PendSV implementation.
 *
 * PendSV saves the runtime-owned current context, calls the scheduler bridge
 * under BASEPRI, then restores the returned context. The port never receives a
 * preselected target from Thread mode.
 */
FIBER_ATTR_NAKED_ASM
void PendSV_Handler(void)
{
	__ASM volatile(
			".syntax unified                         \n"

			"mrs   r3, ipsr                         \n"
			"cmp   r3, #14                          \n"
			"bne   91f                              \n" /* must execute as PendSV */
			"mvn   r3, #2                           \n" /* 0xFFFFFFFD: Thread/PSP/basic */
			"cmp   lr, r3                           \n"
			"beq   7f                               \n"
#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
			"bic   r3, r3, #0x10                    \n" /* 0xFFFFFFED: Thread/PSP/extended */
			"cmp   lr, r3                           \n"
#endif
			"bne   91f                              \n" /* reject every other EXC_RETURN encoding */
			"7:                                     \n"

			/* ----------------------------------------------------------------------
			 * Prologue: get PSP and sync pipeline
			 * ---------------------------------------------------------------------- */
			"mrs   r0, psp                          \n" /* r0 = PSP */
			"tst   r0, #7                           \n"
			"bne   92f                              \n" /* STKALIGN requires an 8-byte hardware-frame base */

			"dsb                                    \n"  /* serialize before context publication */
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

			"ldr   r1, =fiber_internal_runtime_current_context_slot \n" /* r1 = &current context */
			"ldr   r1, [r1]                         \n" /* r1 = current context */
			"cmp   r1, #0                           \n"
			"beq   90f                              \n" /* no current is a fatal port state */

			/* Validate the running context before the assembly reads its fields.
			 * This also makes an externally pended PendSV fail closed. */
			"push  {r0, r1, r2, lr}                 \n"
			"mov   r0, r1                           \n"
			"bl    fiber_port_context_validate_save_current \n"
			"pop   {r0, r1, r2, lr}                 \n"

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
			"bhi   92f                              \n"
			"ldr   r3, [r0, %c[xpsr]]               \n"
			"tst   r3, #0x200                       \n" /* xPSR.STACKALIGN */
			"beq   83f                              \n"
			"subs  r2, #%c[alignpad]                \n"
			"bcc   92f                              \n"
			"83:                                    \n"
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
			"bl    fiber_port_scheduler_pick_next_from_pendsv \n"
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

			"dsb                                    \n"  /* serialize restored CPU state */

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
			  [alignpad] "I" (FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES),
			  [xpsr] "I" (fiber_portOFFSET_STACKED_XPSR),
#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
			  [hwfp] "I" (FIBER_PORT_EXC_FP_EXT_BYTES),
#endif
			  [offsb] "I" (fiber_portOFF_STACK_BASE),
			  [offtop] "I" (fiber_portOFF_STACK_TOP)
			: "memory","cc"
	);
}

#undef fiber_portSTRINGIFY
#undef fiber_portSTRINGIFY2

#endif /* FIBER_PORT_ARMV7EM && Cortex-M4 */
