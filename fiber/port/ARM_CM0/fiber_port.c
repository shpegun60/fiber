/*
 * fiber_port.c
 *
 * ARM_CM0 PendSV port.
 *
 * This file owns the Cortex-M0/M0+ Thumb-1 SVC first-start and PendSV
 * implementation. The port is compile-covered; hardware validation is still
 * required before claiming runtime support on a specific STM32 ARMv6-M target.
 */

#include "../../fiber_runtime_port_abi.h"
#include "../fiber_port_select.h"

#if FIBER_PORT_ARMV6M

#include "fiber_port_private.h"

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
	fiber_portOFF_STACK_TOP = offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_top)
};

FIBER_STATIC_ASSERT(fiber_portOFF_STACK_BASE <= 124, "fiber_portOFF_STACK_BASE must fit Thumb-1 LDR word offset");
FIBER_STATIC_ASSERT(fiber_portOFF_STACK_TOP <= 124, "fiber_portOFF_STACK_TOP must fit Thumb-1 LDR word offset");

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

	/* ARMv6-M software frame, low to high: [LR][r4..r7][r8..r11]. */
	*(--sp) = 0u;                    /* r11 */
	*(--sp) = 0u;                    /* r10 */
	*(--sp) = fiber_port_read_r9();  /* r9  */
	*(--sp) = 0u;                    /* r8  */
	*(--sp) = 0u;                    /* r7  */
	*(--sp) = 0u;                    /* r6  */
	*(--sp) = 0u;                    /* r5  */
	*(--sp) = 0u;                    /* r4  */
	*(--sp) = FIBER_PORT_INITIAL_EXC_RETURN;

	ctx->sp = sp;

	{ __DSB(); __ISB(); __COMPILER_BARRIER(); }
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_schedule(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	fiber_internal_runtime_require_current_context();
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
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
			"cmp   r3, #" fiber_portSTRINGIFY(FIBER_SVC_START_NUMBER) " \n"
			"bne   94f                              \n"

			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"

			"ldr   r0, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r0, [r0]                         \n"
			"cmp   r0, #0                           \n"
			"beq   90f                              \n"

			"push  {r0, lr}                         \n"
			"bl    fiber_port_context_validate_restore \n"
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
 * through fiber_portASM_ENTER_SCHEDULER_CRITICAL.
 */
FIBER_ATTR_NAKED_ASM
void PendSV_Handler(void)
{
	__ASM volatile(
			".syntax unified                         \n"

			/* ----------------------------------------------------------------------
			 * Prologue: get PSP and sync pipeline.
			 * ---------------------------------------------------------------------- */
			"mrs   r0, psp                          \n" /* r0 = PSP */

			"dsb                                    \n"
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

			"ldr   r1, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r1, [r1]                         \n" /* r1 = current context */
			"cmp   r1, #0                           \n"
			"beq   90f                              \n" /* no current is fatal */

			/* Validate the running context before the assembly reads its fields.
			 * This also makes an externally pended PendSV fail closed. */
			"push  {r0, r1, r2, lr}                 \n"
			"mov   r0, r1                           \n"
			"bl    fiber_port_context_validate_save_current \n"
			"pop   {r0, r1, r2, r3}                 \n"
			"mov   lr, r3                           \n"

			"ldr   r2, [r1, %c[offsb]]              \n" /* r2 = current->boot.stack_base */
			"cmp   r0, r2                           \n"
			"blo   92f                              \n" /* PSP is already below stack base */
			"mov   r3, r0                           \n"
			"subs  r3, #%c[swbytes]                 \n" /* core software frame */
			"bcc   92f                              \n"
			"cmp   r3, r2                           \n"
			"blo   92f                              \n" /* software frame would cross stack base */
			"ldr   r2, [r1, %c[offtop]]             \n" /* r2 = current->boot.stack_top */
			"subs  r2, #%c[hwbase]                  \n" /* complete HW frame must fit below stack_top */
			"bcc   92f                              \n"
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n" /* HW frame crosses declared stack top */

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

			fiber_portASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n" /* arg0 = current */
			"bl    fiber_port_scheduler_pick_next_from_pendsv \n"
			fiber_portASM_EXIT_SCHEDULER_CRITICAL

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

			"dsb                                    \n"
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
			  [hwbase] "I" (FIBER_PORT_EXC_BASE_BYTES),
			  [offsb] "I" (fiber_portOFF_STACK_BASE),
			  [offtop] "I" (fiber_portOFF_STACK_TOP)
			: "memory","cc"
	);
}

#undef fiber_portSTRINGIFY
#undef fiber_portSTRINGIFY2

#endif /* FIBER_PORT_ARMV6M */
