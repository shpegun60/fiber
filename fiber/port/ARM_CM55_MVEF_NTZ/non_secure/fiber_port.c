/*
 * fiber_port.c
 *
 * ARM_CM55_MVEF_NTZ Non-secure MVE-FP PendSV runtime.
 *
 * The save/restore backbone follows pinned FreeRTOS
 * portable/GCC/ARM_CM55_NTZ/non_secure/portasm.c for the non-MPU branch:
 * [PSPLIM][EXC_RETURN][r4-r11], with s16-s31 immediately above that core
 * frame only when EXC_RETURN describes an extended FP hardware frame. MVE
 * does not add a VPR software slot in this non-MPU FreeRTOS frame.
 */

#include "fiber_port_private.h"

enum {
	fiber_portOFF_STACK_BASE =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_base),
	fiber_portOFF_STACK_TOP =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_top),
	fiber_portOFFSET_STACKED_XPSR = 7u * sizeof(uint32_t),
	fiber_portOFFSET_EXTENDED_STACKED_XPSR =
		FIBER_PORT_EXC_FP_EXT_BYTES + fiber_portOFFSET_STACKED_XPSR
};

FIBER_STATIC_ASSERT(fiber_portOFF_STACK_BASE < 4096u,
		"[fiber]: ARM_CM55_MVEF_NTZ stack-base offset must fit Thumb-2 LDR");
FIBER_STATIC_ASSERT(fiber_portOFF_STACK_TOP < 4096u,
		"[fiber]: ARM_CM55_MVEF_NTZ stack-top offset must fit Thumb-2 LDR");
FIBER_STATIC_ASSERT((fiber_portOFF_STACK_BASE & 3u) == 0u,
		"[fiber]: ARM_CM55_MVEF_NTZ stack-base offset must be word aligned");
FIBER_STATIC_ASSERT((fiber_portOFF_STACK_TOP & 3u) == 0u,
		"[fiber]: ARM_CM55_MVEF_NTZ stack-top offset must be word aligned");
FIBER_STATIC_ASSERT(fiber_portOFFSET_EXTENDED_STACKED_XPSR == 100u,
		"[fiber]: ARM_CM55_MVEF_NTZ extended xPSR offset changed");

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_schedule(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	fiber_internal_runtime_require_current_context();
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	fiber_port_fpu_require_configured();
	fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVSET_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}

typedef struct FiberPortSchedulerCpuState {
	uint32_t primask;
	uint32_t control;
	uint32_t basepri;
	uint32_t faultmask;
	uint32_t psplim;
	uint32_t cpacr;
	uint32_t fpccr;
} FiberPortSchedulerCpuState;

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_capture_scheduler_cpu_state(
		FiberPortSchedulerCpuState *const state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->control = __get_CONTROL();
	state->basepri = fiber_port_basepri_read();
	state->faultmask = __get_FAULTMASK();
	state->psplim = __get_PSPLIM();
	state->cpacr = fiber_portCPACR_REG;
	state->fpccr = fiber_portFPCCR_REG;
	fiber_portCOMPILER_BARRIER();
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_scheduler_cpu_state(
		const FiberPortSchedulerCpuState *const before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'r');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'B');
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 't');
	FIBER_REQUIRE(__get_PSPLIM() == before->psplim, 'L');
	FIBER_REQUIRE(fiber_portCPACR_REG == before->cpacr, 'e');
	FIBER_REQUIRE(fiber_portFPCCR_REG == before->fpccr, 'E');
	fiber_port_fpu_require_configured();
	fiber_portCOMPILER_BARRIER();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_first_from_start(void)
{
	/* This one-shot call keeps the complete runtime object in the exact cohort
	 * link proof without adding a cohort read to the PendSV hot path. */
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	const uint32_t critical_state = fiber_port_scheduler_critical_enter();
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			(uint32_t)FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FiberPortSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const first =
			fiber_internal_runtime_select_scheduler_candidate(NULL);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(first);
	fiber_port_scheduler_critical_exit(critical_state);
	FIBER_REQUIRE(fiber_port_basepri_read() == critical_state, 'b');
	return first;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(
		FiberContext *const current)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'j');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			(uint32_t)FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE(__get_PSPLIM() == (uint32_t)current->boot.stack_base, 'L');
	fiber_port_fpu_require_configured();

	FiberPortSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const next =
			fiber_internal_runtime_select_scheduler_candidate(current);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	/* Current was checked before save. Restore validation also covers a
	 * scheduler decision that returns the same fiber. */
	fiber_port_context_validate_restore(next);
	fiber_internal_runtime_publish_current_context(next);
	return next;
}

FIBER_ATTR_NAKED_ASM
void PendSV_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                         \n"

			/* Only selected Non-secure Thread/PSP basic or extended returns
			 * can enter this handler. */
			"mrs   r3, ipsr                         \n"
			"cmp   r3, #14                          \n"
			"bne   91f                              \n"
			"mvn   r3, #67                          \n" /* 0xFFFFFFBC */
			"cmp   lr, r3                           \n"
			"beq   7f                               \n"
			"bic   r3, r3, #0x10                    \n" /* 0xFFFFFFAC */
			"cmp   lr, r3                           \n"
			"bne   91f                              \n"
			"7:                                     \n"
			"tst   lr, #4                           \n"
			"beq   91f                              \n"

			/* PSP names the bottom of the basic or extended hardware frame. */
			"mrs   r0, psp                          \n"
			"tst   r0, #7                           \n"
			"bne   92f                              \n"
			"dsb                                    \n"
			"isb                                    \n"

			/* Do not read current metadata before the C preflight validates it. */
			"ldr   r1, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r1, [r1]                         \n"
			"cmp   r1, #0                           \n"
			"beq   90f                              \n"
			"push  {r0, r1, r2, lr}                 \n"
			"mov   r0, r1                           \n"
			"bl    fiber_port_context_validate_save_current \n"
			"pop   {r0, r1, r2, lr}                 \n"

			/* Prove basic/extended hardware and future software storage before
			 * the first PSP write. */
			"ldr   r2, [r1, %c[offsb]]              \n"
			"cmp   r0, r2                           \n"
			"blo   92f                              \n"
			"mov   r3, r0                           \n"
			"tst   lr, #0x10                        \n"
			"bne   8f                               \n"
			"subs  r3, #%c[highfp]                  \n"
			"bcc   92f                              \n"
			"8:                                     \n"
			"subs  r3, #%c[swbytes]                 \n"
			"bcc   92f                              \n"
			"cmp   r3, r2                           \n"
			"blo   92f                              \n"
			"ldr   r2, [r1, %c[offtop]]             \n"
			"subs  r2, #%c[hwbase]                  \n"
			"bcc   92f                              \n"
			"tst   lr, #0x10                        \n"
			"bne   81f                              \n"
			"subs  r2, #%c[hwfp]                    \n"
			"bcc   92f                              \n"
			"81:                                    \n"
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n"
			"tst   lr, #0x10                        \n"
			"bne   82f                              \n"
			"ldr   r3, [r0, %c[xpsrfp]]             \n"
			"b     83f                              \n"
			"82:                                    \n"
			"ldr   r3, [r0, %c[xpsr]]               \n"
			"83:                                    \n"
			"tst   r3, #0x200                       \n"
			"beq   84f                              \n"
			"subs  r2, #%c[alignpad]                \n"
			"bcc   92f                              \n"
			"84:                                    \n"
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n"

			/* Pinned FreeRTOS M55 non-MPU ordering: high FP state first, then
			 * [PSPLIM][EXC_RETURN][r4-r11]. */
			"tst   lr, #0x10                        \n"
			"bne   2f                               \n"
			"vstmdb r0!, {s16-s31}                  \n"
			"2:                                     \n"
			"ldr   r2, [r1, %c[offsb]]              \n"
			"mrs   r3, psplim                       \n"
			"cmp   r3, r2                           \n"
			"bne   93f                              \n"
			"mov   r2, r3                           \n"
			"mov   r3, lr                           \n"
			"stmdb r0!, {r2-r11}                    \n"
			"str   r0, [r1]                         \n"

			fiber_portASM_ENTER_SCHEDULER_CRITICAL
			"mov   r0, r1                           \n"
			"bl    fiber_port_scheduler_pick_next_from_pendsv \n"
			fiber_portASM_EXIT_SCHEDULER_CRITICAL
			"mrs   r1, " fiber_portBASEPRI_SYM "    \n"
			"cmp   r1, #0                           \n"
			"bne   95f                              \n"

			/* Restore the ten-word core frame, then s16-s31 only when the
			 * selected exception return has an extended frame. */
			"mov   r1, r0                           \n"
			"ldr   r0, [r1]                         \n"
			"ldmia r0!, {r2-r11}                    \n"
			"mvn   r1, #67                          \n" /* 0xFFFFFFBC */
			"cmp   r3, r1                           \n"
			"beq   3f                               \n"
			"bic   r1, r1, #0x10                    \n" /* 0xFFFFFFAC */
			"cmp   r3, r1                           \n"
			"bne   94f                              \n"
			"3:                                     \n"
			"tst   r3, #0x10                        \n"
			"bne   22f                              \n"
			"vldmia r0!, {s16-s31}                  \n"
			"22:                                    \n"
			"msr   psplim, r2                       \n"
			"dsb                                    \n"
			"isb                                    \n"
			"mrs   r1, psplim                       \n"
			"cmp   r1, r2                           \n"
			"bne   93f                              \n"
			"msr   psp, r0                          \n"
			"isb                                    \n"
			"mrs   r1, psp                          \n"
			"cmp   r1, r0                           \n"
			"bne   92f                              \n"

			/* The scheduler must not leak masking or Thread stack selection. */
			"mrs   r1, control                      \n"
			"and   r1, r1, #3                       \n"
			"cmp   r1, #2                           \n"
			"bne   96f                              \n"
			"mrs   r1, primask                      \n"
			"cmp   r1, #0                           \n"
			"bne   96f                              \n"
			"mrs   r1, faultmask                    \n"
			"cmp   r1, #0                           \n"
			"bne   96f                              \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    r3                               \n"

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
			"93:                                    \n"
			"movs  r0, #76                          \n" /* 'L' */
			"bl    fiber_panic                      \n"
			"b     93b                              \n"
			"94:                                    \n"
			"movs  r0, #120                         \n" /* 'x' */
			"bl    fiber_panic                      \n"
			"b     94b                              \n"
			"95:                                    \n"
			"movs  r0, #98                          \n" /* 'b' */
			"bl    fiber_panic                      \n"
			"b     95b                              \n"
			"96:                                    \n"
			"movs  r0, #108                         \n" /* 'l' */
			"bl    fiber_panic                      \n"
			"b     96b                              \n"
			".ltorg                                 \n"
			:
			: [sched_basepri] "i" (FIBER_PORT_SCHEDULER_BASEPRI),
			  [swbytes] "I" (FIBER_PORT_SOFTWARE_FRAME_BYTES),
			  [highfp] "I" (FIBER_PORT_HIGH_FP_SOFTWARE_BYTES),
			  [hwbase] "I" (FIBER_PORT_EXC_BASE_BYTES),
			  [hwfp] "I" (FIBER_PORT_EXC_FP_EXT_BYTES),
			  [alignpad] "I" (FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES),
			  [xpsr] "I" (fiber_portOFFSET_STACKED_XPSR),
			  [xpsrfp] "I" (fiber_portOFFSET_EXTENDED_STACKED_XPSR),
			  [offsb] "I" (fiber_portOFF_STACK_BASE),
			  [offtop] "I" (fiber_portOFF_STACK_TOP)
			: "memory", "cc");
}
