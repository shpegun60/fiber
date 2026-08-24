/* ARM_CM33F_NTZ exact non-MPU FPU/SVC/PendSV implementation. */

#include "fiber_port_private.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

enum FiberPortInitialFrameWord {
	fiber_portFRAME_PSPLIM = 0,
	fiber_portFRAME_EXC_RETURN = 1,
	fiber_portFRAME_R4 = 2,
	fiber_portFRAME_R5 = 3,
	fiber_portFRAME_R6 = 4,
	fiber_portFRAME_R7 = 5,
	fiber_portFRAME_R8 = 6,
	fiber_portFRAME_R9 = 7,
	fiber_portFRAME_R10 = 8,
	fiber_portFRAME_R11 = 9,
	fiber_portFRAME_R0 = 10,
	fiber_portFRAME_R1 = 11,
	fiber_portFRAME_R2 = 12,
	fiber_portFRAME_R3 = 13,
	fiber_portFRAME_R12 = 14,
	fiber_portFRAME_LR = 15,
	fiber_portFRAME_PC = 16,
	fiber_portFRAME_XPSR = 17,
	fiber_portFRAME_WORD_COUNT = 18
};

FIBER_STATIC_ASSERT(fiber_portFRAME_EXC_RETURN ==
		FIBER_PORT_EXC_RETURN_WORD_INDEX,
		"[fiber]: ARM_CM33F_NTZ EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_R0 == FIBER_PORT_SOFTWARE_FRAME_WORDS,
		"[fiber]: ARM_CM33F_NTZ hardware frame offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_WORD_COUNT * sizeof(uint32_t) ==
		FIBER_PORT_INITIAL_CONTEXT_BYTES,
		"[fiber]: ARM_CM33F_NTZ initial frame size changed");

enum {
	fiber_portOFF_STACK_BASE =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_base),
	fiber_portOFF_STACK_TOP =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_top),
	fiber_portOFFSET_STACKED_XPSR = 7u * 4u,
	fiber_portOFFSET_EXTENDED_STACKED_XPSR =
		FIBER_PORT_EXC_FP_EXT_BYTES + (7u * 4u)
};

FIBER_STATIC_ASSERT(fiber_portOFF_STACK_BASE < 4096u,
		"[fiber]: ARM_CM33F_NTZ stack-base offset must fit Thumb-2 LDR");
FIBER_STATIC_ASSERT(fiber_portOFF_STACK_TOP < 4096u,
		"[fiber]: ARM_CM33F_NTZ stack-top offset must fit Thumb-2 LDR");
FIBER_STATIC_ASSERT((fiber_portOFF_STACK_BASE & 3u) == 0u,
		"[fiber]: ARM_CM33F_NTZ stack-base offset must be word aligned");
FIBER_STATIC_ASSERT((fiber_portOFF_STACK_TOP & 3u) == 0u,
		"[fiber]: ARM_CM33F_NTZ stack-top offset must be word aligned");

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_init_context_frame(FiberContext *const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_boot_record_check(&ctx->boot);

	uint32_t *const frame = (uint32_t *)ctx->boot.stack_top -
			fiber_portFRAME_WORD_COUNT;

	/* FreeRTOS seeds the same basic frame when configENABLE_FPU is one.
	 * No s16-s31 words exist until PendSV sees EXC_RETURN bit 4 cleared. */
	frame[fiber_portFRAME_PSPLIM] = (uint32_t)ctx->boot.stack_base;
	frame[fiber_portFRAME_EXC_RETURN] = fiber_portINITIAL_EXC_RETURN;
	frame[fiber_portFRAME_R4] = 0u;
	frame[fiber_portFRAME_R5] = 0u;
	frame[fiber_portFRAME_R6] = 0u;
	frame[fiber_portFRAME_R7] = 0u;
	frame[fiber_portFRAME_R8] = 0u;
	frame[fiber_portFRAME_R9] = fiber_port_read_r9();
	frame[fiber_portFRAME_R10] = 0u;
	frame[fiber_portFRAME_R11] = 0u;
	frame[fiber_portFRAME_R0] = (uint32_t)(uintptr_t)ctx->boot.arg;
	frame[fiber_portFRAME_R1] = 0u;
	frame[fiber_portFRAME_R2] = 0u;
	frame[fiber_portFRAME_R3] = 0u;
	frame[fiber_portFRAME_R12] = 0u;
	frame[fiber_portFRAME_LR] =
			((uint32_t)(uintptr_t)&fiber_internal_task_return) | 1u;
	frame[fiber_portFRAME_PC] =
			fiber_port_stacked_pc((uintptr_t)ctx->boot.entry);
	frame[fiber_portFRAME_XPSR] = fiber_port_initial_xpsr();

	ctx->sp = frame;
	{
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
}

/* -------------------------------------------------------------------------- */
/* FPU policy                                                                  */
/* -------------------------------------------------------------------------- */

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_fpu_require_configured(void)
{
	FIBER_REQUIRE((fiber_portCPACR_REG & fiber_portCPACR_CP10_CP11_FULL) ==
			fiber_portCPACR_CP10_CP11_FULL, 'e');

	const uint32_t fpccr = fiber_portFPCCR_REG;
	FIBER_REQUIRE((fpccr & fiber_portFPCCR_ASPEN_BIT) != 0u, 'E');
#if FIBER_FPU_LAZY
	FIBER_REQUIRE((fpccr & fiber_portFPCCR_LSPEN_BIT) != 0u, 'E');
#else
	FIBER_REQUIRE((fpccr & fiber_portFPCCR_LSPEN_BIT) == 0u, 'E');
#endif

}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_fpu_require_ready(void)
{
	fiber_port_fpu_require_configured();
	const uint32_t fpccr = fiber_portFPCCR_REG;
	/* First start enters from Thread mode; a pending lazy preservation belongs
	 * to an interrupted FP context and is never an acceptable start state. */
	FIBER_REQUIRE((fpccr & fiber_portFPCCR_LSPACT_BIT) == 0u, 'E');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_fpu_prepare(void)
{
	uint32_t cpacr = fiber_portCPACR_REG;
	if ((cpacr & fiber_portCPACR_CP10_CP11_FULL) !=
			fiber_portCPACR_CP10_CP11_FULL) {
		cpacr = (cpacr & ~fiber_portCPACR_CP10_CP11_FULL) |
				fiber_portCPACR_CP10_CP11_FULL;
		fiber_portCPACR_REG = cpacr;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
	}
	FIBER_REQUIRE((fiber_portCPACR_REG & fiber_portCPACR_CP10_CP11_FULL) ==
			fiber_portCPACR_CP10_CP11_FULL, 'e');

	uint32_t fpccr = fiber_portFPCCR_REG;
	fpccr |= fiber_portFPCCR_ASPEN_BIT;
#if FIBER_FPU_LAZY
	fpccr |= fiber_portFPCCR_LSPEN_BIT;
#else
	fpccr &= ~fiber_portFPCCR_LSPEN_BIT;
#endif
	if (fpccr != fiber_portFPCCR_REG) {
		fiber_portFPCCR_REG = fpccr;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
	}
	fiber_port_fpu_require_ready();
}

/* -------------------------------------------------------------------------- */
/* SVC first-start staging ABI                                                 */
/* -------------------------------------------------------------------------- */

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void)
{
	fiber_portASM volatile("dmb" ::: "memory");
	fiber_portCOMPILER_BARRIER();
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_panic_wait(void)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	for (;;) {
		__WFE();
	}
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_require_scheduler_configuration_environment(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
}

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

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_primask_save_disable(void)
{
	uint32_t state;
	fiber_portASM volatile(
			"mrs %0, primask \n"
			"cpsid i         \n"
			: "=r"(state)
			:
			: "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	return state;
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_primask_restore(const uint32_t state)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portASM volatile("msr primask, %0" :: "r"(state) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == state, 'r');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_svc_vector(void)
{
	const uint32_t *const vectors = fiber_port_vectors_base_ptr();
	const uintptr_t actual = (uintptr_t)vectors[fiber_portVECTOR_INDEX_SVC];
	const uintptr_t expected = (uintptr_t)&SVC_Handler;
	FIBER_REQUIRE((actual & 1u) != 0u, 'y');
	FIBER_REQUIRE((actual & ~(uintptr_t)1u) ==
			(expected & ~(uintptr_t)1u), 'y');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_pendsv_vector(void)
{
	const uint32_t *const vectors = fiber_port_vectors_base_ptr();
	const uintptr_t actual = (uintptr_t)vectors[fiber_portVECTOR_INDEX_PENDSV];
	const uintptr_t expected = (uintptr_t)&PendSV_Handler;
	FIBER_REQUIRE((actual & 1u) != 0u, 'Y');
	FIBER_REQUIRE((actual & ~(uintptr_t)1u) ==
			(expected & ~(uintptr_t)1u), 'Y');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint8_t fiber_port_probe_implemented_priority_mask(void)
{
	volatile uint8_t *const first_user_priority =
			(volatile uint8_t *)0xE000E400u;
	const uint32_t primask = fiber_port_primask_save_disable();
	const uint8_t original_priority = *first_user_priority;

	*first_user_priority = 0xFFu;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	const uint8_t implemented_mask = *first_user_priority;

	*first_user_priority = original_priority;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(*first_user_priority == original_priority, 'Q');
	fiber_port_primask_restore(primask);
	return implemented_mask;
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_count_implemented_priority_bits(uint8_t implemented_mask)
{
	uint32_t implemented_bits = 0u;
	while ((implemented_mask & 0x80u) != 0u) {
		++implemented_bits;
		implemented_mask = (uint8_t)(implemented_mask << 1u);
	}
	return implemented_bits;
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_basepri_priority_policy(void)
{
	const uint8_t implemented_mask =
			fiber_port_probe_implemented_priority_mask();
	const uint32_t implemented_bits =
			fiber_port_count_implemented_priority_bits(implemented_mask);
	const uint8_t cmsis_mask =
			(uint8_t)(0xFFu << (8u - __NVIC_PRIO_BITS));

	FIBER_REQUIRE(implemented_mask != 0u, 'Q');
	FIBER_REQUIRE(implemented_mask == cmsis_mask, 'Q');
	FIBER_REQUIRE(implemented_bits == (uint32_t)__NVIC_PRIO_BITS, 'Q');
	FIBER_REQUIRE(((uint32_t)FIBER_PORT_SCHEDULER_BASEPRI &
			(uint32_t)implemented_mask) != 0u, 'Q');
	FIBER_REQUIRE(((uint32_t)FIBER_PORT_SCHEDULER_BASEPRI &
			~(uint32_t)implemented_mask) == 0u, 'q');

	uint32_t max_prigroup = 0u;
	if (implemented_bits < 8u) {
		max_prigroup = 7u - implemented_bits;
	}
	max_prigroup = (max_prigroup << 8u) & (0x07u << 8u);
	FIBER_REQUIRE((SCB->AIRCR & (0x07u << 8u)) <= max_prigroup, 'g');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_exception_start_configuration(void)
{
	FIBER_REQUIRE(NVIC_GetPriority(PendSV_IRQn) ==
			fiber_portLOWEST_EXCEPTION_PRIORITY, 'P');
	FIBER_REQUIRE(NVIC_GetPriority(SVCall_IRQn) == 0u, 'w');
	fiber_port_validate_pendsv_vector();
	fiber_port_validate_svc_vector();
#ifdef SCB_CCR_STKALIGN_Msk
	FIBER_REQUIRE((SCB->CCR & SCB_CCR_STKALIGN_Msk) != 0u, 'A');
#endif
	fiber_port_validate_basepri_priority_policy();
	fiber_port_fpu_require_ready();
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_prepare_exception_start(void)
{
	fiber_port_require_start_environment();
	fiber_port_require_start_interrupt_state();
	const uint32_t primask = fiber_port_primask_save_disable();
	FIBER_REQUIRE(primask == 0u, 'p');

	NVIC_SetPriority(PendSV_IRQn, fiber_portLOWEST_EXCEPTION_PRIORITY);
	NVIC_SetPriority(SVCall_IRQn, 0u);
	fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVCLEAR_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_port_validate_exception_start_configuration();

	fiber_port_primask_restore(primask);
	fiber_port_require_start_interrupt_state();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_prepare_start(void)
{
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_require_start_environment();
	fiber_port_require_start_interrupt_state();
	fiber_port_runtime_prepare();
	fiber_port_prepare_exception_start();
	fiber_port_require_start_environment();
	fiber_port_require_start_interrupt_state();
	fiber_port_fpu_require_ready();
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
FiberContext *fiber_port_runtime_select_first(void)
{
	return fiber_port_scheduler_pick_first_from_start();
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
	/* Current was checked before save. Restore validation below also covers a
	 * scheduler decision that selects current again. */
	fiber_port_context_validate_restore(next);
	fiber_internal_runtime_publish_current_context(next);
	return next;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_start_first(FiberContext *const first)
{
	const uintptr_t msp_top = fiber_port_context_prepare_first_start(first);
	fiber_port_require_start_environment();
	fiber_port_require_start_interrupt_state();
	const uint32_t primask = fiber_port_primask_save_disable();
	FIBER_REQUIRE(primask == 0u, 'p');
	FIBER_REQUIRE(__get_PRIMASK() == 1u, 'p');
	fiber_port_validate_exception_start_configuration();
	fiber_port_fpu_require_ready();
	fiber_port_start_first_context(msp_top);
	FIBER_API_UNREACHABLE();
}

#define fiber_portSTRINGIFY2(value) #value
#define fiber_portSTRINGIFY(value) fiber_portSTRINGIFY2(value)

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
void fiber_port_start_first_context(
		uintptr_t msp_top FIBER_ATTR_UNUSED_PARAM)
{
	fiber_portASM volatile(
			".syntax unified                         \n"
			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"

			/* Establish the exact basic Thread/MSP origin for the one SVC. */
			"movs  r3, #0                           \n"
			"msr   control, r3                      \n"
			"isb                                    \n"
			"mrs   r3, control                      \n"
			"tst   r3, #7                           \n"
			"bne   9f                               \n"

			"cmp   r0, #0                           \n"
			"beq   1f                               \n"
			"tst   r0, #7                           \n"
			"bne   9f                               \n"
			"msr   msp, r0                          \n"
			"isb                                    \n"
			"mrs   r3, msp                          \n"
			"cmp   r3, r0                           \n"
			"bne   9f                               \n"

			"1:                                     \n"
			"ldr   r3, =0xE000ED04                  \n"
			"ldr   r2, =0x08000000                  \n"
			"str   r2, [r3]                         \n"
			"movs  r0, #0                           \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mrs   r3, " fiber_portBASEPRI_SYM "    \n"
			"cmp   r3, #0                           \n"
			"bne   9f                               \n"
			"mrs   r3, faultmask                    \n"
			"cmp   r3, #0                           \n"
			"bne   9f                               \n"
			"cpsie f                                \n"
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"svc   #" fiber_portSTRINGIFY(FIBER_SVC_START_NUMBER) " \n"

			"movs  r0, #121                         \n"
			"bl    fiber_panic                      \n"
			"b     .                                \n"

			"9:                                     \n"
			"movs  r0, #108                         \n"
			"bl    fiber_panic                      \n"
			"b     9b                               \n"
			".ltorg                                 \n"
			:
			:
			: "memory", "cc");
}

FIBER_ATTR_NAKED_ASM
void SVC_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                         \n"
			"mrs   r3, ipsr                         \n"
			"cmp   r3, #11                          \n"
			"bne   93f                              \n"
			"mvn   r3, #71                          \n" /* 0xFFFFFFB8 */
			"cmp   lr, r3                           \n"
			"bne   93f                              \n"
			"tst   lr, #4                           \n"
			"bne   93f                              \n"

			"mrs   r0, msp                          \n"
			"tst   r0, #7                           \n"
			"bne   93f                              \n"
			"ldr   r2, [r0, #28]                    \n"
			"tst   r2, #0x01000000                  \n"
			"beq   93f                              \n"
			"tst   r2, #0x200                       \n"
			"bne   93f                              \n"
			"ubfx  r2, r2, #0, #9                   \n"
			"cmp   r2, #0                           \n"
			"bne   93f                              \n"

			"ldr   r3, [r0, #24]                    \n"
			"cmp   r3, #2                           \n"
			"blo   94f                              \n"
			"tst   r3, #1                           \n"
			"bne   93f                              \n"
			"subs  r3, #2                           \n"
			"ldrb  r2, [r3, #1]                     \n"
			"cmp   r2, #0xDF                        \n"
			"bne   94f                              \n"
			"ldrb  r3, [r3]                         \n"
			"cmp   r3, #" fiber_portSTRINGIFY(FIBER_SVC_START_NUMBER) " \n"
			"bne   94f                              \n"

			/* Revalidate the FPU policy after the one point where external
			 * scheduler code could have executed. */
			"ldr   r1, =0xE000ED88                  \n"
			"ldr   r1, [r1]                         \n"
			"ldr   r2, =0x00F00000                  \n"
			"ands  r1, r1, r2                       \n"
			"cmp   r1, r2                           \n"
			"bne   97f                              \n"
			"ldr   r1, =0xE000EF34                  \n"
			"ldr   r1, [r1]                         \n"
			"tst   r1, #0x80000000                  \n"
			"beq   97f                              \n"
#if FIBER_FPU_LAZY
			"tst   r1, #0x40000000                  \n"
			"beq   97f                              \n"
#else
			"tst   r1, #0x40000000                  \n"
			"bne   97f                              \n"
#endif
			"tst   r1, #1                           \n"
			"bne   97f                              \n"

			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"movs  r0, #0                           \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mrs   r1, " fiber_portBASEPRI_SYM "    \n"
			"cmp   r1, #0                           \n"
			"bne   96f                              \n"

			"ldr   r0, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r0, [r0]                         \n"
			"cmp   r0, #0                           \n"
			"beq   90f                              \n"
			"push  {r0, lr}                         \n"
			"bl    fiber_port_context_validate_restore \n"
			"pop   {r2, r3}                         \n"

			"ldr   r0, [r2]                         \n"
			"ldmia r0!, {r2-r11}                    \n"
			"mvn   r1, #67                          \n" /* 0xFFFFFFBC */
			"cmp   r3, r1                           \n"
			"bne   92f                              \n"
			"msr   psplim, r2                       \n"
			"dsb                                    \n"
			"isb                                    \n"
			"mrs   r1, psplim                       \n"
			"cmp   r1, r2                           \n"
			"bne   95f                              \n"

			"movs  r1, #2                           \n"
			"msr   control, r1                      \n"
			"isb                                    \n"
			"mrs   r1, control                      \n"
			"and   r1, r1, #7                       \n"
			"cmp   r1, #2                           \n"
			"bne   93f                              \n"
			"msr   psp, r0                          \n"
			"isb                                    \n"
			"mrs   r1, psp                          \n"
			"cmp   r1, r0                           \n"
			"bne   92f                              \n"
			"mrs   r1, faultmask                    \n"
			"cmp   r1, #0                           \n"
			"bne   93f                              \n"

			"dsb                                    \n"
			"isb                                    \n"
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    r3                               \n"

			"90:                                    \n"
			"movs  r0, #67                          \n"
			"bl    fiber_panic                      \n"
			"b     90b                              \n"
			"92:                                    \n"
			"movs  r0, #120                         \n"
			"bl    fiber_panic                      \n"
			"b     92b                              \n"
			"93:                                    \n"
			"movs  r0, #108                         \n"
			"bl    fiber_panic                      \n"
			"b     93b                              \n"
			"94:                                    \n"
			"movs  r0, #117                         \n"
			"bl    fiber_panic                      \n"
			"b     94b                              \n"
			"95:                                    \n"
			"movs  r0, #76                          \n"
			"bl    fiber_panic                      \n"
			"b     95b                              \n"
			"96:                                    \n"
			"movs  r0, #98                          \n"
			"bl    fiber_panic                      \n"
			"b     96b                              \n"
			"97:                                    \n"
			"movs  r0, #69                          \n"
			"bl    fiber_panic                      \n"
			"b     97b                              \n"
			".ltorg                                 \n"
			:
			:
			: "memory", "cc");
}

/* FreeRTOS ARM_CM33_NTZ non-MPU PendSV shape with exact Fiber ownership:
 * [PSPLIM][EXC_RETURN][r4-r11] and, only for an extended frame,
 * [s16-s31] immediately before the hardware FP extension. */
FIBER_ATTR_NAKED_ASM
void PendSV_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                         \n"

			/* Accept only the selected Non-secure Thread/PSP basic or
			 * extended exception-return encodings. */
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

			/* PSP starts at the basic or extended hardware exception frame. */
			"mrs   r0, psp                          \n"
			"tst   r0, #7                           \n"
			"bne   92f                              \n"
			"dsb                                    \n"
			"isb                                    \n"

			/* Do not read current metadata before its C preflight has checked it. */
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

			/* FreeRTOS saves high FP state before the ten-word core frame. */
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

			/* Restore core state, then high FP state only for an extended frame. */
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

			/* The scheduler may not leak mask or thread-stack selection state. */
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
			"movs  r0, #67                          \n"
			"bl    fiber_panic                      \n"
			"b     90b                              \n"
			"91:                                    \n"
			"movs  r0, #106                         \n"
			"bl    fiber_panic                      \n"
			"b     91b                              \n"
			"92:                                    \n"
			"movs  r0, #100                         \n"
			"bl    fiber_panic                      \n"
			"b     92b                              \n"
			"93:                                    \n"
			"movs  r0, #76                          \n"
			"bl    fiber_panic                      \n"
			"b     93b                              \n"
			"94:                                    \n"
			"movs  r0, #120                         \n"
			"bl    fiber_panic                      \n"
			"b     94b                              \n"
			"95:                                    \n"
			"movs  r0, #98                          \n"
			"bl    fiber_panic                      \n"
			"b     95b                              \n"
			"96:                                    \n"
			"movs  r0, #108                         \n"
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
