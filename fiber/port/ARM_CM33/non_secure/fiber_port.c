/* ARM_CM33 TrustZone Non-secure exact initial context construction. */

#include "fiber_port_private.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

enum FiberPortInitialFrameWord {
	fiber_portFRAME_SECURE_CONTEXT = 0,
	fiber_portFRAME_PSPLIM = 1,
	fiber_portFRAME_EXC_RETURN = 2,
	fiber_portFRAME_R4 = 3,
	fiber_portFRAME_R5 = 4,
	fiber_portFRAME_R6 = 5,
	fiber_portFRAME_R7 = 6,
	fiber_portFRAME_R8 = 7,
	fiber_portFRAME_R9 = 8,
	fiber_portFRAME_R10 = 9,
	fiber_portFRAME_R11 = 10,
	fiber_portFRAME_R0 = 11,
	fiber_portFRAME_R1 = 12,
	fiber_portFRAME_R2 = 13,
	fiber_portFRAME_R3 = 14,
	fiber_portFRAME_R12 = 15,
	fiber_portFRAME_LR = 16,
	fiber_portFRAME_PC = 17,
	fiber_portFRAME_XPSR = 18,
	fiber_portFRAME_WORD_COUNT = 19
};

FIBER_STATIC_ASSERT(fiber_portFRAME_EXC_RETURN ==
		FIBER_PORT_EXC_RETURN_WORD_INDEX,
		"[fiber]: ARM_CM33 EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_R0 == FIBER_PORT_SOFTWARE_FRAME_WORDS,
		"[fiber]: ARM_CM33 hardware frame offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_WORD_COUNT * sizeof(uint32_t) ==
		FIBER_PORT_INITIAL_CONTEXT_BYTES,
		"[fiber]: ARM_CM33 initial frame size changed");

enum {
	fiber_portOFF_STACK_BASE =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_base),
	fiber_portOFF_STACK_TOP =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_top),
	fiber_portOFFSET_STACKED_XPSR = 7u * 4u
};

FIBER_STATIC_ASSERT(fiber_portOFF_STACK_BASE < 4096u,
		"[fiber]: ARM_CM33 stack-base offset must fit Thumb-2 LDR");
FIBER_STATIC_ASSERT(fiber_portOFF_STACK_TOP < 4096u,
		"[fiber]: ARM_CM33 stack-top offset must fit Thumb-2 LDR");
FIBER_STATIC_ASSERT((fiber_portOFF_STACK_BASE & 3u) == 0u,
		"[fiber]: ARM_CM33 stack-base offset must be word aligned");
FIBER_STATIC_ASSERT((fiber_portOFF_STACK_TOP & 3u) == 0u,
		"[fiber]: ARM_CM33 stack-top offset must be word aligned");

void fiber_port_init_context_frame(FiberContext *const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_boot_record_check(&ctx->boot);

	uint32_t *const frame = (uint32_t *)ctx->boot.stack_top -
			fiber_portFRAME_WORD_COUNT;

	/* Exact FreeRTOS companion-aware no-MPU/no-FPU frame. The SecureContext
	 * handle remains zero until first-start allocation succeeds. */
	frame[fiber_portFRAME_SECURE_CONTEXT] = fiber_portNO_SECURE_CONTEXT;
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
	(void)*(volatile const unsigned char *)
			&fiber_port_arm_cm33_secure_context_handler_bundle_v1_anchor;
	(void)*(volatile const unsigned char *)
			&fiber_port_arm_cm33_secure_context_attachment_bundle_v1_anchor;
	fiber_port_require_start_environment();
	fiber_port_require_start_interrupt_state();
	fiber_port_runtime_prepare();
	fiber_port_prepare_exception_start();
	fiber_port_require_start_environment();
	fiber_port_require_start_interrupt_state();
}

typedef struct FiberPortSchedulerCpuState {
	uint32_t primask;
	uint32_t control;
	uint32_t basepri;
	uint32_t faultmask;
	uint32_t psplim;
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

	FiberPortSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const next =
			fiber_internal_runtime_select_scheduler_candidate(current);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
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
	fiber_port_start_first_context(msp_top);
	FIBER_API_UNREACHABLE();
}
