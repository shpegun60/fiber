/* ARM_CM23_NTZ context construction, SVC first start, and PendSV switch. */

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
		"[fiber]: ARM_CM23_NTZ EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_R0 == FIBER_PORT_SOFTWARE_FRAME_WORDS,
		"[fiber]: ARM_CM23_NTZ hardware frame offset changed");
FIBER_STATIC_ASSERT(fiber_portFRAME_WORD_COUNT * sizeof(uint32_t) ==
		FIBER_PORT_INITIAL_CONTEXT_BYTES,
		"[fiber]: ARM_CM23_NTZ initial frame size changed");

enum {
	fiber_portOFF_STACK_BASE =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_base),
	fiber_portOFF_STACK_TOP =
		offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_top),
	fiber_portOFFSET_STACKED_XPSR = 7u * 4u
};

FIBER_STATIC_ASSERT(fiber_portOFF_STACK_BASE <= 124u,
		"[fiber]: ARM_CM23_NTZ stack-base offset must fit Thumb-1 LDR");
FIBER_STATIC_ASSERT(fiber_portOFF_STACK_TOP <= 124u,
		"[fiber]: ARM_CM23_NTZ stack-top offset must fit Thumb-1 LDR");
FIBER_STATIC_ASSERT((fiber_portOFF_STACK_BASE & 3u) == 0u,
		"[fiber]: ARM_CM23_NTZ stack-base offset must be word aligned");
FIBER_STATIC_ASSERT((fiber_portOFF_STACK_TOP & 3u) == 0u,
		"[fiber]: ARM_CM23_NTZ stack-top offset must be word aligned");

void fiber_port_init_context_frame(FiberContext *const ctx)
{
	FIBER_REQUIRE(ctx != NULL, 'C');
	fiber_port_boot_record_check(&ctx->boot);

	uint32_t *const frame = (uint32_t *)ctx->boot.stack_top -
			fiber_portFRAME_WORD_COUNT;

	/* FreeRTOS seeds this ignored NTZ slot with pxEndOfStack. A later save
	 * writes zero because Non-secure Cortex-M23 cannot access PSPLIM. */
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
	/* SVC first start seeds privileged Thread/PSP. This non-MPU port has no
	 * user-mode yield service, so a direct PendSV request is valid only here. */
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
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
	fiber_port_prepare_exception_start();
	fiber_port_runtime_prepare();
	fiber_port_require_start_environment();
	fiber_port_require_start_interrupt_state();
}

typedef struct FiberPortSchedulerCpuState {
	uint32_t primask;
	uint32_t control;
} FiberPortSchedulerCpuState;

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_capture_scheduler_cpu_state(
		FiberPortSchedulerCpuState *const state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->control = __get_CONTROL();
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
	fiber_portCOMPILER_BARRIER();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_first_from_start(void)
{
	const uint32_t primask = fiber_port_primask_save_disable();
	FiberPortSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const first =
			fiber_internal_runtime_select_scheduler_candidate(NULL);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(first);
	fiber_port_primask_restore(primask);
	return first;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_runtime_select_first(void)
{
	return fiber_port_scheduler_pick_first_from_start();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'j');
	FIBER_REQUIRE(__get_PRIMASK() == 1u, 'p');
	FiberPortSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const next =
			fiber_internal_runtime_select_scheduler_candidate(current);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	/* The source was validated before saving. Validate only the selected
	 * restore target; this also covers the scheduler returning current. */
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
	/* The user scheduler ran after initial setup. Revalidate the exception
	 * configuration under a mask retained into the naked start helper. */
	const uint32_t primask = fiber_port_primask_save_disable();
	FIBER_REQUIRE(primask == 0u, 'p');
	FIBER_REQUIRE(__get_PRIMASK() == 1u, 'p');
	fiber_port_validate_exception_start_configuration();
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

			"movs  r3, #0                           \n"
			"msr   control, r3                      \n"
			"isb                                    \n"
			"mrs   r3, control                      \n"
			"movs  r2, #3                           \n"
			"tst   r3, r2                           \n"
			"bne   9f                               \n"

			"cmp   r0, #0                           \n"
			"beq   1f                               \n"
			"mov   r3, r0                           \n"
			"movs  r2, #7                           \n"
			"tst   r3, r2                           \n"
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
			"dsb                                    \n"
			"isb                                    \n"
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
			/* Thumb-1 literal loads in this naked function must not depend on
			 * a compiler-selected pool beyond their 1 KiB PC-relative range. */
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
			"mrs   r2, ipsr                         \n"
			"cmp   r2, #11                          \n"
			"bne   93f                              \n"

			"movs  r2, #71                          \n"
			"mvns  r2, r2                           \n"
			"mov   r3, lr                           \n"
			"cmp   r3, r2                           \n"
			"bne   93f                              \n"
			"movs  r2, #4                           \n"
			"tst   r3, r2                           \n"
			"bne   93f                              \n"

			"mrs   r0, msp                          \n"
			"movs  r2, #7                           \n"
			"mov   r3, r0                           \n"
			"tst   r3, r2                           \n"
			"bne   93f                              \n"
			"ldr   r2, [r0, #28]                    \n"
			"mov   r1, r2                           \n"
			"lsls  r1, r1, #7                       \n"
			"bpl   93f                              \n"
			"mov   r1, r2                           \n"
			"lsls  r1, r1, #22                      \n"
			"bmi   93f                              \n"
			"lsls  r2, r2, #23                      \n"
			"bne   93f                              \n"

			"ldr   r3, [r0, #24]                    \n"
			"cmp   r3, #2                           \n"
			"blo   94f                              \n"
			"movs  r2, #1                           \n"
			"tst   r3, r2                           \n"
			"bne   93f                              \n"
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
			"pop   {r2, r3}                         \n"

			/* ARMv8-M FreeRTOS explicitly seeds privileged Thread/PSP CONTROL.
			 * EXC_RETURN still selects and proves the actual unstack source. */
			"movs  r0, #2                           \n"
			"msr   control, r0                      \n"
			"isb                                    \n"
			"mrs   r1, control                      \n"
			"movs  r0, #3                           \n"
			"ands  r1, r0                           \n"
			"cmp   r1, #2                           \n"
			"bne   93f                              \n"

			"ldr   r0, [r2]                         \n"
			"adds  r0, #24                          \n"
			"ldmia r0!, {r4-r7}                     \n"
			"mov   r8,  r4                          \n"
			"mov   r9,  r5                          \n"
			"mov   r10, r6                          \n"
			"mov   r11, r7                          \n"
			"msr   psp, r0                          \n"
			"subs  r0, #36                          \n"
			"ldmia r0!, {r3-r7}                     \n"
			"mov   lr, r3                           \n"

			"dsb                                    \n"
			"isb                                    \n"
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    lr                               \n"

			"90:                                    \n"
			"movs  r0, #67                          \n"
			"bl    fiber_panic                      \n"
			"b     90b                              \n"
			"93:                                    \n"
			"movs  r0, #108                         \n"
			"bl    fiber_panic                      \n"
			"b     93b                              \n"
			"94:                                    \n"
			"movs  r0, #117                         \n"
			"bl    fiber_panic                      \n"
			"b     94b                              \n"
			/* All paths above return or loop before this literal pool. */
			".ltorg                                 \n"
			:
			:
			: "memory", "cc");
}

/*
 * Exact FreeRTOS ARM_CM23_NTZ non-MPU PendSV frame, low to high:
 *
 *   [ignored PSPLIM][EXC_RETURN][r4..r7][r8..r11][hardware frame]
 *
 * Non-secure Cortex-M23 has no accessible PSPLIM register. The frame slot is
 * still retained for binary compatibility with the reference layout; an
 * ordinary save writes zero and restore skips it without touching PSPLIM.
 */
FIBER_ATTR_NAKED_ASM
void PendSV_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                         \n"

			/* Handler identity and exact Non-secure Thread/PSP EXC_RETURN. */
			"mrs   r2, ipsr                         \n"
			"cmp   r2, #14                          \n"
			"bne   91f                              \n"
			"movs  r2, #67                          \n"
			"mvns  r2, r2                           \n" /* 0xFFFFFFBC */
			"mov   r3, lr                           \n"
			"cmp   r3, r2                           \n"
			"bne   91f                              \n"
			"movs  r2, #4                           \n"
			"tst   r3, r2                           \n"
			"beq   91f                              \n"

			/* PSP points at the hardware frame while PendSV executes. */
			"mrs   r0, psp                          \n"
			"movs  r2, #7                           \n"
			"mov   r3, r0                           \n"
			"tst   r3, r2                           \n"
			"bne   92f                              \n"
			"dsb                                    \n"
			"isb                                    \n"

			/* Read the common-owned current slot only through its frozen
			 * assembly spelling, then validate before reading boot metadata. */
			"ldr   r1, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r1, [r1]                         \n"
			"cmp   r1, #0                           \n"
			"beq   90f                              \n"
			"push  {r0, r1, r2, lr}                 \n"
			"mov   r0, r1                           \n"
			"bl    fiber_port_context_validate_save_current \n"
			"pop   {r0, r1, r2, r3}                 \n"
			"mov   lr, r3                           \n"

			/* Prove the complete hardware frame and future 40-byte software
			 * frame fit before any source-stack write. */
			"ldr   r2, [r1, %c[offsb]]              \n"
			"cmp   r0, r2                           \n"
			"blo   92f                              \n"
			"mov   r3, r0                           \n"
			"subs  r3, #%c[swbytes]                 \n"
			"bcc   92f                              \n"
			"cmp   r3, r2                           \n"
			"blo   92f                              \n"
			"ldr   r2, [r1, %c[offtop]]             \n"
			"subs  r2, #%c[hwbase]                  \n"
			"bcc   92f                              \n"
			/* Do not read xPSR until the basic hardware frame itself is
			 * proven to fit. A corrupted PSP may otherwise read past stack_top
			 * before the controlled bounds panic. */
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n"
			"ldr   r3, [r0, %c[xpsr]]               \n"
			"lsls  r3, r3, #22                      \n" /* xPSR.STACKALIGN -> N */
			"bpl   83f                              \n"
			"subs  r2, #%c[alignpad]                \n"
			"bcc   92f                              \n"
			"83:                                    \n"
			"cmp   r0, r2                           \n"
			"bhi   92f                              \n"

			/* Save exactly the FreeRTOS NTZ non-MPU software frame. r12 holds
			 * the frame base only while the source context is made complete. */
			"subs  r0, #%c[swbytes]                 \n"
			"mov   r12, r0                          \n"
			"movs  r2, #0                           \n" /* inaccessible Non-secure PSPLIM */
			"mov   r3, lr                           \n"
			"stmia r0!, {r2-r7}                     \n"
			"mov   r4, r8                           \n"
			"mov   r5, r9                           \n"
			"mov   r6, r10                          \n"
			"mov   r7, r11                          \n"
			"stmia r0!, {r4-r7}                     \n"
			"mov   r3, r12                          \n"
			"str   r3, [r1]                         \n"

			/* The scheduler may run only under the selected PRIMASK envelope. */
			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"mov   r0, r1                           \n"
			"bl    fiber_port_scheduler_pick_next_from_pendsv \n"
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"

			/* Restore the selected ten-word software frame. Skip the PSPLIM
			 * placeholder and never access a Non-secure PSPLIM register. */
			"mov   r2, r0                           \n"
			"ldr   r0, [r2]                         \n"
			"adds  r0, #24                          \n"
			"ldmia r0!, {r4-r7}                     \n"
			"mov   r8,  r4                          \n"
			"mov   r9,  r5                          \n"
			"mov   r10, r6                          \n"
			"mov   r11, r7                          \n"
			"msr   psp, r0                          \n"
			"subs  r0, #36                          \n"
			"ldmia r0!, {r3-r7}                     \n"
			"mov   lr, r3                           \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    lr                               \n"

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
			/* All paths above return or loop before this literal pool. */
			".ltorg                                 \n"
			:
			: [swbytes] "I" (FIBER_PORT_SOFTWARE_FRAME_BYTES),
			  [hwbase] "I" (FIBER_PORT_EXC_BASE_BYTES),
			  [alignpad] "I" (FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES),
			  [xpsr] "I" (fiber_portOFFSET_STACKED_XPSR),
			  [offsb] "I" (fiber_portOFF_STACK_BASE),
			  [offtop] "I" (fiber_portOFF_STACK_TOP)
			: "memory", "cc");
}
