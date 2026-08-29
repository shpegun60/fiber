/* ARM_CM55F_NTZ strict first-start SVC path. PendSV mechanics live in
 * fiber_port.c so the two exception owners remain independently auditable. */

#include "fiber_port_private.h"

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

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_runtime_select_first(void)
{
	return fiber_port_scheduler_pick_first_from_start();
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
