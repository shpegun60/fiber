/* ARM_CM4_MPU protected SVC first-start and unprivileged service veneers. */

#include "fiber_port_private.h"

#define FIBER_CM4_MPU_PRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

FIBER_PORT_CONTEXT_COHORT_DEFINE();

static FIBER_CM4_MPU_PRIVILEGED
uintptr_t fiber_port_code_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM4_MPU_PRIVILEGED
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) &&
			(inner_end > inner_start) &&
			(inner_start >= outer_start) &&
			(inner_end <= outer_end);
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_validate_core_identity(void)
{
	enum {
		FIBER_CM4_MPU_CPUID_ID_MASK = 0xFF0FFFF0u,
		FIBER_CM4_MPU_CORTEX_M4_ID = 0x410FC240u,
		FIBER_CM4_MPU_CORTEX_M7_ID = 0x410FC270u,
		FIBER_CM4_MPU_CORTEX_M7_R0P0 = 0x410FC270u,
		FIBER_CM4_MPU_CORTEX_M7_R0P1 = 0x410FC271u
	};

	const uint32_t cpuid = fiber_portSCB_CPUID_REG;
#if __CORTEX_M == 7
	FIBER_REQUIRE((cpuid & FIBER_CM4_MPU_CPUID_ID_MASK) ==
			FIBER_CM4_MPU_CORTEX_M7_ID, '7');
	if ((cpuid == FIBER_CM4_MPU_CORTEX_M7_R0P0) ||
			(cpuid == FIBER_CM4_MPU_CORTEX_M7_R0P1)) {
		FIBER_REQUIRE(
				FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND != 0,
				'7');
	}
#else
	FIBER_REQUIRE((cpuid & FIBER_CM4_MPU_CPUID_ID_MASK) ==
			FIBER_CM4_MPU_CORTEX_M4_ID, '4');
#endif
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_validate_svc_vector(void)
{
	FiberPortMpuMemoryLayout layout;
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	const uintptr_t vector_base = (uintptr_t)fiber_portSCB_VTOR_REG;
	FIBER_REQUIRE(vector_base != 0u, 'V');
	FIBER_REQUIRE((vector_base & 0x7Fu) == 0u, 'V');
	FIBER_REQUIRE(vector_base <= UINTPTR_MAX - (16u * sizeof(uint32_t)),
			'O');
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_code_start,
			layout.privileged_code_end, vector_base,
			vector_base + (16u * sizeof(uint32_t))), 'V');
	const volatile uint32_t *const vectors =
			(const volatile uint32_t *)vector_base;
	const uintptr_t initial_msp = (uintptr_t)vectors[0];
	FIBER_REQUIRE(initial_msp >= FIBER_PORT_EXC_BASE_BYTES, 'P');
	FIBER_REQUIRE((initial_msp & 7u) == 0u, 'P');
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_data_start,
			layout.privileged_data_end,
			initial_msp - FIBER_PORT_EXC_BASE_BYTES,
			initial_msp), 'P');
	const uintptr_t svc = fiber_port_code_address(
			(uintptr_t)vectors[11]);
	FIBER_REQUIRE(svc <= UINTPTR_MAX - 2u, 'O');
	FIBER_REQUIRE(svc == fiber_port_code_address(
			(uintptr_t)&SVC_Handler), 'y');
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_code_start,
			layout.privileged_code_end, svc, svc + 2u), 'y');
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_validate_first_start_environment(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 0u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	fiber_port_validate_core_identity();
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE,
			'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_validate_svc_cpu_state(void)
{
	FIBER_REQUIRE(__get_IPSR() == 11u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_validate_svc_frame_shape(const uint32_t *hardware_frame)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE((((uintptr_t)hardware_frame) & 7u) == 0u, 'A');
	const uint32_t stacked_pc = hardware_frame[6];
	const uint32_t stacked_xpsr = hardware_frame[7];
	FIBER_REQUIRE(stacked_pc >= 2u, 'x');
	FIBER_REQUIRE((stacked_pc & 1u) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_THUMB_BIT) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_IPSR_MASK) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_STACK_ALIGN_BIT) == 0u,
			'a');
}

static FIBER_CM4_MPU_PRIVILEGED
uint32_t fiber_port_decode_svc_number(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t pc = (uintptr_t)hardware_frame[6];
	FIBER_REQUIRE(pc >= 2u, 'u');
	const int in_privileged = fiber_port_range_contains(
			layout->privileged_code_start, layout->privileged_code_end,
			pc - 2u, pc);
	const int in_unprivileged = fiber_port_range_contains(
			layout->unprivileged_code_start, layout->unprivileged_code_end,
			pc - 2u, pc);
	FIBER_REQUIRE((in_privileged != 0) || (in_unprivileged != 0), 'u');

	const volatile uint8_t *const instruction =
			(const volatile uint8_t *)(pc - 2u);
	FIBER_REQUIRE(instruction[1] == 0xDFu, 'u');
	return instruction[0];
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_validate_exact_svc_site(uint32_t stacked_pc,
		const unsigned char *expected_site,
		char panic_code)
{
	FIBER_REQUIRE(expected_site != NULL, panic_code);
	FIBER_REQUIRE((uintptr_t)stacked_pc ==
			fiber_port_code_address((uintptr_t)expected_site), panic_code);
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_mpu_write_region(
		const FiberPortMpuRegionRegisters *region)
{
	FIBER_REQUIRE(region != NULL, 'M');
	fiber_portMPU_RBAR_REG = region->rbar;
	fiber_portMPU_RASR_REG = region->rasr;
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_mpu_validate_region_readback(uint32_t region_number,
		const FiberPortMpuRegionRegisters *expected)
{
	FIBER_REQUIRE(expected != NULL, 'M');
	fiber_portMPU_RNR_REG = region_number;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == region_number, 'M');
	FIBER_REQUIRE((fiber_portMPU_RBAR_REG &
			fiber_portMPU_REGION_ADDRESS_MASK) ==
			(expected->rbar & fiber_portMPU_REGION_ADDRESS_MASK), 'M');
	FIBER_REQUIRE(fiber_portMPU_RASR_REG == expected->rasr, 'M');
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_mpu_validate_active_context(const FiberContext *ctx)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(ctx != NULL, 'N');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE,
			'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED,
			'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) != 0u, 'M');
	fiber_port_mpu_build_global_regions(&global);

	for (uint32_t index = 0u;
			index < fiber_portMPU_CONTEXT_REGION_COUNT; ++index) {
		fiber_port_mpu_validate_region_readback(index,
				&ctx->mpu_regions[index]);
	}
	for (uint32_t index = 0u;
			index < fiber_portMPU_GLOBAL_REGION_COUNT; ++index) {
		fiber_port_mpu_validate_region_readback(
				index + fiber_portMPU_CURRENT_CONTEXT_REGION,
				&global.regions[index]);
	}

	fiber_portMPU_RNR_REG = 0u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == 0u, 'M');
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_mpu_activate_first_context(FiberContext *first)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(first != NULL, 'N');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE,
			'M');
	fiber_port_mpu_build_global_regions(&global);

	fiber_portDATA_MEMORY_BARRIER();
	fiber_portMPU_CTRL_REG = 0u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE((fiber_portMPU_CTRL_REG & fiber_portMPU_CTRL_ENABLE) ==
			0u, 'M');

	for (uint32_t index = 0u;
			index < fiber_portMPU_CONTEXT_REGION_COUNT; ++index) {
		fiber_port_mpu_write_region(&first->mpu_regions[index]);
	}
	for (uint32_t index = 0u;
			index < fiber_portMPU_GLOBAL_REGION_COUNT; ++index) {
		fiber_port_mpu_write_region(&global.regions[index]);
	}

	fiber_portSCB_SHCSR_REG |= fiber_portSCB_MEMFAULTENA_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) != 0u, 'M');

	fiber_portMPU_CTRL_REG = fiber_portMPU_CTRL_REQUIRED;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED,
			'M');
	fiber_port_mpu_validate_active_context(first);
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_validate_start_svc_frame(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES,
			'O');
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_data_start,
			layout->privileged_data_end, frame_start,
			frame_start + FIBER_PORT_EXC_BASE_BYTES), 'P');
	FIBER_REQUIRE((uintptr_t)hardware_frame[6] >= 2u, 'u');
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_code_start,
			layout->privileged_code_end,
			(uintptr_t)hardware_frame[6] - 2u,
			(uintptr_t)hardware_frame[6]), 'u');
}

FIBER_CM4_MPU_PRIVILEGED
void fiber_port_svc_dispatch(uint32_t *hardware_frame,
		uint32_t exc_return,
		FiberContext *current)
{
	FiberPortMpuMemoryLayout layout;
	fiber_port_validate_svc_cpu_state();
	FIBER_REQUIRE((exc_return == fiber_portEXC_RETURN_THREAD_MSP) ||
			(exc_return == fiber_portEXC_RETURN_THREAD_PSP_BASIC) ||
			(exc_return == fiber_portEXC_RETURN_THREAD_PSP_EXTENDED), 'l');
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	if (exc_return == fiber_portEXC_RETURN_THREAD_MSP) {
		FIBER_REQUIRE((__get_CONTROL() & 7u) == 0u, 'l');
		fiber_port_validate_start_svc_frame(hardware_frame, &layout);
	} else {
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_port_context_validate_running_svc(current, hardware_frame,
				exc_return);
		fiber_port_mpu_validate_active_context(current);
	}
	fiber_port_validate_svc_frame_shape(hardware_frame);

	const uint32_t service = fiber_port_decode_svc_number(hardware_frame,
			&layout);
	switch (service) {
	case fiber_portSVC_START:
		FIBER_REQUIRE(exc_return == fiber_portEXC_RETURN_THREAD_MSP, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_start_return_site, 'u');
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_port_context_validate_initial_restore(current);
		__disable_irq();
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_port_mpu_activate_first_context(current);
		fiber_port_restore_first_context_from_svc(current);
		FIBER_API_UNREACHABLE();

	case fiber_portSVC_YIELD:
		FIBER_REQUIRE(exc_return != fiber_portEXC_RETURN_THREAD_MSP, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_yield_return_site, 'u');
		__disable_irq();
		fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVSET_BIT;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		__enable_irq();
		return;

	case fiber_portSVC_RETURN:
		FIBER_REQUIRE(exc_return != fiber_portEXC_RETURN_THREAD_MSP, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_return_return_site, 'u');
		fiber_internal_task_return();
		FIBER_API_UNREACHABLE();

	default:
		fiber_panic('u');
	}
}

/* This exact unprivileged veneer is the only slice-3 route to PENDSVSET. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FIBER_ATTR_NAKED_ASM fiber_portUNPRIVILEGED_FUNCTION
void fiber_port_runtime_schedule(void)
{
	__ASM volatile(
			".syntax unified                                     \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_YIELD) " \n"
			".global fiber_port_svc_yield_return_site            \n"
			"fiber_port_svc_yield_return_site:                    \n"
			"bx    lr                                              \n"
			:
			:
			: "memory", "cc");
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FIBER_ATTR_NAKED_ASM fiber_portUNPRIVILEGED_FUNCTION
void fiber_port_unprivileged_task_return(void)
{
	__ASM volatile(
			".syntax unified                                     \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_RETURN) " \n"
			".global fiber_port_svc_return_return_site           \n"
			"fiber_port_svc_return_return_site:                   \n"
			"1: b  1b                                             \n"
			:
			:
			: "memory", "cc");
}

static FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_start_first_context_transfer(void)
{
	__ASM volatile(
			".syntax unified                                     \n"
			"movs  r3, #0                                        \n"
			"msr   control, r3                                   \n"
			"isb                                                  \n"
			"mrs   r3, control                                   \n"
			"tst   r3, #7                                        \n"
			"bne   90f                                           \n"
			"ldr   r0, =0xE000ED08                               \n"
			"ldr   r0, [r0]                                      \n"
			"ldr   r0, [r0]                                      \n"
			"cmp   r0, #0                                        \n"
			"beq   91f                                           \n"
			"tst   r0, #7                                        \n"
			"bne   91f                                           \n"
			"msr   msp, r0                                       \n"
			"isb                                                  \n"
			"ldr   r3, =0xE000ED04                               \n"
			"ldr   r2, =0x08000000                               \n"
			"str   r2, [r3]                                      \n"
			"dsb                                                  \n"
			"isb                                                  \n"
			"cpsie i                                              \n"
			"cpsie f                                              \n"
			"dsb                                                  \n"
			"isb                                                  \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_START) " \n"
			".global fiber_port_svc_start_return_site            \n"
			"fiber_port_svc_start_return_site:                    \n"
			"movs  r0, #121                                      \n"
			"bl    fiber_panic                                   \n"
			"b     .                                              \n"
			"90:                                                  \n"
			"movs  r0, #108                                      \n"
			"bl    fiber_panic                                   \n"
			"b     90b                                            \n"
			"91:                                                  \n"
			"movs  r0, #80                                       \n"
			"bl    fiber_panic                                   \n"
			"b     91b                                            \n"
			".ltorg                                               \n"
			:
			:
			: "memory", "cc");
}

FIBER_API_NORETURN FIBER_CM4_MPU_PRIVILEGED
void fiber_port_start_first_context(void)
{
	fiber_port_validate_first_start_environment();
	__disable_irq();
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	fiber_port_fpu_prepare();
	fiber_port_validate_svc_vector();
	fiber_port_start_first_context_transfer();
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_restore_first_context_from_svc(
		FiberContext *first FIBER_ATTR_UNUSED_PARAM)
{
	__ASM volatile(
			".syntax unified                         \n"
			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"mov   r2, r0                           \n"
			"ldr   r0, =0xE000ED08                 \n"
			"ldr   r0, [r0]                         \n"
			"ldr   r0, [r0]                         \n"
			"cmp   r0, #0                           \n"
			"beq   90f                              \n"
			"tst   r0, #7                           \n"
			"bne   90f                              \n"
			"msr   msp, r0                          \n"
			"isb                                    \n"
			"ldr   r1, [r2, #0]                    \n"
			"ldmdb r1!, {r0, r4-r11}               \n"
			"msr   psp, r0                          \n"
			"stmia r0, {r4-r11}                    \n"
			"ldmdb r1!, {r3-r11, lr}               \n"
			"str   r1, [r2, #0]                    \n"
			"msr   control, r3                      \n"
			"isb                                    \n"
			"movs  r0, #0                           \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    lr                               \n"
			"90:                                    \n"
			"movs  r0, #80                          \n"
			"bl    fiber_panic                      \n"
			"b     90b                              \n"
			".ltorg                                 \n"
			:
			:
			: "memory", "cc");
}

FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void SVC_Handler(void)
{
	__ASM volatile(
			".syntax unified                                     \n"
			"tst   lr, #4                                        \n"
			"ite   eq                                            \n"
			"mrseq r0, msp                                       \n"
			"mrsne r0, psp                                       \n"
			"mov   r1, lr                                        \n"
			"ldr   r2, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r2, [r2]                                      \n"
			"b     fiber_port_svc_dispatch                       \n"
			".ltorg                                               \n"
			:
			:
			: "memory", "cc");
}

#undef FIBER_CM4_MPU_PRIVILEGED
