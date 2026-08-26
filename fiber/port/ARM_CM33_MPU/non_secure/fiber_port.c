/*
 * ARM_CM33_MPU/non_secure protected first-start runtime.
 *
 * This staged source implements only the one-shot SVC transition to the first
 * sealed unprivileged context.  It follows the pinned FreeRTOS
 * GCC/ARM_CM33_NTZ/non_secure MPU restore order: global regions are installed
 * while the MPU is disabled, then naked restore writes MAIR0 and the
 * per-context RBAR/RLAR pairs before enabling the MPU and exception-returning
 * through the protected frame.  PendSV, scheduler selection, and public MPU
 * policy are deliberately not introduced here.
 */

#include "fiber_port_private.h"
#include "../../../fiber_panic.h"

#define fiber_portSTRINGIFY2(_value) #_value
#define fiber_portSTRINGIFY(_value) fiber_portSTRINGIFY2(_value)

#define FIBER_CM33_MPU_PRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

FIBER_PORT_CONTEXT_COHORT_DEFINE();

static FIBER_CM33_MPU_PRIVILEGED
uintptr_t fiber_port_code_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM33_MPU_PRIVILEGED
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) && (inner_end > inner_start) &&
			(inner_start >= outer_start) && (inner_end <= outer_end);
}

static FIBER_CM33_MPU_PRIVILEGED
int fiber_port_code_address_is_in_range(uintptr_t range_start,
		uintptr_t range_end,
		uintptr_t address)
{
	return (address <= (UINTPTR_MAX - 2u)) &&
			fiber_port_range_contains(range_start, range_end,
					address, address + 2u);
}

static FIBER_CM33_MPU_PRIVILEGED
uint32_t fiber_port_primask_save_disable(void)
{
	uint32_t primask;
	fiber_portASM volatile(
			"mrs %0, primask\n"
			"cpsid i"
			: "=r"(primask)
			:
			: "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	return primask;
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_primask_restore(uint32_t primask)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_require_privileged_thread_start_environment(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_require_mpu_geometry(void)
{
	FIBER_REQUIRE((fiber_portMPU_TYPE_REG & fiber_portMPU_TYPE_DREGION_MASK) ==
			fiber_portMPU_EXPECTED_TYPE, 'M');
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_validate_start_vector_source(
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t raw_vtor = (uintptr_t)fiber_portSCB_VTOR_REG;
	const uintptr_t vector_base = fiber_port_vectors_base_addr();
	FIBER_REQUIRE(raw_vtor == vector_base, 'V');
	FIBER_REQUIRE((vector_base &
			((uintptr_t)fiber_portVECTOR_ALIGNMENT - 1u)) == 0u, 'V');

	const uintptr_t actual_svc =
			(uintptr_t)fiber_port_read_vector_slot(fiber_portVECTOR_INDEX_SVC);
	const uintptr_t expected_svc = (uintptr_t)&SVC_Handler;
	FIBER_REQUIRE((actual_svc & 1u) != 0u, 'y');
	FIBER_REQUIRE(fiber_port_code_address(actual_svc) ==
			fiber_port_code_address(expected_svc), 'y');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			fiber_port_code_address(expected_svc)), 'L');

	const uintptr_t initial_msp = (uintptr_t)fiber_port_read_initial_msp();
	FIBER_REQUIRE(initial_msp != 0u, 'P');
	FIBER_REQUIRE((initial_msp & 7u) == 0u, 'A');
	FIBER_REQUIRE(initial_msp >= layout->privileged_sram_start +
			FIBER_PORT_EXC_BASE_BYTES, 'P');
	FIBER_REQUIRE(initial_msp <= layout->privileged_sram_end, 'P');
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_configure_first_start_exceptions(void)
{
	const uint32_t previous = fiber_port_primask_save_disable();
	FIBER_REQUIRE(previous == 0u, 'p');

	/* SVC is the selected-port gate. PendSV has no owner in this slice, so it is
	 * cleared but intentionally neither configured nor validated here. */
	NVIC_SetPriority(SVCall_IRQn, 0u);
	fiber_portSCB_CCR_REG |= fiber_portSCB_CCR_STKALIGN_BIT;
	fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVCLEAR_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();

	FIBER_REQUIRE(NVIC_GetPriority(SVCall_IRQn) == 0u, 'w');
	FIBER_REQUIRE((fiber_portSCB_CCR_REG &
			fiber_portSCB_CCR_STKALIGN_BIT) != 0u, 'A');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == 0u, 'J');
	fiber_port_primask_restore(previous);
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_validate_runtime_linker_placement(
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t privileged_targets[] = {
		fiber_port_code_address((uintptr_t)&fiber_port_prepare_first_start),
		fiber_port_code_address((uintptr_t)&fiber_port_svc_dispatch),
		fiber_port_code_address((uintptr_t)&fiber_port_start_first_context),
		fiber_port_code_address((uintptr_t)&fiber_port_restore_first_context_from_svc),
		fiber_port_code_address((uintptr_t)&SVC_Handler),
		fiber_port_code_address((uintptr_t)&fiber_panic)
	};

	for (uint32_t index = 0u;
			index < (uint32_t)(sizeof(privileged_targets) /
				sizeof(privileged_targets[0])); ++index) {
		FIBER_REQUIRE(fiber_port_code_address_is_in_range(
					layout->privileged_flash_start,
					layout->privileged_flash_end,
					privileged_targets[index]), 'L');
	}
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end,
			fiber_port_code_address(
				(uintptr_t)&fiber_port_unprivileged_task_return)), 'L');
}

static FIBER_CM33_MPU_PRIVILEGED
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
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_STACK_ALIGN_BIT) == 0u, 'a');
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_validate_start_svc_frame(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES,
			'O');
	const uintptr_t frame_end = frame_start + FIBER_PORT_EXC_BASE_BYTES;
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_sram_start,
				layout->privileged_sram_end, frame_start, frame_end), 'P');
	FIBER_REQUIRE(frame_end == (uintptr_t)fiber_port_read_initial_msp(), 'P');
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_validate_return_svc_frame(FiberContext *current,
		const uint32_t *hardware_frame)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	fiber_port_context_seal_check(current);
	FIBER_REQUIRE(current->protected_context_cursor ==
			&current->protected_context.r4, 'P');
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES,
			'O');
	const uintptr_t frame_end = frame_start + FIBER_PORT_EXC_BASE_BYTES;
	FIBER_REQUIRE(frame_start == (uintptr_t)__get_PSP(), 'P');
	FIBER_REQUIRE(fiber_port_range_contains(current->boot.stack_base,
				current->boot.stack_top, frame_start, frame_end), 'P');
#if FIBER_STACK_CANARY
	FIBER_REQUIRE(*(const volatile uint32_t *)(uintptr_t)current->boot.begin ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#endif
}

static FIBER_CM33_MPU_PRIVILEGED
uint32_t fiber_port_decode_svc_number(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t pc = (uintptr_t)hardware_frame[6];
	FIBER_REQUIRE(pc >= 2u, 'u');
	const uintptr_t instruction_address = pc - 2u;
	const int in_privileged = fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			instruction_address);
	const int in_syscall = fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end, instruction_address);
	FIBER_REQUIRE((in_privileged != 0) || (in_syscall != 0), 'u');

	const volatile uint8_t *const instruction =
			(const volatile uint8_t *)instruction_address;
	FIBER_REQUIRE(instruction[1] == 0xDFu, 'u');
	return instruction[0];
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_validate_exact_svc_site(uint32_t stacked_pc,
		const unsigned char *expected_site)
{
	FIBER_REQUIRE(expected_site != NULL, 'u');
	FIBER_REQUIRE((uintptr_t)stacked_pc ==
			fiber_port_code_address((uintptr_t)expected_site), 'u');
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_mpu_write_region(uint32_t region_number,
		const FiberPortMpuRegionRegisters *region)
{
	FIBER_REQUIRE(region != NULL, 'M');
	FIBER_REQUIRE(region_number < fiber_portMPU_TOTAL_REGIONS, 'M');
	fiber_portMPU_RNR_REG = region_number;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == region_number, 'M');
	fiber_portMPU_RBAR_REG = region->rbar;
	fiber_portMPU_RLAR_REG = region->rlar;
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_mpu_validate_region_readback(uint32_t region_number,
		const FiberPortMpuRegionRegisters *expected)
{
	FIBER_REQUIRE(expected != NULL, 'M');
	FIBER_REQUIRE(region_number < fiber_portMPU_TOTAL_REGIONS, 'M');
	fiber_portMPU_RNR_REG = region_number;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == region_number, 'M');
	FIBER_REQUIRE(fiber_portMPU_RBAR_REG == expected->rbar, 'M');
	FIBER_REQUIRE(fiber_portMPU_RLAR_REG == expected->rlar, 'M');
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_mpu_program_global_image_while_disabled(FiberContext *first)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(first != NULL, 'N');
	FIBER_REQUIRE(__get_IPSR() == 11u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_mpu_build_global_regions(&global);

	/* FreeRTOS writes its four permanent mappings before the first SVC restore.
	 * Fiber proves every region while the MPU is still disabled; assembly then
	 * writes the selected context pairs and performs the sole enable transition. */
	fiber_portDATA_SYNC_BARRIER();
	fiber_portMPU_CTRL_REG = 0u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	for (uint32_t region = 0u; region < fiber_portMPU_GLOBAL_REGION_COUNT;
			++region) {
		fiber_port_mpu_write_region(region, &global.regions[region]);
	}
	fiber_portSCB_SHCSR_REG |= fiber_portSCB_MEMFAULTENA_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) != 0u, 'M');
	for (uint32_t region = 0u; region < fiber_portMPU_GLOBAL_REGION_COUNT;
			++region) {
		fiber_port_mpu_validate_region_readback(region,
				&global.regions[region]);
	}
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
}

static FIBER_CM33_MPU_PRIVILEGED
void fiber_port_mpu_validate_active_initial_context(const FiberContext *ctx)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(ctx != NULL, 'N');
	FIBER_REQUIRE(__get_IPSR() == 11u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) != 0u, 'M');
	fiber_port_context_validate_initial_restore(ctx);
	FIBER_REQUIRE(fiber_portMPU_MAIR0_REG == ctx->mair0, 'M');
	fiber_port_mpu_build_global_regions(&global);

	for (uint32_t region = 0u; region < fiber_portMPU_GLOBAL_REGION_COUNT;
			++region) {
		fiber_port_mpu_validate_region_readback(region,
				&global.regions[region]);
	}
	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_validate_region_readback(
				fiber_portMPU_STACK_REGION_NUMBER + index,
				&ctx->mpu_regions[index]);
	}

	/* Match the final RNR block programmed by FreeRTOS' 8/16-region restore. */
	fiber_portMPU_RNR_REG = fiber_portMPU_LAST_CONTEXT_BLOCK_REGION;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG ==
			fiber_portMPU_LAST_CONTEXT_BLOCK_REGION, 'M');
}

FIBER_CM33_MPU_PRIVILEGED
void fiber_port_prepare_first_start(FiberContext *first)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_port_require_privileged_thread_start_environment();
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_runtime_linker_placement(&layout);
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_context_validate_initial_restore(first);
	fiber_port_validate_start_vector_source(&layout);
	fiber_port_configure_first_start_exceptions();
	fiber_port_validate_start_vector_source(&layout);
	fiber_port_require_privileged_thread_start_environment();
}

FIBER_API_NORETURN FIBER_CM33_MPU_PRIVILEGED
void fiber_port_svc_dispatch(uint32_t *hardware_frame,
		uint32_t exc_return,
		FiberContext *current)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(__get_IPSR() == 11u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_runtime_linker_placement(&layout);

	if (exc_return == fiber_portSVC_ORIGIN_EXC_RETURN) {
		FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
		fiber_port_validate_start_svc_frame(hardware_frame, &layout);
	} else if (exc_return == fiber_portINITIAL_EXC_RETURN) {
		FIBER_REQUIRE(__get_CONTROL() ==
				fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
		fiber_port_validate_return_svc_frame(current, hardware_frame);
	} else {
		fiber_panic('l');
	}
	fiber_port_validate_svc_frame_shape(hardware_frame);

	switch (fiber_port_decode_svc_number(hardware_frame, &layout)) {
	case fiber_portSVC_START:
		FIBER_REQUIRE(exc_return == fiber_portSVC_ORIGIN_EXC_RETURN, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_start_return_site);
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_port_context_validate_initial_restore(current);
		FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
		FIBER_REQUIRE(fiber_port_primask_save_disable() == 0u, 'p');
		fiber_port_mpu_program_global_image_while_disabled(current);
		fiber_port_restore_first_context_from_svc(current, exc_return);
		FIBER_API_UNREACHABLE();

	case fiber_portSVC_RETURN:
		FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_return_return_site);
		fiber_panic('R');
		FIBER_API_UNREACHABLE();

	/* Yield is reserved until the matching protected PendSV owner arrives. */
	case fiber_portSVC_YIELD:
	default:
		fiber_panic('u');
		FIBER_API_UNREACHABLE();
	}
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_start_first_context(FiberContext *first FIBER_ATTR_UNUSED_PARAM)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			"bl    fiber_port_prepare_first_start                 \n"
			"mrs   r3, ipsr                                       \n"
			"cmp   r3, #0                                         \n"
			"bne   90f                                            \n"
			"mrs   r3, control                                    \n"
			"cmp   r3, #0                                         \n"
			"bne   90f                                            \n"
			"mrs   r3, primask                                    \n"
			"cmp   r3, #0                                         \n"
			"bne   91f                                            \n"
			"mrs   r3, " fiber_portBASEPRI_SYM "                  \n"
			"cmp   r3, #0                                         \n"
			"bne   92f                                            \n"
			"mrs   r3, faultmask                                  \n"
			"cmp   r3, #0                                         \n"
			"bne   90f                                            \n"
			"cpsid i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"ldr   r3, =0xE000ED08                                \n"
			"ldr   r3, [r3]                                       \n"
			"tst   r3, #127                                       \n"
			"bne   93f                                            \n"
			"ldr   r2, [r3, #44]                                  \n"
			"ldr   r1, =SVC_Handler + 1                            \n"
			"cmp   r2, r1                                         \n"
			"bne   93f                                            \n"
			"ldr   r0, [r3]                                       \n"
			"cmp   r0, #0                                         \n"
			"beq   94f                                            \n"
			"tst   r0, #7                                         \n"
			"bne   94f                                            \n"
			"msr   msp, r0                                        \n"
			"isb                                                   \n"
			"mrs   r2, msp                                        \n"
			"cmp   r2, r0                                         \n"
			"bne   94f                                            \n"
			"ldr   r3, =0xE000ED04                                \n"
			"ldr   r2, =0x08000000                                \n"
			"str   r2, [r3]                                       \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"cpsie f                                               \n"
			"cpsie i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_START) "  \n"
			".global fiber_port_svc_start_return_site             \n"
			"fiber_port_svc_start_return_site:                     \n"
			"movs  r0, #121                                       \n"
			"bl    fiber_panic                                    \n"
			"b     .                                               \n"
			"90:                                                   \n"
			"movs  r0, #108                                       \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			"91:                                                   \n"
			"movs  r0, #112                                       \n"
			"bl    fiber_panic                                    \n"
			"b     91b                                             \n"
			"92:                                                   \n"
			"movs  r0, #98                                        \n"
			"bl    fiber_panic                                    \n"
			"b     92b                                             \n"
			"93:                                                   \n"
			"movs  r0, #86                                        \n"
			"bl    fiber_panic                                    \n"
			"b     93b                                             \n"
			"94:                                                   \n"
			"movs  r0, #80                                        \n"
			"bl    fiber_panic                                    \n"
			"b     94b                                             \n"
			".ltorg                                                \n"
			:
			:
			: "memory", "cc");
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_restore_first_context_from_svc(
		FiberContext *first FIBER_ATTR_UNUSED_PARAM,
		uint32_t svc_exc_return FIBER_ATTR_UNUSED_PARAM)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			/* FreeRTOS' first restore disables MPU, loads MAIR0, programs
			 * per-context pairs through RBAR aliases, then enables the MPU. */
			/* A normal C call overwrote LR. Recover the SVC exception-return
			 * token from r1, then keep it with the selected context on MSP while
			 * r0 walks MAIR0 and the per-context MPU pairs. */
			"mov   lr, r1                                         \n"
			"push  {r0, lr}                                       \n"
			"ldr   r1, =0xE000ED94                                \n"
			"ldr   r2, [r1]                                       \n"
			"bic   r2, r2, #1                                     \n"
			"str   r2, [r1]                                       \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"adds  r0, #4                                         \n"
			"ldr   r1, [r0]                                       \n"
			"ldr   r2, =0xE000EDC0                                \n"
			"str   r1, [r2]                                       \n"
			"adds  r0, #4                                         \n"
			"ldr   r1, =0xE000ED98                                \n"
			"ldr   r2, =0xE000ED9C                                \n"
			"movs  r3, #4                                         \n"
			"str   r3, [r1]                                       \n"
			"ldmia r0!, {r4-r11}                                  \n"
			"stmia r2, {r4-r11}                                   \n"
#if FIBER_PORT_CM33_MPU_TOTAL_REGIONS == 16
			"movs  r3, #8                                         \n"
			"str   r3, [r1]                                       \n"
			"ldmia r0!, {r4-r11}                                  \n"
			"stmia r2, {r4-r11}                                   \n"
			"movs  r3, #12                                        \n"
			"str   r3, [r1]                                       \n"
			"ldmia r0!, {r4-r11}                                  \n"
			"stmia r2, {r4-r11}                                   \n"
#endif
			"ldr   r1, =0xE000ED94                                \n"
			"ldr   r2, [r1]                                       \n"
			"orr   r2, r2, #5                                     \n"
			"str   r2, [r1]                                       \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			/* The first C validation is intentionally after enable: it proves
			 * MAIR0, all global pairs, all context pairs, SHCSR, and CTRL. */
			"ldr   r0, [sp, #0]                                   \n"
			"bl    fiber_port_mpu_validate_active_initial_context \n"
			"ldr   r0, [sp, #0]                                   \n"
			"ldr   lr, [sp, #4]                                   \n"
			"add   sp, #8                                         \n"
			/* `lr` is the original SVC return token here. Verify it before
			 * target context restore deliberately replaces LR with the selected
			 * context's EXC_RETURN. */
			"mvn   r5, #71                                        \n" /* 0xFFFFFFB8 */
			"cmp   lr, r5                                         \n"
			"bne   91f                                            \n"
			"ldr   r1, [r0, #0]                                   \n"
			"ldmdb r1!, {r2-r4, lr}                               \n"
			"msr   psp, r2                                        \n"
			"isb                                                   \n"
			"mrs   r5, psp                                        \n"
			"cmp   r5, r2                                         \n"
			"bne   90f                                            \n"
			"msr   psplim, r3                                     \n"
			"isb                                                   \n"
			"mrs   r5, psplim                                     \n"
			"cmp   r5, r3                                         \n"
			"bne   90f                                            \n"
			"msr   control, r4                                    \n"
			"isb                                                   \n"
			"mrs   r5, control                                    \n"
			"and   r5, r5, #3                                     \n"
			"cmp   r5, #3                                         \n"
			"bne   91f                                            \n"
			"mvn   r5, #67                                        \n" /* 0xFFFFFFBC */
			"cmp   lr, r5                                         \n"
			"bne   92f                                            \n"
			"ldmdb r1!, {r4-r11}                                  \n"
			"stmia r2!, {r4-r11}                                  \n"
			"ldmdb r1!, {r4-r11}                                  \n"
			"str   r1, [r0, #0]                                   \n"
			"movs  r0, #0                                         \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mrs   r1, " fiber_portBASEPRI_SYM "                  \n"
			"cmp   r1, #0                                         \n"
			"bne   93f                                            \n"
			"cpsie i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"bx    lr                                              \n"
			"90:                                                   \n"
			"movs  r0, #80                                        \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			"91:                                                   \n"
			"movs  r0, #108                                       \n"
			"bl    fiber_panic                                    \n"
			"b     91b                                             \n"
			"92:                                                   \n"
			"movs  r0, #120                                       \n"
			"bl    fiber_panic                                    \n"
			"b     92b                                             \n"
			"93:                                                   \n"
			"movs  r0, #98                                        \n"
			"bl    fiber_panic                                    \n"
			"b     93b                                             \n"
			".ltorg                                                \n"
			:
			:
			: "memory", "cc");
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portSYSCALL_FUNCTION
void fiber_port_unprivileged_task_return(void)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_RETURN) " \n"
			".global fiber_port_svc_return_return_site            \n"
			"fiber_port_svc_return_return_site:                    \n"
			"1: b 1b                                               \n"
			:
			:
			: "memory", "cc");
}

FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void SVC_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			"mrs   r3, ipsr                                       \n"
			"cmp   r3, #11                                        \n"
			"bne   90f                                            \n"
			"mov   r1, lr                                         \n"
			"tst   r1, #4                                         \n"
			"ite   eq                                             \n"
			"mrseq r0, msp                                        \n"
			"mrsne r0, psp                                        \n"
			/* The common slot is assembly-visible only. C port code never
			 * declares it, reads it, takes its address, or writes it. */
			"ldr   r2, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r2, [r2]                                       \n"
			"ldr   r3, =fiber_port_svc_dispatch + 1               \n"
			"bx    r3                                              \n"
			"90:                                                   \n"
			"movs  r0, #105                                       \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			".ltorg                                                \n"
			:
			:
			: "memory", "cc");
}

#undef FIBER_CM33_MPU_PRIVILEGED
#undef fiber_portSTRINGIFY
#undef fiber_portSTRINGIFY2
