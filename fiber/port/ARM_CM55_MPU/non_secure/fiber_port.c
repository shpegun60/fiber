/*
 * ARM_CM55_MPU/non_secure protected selected runtime.
 *
 * This selected source implements the protected SVC/PendSV engine plus the
 * frozen eight-function forward ABI for the sealed no-FPU/no-TrustZone cohort.
 * It follows pinned FreeRTOS
 * GCC/ARM_CM55_NTZ/non_secure MPU ordering: first start installs global MPU
 * regions, PendSV copies the complete basic hardware frame into privileged
 * context storage, selects under BASEPRI, replaces MAIR0/context pairs while
 * the MPU is disabled, and restores through the protected frame. Public
 * heterogeneous MPU policy remains deliberately absent.
 */

#include "fiber_port_private.h"
#include "../../../fiber_panic.h"

#define fiber_portSTRINGIFY2(_value) #_value
#define fiber_portSTRINGIFY(_value) fiber_portSTRINGIFY2(_value)

#define FIBER_CM55_MPU_PRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

#define FIBER_CM55_MPU_UNPRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portUNPRIVILEGED_FUNCTION

FIBER_PORT_CONTEXT_COHORT_DEFINE();

/* Thread-mode common helpers must remain executable by an unprivileged fiber.
 * They access neither protected context storage nor privileged scheduler state. */
FIBER_CM55_MPU_UNPRIVILEGED
void fiber_port_runtime_memory_barrier(void)
{
	fiber_portASM volatile("dmb" ::: "memory");
	fiber_portCOMPILER_BARRIER();
}

FIBER_API_NORETURN FIBER_CM55_MPU_PRIVILEGED
void fiber_port_panic_wait(void)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	for (;;) {
		__WFE();
	}
}

static FIBER_CM55_MPU_PRIVILEGED
uintptr_t fiber_port_code_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM55_MPU_PRIVILEGED
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) && (inner_end > inner_start) &&
			(inner_start >= outer_start) && (inner_end <= outer_end);
}

static FIBER_CM55_MPU_PRIVILEGED
int fiber_port_code_address_is_in_range(uintptr_t range_start,
		uintptr_t range_end,
		uintptr_t address)
{
	return (address <= (UINTPTR_MAX - 2u)) &&
			fiber_port_range_contains(range_start, range_end,
					address, address + 2u);
}

static FIBER_CM55_MPU_PRIVILEGED
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

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_primask_restore(uint32_t primask)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_require_privileged_thread_start_environment(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
}

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_require_mpu_geometry(void)
{
	FIBER_REQUIRE((fiber_portMPU_TYPE_REG & fiber_portMPU_TYPE_DREGION_MASK) ==
			fiber_portMPU_EXPECTED_TYPE, 'M');
}

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_validate_runtime_vector_source(
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

	const uintptr_t actual_pendsv = (uintptr_t)fiber_port_read_vector_slot(
			fiber_portVECTOR_INDEX_PENDSV);
	const uintptr_t expected_pendsv = (uintptr_t)&PendSV_Handler;
	FIBER_REQUIRE((actual_pendsv & 1u) != 0u, 'Y');
	FIBER_REQUIRE(fiber_port_code_address(actual_pendsv) ==
			fiber_port_code_address(expected_pendsv), 'Y');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			fiber_port_code_address(expected_pendsv)), 'L');

	const uintptr_t initial_msp = (uintptr_t)fiber_port_read_initial_msp();
	FIBER_REQUIRE(initial_msp != 0u, 'P');
	FIBER_REQUIRE((initial_msp & 7u) == 0u, 'A');
	FIBER_REQUIRE(initial_msp >= layout->privileged_sram_start +
			FIBER_PORT_EXC_BASE_BYTES, 'P');
	FIBER_REQUIRE(initial_msp <= layout->privileged_sram_end, 'P');
}

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_configure_first_start_exceptions(void)
{
	const uint32_t previous = fiber_port_primask_save_disable();
	FIBER_REQUIRE(previous == 0u, 'p');

	const uint32_t lowest_priority = (1u << __NVIC_PRIO_BITS) - 1u;
	NVIC_SetPriority(SVCall_IRQn, 0u);
	NVIC_SetPriority(PendSV_IRQn, lowest_priority);
	fiber_portSCB_CCR_REG |= fiber_portSCB_CCR_STKALIGN_BIT;
	fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVCLEAR_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();

	FIBER_REQUIRE(NVIC_GetPriority(SVCall_IRQn) == 0u, 'w');
	FIBER_REQUIRE(NVIC_GetPriority(PendSV_IRQn) == lowest_priority, 'P');
	FIBER_REQUIRE((fiber_portSCB_CCR_REG &
			fiber_portSCB_CCR_STKALIGN_BIT) != 0u, 'A');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == 0u, 'J');
	fiber_port_primask_restore(previous);
}

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_validate_runtime_linker_placement(
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t privileged_targets[] = {
		fiber_port_code_address((uintptr_t)&fiber_port_panic_wait),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_require_scheduler_configuration_environment),
		fiber_port_code_address((uintptr_t)&fiber_port_runtime_prepare_start),
		fiber_port_code_address((uintptr_t)&fiber_port_runtime_select_first),
		fiber_port_code_address((uintptr_t)&fiber_port_runtime_start_first),
		fiber_port_code_address((uintptr_t)&fiber_port_prepare_first_start),
		fiber_port_code_address((uintptr_t)&fiber_port_svc_dispatch),
		fiber_port_code_address((uintptr_t)&fiber_port_context_validate_restore),
		fiber_port_code_address((uintptr_t)&fiber_port_pendsv_validate_save_current),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_scheduler_pick_next_from_pendsv),
		fiber_port_code_address((uintptr_t)&fiber_port_mpu_switch_to_context),
		fiber_port_code_address((uintptr_t)&fiber_port_start_first_context),
		fiber_port_code_address((uintptr_t)&fiber_port_restore_first_context_from_svc),
		fiber_port_code_address((uintptr_t)&SVC_Handler),
		fiber_port_code_address((uintptr_t)&PendSV_Handler),
		fiber_port_code_address(
			(uintptr_t)&fiber_internal_runtime_select_scheduler_candidate),
		fiber_port_code_address(
			(uintptr_t)&fiber_internal_runtime_publish_current_context),
		fiber_port_code_address((uintptr_t)&fiber_internal_runtime_require_current_context),
		fiber_port_code_address((uintptr_t)&fiber_internal_task_return),
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
	/* These public Thread entries execute after CONTROL.nPRIV becomes one. The
	 * linker contract places their shared input section in unprivileged flash;
	 * check the externally visible entries here as the board-side fail-closed
	 * counterpart to the synthetic ELF range audit. */
	const uintptr_t unprivileged_targets[] = {
		fiber_port_code_address((uintptr_t)&fiber_current),
		fiber_port_code_address((uintptr_t)&fiber_schedule),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_runtime_memory_barrier)
	};
	for (uint32_t index = 0u;
			index < (uint32_t)(sizeof(unprivileged_targets) /
				sizeof(unprivileged_targets[0])); ++index) {
		FIBER_REQUIRE(fiber_port_code_address_is_in_range(
					layout->unprivileged_flash_start,
					layout->unprivileged_flash_end,
					unprivileged_targets[index]), 'L');
	}
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end,
			fiber_port_code_address(
				(uintptr_t)&fiber_port_unprivileged_task_return)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end,
			fiber_port_code_address(
				(uintptr_t)&fiber_port_runtime_schedule)), 'L');
}

static FIBER_CM55_MPU_PRIVILEGED
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

static FIBER_CM55_MPU_PRIVILEGED
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

/* The current image is live on PSP while SVC/PendSV execute. Verify it before
 * either handler reads mutable context fields or copies the hardware frame. */
static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_validate_running_context_frame(const FiberContext *current,
		const uint32_t *hardware_frame)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	fiber_port_context_seal_check(current);
	const FiberPortProtectedContext *const image =
			&current->protected_context;
	FIBER_REQUIRE(current->protected_context_cursor == &image->r4, 'P');
	FIBER_REQUIRE(image->cursor_limit == 0u, 'P');
	FIBER_REQUIRE(image->psplim == (uint32_t)current->boot.stack_base, 'L');
	FIBER_REQUIRE(image->control ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'q');
	FIBER_REQUIRE(image->exc_return == fiber_portINITIAL_EXC_RETURN, 'x');
	FIBER_REQUIRE(current->runtime_flags == 0u, 'F');
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES,
			'O');
	const uintptr_t frame_end = frame_start + FIBER_PORT_EXC_BASE_BYTES;
	FIBER_REQUIRE(frame_start == (uintptr_t)__get_PSP(), 'P');
	FIBER_REQUIRE(image->psp == (uint32_t)frame_start, 'P');
	FIBER_REQUIRE((frame_start &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'A');
	FIBER_REQUIRE(fiber_port_range_contains(current->boot.stack_base,
				current->boot.stack_top, frame_start, frame_end), 'P');
#if FIBER_STACK_CANARY
	FIBER_REQUIRE(*(const volatile uint32_t *)(uintptr_t)current->boot.begin ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#endif
	fiber_port_validate_svc_frame_shape(hardware_frame);
}

static FIBER_CM55_MPU_PRIVILEGED
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

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_validate_exact_svc_site(uint32_t stacked_pc,
		const unsigned char *expected_site)
{
	FIBER_REQUIRE(expected_site != NULL, 'u');
	FIBER_REQUIRE((uintptr_t)stacked_pc ==
			fiber_port_code_address((uintptr_t)expected_site), 'u');
}

static FIBER_CM55_MPU_PRIVILEGED
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

static FIBER_CM55_MPU_PRIVILEGED
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

static FIBER_CM55_MPU_PRIVILEGED
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

static FIBER_CM55_MPU_PRIVILEGED
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

/* Validate the active MPU image without assuming that the selected context is
 * still an initial image. This is used before saving the running context and
 * after replacing the next context's per-fiber image. */
static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_mpu_validate_active_context(const FiberContext *ctx)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(ctx != NULL, 'N');
	fiber_port_context_seal_check(ctx);
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) != 0u, 'M');
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

	/* Match the last RNR block written by the FreeRTOS 8/16-region sequence. */
	fiber_portMPU_RNR_REG = fiber_portMPU_LAST_CONTEXT_BLOCK_REGION;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG ==
			fiber_portMPU_LAST_CONTEXT_BLOCK_REGION, 'M');
}

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_validate_saved_hardware_frame(const FiberContext *ctx,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(ctx != NULL, 'N');
	FIBER_REQUIRE(layout != NULL, 'L');
	const FiberPortProtectedContext *const image =
			&ctx->protected_context;
	const uint32_t stacked_pc = image->pc;
	const uint32_t stacked_xpsr = image->xpsr;
	FIBER_REQUIRE(stacked_pc >= 2u, 'x');
	FIBER_REQUIRE((stacked_pc & 1u) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_THUMB_BIT) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_IPSR_MASK) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_STACK_ALIGN_BIT) == 0u,
			'a');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_flash_start,
			layout->unprivileged_flash_end, (uintptr_t)stacked_pc), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->privileged_flash_start,
			layout->privileged_flash_end, (uintptr_t)stacked_pc), 'c');
	FIBER_REQUIRE(!fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end, (uintptr_t)stacked_pc), 'c');
}

FIBER_CM55_MPU_PRIVILEGED
void fiber_port_context_validate_restore(FiberContext *ctx)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_REQUIRE(ctx != NULL, 'N');
	fiber_port_context_seal_check(ctx);
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	const FiberPortProtectedContext *const image =
			&ctx->protected_context;
	FIBER_REQUIRE(ctx->protected_context_cursor == &image->cursor_limit, 'P');
	FIBER_REQUIRE(image->cursor_limit == 0u, 'P');
	FIBER_REQUIRE(image->psplim == (uint32_t)ctx->boot.stack_base, 'L');
	FIBER_REQUIRE(image->control ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'q');
	FIBER_REQUIRE(image->exc_return == fiber_portINITIAL_EXC_RETURN, 'x');
	FIBER_REQUIRE(ctx->runtime_flags == 0u, 'F');

	const uintptr_t psp = (uintptr_t)image->psp;
	FIBER_REQUIRE((psp &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'A');
	FIBER_REQUIRE(psp <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES, 'O');
	FIBER_REQUIRE(psp >= ctx->boot.stack_base, 'P');
	FIBER_REQUIRE((psp + FIBER_PORT_EXC_BASE_BYTES) <=
			ctx->boot.stack_top, 'P');
#if FIBER_STACK_CANARY
	FIBER_REQUIRE(*(const volatile uint32_t *)(uintptr_t)ctx->boot.begin ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#endif
	fiber_port_validate_saved_hardware_frame(ctx, &layout);
}

FIBER_CM55_MPU_PRIVILEGED
void fiber_port_pendsv_validate_save_current(FiberContext *current,
		uint32_t *hardware_frame,
		uint32_t exc_return)
{
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE(__get_CONTROL() ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	fiber_port_validate_running_context_frame(current, hardware_frame);
	fiber_port_mpu_validate_active_context(current);
}

typedef struct FiberPortMpuSchedulerCpuState {
	uint32_t primask;
	uint32_t basepri;
	uint32_t faultmask;
	uint32_t control;
	uint32_t ipsr;
	uint32_t psp;
	uint32_t psplim;
	uintptr_t vector_base;
	uint32_t svc_priority;
	uint32_t pendsv_priority;
	uint32_t pendsv_pending;
	uint32_t mpu_ctrl;
	uint32_t mpu_rnr;
	uint32_t mair0;
	uint32_t memfault_enabled;
	FiberPortMpuRegionRegisters mpu_regions[fiber_portMPU_TOTAL_REGIONS];
} FiberPortMpuSchedulerCpuState;

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_capture_scheduler_mpu_image(
		FiberPortMpuSchedulerCpuState *state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	/* The first scheduler selection runs before MPU activation, so RNR has no
	 * canonical active-context value yet. Preserve exactly whichever valid RNR
	 * the application supplied; ordinary PendSV still reaches the canonical
	 * last context region through fiber_port_mpu_validate_active_context(). */
	FIBER_REQUIRE(state->mpu_rnr < fiber_portMPU_TOTAL_REGIONS, 'M');

	for (uint32_t region = 0u; region < fiber_portMPU_TOTAL_REGIONS;
			++region) {
		fiber_portMPU_RNR_REG = region;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		FIBER_REQUIRE(fiber_portMPU_RNR_REG == region, 'M');
		state->mpu_regions[region].rbar = fiber_portMPU_RBAR_REG;
		state->mpu_regions[region].rlar = fiber_portMPU_RLAR_REG;
	}

	fiber_portMPU_RNR_REG = state->mpu_rnr;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == state->mpu_rnr, 'M');
}

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_validate_scheduler_mpu_image(
		const FiberPortMpuSchedulerCpuState *before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	FIBER_REQUIRE(before->mpu_rnr < fiber_portMPU_TOTAL_REGIONS, 'M');

	for (uint32_t region = 0u; region < fiber_portMPU_TOTAL_REGIONS;
			++region) {
		fiber_portMPU_RNR_REG = region;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		FIBER_REQUIRE(fiber_portMPU_RNR_REG == region, 'M');
		FIBER_REQUIRE(fiber_portMPU_RBAR_REG ==
				before->mpu_regions[region].rbar, 'M');
		FIBER_REQUIRE(fiber_portMPU_RLAR_REG ==
				before->mpu_regions[region].rlar, 'M');
	}

	fiber_portMPU_RNR_REG = before->mpu_rnr;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == before->mpu_rnr, 'M');
}

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_capture_scheduler_cpu_state(
		FiberPortMpuSchedulerCpuState *state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->basepri = fiber_port_basepri_read();
	state->faultmask = __get_FAULTMASK();
	state->control = __get_CONTROL();
	state->ipsr = __get_IPSR();
	state->psp = __get_PSP();
	state->psplim = __get_PSPLIM();
	state->vector_base = fiber_port_vectors_base_addr();
	state->svc_priority = NVIC_GetPriority(SVCall_IRQn);
	state->pendsv_priority = NVIC_GetPriority(PendSV_IRQn);
	state->pendsv_pending = fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT;
	FIBER_REQUIRE(state->pendsv_pending == 0u, 'J');
	state->mpu_ctrl = fiber_portMPU_CTRL_REG;
	state->mpu_rnr = fiber_portMPU_RNR_REG;
	state->mair0 = fiber_portMPU_MAIR0_REG;
	state->memfault_enabled = fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT;
	fiber_port_capture_scheduler_mpu_image(state);
	fiber_portCOMPILER_BARRIER();
}

static FIBER_CM55_MPU_PRIVILEGED
void fiber_port_validate_scheduler_cpu_state(
		const FiberPortMpuSchedulerCpuState *before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'r');
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'B');
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 't');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
	FIBER_REQUIRE(__get_IPSR() == before->ipsr, 'i');
	FIBER_REQUIRE(__get_PSP() == before->psp, 'P');
	FIBER_REQUIRE(__get_PSPLIM() == before->psplim, 'L');
	FIBER_REQUIRE(fiber_port_vectors_base_addr() == before->vector_base, 'V');
	FIBER_REQUIRE(NVIC_GetPriority(SVCall_IRQn) == before->svc_priority, 'w');
	FIBER_REQUIRE(NVIC_GetPriority(PendSV_IRQn) == before->pendsv_priority,
			'P');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == before->pendsv_pending, 'J');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == before->mpu_ctrl, 'M');
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == before->mpu_rnr, 'M');
	FIBER_REQUIRE(fiber_portMPU_MAIR0_REG == before->mair0, 'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) == before->memfault_enabled, 'M');
	fiber_port_validate_scheduler_mpu_image(before);
	fiber_portCOMPILER_BARRIER();
}

FIBER_CM55_MPU_PRIVILEGED
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(
		FiberContext *current)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE(__get_CONTROL() ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');

	FiberPortMpuSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const next =
			fiber_internal_runtime_select_scheduler_candidate(current);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(next);
	return next;
}

FIBER_CM55_MPU_PRIVILEGED
void fiber_port_mpu_switch_to_context(FiberContext *next)
{
	FIBER_REQUIRE(next != NULL, 'N');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE(__get_CONTROL() ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	fiber_port_context_validate_restore(next);
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');

	/* FreeRTOS disables the MPU while replacing MAIR0 and each task-owned
	 * RBAR/RLAR pair. Fiber keeps PRIMASK asserted and read-backs every image
	 * word before exposing the selected unprivileged context. */
	fiber_portDATA_SYNC_BARRIER();
	fiber_portMPU_CTRL_REG = 0u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');

	fiber_portMPU_MAIR0_REG = next->mair0;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_MAIR0_REG == next->mair0, 'M');
	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_write_region(
				fiber_portMPU_STACK_REGION_NUMBER + index,
				&next->mpu_regions[index]);
	}

	/* ARMv8-M cannot encode privileged-RW plus unprivileged-RO for the
	 * current-slot aperture. Its selected context pair is therefore RO/XN for
	 * both privilege levels. Publish only while MPU_CTRL is disabled, after all
	 * candidate image writes/readbacks and before exposing that image. */
	fiber_internal_runtime_publish_current_context(next);

	fiber_portMPU_CTRL_REG = fiber_portMPU_CTRL_REQUIRED;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	fiber_port_mpu_validate_active_context(next);
}

FIBER_CM55_MPU_PRIVILEGED
void fiber_port_require_scheduler_configuration_environment(void)
{
	fiber_port_require_privileged_thread_start_environment();
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
}

/* Common fiber_start() calls this before the first scheduler selection. The
 * first hook therefore sees a fully checked port environment, but MPU remains
 * disabled until the selected first context enters through SVC 70. */
FIBER_CM55_MPU_PRIVILEGED
void fiber_port_runtime_prepare_start(void)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_require_scheduler_configuration_environment();
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_runtime_linker_placement(&layout);
	fiber_port_validate_runtime_vector_source(&layout);
	fiber_port_configure_first_start_exceptions();
	fiber_port_validate_runtime_vector_source(&layout);
	fiber_port_require_scheduler_configuration_environment();
}

FIBER_CM55_MPU_PRIVILEGED
FiberContext *fiber_port_runtime_select_first(void)
{
	fiber_port_require_scheduler_configuration_environment();

	/* The first hook runs privileged while MPU_CTRL is disabled. Preserve all
	 * architectural state, including the otherwise non-canonical pre-start RNR,
	 * so policy code cannot mutate the prepared SVC transfer contract. */
	const uint32_t previous = fiber_port_primask_save_disable();
	FIBER_REQUIRE(previous == 0u, 'p');
	FiberPortMpuSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const first =
			fiber_internal_runtime_select_scheduler_candidate(NULL);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_initial_restore(first);
	fiber_port_primask_restore(previous);
	return first;
}

FIBER_API_NORETURN FIBER_CM55_MPU_PRIVILEGED
void fiber_port_runtime_start_first(FiberContext *first)
{
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_internal_runtime_require_current_context();
	fiber_port_require_scheduler_configuration_environment();
	fiber_port_context_validate_initial_restore(first);
	fiber_port_start_first_context(first);
	FIBER_API_UNREACHABLE();
}

/* The naked first-start veneer repeats only final transfer checks. Setup and
 * exception configuration completed before the scheduler chose `first`. */
FIBER_CM55_MPU_PRIVILEGED
void fiber_port_prepare_first_start(FiberContext *first)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_internal_runtime_require_current_context();
	fiber_port_require_scheduler_configuration_environment();
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_runtime_linker_placement(&layout);
	fiber_port_context_validate_initial_restore(first);
	fiber_port_validate_runtime_vector_source(&layout);
}

FIBER_CM55_MPU_PRIVILEGED
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
		fiber_port_validate_running_context_frame(current, hardware_frame);
		fiber_port_mpu_validate_active_context(current);
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
		fiber_internal_task_return();
		FIBER_API_UNREACHABLE();

	case fiber_portSVC_YIELD: {
		FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_yield_return_site);
		const uint32_t previous = fiber_port_primask_save_disable();
		FIBER_REQUIRE(previous == 0u, 'p');
		fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVSET_BIT;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
				fiber_portNVIC_PENDSVSET_BIT) != 0u, 'J');
		fiber_port_primask_restore(previous);
		return;
	}

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
#if FIBER_PORT_CM55_MPU_TOTAL_REGIONS == 16
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

/* The forward ABI keeps fiber_schedule() CPU-neutral. On this protected port
 * its only Thread-mode transfer is the exact syscall-flash SVC 71 veneer. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FIBER_ATTR_NAKED_ASM fiber_portSYSCALL_FUNCTION
void fiber_port_runtime_schedule(void)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_YIELD) "  \n"
			".global fiber_port_svc_yield_return_site             \n"
			"fiber_port_svc_yield_return_site:                     \n"
			"bx    lr                                              \n"
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

/*
 * Protected ARMv8.1-M Mainline MPU context switch.
 *
 * This mirrors the pinned FreeRTOS ARM_CM55_NTZ MPU sequence: the complete
 * basic hardware frame is copied into privileged FiberContext storage, then
 * the scheduler runs under BASEPRI, MAIR0/per-context MPU pairs are replaced
 * while PRIMASK protects the disabled-MPU interval, and the selected frame is
 * copied back to PSP before exception return. The extra C preflight/readback
 * calls are deliberate integrity checks; they do not alter the 20-word image.
 */
FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void PendSV_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			"mrs   r0, psp                                        \n" /* hardware frame */
			"ldr   r1, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r1, [r1]                                       \n" /* current */
			"cmp   r1, #0                                         \n"
			"beq   90f                                            \n"

			/* Do not load metadata through current until C establishes pointer,
			 * seal, active MPU image, frame bounds, and exception provenance. */
			"push  {r0, r1, r2, lr}                               \n"
			"mov   r2, lr                                         \n"
			"mov   r3, r0                                         \n"
			"mov   r0, r1                                         \n"
			"mov   r1, r3                                         \n"
			"bl    fiber_port_pendsv_validate_save_current        \n"
			"pop   {r0, r1, r2, lr}                               \n"

			/* Save r4-r11, copy the complete basic hardware frame, then save
			 * PSP, PSPLIM, CONTROL, and EXC_RETURN. The cursor reaches the
			 * one-past cursor_limit word exactly as in FreeRTOS. */
			"mov   r2, r1                                         \n"
			"ldr   r1, [r2, #0]                                   \n"
			"stmia r1!, {r4-r11}                                  \n"
			"ldmia r0, {r4-r11}                                   \n"
			"stmia r1!, {r4-r11}                                  \n"
			"mrs   r3, psplim                                     \n"
			"mrs   r4, control                                    \n"
			"stmia r1!, {r0, r3, r4, lr}                          \n"
			"str   r1, [r2, #0]                                   \n"

			/* The reverse bridge owns scheduler policy and validates the selected
			 * restore image before returning it in r0. Publication moves with the
			 * MPU image below, while MPU_CTRL is disabled. */
			"movs  r0, #%c[sched_basepri]                          \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mov   r0, r2                                         \n"
			"bl    fiber_port_scheduler_pick_next_from_pendsv     \n"

			/* No configurable IRQ may observe MPU_CTRL disabled or a partial
			 * MAIR0/RBAR/RLAR image. BASEPRI stays raised until validation ends. */
			"cpsid i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"push  {r0, lr}                                       \n"
			"bl    fiber_port_mpu_switch_to_context               \n"
			"pop   {r2, lr}                                       \n"
			"movs  r0, #0                                         \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mrs   r3, " fiber_portBASEPRI_SYM "                  \n"
			"cmp   r3, #0                                         \n"
			"bne   94f                                            \n"

			/* Restore the selected protected image in the exact inverse order:
			 * special words, copied hardware frame, callee-saved words, cursor. */
			"ldr   r1, [r2, #0]                                   \n"
			"ldmdb r1!, {r0, r3, r4, lr}                          \n"
			"msr   psp, r0                                        \n"
			"isb                                                   \n"
			"mrs   r5, psp                                        \n"
			"cmp   r5, r0                                         \n"
			"bne   91f                                            \n"
			"msr   psplim, r3                                     \n"
			"isb                                                   \n"
			"mrs   r5, psplim                                     \n"
			"cmp   r5, r3                                         \n"
			"bne   92f                                            \n"
			"msr   control, r4                                    \n"
			"isb                                                   \n"
			"mrs   r5, control                                    \n"
			"and   r5, r5, #3                                     \n"
			"cmp   r5, #3                                         \n"
			"bne   93f                                            \n"
			"mvn   r5, #67                                        \n" /* 0xFFFFFFBC */
			"cmp   lr, r5                                         \n"
			"bne   95f                                            \n"
			"ldmdb r1!, {r4-r11}                                  \n"
			"stmia r0!, {r4-r11}                                  \n"
			"ldmdb r1!, {r4-r11}                                  \n"
			"str   r1, [r2, #0]                                   \n"
			"cpsie i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"bx    lr                                              \n"

			"90:                                                   \n"
			"movs  r0, #106                                       \n" /* 'j' */
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			"91:                                                   \n"
			"movs  r0, #80                                        \n" /* 'P' */
			"bl    fiber_panic                                    \n"
			"b     91b                                             \n"
			"92:                                                   \n"
			"movs  r0, #76                                        \n" /* 'L' */
			"bl    fiber_panic                                    \n"
			"b     92b                                             \n"
			"93:                                                   \n"
			"movs  r0, #108                                       \n" /* 'l' */
			"bl    fiber_panic                                    \n"
			"b     93b                                             \n"
			"94:                                                   \n"
			"movs  r0, #98                                        \n" /* 'b' */
			"bl    fiber_panic                                    \n"
			"b     94b                                             \n"
			"95:                                                   \n"
			"movs  r0, #120                                       \n" /* 'x' */
			"bl    fiber_panic                                    \n"
			"b     95b                                             \n"
			".ltorg                                                \n"
			:
			: [sched_basepri] "i" (FIBER_PORT_SCHEDULER_BASEPRI)
			: "memory", "cc");
}

#undef FIBER_CM55_MPU_UNPRIVILEGED
#undef FIBER_CM55_MPU_PRIVILEGED
#undef fiber_portSTRINGIFY
#undef fiber_portSTRINGIFY2
