/*
 * ARM_CM55F_MPU/non_secure strict first-start SVC component.
 *
 * The pinned FreeRTOS ARM_CM55_NTZ MPU+FPU branch restores its first task from
 * one privileged xMPU_SETTINGS.ulContext[54] image. This component implements
 * that basic first restore: MAIR0 and selected RNR 4[/8/12] pairs are
 * installed while the MPU is disabled, then the exact twenty-word basic view
 * is copied to PSP and returned through 0xFFFFFFBC. It also owns the mandatory
 * forward runtime ABI and pulls the separate scalar-FP PendSV component through
 * a private archive anchor.
 */

#include "fiber_port_private.h"
#include "../../../fiber_panic.h"

#define fiber_portSTRINGIFY2(_value) #_value
#define fiber_portSTRINGIFY(_value) fiber_portSTRINGIFY2(_value)

#define FIBER_CM55F_MPU_SVC \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

#define FIBER_CM55F_MPU_UNPRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portUNPRIVILEGED_FUNCTION

/* This always-linked mandatory runtime object defines the exact selected-port
 * context cohort. Construction and PendSV retain independent relocations. */
FIBER_PORT_CONTEXT_COHORT_DEFINE();

static FIBER_CM55F_MPU_SVC
uintptr_t fiber_port_code_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM55F_MPU_SVC
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) && (inner_end > inner_start) &&
			(inner_start >= outer_start) && (inner_end <= outer_end);
}

static FIBER_CM55F_MPU_SVC
int fiber_port_code_address_is_in_range(uintptr_t range_start,
		uintptr_t range_end,
		uintptr_t address)
{
	return (address <= (UINTPTR_MAX - 2u)) &&
			fiber_port_range_contains(range_start, range_end,
					address, address + 2u);
}

FIBER_CM55F_MPU_SVC
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

FIBER_CM55F_MPU_SVC
void fiber_port_primask_restore(uint32_t primask)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == primask, 'r');
}

static FIBER_CM55F_MPU_SVC
void fiber_port_require_privileged_thread_start_environment(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
}

static FIBER_CM55F_MPU_SVC
void fiber_port_require_mpu_geometry(void)
{
	FIBER_REQUIRE((fiber_portMPU_TYPE_REG & fiber_portMPU_TYPE_DREGION_MASK) ==
			fiber_portMPU_EXPECTED_TYPE, 'M');
}

static FIBER_CM55F_MPU_SVC
void fiber_port_validate_runtime_vector_source(
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t raw_vtor = (uintptr_t)fiber_portSCB_VTOR_REG;
	const uintptr_t vector_base = fiber_port_vectors_base_addr();
	FIBER_REQUIRE(raw_vtor == vector_base, 'V');
	FIBER_REQUIRE((vector_base &
			((uintptr_t)fiber_portVECTOR_ALIGNMENT - 1u)) == 0u, 'V');

	const uintptr_t actual_svc = (uintptr_t)fiber_port_read_vector_slot(
			fiber_portVECTOR_INDEX_SVC);
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

static FIBER_CM55F_MPU_SVC
uint8_t fiber_port_probe_implemented_priority_mask(void)
{
	volatile uint8_t *const first_user_priority =
			(volatile uint8_t *)(uintptr_t)0xE000E400u;
	const uint32_t primask = fiber_port_primask_save_disable();
	FIBER_REQUIRE(primask == 0u, 'p');
	const uint8_t original = *first_user_priority;

	*first_user_priority = 0xFFu;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	const uint8_t implemented = *first_user_priority;

	*first_user_priority = original;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(*first_user_priority == original, 'Q');
	fiber_port_primask_restore(primask);
	return implemented;
}

static FIBER_CM55F_MPU_SVC
uint32_t fiber_port_count_implemented_priority_bits(uint8_t implemented_mask)
{
	uint32_t bits = 0u;
	while ((implemented_mask & 0x80u) != 0u) {
		++bits;
		implemented_mask = (uint8_t)(implemented_mask << 1u);
	}
	return bits;
}

static FIBER_CM55F_MPU_SVC
void fiber_port_validate_basepri_priority_policy(void)
{
	const uint8_t implemented_mask = fiber_port_probe_implemented_priority_mask();
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

static FIBER_CM55F_MPU_SVC
void fiber_port_configure_first_start_exceptions(void)
{
	const uint32_t previous = fiber_port_primask_save_disable();
	FIBER_REQUIRE(previous == 0u, 'p');

	const uint32_t lowest_priority = (1u << __NVIC_PRIO_BITS) - 1u;
	NVIC_SetPriority(SVCall_IRQn, 0u);
	NVIC_SetPriority(PendSV_IRQn, lowest_priority);
	fiber_portSCB_CCR_REG |= fiber_portSCB_CCR_STKALIGN_BIT;
	/* First selection happens before the first context owns PendSV. Do not let
	 * inherited pending state cross that ownership boundary. */
	fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVCLEAR_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();

	FIBER_REQUIRE(NVIC_GetPriority(SVCall_IRQn) == 0u, 'w');
	FIBER_REQUIRE(NVIC_GetPriority(PendSV_IRQn) == lowest_priority, 'P');
	FIBER_REQUIRE((fiber_portSCB_CCR_REG &
			fiber_portSCB_CCR_STKALIGN_BIT) != 0u, 'A');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == 0u, 'J');
	fiber_port_validate_basepri_priority_policy();
	fiber_port_primask_restore(previous);
}

static FIBER_CM55F_MPU_SVC
void fiber_port_validate_first_start_linker_placement(
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t privileged_targets[] = {
		fiber_port_code_address((uintptr_t)&fiber_port_context_init),
		fiber_port_code_address((uintptr_t)&fiber_port_panic_wait),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_require_scheduler_configuration_environment),
		fiber_port_code_address((uintptr_t)&fiber_port_runtime_prepare_start),
		fiber_port_code_address((uintptr_t)&fiber_port_runtime_select_first),
		fiber_port_code_address((uintptr_t)&fiber_port_runtime_start_first),
		fiber_port_code_address((uintptr_t)&fiber_port_handler_bundle_v1_anchor),
		fiber_port_code_address((uintptr_t)&fiber_port_prepare_first_start),
		fiber_port_code_address((uintptr_t)&fiber_port_svc_dispatch),
		fiber_port_code_address((uintptr_t)&fiber_port_start_first_context),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_restore_first_context_from_svc),
		fiber_port_code_address((uintptr_t)&SVC_Handler),
		fiber_port_code_address((uintptr_t)&PendSV_Handler),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_pendsv_validate_save_current),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_scheduler_pick_first_from_start),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_scheduler_pick_next_from_pendsv),
		fiber_port_code_address((uintptr_t)&fiber_port_mpu_switch_to_context),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_mpu_validate_active_context),
		fiber_port_code_address((uintptr_t)&fiber_port_fpu_prepare),
		fiber_port_code_address((uintptr_t)&fiber_port_fpu_require_ready),
		fiber_port_code_address((uintptr_t)&fiber_port_mpu_load_linker_layout),
		fiber_port_code_address((uintptr_t)&fiber_port_mpu_linker_layout_check),
		fiber_port_code_address((uintptr_t)&fiber_port_mpu_build_global_regions),
		fiber_port_code_address(
			(uintptr_t)&fiber_port_context_validate_initial_restore),
		fiber_port_code_address(
			(uintptr_t)&fiber_internal_runtime_require_current_context),
		fiber_port_code_address(
			(uintptr_t)&fiber_internal_runtime_select_scheduler_candidate),
		fiber_port_code_address(
			(uintptr_t)&fiber_internal_runtime_publish_current_context),
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
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_flash_start,
			layout->unprivileged_flash_end,
			fiber_port_code_address((uintptr_t)&fiber_current)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_flash_start,
			layout->unprivileged_flash_end,
			fiber_port_code_address((uintptr_t)&fiber_schedule)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_flash_start,
			layout->unprivileged_flash_end,
			fiber_port_code_address(
				(uintptr_t)&fiber_port_runtime_memory_barrier)), 'L');
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

static FIBER_CM55F_MPU_SVC
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

static FIBER_CM55F_MPU_SVC
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

static FIBER_CM55F_MPU_SVC
const uint32_t *fiber_port_running_svc_core_frame(FiberContext *current,
		const uint32_t *hardware_frame,
		uint32_t exc_return)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	fiber_port_context_seal_check(current);

	const uintptr_t raw_frame = (uintptr_t)hardware_frame;
	FIBER_REQUIRE((raw_frame &
			((uintptr_t)FIBER_PORT_STACK_ALIGNMENT - 1u)) == 0u, 'A');
	FIBER_REQUIRE(raw_frame == (uintptr_t)__get_PSP(), 'P');

	uintptr_t fp_extension = 0u;
	if (exc_return == fiber_portINITIAL_EXC_RETURN) {
		fp_extension = 0u;
	} else if (exc_return == fiber_portEXTENDED_EXC_RETURN) {
		fp_extension = (uintptr_t)FIBER_PORT_EXC_FP_EXT_BYTES;
	} else {
		fiber_panic('l');
		FIBER_API_UNREACHABLE();
	}
	FIBER_REQUIRE(raw_frame <= UINTPTR_MAX - fp_extension -
			FIBER_PORT_EXC_BASE_BYTES, 'O');
	const uintptr_t core_frame = raw_frame + fp_extension;
	const uintptr_t frame_end = core_frame + FIBER_PORT_EXC_BASE_BYTES;
	FIBER_REQUIRE(fiber_port_range_contains(current->boot.stack_base,
				current->boot.stack_top, raw_frame, frame_end), 'P');
#if FIBER_STACK_CANARY
	FIBER_REQUIRE(*(const volatile uint32_t *)(uintptr_t)current->boot.begin ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#endif
	const FiberPortProtectedBasicContext *const image =
			&current->protected_context.basic;
	FIBER_REQUIRE(current->protected_context_cursor == &image->r4, 'P');
	FIBER_REQUIRE(image->cursor_limit == 0u, 'P');
	FIBER_REQUIRE(image->psplim == (uint32_t)current->boot.stack_base, 'L');
	FIBER_REQUIRE((__get_CONTROL() & 3u) ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	return (const uint32_t *)core_frame;
}

static FIBER_CM55F_MPU_SVC
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

static FIBER_CM55F_MPU_SVC
void fiber_port_validate_exact_svc_site(uint32_t stacked_pc,
		const unsigned char *expected_site)
{
	FIBER_REQUIRE(expected_site != NULL, 'u');
	FIBER_REQUIRE((uintptr_t)stacked_pc ==
			fiber_port_code_address((uintptr_t)expected_site), 'u');
}

static FIBER_CM55F_MPU_SVC
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

static FIBER_CM55F_MPU_SVC
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

static FIBER_CM55F_MPU_SVC
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

static FIBER_CM55F_MPU_SVC
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
	fiber_port_fpu_require_ready();
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
	fiber_portMPU_RNR_REG = fiber_portMPU_LAST_CONTEXT_BLOCK_REGION;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG ==
			fiber_portMPU_LAST_CONTEXT_BLOCK_REGION, 'M');
}

/* The only direct Thread-mode helper reachable after CONTROL.nPRIV is set.
 * It intentionally touches no scheduler, MPU, or FP state. */
FIBER_CM55F_MPU_UNPRIVILEGED
void fiber_port_runtime_memory_barrier(void)
{
	fiber_portASM volatile("dmb" ::: "memory");
	fiber_portCOMPILER_BARRIER();
}

FIBER_API_NORETURN FIBER_CM55F_MPU_SVC
void fiber_port_panic_wait(void)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	for (;;) {
		__WFE();
	}
}

FIBER_CM55F_MPU_SVC
void fiber_port_require_scheduler_configuration_environment(void)
{
	fiber_port_require_privileged_thread_start_environment();
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
}

/* This private one-shot call keeps the separately compiled PendSV component in
 * the selected archive. A weak startup PendSV alias therefore cannot satisfy
 * handler extraction by accident. The component itself retains its reverse ABI
 * and exact cohort references. */
FIBER_CM55F_MPU_SVC
void fiber_port_handler_bundle_v1_anchor(void)
{
	fiber_port_arm_cm55f_mpu_pendsv_handler_component_v1_anchor();
}

/* Common fiber_start() calls this before it asks the scheduler for a first
 * context. The first hook therefore observes the same checked exception/FPU
 * policy that later PendSV relies on, while MPU remains disabled until SVC 70. */
FIBER_CM55F_MPU_SVC
void fiber_port_runtime_prepare_start(void)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_handler_bundle_v1_anchor();
	fiber_port_require_scheduler_configuration_environment();
	fiber_port_fpu_prepare();
	fiber_port_fpu_require_ready();
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_first_start_linker_placement(&layout);
	fiber_port_validate_runtime_vector_source(&layout);
	fiber_port_configure_first_start_exceptions();
	fiber_port_validate_runtime_vector_source(&layout);
	fiber_port_require_scheduler_configuration_environment();
	fiber_port_fpu_require_ready();
}

FIBER_CM55F_MPU_SVC
FiberContext *fiber_port_runtime_select_first(void)
{
	return fiber_port_scheduler_pick_first_from_start();
}

FIBER_API_NORETURN FIBER_CM55F_MPU_SVC
void fiber_port_runtime_start_first(FiberContext *first)
{
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_internal_runtime_require_current_context();
	fiber_port_require_scheduler_configuration_environment();
	fiber_port_fpu_require_ready();
	fiber_port_context_validate_initial_restore(first);
	fiber_port_start_first_context(first);
	FIBER_API_UNREACHABLE();
}

FIBER_CM55F_MPU_SVC
void fiber_port_prepare_first_start(FiberContext *first)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_internal_runtime_require_current_context();
	fiber_port_require_privileged_thread_start_environment();
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_fpu_prepare();
	fiber_port_fpu_require_ready();
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_first_start_linker_placement(&layout);
	fiber_port_context_validate_initial_restore(first);
	fiber_port_validate_runtime_vector_source(&layout);
	fiber_port_configure_first_start_exceptions();
	fiber_port_validate_runtime_vector_source(&layout);
	fiber_port_require_privileged_thread_start_environment();
	fiber_port_fpu_require_ready();
}

FIBER_CM55F_MPU_SVC
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
	fiber_port_validate_first_start_linker_placement(&layout);

	const uint32_t *core_frame;
	if (exc_return == fiber_portSVC_ORIGIN_EXC_RETURN) {
		FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
		fiber_port_fpu_require_ready();
		fiber_port_validate_start_svc_frame(hardware_frame, &layout);
		core_frame = hardware_frame;
	} else {
		fiber_port_fpu_require_ready();
		core_frame = fiber_port_running_svc_core_frame(current,
				hardware_frame, exc_return);
		fiber_port_mpu_validate_active_context(current);
	}
	fiber_port_validate_svc_frame_shape(core_frame);

	switch (fiber_port_decode_svc_number(core_frame, &layout)) {
	case fiber_portSVC_START:
		FIBER_REQUIRE(exc_return == fiber_portSVC_ORIGIN_EXC_RETURN, 'l');
		fiber_port_validate_exact_svc_site(core_frame[6],
				fiber_port_svc_start_return_site);
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_port_context_validate_initial_restore(current);
		FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
		FIBER_REQUIRE(fiber_port_primask_save_disable() == 0u, 'p');
		fiber_port_mpu_program_global_image_while_disabled(current);
		fiber_port_restore_first_context_from_svc(current, exc_return);
		FIBER_API_UNREACHABLE();

	case fiber_portSVC_YIELD: {
		FIBER_REQUIRE((exc_return == fiber_portINITIAL_EXC_RETURN) ||
				(exc_return == fiber_portEXTENDED_EXC_RETURN), 'l');
		fiber_port_validate_exact_svc_site(core_frame[6],
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

	case fiber_portSVC_RETURN:
		FIBER_REQUIRE((exc_return == fiber_portINITIAL_EXC_RETURN) ||
				(exc_return == fiber_portEXTENDED_EXC_RETURN), 'l');
		fiber_port_validate_exact_svc_site(core_frame[6],
				fiber_port_svc_return_return_site);
		fiber_internal_task_return();
		FIBER_API_UNREACHABLE();

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
			/* FreeRTOS first restore: disable MPU, load MAIR0 and the
			 * selected 4[/8/12] pairs, enable, then restore basic context. */
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
#if FIBER_PORT_CM55F_MPU_TOTAL_REGIONS == 16
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
			"ldr   r0, [sp, #0]                                   \n"
			"bl    fiber_port_mpu_validate_active_initial_context \n"
			"ldr   r0, [sp, #0]                                   \n"
			"ldr   lr, [sp, #4]                                   \n"
			"add   sp, #8                                         \n"
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
			"and   r5, r5, #7                                     \n"
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

/* Public fiber_schedule() remains CPU-neutral. This protected port uses the
 * exact syscall-flash SVC #71 veneer, which the privileged handler validates
 * before it requests PendSV. */
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
			/* Assembly-visible common state only: load the current pointer;
			 * no selected-port C translation unit can name this lvalue. */
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

#undef FIBER_CM55F_MPU_SVC
