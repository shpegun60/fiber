/*
 * ARM_CM33F_MPU/non_secure protected SVC #70/#71/#72 and runtime adapters.
 *
 * Adapted from the pinned FreeRTOS ARM_CM33_NTZ MPU+FPU first restore:
 * MAIR0, RNR 4[/8/12] alias blocks, basic special/core/integer state, and
 * 0xFFFFFFBC exception return. Running services validate owned syscall sites;
 * the separate PendSV object owns FP transfers. This mandatory runtime object
 * provides the exact context/storage cohorts and retains that handler member.
 */

#include "fiber_port_private.h"

#define fiber_portSTRINGIFY2(_value) #_value
#define fiber_portSTRINGIFY(_value) fiber_portSTRINGIFY2(_value)

#define FIBER_CM33F_MPU_SVC \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

#define FIBER_CM33F_MPU_UNPRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portUNPRIVILEGED_FUNCTION

FIBER_PORT_CONTEXT_COHORT_DEFINE();

/* Cover the complete nine-bit architectural exception-number space in the
 * immutable map, not just the words read by this first-start component. */
enum { FIBER_CM33F_MPU_VECTOR_STORAGE_BYTES = 512u * 4u };

static FIBER_CM33F_MPU_SVC
uintptr_t fiber_port_code_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM33F_MPU_SVC
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) && (inner_end > inner_start) &&
			(inner_start >= outer_start) && (inner_end <= outer_end);
}

static FIBER_CM33F_MPU_SVC
int fiber_port_code_address_is_in_range(uintptr_t range_start,
		uintptr_t range_end,
		uintptr_t address)
{
	return (address <= UINTPTR_MAX - 2u) &&
			fiber_port_range_contains(range_start, range_end,
					address, address + 2u);
}

static FIBER_CM33F_MPU_SVC
void fiber_port_require_privileged_thread_start_environment(void)
{
	FIBER_REQUIRE(fiber_port_cpu_read_ipsr() == 0u, 'i');
	FIBER_REQUIRE(fiber_port_cpu_read_control() == 0u, 'l');
	FIBER_REQUIRE(fiber_port_cpu_read_primask() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(fiber_port_cpu_read_faultmask() == 0u, 'f');
}

FIBER_CM33F_MPU_SVC
uint32_t fiber_port_primask_save_disable(void)
{
	uint32_t primask;
	fiber_portASM volatile("mrs %0, primask\ncpsid i"
			: "=r"(primask) :: "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	return primask;
}

FIBER_CM33F_MPU_SVC
void fiber_port_primask_restore(uint32_t primask)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_cpu_read_primask() == primask, 'r');
}

static FIBER_CM33F_MPU_SVC
void fiber_port_require_mpu_geometry(void)
{
	FIBER_REQUIRE((fiber_portMPU_TYPE_REG & fiber_portMPU_TYPE_DREGION_MASK) ==
			fiber_portMPU_EXPECTED_TYPE, 'M');
}

static FIBER_CM33F_MPU_SVC
void fiber_port_validate_start_vector_source(
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t raw_vtor = (uintptr_t)fiber_portSCB_VTOR_REG;
	const uintptr_t vector_base = fiber_port_vectors_base_addr();
	FIBER_REQUIRE(raw_vtor == vector_base, 'V');
	FIBER_REQUIRE((vector_base &
			((uintptr_t)fiber_portVECTOR_ALIGNMENT - 1u)) == 0u, 'V');
	FIBER_REQUIRE(vector_base <= UINTPTR_MAX -
			FIBER_CM33F_MPU_VECTOR_STORAGE_BYTES, 'V');
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_flash_start,
				layout->privileged_flash_end, vector_base,
				vector_base + FIBER_CM33F_MPU_VECTOR_STORAGE_BYTES), 'V');

	const uintptr_t actual_svc = (uintptr_t)fiber_port_read_vector_slot(
			fiber_portVECTOR_INDEX_SVC);
	FIBER_REQUIRE((actual_svc & 1u) != 0u, 'y');
	FIBER_REQUIRE(fiber_port_code_address(actual_svc) ==
			fiber_port_code_address((uintptr_t)&SVC_Handler), 'y');
	const uintptr_t actual_pendsv = (uintptr_t)fiber_port_read_vector_slot(
			fiber_portVECTOR_INDEX_PENDSV);
	FIBER_REQUIRE((actual_pendsv & 1u) != 0u, 'Y');
	FIBER_REQUIRE(fiber_port_code_address(actual_pendsv) ==
			fiber_port_code_address((uintptr_t)&PendSV_Handler), 'Y');
	const uintptr_t initial_msp = (uintptr_t)fiber_port_read_initial_msp();
	FIBER_REQUIRE(initial_msp != 0u, 'P');
	FIBER_REQUIRE((initial_msp & 7u) == 0u, 'A');
	FIBER_REQUIRE(initial_msp >= layout->privileged_sram_start +
			FIBER_PORT_EXC_BASE_BYTES, 'P');
	FIBER_REQUIRE(initial_msp <= layout->privileged_sram_end, 'P');
	FIBER_REQUIRE((uintptr_t)fiber_portSCB_VTOR_REG == raw_vtor, 'V');
	FIBER_REQUIRE((uintptr_t)fiber_port_read_initial_msp() == initial_msp, 'P');
}

static FIBER_CM33F_MPU_SVC
uint8_t fiber_port_probe_implemented_priority_mask(void)
{
	volatile uint8_t *const first_user_priority =
			(volatile uint8_t *)(uintptr_t)0xE000E400u;
	const uint32_t primask = fiber_port_primask_save_disable();
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

static FIBER_CM33F_MPU_SVC
void fiber_port_validate_basepri_priority_policy(void)
{
	const uint8_t implemented_mask = fiber_port_probe_implemented_priority_mask();
	uint8_t remaining = implemented_mask;
	uint32_t bits = 0u;
	while ((remaining & 0x80u) != 0u) {
		++bits;
		remaining = (uint8_t)(remaining << 1u);
	}
	const uint8_t cmsis_mask = (uint8_t)(0xFFu << (8u - __NVIC_PRIO_BITS));
	FIBER_REQUIRE(implemented_mask != 0u, 'Q');
	FIBER_REQUIRE(implemented_mask == cmsis_mask, 'Q');
	FIBER_REQUIRE(bits == (uint32_t)__NVIC_PRIO_BITS, 'Q');
	FIBER_REQUIRE(((uint32_t)FIBER_PORT_SCHEDULER_BASEPRI &
			(uint32_t)implemented_mask) != 0u, 'Q');
	FIBER_REQUIRE(((uint32_t)FIBER_PORT_SCHEDULER_BASEPRI &
			~(uint32_t)implemented_mask) == 0u, 'q');
	const uint32_t max_prigroup = (bits < 8u) ? (7u - bits) : 0u;
	FIBER_REQUIRE((SCB->AIRCR & (0x07u << 8u)) <=
			(max_prigroup << 8u), 'g');
}

static FIBER_CM33F_MPU_SVC
void fiber_port_configure_first_start_exceptions(void)
{
	const uint32_t previous = fiber_port_primask_save_disable();
	FIBER_REQUIRE(previous == 0u, 'p');
	const uint32_t lowest_priority = (1u << __NVIC_PRIO_BITS) - 1u;
	fiber_port_cpu_set_priority(SVCall_IRQn, 0u);
	fiber_port_cpu_set_priority(PendSV_IRQn, lowest_priority);
	fiber_portSCB_CCR_REG |= fiber_portSCB_CCR_STKALIGN_BIT;
	fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVCLEAR_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_cpu_get_priority(SVCall_IRQn) == 0u, 'w');
	FIBER_REQUIRE(fiber_port_cpu_get_priority(PendSV_IRQn) == lowest_priority, 'P');
	FIBER_REQUIRE((fiber_portSCB_CCR_REG &
			fiber_portSCB_CCR_STKALIGN_BIT) != 0u, 'A');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == 0u, 'J');
	fiber_port_validate_basepri_priority_policy();
	fiber_port_primask_restore(previous);
}

static FIBER_CM33F_MPU_SVC
void fiber_port_validate_start_svc_frame(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE((frame_start & 7u) == 0u, 'A');
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES, 'O');
	const uintptr_t frame_end = frame_start + FIBER_PORT_EXC_BASE_BYTES;
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_sram_start,
				layout->privileged_sram_end, frame_start, frame_end), 'P');
	FIBER_REQUIRE(frame_end == (uintptr_t)fiber_port_read_initial_msp(), 'P');
	const uint32_t stacked_pc = hardware_frame[6];
	const uint32_t stacked_xpsr = hardware_frame[7];
	FIBER_REQUIRE(stacked_pc >= 2u && (stacked_pc & 1u) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_THUMB_BIT) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_IPSR_MASK) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_STACK_ALIGN_BIT) == 0u, 'a');
}

static FIBER_CM33F_MPU_SVC
void fiber_port_validate_start_svc_site(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	const uintptr_t pc = (uintptr_t)hardware_frame[6];
	FIBER_REQUIRE(pc == fiber_port_code_address(
			(uintptr_t)fiber_port_svc_start_return_site), 'u');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			pc - 2u), 'u');
	const volatile uint8_t *const instruction =
			(const volatile uint8_t *)(pc - 2u);
	FIBER_REQUIRE(instruction[1] == 0xDFu, 'u');
	FIBER_REQUIRE(instruction[0] == fiber_portSVC_START, 'u');
}

static FIBER_CM33F_MPU_SVC
void fiber_port_validate_running_svc_frame(FiberContext *current,
		const uint32_t *hardware_frame, uint32_t exc_return)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE((exc_return == fiber_portINITIAL_EXC_RETURN) ||
			(exc_return == fiber_portEXTENDED_EXC_RETURN), 'l');
	fiber_port_context_seal_check(current);
	fiber_port_fpu_require_configured();
	FIBER_REQUIRE(current->protected_context_cursor ==
			&current->protected_context.words[0], 'P');
	FIBER_REQUIRE(current->protected_context.extended.cursor_limit == 0u, 'P');
	FIBER_REQUIRE(current->runtime_flags == 0u, 'F');
	FIBER_REQUIRE((fiber_port_cpu_read_control() & 3u) == 1u, 'l');
	FIBER_REQUIRE(fiber_port_cpu_read_psplim() == (uint32_t)current->boot.stack_base, 'L');
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE((frame_start & 7u) == 0u, 'A');
	FIBER_REQUIRE(frame_start == (uintptr_t)fiber_port_cpu_read_psp(), 'P');
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES, 'O');
	FIBER_REQUIRE(fiber_port_range_contains(current->boot.stack_base,
			current->boot.stack_top, frame_start,
			frame_start + FIBER_PORT_EXC_BASE_BYTES), 'P');
	const uint32_t xpsr = hardware_frame[7];
	uintptr_t frame_bytes = FIBER_PORT_EXC_BASE_BYTES;
	if (exc_return == fiber_portEXTENDED_EXC_RETURN) {
		frame_bytes += FIBER_PORT_EXC_FP_EXT_BYTES;
	}
	if ((xpsr & fiber_portXPSR_STACK_ALIGN_BIT) != 0u) {
		frame_bytes += FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES;
	}
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - frame_bytes, 'O');
	FIBER_REQUIRE(fiber_port_range_contains(current->boot.stack_base,
			current->boot.stack_top, frame_start, frame_start + frame_bytes), 'P');
	FIBER_REQUIRE((xpsr & fiber_portXPSR_THUMB_BIT) != 0u, 'x');
	FIBER_REQUIRE((xpsr & fiber_portXPSR_IPSR_MASK) == 0u, 'x');
	FIBER_REQUIRE(hardware_frame[6] >= 2u &&
			(hardware_frame[6] & 1u) == 0u, 'x');
#if FIBER_STACK_CANARY
	FIBER_REQUIRE(*(const volatile uint32_t *)(uintptr_t)current->boot.begin ==
			FIBER_INTERNAL_STACK_CANARY_VALUE, 'c');
#endif
}

static FIBER_CM33F_MPU_SVC
uint32_t fiber_port_decode_running_svc(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	const uintptr_t instruction_address = (uintptr_t)hardware_frame[6] - 2u;
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			instruction_address) || fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end, instruction_address), 'u');
	const volatile uint8_t *const instruction =
			(const volatile uint8_t *)instruction_address;
	FIBER_REQUIRE(instruction[1] == 0xDFu, 'u');
	return instruction[0];
}

static FIBER_CM33F_MPU_SVC
void fiber_port_validate_exact_svc_site(uint32_t pc,
		const unsigned char *site)
{
	FIBER_REQUIRE((uintptr_t)pc == fiber_port_code_address((uintptr_t)site), 'u');
}

static FIBER_CM33F_MPU_SVC
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

static FIBER_CM33F_MPU_SVC
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

static FIBER_CM33F_MPU_SVC
void fiber_port_mpu_program_global_image_while_disabled(void)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(fiber_port_cpu_read_ipsr() == 11u, 'i');
	FIBER_REQUIRE(fiber_port_cpu_read_primask() == 1u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(fiber_port_cpu_read_faultmask() == 0u, 'f');
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_mpu_build_global_regions(&global);
	fiber_portDATA_SYNC_BARRIER();
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
		fiber_port_mpu_validate_region_readback(region, &global.regions[region]);
	}
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
}

static FIBER_CM33F_MPU_SVC
void fiber_port_mpu_validate_active_initial_context(const FiberContext *first)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(fiber_port_cpu_read_ipsr() == 11u, 'i');
	FIBER_REQUIRE(fiber_port_cpu_read_control() == 0u, 'l');
	FIBER_REQUIRE(fiber_port_cpu_read_primask() == 1u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(fiber_port_cpu_read_faultmask() == 0u, 'f');
	fiber_port_fpu_require_ready();
	fiber_port_context_validate_initial_restore(first);
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	FIBER_REQUIRE(fiber_portMPU_MAIR0_REG == first->mair0, 'M');
	fiber_port_mpu_build_global_regions(&global);
	for (uint32_t region = 0u; region < fiber_portMPU_GLOBAL_REGION_COUNT;
			++region) {
		fiber_port_mpu_validate_region_readback(region, &global.regions[region]);
	}
	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_validate_region_readback(
				fiber_portMPU_STACK_REGION_NUMBER + index,
				&first->mpu_regions[index]);
	}
}

static FIBER_CM33F_MPU_SVC
void fiber_port_validate_privileged_target(
		const FiberPortMpuMemoryLayout *layout, uintptr_t target)
{
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			fiber_port_code_address(target)), 'L');
}

static FIBER_CM33F_MPU_SVC
void fiber_port_validate_first_start_linker_placement(
		const FiberPortMpuMemoryLayout *layout)
{
	/* Direct checks avoid an automatic address array becoming a library copy. */
#define FIBER_CM33F_MPU_CHECK_TARGET(_target) \
	fiber_port_validate_privileged_target(layout, (uintptr_t)&_target)
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_context_init);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_panic_wait);
	FIBER_CM33F_MPU_CHECK_TARGET(
			fiber_port_require_scheduler_configuration_environment);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_runtime_prepare_start);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_runtime_select_first);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_runtime_start_first);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_handler_bundle_v1_anchor);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_prepare_first_start);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_svc_dispatch);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_start_first_context);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_restore_first_context_from_svc);
	FIBER_CM33F_MPU_CHECK_TARGET(SVC_Handler);
	FIBER_CM33F_MPU_CHECK_TARGET(PendSV_Handler);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_context_validate_restore);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_pendsv_validate_save_current);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_scheduler_pick_next_from_pendsv);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_scheduler_pick_first_from_start);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_mpu_switch_to_context);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_mpu_validate_active_context);
	FIBER_CM33F_MPU_CHECK_TARGET(
			fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_internal_runtime_select_scheduler_candidate);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_internal_runtime_require_current_context);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_internal_runtime_publish_current_context);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_internal_task_return);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_fpu_prepare);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_fpu_require_ready);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_fpu_require_configured);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_mpu_load_linker_layout);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_mpu_linker_layout_check);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_mpu_build_global_regions);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_context_validate_initial_restore);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_port_context_seal_check);
	FIBER_CM33F_MPU_CHECK_TARGET(fiber_panic);
#undef FIBER_CM33F_MPU_CHECK_TARGET
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_flash_start, layout->unprivileged_flash_end,
			fiber_port_code_address((uintptr_t)&fiber_current)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_flash_start, layout->unprivileged_flash_end,
			fiber_port_code_address((uintptr_t)&fiber_schedule)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_flash_start, layout->unprivileged_flash_end,
			fiber_port_code_address(
					(uintptr_t)&fiber_port_runtime_memory_barrier)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->privileged_flash_start, layout->privileged_flash_end,
			fiber_port_code_address(
					(uintptr_t)fiber_port_svc_start_return_site)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end,
			fiber_port_code_address(
					(uintptr_t)&fiber_port_unprivileged_task_return)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end,
			fiber_port_code_address((uintptr_t)&fiber_port_yield_from_thread)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end,
			fiber_port_code_address((uintptr_t)&fiber_port_runtime_schedule)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end,
			fiber_port_code_address((uintptr_t)fiber_port_svc_yield_return_site)), 'L');
	FIBER_REQUIRE(fiber_port_code_address_is_in_range(
			layout->unprivileged_syscalls_start,
			layout->unprivileged_syscalls_end,
			fiber_port_code_address((uintptr_t)fiber_port_svc_return_return_site)), 'L');
}

/* This direct Thread helper remains executable after CONTROL.nPRIV is set. */
FIBER_CM33F_MPU_UNPRIVILEGED
void fiber_port_runtime_memory_barrier(void)
{
	fiber_portASM volatile("dmb" ::: "memory");
	fiber_portCOMPILER_BARRIER();
}

FIBER_API_NORETURN FIBER_CM33F_MPU_SVC
void fiber_port_panic_wait(void)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	for (;;) {
		fiber_port_cpu_wait();
	}
}

FIBER_CM33F_MPU_SVC
void fiber_port_require_scheduler_configuration_environment(void)
{
	fiber_port_require_privileged_thread_start_environment();
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
}

FIBER_CM33F_MPU_SVC
void fiber_port_handler_bundle_v1_anchor(void)
{
	fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor();
}

/* Prepare port-owned policy before common invokes the first scheduler hook.
 * Context publication stays common-owned and MPU remains disabled until SVC. */
FIBER_CM33F_MPU_SVC
void fiber_port_runtime_prepare_start(void)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_handler_bundle_v1_anchor();
	fiber_port_require_scheduler_configuration_environment();
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_first_start_linker_placement(&layout);
	fiber_port_validate_start_vector_source(&layout);
	fiber_port_fpu_prepare();
	fiber_port_fpu_require_ready();
	fiber_port_configure_first_start_exceptions();
	fiber_port_validate_start_vector_source(&layout);
	fiber_port_require_scheduler_configuration_environment();
	fiber_port_fpu_require_ready();
}

FIBER_CM33F_MPU_SVC
FiberContext *fiber_port_runtime_select_first(void)
{
	return fiber_port_scheduler_pick_first_from_start();
}

FIBER_API_NORETURN FIBER_CM33F_MPU_SVC
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

/* Keep the previously qualified exact SVC site in the private yield veneer. */
FIBER_API_ATTR_SENSITIVE FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
fiber_portSYSCALL_FUNCTION
void fiber_port_runtime_schedule(void)
{
	fiber_portASM volatile("b fiber_port_yield_from_thread" ::: "memory");
}

FIBER_CM33F_MPU_SVC
void fiber_port_prepare_first_start(FiberContext *first)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_port_require_privileged_thread_start_environment();
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor();
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_first_start_linker_placement(&layout);
	fiber_port_context_validate_initial_restore(first);
	fiber_port_validate_start_vector_source(&layout);
	fiber_port_fpu_prepare();
	fiber_port_fpu_require_ready();
	fiber_port_configure_first_start_exceptions();
	fiber_port_validate_start_vector_source(&layout);
	fiber_port_require_privileged_thread_start_environment();
	fiber_port_fpu_require_ready();
}

FIBER_CM33F_MPU_SVC
void fiber_port_svc_dispatch(uint32_t *hardware_frame,
		uint32_t exc_return,
		FiberContext *current)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_REQUIRE(fiber_port_cpu_read_ipsr() == 11u, 'i');
	if (exc_return != fiber_portSVC_ORIGIN_EXC_RETURN) {
		FIBER_REQUIRE((exc_return == fiber_portINITIAL_EXC_RETURN) ||
				(exc_return == fiber_portEXTENDED_EXC_RETURN), 'l');
		FIBER_REQUIRE(fiber_port_cpu_read_primask() == 0u, 'p');
		FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
		FIBER_REQUIRE(fiber_port_cpu_read_faultmask() == 0u, 'f');
		fiber_port_mpu_load_linker_layout(&layout);
		fiber_port_mpu_linker_layout_check(&layout);
		fiber_port_validate_first_start_linker_placement(&layout);
		fiber_port_validate_running_svc_frame(current, hardware_frame, exc_return);
		fiber_port_mpu_validate_active_context(current);
		switch (fiber_port_decode_running_svc(hardware_frame, &layout)) {
		case fiber_portSVC_YIELD: {
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
		case fiber_portSVC_RETURN:
			fiber_port_validate_exact_svc_site(hardware_frame[6],
					fiber_port_svc_return_return_site);
			fiber_internal_task_return();
			FIBER_API_UNREACHABLE();
		case fiber_portSVC_START:
			fiber_panic('l');
			FIBER_API_UNREACHABLE();
		default:
			fiber_panic('u');
			FIBER_API_UNREACHABLE();
		}
	}
	FIBER_REQUIRE(exc_return == fiber_portSVC_ORIGIN_EXC_RETURN, 'l');
	FIBER_REQUIRE(fiber_port_cpu_read_control() == 0u, 'l');
	FIBER_REQUIRE(fiber_port_cpu_read_primask() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(fiber_port_cpu_read_faultmask() == 0u, 'f');
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_require_mpu_geometry();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_fpu_require_ready();
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_first_start_linker_placement(&layout);
	fiber_port_validate_start_vector_source(&layout);
	fiber_port_validate_start_svc_frame(hardware_frame, &layout);
	fiber_port_validate_start_svc_site(hardware_frame, &layout);
	FIBER_REQUIRE(current != NULL, 'C');
	fiber_port_context_validate_initial_restore(current);
	FIBER_REQUIRE(fiber_port_primask_save_disable() == 0u, 'p');
	fiber_port_mpu_program_global_image_while_disabled();
	fiber_port_restore_first_context_from_svc(current, exc_return);
	FIBER_API_UNREACHABLE();
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
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
			"90: movs r0, #108                                    \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			"91: movs r0, #112                                    \n"
			"bl    fiber_panic                                    \n"
			"b     91b                                             \n"
			"92: movs r0, #98                                     \n"
			"bl    fiber_panic                                    \n"
			"b     92b                                             \n"
			"93: movs r0, #86                                     \n"
			"bl    fiber_panic                                    \n"
			"b     93b                                             \n"
			"94: movs r0, #80                                     \n"
			"bl    fiber_panic                                    \n"
			"b     94b                                             \n"
			".ltorg                                                \n"
			::: "memory", "cc");
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_restore_first_context_from_svc(
		FiberContext *first FIBER_ATTR_UNUSED_PARAM,
		uint32_t svc_exc_return FIBER_ATTR_UNUSED_PARAM)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			"mvn   r3, #71                                        \n" /* 0xFFFFFFB8 */
			"cmp   r1, r3                                         \n"
			"bne   91f                                            \n"
			"mov   lr, r1                                         \n"
			"push  {r0, lr}                                       \n"
			"dmb                                                   \n"
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
#if FIBER_PORT_CM33F_MPU_TOTAL_REGIONS == 16
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
			"movs  r2, #5                                         \n"
			"str   r2, [r1]                                       \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"ldr   r0, [sp, #0]                                   \n"
			"bl    fiber_port_mpu_validate_active_initial_context \n"
			"ldr   r0, [sp, #0]                                   \n"
			"add   sp, #8                                         \n"
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
			"stmia r2!, {r4-r11}                                   \n"
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
			"90: movs r0, #80                                     \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			"91: movs r0, #108                                    \n"
			"bl    fiber_panic                                    \n"
			"b     91b                                             \n"
			"92: movs r0, #120                                    \n"
			"bl    fiber_panic                                    \n"
			"b     92b                                             \n"
			"93: movs r0, #98                                     \n"
			"bl    fiber_panic                                    \n"
			"b     93b                                             \n"
			".ltorg                                                \n"
			::: "memory", "cc");
}

FIBER_API_ATTR_SENSITIVE FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
fiber_portSYSCALL_FUNCTION
void fiber_port_yield_from_thread(void)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_YIELD) "  \n"
			".global fiber_port_svc_yield_return_site             \n"
			"fiber_port_svc_yield_return_site:                     \n"
			"bx    lr                                              \n"
			::: "memory", "cc");
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE
FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY fiber_portSYSCALL_FUNCTION
void fiber_port_unprivileged_task_return(void)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_RETURN) " \n"
			".global fiber_port_svc_return_return_site            \n"
			"fiber_port_svc_return_return_site:                    \n"
			"1: b 1b                                              \n"
			::: "memory", "cc");
}

FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void SVC_Handler(void)
{
	fiber_portASM volatile(
			".syntax unified                                      \n"
			"mrs   r3, ipsr                                       \n"
			"cmp   r3, #11                                        \n"
			"bne   90f                                            \n"
			"mov   r1, lr                                         \n"
			/* Whitelist exact origin tokens before selecting a raw frame. */
			"mvn   r3, #71                                        \n"
			"cmp   r1, r3                                         \n"
			"beq   1f                                             \n"
			"mvn   r3, #67                                        \n"
			"cmp   r1, r3                                         \n"
			"beq   2f                                             \n"
			"bic   r3, r3, #0x10                                  \n"
			"cmp   r1, r3                                         \n"
			"bne   91f                                            \n"
			"2: mrs r0, psp                                       \n"
			"b     3f                                             \n"
			"1: mrs r0, msp                                       \n"
			"3:                                                   \n"
			/* No C lvalue for common-owned scheduler storage is exposed. */
			"ldr   r2, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r2, [r2]                                       \n"
			"ldr   r3, =fiber_port_svc_dispatch + 1               \n"
			"bx    r3                                              \n"
			"90: movs r0, #105                                    \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			"91: movs r0, #108                                    \n"
			"bl    fiber_panic                                    \n"
			"b     91b                                             \n"
			".ltorg                                                \n"
			::: "memory", "cc");
}

#undef FIBER_CM33F_MPU_SVC
#undef FIBER_CM33F_MPU_UNPRIVILEGED
#undef fiber_portSTRINGIFY
#undef fiber_portSTRINGIFY2
