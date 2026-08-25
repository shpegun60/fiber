/*
 * ARM_CM0_MPU protected first-start service.
 *
 * This slice owns the strong SVC/PendSV handlers, the native start/yield/return
 * services, protected MPU replacement, and Thumb-1 first/ordinary restore.
 * It deliberately owns no forward runtime ABI operation yet: the private yield
 * veneer exists only with its matching protected PendSV owner.
 */

#include "fiber_port_private.h"
#include "../../fiber_panic.h"

#define fiber_portSTRINGIFY2(_value) #_value
#define fiber_portSTRINGIFY(_value) fiber_portSTRINGIFY2(_value)

#define FIBER_CM0_MPU_PRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION

#define FIBER_CM0_MPU_UNPRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portUNPRIVILEGED_FUNCTION

FIBER_PORT_CONTEXT_COHORT_DEFINE();

static FIBER_CM0_MPU_PRIVILEGED
uintptr_t fiber_port_code_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM0_MPU_PRIVILEGED
int fiber_port_range_contains(uintptr_t outer_start,
		uintptr_t outer_end,
		uintptr_t inner_start,
		uintptr_t inner_end)
{
	return (outer_end > outer_start) && (inner_end > inner_start) &&
			(inner_start >= outer_start) && (inner_end <= outer_end);
}

static FIBER_CM0_MPU_PRIVILEGED
uint32_t fiber_port_primask_save_disable(void)
{
	uint32_t primask;
	fiber_portASM volatile(
			"mrs %0, primask\n"
			"cpsid i"
			: "=r"(primask)
			:
			: "memory");
	__DSB();
	__ISB();
	return primask;
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_primask_restore(uint32_t primask)
{
	__DSB();
	__ISB();
	fiber_portASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	__DSB();
	__ISB();
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_require_privileged_thread_msp(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
}

static FIBER_CM0_MPU_PRIVILEGED
uint8_t fiber_port_lowest_priority_encoding(void)
{
	const uint32_t lowest = (1u << __NVIC_PRIO_BITS) - 1u;
	return (uint8_t)(lowest << (8u - __NVIC_PRIO_BITS));
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_priority_contract(void)
{
	volatile uint8_t *const first_user_priority =
			(volatile uint8_t *)(uintptr_t)0xE000E400u;
	const uint32_t primask = fiber_port_primask_save_disable();
	FIBER_REQUIRE(primask == 0u, 'p');
	const uint8_t original = *first_user_priority;
	*first_user_priority = 0xFFu;
	__DSB();
	__ISB();
	__COMPILER_BARRIER();
	const uint8_t implemented = *first_user_priority;
	*first_user_priority = original;
	__DSB();
	__ISB();
	__COMPILER_BARRIER();
	FIBER_REQUIRE(*first_user_priority == original, 'Q');
	fiber_port_primask_restore(primask);

	const uint8_t expected =
			(uint8_t)(0xFFu << (8u - __NVIC_PRIO_BITS));
	FIBER_REQUIRE(implemented != 0u, 'Q');
	FIBER_REQUIRE(implemented == expected, 'Q');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_exception_vectors(void)
{
#if FIBER_PORT_HAS_VTOR
	const uintptr_t first = (uintptr_t)fiber_portSCB_VTOR_REG;
	__DSB();
	__ISB();
	const uintptr_t second = (uintptr_t)fiber_portSCB_VTOR_REG;
	FIBER_REQUIRE(first == second, 'V');
	FIBER_REQUIRE((first & (fiber_portVECTOR_ALIGNMENT - 1u)) == 0u, 'V');
#endif

	const uintptr_t actual_svc = (uintptr_t)fiber_port_read_vector_slot(
			fiber_portVECTOR_INDEX_SVC);
	const uintptr_t actual_pendsv = (uintptr_t)fiber_port_read_vector_slot(
			fiber_portVECTOR_INDEX_PENDSV);
	FIBER_REQUIRE((actual_svc & 1u) != 0u, 'y');
	FIBER_REQUIRE((actual_pendsv & 1u) != 0u, 'Y');
	FIBER_REQUIRE(fiber_port_code_address(actual_svc) ==
			fiber_port_code_address((uintptr_t)&SVC_Handler), 'y');
	FIBER_REQUIRE(fiber_port_code_address(actual_pendsv) ==
			fiber_port_code_address((uintptr_t)&PendSV_Handler), 'Y');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_configure_exception_priorities(void)
{
	const uint32_t previous = fiber_port_primask_save_disable();
	FIBER_REQUIRE(previous == 0u, 'p');
	const uint32_t lowest = (uint32_t)fiber_port_lowest_priority_encoding();
	fiber_portNVIC_SHPR3_REG =
			(fiber_portNVIC_SHPR3_REG &
			~(fiber_portNVIC_PRIORITY_BYTE_MASK <<
				fiber_portNVIC_PENDSV_PRIORITY_SHIFT)) |
			(lowest << fiber_portNVIC_PENDSV_PRIORITY_SHIFT);
	fiber_portNVIC_SHPR2_REG &= ~(fiber_portNVIC_PRIORITY_BYTE_MASK <<
			fiber_portNVIC_SVC_PRIORITY_SHIFT);
	__DSB();
	__ISB();
	fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVCLR_BIT;
	__DSB();
	__ISB();
	const uint32_t pendsv_priority =
			(fiber_portNVIC_SHPR3_REG >>
			fiber_portNVIC_PENDSV_PRIORITY_SHIFT) &
			fiber_portNVIC_PRIORITY_BYTE_MASK;
	const uint32_t svc_priority = ((fiber_portNVIC_SHPR2_REG >>
			fiber_portNVIC_SVC_PRIORITY_SHIFT) &
			fiber_portNVIC_PRIORITY_BYTE_MASK);
	FIBER_REQUIRE(pendsv_priority == lowest, 'P');
	FIBER_REQUIRE(svc_priority == 0u, 'w');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == 0u, 'J');
	fiber_port_primask_restore(previous);
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_svc_cpu_state(void)
{
	FIBER_REQUIRE(__get_IPSR() == 11u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
}

static FIBER_CM0_MPU_PRIVILEGED
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

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_start_svc_frame(const uint32_t *hardware_frame,
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t frame_start = (uintptr_t)hardware_frame;
	FIBER_REQUIRE(frame_start <= UINTPTR_MAX - FIBER_PORT_EXC_BASE_BYTES, 'O');
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_data_start,
			layout->privileged_data_end, frame_start,
			frame_start + FIBER_PORT_EXC_BASE_BYTES), 'P');
}

static FIBER_CM0_MPU_PRIVILEGED
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

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_exact_svc_site(uint32_t stacked_pc,
		const unsigned char *expected_site,
		char panic_code)
{
	FIBER_REQUIRE(expected_site != NULL, panic_code);
	FIBER_REQUIRE((uintptr_t)stacked_pc ==
			fiber_port_code_address((uintptr_t)expected_site), panic_code);
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_mpu_write_region(const FiberPortMpuRegionRegisters *region)
{
	FIBER_REQUIRE(region != NULL, 'M');
	fiber_portMPU_RBAR_REG = region->rbar;
	fiber_portMPU_RASR_REG = region->rasr;
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_mpu_validate_region_readback(uint32_t region_number,
		const FiberPortMpuRegionRegisters *expected)
{
	FIBER_REQUIRE(expected != NULL, 'M');
	FIBER_REQUIRE(region_number < fiber_portMPU_TOTAL_REGIONS, 'M');
	fiber_portMPU_RNR_REG = region_number;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == region_number, 'M');
	FIBER_REQUIRE((fiber_portMPU_RBAR_REG & fiber_portMPU_RBAR_ADDRESS_MASK) ==
			(expected->rbar & fiber_portMPU_RBAR_ADDRESS_MASK), 'M');
	FIBER_REQUIRE(fiber_portMPU_RASR_REG == expected->rasr, 'M');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_mpu_validate_active_context(const FiberContext *ctx)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(ctx != NULL, 'N');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	fiber_port_mpu_build_global_regions(&global);

	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_validate_region_readback(index, &ctx->mpu_regions[index]);
	}
	for (uint32_t index = 0u; index < fiber_portMPU_GLOBAL_REGION_COUNT;
			++index) {
		fiber_port_mpu_validate_region_readback(
				index + fiber_portMPU_CURRENT_CONTEXT_REGION,
				&global.regions[index]);
	}

	/* RBAR.VALID owns selection for writes. Make diagnostics deterministic. */
	fiber_portMPU_RNR_REG = 0u;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == 0u, 'M');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_mpu_activate_first_context(FiberContext *first)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(first != NULL, 'N');
	FIBER_REQUIRE(__get_IPSR() == 11u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_mpu_build_global_regions(&global);

	/* FreeRTOS disables the MPU while replacing task regions. Fiber keeps
	 * PRIMASK asserted and proves every register write/readback before any
	 * unprivileged exception return. */
	__DMB();
	fiber_portMPU_CTRL_REG = 0u;
	__DSB();
	__ISB();
	FIBER_REQUIRE((fiber_portMPU_CTRL_REG & fiber_portMPU_CTRL_ENABLE) == 0u,
			'M');

	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_write_region(&first->mpu_regions[index]);
	}
	for (uint32_t index = 0u; index < fiber_portMPU_GLOBAL_REGION_COUNT;
			++index) {
		fiber_port_mpu_write_region(&global.regions[index]);
	}

	fiber_portMPU_CTRL_REG = fiber_portMPU_CTRL_REQUIRED;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	fiber_port_mpu_validate_active_context(first);
}

FIBER_CM0_MPU_PRIVILEGED
void fiber_port_pendsv_validate_save_current(FiberContext *current,
		uint32_t *hardware_frame,
		uint32_t exc_return)
{
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(__get_CONTROL() ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	FIBER_REQUIRE((uintptr_t)hardware_frame == (uintptr_t)__get_PSP(), 'P');
	fiber_port_context_validate_save_current(current, hardware_frame);
	fiber_port_mpu_validate_active_context(current);
}

typedef struct FiberPortMpuSchedulerCpuState {
	uint32_t primask;
	uint32_t control;
	uint32_t ipsr;
	uint32_t psp;
	uintptr_t vector_base;
	uint32_t shpr2;
	uint32_t shpr3;
	uint32_t pendsv_pending;
	uint32_t mpu_ctrl;
	uint32_t mpu_rnr;
	FiberPortMpuRegionRegisters
			mpu_regions[fiber_portMPU_TOTAL_REGIONS];
} FiberPortMpuSchedulerCpuState;

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_capture_scheduler_mpu_image(
		FiberPortMpuSchedulerCpuState *state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	/* Active-context validation leaves RNR deterministic. Do not let the
	 * scheduler hook acquire a hidden region-selection side channel. */
	FIBER_REQUIRE(state->mpu_rnr == 0u, 'M');

	for (uint32_t index = 0u; index < fiber_portMPU_TOTAL_REGIONS; ++index) {
		fiber_portMPU_RNR_REG = index;
		__DSB();
		__ISB();
		FIBER_REQUIRE(fiber_portMPU_RNR_REG == index, 'M');
		state->mpu_regions[index].rbar =
				fiber_portMPU_RBAR_REG & fiber_portMPU_RBAR_ADDRESS_MASK;
		state->mpu_regions[index].rasr = fiber_portMPU_RASR_REG;
	}

	fiber_portMPU_RNR_REG = 0u;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == 0u, 'M');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_scheduler_mpu_image(
		const FiberPortMpuSchedulerCpuState *before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	FIBER_REQUIRE(before->mpu_rnr == 0u, 'M');

	for (uint32_t index = 0u; index < fiber_portMPU_TOTAL_REGIONS; ++index) {
		fiber_portMPU_RNR_REG = index;
		__DSB();
		__ISB();
		FIBER_REQUIRE(fiber_portMPU_RNR_REG == index, 'M');
		FIBER_REQUIRE((fiber_portMPU_RBAR_REG &
				fiber_portMPU_RBAR_ADDRESS_MASK) ==
				before->mpu_regions[index].rbar, 'M');
		FIBER_REQUIRE(fiber_portMPU_RASR_REG ==
				before->mpu_regions[index].rasr, 'M');
	}

	fiber_portMPU_RNR_REG = before->mpu_rnr;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == before->mpu_rnr, 'M');
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_capture_scheduler_cpu_state(
		FiberPortMpuSchedulerCpuState *state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	__COMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->control = __get_CONTROL();
	state->ipsr = __get_IPSR();
	state->psp = __get_PSP();
	state->vector_base = fiber_port_vectors_base_addr();
	state->shpr2 = fiber_portNVIC_SHPR2_REG;
	state->shpr3 = fiber_portNVIC_SHPR3_REG;
	state->pendsv_pending = fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT;
	FIBER_REQUIRE(state->pendsv_pending == 0u, 'J');
	state->mpu_ctrl = fiber_portMPU_CTRL_REG;
	state->mpu_rnr = fiber_portMPU_RNR_REG;
	fiber_port_capture_scheduler_mpu_image(state);
	__COMPILER_BARRIER();
}

static FIBER_CM0_MPU_PRIVILEGED
void fiber_port_validate_scheduler_cpu_state(
		const FiberPortMpuSchedulerCpuState *before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	__COMPILER_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'r');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
	FIBER_REQUIRE(__get_IPSR() == before->ipsr, 'i');
	FIBER_REQUIRE(__get_PSP() == before->psp, 'P');
	FIBER_REQUIRE(fiber_port_vectors_base_addr() == before->vector_base, 'V');
	FIBER_REQUIRE(fiber_portNVIC_SHPR2_REG == before->shpr2, 'w');
	FIBER_REQUIRE(fiber_portNVIC_SHPR3_REG == before->shpr3, 'P');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == before->pendsv_pending, 'J');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == before->mpu_ctrl, 'M');
	fiber_port_validate_scheduler_mpu_image(before);
	__COMPILER_BARRIER();
}

FIBER_CM0_MPU_PRIVILEGED
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(
		FiberContext *current)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(__get_CONTROL() ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');

	FiberPortMpuSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const next =
			fiber_internal_runtime_select_scheduler_candidate(current);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(next);
	fiber_internal_runtime_publish_current_context(next);
	return next;
}

FIBER_CM0_MPU_PRIVILEGED
void fiber_port_mpu_switch_to_context(FiberContext *next)
{
	FIBER_REQUIRE(next != NULL, 'N');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(__get_CONTROL() ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	/* The bridge validates next before publication. Repeat the invariant here so
	 * this private MPU writer is also fail-closed if called by a future port path. */
	fiber_port_context_validate_restore(next);

	/* FreeRTOS replaces its task-owned MPU pairs while MPU_CTRL is disabled.
	 * Fiber keeps PRIMASK asserted across the entire interval and retains global
	 * regions 4-7, whose linker-derived image is immutable and was validated in
	 * the preflight. */
	__DMB();
	fiber_portMPU_CTRL_REG = 0u;
	__DSB();
	__ISB();
	FIBER_REQUIRE((fiber_portMPU_CTRL_REG & fiber_portMPU_CTRL_ENABLE) == 0u,
			'M');

	for (uint32_t index = 0u; index < fiber_portMPU_CONTEXT_REGION_COUNT;
			++index) {
		fiber_port_mpu_write_region(&next->mpu_regions[index]);
	}

	fiber_portMPU_CTRL_REG = fiber_portMPU_CTRL_REQUIRED;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	fiber_port_mpu_validate_active_context(next);
}

FIBER_CM0_MPU_PRIVILEGED
void fiber_port_prepare_first_start(FiberContext *first)
{
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_port_require_privileged_thread_msp();
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_context_validate_initial_restore(first);
	fiber_port_validate_exception_vectors();
	fiber_port_validate_priority_contract();
	fiber_port_configure_exception_priorities();
	fiber_port_validate_exception_vectors();
	fiber_port_require_privileged_thread_msp();
}

FIBER_CM0_MPU_PRIVILEGED
void fiber_port_svc_dispatch(uint32_t *hardware_frame,
		uint32_t exc_return,
		FiberContext *current)
{
	FiberPortMpuMemoryLayout layout;
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_validate_svc_cpu_state();
	FIBER_REQUIRE((exc_return == fiber_portEXC_RETURN_THREAD_MSP) ||
			(exc_return == fiber_portINITIAL_EXC_RETURN), 'l');
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	if (exc_return == fiber_portEXC_RETURN_THREAD_MSP) {
		FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
		fiber_port_validate_start_svc_frame(hardware_frame, &layout);
	} else {
		FIBER_REQUIRE(__get_CONTROL() ==
				fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_port_context_validate_running_svc(current, hardware_frame);
		fiber_port_mpu_validate_active_context(current);
	}
	fiber_port_validate_svc_frame_shape(hardware_frame);

	const uint32_t service = fiber_port_decode_svc_number(hardware_frame,
			&layout);
	switch (service) {
	case fiber_portSVC_START: {
		FIBER_REQUIRE(exc_return == fiber_portEXC_RETURN_THREAD_MSP, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_start_return_site, 'u');
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_port_context_validate_initial_restore(current);
		const uint32_t previous = fiber_port_primask_save_disable();
		FIBER_REQUIRE(previous == 0u, 'p');
		fiber_port_mpu_activate_first_context(current);
		fiber_port_restore_first_context_from_svc(current);
		FIBER_API_UNREACHABLE();
	}

	case fiber_portSVC_RETURN:
		FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_return_return_site, 'u');
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_internal_task_return();
		FIBER_API_UNREACHABLE();

	case fiber_portSVC_YIELD: {
		FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_yield_return_site, 'u');
		FIBER_REQUIRE(current != NULL, 'C');
		/* This is the only private unprivileged route that can pend the now-owned
		 * protected PendSV. Keep the request atomic even though SVCall already
		 * runs privileged, then return so the pending exception owns the save. */
		const uint32_t previous = fiber_port_primask_save_disable();
		FIBER_REQUIRE(previous == 0u, 'p');
		fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVSET_BIT;
		__DSB();
		__ISB();
		FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
				fiber_portNVIC_PENDSVSET_BIT) != 0u, 'J');
		fiber_port_primask_restore(previous);
		return;
	}

	default:
		fiber_panic('u');
	}
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_start_first_context(FiberContext *first FIBER_ATTR_UNUSED_PARAM)
{
	__ASM volatile(
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
			"cpsid i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"ldr   r3, =0xE000ED04                                \n"
			"ldr   r2, =0x08000000                                \n"
			"str   r2, [r3]                                       \n"
			"dsb                                                   \n"
			"isb                                                   \n"
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
			".ltorg                                                \n"
			:
			:
			: "memory", "cc");
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_restore_first_context_from_svc(
		FiberContext *first FIBER_ATTR_UNUSED_PARAM)
{
	__ASM volatile(
			".syntax unified                                      \n"
			"cpsid i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"ldr   r1, [r0, #0]                                   \n"
			"subs  r1, #12                                        \n"
			"ldmia r1!, {r2-r4}                                   \n"
			"mov   r5, r4                                         \n"
			"subs  r1, #12                                        \n"
			"msr   psp, r2                                        \n"
			"isb                                                   \n"
			"mrs   r4, psp                                        \n"
			"cmp   r4, r2                                         \n"
			"bne   90f                                            \n"
			"msr   control, r3                                    \n"
			"isb                                                   \n"
			"mrs   r4, control                                    \n"
			"movs  r6, #3                                         \n"
			"cmp   r4, r6                                         \n"
			"bne   90f                                            \n"
			"mov   lr, r5                                         \n"
			"movs  r4, #2                                         \n"
			"mvns  r4, r4                                         \n"
			"cmp   lr, r4                                         \n"
			"bne   90f                                            \n"
			"subs  r1, #32                                        \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"stmia r2!, {r4-r7}                                   \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"stmia r2!, {r4-r7}                                   \n"
			"subs  r1, #48                                        \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"mov   r8, r4                                         \n"
			"mov   r9, r5                                         \n"
			"mov   r10, r6                                        \n"
			"mov   r11, r7                                        \n"
			"subs  r1, #32                                        \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"subs  r1, #16                                        \n"
			"str   r1, [r0, #0]                                   \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"cpsie i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"bx    lr                                              \n"
			"90:                                                   \n"
			"movs  r0, #80                                        \n"
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			".ltorg                                                \n"
			:
			:
			: "memory", "cc");
}

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
FIBER_CM0_MPU_UNPRIVILEGED
void fiber_port_unprivileged_task_return(void)
{
	__ASM volatile(
			".syntax unified                                      \n"
			"svc   #" fiber_portSTRINGIFY(fiber_portSVC_RETURN) " \n"
			".global fiber_port_svc_return_return_site            \n"
			"fiber_port_svc_return_return_site:                    \n"
			"1: b 1b                                               \n"
			:
			:
			: "memory", "cc");
}

FIBER_ATTR_NAKED_ASM FIBER_CM0_MPU_UNPRIVILEGED
void fiber_port_unprivileged_yield(void)
{
	__ASM volatile(
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
	__ASM volatile(
			".syntax unified                                      \n"
			"mrs   r2, ipsr                                       \n"
			"cmp   r2, #11                                        \n"
			"bne   90f                                            \n"
			"mov   r1, lr                                         \n"
			"movs  r3, #4                                         \n"
			"tst   r1, r3                                         \n"
			"beq   1f                                             \n"
			"mrs   r0, psp                                        \n"
			"b     2f                                             \n"
			"1:                                                    \n"
			"mrs   r0, msp                                        \n"
			"2:                                                    \n"
			"ldr   r2, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r2, [r2]                                       \n"
			/* A narrow Thumb-1 B reaches only a short span. LTO may place the
			 * non-naked C dispatcher beyond that span, so preserve the exact
			 * r0/r1/r2 ABI and tail-branch through an explicit Thumb address. */
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
 * Protected ARMv6-M MPU context switch.
 *
 * This keeps the pinned FreeRTOS ARM_CM0 MPU image geometry: r4-r11, copied
 * eight-word hardware frame, PSP, CONTROL, and EXC_RETURN live only in
 * privileged FiberContext storage. Thumb-1 cannot use the ARMv7-M decrement
 * multiple-transfer forms, so high registers and the basic frame are staged
 * through r4-r7 exactly as in the reference port.
 */
FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void PendSV_Handler(void)
{
	__ASM volatile(
			".syntax unified                                      \n"

			/* Reject foreign/pre-start PendSV before consuming either a
			 * protected context field or the interrupted user frame. */
			"mrs   r2, ipsr                                       \n"
			"cmp   r2, #14                                        \n"
			"bne   90f                                            \n"
			"movs  r2, #2                                         \n"
			"mvns  r2, r2                                         \n" /* 0xFFFFFFFD */
			"mov   r3, lr                                         \n"
			"cmp   r3, r2                                         \n"
			"bne   90f                                            \n"

			"mrs   r0, psp                                        \n" /* r0 = interrupted HW frame */
			"dsb                                                   \n"
			"isb                                                   \n"
			"ldr   r1, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r1, [r1]                                       \n" /* r1 = current */
			"cmp   r1, #0                                         \n"
			"beq   91f                                            \n"

			/* The C preflight validates provenance, active MPU image, immutable
			 * context metadata, cursor, PSP bounds, and basic frame before this
			 * assembly dereferences current->protected_context_cursor. */
			"push  {r0, r1, r2, lr}                               \n"
			"mov   r2, lr                                         \n"
			"mov   r3, r0                                         \n"
			"mov   r0, r1                                         \n"
			"mov   r1, r3                                         \n"
			"bl    fiber_port_pendsv_validate_save_current        \n"
			"pop   {r0, r1, r2, r3}                               \n"
			"mov   lr, r3                                         \n"

			/* Save r4-r11 and copy the complete basic hardware frame into the
			 * protected 20-word image. r3 ends at cursor_limit. */
			"ldr   r3, [r1, #0]                                   \n"
			"stmia r3!, {r4-r7}                                   \n"
			"mov   r4, r8                                         \n"
			"mov   r5, r9                                         \n"
			"mov   r6, r10                                        \n"
			"mov   r7, r11                                        \n"
			"stmia r3!, {r4-r7}                                   \n"
			"ldmia r0!, {r4-r7}                                   \n"
			"stmia r3!, {r4-r7}                                   \n"
			"ldmia r0!, {r4-r7}                                   \n"
			"stmia r3!, {r4-r7}                                   \n"
			"mrs   r0, psp                                        \n"
			"mrs   r2, control                                    \n"
			"mov   r4, lr                                         \n"
			"stmia r3!, {r0, r2, r4}                              \n"
			"str   r3, [r1, #0]                                   \n"

			/* FreeRTOS protects vTaskSwitchContext with PRIMASK on ARMv6-M.
			 * Fiber uses the same envelope, then checks that the user scheduler
			 * preserved all handler-owned CPU state before publishing next. */
			"mrs   r3, primask                                    \n"
			"cmp   r3, #0                                         \n"
			"bne   92f                                            \n"
			"cpsid i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"push  {r3, lr}                                       \n"
			"mov   r0, r1                                         \n"
			"bl    fiber_port_scheduler_pick_next_from_pendsv     \n"
			"pop   {r2, r3}                                       \n"
			"mov   lr, r3                                         \n"

			/* The protected MPU image changes while PRIMASK remains asserted.
			 * C performs disable/write/enable/readback atomically; retain r0 and
			 * the exception-return token across the call on the privileged MSP. */
			"push  {r0, lr}                                       \n"
			"bl    fiber_port_mpu_switch_to_context               \n"
			"pop   {r2, r3}                                       \n" /* r2 = next */
			"mov   lr, r3                                         \n"

			/* Restore next's exact protected image. The hardware frame is copied
			 * only after next's MPU stack image is active. */
			"ldr   r1, [r2, #0]                                   \n"
			"subs  r1, #12                                        \n"
			"ldmia r1!, {r0, r3, r4}                              \n"
			"mov   r5, r4                                         \n"
			"subs  r1, #12                                        \n"
			"msr   psp, r0                                        \n"
			"isb                                                   \n"
			"mrs   r4, psp                                        \n"
			"cmp   r4, r0                                         \n"
			"bne   93f                                            \n"
			"msr   control, r3                                    \n"
			"isb                                                   \n"
			"mrs   r4, control                                    \n"
			"movs  r6, #3                                         \n"
			"cmp   r4, r6                                         \n"
			"bne   93f                                            \n"
			"mov   lr, r5                                         \n"
			"movs  r4, #2                                         \n"
			"mvns  r4, r4                                         \n"
			"cmp   lr, r4                                         \n"
			"bne   93f                                            \n"
			"subs  r1, #32                                        \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"stmia r0!, {r4-r7}                                   \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"stmia r0!, {r4-r7}                                   \n"
			"subs  r1, #48                                        \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"mov   r8, r4                                         \n"
			"mov   r9, r5                                         \n"
			"mov   r10, r6                                        \n"
			"mov   r11, r7                                        \n"
			"subs  r1, #32                                        \n"
			"ldmia r1!, {r4-r7}                                   \n"
			"subs  r1, #16                                        \n"
			"str   r1, [r2, #0]                                   \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"cpsie i                                               \n"
			"dsb                                                   \n"
			"isb                                                   \n"
			"bx    lr                                              \n"

			"90:                                                   \n"
			"movs  r0, #106                                       \n" /* 'j' */
			"bl    fiber_panic                                    \n"
			"b     90b                                             \n"
			"91:                                                   \n"
			"movs  r0, #67                                        \n" /* 'C' */
			"bl    fiber_panic                                    \n"
			"b     91b                                             \n"
			"92:                                                   \n"
			"movs  r0, #112                                       \n" /* 'p' */
			"bl    fiber_panic                                    \n"
			"b     92b                                             \n"
			"93:                                                   \n"
			"movs  r0, #80                                        \n" /* 'P' */
			"bl    fiber_panic                                    \n"
			"b     93b                                             \n"
			".ltorg                                                \n"
			:
			:
			: "memory", "cc");
}

#undef FIBER_CM0_MPU_UNPRIVILEGED
#undef FIBER_CM0_MPU_PRIVILEGED
#undef fiber_portSTRINGIFY
#undef fiber_portSTRINGIFY2
