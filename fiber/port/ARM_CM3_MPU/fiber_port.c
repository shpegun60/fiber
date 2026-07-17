/* ARM_CM3_MPU slice 6: complete protected runtime ABI engine. */

#include "fiber_port_private.h"
#include "../../fiber_panic.h"
#include "../../fiber_platform_policy.h"

#define fiber_portSTRINGIFY2(_value) #_value
#define fiber_portSTRINGIFY(_value) fiber_portSTRINGIFY2(_value)

#define FIBER_CM3_MPU_PRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION
#define FIBER_CM3_MPU_UNPRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portUNPRIVILEGED_FUNCTION

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_CM3_MPU_UNPRIVILEGED
void fiber_port_runtime_memory_barrier(void)
{
	__DMB();
	__COMPILER_BARRIER();
}

FIBER_API_NORETURN FIBER_CM3_MPU_PRIVILEGED
void fiber_port_panic_wait(void)
{
	__DSB();
	__ISB();
	for (;;) {
		__WFE();
	}
}

static FIBER_CM3_MPU_PRIVILEGED
uintptr_t fiber_port_code_address(uintptr_t address)
{
	return address & ~(uintptr_t)1u;
}

static FIBER_CM3_MPU_PRIVILEGED
int fiber_port_range_contains(uintptr_t start,
		uintptr_t end,
		uintptr_t value_start,
		uintptr_t value_end)
{
	return (start <= value_start) && (value_start <= value_end) &&
			(value_end <= end);
}

static FIBER_CM3_MPU_PRIVILEGED
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

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_primask_restore(uint32_t primask)
{
	__DSB();
	__ISB();
	fiber_portASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	__DSB();
	__ISB();
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_require_privileged_thread_msp(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_CONTROL() == 0u, 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
}

static FIBER_CM3_MPU_PRIVILEGED
uint32_t fiber_port_scheduler_critical_enter(void)
{
	const uint32_t previous = fiber_port_basepri_read();
	FIBER_REQUIRE(previous == 0u, 'b');
	fiber_port_basepri_write(FIBER_PORT_SCHEDULER_BASEPRI);
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'B');
	return previous;
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_scheduler_critical_exit(uint32_t previous)
{
	FIBER_REQUIRE(previous == 0u, 'b');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'B');
	fiber_port_basepri_write(previous);
	FIBER_REQUIRE(fiber_port_basepri_read() == previous, 'B');
}

static FIBER_CM3_MPU_PRIVILEGED
uint8_t fiber_port_lowest_priority_encoding(void)
{
	const uint32_t lowest = (1u << __NVIC_PRIO_BITS) - 1u;
	return (uint8_t)(lowest << (8u - __NVIC_PRIO_BITS));
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_validate_priority_contract(void)
{
	const uint32_t primask = fiber_port_primask_save_disable();
	const uint8_t original = fiber_portNVIC_FIRST_USER_PRIORITY_REG;
	fiber_portNVIC_FIRST_USER_PRIORITY_REG = 0xFFu;
	__DSB();
	__ISB();
	__COMPILER_BARRIER();
	const uint8_t implemented = fiber_portNVIC_FIRST_USER_PRIORITY_REG;
	fiber_portNVIC_FIRST_USER_PRIORITY_REG = original;
	__DSB();
	__ISB();
	__COMPILER_BARRIER();
	FIBER_REQUIRE(fiber_portNVIC_FIRST_USER_PRIORITY_REG == original, 'Q');
	fiber_port_primask_restore(primask);

	const uint8_t expected =
			(uint8_t)(0xFFu << (8u - __NVIC_PRIO_BITS));
	FIBER_REQUIRE(implemented != 0u, 'Q');
	FIBER_REQUIRE(implemented == expected, 'Q');
	FIBER_REQUIRE((FIBER_PORT_SCHEDULER_BASEPRI & implemented) != 0u, 'Q');
	FIBER_REQUIRE((FIBER_PORT_SCHEDULER_BASEPRI &
			(uint32_t)(uint8_t)~implemented) == 0u, 'q');

	uint32_t implemented_bits = 0u;
	uint8_t probe = implemented;
	while ((probe & 0x80u) != 0u) {
		++implemented_bits;
		probe = (uint8_t)(probe << 1u);
	}
	FIBER_REQUIRE(implemented_bits == (uint32_t)__NVIC_PRIO_BITS, 'Q');

	uint32_t max_prigroup = 0u;
	if (implemented_bits < 8u) {
		max_prigroup = 7u - implemented_bits;
	} else {
		FIBER_REQUIRE((FIBER_PORT_SCHEDULER_BASEPRI & 1u) == 0u, 'g');
	}
	max_prigroup = (max_prigroup << 8u) &
			fiber_portSCB_AIRCR_PRIGROUP_MASK;
	FIBER_REQUIRE((fiber_portSCB_AIRCR_REG &
			fiber_portSCB_AIRCR_PRIGROUP_MASK) <= max_prigroup, 'g');
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_validate_vector_table(
		const FiberPortMpuMemoryLayout *layout)
{
	FIBER_REQUIRE(layout != NULL, 'L');
	const uintptr_t first_vtor = (uintptr_t)fiber_portSCB_VTOR_REG;
	__DSB();
	__ISB();
	const uintptr_t second_vtor = (uintptr_t)fiber_portSCB_VTOR_REG;
	FIBER_REQUIRE(first_vtor == second_vtor, 'V');
	FIBER_REQUIRE((first_vtor & (fiber_portVECTOR_ALIGNMENT - 1u)) == 0u,
			'V');
	FIBER_REQUIRE(first_vtor <= UINTPTR_MAX -
			(fiber_portVECTOR_REQUIRED_WORDS * sizeof(uint32_t)), 'O');
	FIBER_REQUIRE(fiber_port_range_contains(layout->privileged_code_start,
			layout->privileged_code_end, first_vtor,
			first_vtor +
				(fiber_portVECTOR_REQUIRED_WORDS * sizeof(uint32_t))), 'V');

	const volatile uint32_t *const vectors =
			(const volatile uint32_t *)first_vtor;
	const uintptr_t initial_msp = (uintptr_t)vectors[0];
	FIBER_REQUIRE(initial_msp != 0u, 'P');
	FIBER_REQUIRE((initial_msp & 7u) == 0u, 'P');
	FIBER_REQUIRE(initial_msp > layout->privileged_data_start, 'P');
	FIBER_REQUIRE(initial_msp <= layout->privileged_data_end, 'P');

	const uintptr_t actual_svc =
			(uintptr_t)vectors[fiber_portVECTOR_INDEX_SVC];
	const uintptr_t actual_pendsv =
			(uintptr_t)vectors[fiber_portVECTOR_INDEX_PENDSV];
	FIBER_REQUIRE((actual_svc & 1u) != 0u, 'y');
	FIBER_REQUIRE((actual_pendsv & 1u) != 0u, 'Y');
	FIBER_REQUIRE(fiber_port_code_address(actual_svc) ==
			fiber_port_code_address((uintptr_t)&SVC_Handler), 'y');
	FIBER_REQUIRE(fiber_port_code_address(actual_pendsv) ==
			fiber_port_code_address((uintptr_t)&PendSV_Handler), 'Y');
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_apply_fault_policy(void)
{
#if FIBER_CLEAR_STICKY_FAULT_STATUS_ON_START
	const uint32_t cfsr = fiber_portSCB_CFSR_REG;
	const uint32_t hfsr = fiber_portSCB_HFSR_REG;
	fiber_portSCB_CFSR_REG = cfsr;
	fiber_portSCB_HFSR_REG = hfsr;
	fiber_portSCB_DFSR_REG = 0x1Fu;
#endif

	uint32_t required_faults = fiber_portSCB_MEMFAULTENA_BIT;
#if FIBER_ENABLE_CONFIGURABLE_FAULTS
	required_faults |= fiber_portSCB_BUSFAULTENA_BIT |
			fiber_portSCB_USGFAULTENA_BIT;
#endif
	fiber_portSCB_SHCSR_REG |= required_faults;

	uint32_t required_ccr = fiber_portSCB_CCR_STKALIGN_BIT;
#if FIBER_ENABLE_UNALIGNED_TRAP
	required_ccr |= fiber_portSCB_CCR_UNALIGN_TRP_BIT;
#endif
#if FIBER_ENABLE_DIV0_TRAP
	required_ccr |= fiber_portSCB_CCR_DIV_0_TRP_BIT;
#endif
	fiber_portSCB_CCR_REG |= required_ccr;
	__DSB();
	__ISB();
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG & required_faults) ==
			required_faults, 'F');
	FIBER_REQUIRE((fiber_portSCB_CCR_REG & required_ccr) == required_ccr,
			'A');
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_configure_exception_priorities(void)
{
	const uint32_t primask = fiber_port_primask_save_disable();
	const uint32_t lowest = (uint32_t)fiber_port_lowest_priority_encoding();
	fiber_portNVIC_SHPR3_REG =
			(fiber_portNVIC_SHPR3_REG &
			~(fiber_portNVIC_PRIORITY_BYTE_MASK <<
				fiber_portNVIC_PENDSV_PRIORITY_SHIFT)) |
			(lowest << fiber_portNVIC_PENDSV_PRIORITY_SHIFT);
	fiber_portNVIC_SHPR2_REG &=
			~(fiber_portNVIC_PRIORITY_BYTE_MASK <<
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
	const uint32_t svc_priority =
			(fiber_portNVIC_SHPR2_REG >> fiber_portNVIC_SVC_PRIORITY_SHIFT) &
			fiber_portNVIC_PRIORITY_BYTE_MASK;
	FIBER_REQUIRE(pendsv_priority == lowest, 'P');
	FIBER_REQUIRE(svc_priority == 0u, 'w');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == 0u, 'J');
	fiber_port_primask_restore(primask);
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_require_scheduler_configuration_environment(void)
{
	fiber_port_require_privileged_thread_msp();
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_runtime_prepare_start(void)
{
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_require_privileged_thread_msp();
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');

	FiberPortMpuMemoryLayout layout;
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_vector_table(&layout);
	fiber_port_validate_priority_contract();
	fiber_port_apply_fault_policy();
	fiber_port_configure_exception_priorities();
	fiber_port_validate_vector_table(&layout);
	fiber_port_require_privileged_thread_msp();
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_validate_svc_cpu_state(void)
{
	FIBER_REQUIRE(__get_IPSR() == 11u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_validate_svc_frame_shape(const uint32_t *hardware_frame)
{
	FIBER_REQUIRE(hardware_frame != NULL, 'P');
	FIBER_REQUIRE((((uintptr_t)hardware_frame) & 7u) == 0u, 'A');
	const uint32_t stacked_pc = hardware_frame[6];
	const uint32_t stacked_xpsr = hardware_frame[7];
	FIBER_REQUIRE((stacked_pc & 1u) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_THUMB_BIT) != 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_IPSR_MASK) == 0u, 'x');
	FIBER_REQUIRE((stacked_xpsr & fiber_portXPSR_STACK_ALIGN_BIT) == 0u, 'a');
}

static FIBER_CM3_MPU_PRIVILEGED
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

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_validate_exact_svc_site(uint32_t stacked_pc,
		const unsigned char *expected_site,
		char panic_code)
{
	FIBER_REQUIRE(expected_site != NULL, panic_code);
	FIBER_REQUIRE((uintptr_t)stacked_pc ==
			fiber_port_code_address((uintptr_t)expected_site), panic_code);
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_write_region(
		const FiberPortMpuRegionRegisters *region)
{
	FIBER_REQUIRE(region != NULL, 'M');
	fiber_portMPU_RBAR_REG = region->rbar;
	fiber_portMPU_RASR_REG = region->rasr;
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_validate_region_readback(uint32_t region_number,
		const FiberPortMpuRegionRegisters *expected)
{
	FIBER_REQUIRE(expected != NULL, 'M');
	fiber_portMPU_RNR_REG = region_number;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == region_number, 'M');
	FIBER_REQUIRE((fiber_portMPU_RBAR_REG &
			fiber_portMPU_REGION_ADDRESS_MASK) ==
			(expected->rbar & fiber_portMPU_REGION_ADDRESS_MASK), 'M');
	FIBER_REQUIRE(fiber_portMPU_RASR_REG == expected->rasr, 'M');
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_validate_active_context(const FiberContext *ctx)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(ctx != NULL, 'N');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG & fiber_portSCB_MEMFAULTENA_BIT) !=
			0u, 'M');
	fiber_port_mpu_build_global_regions(&global);

	for (uint32_t index = 0u; index < fiber_portMPU_REGION_COUNT; ++index) {
		fiber_port_mpu_validate_region_readback(index,
				&ctx->mpu_regions[index]);
	}
	for (uint32_t index = 0u; index < fiber_portMPU_GLOBAL_REGION_COUNT;
			++index) {
		fiber_port_mpu_validate_region_readback(
				index + fiber_portMPU_CURRENT_CONTEXT_REGION,
				&global.regions[index]);
	}

	/* All region writes use RBAR.VALID, so RNR has no runtime ownership. Keep
	 * its post-validation value deterministic for diagnostics. */
	fiber_portMPU_RNR_REG = 0u;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == 0u, 'M');
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_activate_first_context(FiberContext *first)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(first != NULL, 'N');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	fiber_port_mpu_build_global_regions(&global);

	__DMB();
	fiber_portMPU_CTRL_REG = 0u;
	__DSB();
	__ISB();
	FIBER_REQUIRE((fiber_portMPU_CTRL_REG & fiber_portMPU_CTRL_ENABLE) == 0u,
			'M');

	for (uint32_t index = 0u; index < fiber_portMPU_REGION_COUNT; ++index) {
		fiber_port_mpu_write_region(&first->mpu_regions[index]);
	}
	for (uint32_t index = 0u; index < fiber_portMPU_GLOBAL_REGION_COUNT;
			++index) {
		fiber_port_mpu_write_region(&global.regions[index]);
	}

	fiber_portSCB_SHCSR_REG |= fiber_portSCB_MEMFAULTENA_BIT;
	__DSB();
	__ISB();
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG & fiber_portSCB_MEMFAULTENA_BIT) !=
			0u, 'M');

	fiber_portMPU_CTRL_REG = fiber_portMPU_CTRL_REQUIRED;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');

	fiber_port_mpu_validate_active_context(first);
}

FIBER_CM3_MPU_PRIVILEGED
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
	FIBER_REQUIRE((uintptr_t)hardware_frame == (uintptr_t)__get_PSP(), 'P');
	fiber_port_context_validate_save_current(current, hardware_frame);
	fiber_port_mpu_validate_active_context(current);
}

typedef struct FiberPortMpuSchedulerCpuState {
	uint32_t primask;
	uint32_t basepri;
	uint32_t faultmask;
	uint32_t control;
	uint32_t ipsr;
	uint32_t psp;
	uint32_t vtor;
	uint32_t mpu_ctrl;
	uint32_t memfault_enabled;
} FiberPortMpuSchedulerCpuState;

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_capture_scheduler_cpu_state(
		FiberPortMpuSchedulerCpuState *state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	__COMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->basepri = fiber_port_basepri_read();
	state->faultmask = __get_FAULTMASK();
	state->control = __get_CONTROL();
	state->ipsr = __get_IPSR();
	state->psp = __get_PSP();
	state->vtor = fiber_portSCB_VTOR_REG;
	state->mpu_ctrl = fiber_portMPU_CTRL_REG;
	state->memfault_enabled =
			fiber_portSCB_SHCSR_REG & fiber_portSCB_MEMFAULTENA_BIT;
	__COMPILER_BARRIER();
}

static FIBER_CM3_MPU_PRIVILEGED
void fiber_port_validate_scheduler_cpu_state(
		const FiberPortMpuSchedulerCpuState *before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	__COMPILER_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'r');
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'B');
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 't');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
	FIBER_REQUIRE(__get_IPSR() == before->ipsr, 'i');
	FIBER_REQUIRE(__get_PSP() == before->psp, 'P');
	FIBER_REQUIRE(fiber_portSCB_VTOR_REG == before->vtor, 'V');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == before->mpu_ctrl, 'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG & fiber_portSCB_MEMFAULTENA_BIT) ==
			before->memfault_enabled, 'M');
	__COMPILER_BARRIER();
}

FIBER_CM3_MPU_PRIVILEGED
FiberContext *fiber_port_runtime_select_first(void)
{
	fiber_port_require_privileged_thread_msp();
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');

	const uint32_t critical_state = fiber_port_scheduler_critical_enter();
	FiberPortMpuSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const first =
			fiber_internal_runtime_select_scheduler_candidate(NULL);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(first);
	fiber_port_scheduler_critical_exit(critical_state);
	return first;
}

FIBER_API_NORETURN FIBER_CM3_MPU_PRIVILEGED
void fiber_port_runtime_start_first(FiberContext *first)
{
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_internal_runtime_require_current_context();
	fiber_port_require_privileged_thread_msp();
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == 0u, 'M');
	fiber_port_context_validate_restore(first);
	fiber_port_start_first_context();
	FIBER_API_UNREACHABLE();
}

FIBER_CM3_MPU_PRIVILEGED
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
	fiber_internal_runtime_publish_current_context(next);
	return next;
}

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_mpu_switch_to_context(FiberContext *next)
{
	FiberPortMpuGlobalRegionImage global;
	FIBER_REQUIRE(next != NULL, 'N');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE(__get_CONTROL() ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE, 'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	fiber_port_mpu_build_global_regions(&global);

	/* The FreeRTOS reference disables the MPU while replacing regions 0-3.
	 * Fiber additionally masks all configurable interrupts for this short
	 * interval so no ISR observes a disabled or partially programmed MPU. */
	__DMB();
	fiber_portMPU_CTRL_REG = 0u;
	__DSB();
	__ISB();
	FIBER_REQUIRE((fiber_portMPU_CTRL_REG & fiber_portMPU_CTRL_ENABLE) == 0u,
			'M');

	for (uint32_t index = 0u; index < fiber_portMPU_REGION_COUNT; ++index) {
		fiber_port_mpu_write_region(&next->mpu_regions[index]);
	}

	fiber_portMPU_CTRL_REG = fiber_portMPU_CTRL_REQUIRED;
	__DSB();
	__ISB();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED, 'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG & fiber_portSCB_MEMFAULTENA_BIT) !=
			0u, 'M');
	fiber_port_mpu_validate_active_context(next);
}

static FIBER_CM3_MPU_PRIVILEGED
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

FIBER_CM3_MPU_PRIVILEGED
void fiber_port_svc_dispatch(uint32_t *hardware_frame,
		uint32_t exc_return,
		FiberContext *current)
{
	FiberPortMpuMemoryLayout layout;
	fiber_port_validate_svc_cpu_state();
	FIBER_REQUIRE((exc_return == fiber_portEXC_RETURN_THREAD_MSP) ||
			(exc_return == fiber_portINITIAL_EXC_RETURN), 'l');
	fiber_port_validate_svc_frame_shape(hardware_frame);
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	if (exc_return == fiber_portEXC_RETURN_THREAD_MSP) {
		FIBER_REQUIRE((__get_CONTROL() & 3u) == 0u, 'l');
		fiber_port_validate_start_svc_frame(hardware_frame, &layout);
	} else if (exc_return == fiber_portINITIAL_EXC_RETURN) {
		FIBER_REQUIRE(__get_CONTROL() ==
				fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_port_context_validate_running_svc(current, hardware_frame);
	} else {
		fiber_panic('l');
	}

	const uint32_t service = fiber_port_decode_svc_number(hardware_frame,
			&layout);
	switch (service) {
	case fiber_portSVC_START:
		FIBER_REQUIRE(exc_return == fiber_portEXC_RETURN_THREAD_MSP, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_start_return_site, 'u');
		FIBER_REQUIRE(current != NULL, 'C');
		fiber_port_context_validate_restore(current);
		__disable_irq();
		__DSB();
		__ISB();
		fiber_port_mpu_activate_first_context(current);
		fiber_port_restore_first_context_from_svc(current);
		FIBER_API_UNREACHABLE();

	case fiber_portSVC_YIELD:
		FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_yield_return_site, 'u');
		__disable_irq();
		fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVSET_BIT;
		__DSB();
		__ISB();
		__enable_irq();
		return;

	case fiber_portSVC_RETURN:
		FIBER_REQUIRE(exc_return == fiber_portINITIAL_EXC_RETURN, 'l');
		fiber_port_validate_exact_svc_site(hardware_frame[6],
				fiber_port_svc_return_return_site, 'u');
		fiber_internal_task_return();
		FIBER_API_UNREACHABLE();

	default:
		fiber_panic('u');
	}
}

/* Public schedule remains CPU-neutral. In an unprivileged profile this exact
 * veneer is the only allowed route to PENDSVSET. */
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

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_start_first_context(void)
{
	__ASM volatile(
			".syntax unified                                     \n"
			"mrs   r3, ipsr                                      \n"
			"cmp   r3, #0                                        \n"
			"bne   90f                                           \n"
			"mrs   r3, control                                   \n"
			"tst   r3, #3                                        \n"
			"bne   90f                                           \n"
			"mrs   r3, primask                                   \n"
			"cmp   r3, #0                                        \n"
			"bne   91f                                           \n"
			"mrs   r3, basepri                                   \n"
			"cmp   r3, #0                                        \n"
			"bne   92f                                           \n"
			"mrs   r3, faultmask                                 \n"
			"cmp   r3, #0                                        \n"
			"bne   93f                                           \n"
			"cpsid i                                              \n"
			"dsb                                                  \n"
			"isb                                                  \n"
			"ldr   r0, =0xE000ED08                               \n"
			"ldr   r0, [r0]                                      \n"
			"ldr   r0, [r0]                                      \n"
			"cmp   r0, #0                                        \n"
			"beq   94f                                           \n"
			"tst   r0, #7                                        \n"
			"bne   94f                                           \n"
			"msr   msp, r0                                       \n"
			"isb                                                  \n"
			"ldr   r3, =0xE000ED04                               \n"
			"ldr   r2, =0x08000000                               \n"
			"str   r2, [r3]                                      \n"
			"dsb                                                  \n"
			"isb                                                  \n"
			"cpsie i                                              \n"
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
			"movs  r0, #112                                      \n"
			"bl    fiber_panic                                   \n"
			"b     91b                                            \n"
			"92:                                                  \n"
			"movs  r0, #98                                       \n"
			"bl    fiber_panic                                   \n"
			"b     92b                                            \n"
			"93:                                                  \n"
			"movs  r0, #102                                      \n"
			"bl    fiber_panic                                   \n"
			"b     93b                                            \n"
			"94:                                                  \n"
			"movs  r0, #80                                       \n"
			"bl    fiber_panic                                   \n"
			"b     94b                                            \n"
			".ltorg                                               \n"
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
			"msr   basepri, r0                      \n"
			"dsb                                    \n"
			"isb                                    \n"
			"cpsie i                                \n"
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

/*
 * Protected ARMv7-M MPU context switch.
 *
 * Unlike the non-MPU ports, no software frame is written to the unprivileged
 * stack. The hardware frame is copied into privileged FiberContext storage;
 * CONTROL, r4-r11, and EXC_RETURN are stored immediately before it using the
 * exact 20-word geometry audited from the FreeRTOS ARM_CM3_MPU port.
 */
FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void PendSV_Handler(void)
{
	__ASM volatile(
			".syntax unified                         \n"
			"mrs   r0, psp                          \n" /* interrupted HW frame */
			"isb                                    \n"
			"ldr   r1, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r1, [r1]                         \n" /* current context */
			"cmp   r1, #0                           \n"
			"beq   90f                              \n"

			/* Validate handler provenance, active MPU image, context seal,
			 * live PSP bounds, and hardware frame before reading context fields. */
			"push  {r0, r1, r2, lr}                 \n"
			"mov   r2, lr                           \n" /* arg2 = EXC_RETURN */
			"mov   r3, r0                           \n"
			"mov   r0, r1                           \n" /* arg0 = current */
			"mov   r1, r3                           \n" /* arg1 = HW frame */
			"bl    fiber_port_pendsv_validate_save_current \n"
			"pop   {r0, r1, r2, lr}                 \n"

			/* Save CONTROL, r4-r11, EXC_RETURN, PSP, and the copied basic
			 * hardware frame into protected context storage. */
			"ldr   r3, [r1, #0]                    \n" /* cursor -> CONTROL */
			"mrs   r2, control                      \n"
			"stmia r3!, {r2, r4-r11, lr}           \n"
			"ldmia r0, {r4-r11}                    \n" /* copy r0-r3,r12,lr,pc,xpsr */
			"stmia r3!, {r0, r4-r11}               \n"
			"str   r3, [r1, #0]                    \n" /* cursor -> cursor_limit */

			/* Run the external scheduler in privileged PendSV context under
			 * the selected BASEPRI threshold. The bridge validates and publishes
			 * the selected restore context before returning it in r0. */
			"movs  r2, #%c[sched_basepri]           \n"
			"msr   basepri, r2                      \n"
			"dsb                                    \n"
			"isb                                    \n"
			"mov   r0, r1                           \n"
			"bl    fiber_port_scheduler_pick_next_from_pendsv \n"

			/* Replace regions 0-3 atomically. BASEPRI remains raised and
			 * PRIMASK closes the high-priority preemption window while MPU_CTRL
			 * is disabled or the region image is incomplete. */
			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"push  {r0, lr}                         \n"
			"bl    fiber_port_mpu_switch_to_context \n"
			"pop   {r2, lr}                         \n" /* r2 = selected context */
			"movs  r0, #0                           \n"
			"msr   basepri, r0                      \n"
			"dsb                                    \n"
			"isb                                    \n"

			/* Restore the selected protected image and copy its hardware frame
			 * back to the newly mapped PSP stack. Do not rewrite saved state
			 * after restore except for the live cursor transition. */
			"ldr   r1, [r2, #0]                    \n" /* cursor -> cursor_limit */
			"ldmdb r1!, {r0, r4-r11}               \n"
			"msr   psp, r0                          \n"
			"stmia r0, {r4-r11}                    \n"
			"ldmdb r1!, {r3-r11, lr}               \n"
			"str   r1, [r2, #0]                    \n" /* cursor -> CONTROL */
			"msr   control, r3                      \n"
			"isb                                    \n"
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    lr                               \n"

			"90:                                    \n"
			"movs  r0, #106                         \n" /* 'j': foreign/pre-start PendSV */
			"bl    fiber_panic                      \n"
			"b     90b                              \n"
			".ltorg                                 \n"
			:
			: [sched_basepri] "i" (FIBER_PORT_SCHEDULER_BASEPRI)
			: "memory", "cc");
}

#undef FIBER_CM3_MPU_PRIVILEGED
#undef FIBER_CM3_MPU_UNPRIVILEGED
#undef fiber_portSTRINGIFY
#undef fiber_portSTRINGIFY2
