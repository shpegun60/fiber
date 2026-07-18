/* ARM_CM4_MPU build-selected protected runtime engine. */

#include "fiber_port_private.h"
#include "../../fiber_platform_policy.h"

#define FIBER_CM4_MPU_PRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portPRIVILEGED_FUNCTION
#define FIBER_CM4_MPU_UNPRIVILEGED \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY \
	fiber_portUNPRIVILEGED_FUNCTION

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_CM4_MPU_UNPRIVILEGED
void fiber_port_runtime_memory_barrier(void)
{
	fiber_portDATA_MEMORY_BARRIER();
	fiber_portCOMPILER_BARRIER();
}

FIBER_API_NORETURN FIBER_CM4_MPU_PRIVILEGED
void fiber_port_panic_wait(void)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	for (;;) {
		__WFE();
	}
}

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

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_primask_restore(uint32_t primask)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}

static FIBER_CM4_MPU_PRIVILEGED
uint32_t fiber_port_scheduler_critical_enter(void)
{
	const uint32_t previous = fiber_port_basepri_read();
	FIBER_REQUIRE(previous == 0u, 'b');
	fiber_port_basepri_write(FIBER_PORT_SCHEDULER_BASEPRI);
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'B');
	return previous;
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_scheduler_critical_exit(uint32_t previous)
{
	FIBER_REQUIRE(previous == 0u, 'b');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'B');
	fiber_port_basepri_write(previous);
	FIBER_REQUIRE(fiber_port_basepri_read() == previous, 'B');
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
uint8_t fiber_port_lowest_priority_encoding(void)
{
	const uint32_t lowest = (1u << __NVIC_PRIO_BITS) - 1u;
	return (uint8_t)(lowest << (8u - __NVIC_PRIO_BITS));
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_validate_priority_contract(void)
{
	const uint32_t primask = fiber_port_primask_save_disable();
	const uint8_t original = fiber_portNVIC_FIRST_USER_PRIORITY_REG;
	fiber_portNVIC_FIRST_USER_PRIORITY_REG = 0xFFu;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	const uint8_t implemented = fiber_portNVIC_FIRST_USER_PRIORITY_REG;
	fiber_portNVIC_FIRST_USER_PRIORITY_REG = original;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
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

static FIBER_CM4_MPU_PRIVILEGED
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
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG & required_faults) ==
			required_faults, 'F');
	FIBER_REQUIRE((fiber_portSCB_CCR_REG & required_ccr) == required_ccr,
			'A');
}

static FIBER_CM4_MPU_PRIVILEGED
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
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portNVIC_INT_CTRL_REG = fiber_portNVIC_PENDSVCLR_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();

	const uint32_t pendsv_priority =
			(fiber_portNVIC_SHPR3_REG >>
			fiber_portNVIC_PENDSV_PRIORITY_SHIFT) &
			fiber_portNVIC_PRIORITY_BYTE_MASK;
	const uint32_t svc_priority =
			(fiber_portNVIC_SHPR2_REG >>
			fiber_portNVIC_SVC_PRIORITY_SHIFT) &
			fiber_portNVIC_PRIORITY_BYTE_MASK;
	FIBER_REQUIRE(pendsv_priority == lowest, 'P');
	FIBER_REQUIRE(svc_priority == 0u, 'w');
	FIBER_REQUIRE((fiber_portNVIC_INT_CTRL_REG &
			fiber_portNVIC_PENDSVSET_BIT) == 0u, 'J');
	fiber_port_primask_restore(primask);
}

static FIBER_CM4_MPU_PRIVILEGED
void fiber_port_validate_svc_vector(void)
{
	FiberPortMpuMemoryLayout layout;
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);

	const uintptr_t vector_base = (uintptr_t)fiber_portSCB_VTOR_REG;
	FIBER_REQUIRE(vector_base != 0u, 'V');
	FIBER_REQUIRE((vector_base & (fiber_portVECTOR_ALIGNMENT - 1u)) == 0u,
			'V');
	FIBER_REQUIRE(vector_base <= UINTPTR_MAX -
			(fiber_portVECTOR_REQUIRED_WORDS * sizeof(uint32_t)), 'O');
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_code_start,
			layout.privileged_code_end, vector_base,
			vector_base +
				(fiber_portVECTOR_REQUIRED_WORDS * sizeof(uint32_t))), 'V');
	const volatile uint32_t *const vectors =
			(const volatile uint32_t *)vector_base;
	const uintptr_t initial_msp = (uintptr_t)vectors[0];
	FIBER_REQUIRE(initial_msp >= FIBER_PORT_EXC_BASE_BYTES, 'P');
	FIBER_REQUIRE((initial_msp & 7u) == 0u, 'P');
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_data_start,
			layout.privileged_data_end,
			initial_msp - FIBER_PORT_EXC_BASE_BYTES,
			initial_msp), 'P');
	const uintptr_t actual_svc =
			(uintptr_t)vectors[fiber_portVECTOR_INDEX_SVC];
	const uintptr_t actual_pendsv =
			(uintptr_t)vectors[fiber_portVECTOR_INDEX_PENDSV];
	FIBER_REQUIRE((actual_svc & 1u) != 0u, 'y');
	FIBER_REQUIRE((actual_pendsv & 1u) != 0u, 'Y');
	const uintptr_t svc = fiber_port_code_address(actual_svc);
	const uintptr_t pendsv = fiber_port_code_address(actual_pendsv);
	FIBER_REQUIRE(svc <= UINTPTR_MAX - 2u, 'O');
	FIBER_REQUIRE(pendsv <= UINTPTR_MAX - 2u, 'O');
	FIBER_REQUIRE(svc == fiber_port_code_address(
			(uintptr_t)&SVC_Handler), 'y');
	FIBER_REQUIRE(pendsv == fiber_port_code_address(
			(uintptr_t)&PendSV_Handler), 'Y');
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_code_start,
			layout.privileged_code_end, svc, svc + 2u), 'y');
	FIBER_REQUIRE(fiber_port_range_contains(layout.privileged_code_start,
			layout.privileged_code_end, pendsv, pendsv + 2u), 'Y');
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

FIBER_CM4_MPU_PRIVILEGED
void fiber_port_require_scheduler_configuration_environment(void)
{
	fiber_port_validate_first_start_environment();
}

FIBER_CM4_MPU_PRIVILEGED
void fiber_port_runtime_prepare_start(void)
{
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_validate_first_start_environment();

	FiberPortMpuMemoryLayout layout;
	fiber_port_mpu_load_linker_layout(&layout);
	fiber_port_mpu_linker_layout_check(&layout);
	fiber_port_validate_svc_vector();
	fiber_port_validate_priority_contract();
	fiber_port_apply_fault_policy();
	fiber_port_configure_exception_priorities();
	fiber_port_fpu_prepare();
	fiber_port_validate_svc_vector();
	fiber_port_validate_first_start_environment();
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

FIBER_CM4_MPU_PRIVILEGED
void fiber_port_pendsv_validate_save_current(FiberContext *current,
		uint32_t *hardware_frame,
		uint32_t exc_return)
{
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE((exc_return == fiber_portEXC_RETURN_THREAD_PSP_BASIC) ||
			(exc_return == fiber_portEXC_RETURN_THREAD_PSP_EXTENDED), 'l');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((uintptr_t)hardware_frame == (uintptr_t)__get_PSP(), 'P');

	const uint32_t control = __get_CONTROL();
	FIBER_REQUIRE((control & 3u) ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	if (exc_return == fiber_portEXC_RETURN_THREAD_PSP_EXTENDED) {
		FIBER_REQUIRE((control & 4u) != 0u, 'l');
	} else {
		FIBER_REQUIRE((control & 4u) == 0u, 'l');
	}

	FIBER_REQUIRE((fiber_portSCB_CPACR_REG &
			fiber_portCPACR_CP10_CP11_FULL) ==
			fiber_portCPACR_CP10_CP11_FULL, 'e');
	const uint32_t fpccr = fiber_portFPU_FPCCR_REG;
	FIBER_REQUIRE((fpccr & fiber_portFPCCR_ASPEN_BIT) != 0u, 'E');
#if FIBER_FPU_LAZY
	FIBER_REQUIRE((fpccr & fiber_portFPCCR_LSPEN_BIT) != 0u, 'E');
#else
	FIBER_REQUIRE((fpccr & fiber_portFPCCR_LSPEN_BIT) == 0u, 'E');
	FIBER_REQUIRE((fpccr & fiber_portFPCCR_LSPACT_BIT) == 0u, 'E');
#endif
	if (exc_return == fiber_portEXC_RETURN_THREAD_PSP_BASIC) {
		FIBER_REQUIRE((fpccr & fiber_portFPCCR_LSPACT_BIT) == 0u, 'E');
	}

	fiber_port_context_validate_save_current(current, hardware_frame,
			exc_return);
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
	uint32_t mpu_rnr;
	uint32_t memfault_enabled;
	uint32_t cpacr;
	uint32_t fpccr;
} FiberPortMpuSchedulerCpuState;

static FIBER_CM4_MPU_PRIVILEGED
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
	state->mpu_rnr = fiber_portMPU_RNR_REG;
	state->memfault_enabled =
			fiber_portSCB_SHCSR_REG & fiber_portSCB_MEMFAULTENA_BIT;
	state->cpacr = fiber_portSCB_CPACR_REG;
	state->fpccr = fiber_portFPU_FPCCR_REG;
	__COMPILER_BARRIER();
}

static FIBER_CM4_MPU_PRIVILEGED
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
	FIBER_REQUIRE(fiber_portMPU_RNR_REG == before->mpu_rnr, 'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) ==
			before->memfault_enabled, 'M');
	FIBER_REQUIRE(fiber_portSCB_CPACR_REG == before->cpacr, 'e');
	FIBER_REQUIRE(fiber_portFPU_FPCCR_REG == before->fpccr, 'E');
	__COMPILER_BARRIER();
}

FIBER_CM4_MPU_PRIVILEGED
FiberContext *fiber_port_runtime_select_first(void)
{
	fiber_port_validate_first_start_environment();
	FIBER_REQUIRE((fiber_portSCB_CPACR_REG &
			fiber_portCPACR_CP10_CP11_FULL) ==
			fiber_portCPACR_CP10_CP11_FULL, 'e');
	FIBER_REQUIRE((fiber_portFPU_FPCCR_REG &
			fiber_portFPCCR_ASPEN_BIT) != 0u, 'E');
#if FIBER_FPU_LAZY
	FIBER_REQUIRE((fiber_portFPU_FPCCR_REG &
			fiber_portFPCCR_LSPEN_BIT) != 0u, 'E');
#else
	FIBER_REQUIRE((fiber_portFPU_FPCCR_REG &
			fiber_portFPCCR_LSPEN_BIT) == 0u, 'E');
#endif

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

FIBER_API_NORETURN FIBER_CM4_MPU_PRIVILEGED
void fiber_port_runtime_start_first(FiberContext *first)
{
	FIBER_REQUIRE(first != NULL, 'N');
	fiber_internal_runtime_require_current_context();
	fiber_port_validate_first_start_environment();
	fiber_port_context_validate_initial_restore(first);
	fiber_port_start_first_context();
	FIBER_API_UNREACHABLE();
}

FIBER_CM4_MPU_PRIVILEGED
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(
		FiberContext *current)
{
	FIBER_REQUIRE(current != NULL, 'C');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((__get_CONTROL() & 3u) ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	FIBER_REQUIRE((fiber_portFPU_FPCCR_REG &
			fiber_portFPCCR_LSPACT_BIT) == 0u, 'E');

	FiberPortMpuSchedulerCpuState cpu_state;
	fiber_port_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const next =
			fiber_internal_runtime_select_scheduler_candidate(current);
	fiber_port_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(next);
	fiber_internal_runtime_publish_current_context(next);
	return next;
}

FIBER_CM4_MPU_PRIVILEGED
void fiber_port_mpu_switch_to_context(FiberContext *next)
{
	FIBER_REQUIRE(next != NULL, 'N');
	FIBER_REQUIRE(__get_IPSR() == 14u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() != 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() ==
			FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((__get_CONTROL() & 3u) ==
			fiber_portINITIAL_CONTROL_UNPRIVILEGED, 'l');
	FIBER_REQUIRE(fiber_portMPU_TYPE_REG == fiber_portMPU_EXPECTED_TYPE,
			'M');
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED,
			'M');

	/* FreeRTOS disables the MPU while replacing per-task regions. Fiber also
	 * closes PRIMASK so no high-priority ISR can observe a partial image. */
	fiber_portDATA_MEMORY_BARRIER();
	fiber_portMPU_CTRL_REG = 0u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE((fiber_portMPU_CTRL_REG & fiber_portMPU_CTRL_ENABLE) ==
			0u, 'M');

	for (uint32_t index = 0u;
			index < fiber_portMPU_CONTEXT_REGION_COUNT; ++index) {
		fiber_port_mpu_write_region(&next->mpu_regions[index]);
	}

	fiber_portMPU_CTRL_REG = fiber_portMPU_CTRL_REQUIRED;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_portMPU_CTRL_REG == fiber_portMPU_CTRL_REQUIRED,
			'M');
	FIBER_REQUIRE((fiber_portSCB_SHCSR_REG &
			fiber_portSCB_MEMFAULTENA_BIT) != 0u, 'M');
	fiber_port_mpu_validate_active_context(next);
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

/* This exact unprivileged veneer is the only Thread-mode route to PENDSVSET. */
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

/*
 * Protected ARMv7E-M MPU context switch.
 *
 * No software frame is written to the unprivileged stack. The handler copies
 * the complete basic hardware frame, and when EXC_RETURN selects it the low
 * and high FP state, into the fixed 53-word privileged context image.
 */
FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void PendSV_Handler(void)
{
	__ASM volatile(
			".syntax unified                         \n"
			"mrs   r0, psp                          \n" /* basic HW frame */
			"isb                                    \n"
			"ldr   r1, =fiber_internal_runtime_current_context_slot \n"
			"ldr   r1, [r1]                         \n" /* current */
			"cmp   r1, #0                           \n"
			"beq   90f                              \n"

			/* Validate provenance, seal, cursor, MPU image, CONTROL, FP
			 * policy, live PSP, and the complete hardware-frame extent before
			 * reading a field through the current pointer. */
			"push  {r0, r1, r2, lr}                 \n"
			"mov   r2, lr                           \n"
			"mov   r3, r0                           \n"
			"mov   r0, r1                           \n"
			"mov   r1, r3                           \n"
			"bl    fiber_port_pendsv_validate_save_current \n"
			"pop   {r0, r1, r2, lr}                 \n"

			/* Save into the maximum protected image. Extended frames first
			 * save s16-s31, then copy s0-s15/FPSCR from PSP+32 as 17 raw
			 * words, exactly matching the pinned FreeRTOS port. */
			"mov   r2, r1                           \n" /* retain current */
			"ldr   r1, [r2, #0]                    \n" /* cursor -> word 0 */
			"mrs   r3, control                      \n"
			"add   r0, r0, #32                     \n" /* low FP frame */
			"tst   lr, #16                          \n"
			"ittt  eq                               \n"
			"vstmiaeq r1!, {s16-s31}               \n"
			"vldmiaeq r0, {s0-s16}                 \n"
			"vstmiaeq r1!, {s0-s16}                \n"
			"sub   r0, r0, #32                     \n" /* basic frame */
			"stmia r1!, {r3-r11, lr}               \n"
			"ldmia r0, {r4-r11}                    \n"
			"stmia r1!, {r0, r4-r11}               \n"
			"str   r1, [r2, #0]                    \n" /* exact basic/FP limit */

			/* Any pending lazy low-FP save must have completed when the VFP
			 * copy executed. Continuing with LSPACT would publish an incomplete
			 * protected image. */
			"ldr   r3, =0xE000EF34                 \n"
			"ldr   r3, [r3]                         \n"
			"tst   r3, #1                           \n"
			"bne   91f                              \n"

			/* Run scheduler policy in privileged PendSV under BASEPRI. The
			 * M7 expansion preserves the exact incoming PRIMASK around errata
			 * 837070-sensitive BASEPRI writes. */
			"movs  r0, #%c[sched_basepri]           \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC
			"mov   r0, r2                           \n"
			"bl    fiber_port_scheduler_pick_next_from_pendsv \n"

			/* Replace the per-context MPU image with all configurable IRQs
			 * masked. BASEPRI remains raised until the new image is active and
			 * read back. */
			"cpsid i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"push  {r0, lr}                         \n"
			"bl    fiber_port_mpu_switch_to_context \n"
			"pop   {r2, lr}                         \n" /* selected context */
			"movs  r0, #0                           \n"
			fiber_portASM_WRITE_BASEPRI_R0_SYNC

			/* Restore basic state first. For an extended image, r0 now points
			 * immediately after the copied basic frame; copy the 17 low-FP
			 * words there and restore s16-s31 from privileged storage. */
			"ldr   r1, [r2, #0]                    \n"
			"ldmdb r1!, {r0, r4-r11}               \n"
			"msr   psp, r0                          \n"
			"stmia r0!, {r4-r11}                   \n"
			"ldmdb r1!, {r3-r11, lr}               \n"
			"msr   control, r3                      \n"
			"isb                                    \n"
			"tst   lr, #16                          \n"
			"ittt  eq                               \n"
			"vldmdbeq r1!, {s0-s16}                \n"
			"vstmiaeq r0!, {s0-s16}                \n"
			"vldmdbeq r1!, {s16-s31}               \n"
			"str   r1, [r2, #0]                    \n" /* cursor -> word 0 */
			"cpsie i                                \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bx    lr                               \n"

			"90:                                    \n"
			"movs  r0, #106                         \n" /* 'j' */
			"bl    fiber_panic                      \n"
			"b     90b                              \n"
			"91:                                    \n"
			"movs  r0, #69                          \n" /* 'E' */
			"bl    fiber_panic                      \n"
			"b     91b                              \n"
			".ltorg                                 \n"
			:
			: [sched_basepri] "i" (FIBER_PORT_SCHEDULER_BASEPRI)
			: "memory", "cc");
}

#undef FIBER_CM4_MPU_PRIVILEGED
