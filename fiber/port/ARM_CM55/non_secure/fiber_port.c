/* Scalar M55 TrustZone/SecureContext forward runtime adapters. */
#include "fiber_portmacro.h"
#include "fiber_port_private.h"
#include "../../fiber_port_runtime_abi.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_cpu_ipsr(void)
{
	uint32_t value;
	fiber_portASM volatile("mrs %0, ipsr" : "=r"(value) :: "memory");
	return value;
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_start_masks_check(void)
{
	FiberPortRunningCpuState cpu;
	fiber_port_running_cpu_capture(&cpu);
	FIBER_REQUIRE(cpu.ipsr == 0u, 'i');
	FIBER_REQUIRE(cpu.control == 0u, 'l');
	FIBER_REQUIRE(cpu.primask == 0u, 'p');
	FIBER_REQUIRE(cpu.basepri == 0u, 'b');
	FIBER_REQUIRE(cpu.faultmask == 0u, 'f');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_basepri_write(const uint32_t value)
{
	fiber_portASM volatile("msr basepri, %0" :: "r"(value) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_basepri_read() == value, 'b');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_exception_configuration_check(void)
{
	const uintptr_t vector = (uintptr_t)__fiber_c55s_ns_vector_start__;
	FIBER_REQUIRE(*(const volatile uint32_t *)0xE000ED08u == vector, 'V');
	const volatile uint32_t *const words = (const volatile uint32_t *)vector;
	FIBER_REQUIRE(words[11] == ((uint32_t)(uintptr_t)&SVC_Handler | 1u), 'y');
	FIBER_REQUIRE(words[14] == ((uint32_t)(uintptr_t)&PendSV_Handler | 1u), 'Y');
	const uint8_t mask = (uint8_t)(0xFFu << (8u - __NVIC_PRIO_BITS));
	FIBER_REQUIRE(*(const volatile uint8_t *)0xE000ED1Fu == 0u, 'w');
	FIBER_REQUIRE(*(const volatile uint8_t *)0xE000ED22u == mask, 'P');
	FIBER_REQUIRE((*(const volatile uint32_t *)0xE000ED14u & (1u << 9u)) != 0u, 'A');
	uint32_t max_prigroup = 0u;
	if (__NVIC_PRIO_BITS < 8u) {
		max_prigroup = 7u - __NVIC_PRIO_BITS;
	}
	FIBER_REQUIRE((*(const volatile uint32_t *)0xE000ED0Cu & (7u << 8u)) <=
			(max_prigroup << 8u), 'g');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_prepare_exception_configuration(void)
{
	fiber_port_start_masks_check();
	fiber_portASM volatile("cpsid i" ::: "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	volatile uint8_t *const probe = (volatile uint8_t *)0xE000E400u;
	const uint8_t original = *probe;
	*probe = 0xFFu;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	const uint8_t implemented = *probe;
	*probe = original;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(*probe == original, 'Q');
	FIBER_REQUIRE(implemented ==
			(uint8_t)(0xFFu << (8u - __NVIC_PRIO_BITS)), 'Q');
	FIBER_REQUIRE((FIBER_PORT_SCHEDULER_BASEPRI & implemented) != 0u &&
			(FIBER_PORT_SCHEDULER_BASEPRI & ~(uint32_t)implemented) == 0u, 'q');
	*(volatile uint8_t *)0xE000ED1Fu = 0u;
	*(volatile uint8_t *)0xE000ED22u = implemented;
	*(volatile uint32_t *)0xE000ED14u |= 1u << 9u;
	*(volatile uint32_t *)0xE000ED04u = 1u << 27u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_port_exception_configuration_check();
	FIBER_REQUIRE((*(const volatile uint32_t *)0xE000ED04u & (1u << 28u)) == 0u, 'D');
	fiber_portASM volatile("cpsie i" ::: "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_port_start_masks_check();
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
		fiber_portASM volatile("wfe" ::: "memory");
	}
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_require_scheduler_configuration_environment(void)
{
	FIBER_REQUIRE(fiber_port_cpu_ipsr() == 0u, 'i');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_prepare_start(void)
{
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	/* Unique component references force both strong handler archive members,
	 * independently of startup's already satisfied weak handler aliases. */
	fiber_port_arm_cm55_secure_context_first_start_component_v1_anchor();
	fiber_port_arm_cm55_secure_context_pendsv_component_v1_anchor();
	fiber_port_start_masks_check();
	fiber_port_prepare_start_environment();
	fiber_port_prepare_exception_configuration();
	fiber_port_start_masks_check();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_runtime_select_first(void)
{
	fiber_port_start_masks_check();
	fiber_port_basepri_write(FIBER_PORT_SCHEDULER_BASEPRI);
	FiberPortRunningCpuState cpu;
	fiber_port_running_cpu_capture(&cpu);
	FiberContext *const first =
			fiber_internal_runtime_select_scheduler_candidate(NULL);
	fiber_port_running_cpu_check(&cpu);
	fiber_port_validate_first_candidate(first);
	fiber_port_running_cpu_check(&cpu);
	fiber_port_basepri_write(0u);
	fiber_port_start_masks_check();
	return first;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_start_first(FiberContext *const first)
{
	fiber_port_start_masks_check();
	fiber_port_exception_configuration_check();
	fiber_port_first_start(first);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_schedule(void)
{
	FIBER_REQUIRE(fiber_port_cpu_ipsr() == 0u, 'i');
	fiber_internal_runtime_require_current_context();
	FiberPortRunningCpuState cpu;
	fiber_port_running_cpu_capture(&cpu);
	FIBER_REQUIRE(cpu.control == 2u, 'l');
	FIBER_REQUIRE(cpu.primask == 0u, 'p');
	FIBER_REQUIRE(cpu.basepri == 0u, 'b');
	FIBER_REQUIRE(cpu.faultmask == 0u, 'f');
	*(volatile uint32_t *)0xE000ED04u = 1u << 28u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}
