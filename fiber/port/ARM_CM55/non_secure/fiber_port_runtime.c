/* C55S first-start policy. The forward adapters live in fiber_port.c. */
#include "fiber_portmacro.h"
#include "fiber_port_private.h"

typedef struct FiberPortFirstStartPlan {
	uintptr_t top;
	FiberContext *first;
	uint32_t state;
} FiberPortFirstStartPlan;

static volatile FiberPortFirstStartPlan fiber_port_first_start_plan;
FIBER_STATIC_ASSERT(sizeof(FiberPortFirstStartPlan) == 12u,
		"[fiber]: C55S private first-start plan geometry changed");

/* Prepare the CPU/MSP plan before the scheduler sees current == NULL.
 * The older private component entry may still start directly from state 0;
 * the public runtime path must traverse prepared -> selected -> committed. */
static volatile FiberPortFirstStartPlan fiber_port_start_environment_plan;

typedef struct FiberPortFirstStartCpuState {
	uint32_t ipsr, control, primask, basepri, faultmask, psplim;
} FiberPortFirstStartCpuState;

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_first_start_cpu_capture(FiberPortFirstStartCpuState *const state)
{
	fiber_portASM volatile("mrs %0, ipsr" : "=r"(state->ipsr) :: "memory");
	fiber_portASM volatile("mrs %0, control" : "=r"(state->control) :: "memory");
	fiber_portASM volatile("mrs %0, primask" : "=r"(state->primask) :: "memory");
	state->basepri = fiber_port_basepri_read();
	fiber_portASM volatile("mrs %0, faultmask" : "=r"(state->faultmask) :: "memory");
	fiber_portASM volatile("mrs %0, psplim" : "=r"(state->psplim) :: "memory");
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_first_start_cpu_check(const FiberPortFirstStartCpuState *const before)
{
	FiberPortFirstStartCpuState after;
	fiber_port_first_start_cpu_capture(&after);
	FIBER_REQUIRE(after.ipsr == before->ipsr, 'i');
	FIBER_REQUIRE(after.control == before->control, 'l');
	FIBER_REQUIRE(after.primask == before->primask, 'p');
	FIBER_REQUIRE(after.basepri == before->basepri, 'b');
	FIBER_REQUIRE(after.faultmask == before->faultmask, 'f');
	FIBER_REQUIRE(after.psplim == before->psplim, 'L');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_port_first_start_contains(const uintptr_t begin, const uintptr_t end,
		const uintptr_t address, const uintptr_t bytes)
{
	return end > begin && address >= begin && address <= end && bytes <= end - address;
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_first_start_maps_check(void)
{
	const uintptr_t vector = (uintptr_t)__fiber_c55s_ns_vector_start__;
	const uintptr_t vector_end = (uintptr_t)__fiber_c55s_ns_vector_end__;
	const uintptr_t code = (uintptr_t)__fiber_c55s_ns_start_code_start__;
	const uintptr_t code_end = (uintptr_t)__fiber_c55s_ns_start_code_end__;
	const uintptr_t low = (uintptr_t)__fiber_c55s_ns_msp_stack_start__;
	const uintptr_t high = (uintptr_t)__fiber_c55s_ns_msp_stack_end__;
	FIBER_REQUIRE(vector != 0u && (vector & 127u) == 0u, 'V');
	FIBER_REQUIRE(vector_end > vector && vector_end - vector >= 64u, 'V');
	FIBER_REQUIRE(code_end > code && ((code | code_end) & 1u) == 0u, 'c');
	FIBER_REQUIRE(high > low && ((low | high) & 7u) == 0u, 'M');
	FIBER_REQUIRE(high - low >= FIBER_PORT_CM55_FIRST_START_MSP_RESERVE, 'M');
	FIBER_REQUIRE(high <= code || low >= code_end, 'M');
	FIBER_REQUIRE(high <= vector || low >= vector_end, 'M');
	FIBER_REQUIRE(fiber_port_first_start_contains(code, code_end,
			(uintptr_t)&SVC_Handler & ~(uintptr_t)1u, 2u), 'c');
	FIBER_REQUIRE(fiber_port_first_start_contains(code, code_end,
			(uintptr_t)&fiber_port_start_first_context & ~(uintptr_t)1u, 2u), 'c');
	FIBER_REQUIRE(fiber_port_first_start_contains(code, code_end,
			(uintptr_t)&fiber_port_restore_first_context_from_svc & ~(uintptr_t)1u, 2u), 'c');
	FIBER_REQUIRE(fiber_port_first_start_contains(code, code_end,
			(uintptr_t)&fiber_port_svc_dispatch & ~(uintptr_t)1u, 2u), 'c');
	FIBER_REQUIRE(fiber_port_first_start_contains(code, code_end,
			(uintptr_t)&fiber_port_secure_context_prepare_first_start & ~(uintptr_t)1u, 2u), 'c');
	FIBER_REQUIRE(fiber_port_first_start_contains(code, code_end,
			(uintptr_t)fiber_port_c55s_first_start_svc_return - 2u, 2u), 'c');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_port_first_start_vectors_check(void)
{
	const uintptr_t vector = (uintptr_t)__fiber_c55s_ns_vector_start__;
	FIBER_REQUIRE(*(const volatile uint32_t *)0xE000ED08u == vector, 'V');
	const uint32_t *const words = (const uint32_t *)vector;
	FIBER_REQUIRE(words[11] == ((uint32_t)(uintptr_t)&SVC_Handler | 1u), 'V');
	const uintptr_t top = words[0];
	const uintptr_t low = (uintptr_t)__fiber_c55s_ns_msp_stack_start__;
	const uintptr_t high = (uintptr_t)__fiber_c55s_ns_msp_stack_end__;
	FIBER_REQUIRE((top & 7u) == 0u && top <= high && top >= low, 'M');
	FIBER_REQUIRE(top - low >= FIBER_PORT_CM55_FIRST_START_MSP_RESERVE, 'M');
	return top;
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_first_start_context_check(FiberContext *const ctx,
		const FiberPortFirstStartCpuState *const cpu)
{
	const uintptr_t begin = (uintptr_t)ctx;
	FIBER_REQUIRE(begin != 0u && (begin & (_Alignof(FiberContext) - 1u)) == 0u, 'C');
	FIBER_REQUIRE(begin <= UINTPTR_MAX - sizeof(*ctx), 'O');
	const uintptr_t end = begin + sizeof(*ctx);
	const uintptr_t low = (uintptr_t)__fiber_c55s_ns_msp_stack_start__;
	const uintptr_t high = (uintptr_t)__fiber_c55s_ns_msp_stack_end__;
	FIBER_REQUIRE(end <= low || begin >= high, 'C');
	FIBER_REQUIRE(fiber_addr_plausible_ram(begin, end) != 0, 'C');
	fiber_port_first_start_cpu_check(cpu);
	fiber_port_context_initial_frame_check(ctx);
	fiber_port_first_start_cpu_check(cpu);
	FIBER_REQUIRE((uintptr_t)ctx->boot.end <= low || (uintptr_t)ctx->boot.begin >= high, 'M');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_port_first_start_environment_check(
		const FiberPortFirstStartCpuState *const cpu)
{
	FIBER_REQUIRE(cpu->ipsr == 0u, 'i');
	FIBER_REQUIRE(cpu->control == 0u, 'l');
	FIBER_REQUIRE(cpu->primask == 0u, 'p');
	FIBER_REQUIRE(cpu->basepri == 0u, 'b');
	FIBER_REQUIRE(cpu->faultmask == 0u, 'f');
	fiber_port_first_start_maps_check();
	const uintptr_t top = fiber_port_first_start_vectors_check();
	uintptr_t msp;
	fiber_portASM volatile("mrs %0, msp" : "=r"(msp) :: "memory");
	FIBER_REQUIRE(fiber_port_first_start_contains(
			(uintptr_t)__fiber_c55s_ns_msp_stack_start__,
			(uintptr_t)__fiber_c55s_ns_msp_stack_end__, msp, 0u), 'M');
	FIBER_REQUIRE(msp - (uintptr_t)__fiber_c55s_ns_msp_stack_start__ >= 32u, 'M');
	fiber_port_first_start_cpu_check(cpu);
	return top;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_prepare_start_environment(void)
{
	FiberPortFirstStartCpuState cpu;
	fiber_port_first_start_cpu_capture(&cpu);
	FIBER_REQUIRE(fiber_port_start_environment_plan.state == 0u &&
			fiber_port_start_environment_plan.top == 0u &&
			fiber_port_start_environment_plan.first == NULL, 'D');
	FIBER_REQUIRE(fiber_port_first_start_plan.state == 0u, 'D');
	const uintptr_t top = fiber_port_first_start_environment_check(&cpu);
	fiber_port_start_environment_plan.top = top;
	fiber_port_start_environment_plan.state = 1u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_start_environment_plan.state == 1u &&
			fiber_port_start_environment_plan.top == top, 'D');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_first_candidate(FiberContext *const first)
{
	FiberPortFirstStartCpuState cpu;
	fiber_port_first_start_cpu_capture(&cpu);
	FIBER_REQUIRE(cpu.ipsr == 0u && cpu.control == 0u, 'i');
	FIBER_REQUIRE(cpu.primask == 0u, 'p');
	FIBER_REQUIRE(cpu.basepri == FIBER_PORT_SCHEDULER_BASEPRI, 'b');
	FIBER_REQUIRE(cpu.faultmask == 0u, 'f');
	FIBER_REQUIRE(fiber_port_start_environment_plan.state == 1u &&
			fiber_port_start_environment_plan.first == NULL, 'D');
	fiber_port_first_start_context_check(first, &cpu);
	FIBER_REQUIRE(fiber_port_first_start_vectors_check() ==
			fiber_port_start_environment_plan.top, 'V');
	fiber_port_first_start_cpu_check(&cpu);
	fiber_port_start_environment_plan.first = first;
	fiber_port_start_environment_plan.state = 2u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_start_environment_plan.state == 2u &&
			fiber_port_start_environment_plan.first == first, 'D');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_port_prepare_first_start(FiberContext *const first)
{
	FiberPortFirstStartCpuState cpu;
	fiber_port_first_start_cpu_capture(&cpu);
	FIBER_REQUIRE(cpu.ipsr == 0u, 'i');
	FIBER_REQUIRE(cpu.control == 0u, 'l');
	FIBER_REQUIRE(cpu.primask == 0u, 'p');
	FIBER_REQUIRE(cpu.basepri == 0u, 'b');
	FIBER_REQUIRE(cpu.faultmask == 0u, 'f');
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	fiber_port_arm_cm55_secure_context_first_start_component_v1_anchor();
	fiber_port_arm_cm55_secure_context_pendsv_component_v1_anchor();
	FIBER_REQUIRE(fiber_port_first_start_plan.state == 0u, 'D');
	FIBER_REQUIRE(fiber_port_first_start_plan.top == 0u &&
			fiber_port_first_start_plan.first == NULL, 'D');
	const uintptr_t top = fiber_port_first_start_environment_check(&cpu);
	if (fiber_port_start_environment_plan.state != 0u) {
		FIBER_REQUIRE(fiber_port_start_environment_plan.state == 2u &&
				fiber_port_start_environment_plan.first == first &&
				fiber_port_start_environment_plan.top == top, 'D');
	}
	fiber_port_first_start_context_check(first, &cpu);
	FIBER_REQUIRE(fiber_port_first_start_vectors_check() == top, 'V');
	fiber_port_first_start_cpu_check(&cpu);
	fiber_port_first_start_plan.top = FIBER_REWIND_MSP ? top : 0u;
	fiber_port_first_start_plan.first = first;
	fiber_portDATA_SYNC_BARRIER();
	fiber_port_first_start_plan.state = 1u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_first_start_plan.state == 1u &&
			fiber_port_first_start_plan.first == first &&
			fiber_port_first_start_plan.top == (FIBER_REWIND_MSP ? top : 0u), 'D');
	if (fiber_port_start_environment_plan.state != 0u) {
		fiber_port_start_environment_plan.state = 3u;
		fiber_portDATA_SYNC_BARRIER();
		FIBER_REQUIRE(fiber_port_start_environment_plan.state == 3u, 'D');
	}
	return fiber_port_first_start_plan.top;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_first_start(FiberContext *const first)
{
	const uintptr_t top = fiber_port_prepare_first_start(first);
	fiber_port_start_first_context(top);
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_svc_dispatch(uint32_t *const hardware_frame,
		const uint32_t exc_return, FiberContext *const current)
{
	FiberPortFirstStartCpuState cpu;
	fiber_port_first_start_cpu_capture(&cpu);
	FIBER_REQUIRE(cpu.ipsr == 11u, 'i');
	FIBER_REQUIRE(cpu.control == 0u, 'l');
	FIBER_REQUIRE(cpu.primask == 1u, 'p');
	FIBER_REQUIRE(cpu.basepri == 0u, 'b');
	FIBER_REQUIRE(cpu.faultmask == 0u, 'f');
	FIBER_REQUIRE(exc_return == fiber_portSVC_ORIGIN_EXC_RETURN, 'x');
	FIBER_REQUIRE(fiber_port_first_start_plan.state == 1u, 'D');
	FIBER_REQUIRE(current != NULL && current == fiber_port_first_start_plan.first, 'C');
	if (fiber_port_start_environment_plan.state != 0u) {
		FIBER_REQUIRE(fiber_port_start_environment_plan.state == 3u &&
				fiber_port_start_environment_plan.first == current, 'D');
	}
	fiber_port_first_start_maps_check();
	const uintptr_t top = fiber_port_first_start_vectors_check();
	const uintptr_t raw = (uintptr_t)hardware_frame;
	const uintptr_t low = (uintptr_t)__fiber_c55s_ns_msp_stack_start__;
	const uintptr_t high = (uintptr_t)__fiber_c55s_ns_msp_stack_end__;
	/* Physical MSP/C-stack trust is integration-owned. Validate the raw frame
	 * parameter's complete extent before explicitly decoding its words. */
	FIBER_REQUIRE((raw & 7u) == 0u &&
			fiber_port_first_start_contains(low, high, raw, 32u), 'M');
	FIBER_REQUIRE(raw + 32u - low >= FIBER_PORT_CM55_FIRST_START_MSP_RESERVE, 'M');
#if FIBER_REWIND_MSP
	FIBER_REQUIRE(top == fiber_port_first_start_plan.top && raw + 32u == top, 'M');
#else
	FIBER_REQUIRE(fiber_port_first_start_plan.top == 0u, 'M');
	(void)top;
#endif
	const uint32_t xpsr = ((const volatile uint32_t *)hardware_frame)[7];
	FIBER_REQUIRE((xpsr & 0x01000000u) != 0u && (xpsr & 0x3FFu) == 0u, 'X');
	const uintptr_t pc = ((const volatile uint32_t *)hardware_frame)[6];
	FIBER_REQUIRE(pc >= 2u && (pc & 1u) == 0u, 'u');
	FIBER_REQUIRE(pc == (uintptr_t)fiber_port_c55s_first_start_svc_return, 'u');
	FIBER_REQUIRE(fiber_port_first_start_contains(
			(uintptr_t)__fiber_c55s_ns_start_code_start__,
			(uintptr_t)__fiber_c55s_ns_start_code_end__, pc - 2u, 2u), 'u');
	FIBER_REQUIRE(*(const volatile uint16_t *)(pc - 2u) ==
			(0xDF00u | FIBER_SVC_START_NUMBER), 'u');
	fiber_port_first_start_context_check(current, &cpu);
	FIBER_REQUIRE(fiber_port_first_start_vectors_check() == top, 'V');
	fiber_port_first_start_cpu_check(&cpu);
	/* From this point every failure is terminal; neither plan nor Secure state
	 * is rolled back or made retryable after a partial commit. */
	fiber_port_first_start_plan.state = 2u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_first_start_plan.state == 2u, 'D');
	fiber_port_secure_context_prepare_first_start(current);
	FIBER_REQUIRE(fiber_port_first_start_vectors_check() == top, 'V');
	fiber_port_first_start_cpu_check(&cpu);
	fiber_port_restore_first_context_from_svc(current);
}
