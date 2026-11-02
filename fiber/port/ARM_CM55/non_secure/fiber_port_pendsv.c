/* C55S staged scalar running transfer. No generic runtime/provider is defined. */
#include "fiber_portmacro.h"
#include "fiber_port_private.h"

typedef struct FiberPortPendSvPlan {
	FiberContext *current;
	FiberContext *next;
	uint32_t *sp;
	uint32_t exc_return;
	uint32_t handle;
	uint32_t hash;
	uint32_t psp;
	uint32_t state;
} FiberPortPendSvPlan;

/* Serialized single-core PendSV: idle -> save -> select -> prepare -> load
 * -> idle. A partial failure is terminal; no rollback clears this plan. */
static volatile FiberPortPendSvPlan fiber_port_pendsv_plan;
FIBER_STATIC_ASSERT(sizeof(FiberPortPendSvPlan) == 32u,
		"[fiber]: C55S private running plan geometry changed");

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_arm_cm55_secure_context_pendsv_component_v1_anchor(void)
{
	FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_running_cpu_capture(FiberPortRunningCpuState *const state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	fiber_portASM volatile("mrs %0, ipsr" : "=r"(state->ipsr) :: "memory");
	fiber_portASM volatile("mrs %0, control" : "=r"(state->control) :: "memory");
	fiber_portASM volatile("mrs %0, primask" : "=r"(state->primask) :: "memory");
	state->basepri = fiber_port_basepri_read();
	fiber_portASM volatile("mrs %0, faultmask" : "=r"(state->faultmask) :: "memory");
	fiber_portASM volatile("mrs %0, psplim" : "=r"(state->psplim) :: "memory");
	fiber_portASM volatile("mrs %0, psp" : "=r"(state->psp) :: "memory");
	fiber_portCOMPILER_BARRIER();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_running_cpu_check(const FiberPortRunningCpuState *const before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	FiberPortRunningCpuState after;
	fiber_port_running_cpu_capture(&after);
	FIBER_REQUIRE(after.ipsr == before->ipsr, 'i');
	FIBER_REQUIRE(after.control == before->control, 'l');
	FIBER_REQUIRE(after.primask == before->primask, 'p');
	FIBER_REQUIRE(after.basepri == before->basepri, 'b');
	FIBER_REQUIRE(after.faultmask == before->faultmask, 'f');
	FIBER_REQUIRE(after.psplim == before->psplim, 'L');
	FIBER_REQUIRE(after.psp == before->psp, 'P');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_pendsv_cpu_capture(FiberPortRunningCpuState *const cpu,
		const uint32_t basepri)
{
	fiber_port_running_cpu_capture(cpu);
	FIBER_REQUIRE(cpu->ipsr == 14u, 'i');
	/* Actual exception entry cleared banked NS SPSEL; do not repair it. */
	FIBER_REQUIRE(cpu->control == 0u, 'l');
	FIBER_REQUIRE(cpu->primask == 0u, 'p');
	FIBER_REQUIRE(cpu->basepri == basepri, 'b');
	FIBER_REQUIRE(cpu->faultmask == 0u, 'f');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_pendsv_environment_check(void)
{
	const uintptr_t vector = (uintptr_t)__fiber_c55s_ns_vector_start__;
	const uintptr_t end = (uintptr_t)__fiber_c55s_ns_vector_end__;
	const uintptr_t code = (uintptr_t)__fiber_c55s_ns_start_code_start__;
	const uintptr_t code_end = (uintptr_t)__fiber_c55s_ns_start_code_end__;
	const uintptr_t handler = (uintptr_t)&PendSV_Handler & ~(uintptr_t)1u;
	FIBER_REQUIRE(vector != 0u && (vector & 127u) == 0u &&
			end > vector && end - vector >= 64u, 'V');
	FIBER_REQUIRE(code_end > code && handler >= code && handler <= code_end &&
			code_end - handler >= 2u, 'c');
	FIBER_REQUIRE(*(const volatile uint32_t *)0xE000ED08u == vector, 'V');
	FIBER_REQUIRE(((const volatile uint32_t *)vector)[14] ==
			((uint32_t)(uintptr_t)&PendSV_Handler | 1u), 'V');
	FIBER_REQUIRE(*(const volatile uint8_t *)0xE000ED22u ==
			(uint8_t)(0xFFu << (8u - __NVIC_PRIO_BITS)), 'b');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_pendsv_current_image_check(FiberContext *const current,
		const FiberPortRunningCpuState *const cpu)
{
	FIBER_REQUIRE(current == fiber_port_pendsv_plan.current, 'C');
	FIBER_REQUIRE(fiber_port_context_saved_frame_check(current) ==
			fiber_port_pendsv_plan.exc_return, 'x');
	fiber_port_running_cpu_check(cpu);
	FIBER_REQUIRE(current->sp == fiber_port_pendsv_plan.sp &&
			current->boot.hash == fiber_port_pendsv_plan.hash, 'S');
	FIBER_REQUIRE(*(const volatile uint32_t *)current->sp ==
			fiber_port_pendsv_plan.handle, 'D');
	FIBER_REQUIRE(cpu->psplim == current->boot.stack_base &&
			cpu->psp == fiber_port_pendsv_plan.psp, 'L');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_pendsv_contexts_disjoint_check(const FiberContext *const current,
		const FiberContext *const next)
{
	if (current == next) {
		return;
	}
	const uintptr_t c = (uintptr_t)current;
	const uintptr_t n = (uintptr_t)next;
	const uintptr_t cb = (uintptr_t)current->boot.begin;
	const uintptr_t ce = (uintptr_t)current->boot.end;
	const uintptr_t nb = (uintptr_t)next->boot.begin;
	const uintptr_t ne = (uintptr_t)next->boot.end;
	/* Both complete context extents were checked before these additions. */
	FIBER_REQUIRE(c + sizeof(*current) <= n || n + sizeof(*next) <= c, 'C');
	FIBER_REQUIRE(ce <= nb || ne <= cb, 'C');
	FIBER_REQUIRE(c + sizeof(*current) <= nb || c >= ne, 'C');
	FIBER_REQUIRE(n + sizeof(*next) <= cb || n >= ce, 'C');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_pendsv_prepare_save(FiberContext *const current,
		const uintptr_t psp, const uint32_t exc_return)
{
	FiberPortRunningCpuState cpu;
	fiber_port_pendsv_cpu_capture(&cpu, 0u);
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 0u, 'D');
	FIBER_REQUIRE(cpu.psp == psp, 'P');
	fiber_port_pendsv_environment_check();
	fiber_port_context_live_frame_check(current, psp, exc_return);
	fiber_port_running_cpu_check(&cpu);
	uint32_t *const old_sp = current->sp;
	const uint32_t hash = current->boot.hash;
	const uintptr_t bytes = (exc_return & 0x40u) != 0u ?
			FIBER_PORT_CM55_SECURE_HEADER_BYTES : FIBER_PORT_SOFTWARE_FRAME_BYTES;
	fiber_port_pendsv_plan.current = current;
	fiber_port_pendsv_plan.next = NULL;
	fiber_port_pendsv_plan.sp = (uint32_t *)(psp - bytes);
	fiber_port_pendsv_plan.exc_return = exc_return;
	fiber_port_pendsv_plan.hash = hash;
	fiber_port_pendsv_plan.psp = (uint32_t)psp;
	fiber_port_pendsv_plan.state = 1u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 1u, 'D');
	const uint32_t handle = fiber_port_secure_context_save_current_from_pendsv(
			current, psp, exc_return);
	fiber_port_running_cpu_check(&cpu);
	FIBER_REQUIRE(current->sp == old_sp && current->boot.hash == hash, 'S');
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 1u &&
			fiber_port_pendsv_plan.current == current &&
			fiber_port_pendsv_plan.sp == (uint32_t *)(psp - bytes) &&
			fiber_port_pendsv_plan.exc_return == exc_return &&
			fiber_port_pendsv_plan.hash == hash && fiber_port_pendsv_plan.psp == psp, 'D');
	fiber_port_pendsv_plan.handle = handle;
	fiber_port_pendsv_plan.state = 2u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 2u &&
			fiber_port_pendsv_plan.handle == handle, 'D');
	return handle;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *const current)
{
	FiberPortRunningCpuState cpu;
	fiber_port_pendsv_cpu_capture(&cpu, FIBER_PORT_SCHEDULER_BASEPRI);
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 2u, 'D');
	fiber_port_pendsv_current_image_check(current, &cpu);
	FiberContext *const next = fiber_internal_runtime_select_scheduler_candidate(current);
	fiber_port_running_cpu_check(&cpu);
	fiber_port_pendsv_current_image_check(current, &cpu);
	FIBER_REQUIRE(next != NULL, 'C');
	(void)fiber_port_context_saved_frame_check(next);
	fiber_port_running_cpu_check(&cpu);
	fiber_port_pendsv_contexts_disjoint_check(current, next);
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 2u, 'D');
	fiber_port_pendsv_plan.next = next;
	fiber_port_pendsv_plan.state = 3u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 3u &&
			fiber_port_pendsv_plan.next == next, 'D');
	return next;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_pendsv_prepare_next(FiberContext *const next)
{
	FiberPortRunningCpuState cpu;
	fiber_port_pendsv_cpu_capture(&cpu, 0u);
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 3u &&
			fiber_port_pendsv_plan.next == next, 'D');
	FIBER_REQUIRE(cpu.psp == fiber_port_pendsv_plan.psp, 'P');
	const uint32_t exc_return = fiber_port_context_saved_frame_check(next);
	fiber_port_running_cpu_check(&cpu);
	uint32_t *const sp = next->sp;
	const uint32_t hash = next->boot.hash;
	const uint32_t handle = fiber_port_secure_context_prepare_next_from_pendsv(next);
	FIBER_REQUIRE(fiber_port_context_saved_frame_check(next) == exc_return, 'x');
	fiber_port_running_cpu_check(&cpu);
	FIBER_REQUIRE(next->sp == sp && next->boot.hash == hash, 'S');
	FIBER_REQUIRE(*(const volatile uint32_t *)sp == handle, 'D');
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 3u &&
			fiber_port_pendsv_plan.next == next, 'D');
	fiber_port_pendsv_plan.sp = sp;
	fiber_port_pendsv_plan.exc_return = exc_return;
	fiber_port_pendsv_plan.handle = handle;
	fiber_port_pendsv_plan.hash = hash;
	fiber_port_pendsv_plan.state = 4u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 4u, 'D');
	return handle;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_pendsv_load_next(FiberContext *const next, const uint32_t handle)
{
	FiberPortRunningCpuState cpu;
	fiber_port_pendsv_cpu_capture(&cpu, 0u);
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 4u &&
			fiber_port_pendsv_plan.next == next && fiber_port_pendsv_plan.handle == handle, 'D');
	FIBER_REQUIRE(cpu.psp == fiber_port_pendsv_plan.psp, 'P');
	FIBER_REQUIRE(fiber_port_context_saved_frame_check(next) ==
			fiber_port_pendsv_plan.exc_return, 'x');
	fiber_port_running_cpu_check(&cpu);
	FIBER_REQUIRE(next->sp == fiber_port_pendsv_plan.sp &&
			next->boot.hash == fiber_port_pendsv_plan.hash, 'S');
	FIBER_REQUIRE(cpu.psplim == next->boot.stack_base, 'L');
	fiber_port_secure_context_load_next_from_pendsv(next, handle);
	fiber_port_running_cpu_check(&cpu);
	/* Common owns the slot. Publication is a reverse call, never a C lvalue. */
	fiber_internal_runtime_publish_current_context(next);
	fiber_port_running_cpu_check(&cpu);
	FIBER_REQUIRE(fiber_port_context_saved_frame_check(next) ==
			fiber_port_pendsv_plan.exc_return, 'x');
	fiber_port_running_cpu_check(&cpu);
	FIBER_REQUIRE(next->sp == fiber_port_pendsv_plan.sp &&
			next->boot.hash == fiber_port_pendsv_plan.hash &&
			*(const volatile uint32_t *)next->sp == handle, 'S');
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 4u &&
			fiber_port_pendsv_plan.next == next, 'D');
	fiber_port_pendsv_plan.state = 0u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_pendsv_plan.state == 0u, 'D');
}

FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
void PendSV_Handler(void)
{
	fiber_portASM volatile(
		".syntax unified\n"
		"mrs r3, ipsr\n"
		"cmp r3, #14\n"
		"bne 9f\n"
		"mvn r3, #67\n" /* BC or FC, differing only in S bit 6. */
		"eor r3, r3, lr\n"
		"bic r3, r3, #0x40\n"
		"cmp r3, #0\n"
		"bne 8f\n"
		"mrs r3, control\n"
		"cmp r3, #0\n"
		"bne 9f\n"
		"mrs r3, primask\n"
		"cmp r3, #0\n"
		"bne 9f\n"
		"mrs r3, basepri\n"
		"cmp r3, #0\n"
		"bne 9f\n"
		"mrs r3, faultmask\n"
		"cmp r3, #0\n"
		"bne 9f\n"
		"mrs r0, psp\n"
		"tst r0, #7\n"
		"bne 8f\n"
		/* Assembly-only load of common-owned current storage. */
		"ldr r1, =fiber_internal_runtime_current_context_slot\n"
		"ldr r1, [r1]\n"
		"cmp r1, #0\n"
		"beq 7f\n"
		"mov r2, lr\n"
		"push {r0-r2, lr}\n"
		"mov r3, r0\n"
		"mov r0, r1\n"
		"mov r1, r3\n"
		"bl fiber_port_pendsv_prepare_save\n"
		"mov r3, r0\n"
		"pop {r0-r2, lr}\n"
		/* Secure save/unload has succeeded before either NS image store. */
		"tst lr, #0x40\n"
		"bne 1f\n"
		"stmdb r0!, {r4-r11}\n"
		"1:\n"
		"mov r2, r3\n"
		"mrs r3, psplim\n"
		"stmdb r0!, {r2, r3, lr}\n"
		"str r0, [r1]\n"
		"movs r0, %c[priority]\n"
		"msr basepri, r0\n"
		"dsb\n"
		"isb\n"
		"mov r0, r1\n"
		"bl fiber_port_scheduler_pick_next_from_pendsv\n"
		"movs r1, #0\n"
		"msr basepri, r1\n"
		"isb\n"
		"mrs r1, basepri\n"
		"cmp r1, #0\n"
		"bne 9f\n"
		"push {r0, lr}\n"
		"bl fiber_port_pendsv_prepare_next\n"
		"mov r3, r0\n"
		"pop {r1, lr}\n"
		"ldr r2, [r1]\n"
		"ldr r0, [r2]\n"
		"cmp r0, r3\n"
		"bne 7f\n"
		"ldmia r2!, {r0, r3, lr}\n"
		"mvn r12, #67\n"
		"eor r12, r12, lr\n"
		"bic r12, r12, #0x40\n"
		"cmp r12, #0\n"
		"bne 8f\n"
		"msr psplim, r3\n"
		"dsb\n"
		"isb\n"
		"mrs r12, psplim\n"
		"cmp r12, r3\n"
		"bne 6f\n"
		"push {r1-r3, lr}\n"
		"mov r12, r0\n"
		"mov r0, r1\n"
		"mov r1, r12\n"
		"bl fiber_port_pendsv_load_next\n"
		"pop {r1-r3, lr}\n"
		"mov r0, r2\n"
		"tst lr, #0x40\n"
		"bne 2f\n"
		"add r0, r0, #32\n"
		"2:\n"
		"msr psp, r0\n"
		"isb\n"
		"mrs r12, psp\n"
		"cmp r12, r0\n"
		"bne 8f\n"
		"mrs r0, ipsr\n"
		"cmp r0, #14\n"
		"bne 9f\n"
		"mrs r0, control\n"
		"cmp r0, #0\n"
		"bne 9f\n"
		"mrs r0, primask\n"
		"cmp r0, #0\n"
		"bne 9f\n"
		"mrs r0, basepri\n"
		"cmp r0, #0\n"
		"bne 9f\n"
		"mrs r0, faultmask\n"
		"cmp r0, #0\n"
		"bne 9f\n"
		/* Successful NS resume has no C call after its final GPR load.
		 * Secure resume skips the NS GPR area entirely; hardware owns it. */
		"tst lr, #0x40\n"
		"bne 3f\n"
		"ldmia r2!, {r4-r11}\n"
		"3:\n"
		"dsb\n"
		"isb\n"
		"bx lr\n"
		"6:\n"
		"movs r0, #76\n"
		"b 5f\n"
		"7:\n"
		"movs r0, #68\n"
		"b 5f\n"
		"8:\n"
		"movs r0, #120\n"
		"b 5f\n"
		"9:\n"
		"movs r0, #108\n"
		"5:\n"
		"bl fiber_panic\n"
		"b .\n"
		".ltorg\n"
		:
		: [priority] "i" (FIBER_PORT_SCHEDULER_BASEPRI)
		: "memory", "cc");
}
