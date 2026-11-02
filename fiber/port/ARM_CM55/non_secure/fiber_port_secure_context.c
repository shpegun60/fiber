/* ARM_CM55 selected-port pre-start SecureContext attachment. */

#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "fiber_port_private.h"
#include "fiber_port_secure_context_abi.h"
#include "fiber_port_secure_context_gateway_abi.h"
#include "fiber_port_secure_gateway_abi.h"
#include "../../../fiber_runtime_context_configuration_abi.h"

typedef struct FiberPortAttachmentCpuState {
	uint32_t ipsr;
	uint32_t primask;
	uint32_t basepri;
	uint32_t faultmask;
	uint32_t control;
	uint32_t psplim;
} FiberPortAttachmentCpuState;

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_capture_attachment_cpu_state(
		FiberPortAttachmentCpuState *const state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	fiber_portASM volatile("mrs %0, ipsr" : "=r"(state->ipsr) :: "memory");
	fiber_portASM volatile("mrs %0, primask" : "=r"(state->primask) :: "memory");
	state->basepri = fiber_port_basepri_read();
	fiber_portASM volatile("mrs %0, faultmask" : "=r"(state->faultmask) :: "memory");
	fiber_portASM volatile("mrs %0, control" : "=r"(state->control) :: "memory");
	fiber_portASM volatile("mrs %0, psplim" : "=r"(state->psplim) :: "memory");
	fiber_portCOMPILER_BARRIER();
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_attachment_cpu_state(
		const FiberPortAttachmentCpuState *const before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	FiberPortAttachmentCpuState after;
	fiber_port_capture_attachment_cpu_state(&after);
	FIBER_REQUIRE(after.ipsr == before->ipsr, 'i');
	FIBER_REQUIRE(after.primask == before->primask, 'p');
	FIBER_REQUIRE(after.basepri == before->basepri, 'b');
	FIBER_REQUIRE(after.faultmask == before->faultmask, 'f');
	FIBER_REQUIRE(after.control == before->control, 'l');
	FIBER_REQUIRE(after.psplim == before->psplim, 'L');
	fiber_portCOMPILER_BARRIER();
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_validate_secure_gateway(
		const FiberPortAttachmentCpuState *const cpu_state,
		uint32_t *const max_contexts)
{
	uint32_t value;

	FIBER_REQUIRE(cpu_state != NULL, 'C');
	FIBER_REQUIRE(max_contexts != NULL, 'C');
	value = fiber_secure_gateway_c55s_v1_abi_version();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_ARM_CM55_SECURE_GATEWAY_ABI_VERSION, 'Q');
	value = fiber_secure_gateway_c55s_v1_context_port_id();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_PORT_CONTEXT_ABI_PORT_ID, 'Q');
	value = fiber_secure_gateway_c55s_v1_context_layout_version();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION, 'Q');
	value = fiber_secure_gateway_c55s_v1_context_feature_mask();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_PORT_CONTEXT_ABI_FEATURE_MASK, 'Q');
	value = fiber_secure_context_gateway_c55s_v1_abi_version();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_ABI_VERSION, 'Q');
	value = fiber_secure_context_gateway_c55s_v1_stack_alignment();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT, 'Q');
	*max_contexts = fiber_secure_context_gateway_c55s_v1_max_contexts();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(*max_contexts != 0u, 'Q');
	const uint32_t maximum =
			fiber_secure_context_gateway_c55s_v1_max_stack_bytes();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(maximum >=
			FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT, 'Q');
	FIBER_REQUIRE((maximum &
			(FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT - 1u)) == 0u,
			'Q');
	return maximum;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void fiber_port_secure_context_attach(FiberContext *const ctx,
		const size_t secure_stack_bytes)
{
	/* Handler rejection intentionally precedes the common lifecycle guard so
	 * public panic precedence is deterministic. */
	uint32_t ipsr;
	fiber_portASM volatile("mrs %0, ipsr" : "=r"(ipsr) :: "memory");
	FIBER_REQUIRE(ipsr == 0u, 'i');
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_RETAIN_V1();
	fiber_internal_runtime_require_context_configuration_open(ctx);
	FiberPortAttachmentCpuState cpu_state;
	fiber_port_capture_attachment_cpu_state(&cpu_state);

	const uintptr_t context_begin = (uintptr_t)ctx;
	FIBER_REQUIRE((context_begin &
			((uintptr_t)_Alignof(FiberContext) - 1u)) == 0u, 'A');
	FIBER_REQUIRE(context_begin <= (UINTPTR_MAX - sizeof(*ctx)), 'O');
	FIBER_REQUIRE(fiber_addr_plausible_ram(
			context_begin, context_begin + sizeof(*ctx)) != 0, 'C');
	fiber_port_boot_check(&ctx->boot);
	fiber_port_context_initial_frame_check(ctx);
	FIBER_REQUIRE(ctx->boot.secure_stack_bytes == 0u, 'D');
	fiber_port_validate_attachment_cpu_state(&cpu_state);

	uint32_t max_contexts;
	const uint32_t maximum =
			fiber_port_validate_secure_gateway(&cpu_state, &max_contexts);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	(void)max_contexts;

	FIBER_REQUIRE(secure_stack_bytes <= (size_t)UINT32_MAX, 'O');
	const uint32_t requested = (uint32_t)secure_stack_bytes;
	FIBER_REQUIRE(requested >=
			FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT, 'D');
	FIBER_REQUIRE((requested &
			(FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT - 1u)) == 0u,
			'D');
	FIBER_REQUIRE(requested <= maximum, 'D');

	fiber_port_boot_attach_secure_stack(&ctx->boot, requested);
	fiber_port_context_initial_frame_check(ctx);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
}

/* Private NS state, not common scheduler storage or a Secure pool provider. */
static volatile uint32_t fiber_port_live_secure_context_handle;
/* 0 -> 1 before initialization -> 2 after first load, never reset/retried. */
static volatile uint32_t fiber_port_secure_context_start_state;

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_first_start_snapshot_check(FiberContext *const ctx,
		uint32_t *const saved_sp, const uint32_t boot_hash,
		const uint32_t saved_r9, const uint32_t expected_handle,
		const FiberPortAttachmentCpuState *const cpu_state)
{
	FIBER_REQUIRE(ctx->sp == saved_sp, 'S');
	FIBER_REQUIRE(ctx->boot.hash == boot_hash, 'h');
	if (expected_handle == 0u) {
		fiber_port_context_initial_frame_check(ctx);
	} else {
		fiber_port_context_first_start_frame_check(ctx, expected_handle);
	}
	FIBER_REQUIRE(saved_sp[8] == saved_r9, '9');
	fiber_port_validate_attachment_cpu_state(cpu_state);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_prepare_first_start(FiberContext *const ctx)
{
	FiberPortAttachmentCpuState cpu_state;
	fiber_port_capture_attachment_cpu_state(&cpu_state);
	FIBER_REQUIRE(cpu_state.ipsr == 11u, 'i');
	FIBER_REQUIRE(cpu_state.primask == 1u, 'p');
	FIBER_REQUIRE(cpu_state.basepri == 0u, 'b');
	FIBER_REQUIRE(cpu_state.faultmask == 0u, 'f');
	FIBER_REQUIRE(cpu_state.control == 0u, 'l');
	FIBER_REQUIRE(fiber_port_live_secure_context_handle == 0u, 'D');
	FIBER_REQUIRE(fiber_port_secure_context_start_state == 0u, 'D');
	FIBER_PORT_CONTEXT_COHORT_RETAIN();
	const uintptr_t begin = (uintptr_t)ctx;
	FIBER_REQUIRE(begin != 0u && (begin & (_Alignof(FiberContext) - 1u)) == 0u, 'C');
	FIBER_REQUIRE(begin <= UINTPTR_MAX - sizeof(*ctx), 'O');
	FIBER_REQUIRE(fiber_addr_plausible_ram(begin, begin + sizeof(*ctx)) != 0, 'C');
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	fiber_port_context_initial_frame_check(ctx);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	uint32_t *const saved_sp = ctx->sp;
	const uint32_t saved_r9 = saved_sp[8];
	const uint32_t boot_hash = ctx->boot.hash;
	const uint32_t requested = ctx->boot.secure_stack_bytes;
	uint32_t maximum_contexts;
	const uint32_t maximum_bytes = fiber_port_validate_secure_gateway(
			&cpu_state, &maximum_contexts);
	fiber_port_first_start_snapshot_check(ctx, saved_sp, boot_hash, saved_r9,
			0u, &cpu_state);
	FIBER_REQUIRE(requested <= maximum_bytes, 'D');

	fiber_port_secure_context_start_state = 1u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_secure_context_start_state == 1u, 'D');
	uint32_t result = fiber_secure_context_gateway_c55s_v1_initialize();
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	FIBER_REQUIRE(result == 1u, 'Q');
	fiber_port_first_start_snapshot_check(ctx, saved_sp, boot_hash, saved_r9,
			0u, &cpu_state);
	uint32_t handle = 0u;
	if (requested != 0u) {
		handle = fiber_secure_context_gateway_c55s_v1_allocate(requested, begin);
		fiber_port_validate_attachment_cpu_state(&cpu_state);
		FIBER_REQUIRE(handle != 0u && handle <= maximum_contexts, 'D');
		fiber_port_first_start_snapshot_check(ctx, saved_sp, boot_hash, saved_r9,
				0u, &cpu_state);
		*(volatile uint32_t *)saved_sp = handle;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		FIBER_REQUIRE(*(const volatile uint32_t *)saved_sp == handle, 'D');
	}
	fiber_port_context_first_start_frame_check(ctx, handle);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	result = fiber_secure_context_gateway_c55s_v1_load(handle, begin);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	FIBER_REQUIRE(result == 1u, 'Q');
	fiber_port_context_first_start_frame_check(ctx, handle);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	fiber_port_first_start_snapshot_check(ctx, saved_sp, boot_hash, saved_r9,
			handle, &cpu_state);
	fiber_port_live_secure_context_handle = handle;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_live_secure_context_handle == handle, 'D');
	fiber_port_secure_context_start_state = 2u;
	fiber_portDATA_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_secure_context_start_state == 2u, 'D');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_running_cpu_capture(FiberPortRunningCpuState *const cpu)
{
	fiber_port_running_cpu_capture(cpu);
	FIBER_REQUIRE(cpu->ipsr == 14u, 'i');
	FIBER_REQUIRE(cpu->control == 0u, 'l');
	FIBER_REQUIRE(cpu->primask == 0u, 'p');
	FIBER_REQUIRE(cpu->basepri == 0u, 'b');
	FIBER_REQUIRE(cpu->faultmask == 0u, 'f');
	FIBER_REQUIRE(fiber_port_secure_context_start_state == 2u, 'D');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_saved_snapshot_check(FiberContext *const ctx,
		uint32_t *const sp, const uint32_t hash, const uint32_t exc_return,
		const uint32_t handle, const FiberPortRunningCpuState *const cpu)
{
	FIBER_REQUIRE(fiber_port_context_saved_frame_check(ctx) == exc_return, 'x');
	fiber_port_running_cpu_check(cpu);
	FIBER_REQUIRE(ctx->sp == sp && ctx->boot.hash == hash, 'S');
	FIBER_REQUIRE(*(const volatile uint32_t *)sp == handle, 'D');
	FIBER_REQUIRE(fiber_port_secure_context_start_state == 2u, 'D');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_secure_context_save_current_from_pendsv(
		FiberContext *const current, const uintptr_t psp, const uint32_t exc_return)
{
	FiberPortRunningCpuState cpu;
	fiber_port_secure_context_running_cpu_capture(&cpu);
	fiber_port_context_live_frame_check(current, psp, exc_return);
	fiber_port_running_cpu_check(&cpu);
	uint32_t *const old_sp = current->sp;
	const uint32_t hash = current->boot.hash;
	const uint32_t handle = fiber_port_live_secure_context_handle;
	FIBER_REQUIRE((current->boot.secure_stack_bytes == 0u) == (handle == 0u), 'D');
	FIBER_REQUIRE((exc_return & 0x40u) == 0u || handle != 0u, 'D');
	/* A zero save explicitly verifies that no Secure stack is loaded. */
	const uint32_t result = fiber_secure_context_gateway_c55s_v1_save(
			handle, (uintptr_t)current);
	fiber_port_running_cpu_check(&cpu);
	FIBER_REQUIRE(result == 1u, 'Q');
	fiber_port_context_live_frame_check(current, psp, exc_return);
	fiber_port_running_cpu_check(&cpu);
	FIBER_REQUIRE(current->sp == old_sp && current->boot.hash == hash, 'S');
	FIBER_REQUIRE(fiber_port_live_secure_context_handle == handle &&
			fiber_port_secure_context_start_state == 2u, 'D');
	fiber_port_live_secure_context_handle = 0u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_live_secure_context_handle == 0u, 'D');
	return handle;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_secure_context_prepare_next_from_pendsv(FiberContext *const next)
{
	FiberPortRunningCpuState cpu;
	fiber_port_secure_context_running_cpu_capture(&cpu);
	FIBER_REQUIRE(fiber_port_live_secure_context_handle == 0u, 'D');
	const uint32_t exc_return = fiber_port_context_saved_frame_check(next);
	fiber_port_running_cpu_check(&cpu);
	uint32_t *const sp = next->sp;
	const uint32_t hash = next->boot.hash;
	uint32_t handle = *(const volatile uint32_t *)sp;
	if (next->boot.secure_stack_bytes != 0u && handle == 0u) {
		/* The generic saved checker has already proved a complete cold image,
		 * not merely a zero word in an arbitrary previously running frame. */
		fiber_port_context_initial_frame_check(next);
		fiber_port_running_cpu_check(&cpu);
		const uint32_t r9 = sp[8];
		const uint32_t requested = next->boot.secure_stack_bytes;
		FiberPortAttachmentCpuState query_cpu;
		fiber_port_capture_attachment_cpu_state(&query_cpu);
		uint32_t maximum_contexts;
		const uint32_t maximum_bytes = fiber_port_validate_secure_gateway(
				&query_cpu, &maximum_contexts);
		fiber_port_secure_context_saved_snapshot_check(next, sp, hash,
				exc_return, 0u, &cpu);
		FIBER_REQUIRE(sp[8] == r9 && requested <= maximum_bytes, 'D');
		handle = fiber_secure_context_gateway_c55s_v1_allocate(requested, (uintptr_t)next);
		fiber_port_running_cpu_check(&cpu);
		FIBER_REQUIRE(handle != 0u && handle <= maximum_contexts, 'D');
		fiber_port_secure_context_saved_snapshot_check(next, sp, hash,
				exc_return, 0u, &cpu);
		FIBER_REQUIRE(sp[8] == r9, '9');
		*(volatile uint32_t *)sp = handle;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		FIBER_REQUIRE(*(const volatile uint32_t *)sp == handle, 'D');
		fiber_port_context_first_start_frame_check(next, handle);
		FIBER_REQUIRE(sp[8] == r9, '9');
	}
	fiber_port_secure_context_saved_snapshot_check(next, sp, hash,
			exc_return, handle, &cpu);
	FIBER_REQUIRE((next->boot.secure_stack_bytes == 0u) == (handle == 0u), 'D');
	FIBER_REQUIRE(fiber_port_live_secure_context_handle == 0u, 'D');
	return handle;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_load_next_from_pendsv(FiberContext *const next,
		const uint32_t handle)
{
	FiberPortRunningCpuState cpu;
	fiber_port_secure_context_running_cpu_capture(&cpu);
	FIBER_REQUIRE(fiber_port_live_secure_context_handle == 0u, 'D');
	const uint32_t exc_return = fiber_port_context_saved_frame_check(next);
	fiber_port_running_cpu_check(&cpu);
	FIBER_REQUIRE(cpu.psplim == next->boot.stack_base, 'L');
	FIBER_REQUIRE((next->boot.secure_stack_bytes == 0u) == (handle == 0u), 'D');
	uint32_t *const sp = next->sp;
	const uint32_t hash = next->boot.hash;
	FIBER_REQUIRE(*(const volatile uint32_t *)sp == handle, 'D');
	/* Load zero too: the paired gateway must prove empty Secure PSP/PSPLIM. */
	const uint32_t result = fiber_secure_context_gateway_c55s_v1_load(
			handle, (uintptr_t)next);
	fiber_port_running_cpu_check(&cpu);
	FIBER_REQUIRE(result == 1u, 'Q');
	fiber_port_secure_context_saved_snapshot_check(next, sp, hash,
			exc_return, handle, &cpu);
	FIBER_REQUIRE(fiber_port_live_secure_context_handle == 0u, 'D');
	fiber_port_live_secure_context_handle = handle;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(fiber_port_live_secure_context_handle == handle, 'D');
}
