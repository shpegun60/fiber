/* ARM_CM33F selected-port pre-start SecureContext attachment. */

#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
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
	value = fiber_secure_gateway_c3fs_v1_abi_version();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_ARM_CM33F_SECURE_GATEWAY_ABI_VERSION, 'Q');
	value = fiber_secure_gateway_c3fs_v1_context_port_id();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_PORT_CONTEXT_ABI_PORT_ID, 'Q');
	value = fiber_secure_gateway_c3fs_v1_context_layout_version();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION, 'Q');
	value = fiber_secure_gateway_c3fs_v1_context_feature_mask();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_PORT_CONTEXT_ABI_FEATURE_MASK, 'Q');
	value = fiber_secure_context_gateway_c3fs_v1_abi_version();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_ABI_VERSION, 'Q');
	value = fiber_secure_context_gateway_c3fs_v1_stack_alignment();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT, 'Q');
	*max_contexts = fiber_secure_context_gateway_c3fs_v1_max_contexts();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(*max_contexts != 0u, 'Q');
	const uint32_t maximum =
			fiber_secure_context_gateway_c3fs_v1_max_stack_bytes();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(maximum >=
			FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT, 'Q');
	FIBER_REQUIRE((maximum &
			(FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT - 1u)) == 0u,
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
			FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT, 'D');
	FIBER_REQUIRE((requested &
			(FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT - 1u)) == 0u,
			'D');
	FIBER_REQUIRE(requested <= maximum, 'D');

	fiber_port_boot_attach_secure_stack(&ctx->boot, requested);
	fiber_port_context_initial_frame_check(ctx);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
}
