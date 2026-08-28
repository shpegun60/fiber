/* ARM_CM33 selected-port pre-start SecureContext attachment. */

#include "fiber_port_private.h"
#include "fiber_port_secure_context_abi.h"
#include "fiber_port_secure_context_gateway_abi.h"
#include "fiber_port_secure_gateway_abi.h"
#include "../../../fiber_runtime_context_configuration_abi.h"

/* Naked handler references are opaque to the LTO archive scanner.  The
 * always-linked mandatory port object retains this symbol so this complete
 * attachment object is extracted before LTO partitions the handler code. */
const unsigned char
fiber_port_arm_cm33_secure_context_attachment_bundle_v1_anchor
		__attribute__((used)) = 1u;

typedef struct FiberPortAttachmentCpuState {
	uint32_t ipsr;
	uint32_t primask;
	uint32_t basepri;
	uint32_t faultmask;
	uint32_t control;
	uint32_t psplim;
} FiberPortAttachmentCpuState;

/* FreeRTOS calls this xSecureContext. Fiber keeps the same one-live-context
 * state in the selected port, never in common runtime or public storage. */
static volatile uint32_t fiber_port_current_secure_context_handle;

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_capture_attachment_cpu_state(
		FiberPortAttachmentCpuState *const state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	state->ipsr = __get_IPSR();
	state->primask = __get_PRIMASK();
	state->basepri = fiber_port_basepri_read();
	state->faultmask = __get_FAULTMASK();
	state->control = __get_CONTROL();
	state->psplim = __get_PSPLIM();
	fiber_portCOMPILER_BARRIER();
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_attachment_cpu_state(
		const FiberPortAttachmentCpuState *const before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(__get_IPSR() == before->ipsr, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 'f');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
	FIBER_REQUIRE(__get_PSPLIM() == before->psplim, 'L');
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
	value = fiber_secure_gateway_v1_abi_version();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_ARM_CM33_SECURE_GATEWAY_ABI_VERSION, 'Q');
	value = fiber_secure_gateway_v1_context_port_id();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_PORT_CONTEXT_ABI_PORT_ID, 'Q');
	value = fiber_secure_gateway_v1_context_layout_version();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION, 'Q');
	value = fiber_secure_gateway_v1_context_feature_mask();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_PORT_CONTEXT_ABI_FEATURE_MASK, 'Q');
	value = fiber_secure_context_gateway_v1_abi_version();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_ABI_VERSION, 'Q');
	value = fiber_secure_context_gateway_v1_stack_alignment();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(value ==
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT, 'Q');
	*max_contexts = fiber_secure_context_gateway_v1_max_contexts();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(*max_contexts != 0u, 'Q');
	const uint32_t maximum =
			fiber_secure_context_gateway_v1_max_stack_bytes();
	fiber_port_validate_attachment_cpu_state(cpu_state);
	FIBER_REQUIRE(maximum >=
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT, 'Q');
	FIBER_REQUIRE((maximum &
			(FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT - 1u)) == 0u,
			'Q');
	return maximum;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void fiber_port_secure_context_attach(FiberContext *const ctx,
		const size_t secure_stack_bytes)
{
	/* Handler rejection intentionally precedes the common lifecycle guard so
	 * public panic precedence is deterministic. */
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
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
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT, 'D');
	FIBER_REQUIRE((requested &
			(FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT - 1u)) == 0u,
			'D');
	FIBER_REQUIRE(requested <= maximum, 'D');

	fiber_port_boot_attach_secure_stack(&ctx->boot, requested);
	fiber_port_context_initial_frame_check(ctx);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_prepare_first_start(FiberContext *const ctx)
{
	FIBER_REQUIRE(__get_IPSR() ==
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER, 'j');
	FIBER_REQUIRE(__get_PRIMASK() == 1u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 0u, 'l');
	FIBER_REQUIRE(ctx != NULL, 'C');
	FIBER_REQUIRE(fiber_port_current_secure_context_handle ==
			fiber_portNO_SECURE_CONTEXT, 'D');
	FiberPortAttachmentCpuState cpu_state;
	fiber_port_capture_attachment_cpu_state(&cpu_state);

	const uintptr_t context_begin = (uintptr_t)ctx;
	FIBER_REQUIRE((context_begin &
			((uintptr_t)_Alignof(FiberContext) - 1u)) == 0u, 'A');
	FIBER_REQUIRE(context_begin <= (UINTPTR_MAX - sizeof(*ctx)), 'O');
	FIBER_REQUIRE(fiber_addr_plausible_ram(
			context_begin, context_begin + sizeof(*ctx)) != 0, 'C');
	fiber_port_context_initial_frame_check(ctx);
	fiber_port_validate_attachment_cpu_state(&cpu_state);

	uint32_t max_contexts;
	const uint32_t max_stack_bytes =
			fiber_port_validate_secure_gateway(&cpu_state, &max_contexts);
	fiber_port_validate_attachment_cpu_state(&cpu_state);

	const uint32_t initialized =
			fiber_secure_context_gateway_v1_initialize();
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	FIBER_REQUIRE(initialized == 1u, 'Q');

	uint32_t handle = fiber_portNO_SECURE_CONTEXT;
	if (ctx->boot.secure_stack_bytes != 0u) {
		FIBER_REQUIRE(ctx->boot.secure_stack_bytes <= max_stack_bytes, 'D');
		handle = fiber_secure_context_gateway_v1_allocate(
				ctx->boot.secure_stack_bytes, context_begin);
		fiber_port_validate_attachment_cpu_state(&cpu_state);
		FIBER_REQUIRE((handle != fiber_portNO_SECURE_CONTEXT) &&
				(handle <= max_contexts), 'D');
		ctx->sp[0] = handle;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}

	const uint32_t loaded = fiber_secure_context_gateway_v1_load(
			handle, context_begin);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	FIBER_REQUIRE(loaded == 1u, 'D');
	fiber_port_context_first_start_frame_check(ctx);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	fiber_port_current_secure_context_handle = handle;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(fiber_port_current_secure_context_handle == handle, 'D');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_secure_context_save_current_from_pendsv(
		FiberContext *const current)
{
	FIBER_REQUIRE(__get_IPSR() ==
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER, 'j');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');
	FIBER_REQUIRE(current != NULL, 'C');
	const uint32_t handle = fiber_port_current_secure_context_handle;
	if (current->boot.secure_stack_bytes == 0u) {
		FIBER_REQUIRE(handle == fiber_portNO_SECURE_CONTEXT, 'D');
	} else {
		FIBER_REQUIRE(handle != fiber_portNO_SECURE_CONTEXT, 'D');
	}

	FiberPortAttachmentCpuState cpu_state;
	fiber_port_capture_attachment_cpu_state(&cpu_state);
	const uint32_t saved = fiber_secure_context_gateway_v1_save(
			handle, (uintptr_t)current);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	FIBER_REQUIRE(saved == 1u, 'D');

	fiber_port_current_secure_context_handle = fiber_portNO_SECURE_CONTEXT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(fiber_port_current_secure_context_handle ==
			fiber_portNO_SECURE_CONTEXT, 'D');
	return handle;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_secure_context_prepare_next_from_pendsv(
		FiberContext *const next)
{
	FIBER_REQUIRE(__get_IPSR() ==
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER, 'j');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');
	FIBER_REQUIRE(next != NULL, 'C');
	FIBER_REQUIRE(next->sp != NULL, 'P');
	FIBER_REQUIRE(fiber_port_current_secure_context_handle ==
			fiber_portNO_SECURE_CONTEXT, 'D');

	FiberPortAttachmentCpuState cpu_state;
	fiber_port_capture_attachment_cpu_state(&cpu_state);
	uint32_t handle = next->sp[0];
	if ((next->boot.secure_stack_bytes != 0u) &&
			(handle == fiber_portNO_SECURE_CONTEXT)) {
		handle = fiber_secure_context_gateway_v1_allocate(
				next->boot.secure_stack_bytes, (uintptr_t)next);
		fiber_port_validate_attachment_cpu_state(&cpu_state);
		const uint32_t max_contexts =
				fiber_secure_context_gateway_v1_max_contexts();
		fiber_port_validate_attachment_cpu_state(&cpu_state);
		FIBER_REQUIRE(max_contexts != 0u, 'Q');
		FIBER_REQUIRE((handle != fiber_portNO_SECURE_CONTEXT) &&
				(handle <= max_contexts), 'D');
		next->sp[0] = handle;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
	}
	fiber_port_context_validate_loaded_secure_handle(next);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	return handle;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_load_next_from_pendsv(
		FiberContext *const next,
		const uint32_t handle)
{
	FIBER_REQUIRE(__get_IPSR() ==
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER, 'j');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');
	FIBER_REQUIRE(next != NULL, 'C');
	FIBER_REQUIRE(next->sp != NULL, 'P');
	FIBER_REQUIRE(__get_PSPLIM() == (uint32_t)next->boot.stack_base, 'L');
	FIBER_REQUIRE(next->sp[0] == handle, 'D');
	FIBER_REQUIRE(fiber_port_current_secure_context_handle ==
			fiber_portNO_SECURE_CONTEXT, 'D');
	fiber_port_context_validate_loaded_secure_handle(next);

	FiberPortAttachmentCpuState cpu_state;
	fiber_port_capture_attachment_cpu_state(&cpu_state);
	const uint32_t loaded = fiber_secure_context_gateway_v1_load(
			handle, (uintptr_t)next);
	fiber_port_validate_attachment_cpu_state(&cpu_state);
	FIBER_REQUIRE(loaded == 1u, 'D');

	fiber_port_current_secure_context_handle = handle;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(fiber_port_current_secure_context_handle == handle, 'D');
}
