/* Stateful ARM_CM33 SecureContext NSC gateway backed by the private pool. */

#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_context_pool.h"

#define fiber_secure_contextSCB_AIRCR \
	(*((volatile uint32_t *)0xE000ED0Cu))
#define fiber_secure_contextAIRCR_VECTKEY_MASK (0xFFFFu << 16u)
#define fiber_secure_contextAIRCR_VECTKEY_WRITE (0x05FAu << 16u)
#define fiber_secure_contextAIRCR_PRIS_MASK (1u << 14u)
#define fiber_secure_contextGATEWAY_INITIALIZING 0x53434742u
#define fiber_secure_contextGATEWAY_READY 0x53434752u

static volatile uint32_t fiber_secure_context_gateway_state;

static uint32_t fiber_secure_context_gateway_is_runtime_exception(void)
{
	const uint32_t exception_number = __get_IPSR();

	return ((exception_number ==
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER) ||
			(exception_number ==
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER)) ?
			1u : 0u;
}

_Static_assert(FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT ==
		FIBER_ARM_CM33_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES,
		"[fiber]: ARM_CM33 SecureContext gateway/pool alignment mismatch");

uint32_t fiber_secure_context_gateway_v1_abi_version(void)
{
	return FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_ABI_VERSION;
}

uint32_t fiber_secure_context_gateway_v1_stack_alignment(void)
{
	return FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT;
}

uint32_t fiber_secure_context_gateway_v1_max_stack_bytes(void)
{
	return FIBER_ARM_CM33_SECURE_CONTEXT_MAX_STACK_BYTES;
}

uint32_t fiber_secure_context_gateway_v1_max_contexts(void)
{
	return FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT;
}

uint32_t fiber_secure_context_gateway_v1_initialize(void)
{
	uint32_t aircr_before;
	uint32_t aircr_expected;
	uint32_t aircr_after;

	/* FreeRTOS accepts any Handler mode. The Fiber first-start contract owns
	 * one exact Non-secure SVCall and rejects runtime reinitialization. Enter
	 * an irreversible intermediate state before the first destructive write,
	 * so a partial failure cannot retry initialization. */
	if ((__get_IPSR() !=
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER) ||
			(fiber_secure_context_gateway_state != 0u)) {
		return 0u;
	}
	fiber_secure_context_gateway_state =
			fiber_secure_contextGATEWAY_INITIALIZING;
	__DSB();
	__ISB();
	if (fiber_secure_context_gateway_state !=
			fiber_secure_contextGATEWAY_INITIALIZING) {
		return 0u;
	}

	/* Match SecureInit_DePrioritizeNSExceptions(), then prove that only PRIS
	 * changed. VECTKEYSTAT is excluded from readback comparison. */
	aircr_before = fiber_secure_contextSCB_AIRCR;
	aircr_expected =
			(aircr_before & ~(fiber_secure_contextAIRCR_VECTKEY_MASK |
				fiber_secure_contextAIRCR_PRIS_MASK)) |
			fiber_secure_contextAIRCR_VECTKEY_WRITE |
			fiber_secure_contextAIRCR_PRIS_MASK;
	fiber_secure_contextSCB_AIRCR = aircr_expected;
	__DSB();
	__ISB();
	aircr_after = fiber_secure_contextSCB_AIRCR;
	if (((aircr_after & fiber_secure_contextAIRCR_PRIS_MASK) == 0u) ||
			((aircr_after & ~fiber_secure_contextAIRCR_VECTKEY_MASK) !=
			 (aircr_expected & ~fiber_secure_contextAIRCR_VECTKEY_MASK))) {
		return 0u;
	}

	/* Match SecureContext_Init(): no Secure Thread stack is active until an
	 * owned context is loaded, and Secure Thread mode is privileged PSP. */
	__set_PSPLIM(0u);
	__set_PSP(0u);
	__DSB();
	__ISB();
	if ((__get_PSPLIM() != 0u) || (__get_PSP() != 0u)) {
		return 0u;
	}

	fiber_secure_context_pool_boot_initialize();

	__set_CONTROL(2u);
	__ISB();
	if ((__get_CONTROL() & 3u) != 2u) {
		return 0u;
	}

	fiber_secure_context_gateway_state = fiber_secure_contextGATEWAY_READY;
	__DSB();
	__ISB();
	return (fiber_secure_context_gateway_state ==
			fiber_secure_contextGATEWAY_READY) ? 1u : 0u;
}

uint32_t fiber_secure_context_gateway_v1_allocate(
		const uint32_t secure_stack_bytes,
		const uintptr_t owner_token)
{
	/* FreeRTOS accepts any Handler mode. Fiber narrows that boundary to exact
	 * Non-secure first-start SVCall or lazy-activation PendSV, a completed
	 * one-shot initialization, and no loaded Secure stack. */
	if ((fiber_secure_context_gateway_is_runtime_exception() == 0u) ||
			(fiber_secure_context_gateway_state !=
				fiber_secure_contextGATEWAY_READY) ||
			(__get_PSPLIM() != 0u) || (__get_PSP() != 0u)) {
		return (uint32_t)FIBER_SECURE_CONTEXT_HANDLE_INVALID;
	}

	return (uint32_t)fiber_secure_context_pool_allocate(
			secure_stack_bytes, owner_token);
}

uint32_t fiber_secure_context_gateway_v1_load(
		const uint32_t handle,
		const uintptr_t owner_token)
{
	FiberSecureContextRecord *record;
	uintptr_t stack_pointer;
	uintptr_t stack_limit;

	if ((fiber_secure_context_gateway_is_runtime_exception() == 0u) ||
			(fiber_secure_context_gateway_state !=
				fiber_secure_contextGATEWAY_READY) ||
			(owner_token == 0u) || (__get_PSPLIM() != 0u) ||
			(__get_PSP() != 0u)) {
		return 0u;
	}

	/* An unattached fiber deliberately carries handle zero. Prove that no
	 * stale Secure Thread stack can be inherited by that fiber. */
	if (handle == (uint32_t)FIBER_SECURE_CONTEXT_HANDLE_INVALID) {
		return 1u;
	}

	record = fiber_secure_context_pool_lookup_owned(
			(FiberSecureContextHandle)handle, owner_token);
	if (record == 0) {
		return 0u;
	}
	stack_pointer = record->current_stack_pointer;
	stack_limit = record->stack_limit;

	/* Keep the exact FreeRTOS load order: PSPLIM before PSP. Readback and
	 * barriers are deliberate Fiber hardening on this one-shot path. */
	__set_PSPLIM((uint32_t)stack_limit);
	__DSB();
	__ISB();
	if (__get_PSPLIM() != (uint32_t)stack_limit) {
		return 0u;
	}
	__set_PSP((uint32_t)stack_pointer);
	__DSB();
	__ISB();
	if ((__get_PSP() != (uint32_t)stack_pointer) ||
			(__get_PSPLIM() != (uint32_t)stack_limit)) {
		return 0u;
	}

	return 1u;
}

uint32_t fiber_secure_context_gateway_v1_save(
		const uint32_t handle,
		const uintptr_t owner_token)
{
	FiberSecureContextRecord *record;
	uintptr_t stack_pointer;

	if ((__get_IPSR() !=
			FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER) ||
			(fiber_secure_context_gateway_state !=
				fiber_secure_contextGATEWAY_READY) ||
			(owner_token == 0u)) {
		return 0u;
	}

	/* An unattached fiber must not have inherited any Secure Thread state. */
	if (handle == (uint32_t)FIBER_SECURE_CONTEXT_HANDLE_INVALID) {
		return ((__get_PSPLIM() == 0u) && (__get_PSP() == 0u)) ? 1u : 0u;
	}

	record = fiber_secure_context_pool_lookup_owned(
			(FiberSecureContextHandle)handle, owner_token);
	if (record == 0) {
		return 0u;
	}
	stack_pointer = (uintptr_t)__get_PSP();
	if ((__get_PSPLIM() != (uint32_t)record->stack_limit) ||
			((stack_pointer &
				(FIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT - 1u)) !=
			 0u) ||
			(stack_pointer < record->stack_limit) ||
			(stack_pointer > record->stack_top)) {
		return 0u;
	}

	/* Match SecureContext_SaveContextAsm(): save PSP, then remove all Secure
	 * Thread stack state before another context can be selected. */
	record->current_stack_pointer = stack_pointer;
	__DSB();
	__ISB();
	if (fiber_secure_context_pool_lookup_owned(
			(FiberSecureContextHandle)handle, owner_token) != record) {
		return 0u;
	}

	__set_PSPLIM(0u);
	__DSB();
	__ISB();
	if (__get_PSPLIM() != 0u) {
		return 0u;
	}
	__set_PSP(0u);
	__DSB();
	__ISB();
	if ((__get_PSP() != 0u) || (__get_PSPLIM() != 0u)) {
		return 0u;
	}

	return 1u;
}
