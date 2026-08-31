/* Immutable C55S SecureContext capacity gateway. */

#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_context_pool.h"

_Static_assert(FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT ==
		FIBER_ARM_CM55_SECURE_CONTEXT_STACK_ALIGNMENT_BYTES,
		"[fiber]: ARM_CM55 SecureContext capacity alignment mismatch");

uint32_t fiber_secure_context_gateway_c55s_v1_abi_version(void)
{
	return FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_ABI_VERSION;
}

uint32_t fiber_secure_context_gateway_c55s_v1_stack_alignment(void)
{
	return FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT;
}

uint32_t fiber_secure_context_gateway_c55s_v1_max_stack_bytes(void)
{
	return FIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES;
}

uint32_t fiber_secure_context_gateway_c55s_v1_max_contexts(void)
{
	return FIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT;
}
