/*
 * Immutable ARM_CM55 C55S Secure companion identity gateway.
 *
 * Stateful SecureContext initialization, allocation, save, and load are not
 * part of Slice 2. The four NSC veneers only prove that both images selected
 * the same versioned C55S contract.
 */
#include "fiber_secure_gateway_abi.h"

uint32_t fiber_secure_gateway_c55s_v1_abi_version(void)
{
	return FIBER_ARM_CM55_SECURE_GATEWAY_ABI_VERSION;
}

uint32_t fiber_secure_gateway_c55s_v1_context_port_id(void)
{
	return FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_PORT_ID;
}

uint32_t fiber_secure_gateway_c55s_v1_context_layout_version(void)
{
	return FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION;
}

uint32_t fiber_secure_gateway_c55s_v1_context_feature_mask(void)
{
	return FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_FEATURE_MASK;
}
