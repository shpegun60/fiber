/*
 * Gateway-only ARM_CM33 Secure companion.
 *
 * This object intentionally provides only immutable identity queries. The
 * separately versioned stateful gateway owns Secure initialization,
 * allocation, owned save, and owned load for the complete paired runtime.
 */

#include "fiber_secure_gateway_abi.h"

uint32_t fiber_secure_gateway_v1_abi_version(void)
{
	return FIBER_ARM_CM33_SECURE_GATEWAY_ABI_VERSION;
}

uint32_t fiber_secure_gateway_v1_context_port_id(void)
{
	return FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_PORT_ID;
}

uint32_t fiber_secure_gateway_v1_context_layout_version(void)
{
	return FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION;
}

uint32_t fiber_secure_gateway_v1_context_feature_mask(void)
{
	return FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_FEATURE_MASK;
}
