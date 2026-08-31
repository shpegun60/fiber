/*
 * Non-secure import surface for the exact ARM_CM55 C55S Secure companion.
 *
 * This is selected-port integration only. It is not included by fiber_core.h
 * and does not expose a user-facing attachment or SecureContext API.
 */
#ifndef FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_GATEWAY_ABI_H_

#include <stdint.h>

#include "fiber_portmacro.h"
#include "../secure/fiber_secure_gateway_contract.h"

FIBER_STATIC_ASSERT(FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_PORT_ID ==
		FIBER_PORT_CONTEXT_ABI_PORT_ID,
		"[fiber]: ARM_CM55 Secure gateway port identity mismatch");
FIBER_STATIC_ASSERT(FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION ==
		FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION,
		"[fiber]: ARM_CM55 Secure gateway layout identity mismatch");
FIBER_STATIC_ASSERT(FIBER_ARM_CM55_SECURE_GATEWAY_CONTEXT_FEATURE_MASK ==
		FIBER_PORT_CONTEXT_ABI_FEATURE_MASK,
		"[fiber]: ARM_CM55 Secure gateway feature identity mismatch");

#ifdef __cplusplus
extern "C" {
#endif

/* Resolved only by the matching C55S Secure CMSE import library. The cohort
 * name and ABI version are part of every symbol spelling. */
uint32_t fiber_secure_gateway_c55s_v1_abi_version(void);
uint32_t fiber_secure_gateway_c55s_v1_context_port_id(void);
uint32_t fiber_secure_gateway_c55s_v1_context_layout_version(void);
uint32_t fiber_secure_gateway_c55s_v1_context_feature_mask(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_GATEWAY_ABI_H_ */
