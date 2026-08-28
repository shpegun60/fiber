/*
 * fiber_port_secure_gateway_abi.h
 *
 * Non-secure import surface for the matched ARM_CM33 Secure companion. This
 * is port-private integration, separate from the user-facing attachment API
 * and not part of fiber_core.h.
 */

#ifndef FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_SECURE_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_SECURE_GATEWAY_ABI_H_

#include <stdint.h>

#include "fiber_portmacro.h"
#include "../secure/fiber_secure_gateway_contract.h"

FIBER_STATIC_ASSERT(FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_PORT_ID ==
		FIBER_PORT_CONTEXT_ABI_PORT_ID,
		"[fiber]: ARM_CM33 Secure gateway port identity mismatch");
FIBER_STATIC_ASSERT(FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION ==
		FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION,
		"[fiber]: ARM_CM33 Secure gateway layout identity mismatch");
FIBER_STATIC_ASSERT(FIBER_ARM_CM33_SECURE_GATEWAY_CONTEXT_FEATURE_MASK ==
		FIBER_PORT_CONTEXT_ABI_FEATURE_MASK,
		"[fiber]: ARM_CM33 Secure gateway feature identity mismatch");

#ifdef __cplusplus
extern "C" {
#endif

/* These names are resolved only from the matched Secure CMSE import library.
 * They intentionally carry v1 in their symbol spelling. */
uint32_t fiber_secure_gateway_v1_abi_version(void);
uint32_t fiber_secure_gateway_v1_context_port_id(void);
uint32_t fiber_secure_gateway_v1_context_layout_version(void);
uint32_t fiber_secure_gateway_v1_context_feature_mask(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_SECURE_GATEWAY_ABI_H_ */
