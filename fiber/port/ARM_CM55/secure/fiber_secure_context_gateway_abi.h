/* Secure-image C55S SecureContext capacity NSC gateway. */
#ifndef FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_

#include <stdint.h>

#include "fiber_secure_context_gateway_contract.h"
#include "fiber_secure_gateway_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Four immutable capacity facts only. Stateful initialization, allocation,
 * load, and save are deliberately absent from this Slice-3 ABI. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_abi_version(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_stack_alignment(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_max_stack_bytes(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_max_contexts(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_ */
