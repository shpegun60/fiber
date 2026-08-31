/* Non-secure import surface for the C55S SecureContext capacity gateway. */
#ifndef FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_GATEWAY_ABI_H_

#include <stdint.h>

#include "../secure/fiber_secure_context_gateway_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t fiber_secure_context_gateway_c55s_v1_abi_version(void);
uint32_t fiber_secure_context_gateway_c55s_v1_stack_alignment(void);
uint32_t fiber_secure_context_gateway_c55s_v1_max_stack_bytes(void);
uint32_t fiber_secure_context_gateway_c55s_v1_max_contexts(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_GATEWAY_ABI_H_ */
