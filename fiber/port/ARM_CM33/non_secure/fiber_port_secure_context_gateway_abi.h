/* Non-secure import surface for the stateful SecureContext gateway ABI v1. */
#ifndef FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_GATEWAY_ABI_H_

#include <stdint.h>

#include "../secure/fiber_secure_context_gateway_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t fiber_secure_context_gateway_v1_abi_version(void);
uint32_t fiber_secure_context_gateway_v1_stack_alignment(void);
uint32_t fiber_secure_context_gateway_v1_max_stack_bytes(void);
uint32_t fiber_secure_context_gateway_v1_max_contexts(void);
uint32_t fiber_secure_context_gateway_v1_initialize(void);
uint32_t fiber_secure_context_gateway_v1_allocate(
		uint32_t secure_stack_bytes,
		uintptr_t owner_token);
uint32_t fiber_secure_context_gateway_v1_load(
		uint32_t handle,
		uintptr_t owner_token);
uint32_t fiber_secure_context_gateway_v1_save(
		uint32_t handle,
		uintptr_t owner_token);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_GATEWAY_ABI_H_ */
