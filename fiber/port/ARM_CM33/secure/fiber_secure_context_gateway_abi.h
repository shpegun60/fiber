/* Secure-image stateful ARM_CM33 SecureContext NSC gateway. */
#ifndef FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_

#include <stdint.h>

#include "fiber_secure_context_gateway_contract.h"
#include "fiber_secure_gateway_abi.h"

#ifndef fiber_secure_gatewayNON_SECURE_CALLABLE
# if defined(__GNUC__) || defined(__clang__)
#  define fiber_secure_gatewayNON_SECURE_CALLABLE \
	__attribute__((cmse_nonsecure_entry)) __attribute__((used)) \
	__attribute__((noinline))
# else
#  error "[fiber]: ARM_CM33 SecureContext gateway requires GCC/Clang CMSE attributes"
# endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_abi_version(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_stack_alignment(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_max_stack_bytes(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_max_contexts(void);

/* One-shot Secure scheduler-domain initialization. It is accepted only from
 * the exact Non-secure first-start SVCall and fails rather than destructively
 * reinitializing an active SecureContext pool. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_initialize(void);

/* Allocation is accepted only from exact SVCall first start or PendSV lazy
 * activation while no Secure PSP context is loaded and after successful
 * one-shot initialization. The owner token is opaque and is never
 * dereferenced in Secure state. Zero remains the invalid/failure handle. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_allocate(
		uint32_t secure_stack_bytes,
		uintptr_t owner_token);

/* Load one owned SecureContext from exact SVCall or PendSV while no Secure PSP
 * is active. Handle zero is the explicit no-SecureContext case and succeeds
 * only while PSP/PSPLIM both remain zero. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_load(
		uint32_t handle,
		uintptr_t owner_token);

/* Save one owned SecureContext from the exact PendSV exception. Handle zero
 * is the explicit no-SecureContext case and succeeds only when no Secure PSP
 * is active. A successful nonzero save stores the live Secure PSP, then
 * clears Secure PSPLIM and PSP so the scheduler cannot inherit Secure state. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_save(
		uint32_t handle,
		uintptr_t owner_token);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_ */
