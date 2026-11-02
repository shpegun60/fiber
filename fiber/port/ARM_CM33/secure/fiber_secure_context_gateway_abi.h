/* Secure-image stateful ARM_CM33 SecureContext NSC gateway. */
#ifndef FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM33_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_

#include <stdint.h>

#include "fiber_secure_context_gateway_contract.h"
#include "fiber_secure_gateway_abi.h"

#ifndef fiber_secure_gatewayNON_SECURE_CALLABLE
# if defined(__GNUC__) || defined(__clang__)
#  define fiber_secure_gatewayNON_SECURE_CALLABLE \
	__attribute__((cmse_nonsecure_entry)) \
	FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
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

/* Stateful entries check their immediate Non-secure caller directly and
 * independently restrict IPSR. Neither check authenticates an owned NS code
 * site: the trusted Non-secure port separately validates those call sites.
 * One-shot initialization requires a Non-secure SVCall caller and fails rather
 * than destructively reinitializing an active SecureContext pool. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_initialize(void);

/* Allocation is accepted only from a Non-secure SVCall or PendSV caller for
 * first start or lazy activation, after successful one-shot initialization and
 * while no Secure PSP context is loaded. The owner token is opaque and is never
 * dereferenced in Secure state. Zero remains the invalid/failure handle. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_allocate(
		uint32_t secure_stack_bytes,
		uintptr_t owner_token);

/* Load one owned SecureContext from a Non-secure SVCall or PendSV caller while
 * no Secure PSP is active. Handle zero is the no-SecureContext case and succeeds
 * only while PSP/PSPLIM both remain zero. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_v1_load(
		uint32_t handle,
		uintptr_t owner_token);

/* Save one owned SecureContext from a Non-secure PendSV caller. Handle zero
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
