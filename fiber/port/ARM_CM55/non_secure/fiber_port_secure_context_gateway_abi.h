/* Non-secure imports for the C55S capacity gateway and guarded lifecycle. */
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
uint32_t fiber_secure_context_gateway_c55s_v1_initialize(void);

/* Backend integration only; requires serialized NS SVC/PendSV, READY, and
 * Secure CONTROL=2. Save is PendSV-only. Owner is opaque and never dereferenced.
 * Allocate returns a nonzero handle on success; load/save return one. Zero
 * from load/save is terminal after a partial update: no retry or Thread resume.
 * See the paired Secure header/ledger for admission, zero-handle, and ordering
 * rules. These declarations carry no Secure entry attribute or CMSIS types. */
uint32_t fiber_secure_context_gateway_c55s_v1_allocate(
		uint32_t secure_stack_bytes, uintptr_t owner_token);
uint32_t fiber_secure_context_gateway_c55s_v1_load(
		uint32_t handle, uintptr_t owner_token);
uint32_t fiber_secure_context_gateway_c55s_v1_save(
		uint32_t handle, uintptr_t owner_token);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_GATEWAY_ABI_H_ */
