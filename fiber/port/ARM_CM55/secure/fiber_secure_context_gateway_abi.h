/* Secure-image C55S SecureContext capacity gateway and guarded lifecycle. */
#ifndef FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_
#define FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_

#include <stdint.h>

#include "fiber_secure_context_gateway_contract.h"
#include "fiber_secure_gateway_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Four immutable capacity facts retain their original Slice-3 spellings. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_abi_version(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_stack_alignment(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_max_stack_bytes(void);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_max_contexts(void);

/* Requires an immediate Non-secure caller in SVC (IPSR == 11), zeroed Secure
 * gateway/pool BSS, and serialized single-core boot. Returns one only after
 * CPU and pool initialization succeed. Preflight rejection returns zero with
 * no gateway/pool or policy-register writes; later failure cannot be retried.
 * CONTROL is written and read back as exactly two. The Non-secure runtime must
 * separately validate its exact first-start call site. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_initialize(void);

/* Selected-companion operations, not portable application APIs. Calls must
 * be serialized, single-core, and immediately Non-secure. All require READY
 * and exact Secure CONTROL=2 (privileged PSP, no active FP/MVE policy).
 * Allocate/load admit only SVC or PendSV; save admits only PendSV. IPSR is not
 * proof of the exact NS call site, which the future NS runtime must validate.
 * No CONTROL, interrupt-mask, or Non-secure bank writes are performed.
 *
 * Allocate requires empty Secure PSP/PSPLIM and delegates size/owner/duplicate/
 * capacity checks to the unchanged private static pool; zero means failure.
 * Load also requires empty PSP/PSPLIM and nonzero owner; zero handle succeeds
 * only for that empty state. It validates ownership, then writes/verifies
 * PSPLIM before PSP. Save requires nonzero owner; zero handle succeeds only
 * for empty PSP/PSPLIM. Otherwise it validates live geometry, stores PSP,
 * barriers, verifies both owned lookup and the stored PSP, then clears and
 * verifies PSPLIM before PSP. Load/save return one only on complete success.
 *
 * Any failed partial update is terminal for the caller: it must not retry,
 * select another context, or resume Thread mode. There is no rollback or new
 * recovery latch; rejection and partial failure both return zero. Corrupted
 * Secure pool metadata/seals fail closed in the private pool. */
fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_allocate(
		uint32_t secure_stack_bytes, uintptr_t owner_token);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_load(
		uint32_t handle, uintptr_t owner_token);

fiber_secure_gatewayNON_SECURE_CALLABLE
uint32_t fiber_secure_context_gateway_c55s_v1_save(
		uint32_t handle, uintptr_t owner_token);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_SECURE_FIBER_SECURE_CONTEXT_GATEWAY_ABI_H_ */
