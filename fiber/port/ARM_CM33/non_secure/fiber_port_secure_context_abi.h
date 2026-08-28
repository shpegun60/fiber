/* Selected ARM_CM33 TrustZone SecureContext attachment API. */
#ifndef FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_ABI_H_
#define FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_ABI_H_

#include <stddef.h>

#include "../../../fiber_api_attributes.h"
#include "fiber_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Valid only after fiber_init(ctx, ...) and before the first fiber_start().
 * This records and seals a request; allocation/load remains port-owned first
 * start work and is not performed by this user-facing function. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void fiber_port_secure_context_attach(FiberContext *ctx,
		size_t secure_stack_bytes);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_ABI_H_ */
