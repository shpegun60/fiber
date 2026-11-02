/* Selected ARM_CM33F TrustZone SecureContext attachment API. */
#ifndef FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_ABI_H_
#define FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_ABI_H_

#include <stddef.h>

#include "../../../fiber_api_attributes.h"
#include "fiber_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Valid only after fiber_init(ctx, ...) and before the first fiber_start().
 * This records and seals a request. Allocation/load is unimplemented in this
 * staged profile and remains future selected-port work. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void fiber_port_secure_context_attach(FiberContext *ctx,
		size_t secure_stack_bytes);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_ABI_H_ */
