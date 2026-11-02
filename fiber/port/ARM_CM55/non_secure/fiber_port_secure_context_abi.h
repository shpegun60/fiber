/* Staged ARM_CM55 selected-port pre-start attachment; not a common API. */
#ifndef FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_ABI_H_
#define FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_ABI_H_

#include <stddef.h>

#include "../../../fiber_api_attributes.h"
#include "fiber_port_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Records and reseals a request after construction, while the existing optional
 * common configuration lifecycle is open. Does not initialize, allocate, load,
 * or save Secure state. This staged profile still cannot start a runtime. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void fiber_port_secure_context_attach(FiberContext *ctx,
		size_t secure_stack_bytes);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_SECURE_CONTEXT_ABI_H_ */
