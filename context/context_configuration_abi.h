/* Optional Context lifecycle service, separate from both mandatory port ABIs. */
#ifndef CTXRT_CONTEXT_CONFIGURATION_ABI_H_
#define CTXRT_CONTEXT_CONFIGURATION_ABI_H_

#include "context_api_attributes.h"
#include "context_api_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_VERSION 1u

extern const unsigned char
fiber_internal_runtime_context_configuration_abi_v1_anchor;

#define FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_RETAIN_V1() \
    ((void)*(volatile const unsigned char *) \
            &fiber_internal_runtime_context_configuration_abi_v1_anchor)

/* NULL is rejected before the closed-configuration guard. The selected
 * feature still owns all context-private validation and mutation. */
CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_context_configuration_open(
        const CtxrtContextV1 *context);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTXRT_CONTEXT_CONFIGURATION_ABI_H_ */
