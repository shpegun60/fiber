/* Frozen reverse-v1 services. Historical symbol names are intentional ABI,
 * not a dependency on Fiber lifecycle types or implementation. */
#ifndef CTXRT_CONTEXT_RUNTIME_PORT_ABI_H_
#define CTXRT_CONTEXT_RUNTIME_PORT_ABI_H_

#include "context_api_attributes.h"
#include "context_api_types.h"
#include "context_panic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FIBER_RUNTIME_PORT_ABI_VERSION 1u

extern const unsigned char fiber_internal_runtime_port_abi_v1_anchor;

/* Actual cold read retained through optimization/LTO, never a hot-path read. */
#define FIBER_RUNTIME_PORT_ABI_RETAIN_V1() \
    ((void)*(volatile const unsigned char *) \
            &fiber_internal_runtime_port_abi_v1_anchor)

/* Assembly-visible only; deliberately no C declaration here:
 * fiber_internal_runtime_current_context_slot
 */

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(
        CtxrtContextV1 *current);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_current_context(void);

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_task_return(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTXRT_CONTEXT_RUNTIME_PORT_ABI_H_ */
