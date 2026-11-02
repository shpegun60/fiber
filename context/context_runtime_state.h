/* Context-private state declarations. Selected backend C must use the
 * separate reverse ABI, never this header or its current-slot lvalue. */
#ifndef CTXRT_CONTEXT_RUNTIME_STATE_H_
#define CTXRT_CONTEXT_RUNTIME_STATE_H_

#include "context_api_attributes.h"
#include "context_api_types.h"
#include "context_port_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

extern CtxrtContextV1 *volatile
fiber_internal_runtime_current_context_slot;

void fiber_internal_scheduler_store_pick_next(CtxrtDispatchFnV1 pick_next,
        void *user);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
CtxrtContextV1 *fiber_internal_runtime_load_current_context(void);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
uint32_t fiber_internal_scheduler_is_configured(void);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_runtime_close_context_configuration(void);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
uint32_t fiber_internal_runtime_context_configuration_is_open(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTXRT_CONTEXT_RUNTIME_STATE_H_ */
