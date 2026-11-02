/* Internal versioned consumer surface over the existing Context engine. */
#ifndef CTXRT_CONTEXT_API_DECL_H_
#define CTXRT_CONTEXT_API_DECL_H_

#include "context_api_attributes.h"
#include "context_api_types.h"

#define CTXRT_API_VERSION 1u

#ifdef __cplusplus
extern "C" {
#endif

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void ctxrt_v1_init(CtxrtContextV1 *context,
        void *stack_begin,
        void *stack_end,
        CtxrtEntryFnV1 entry,
        void *arg);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
CtxrtContextV1 *ctxrt_v1_current(void);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void ctxrt_v1_set_dispatcher(CtxrtDispatchFnV1 dispatch, void *user);

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void ctxrt_v1_start(void);

/* Thread-mode request only; this is not an ISR reschedule operation. */
CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
void ctxrt_v1_yield(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTXRT_CONTEXT_API_DECL_H_ */
