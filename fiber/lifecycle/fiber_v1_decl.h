/* Fiber V1 lifecycle API. No selected CPU representation here. */
#ifndef FIBER_LIFECYCLE_V1_DECL_H_
#define FIBER_LIFECYCLE_V1_DECL_H_

#include "context/context_api_attributes.h"
#include "context/context_api_types.h"

#define FIBER_V1_API_VERSION 1u
#define FIBER_V1_SELECT_ATTR CTXRT_DISPATCH_ATTR

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FiberV1 FiberV1;
typedef struct FiberRuntimeV1 FiberRuntimeV1;

/* NULL current denotes first selection. The definition and complete call
 * graph require FIBER_V1_SELECT_ATTR. Returning NULL is rejected by Context. */
typedef FiberV1 *(*FiberSelectFnV1)(FiberV1 *current, void *user);

/* Every non-NULL Fiber/Runtime argument must name a valid, aligned,
 * caller-owned object accessible to the privileged caller. The consumer
 * cannot validate arbitrary pointers or its metadata through Context hooks.
 * Cold privileged operations. Storage must have static lifetime and begin
 * with FIBER_V1_INITIALIZER. Init requires the optional Context configuration
 * service and an open global gate. Successful initialization cannot repeat. */
void fiber_v1_init(FiberV1 *fiber, void *stack_begin, void *stack_end,
        CtxrtEntryFnV1 entry, void *arg);

/* Context registration must succeed before runtime's policy fields change.
 * Do not modify runtime directly or mix this consumer with another dispatcher. */
void fiber_v1_set_scheduler(FiberRuntimeV1 *runtime,
        FiberSelectFnV1 select, void *user);

/* Identity only: these functions never read privileged Fiber metadata. */
CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
FiberV1 *fiber_v1_current(void);

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_v1_start(void);

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
void fiber_v1_yield(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_LIFECYCLE_V1_DECL_H_ */
