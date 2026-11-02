/* Temporary compiler-policy bridge; the canonical header stays unchanged. */
#ifndef CTXRT_CONTEXT_API_ATTRIBUTES_H_
#define CTXRT_CONTEXT_API_ATTRIBUTES_H_

#include "../fiber/fiber_api_attributes.h"

#define CTXRT_API_NORETURN FIBER_API_NORETURN
#define CTXRT_API_ATTR_SENSITIVE FIBER_API_ATTR_SENSITIVE
#define CTXRT_API_ATTR_INLINE_SENSITIVE FIBER_API_ATTR_INLINE_SENSITIVE
#define CTXRT_GENERAL_REGS_ONLY FIBER_GENERAL_REGS_ONLY
#define CTXRT_API_THREAD_FUNCTION FIBER_API_THREAD_FUNCTION

/* Required on dispatcher definitions, not merely their pointer declarations. */
#define CTXRT_DISPATCH_ATTR FIBER_SCHEDULER_HOOK_ATTR

#endif /* CTXRT_CONTEXT_API_ATTRIBUTES_H_ */
