/*
 * fiber_api_types.h
 *
 * CPU-neutral public declarations. This header intentionally does not select a
 * port or expose a context layout.
 */

#ifndef FIBER_FIBER_API_TYPES_H_
#define FIBER_FIBER_API_TYPES_H_

#include "../context/context_api_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef CtxrtEntryFnV1 FiberEntryFn;

/* Keep the original public spelling source-compatible during the structural
 * opaque-context migration. */
typedef FiberEntryFn entry_t;

/* Legacy names alias the canonical Context types, not another representation. */
typedef CtxrtContextV1 FiberContext;

/* The callback definition must use FIBER_SCHEDULER_HOOK_ATTR from
 * fiber_api_attributes.h. GCC does not propagate target("general-regs-only") through
 * an indirect function-pointer type, so the complete callback call graph remains
 * an integration responsibility. */
typedef CtxrtDispatchFnV1 FiberSchedulerPickNextFn;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_API_TYPES_H_ */
