/*
 * fiber_api_types.h
 *
 * CPU-neutral public declarations. This header intentionally does not select a
 * port or expose a context layout.
 */

#ifndef FIBER_FIBER_API_TYPES_H_
#define FIBER_FIBER_API_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*FiberEntryFn)(void *); /* Cortex-M entry points are Thumb functions. */

/* Keep the original public spelling source-compatible during the structural
 * opaque-context migration. */
typedef FiberEntryFn entry_t;

/* The selected public port type header completes this tagged type. */
typedef struct FiberContext FiberContext;

/* The callback definition must use FIBER_SCHEDULER_HOOK_ATTR from
 * fiber_compiler.h. GCC does not propagate target("general-regs-only") through
 * an indirect function-pointer type, so the complete callback call graph remains
 * an integration responsibility. */
typedef FiberContext *(*FiberSchedulerPickNextFn)(FiberContext *current, void *user);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_API_TYPES_H_ */
