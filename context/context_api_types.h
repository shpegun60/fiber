/* CPU-neutral Context v1 declarations; no selected storage or CPU headers. */
#ifndef CTXRT_CONTEXT_API_TYPES_H_
#define CTXRT_CONTEXT_API_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Temporary CPU-storage tag shared with the existing selected backends.
 * This is not a Fiber lifecycle object or a second storage representation. */
typedef struct FiberContext CtxrtContextV1;
typedef void (*CtxrtEntryFnV1)(void *arg);

/* The definition must use CTXRT_DISPATCH_ATTR. Its complete call graph must
 * obey the sensitive general-registers-only contract; pointer types do not
 * propagate those compiler protections. NULL current denotes first selection. */
typedef CtxrtContextV1 *(*CtxrtDispatchFnV1)(CtxrtContextV1 *current, void *user);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTXRT_CONTEXT_API_TYPES_H_ */
