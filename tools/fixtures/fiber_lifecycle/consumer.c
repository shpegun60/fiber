/* Compiled as both C11 and C++17, with no CMSIS include path. */
#include "fiber/lifecycle/fiber_v1_privileged.h"
#include "context/context_api_decl.h"
#include "mixed_api.h"
static FiberV1 static_fiber = FIBER_V1_INITIALIZER;
static FiberRuntimeV1 static_runtime = FIBER_RUNTIME_V1_INITIALIZER;
#ifdef __cplusplus
static_assert(std::is_same<CtxrtContextV1, FiberContext>::value, "one context type");
static_assert(std::is_same<decltype(fiber_v1_context_privileged(&static_fiber)), CtxrtContextV1 *>::value, "typed accessor");
extern "C" {
#else
_Static_assert(_Generic(fiber_v1_context_privileged(&static_fiber), CtxrtContextV1 *: 1, default: 0), "typed accessor");
#endif
FiberV1 *lifecycle_consumer_storage(void) { return &static_fiber; }
FiberRuntimeV1 *lifecycle_consumer_runtime(void) { return &static_runtime; }
void lifecycle_consumer_init(void *begin, void *end, CtxrtEntryFnV1 entry, void *arg)
{ fiber_v1_init(&static_fiber, begin, end, entry, arg); }
void lifecycle_consumer_install(FiberSelectFnV1 select, void *user)
{ fiber_v1_set_scheduler(&static_runtime, select, user); }
FiberV1 *lifecycle_consumer_current(void) { return fiber_v1_current(); }
void lifecycle_consumer_yield(void) { fiber_v1_yield(); }
CTXRT_API_NORETURN void lifecycle_consumer_start(void) { fiber_v1_start(); }
#ifdef __cplusplus
}
#endif
