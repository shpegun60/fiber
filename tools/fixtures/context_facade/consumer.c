#ifndef INCLUDE_ORDER
#define INCLUDE_ORDER 0
#endif
#if INCLUDE_ORDER == 1
#include "fiber/fiber_core.h"
#include "context/context.h"
#elif INCLUDE_ORDER == 2
#include "context/context.h"
#include "fiber/fiber_core.h"
#else
#include "context/context.h"
#endif

#if INCLUDE_ORDER != 0
#ifdef __cplusplus
#include <type_traits>
static_assert(std::is_same<CtxrtContextV1, FiberContext>::value, "context type compatibility");
static_assert(std::is_same<CtxrtEntryFnV1, FiberEntryFn>::value, "entry compatibility");
static_assert(std::is_same<CtxrtDispatchFnV1, FiberSchedulerPickNextFn>::value, "dispatcher compatibility");
#else
_Static_assert(__builtin_types_compatible_p(CtxrtContextV1, FiberContext), "context compatibility");
_Static_assert(__builtin_types_compatible_p(CtxrtEntryFnV1, FiberEntryFn), "entry compatibility");
_Static_assert(__builtin_types_compatible_p(CtxrtDispatchFnV1, FiberSchedulerPickNextFn), "dispatcher compatibility");
#endif
#endif
#include "consumer.h"
#if CTXRT_API_VERSION != 1u
#error "context facade fixture requires version 1"
#endif

#if USE_NEW
#define NAME(n) modern_##n
#define INIT ctxrt_v1_init
#define CURRENT ctxrt_v1_current
#define SET ctxrt_v1_set_dispatcher
#define START ctxrt_v1_start
#define YIELD ctxrt_v1_yield
#else
#define NAME(n) legacy_##n
#define INIT fiber_init
#define CURRENT fiber_current
#define SET fiber_scheduler_set_pick_next
#define START fiber_start
#define YIELD fiber_schedule
#endif

static CtxrtContextV1 storage;
#ifdef __cplusplus
extern "C" {
#endif
CtxrtContextV1 *NAME(context)(void) { return &storage; }
void NAME(init)(void *begin, void *end, CtxrtEntryFnV1 entry, void *arg)
{
    void (*volatile call)(CtxrtContextV1 *, void *, void *, CtxrtEntryFnV1, void *) = INIT;
    call(&storage, begin, end, entry, arg);
}
CtxrtContextV1 *NAME(current)(void) { return CURRENT(); }
void NAME(set)(CtxrtDispatchFnV1 fn, void *user)
{
    void (*volatile call)(CtxrtDispatchFnV1, void *) = SET;
    call(fn, user);
}
void NAME(start)(void) { START(); }
void NAME(yield)(void) { YIELD(); }
#ifdef __cplusplus
}
#endif
