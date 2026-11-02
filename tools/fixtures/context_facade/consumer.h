#ifndef CONTEXT_FACADE_CONSUMER_H
#define CONTEXT_FACADE_CONSUMER_H
#include "context/context_api_types.h"
#ifdef __cplusplus
extern "C" {
#endif
#define DECLARE_CONSUMER(name) \
    CtxrtContextV1 *name##_context(void); \
    void name##_init(void *, void *, CtxrtEntryFnV1, void *); \
    CtxrtContextV1 *name##_current(void); \
    void name##_set(CtxrtDispatchFnV1, void *); \
    void name##_start(void); \
    void name##_yield(void)
DECLARE_CONSUMER(modern);
DECLARE_CONSUMER(legacy);
#undef DECLARE_CONSUMER
#ifdef __cplusplus
}
#endif
#endif
