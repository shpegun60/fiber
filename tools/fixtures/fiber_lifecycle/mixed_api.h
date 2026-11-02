/* Explicit mixed-cohort references, never part of the pure Context cohort. */
#ifndef LIFECYCLE_FIXTURE_MIXED_API_H_
#define LIFECYCLE_FIXTURE_MIXED_API_H_
#ifndef USE_LEGACY
#error The runner must explicitly select USE_LEGACY=0 or USE_LEGACY=1
#elif USE_LEGACY != 0 && USE_LEGACY != 1
#error Invalid lifecycle fixture cohort
#endif
#if USE_LEGACY
#include "fiber/fiber_api_decl.h"
/* Keep all five real identities visible through GC/LTO. This is a public API
 * consumer record, not a manufactured private-provider archive root. */
static const struct LifecycleLegacyPublicApi {
    void (*init)(FiberContext *, void *, void *, entry_t, void *);
    FiberContext *(*current)(void);
    void (*set_dispatcher)(FiberSchedulerPickNextFn, void *);
    void (*start)(void);
    void (*yield)(void);
} lifecycle_legacy_public_api __attribute__((used, section(".fixture_legacy_public"))) = {
    fiber_init, fiber_current, fiber_scheduler_set_pick_next, fiber_start, fiber_schedule
};
#endif
#endif
