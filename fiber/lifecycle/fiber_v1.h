/* Caller-owned static storage for the Fiber V1 lifecycle consumer. */
#ifndef FIBER_LIFECYCLE_V1_H_
#define FIBER_LIFECYCLE_V1_H_

#include <stddef.h>
#include <stdint.h>
#include "fiber_v1_decl.h"
#include "context/context.h"

typedef enum FiberStateV1 {
    FIBER_V1_EMPTY = 0,
    FIBER_V1_INITIALIZED = 1,
    FIBER_V1_STARTED = 2
} FiberStateV1;

/* Complete for static allocation, private by contract. Callers supply valid,
 * aligned object storage; Context's prefix map checks cannot validate this
 * consumer's tail. Initialized objects must never move, be copied, be
 * reinitialized, or outlive their stacks. */
struct FiberV1 {
    CtxrtContextV1 private_context;
    uint32_t private_state;
};

/* One installed consumer per Context engine. Valid, aligned, caller-owned
 * static privileged storage, disjoint from every execution stack. Policy
 * fields are immutable after first selection. */
struct FiberRuntimeV1 {
    FiberSelectFnV1 private_select;
    void *private_user;
};

#ifdef __cplusplus
#include <type_traits>
static_assert(std::is_standard_layout<FiberV1>::value,
        "FiberV1 identity requires standard-layout storage");
static_assert(offsetof(FiberV1, private_context) == 0u,
        "FiberV1 context must remain the first member");
static_assert(alignof(FiberV1) >= alignof(CtxrtContextV1),
        "FiberV1 must preserve Context alignment");
#define FIBER_V1_INITIALIZER { {}, FIBER_V1_EMPTY }
#else
_Static_assert(offsetof(FiberV1, private_context) == 0u,
        "FiberV1 context must remain the first member");
_Static_assert(_Alignof(FiberV1) >= _Alignof(CtxrtContextV1),
        "FiberV1 must preserve Context alignment");
#define FIBER_V1_INITIALIZER { {0}, FIBER_V1_EMPTY }
#endif

#define FIBER_RUNTIME_V1_INITIALIZER { NULL, NULL }

#endif /* FIBER_LIFECYCLE_V1_H_ */
