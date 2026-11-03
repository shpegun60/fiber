/* Read-only layout facts, never a replacement for the actual consumer. */
#include "fiber/lifecycle/fiber_v1.h"

const uint32_t r9_fiber_layout[] = {
    sizeof(FiberV1), sizeof(CtxrtContextV1),
    offsetof(FiberV1, private_state), _Alignof(FiberV1),
    FIBER_V1_EMPTY, FIBER_V1_INITIALIZED
};
