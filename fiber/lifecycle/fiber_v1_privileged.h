/* Optional integration access, never an unprivileged task-facing API. */
#ifndef FIBER_LIFECYCLE_V1_PRIVILEGED_H_
#define FIBER_LIFECYCLE_V1_PRIVILEGED_H_

#include "fiber_v1.h"

/* Identity only, not permission to configure. A non-NULL Fiber must be a valid,
 * aligned, caller-owned object. Callers must be privileged and obey the selected profile's
 * existing configuration ABI and global Context configuration-open guard.
 * INITIALIZED by itself does not make late feature configuration legal. */
static inline CTXRT_API_ATTR_INLINE_SENSITIVE CTXRT_GENERAL_REGS_ONLY
CtxrtContextV1 *fiber_v1_context_privileged(FiberV1 *const fiber)
{
    return fiber != NULL ? &fiber->private_context : NULL;
}

#endif /* FIBER_LIFECYCLE_V1_PRIVILEGED_H_ */
