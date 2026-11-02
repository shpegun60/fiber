/* Complete static storage remains selected-backend-owned and opaque by contract. */
#ifndef CTXRT_CONTEXT_H_
#define CTXRT_CONTEXT_H_

#include "context_api_decl.h"

/* Temporary physical path: reuse the exact storage type and consumer cohort
 * guard, without importing the Fiber callable or private runtime headers. */
#include "../fiber/port/fiber_port_selected.h"

#endif /* CTXRT_CONTEXT_H_ */
