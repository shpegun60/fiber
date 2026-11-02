/* Fiber V1 lifecycle consumer: all engine state remains Context-owned. */
#include "fiber_v1.h"
#include "context/context_api_decl.h"
#include "context/context_configuration_abi.h"
#include "context/context_panic.h"

static CTXRT_DISPATCH_ATTR
CtxrtContextV1 *fiber_v1_dispatch(CtxrtContextV1 *const current, void *const user)
{
    FiberRuntimeV1 *const runtime = (FiberRuntimeV1 *)user;
    if (runtime == NULL) {
        fiber_panic('n');
    }
    FiberSelectFnV1 const select = runtime->private_select;
    if (select == NULL) {
        fiber_panic('K');
    }

    /* First-member pointer conversion does not inspect the Context layout. */
    FiberV1 *const previous = (FiberV1 *)(void *)current;
    if (previous != NULL && previous->private_state != FIBER_V1_STARTED) {
        fiber_panic('L');
    }
    FiberV1 *const next = select(previous, runtime->private_user);
    if (next == NULL) {
        return NULL;
    }
    if (next->private_state == FIBER_V1_INITIALIZED) {
        /* Selection is observable here; successful CPU entry is not. A later
         * Context validation/restore failure is terminal, never rollback. */
        next->private_state = FIBER_V1_STARTED;
    } else if (next->private_state != FIBER_V1_STARTED) {
        fiber_panic('L');
    }
    return &next->private_context;
}

void fiber_v1_init(FiberV1 *const fiber,
        void *const stack_begin, void *const stack_end,
        CtxrtEntryFnV1 const entry, void *const arg)
{
    if (fiber == NULL) {
        fiber_panic('n');
    }
    const uintptr_t object_begin = (uintptr_t)fiber;
    if (object_begin > UINTPTR_MAX - sizeof(*fiber)) {
        fiber_panic('O');
    }
    const uintptr_t object_end = object_begin + sizeof(*fiber);
    FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_RETAIN_V1();
    fiber_internal_runtime_require_context_configuration_open(&fiber->private_context);
    if (fiber->private_state != FIBER_V1_EMPTY) {
        fiber_panic('L');
    }
    const uintptr_t raw_begin = (uintptr_t)stack_begin;
    const uintptr_t raw_end = (uintptr_t)stack_end;
    /* The backend checks only its Context prefix. Extend disjointness over
     * the complete consumer object, including lifecycle metadata/padding.
     * Malformed stack arguments still go to Context's existing validation. */
    if (raw_begin != 0u && raw_end > raw_begin &&
            object_begin < raw_end && raw_begin < object_end) {
        fiber_panic('C');
    }
    ctxrt_v1_init(&fiber->private_context, stack_begin, stack_end, entry, arg);
    fiber->private_state = FIBER_V1_INITIALIZED;
}

void fiber_v1_set_scheduler(FiberRuntimeV1 *const runtime,
        FiberSelectFnV1 const select, void *const user)
{
    if (runtime == NULL && select != NULL) {
        fiber_panic('n');
    }
    ctxrt_v1_set_dispatcher(select != NULL ? fiber_v1_dispatch : NULL, runtime);
    /* A conforming Context rejects NULL dispatch before returning. Retain a
     * terminal guard rather than accepting a broken integration's return. */
    if (select == NULL) {
        fiber_panic('K');
    }
    runtime->private_user = user;
    runtime->private_select = select;
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
FiberV1 *fiber_v1_current(void)
{
    return (FiberV1 *)(void *)ctxrt_v1_current();
}

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_v1_start(void)
{
    ctxrt_v1_start();
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
void fiber_v1_yield(void)
{
    ctxrt_v1_yield();
}
