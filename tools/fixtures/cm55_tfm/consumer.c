/* Compiled as both C and C++; no CMSIS or private runtime header. */
#ifdef TFM_CONTEXT_ONLY
#include "context.h"
typedef CtxrtContextV1 TestContext;
#define TEST_INIT ctxrt_v1_init
#define TEST_CURRENT ctxrt_v1_current
#define TEST_START ctxrt_v1_start
#define TEST_DISPATCH ctxrt_v1_set_dispatcher
#define TEST_YIELD ctxrt_v1_yield
#define TEST_DISPATCH_ATTR CTXRT_DISPATCH_ATTR
#else
#include "fiber_core.h"
typedef FiberContext TestContext;
#define TEST_INIT fiber_init
#define TEST_CURRENT fiber_current
#define TEST_START fiber_start
#define TEST_DISPATCH fiber_scheduler_set_pick_next
#define TEST_YIELD fiber_schedule
#define TEST_DISPATCH_ATTR FIBER_SCHEDULER_HOOK_ATTR
#endif
static TestContext contexts[2];
static uint32_t stacks[2][256] __attribute__((aligned(8)));
__attribute__((used, section(".proof_roots")))
static const uintptr_t public_operation_roots[] = {
    (uintptr_t)TEST_INIT, (uintptr_t)TEST_CURRENT, (uintptr_t)TEST_START,
    (uintptr_t)TEST_DISPATCH, (uintptr_t)TEST_YIELD
};
static void entry(void *arg) { (void)arg; for (;;) TEST_YIELD(); }
static TEST_DISPATCH_ATTR TestContext *pick(TestContext *current, void *user)
{
    (void)user;
    return current == &contexts[0] ? &contexts[1] : &contexts[0];
}
#ifdef __cplusplus
extern "C"
#endif
void Reset_Handler(void)
{
    TEST_INIT(&contexts[0], stacks[0], stacks[0] + 256, entry, 0);
    TEST_INIT(&contexts[1], stacks[1], stacks[1] + 256, entry, 0);
    TEST_DISPATCH(pick, 0);
    (void)TEST_CURRENT();
    TEST_START();
}
