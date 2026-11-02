/* Actual common runtime, mock forward8. No CPU/exception execution claim. */
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "context/context.h"
#include "fiber/fiber_core.h"
#include "fiber/fiber_runtime_port_abi.h"
#include "fiber/fiber_runtime_context_configuration_abi.h"
#include "fiber/fiber_runtime_state.h"
#include "fiber/port/fiber_port_runtime_abi.h"
#include "consumer.h"

const unsigned char FIBER_PORT_STORAGE_COHORT_SYMBOL = 1;
static jmp_buf escape;
static char trace[128];
static unsigned trace_size, checks, barriers, init_count, hook_count, replacement_hook_count;
static int mode, environment_bad, prepare_bad;
static char panic_code;
static FiberContext *expected_current, *candidate;
static void *expected_user;
static unsigned char stack[256];

#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "ASSERT line=%d expression=%s trace=%s panic=%c\n", \
        __LINE__, #c, trace, panic_code ? panic_code : '-'); exit(90); } } while (0)
static void event(char c)
{ CHECK(trace_size + 1 < sizeof(trace)); trace[trace_size++] = c; trace[trace_size] = 0; }
static void entry(void *arg) { (void)arg; }

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code) { panic_code = code; longjmp(escape, 1); }
void fiber_port_runtime_memory_barrier(void) { ++barriers; }
void fiber_port_panic_wait(void) { abort(); }
void fiber_port_context_init(FiberContext *ctx, void *begin, void *end, entry_t fn, void *arg)
{
    FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
    event('I'); ++init_count;
    CHECK(ctx == modern_context() || ctx == legacy_context());
    CHECK(begin == stack && end == stack + sizeof(stack));
    CHECK(fn == entry && arg == &mode);
}
void fiber_port_require_scheduler_configuration_environment(void)
{
    event('E'); if (environment_bad) fiber_panic('i');
}
void fiber_port_runtime_prepare_start(void)
{
    FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
    FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_RETAIN_V1();
    event('P'); CHECK(fiber_internal_runtime_context_configuration_is_open() == 0);
    if (prepare_bad) fiber_panic('p');
}
FiberContext *fiber_port_runtime_select_first(void)
{
    event('F'); return fiber_internal_runtime_select_scheduler_candidate(NULL);
}
void fiber_port_runtime_start_first(FiberContext *ctx)
{
    event('S'); CHECK(ctx == candidate);
    CHECK(modern_current() == ctx && legacy_current() == ctx);
    longjmp(escape, 2);
}
void fiber_port_runtime_schedule(void)
{
    event('Y'); fiber_internal_runtime_require_current_context();
    expected_current = modern_current();
    CHECK(legacy_current() == expected_current);
    FiberContext *next = fiber_internal_runtime_select_scheduler_candidate(expected_current);
    fiber_internal_runtime_publish_current_context(next);
}

CTXRT_DISPATCH_ATTR
static CtxrtContextV1 *dispatch(CtxrtContextV1 *current, void *user)
{
    event('H'); ++hook_count;
    CHECK(current == expected_current && user == expected_user);
    CHECK(fiber_internal_runtime_context_configuration_is_open() == 0);
    if (mode == 1) modern_set(dispatch, expected_user);
    if (mode == 2) legacy_start();
    return candidate;
}
CTXRT_DISPATCH_ATTR
static CtxrtContextV1 *replacement_dispatch(CtxrtContextV1 *current, void *user)
{
    ++replacement_hook_count;
    return dispatch(current, user);
}

static void set_hook(int modern)
{
    expected_user = &mode;
    if (modern) modern_set(dispatch, expected_user); else legacy_set(dispatch, expected_user);
}
static void start_api(int modern) { if (modern) modern_start(); else legacy_start(); }
static void yield_api(int modern) { if (modern) modern_yield(); else legacy_yield(); }

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    int scenario = atoi(argv[1]);
    int api = scenario & 1;
    int test = scenario / 2;
    candidate = modern_context();
    CHECK(modern_current() == NULL && legacy_current() == NULL);
    CHECK(fiber_internal_runtime_context_configuration_is_open() == 1);
    CHECK(barriers >= 3);
    trace_size = 0; trace[0] = 0;
    int result = setjmp(escape);
    if (result == 0) {
        switch (test) {
        case 0:
            modern_init(stack, stack + sizeof(stack), entry, &mode);
            legacy_init(stack, stack + sizeof(stack), entry, &mode);
            CHECK(init_count == 2 && strcmp(trace, "II") == 0); break;
        case 1: start_api(api); CHECK(0); break; /* K */
        case 2:
            fiber_internal_runtime_publish_current_context(candidate);
            start_api(api); CHECK(0); break; /* K before k */
        case 3:
            set_hook(!api); fiber_internal_runtime_publish_current_context(candidate);
            start_api(api); CHECK(0); break; /* k before prepare */
        case 4:
            set_hook(!api); trace_size = 0; trace[0] = 0;
            start_api(api); CHECK(0); break;
        case 5:
            if (api) modern_set(NULL, &mode); else legacy_set(NULL, &mode);
            CHECK(0); break;
        case 6:
            environment_bad = 1;
            if (api) modern_set(NULL, &mode); else legacy_set(NULL, &mode);
            CHECK(0); break; /* environment before K */
        case 7:
            set_hook(!api); candidate = NULL; start_api(api); CHECK(0); break;
        case 8:
            set_hook(!api); mode = 1; start_api(api); CHECK(0); break;
        case 9:
            set_hook(!api); mode = 2; start_api(api); CHECK(0); break;
        case 10:
            yield_api(api); CHECK(0); break;
        case 11:
            fiber_internal_task_return(); CHECK(0); break;
        case 12:
            fiber_internal_runtime_require_context_configuration_open(NULL); CHECK(0); break;
        case 13:
            set_hook(!api); prepare_bad = 1; start_api(api); CHECK(0); break;
        case 14:
            set_hook(!api); set_hook(api); CHECK(strcmp(trace, "EE") == 0);
            CHECK(fiber_internal_runtime_context_configuration_is_open() == 1); break;
        case 15:
            set_hook(!api); trace_size = 0; trace[0] = 0;
            start_api(api); CHECK(0); break; /* later NULL selection */
        case 16:
            fiber_internal_runtime_publish_current_context(NULL); CHECK(0); break;
        case 17:
            fiber_internal_runtime_require_context_configuration_open(candidate);
            CHECK(fiber_internal_runtime_context_configuration_is_open() == 1); break;
        case 18:
            set_hook(!api);
            expected_user = stack;
            if (api) modern_set(replacement_dispatch, stack); else legacy_set(replacement_dispatch, stack);
            trace_size = 0; trace[0] = 0;
            start_api(api); CHECK(0); break;
        default: CHECK(0);
        }
    } else if (result == 2) {
        CHECK((test == 4 || test == 15 || test == 18) && strcmp(trace, "PFHS") == 0);
        CHECK(hook_count == 1 && fiber_internal_runtime_context_configuration_is_open() == 0);
        if (test == 18) CHECK(replacement_hook_count == 1);
        if (test == 15) {
            FiberContext *original = candidate;
            candidate = NULL;
            if (setjmp(escape) == 0) { yield_api(!api); CHECK(0); }
            CHECK(panic_code == 'N' && hook_count == 2);
            CHECK(modern_current() == original && legacy_current() == original);
            printf("PASS host-mock scenario=%d checks=%u\n", scenario, checks);
            return 0;
        }
        expected_current = candidate; candidate = legacy_context();
        yield_api(!api);
        CHECK(modern_current() == candidate && legacy_current() == candidate);
        CHECK(hook_count == 2 && strcmp(trace, "PFHSYH") == 0);
        yield_api(api); /* next == current is valid; never require a distinct target */
        CHECK(modern_current() == candidate && legacy_current() == candidate);
        CHECK(hook_count == 3 && strcmp(trace, "PFHSYHYH") == 0);
        /* The same latches are observed after crossing both facade directions. */
        if (setjmp(escape) == 0) { set_hook(api); CHECK(0); }
        CHECK(panic_code == 'k');
        panic_code = 0;
        if (setjmp(escape) == 0) {
            if (api) modern_set(NULL, NULL); else legacy_set(NULL, NULL);
            CHECK(0);
        }
        CHECK(panic_code == 'k'); /* closed lifecycle precedes NULL callback */
        panic_code = 0;
        if (setjmp(escape) == 0) { start_api(!api); CHECK(0); }
        CHECK(panic_code == 'k');
        panic_code = 0;
        if (setjmp(escape) == 0) {
            fiber_internal_runtime_require_context_configuration_open(candidate); CHECK(0);
        }
        CHECK(panic_code == 'k');
    } else {
        static const char expected[] = {0, 'K', 'K', 'k', 0, 'K', 'i', 'N', 'k', 'k', 'G', 'R', 'n', 'p', 0, 0, 'N', 0, 0};
        CHECK(test >= 0 && test < 19 && panic_code == expected[test]);
        if (test == 1 || test == 2) CHECK(trace_size == 0);
        if (test == 3) CHECK(strcmp(trace, "E") == 0);
        if (test == 5 || test == 6) {
            CHECK(strcmp(trace, "E") == 0);
            CHECK(fiber_internal_scheduler_is_configured() == 0);
            CHECK(fiber_internal_runtime_context_configuration_is_open() == 1);
        }
        if (test == 7 || test == 8 || test == 9) {
            CHECK(hook_count == 1);
            CHECK(fiber_internal_runtime_context_configuration_is_open() == 0);
            panic_code = 0;
            if (setjmp(escape) == 0) { set_hook(!api); CHECK(0); }
            CHECK(panic_code == 'k');
        }
        if (test == 13) {
            CHECK(strcmp(trace, "EP") == 0 && hook_count == 0);
            CHECK(fiber_internal_runtime_context_configuration_is_open() == 0);
            panic_code = 0;
            if (setjmp(escape) == 0) { start_api(!api); CHECK(0); }
            CHECK(panic_code == 'k' && strcmp(trace, "EP") == 0);
        }
    }
    printf("PASS host-mock scenario=%d checks=%u\n", scenario, checks);
    return 0;
}
