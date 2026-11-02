/* Executes production lifecycle + the explicitly role-selected singleton.
 * Only the eight forward CPU operations are fake. No target CPU claim. */
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include "fiber/lifecycle/fiber_v1_privileged.h"
#include "mixed_api.h"
#if USE_LEGACY
#include "fiber/fiber_runtime_port_abi.h"
#include "fiber/fiber_runtime_state.h"
#include "fiber/port/fiber_port_runtime_abi.h"
#else
#include "context/context_runtime_port_abi.h"
#include "context/context_runtime_state.h"
#include "context/context_port_abi.h"
#endif

const unsigned char FIBER_PORT_STORAGE_COHORT_SYMBOL = 1;
static jmp_buf caught;
static int event, checks, init_calls, prepare_calls, select_calls, start_calls;
static int barriers, schedule_calls, policy_calls, environment_failure;
static int prepare_failure, constructor_failure, entry_calls, dispatch_on_yield;
static FiberV1 a = FIBER_V1_INITIALIZER, b = FIBER_V1_INITIALIZER;
static FiberRuntimeV1 runtime = FIBER_RUNTIME_V1_INITIALIZER;
static unsigned char stack_a[1024], stack_b[1024];
static FiberV1 *chosen, *expected_previous;
static void *expected_user;
static void *seen_begin, *seen_end, *seen_arg;
static CtxrtEntryFnV1 seen_entry;
struct Arena { unsigned char prefix[2048]; FiberV1 fiber; unsigned char suffix[2048]; };
static void overflow_dereference(int sig)
{ (void)sig; fputs("FAIL:OVERFLOW_DEREFERENCE\n", stderr); _Exit(90); }
static int current_matches(FiberV1 *expected)
{
    const CtxrtContextV1 *context = (const CtxrtContextV1 *)(void *)expected;
    int match = fiber_v1_current() == expected && ctxrt_v1_current() == context;
#if USE_LEGACY
    match = match && fiber_current() == context;
#endif
    return match;
}

static void check(int condition, const char *name)
{
    ++checks;
    if (!condition) { fprintf(stderr, "FAIL:%s\n", name); exit(90); }
}
#define CHECK(c, n) check((c), (n))
#define EXPECT(code, action) do { event = 0; if (setjmp(caught) == 0) { action; } \
    CHECK(event == (code), "EVENT"); } while (0)

void fiber_panic(char code) { event = (unsigned char)code; longjmp(caught, 1); }
void fiber_port_panic_wait(void) { event = '!'; longjmp(caught, 1); }
void fiber_port_runtime_memory_barrier(void) { ++barriers; }
void fiber_port_require_scheduler_configuration_environment(void)
{ if (environment_failure) fiber_panic('E'); }
void fiber_port_context_init(CtxrtContextV1 *ctx, void *begin, void *end,
                             CtxrtEntryFnV1 entry, void *arg)
{
    ++init_calls;
    seen_begin = begin; seen_end = end; seen_entry = entry; seen_arg = arg;
    if (constructor_failure) fiber_panic('B');
    /* Deliberately validates only Context, not its consumer's lifetime tail. */
    const uintptr_t c = (uintptr_t)ctx, lo = (uintptr_t)begin, hi = (uintptr_t)end;
    if (!begin || hi <= lo || hi - lo < 128u || !entry) fiber_panic('s');
    if (c < hi && lo < c + sizeof(*ctx)) fiber_panic('C');
    memset(ctx, 0x5a, sizeof(*ctx));
}
void fiber_port_runtime_prepare_start(void)
{
    ++prepare_calls;
    CHECK(fiber_internal_runtime_context_configuration_is_open() == 0u, "CLOSED_BEFORE_CPU");
    if (prepare_failure) fiber_panic('P');
}
CtxrtContextV1 *fiber_port_runtime_select_first(void)
{ ++select_calls; return fiber_internal_runtime_select_scheduler_candidate(NULL); }
void fiber_port_runtime_start_first(CtxrtContextV1 *first)
{
    ++start_calls;
    CHECK(first == ctxrt_v1_current(), "PUBLISHED_BEFORE_CPU");
    event = 256; longjmp(caught, 1); /* selection complete, no entry executed */
}
void fiber_port_runtime_schedule(void)
{
    ++schedule_calls;
    if (dispatch_on_yield) {
        CtxrtContextV1 *next = fiber_internal_runtime_select_scheduler_candidate(ctxrt_v1_current());
        fiber_internal_runtime_publish_current_context(next);
    }
}
static void entry(void *arg) { (void)arg; ++entry_calls; }
static FIBER_V1_SELECT_ATTR FiberV1 *policy(FiberV1 *current, void *user)
{
    ++policy_calls;
    CHECK(current == expected_previous, "POLICY_CURRENT");
    CHECK(user == expected_user, "POLICY_USER");
    return chosen;
}
static FIBER_V1_SELECT_ATTR FiberV1 *other_policy(FiberV1 *current, void *user)
{ (void)current; (void)user; fiber_panic('X'); }
static void initialize(void)
{
    fiber_v1_init(&a, stack_a, stack_a + sizeof(stack_a), entry, &a);
    fiber_v1_init(&b, stack_b, stack_b + sizeof(stack_b), entry, &b);
}
static void install(void)
{
    expected_user = &b; expected_previous = NULL; chosen = &a;
    fiber_v1_set_scheduler(&runtime, policy, expected_user);
}
static void start(void) { EXPECT(256, fiber_v1_start()); }

int main(int argc, char **argv)
{
    if (argc != 2) return 91;
    const int test = atoi(argv[1]);
    switch (test) {
    case 0:
        CHECK(current_matches(NULL), "ONE_NULL_CURRENT");
        initialize();
        CHECK(a.private_state == FIBER_V1_INITIALIZED && b.private_state == FIBER_V1_INITIALIZED, "INITIALIZED");
        CHECK(seen_begin == stack_b && seen_end == stack_b + sizeof(stack_b) && seen_entry == entry && seen_arg == &b, "DIRECT_ENTRY");
        CHECK(fiber_v1_context_privileged(&a) == (CtxrtContextV1 *)(void *)&a && fiber_v1_context_privileged(NULL) == NULL, "TYPED_PREFIX");
        CHECK(entry_calls == 0 && prepare_calls == 0 && start_calls == 0 && schedule_calls == 0, "COLD_NO_TRANSFER");
        break;
    case 1: EXPECT('n', fiber_v1_init(NULL, stack_a, stack_a + sizeof(stack_a), entry, NULL)); CHECK(init_calls == 0, "NULL_NO_WRITE"); break;
    case 2: a.private_state = FIBER_V1_INITIALIZED; EXPECT('L', fiber_v1_init(&a, stack_a, stack_a + sizeof(stack_a), entry, NULL)); CHECK(init_calls == 0, "STATE_NO_WRITE"); break;
    case 3: a.private_state = FIBER_V1_STARTED; EXPECT('L', fiber_v1_init(&a, stack_a, stack_a + sizeof(stack_a), entry, NULL)); CHECK(init_calls == 0, "STATE_NO_WRITE"); break;
    case 4: a.private_state = 99; EXPECT('L', fiber_v1_init(&a, stack_a, stack_a + sizeof(stack_a), entry, NULL)); CHECK(init_calls == 0, "STATE_NO_WRITE"); break;
    case 5:
        signal(SIGSEGV, overflow_dereference);
        EXPECT('O', fiber_v1_init((FiberV1 *)(UINTPTR_MAX - sizeof(FiberV1) + 1u), stack_a, stack_a + sizeof(stack_a), entry, NULL));
        CHECK(init_calls == 0, "OVERFLOW_NO_WRITE"); break;
    case 6: {
        struct Arena arena;
        memset(&arena, 0, sizeof(arena));
        FiberV1 *f = &arena.fiber;
        unsigned char before[sizeof(arena)]; memcpy(before, &arena, sizeof(arena));
        CHECK(sizeof(FiberV1) > sizeof(CtxrtContextV1), "TAIL_EXISTS");
        void *lo = (unsigned char *)&arena + offsetof(struct Arena, fiber) + sizeof(CtxrtContextV1);
        event = 0;
        if (setjmp(caught) == 0) fiber_v1_init(f, lo, (unsigned char *)lo + 1024, entry, NULL);
        CHECK(init_calls == 0 && memcmp(before, &arena, sizeof(arena)) == 0, "TAIL_NO_WRITE");
        CHECK(event == 'C', "TAIL_CODE");
        break;
    }
    case 7: case 8: {
        struct Arena arena;
        memset(&arena, 0, sizeof(arena));
        FiberV1 *f = &arena.fiber;
        unsigned char *bytes = (unsigned char *)&arena;
        void *lo = test == 7 ? (void *)(bytes + offsetof(struct Arena, fiber) - 1024) : (void *)(bytes + offsetof(struct Arena, fiber) + sizeof(*f));
        void *hi = test == 7 ? (void *)f : (void *)((unsigned char *)lo + 1024);
        fiber_v1_init(f, lo, hi, entry, NULL);
        CHECK(init_calls == 1 && f->private_state == FIBER_V1_INITIALIZED, "HALF_OPEN_DISJOINT");
        break;
    }
    case 9:
        constructor_failure = 1; EXPECT('B', fiber_v1_init(&a, stack_a, stack_a + sizeof(stack_a), entry, NULL));
        CHECK(a.private_state == FIBER_V1_EMPTY, "FAILED_INIT_EMPTY"); break;
    case 10: EXPECT('s', fiber_v1_init(&a, NULL, NULL, entry, NULL)); CHECK(init_calls == 1 && a.private_state == FIBER_V1_EMPTY, "DELEGATED_STACK"); break;
    case 11: EXPECT('s', fiber_v1_init(&a, stack_a, stack_a + sizeof(stack_a), NULL, NULL)); CHECK(a.private_state == FIBER_V1_EMPTY, "DELEGATED_ENTRY"); break;
    case 12: EXPECT('n', fiber_v1_set_scheduler(NULL, policy, NULL)); break;
    case 13: EXPECT('K', fiber_v1_set_scheduler(&runtime, NULL, NULL)); CHECK(runtime.private_select == NULL && runtime.private_user == NULL, "FAILED_INSTALL_UNCHANGED"); break;
    case 14: EXPECT('K', fiber_v1_set_scheduler(NULL, NULL, NULL)); break;
    case 15: EXPECT('K', fiber_v1_start()); CHECK(prepare_calls == 0, "UNCONFIGURED_START"); break;
    case 16:
        initialize(); install(); start();
        CHECK(a.private_state == FIBER_V1_STARTED && b.private_state == FIBER_V1_INITIALIZED && entry_calls == 0, "SELECTED_NOT_ENTERED");
        CHECK(current_matches(&a), "ONE_CURRENT");
        CHECK(policy_calls == 1 && select_calls == 1 && start_calls == 1, "ONE_POLICY"); break;
    case 17:
        initialize(); install(); start(); expected_previous = &a; chosen = &b; dispatch_on_yield = 1;
        fiber_v1_yield(); CHECK(fiber_v1_current() == &b && b.private_state == FIBER_V1_STARTED, "SWITCH_NEXT");
        expected_previous = &b; chosen = &a; fiber_v1_yield();
        CHECK(fiber_v1_current() == &a && policy_calls == 3 && entry_calls == 0, "RESELECT_STARTED"); break;
    case 18:
        initialize(); install(); start(); {
        FiberRuntimeV1 before = runtime;
        EXPECT('k', fiber_v1_set_scheduler(&runtime, other_policy, &a));
        CHECK(memcmp(&before, &runtime, sizeof(runtime)) == 0, "HOTSWAP_UNCHANGED");
        expected_previous = &a; chosen = &b; dispatch_on_yield = 1; fiber_v1_yield();
        CHECK(fiber_v1_current() == &b, "ORIGINAL_POLICY_RETAINED"); } break;
    case 19:
        initialize(); install(); prepare_failure = 1; EXPECT('P', fiber_v1_start());
        CHECK(fiber_v1_current() == NULL && select_calls == 0, "FAILED_START_NULL_CURRENT"); {
        FiberV1 fresh = FIBER_V1_INITIALIZER;
        int before = init_calls;
        event = 0;
        if (setjmp(caught) == 0) fiber_v1_init(&fresh, stack_a, stack_a + sizeof(stack_a), entry, NULL);
        CHECK(init_calls == before && fresh.private_state == FIBER_V1_EMPTY, "FAILED_START_CONFIG_CLOSED");
        CHECK(event == 'k', "FAILED_START_CODE"); } break;
    case 20:
        initialize(); install(); chosen = NULL; EXPECT('N', fiber_v1_start());
        CHECK(fiber_v1_current() == NULL && start_calls == 0, "NULL_CHOICE"); break;
    case 21: case 22:
        initialize(); install(); a.private_state = test == 21 ? FIBER_V1_EMPTY : 99;
        EXPECT('L', fiber_v1_start()); CHECK(fiber_v1_current() == NULL, "BAD_NEXT_NOT_PUBLISHED"); break;
    case 23:
        initialize(); install(); start(); expected_previous = &a; chosen = &b; a.private_state = FIBER_V1_INITIALIZED; dispatch_on_yield = 1;
        EXPECT('L', fiber_v1_yield()); CHECK(policy_calls == 1, "BAD_PREVIOUS_NO_POLICY"); break;
    case 24:
        initialize(); install(); start(); a.private_state = 99; runtime.private_select = NULL; runtime.private_user = NULL;
        CHECK(fiber_v1_current() == &a, "CURRENT_IDENTITY_ONLY"); fiber_v1_yield();
        CHECK(schedule_calls == 1 && policy_calls == 1 && a.private_state == 99, "YIELD_REQUEST_ONLY"); break;
    case 25:
        install(); chosen = NULL; EXPECT('N', fiber_v1_start()); {
        FiberRuntimeV1 before = runtime; EXPECT('k', fiber_v1_set_scheduler(&runtime, other_policy, &a));
        CHECK(memcmp(&before, &runtime, sizeof(runtime)) == 0, "FAILED_START_HOTSWAP_UNCHANGED"); } break;
    case 26:
        initialize(); fiber_v1_set_scheduler(&runtime, other_policy, &a); install(); start();
        CHECK(policy_calls == 1 && runtime.private_select == policy && runtime.private_user == expected_user, "COLD_REPLACE"); break;
    case 27:
        runtime.private_select = other_policy; runtime.private_user = &a; environment_failure = 1; {
        FiberRuntimeV1 before = runtime; EXPECT('E', fiber_v1_set_scheduler(&runtime, policy, &b));
        CHECK(memcmp(&before, &runtime, sizeof(runtime)) == 0, "ENV_FAILURE_UNCHANGED"); } break;
    case 28:
        initialize(); install(); start(); EXPECT('k', fiber_v1_start()); CHECK(prepare_calls == 1, "NO_SECOND_START"); break;
    case 29:
        initialize(); install(); runtime.private_select = NULL; EXPECT('K', fiber_v1_start()); CHECK(policy_calls == 0, "NULL_STORED_POLICY"); break;
    case 30:
        initialize(); install(); start(); expected_previous = &a; chosen = &a; dispatch_on_yield = 1;
        fiber_v1_yield(); CHECK(fiber_v1_current() == &a && a.private_state == FIBER_V1_STARTED, "SELF_SELECT"); break;
    default: return 92;
    }
    printf("PASS host-mock scenario=%d checks=%d\n", test, checks);
    return 0;
}
