#include "host_port.h"
#include "fiber_port_tfm_abi.h"
#include "fiber_port_tfm_os_wrapper.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t test_cpu[6];
unsigned test_barriers, test_mask_writes;
static unsigned checks, calls, schedules;
static int mode, change = -1, armed;
static jmp_buf terminal;
static char panic_code;
static FiberContext owners[2];
static FiberContext *current;
static void *mutex_handle;
static unsigned release_after = 1;
#define CHECK(c, id) do { ++checks; if (!(c)) { \
    fprintf(stderr, "FAIL:%s\n", id); exit(23); } } while (0)
#define PANIC(statement, code) do { armed = 1; \
    if (setjmp(terminal) == 0) { statement; CHECK(0, "missing-panic"); } \
    armed = 0; CHECK(panic_code == (code), "panic-code"); } while (0)
void fiber_panic(char code)
{
    if (!armed) { fprintf(stderr, "UNEXPECTED-PANIC:%c\n", code); exit(24); }
    panic_code = code;
    longjmp(terminal, 1);
}
FiberContext *fiber_current(void) { return current; }
void fiber_port_runtime_schedule(void)
{
    CHECK(test_cpu[1] == 0, "yield-unmasked");
    ++schedules;
    CHECK(schedules <= 4, "finite-wait-yield");
    if (schedules == release_after) {
        current = &owners[0];
        CHECK(os_wrapper_mutex_release(mutex_handle) == 0, "release-at-yield");
        current = &owners[1];
    }
}
uint32_t tfm_ns_interface_init(void)
{
    ++calls;
    CHECK(calls <= 2, "external-reentry");
    if (mode == 2) CHECK(fiber_port_tfm_initialize() == UINT32_MAX, "init-reentry");
    if (mode == 4) return fiber_port_tfm_initialize();
    if (change >= 0) test_cpu[change] ^= change == 4 ? 4u : 1u;
    if (mode == 1) return 17u;
    if (mode == 3) return UINT32_MAX;
    return 0;
}
static void masks_preserved(void)
{
    CHECK(test_cpu[0] == 0 && test_cpu[1] == 0 && test_cpu[2] == 0 &&
          test_cpu[3] == 0 && test_cpu[5] == 0, "masks-preserved");
}
static void create_mutex(void)
{
    mutex_handle = os_wrapper_mutex_create();
    CHECK(mutex_handle != NULL, "create");
    CHECK(os_wrapper_mutex_create() == NULL, "duplicate-create");
    test_cpu[4] = 2;
    current = &owners[0];
}
static void mutex_basic(void)
{
    create_mutex();
    CHECK(os_wrapper_mutex_acquire(NULL, 0) == UINT32_MAX, "null-acquire");
    CHECK(os_wrapper_mutex_acquire(&owners[0], 0) == UINT32_MAX, "foreign-acquire");
    CHECK(os_wrapper_mutex_release(mutex_handle) == UINT32_MAX, "unowned-release");
    const uint32_t timeouts[] = {0, 1, 42, UINT32_MAX - 1u, UINT32_MAX};
    for (size_t n = 0; n < sizeof(timeouts) / sizeof(timeouts[0]); ++n) {
        CHECK(os_wrapper_mutex_acquire(mutex_handle, timeouts[n]) == 0, "free-timeout");
        CHECK(os_wrapper_mutex_acquire(mutex_handle, timeouts[n]) == UINT32_MAX, "recursive");
        CHECK(os_wrapper_mutex_delete(mutex_handle) == UINT32_MAX, "delete-owned");
        current = &owners[1];
        CHECK(os_wrapper_mutex_release(mutex_handle) == UINT32_MAX, "foreign-release");
        if (timeouts[n] != UINT32_MAX) {
            unsigned before = schedules;
            CHECK(os_wrapper_mutex_acquire(mutex_handle, timeouts[n]) == UINT32_MAX, "finite-contended");
            CHECK(schedules == before, "finite-no-yield");
        }
        current = &owners[0];
        CHECK(os_wrapper_mutex_release(mutex_handle) == 0, "owner-release");
        CHECK(os_wrapper_mutex_release(mutex_handle) == UINT32_MAX, "double-release");
        masks_preserved();
    }
    CHECK(os_wrapper_mutex_release(NULL) == UINT32_MAX, "null-release");
    CHECK(os_wrapper_mutex_delete(NULL) == UINT32_MAX, "null-delete");
    CHECK(os_wrapper_mutex_delete(&owners[0]) == UINT32_MAX, "foreign-delete");
    CHECK(os_wrapper_mutex_delete(mutex_handle) == 0, "delete");
    CHECK(os_wrapper_mutex_delete(mutex_handle) == UINT32_MAX, "double-delete");
    CHECK(os_wrapper_mutex_acquire(mutex_handle, 0) == UINT32_MAX, "deleted-acquire");
    test_cpu[4] = 0;
    CHECK(os_wrapper_mutex_create() == mutex_handle, "recreate");
    CHECK(os_wrapper_mutex_delete(mutex_handle) == 0, "prestart-delete");
    CHECK(test_mask_writes > 0 && test_barriers > 0, "mask-boundary-exercised");
    masks_preserved();
}
int main(int argc, char **argv)
{
    CHECK(argc >= 2, "scenario-required");
    const char *s = argv[1];
    if (!strcmp(s, "init-ok") || !strcmp(s, "init-reentry")) {
        mode = !strcmp(s, "init-reentry") ? 2 : 0;
        test_cpu[4] = 4; test_cpu[5] = 0x1230; /* Full state is preserved, low CONTROL bits are admission policy. */
        CHECK(fiber_port_tfm_initialize() == 0, "init-success");
        CHECK(fiber_port_tfm_initialize() == 0 && calls == 1, "init-idempotent");
        fiber_port_tfm_require_initialized();
        CHECK(calls == 1 && test_cpu[4] == 4 && test_cpu[5] == 0x1230, "init-state-preserved");
    } else if (!strcmp(s, "init-require")) {
        mode = 1;
        PANIC(fiber_port_tfm_require_initialized(), 'Q');
        CHECK(calls == 1, "automatic-init-external-error");
        mode = 0;
        CHECK(fiber_port_tfm_initialize() == UINT32_MAX && calls == 1, "automatic-init-sticky");
    } else if (!strcmp(s, "init-error")) {
        mode = atoi(argv[2]);
        CHECK(fiber_port_tfm_initialize() == UINT32_MAX, "init-external-error");
        mode = 0;
        CHECK(fiber_port_tfm_initialize() == UINT32_MAX && calls == 1, "init-failed-sticky");
        PANIC(fiber_port_tfm_require_initialized(), 'Q');
        CHECK(calls == 1, "require-no-retry");
    } else if (!strcmp(s, "init-change")) {
        change = atoi(argv[2]);
        const char codes[] = "ipbflL";
        PANIC((void)fiber_port_tfm_initialize(), codes[change]);
        memset(test_cpu, 0, sizeof(test_cpu)); change = -1;
        CHECK(fiber_port_tfm_initialize() == UINT32_MAX && calls == 1, "init-interrupted-sticky");
    } else if (!strcmp(s, "init-admission")) {
        int slot = atoi(argv[2]); test_cpu[slot] = (uint32_t)strtoul(argv[3], NULL, 0);
        const char codes[] = "ipbfl";
        PANIC((void)fiber_port_tfm_initialize(), codes[slot]);
        CHECK(calls == 0 && test_barriers == 0, "init-no-effects");
        memset(test_cpu, 0, sizeof(test_cpu));
        CHECK(fiber_port_tfm_initialize() == 0 && calls == 1, "init-valid-retry");
    } else if (!strcmp(s, "mutex-basic")) {
        mutex_basic();
    } else if (!strcmp(s, "mutex-wait")) {
        release_after = (unsigned)atoi(argv[2]); create_mutex();
        CHECK(os_wrapper_mutex_acquire(mutex_handle, 0) == 0, "wait-owner");
        current = &owners[1];
        CHECK(os_wrapper_mutex_acquire(mutex_handle, UINT32_MAX) == 0, "wait-acquire");
        CHECK(schedules == release_after, "wait-count");
        CHECK(os_wrapper_mutex_release(mutex_handle) == 0, "waiter-owner");
        masks_preserved();
    } else if (!strcmp(s, "mutex-admission")) {
        volatile int operation = atoi(argv[2]), slot = atoi(argv[3]);
        if (operation != 0) create_mutex();
        unsigned writes = test_mask_writes;
        test_cpu[slot] = (uint32_t)strtoul(argv[4], NULL, 0);
        const char codes[] = "ipbfl";
        if (operation == 0) { PANIC((void)os_wrapper_mutex_create(), codes[slot]); }
        if (operation == 1) { PANIC((void)os_wrapper_mutex_acquire(mutex_handle, 0), codes[slot]); }
        if (operation == 2) { PANIC((void)os_wrapper_mutex_release(mutex_handle), codes[slot]); }
        if (operation == 3) { PANIC((void)os_wrapper_mutex_delete(mutex_handle), codes[slot]); }
        CHECK(test_mask_writes == writes && schedules == 0, "mutex-before-effects");
    } else if (!strcmp(s, "mutex-no-owner")) {
        create_mutex(); current = NULL;
        PANIC((void)os_wrapper_mutex_acquire(mutex_handle, 0), 'K');
        PANIC((void)os_wrapper_mutex_release(mutex_handle), 'K');
    } else { CHECK(0, "unknown-scenario"); }
    printf("PASS:C5TF-HOST:%s:%u\n", s, checks);
    return 0;
}
