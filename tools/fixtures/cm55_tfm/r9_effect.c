#include "main.h"
#include "fiber_core.h"
#include "tfm_v2_boundary.h"
#include <stddef.h>

static FiberContext contexts[4];
enum { STACK_WORDS = 512 };
static uint32_t stacks[4][STACK_WORDS] __attribute__((aligned(8)));
static volatile uint32_t ram_calls, code_calls;
static volatile uint32_t active_seed, constructing;
static uint32_t initial_r9[4], saves[2], resumes[2], entries[2];
static uint32_t argument;
volatile uint32_t r9_instrument_calls, r9_coverage_calls, r9_gcov_calls, r9_tfm_calls;
extern uint32_t r9_call_init(FiberContext *, void *, void *, entry_t, void *, uint32_t);
extern void r9_task_a(void *), r9_task_b(void *);
/* Test-only address observation of the real common task-return policy. */
extern void fiber_internal_task_return(void);

static void emit(const char *text)
{
    register uint32_t r0 __asm("r0") = 4;
    register const char *r1 __asm("r1") = text;
    __asm volatile("bkpt 0xab" : "+r"(r0) : "r"(r1) : "memory");
}
static void hex(uint32_t value)
{
    char text[9];
    for (unsigned n = 0; n < 8; ++n) text[n] = "0123456789ABCDEF"[(value >> (28u - n * 4u)) & 15u];
    text[8] = 0; emit(text);
}
__attribute__((noreturn)) static void finish(uint32_t code, const char *message)
{
    emit(message);
    const uint32_t block[2] = {0x20026, code};
    register uint32_t r0 __asm("r0") = 0x20;
    register const void *r1 __asm("r1") = block;
    __asm volatile("bkpt 0xab" : "+r"(r0) : "r"(r1) : "memory");
    for (;;) { __asm volatile("wfe"); }
}
static void check(int condition, const char *id)
{
    if (!condition) { emit("FAIL:C5TF-R9:"); emit(id); finish(43, "\n"); }
}
__attribute__((noreturn)) void r9_fault_report(uint32_t token)
{
    emit("FAULT:C5TF-R9:IPSR="); hex(__get_IPSR());
    emit(" CFSR="); hex(SCB->CFSR); emit(" HFSR="); hex(SCB->HFSR);
    emit(" EXC_RETURN="); hex(token); finish(44, "\n");
}
__attribute__((noreturn)) void r9_unexpected_helper(void)
{ finish(45, "FAIL:C5TF-R9:UNEXPECTED-COMPILER-HELPER\n"); }
__attribute__((noreturn)) void r9_panic_report(char code, uintptr_t caller)
{
    emit("PANIC:C5TF-R9:code="); hex((unsigned char)code);
    emit(" caller="); hex((uint32_t)caller);
    emit(" frame="); hex(contexts[0].sp != NULL ? contexts[0].sp[7] : 0);
    emit(" IPSR="); hex(__get_IPSR()); finish(47, "\n");
}

/* The assembly caller passes the observation before a C prologue can reuse R9. */
__attribute__((noinline)) int r9_hook_ram(uintptr_t begin, uintptr_t end, uint32_t observed)
{
#ifdef R9_RESERVED
    if (constructing) check(observed == active_seed, "RAM-HOOK-STATIC-BASE");
#else
    check(observed == 0x1357cafe, "RAM-HOOK-R9");
#endif
    ++ram_calls;
    return begin >= 0x20010000 && end <= 0x20020000 && begin < end;
}
__attribute__((noinline)) int r9_hook_code(uintptr_t address, uintptr_t unused, uint32_t observed)
{
    (void)unused;
#ifdef R9_RESERVED
    if (constructing) check(observed == active_seed, "CODE-HOOK-STATIC-BASE");
#else
    check(observed == 0x2468beef, "CODE-HOOK-R9");
#endif
    ++code_calls;
    return address >= 0x10000 && address < 0x20000;
}
uint32_t tfm_ns_interface_init(void)
{ ++r9_tfm_calls; return os_wrapper_mutex_create() != NULL ? 0 : UINT32_MAX; }
static void entry(void *arg) { (void)arg; finish(46, "FAIL:C5TF-R9:TASK-EXECUTED\n"); }

static uint32_t live_r9(unsigned owner)
{
#ifdef R9_RESERVED
    return owner == 0 ? 0x13579bdf : 0x2468ace1;
#else
    return owner == 0 ? 0xa19a19a1 : 0xb29b29b2;
#endif
}
static void running(unsigned owner)
{
    check(owner < 2 && fiber_current() == &contexts[owner], "RUNNING-OWNER");
    check(__get_IPSR() == 0 && (__get_CONTROL() & 3) == 2 &&
          __get_PSPLIM() == contexts[owner].boot.stack_base, "RUNNING-STATE");
    check(__get_PRIMASK() == 0 && __get_BASEPRI() == 0 && __get_FAULTMASK() == 0, "RUNNING-MASKS");
}
void r9_task_enter(unsigned owner, uint32_t observed)
{
    running(owner);
    check(entries[owner]++ == 0 && observed == initial_r9[owner], "INITIAL-RESTORE-R9");
    emit("ENTER:C5TF:owner="); hex(owner); emit(" r9="); hex(observed); emit("\n");
}
void r9_task_resumed(unsigned owner, uint32_t observed)
{
    running(owner);
    check(observed == live_r9(owner), "RESTORED-R9");
    ++resumes[owner];
    emit("RESTORE:C5TF:owner="); hex(owner); emit(" r9="); hex(observed); emit("\n");
}
static FiberContext *pick(FiberContext *current_context, void *user)
{
    check(user == &argument, "SCHEDULER-USER");
    if (current_context == NULL) return &contexts[0];
    const unsigned owner = current_context == &contexts[0] ? 0 : 1;
    check(current_context == &contexts[owner] && __get_IPSR() == 14, "SAVED-OWNER");
    check(__get_BASEPRI() != 0 && __get_PRIMASK() == 0 && __get_FAULTMASK() == 0, "SELECTOR-MASKS");
    const uint32_t *frame = current_context->sp;
    check((uintptr_t)frame >= current_context->boot.stack_base &&
          (uintptr_t)(frame + 18) <= current_context->boot.stack_top && ((uintptr_t)frame & 7) == 0,
          "SAVED-FRAME-BOUNDS");
    check(frame[0] == current_context->boot.stack_base && frame[1] == 0xffffffbc &&
          (frame[17] & 0x01000000) != 0, "SAVED-FRAME-DICTIONARY");
    check(frame[7] == live_r9(owner), "SAVED-R9");
    ++saves[owner];
    emit("SAVE:C5TF:owner="); hex(owner); emit(" r9="); hex(frame[7]); emit("\n");
    return &contexts[owner ^ 1u];
}
__attribute__((noreturn)) void r9_runtime_done(void)
{
    running(0);
    check(entries[0] == 1 && entries[1] == 1 && saves[0] == 2 && saves[1] == 2 &&
          resumes[0] == 2 && resumes[1] == 1 && r9_tfm_calls == 1, "SAVE-RESTORE-COUNTS");
#ifdef R9_RESERVED
    finish(0, "PASS:C5TF-R9:RESERVED:4-SEEDS:4-PENDSV\n");
#else
    finish(0, "PASS:C5TF-R9:ORDINARY:4-SEEDS:4-PENDSV\n");
#endif
}

/* Retain the real common plus complete selected port, without invoking start. */
extern void fiber_port_runtime_prepare_start(void);
__attribute__((used, section(".proof_roots"))) static const uintptr_t roots[] = {
    (uintptr_t)fiber_current, (uintptr_t)fiber_start, (uintptr_t)fiber_schedule,
    (uintptr_t)fiber_scheduler_set_pick_next, (uintptr_t)fiber_port_runtime_prepare_start,
    (uintptr_t)os_wrapper_mutex_acquire, (uintptr_t)os_wrapper_mutex_release,
    (uintptr_t)os_wrapper_mutex_delete
};
__attribute__((noreturn)) void r9_ns_main(void)
{
    check(__get_IPSR() == 0 && (__get_CONTROL() & 3) == 0, "ORIGIN");
    check(SCB->VTOR == 0x10000 && __get_MSP() > 0x2001c000 && __get_MSP() <= 0x20020000, "NS-BANK");
    check(__get_PRIMASK() == 0 && __get_BASEPRI() == 0 && __get_FAULTMASK() == 0, "MASKS");
    extern void (*__init_begin[])(void), (*__init_end[])(void);
    for (void (**p)(void) = __init_begin; p < __init_end; ++p) (*p)();
#ifdef R9_MODEL_PROBE
    volatile uint8_t *const priority = (volatile uint8_t *)(uintptr_t)0xe000e400;
    const uint8_t saved_priority = *priority;
    *priority = 0xff; __DSB(); __ISB();
    const uint32_t mask = *priority;
    *priority = saved_priority; __DSB(); __ISB();
    emit("MODEL:C5TF:PRIORITY="); hex(mask);
    finish(0, "\nPASS:C5TF-R9:MODEL\n");
#endif
    const uint32_t seeds[4] = {0x13579bdf, 0x2468ace1, 0x90abcdef, 0x0badcafe};
    for (unsigned n = 0; n < 4; ++n) {
        for (unsigned k = 0; k < STACK_WORDS; ++k) stacks[n][k] = 0xa5a5a5a5;
        const entry_t task = n == 0 ? r9_task_a : (n == 1 ? r9_task_b : entry);
        active_seed = seeds[n]; constructing = 1;
        const uint32_t post = r9_call_init(&contexts[n], stacks[n], stacks[n] + STACK_WORDS, task, &argument, seeds[n]);
        constructing = 0;
#ifdef R9_HOSTILE
        check(r9_instrument_calls > 0 && r9_coverage_calls > 0 && r9_gcov_calls > 0, "HOSTILE-NOT-EFFECTIVE");
#endif
        const uint32_t *const frame = stacks[n] + STACK_WORDS - 18;
        emit("R9:C5TF:seed="); hex(seeds[n]); emit(" frame="); hex(frame[7]); emit(" post="); hex(post); emit("\n");
        check(contexts[n].sp == frame, "FRAME-POINTER");
        check(post == seeds[n], "RETURN-R9");
#ifdef R9_RESERVED
        check(frame[7] == seeds[n], "FRAME-R9");
#endif
        initial_r9[n] = frame[7];
        check(frame[1] == 0xffffffbc && frame[10] == (uint32_t)(uintptr_t)&argument && frame[17] == 0x01000000,
              "FRAME-DICTIONARY");
        check(frame[0] == contexts[n].boot.stack_base && frame[0] > (uint32_t)(uintptr_t)stacks[n] &&
              frame[0] < (uint32_t)(uintptr_t)frame &&
              frame[16] == ((uint32_t)(uintptr_t)task & ~1u) &&
              frame[15] == ((uint32_t)(uintptr_t)fiber_internal_task_return | 1u), "FRAME-PROVENANCE");
        check(frame[2] == 0 && frame[3] == 0 && frame[4] == 0 && frame[5] == 0 && frame[6] == 0 &&
              frame[8] == 0 && frame[9] == 0 && frame[11] == 0 && frame[12] == 0 && frame[13] == 0 &&
              frame[14] == 0, "FRAME-ZERO-REGISTERS");
        check(__get_IPSR() == 0 && (__get_CONTROL() & 3) == 0 && __get_PRIMASK() == 0 &&
              __get_BASEPRI() == 0 && __get_FAULTMASK() == 0, "POST-STATE");
    }
    check(ram_calls >= 8 && code_calls >= 4, "HOOKS-NOT-EXECUTED");
    check(r9_tfm_calls == 0 && fiber_current() == NULL, "RUNTIME-ACTIVATED");
#ifdef R9_HOSTILE
    check(r9_instrument_calls > 0 && r9_coverage_calls > 0 && r9_gcov_calls > 0, "HOSTILE-NOT-EFFECTIVE");
#endif
    fiber_scheduler_set_pick_next(pick, &argument);
    fiber_start();
}

/* Deliberately bounded compiler-boundary fixtures, not production runtimes. */
#define BOUNDARY __attribute__((used, externally_visible, noinline))
__attribute__((used, externally_visible)) const uintptr_t __stack_chk_guard = 0xa7b7c7d7;
BOUNDARY
void __cyg_profile_func_enter(void *function, void *caller)
{ (void)function; (void)caller; ++r9_instrument_calls; }
BOUNDARY void __cyg_profile_func_exit(void *function, void *caller)
{ (void)function; (void)caller; ++r9_instrument_calls; }
BOUNDARY void __sanitizer_cov_trace_pc(void) { ++r9_coverage_calls; }
BOUNDARY void __gcov_init(void *info) { (void)info; ++r9_gcov_calls; }
BOUNDARY void __gcov_exit(void) { r9_unexpected_helper(); }
BOUNDARY void __gcov_merge_add(long long *values, unsigned count)
{ (void)values; (void)count; r9_unexpected_helper(); }
BOUNDARY void __stack_chk_fail(void) { r9_unexpected_helper(); }
#define UBSAN2(name) BOUNDARY void name(void *data, void *value) \
    { (void)data; (void)value; r9_unexpected_helper(); }
#define UBSAN3(name) BOUNDARY void name(void *data, void *left, void *right) \
    { (void)data; (void)left; (void)right; r9_unexpected_helper(); }
UBSAN2(__ubsan_handle_type_mismatch_v1)
UBSAN2(__ubsan_handle_out_of_bounds)
UBSAN2(__ubsan_handle_load_invalid_value)
UBSAN3(__ubsan_handle_pointer_overflow)
UBSAN3(__ubsan_handle_add_overflow)
UBSAN3(__ubsan_handle_sub_overflow)
UBSAN3(__ubsan_handle_mul_overflow)
UBSAN3(__ubsan_handle_shift_out_of_bounds)
BOUNDARY void __ubsan_handle_nonnull_arg(void *data) { (void)data; r9_unexpected_helper(); }
BOUNDARY void __ubsan_handle_builtin_unreachable(void *data) { (void)data; r9_unexpected_helper(); }
