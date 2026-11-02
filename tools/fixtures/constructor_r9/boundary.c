#include <stddef.h>
#include <stdint.h>
#include "fiber_api_attributes.h"

/* Fixture boundaries only; no constructor or frame-builder replacement. */
volatile uint32_t r9_instrument_calls, r9_coverage_calls, r9_gcov_calls;
const uintptr_t __stack_chk_guard = 0xA7B7C7D7u;

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(const char code)
{
    (void)code;
    __builtin_trap();
    for (;;) { }
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int r9_ram_policy(const uintptr_t begin, const uintptr_t end)
{
    return begin >= 0x20000000u && end <= 0x20030000u && begin < end;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int r9_code_policy(const uintptr_t address)
{
    return address >= 0x08000000u && address < 0x08040000u;
}

__attribute__((noinline, used, externally_visible))
void __cyg_profile_func_enter(void *function, void *caller)
{
    (void)function; (void)caller; ++r9_instrument_calls;
}
__attribute__((noinline, used, externally_visible))
void __cyg_profile_func_exit(void *function, void *caller)
{
    (void)function; (void)caller; ++r9_instrument_calls;
}
__attribute__((noinline, used, externally_visible))
void __sanitizer_cov_trace_pc(void) { ++r9_coverage_calls; }
__attribute__((noinline, used, externally_visible))
void __gcov_init(void *info) { (void)info; ++r9_gcov_calls; }
__attribute__((noinline, used, externally_visible))
void __gcov_exit(void) { ++r9_gcov_calls; }
__attribute__((noinline, used, externally_visible))
void __gcov_merge_add(void *values, unsigned count)
{
    (void)values; (void)count; ++r9_gcov_calls;
}

__attribute__((noreturn, noinline, used, externally_visible))
void __stack_chk_fail(void) { __builtin_trap(); for (;;) { } }

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void r9_task_entry(void *arg) { (void)arg; __builtin_trap(); for (;;) { } }
