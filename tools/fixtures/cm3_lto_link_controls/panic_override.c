/* Strong application override for the bounded CM3 LTO link control. */
#include "context/context_panic.h"

__attribute__((used, externally_visible))
volatile char cm3_lto_panic_override_code = 0;

CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
__attribute__((externally_visible))
void fiber_panic(char code)
{
    cm3_lto_panic_override_code = code;
    __asm__ volatile ("udf #0" ::: "memory");
    for (;;) {
        __asm__ volatile ("" ::: "memory");
    }
}
