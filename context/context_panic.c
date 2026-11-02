/* Context-owned fallback; only this definition is weak.
 * WEAK/UNREACHABLE still use the unchanged shared compiler policy; physical
 * canonical-attribute extraction is deliberately deferred. */
#include "context_panic.h"
#include "context_port_abi.h"

static volatile char fiber_internal_fallback_panic_code = 0;

FIBER_API_WEAK CTXRT_API_NORETURN CTXRT_GENERAL_REGS_ONLY
CTXRT_API_ATTR_SENSITIVE
void fiber_panic(char code)
{
    fiber_internal_fallback_panic_code = code;
    fiber_port_runtime_memory_barrier();
    fiber_port_panic_wait();
    FIBER_API_UNREACHABLE();
}
