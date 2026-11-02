#include "fiber_port_boot.h"
#include "fiber_port_storage_cohort_expectation.h"
#include "fiber/fiber_runtime_port_abi.h"

/* Constructor-only link: deliberately do not link the production SVC/PendSV
 * objects. This fixture, not a second runtime provider, owns both bytes here. */
FIBER_PORT_CONTEXT_COHORT_DEFINE();
_Static_assert(FIBER_RUNTIME_PORT_ABI_VERSION == 1u,
        "fixture provides reverse ABI v1 only");
const unsigned char fiber_internal_runtime_port_abi_v1_anchor = 1u;

FIBER_USED fiber_portPRIVILEGED_DATA
FiberContext constructor_fixture_context;
FIBER_USED fiber_portPRIVILEGED_DATA
uint32_t constructor_fixture_scratch[64];

/* Disjoint from privileged RW BSS; real startup must zero both sections. */
FIBER_USED __attribute__((section(".bss.fiber_runtime_current_context_slot")))
FiberContext * volatile fiber_internal_runtime_current_context_slot;

FIBER_USED __attribute__((aligned(32), section(".fixture_user_stack")))
unsigned char constructor_fixture_stack[2048];

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portUNPRIVILEGED_FUNCTION
void constructor_fixture_task(void *argument)
{
    __asm volatile ("" : : "r" (argument) : "memory");
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portSYSCALL_FUNCTION
void fiber_port_unprivileged_task_return(void)
{
    for (;;) { __asm volatile ("udf #0"); }
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_panic(char code)
{
    (void)code;
    for (;;) { __asm volatile ("udf #1"); }
}
