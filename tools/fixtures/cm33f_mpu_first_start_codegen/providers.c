/* Focused first-start dependencies, not a complete common runtime. */
#include "fiber_port_private.h"
#include "fiber/fiber_runtime_port_abi.h"

_Static_assert(FIBER_PORT_RUNTIME_SELECTABLE == 1, "complete runtime metadata");
_Static_assert(sizeof(FiberPortProtectedContext) == 54u * 4u, "54-word backing");
_Static_assert(offsetof(FiberPortProtectedBasicContext, cursor_limit) == 20u * 4u,
        "basic restore consumes 20 words, not the backing capacity");

/* The actual production SVC object owns the exact context/storage providers. */
_Static_assert(FIBER_RUNTIME_PORT_ABI_VERSION == 1u,
        "fixture provides reverse ABI v1 only");
const unsigned char fiber_internal_runtime_port_abi_v1_anchor = 1u;
FIBER_USED __attribute__((section(".bss.fiber_runtime_current_context_slot")))
FiberContext *volatile fiber_internal_runtime_current_context_slot;

FIBER_USED fiber_portPRIVILEGED_DATA FiberContext codegen_context;
FIBER_USED __attribute__((section(".fixture_user_stack"), aligned(32)))
unsigned char codegen_stack[2048];

FIBER_API_NORETURN FIBER_SCHEDULER_HOOK_ATTR fiber_portPRIVILEGED_FUNCTION
void fiber_panic(char code)
{
    (void)code;
    for (;;) { __asm volatile ("udf #1"); }
}

/* Match the common task-return policy; never shadow the production SVC72 veneer. */
FIBER_API_NORETURN FIBER_SCHEDULER_HOOK_ATTR fiber_portPRIVILEGED_FUNCTION
void fiber_internal_task_return(void)
{
    fiber_panic('R');
}

/* No scheduler is configured in this first-start-only fixture. */
FIBER_SCHEDULER_HOOK_ATTR fiber_portPRIVILEGED_FUNCTION
FiberContext *fiber_internal_runtime_select_scheduler_candidate(FiberContext *current)
{
    (void)current;
    fiber_panic('K');
}

FIBER_SCHEDULER_HOOK_ATTR fiber_portPRIVILEGED_FUNCTION
void fiber_internal_runtime_publish_current_context(FiberContext *next)
{
    FIBER_REQUIRE(next != NULL, 'N');
    __asm volatile ("dmb" ::: "memory");
    fiber_internal_runtime_current_context_slot = next;
    __asm volatile ("dmb" ::: "memory");
}

FIBER_SCHEDULER_HOOK_ATTR fiber_portPRIVILEGED_FUNCTION
void fiber_internal_runtime_require_current_context(void)
{
    __asm volatile ("dmb" ::: "memory");
    FIBER_REQUIRE(fiber_internal_runtime_current_context_slot != NULL, 'C');
    __asm volatile ("dmb" ::: "memory");
}

/* Placement-only public-name dependencies. These conspicuously named terminal
 * fixtures are never called; they cannot masquerade as usable public runtime. */
FIBER_API_NORETURN FIBER_SCHEDULER_HOOK_ATTR FIBER_API_THREAD_FUNCTION
FiberContext *fixture_unexecuted_fiber_current(void) __asm__("fiber_current");
FIBER_API_NORETURN FIBER_SCHEDULER_HOOK_ATTR FIBER_API_THREAD_FUNCTION
FiberContext *fixture_unexecuted_fiber_current(void)
{
    for (;;) { __asm volatile ("udf #73"); }
}

FIBER_API_NORETURN FIBER_SCHEDULER_HOOK_ATTR FIBER_API_THREAD_FUNCTION
void fixture_unexecuted_fiber_schedule(void) __asm__("fiber_schedule");
FIBER_API_NORETURN FIBER_SCHEDULER_HOOK_ATTR FIBER_API_THREAD_FUNCTION
void fixture_unexecuted_fiber_schedule(void)
{
    for (;;) { __asm volatile ("udf #74"); }
}

FIBER_SCHEDULER_HOOK_ATTR fiber_portUNPRIVILEGED_FUNCTION
void codegen_task(void *argument)
{
    (void)argument;
    for (;;) { __asm volatile ("nop"); }
}

FIBER_USED __attribute__((section(".proof_geometry")))
const uint32_t codegen_geometry[] = {
    sizeof(FiberPortProtectedContext) / 4u,
    offsetof(FiberPortProtectedBasicContext, cursor_limit) / 4u,
    sizeof(FiberContext), offsetof(FiberContext, protected_context),
    fiber_portINITIAL_CONTROL_UNPRIVILEGED,
    fiber_portSVC_ORIGIN_EXC_RETURN, fiber_portINITIAL_EXC_RETURN,
    FIBER_PORT_CM33F_MPU_TOTAL_REGIONS, FIBER_PORT_RUNTIME_SELECTABLE
};

FIBER_USED __attribute__((section(".proof_geometry")))
const void *const codegen_cohort_identities[] = {
    &FIBER_PORT_CONTEXT_COHORT_SYMBOL, &FIBER_PORT_STORAGE_COHORT_SYMBOL
};

FIBER_USED __attribute__((section(".proof_roots")))
const void *const codegen_roots[] = {
    (const void *)&fiber_port_start_first_context,
    (const void *)&fiber_port_context_init,
    (const void *)&fiber_port_runtime_memory_barrier,
    (const void *)&fiber_port_panic_wait,
    (const void *)&fiber_port_require_scheduler_configuration_environment,
    (const void *)&fiber_port_runtime_prepare_start,
    (const void *)&fiber_port_runtime_select_first,
    (const void *)&fiber_port_runtime_start_first,
    (const void *)&fiber_port_runtime_schedule,
    (const void *)&fiber_port_handler_bundle_v1_anchor,
    (const void *)&codegen_task, (const void *)&codegen_context,
    (const void *)&codegen_stack, (const void *)&codegen_geometry
};

/* Both vectors reference real production handlers, not fixture replacements. */
FIBER_USED __attribute__((section(".proof_vectors"), aligned(2048)))
const uintptr_t codegen_vectors[512] = {
    [0] = 0x30010000u, [11] = (uintptr_t)&SVC_Handler,
    [14] = (uintptr_t)&PendSV_Handler
};
