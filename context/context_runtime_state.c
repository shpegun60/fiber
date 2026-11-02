/* Sole Context state owner. Historical service/slot names remain unchanged
 * at this ABI checkpoint. */
#include "context_runtime_state.h"
#include "context_panic.h"
#include "context_runtime_port_abi.h"

const unsigned char fiber_internal_runtime_port_abi_v1_anchor =
        (unsigned char)FIBER_RUNTIME_PORT_ABI_VERSION;

CtxrtContextV1 *volatile fiber_internal_runtime_current_context_slot
        __attribute__((section(".bss.fiber_runtime_current_context_slot"))) = 0;

static CtxrtDispatchFnV1 volatile
fiber_internal_runtime_scheduler_pick_next = 0;
static void *volatile fiber_internal_runtime_scheduler_user = 0;
static volatile uint32_t
fiber_internal_runtime_scheduler_first_selection_started = 0;
static volatile uint32_t
fiber_internal_runtime_context_configuration_closed = 0;

/* Cold registration retains its ordinary body contract. Sensitive/GRO
 * callers do not confer those protections on this helper transitively. */
void fiber_internal_scheduler_store_pick_next(CtxrtDispatchFnV1 pick_next,
        void *user)
{
    FIBER_REQUIRE(fiber_internal_runtime_current_context_slot == 0, 'k');
    FIBER_REQUIRE(
            fiber_internal_runtime_scheduler_first_selection_started == 0u,
            'k');
    FIBER_REQUIRE(pick_next != 0, 'K');

    fiber_port_runtime_memory_barrier();
    fiber_internal_runtime_scheduler_user = user;
    fiber_port_runtime_memory_barrier();
    fiber_internal_runtime_scheduler_pick_next = pick_next;
    fiber_port_runtime_memory_barrier();
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY CTXRT_API_THREAD_FUNCTION
CtxrtContextV1 *fiber_internal_runtime_load_current_context(void)
{
    fiber_port_runtime_memory_barrier();
    return fiber_internal_runtime_current_context_slot;
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(
        CtxrtContextV1 *current)
{
    const uint32_t first_selection = (current == 0) ? 1u : 0u;
    if (first_selection != 0u) {
        FIBER_REQUIRE(fiber_internal_runtime_current_context_slot == 0, 'k');
        FIBER_REQUIRE(
                fiber_internal_runtime_scheduler_first_selection_started == 0u,
                'k');
        FIBER_REQUIRE(fiber_internal_runtime_scheduler_pick_next != 0, 'K');

        fiber_port_runtime_memory_barrier();
        fiber_internal_runtime_scheduler_first_selection_started = 1u;
        fiber_port_runtime_memory_barrier();
    }

    CtxrtDispatchFnV1 const pick_next =
            fiber_internal_runtime_scheduler_pick_next;
    fiber_port_runtime_memory_barrier();
    void *const user = fiber_internal_runtime_scheduler_user;

    FIBER_REQUIRE(pick_next != 0, 'K');
    CtxrtContextV1 *const next = pick_next(current, user);
    FIBER_REQUIRE(next != 0, 'N');

    return next;
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next)
{
    FIBER_REQUIRE(next != 0, 'N');

    fiber_port_runtime_memory_barrier();
    fiber_internal_runtime_current_context_slot = next;
    fiber_port_runtime_memory_barrier();
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_current_context(void)
{
    fiber_port_runtime_memory_barrier();
    FIBER_REQUIRE(fiber_internal_runtime_current_context_slot != 0, 'G');
    fiber_port_runtime_memory_barrier();
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
uint32_t fiber_internal_scheduler_is_configured(void)
{
    fiber_port_runtime_memory_barrier();
    return (fiber_internal_runtime_scheduler_pick_next != 0) ? 1u : 0u;
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_runtime_close_context_configuration(void)
{
    fiber_port_runtime_memory_barrier();
    FIBER_REQUIRE(fiber_internal_runtime_context_configuration_closed == 0u,
            'k');
    fiber_internal_runtime_context_configuration_closed = 1u;
    fiber_port_runtime_memory_barrier();
}

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
uint32_t fiber_internal_runtime_context_configuration_is_open(void)
{
    fiber_port_runtime_memory_barrier();
    const uint32_t open =
            (fiber_internal_runtime_context_configuration_closed == 0u) &&
            (fiber_internal_runtime_current_context_slot == 0) &&
            (fiber_internal_runtime_scheduler_first_selection_started == 0u);
    fiber_port_runtime_memory_barrier();

    return open ? 1u : 0u;
}
