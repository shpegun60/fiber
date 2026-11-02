/* Optional Context owner; mandatory Context objects do not depend on this unit. */
#include "context_configuration_abi.h"
#include "context_panic.h"
#include "context_runtime_state.h"

const unsigned char fiber_internal_runtime_context_configuration_abi_v1_anchor =
        (unsigned char)FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_VERSION;

CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_context_configuration_open(
        const CtxrtContextV1 *const ctx)
{
    FIBER_REQUIRE(ctx != 0, 'n');
    FIBER_REQUIRE(fiber_internal_runtime_context_configuration_is_open() != 0u,
            'k');
}
