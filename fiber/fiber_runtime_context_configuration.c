/*
 * fiber_runtime_context_configuration.c
 *
 * Optional common-owned lifecycle guard. It deliberately knows no selected
 * context layout, CPU register, scheduler callback, or port-private feature.
 */

#include "fiber_runtime_context_configuration_abi.h"
#include "fiber_panic.h"
#include "fiber_runtime_state.h"

const unsigned char fiber_internal_runtime_context_configuration_abi_v1_anchor =
		(unsigned char)FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_VERSION;

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_context_configuration_open(
		const FiberContext * const ctx)
{
	FIBER_REQUIRE(ctx != 0, 'n');
	FIBER_REQUIRE(fiber_internal_runtime_context_configuration_is_open() != 0u,
			'k');
}
