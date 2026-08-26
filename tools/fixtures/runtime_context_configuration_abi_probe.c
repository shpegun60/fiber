/* Optional selected-port extension probe. It intentionally includes no
 * selected-port header: the reverse extension ABI remains CPU-neutral. */

#include "fiber/fiber_runtime_context_configuration_abi.h"

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_runtime_context_configuration_abi_probe_entry(void)
{
	FIBER_RUNTIME_CONTEXT_CONFIGURATION_ABI_RETAIN_V1();
}
