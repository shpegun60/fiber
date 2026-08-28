#include <stdint.h>

#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_gateway_abi.h"

static volatile uint32_t fiber_arm_cm33_secure_gateway_probe_word;

void Reset_Handler(void)
{
	fiber_arm_cm33_secure_gateway_probe_word =
			fiber_secure_gateway_v1_abi_version() ^
			fiber_secure_gateway_v1_context_port_id() ^
			fiber_secure_gateway_v1_context_layout_version() ^
			fiber_secure_gateway_v1_context_feature_mask() ^
			fiber_secure_context_gateway_v1_abi_version() ^
			fiber_secure_context_gateway_v1_stack_alignment() ^
			fiber_secure_context_gateway_v1_max_stack_bytes() ^
			fiber_secure_context_gateway_v1_max_contexts() ^
			fiber_secure_context_gateway_v1_initialize() ^
			fiber_secure_context_gateway_v1_allocate(0u, 0u) ^
			fiber_secure_context_gateway_v1_load(0u, 0u) ^
			fiber_secure_context_gateway_v1_save(0u, 0u);

	for (;;) {
		__asm volatile ("wfe");
	}
}
