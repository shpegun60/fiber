#include <stdint.h>

#include "fiber_port_secure_gateway_abi.h"

static volatile uint32_t fiber_arm_cm33_non_secure_gateway_probe_word;

void Reset_Handler(void)
{
	fiber_arm_cm33_non_secure_gateway_probe_word =
			fiber_secure_gateway_v1_abi_version() ^
			fiber_secure_gateway_v1_context_port_id() ^
			fiber_secure_gateway_v1_context_layout_version() ^
			fiber_secure_gateway_v1_context_feature_mask();

	for (;;) {
		__asm volatile ("wfe");
	}
}
