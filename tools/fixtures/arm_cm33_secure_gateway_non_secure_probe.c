#include <stdint.h>

#include "fiber_port_secure_context_gateway_abi.h"
#include "fiber_port_secure_gateway_abi.h"
#include "fiber_port_private.h"

extern void fiber_arm_cm33_secure_context_attach_probe(void);
void Reset_Handler(void);

static volatile uint32_t fiber_arm_cm33_non_secure_gateway_probe_word;

__attribute__((used, section(".isr_vector")))
const uintptr_t fiber_arm_cm33_secure_context_vectors[16] = {
	[1] = (uintptr_t)Reset_Handler,
	[11] = (uintptr_t)SVC_Handler,
	[14] = (uintptr_t)PendSV_Handler
};

void Reset_Handler(void)
{
	fiber_arm_cm33_secure_context_attach_probe();
	fiber_arm_cm33_non_secure_gateway_probe_word =
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
			fiber_secure_context_gateway_v1_save(0u, 0u) ^
			(uint32_t)(uintptr_t)&fiber_port_context_init ^
			(uint32_t)(uintptr_t)&fiber_port_runtime_memory_barrier ^
			(uint32_t)(uintptr_t)&fiber_port_panic_wait ^
			(uint32_t)(uintptr_t)
				&fiber_port_require_scheduler_configuration_environment ^
			(uint32_t)(uintptr_t)&fiber_port_runtime_prepare_start ^
			(uint32_t)(uintptr_t)&fiber_port_runtime_select_first ^
			(uint32_t)(uintptr_t)&fiber_port_runtime_start_first ^
			(uint32_t)(uintptr_t)&fiber_port_runtime_schedule ^
			(uint32_t)(uintptr_t)&fiber_port_start_first_context;

	for (;;) {
		__asm volatile ("wfe");
	}
}
