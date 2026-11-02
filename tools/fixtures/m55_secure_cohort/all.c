/* Link-only complete NSC surface. This image is never executed. */
#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_gateway_abi.h"

uint32_t cohort_consumer(void)
{
    return fiber_secure_gateway_c55s_v1_abi_version() ^
            fiber_secure_gateway_c55s_v1_context_port_id() ^
            fiber_secure_gateway_c55s_v1_context_layout_version() ^
            fiber_secure_gateway_c55s_v1_context_feature_mask() ^
            fiber_secure_context_gateway_c55s_v1_abi_version() ^
            fiber_secure_context_gateway_c55s_v1_stack_alignment() ^
            fiber_secure_context_gateway_c55s_v1_max_stack_bytes() ^
            fiber_secure_context_gateway_c55s_v1_max_contexts() ^
            fiber_secure_context_gateway_c55s_v1_initialize() ^
            fiber_secure_context_gateway_c55s_v1_allocate(64u, 0x20000040u) ^
            fiber_secure_context_gateway_c55s_v1_load(1u, 0x20000040u) ^
            fiber_secure_context_gateway_c55s_v1_save(1u, 0x20000040u);
}
