/* Actual Secure import consumer; compile/link only, never a query double. */
#include "fiber_port_secure_gateway_abi.h"
#include "fiber_port_secure_context_gateway_abi.h"
uint32_t fixture_real_imports(void)
{
    return fiber_secure_gateway_c3fs_v1_abi_version() +
        fiber_secure_gateway_c3fs_v1_context_port_id() +
        fiber_secure_gateway_c3fs_v1_context_layout_version() +
        fiber_secure_gateway_c3fs_v1_context_feature_mask() +
        fiber_secure_context_gateway_c3fs_v1_abi_version() +
        fiber_secure_context_gateway_c3fs_v1_stack_alignment() +
        fiber_secure_context_gateway_c3fs_v1_max_stack_bytes() +
        fiber_secure_context_gateway_c3fs_v1_max_contexts() +
        fiber_secure_context_gateway_c3fs_v1_initialize();
}
