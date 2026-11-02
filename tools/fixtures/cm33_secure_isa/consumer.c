/* Link-only surface consumer. The order below is not a runtime protocol. */
#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_gateway_abi.h"

#if defined(CM33_ISA_WITH_HELPER)
void cm33_isa_memory_helper(unsigned char *bytes);
static unsigned char cm33_isa_helper_bytes[264];
#endif

uint32_t cm33_isa_consumer(void)
{
#if defined(CM33_ISA_WITH_HELPER)
    cm33_isa_memory_helper(cm33_isa_helper_bytes);
#endif
    return fiber_secure_gateway_v1_abi_version() ^
            fiber_secure_gateway_v1_context_port_id() ^
            fiber_secure_gateway_v1_context_layout_version() ^
            fiber_secure_gateway_v1_context_feature_mask() ^
            fiber_secure_context_gateway_v1_abi_version() ^
            fiber_secure_context_gateway_v1_stack_alignment() ^
            fiber_secure_context_gateway_v1_max_stack_bytes() ^
            fiber_secure_context_gateway_v1_max_contexts() ^
            fiber_secure_context_gateway_v1_initialize() ^
            fiber_secure_context_gateway_v1_allocate(64u, 0x20000040u) ^
            fiber_secure_context_gateway_v1_load(1u, 0x20000040u) ^
            fiber_secure_context_gateway_v1_save(1u, 0x20000040u);
}
