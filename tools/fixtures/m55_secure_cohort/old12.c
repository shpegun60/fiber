/* Synthetic pre-guard provider: current NSC names, deliberately no guard. */
#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_gateway_abi.h"

uint32_t fiber_secure_gateway_c55s_v1_abi_version(void) { return 1u; }
uint32_t fiber_secure_gateway_c55s_v1_context_port_id(void) { return 0x43353553u; }
uint32_t fiber_secure_gateway_c55s_v1_context_layout_version(void) { return 0x10001u; }
uint32_t fiber_secure_gateway_c55s_v1_context_feature_mask(void) { return 0x8au; }
uint32_t fiber_secure_context_gateway_c55s_v1_abi_version(void) { return 1u; }
uint32_t fiber_secure_context_gateway_c55s_v1_stack_alignment(void) { return 8u; }
uint32_t fiber_secure_context_gateway_c55s_v1_max_stack_bytes(void) { return 128u; }
uint32_t fiber_secure_context_gateway_c55s_v1_max_contexts(void) { return 3u; }
uint32_t fiber_secure_context_gateway_c55s_v1_initialize(void) { return 0u; }
uint32_t fiber_secure_context_gateway_c55s_v1_allocate(uint32_t bytes, uintptr_t owner)
{
    (void)bytes;
    (void)owner;
    return 0u;
}
uint32_t fiber_secure_context_gateway_c55s_v1_load(uint32_t handle, uintptr_t owner)
{
    (void)handle;
    (void)owner;
    return 0u;
}
uint32_t fiber_secure_context_gateway_c55s_v1_save(uint32_t handle, uintptr_t owner)
{
    (void)handle;
    (void)owner;
    return 0u;
}
