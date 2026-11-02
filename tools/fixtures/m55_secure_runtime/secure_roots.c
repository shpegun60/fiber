#include <stdint.h>
#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_gateway_abi.h"
/* Actual production imports, not implementations or reverse-ABI adapters. */
__attribute__((used,externally_visible))
const uintptr_t runtime_secure_roots[]={
    (uintptr_t)fiber_secure_gateway_c55s_v1_abi_version,
    (uintptr_t)fiber_secure_gateway_c55s_v1_context_port_id,
    (uintptr_t)fiber_secure_gateway_c55s_v1_context_layout_version,
    (uintptr_t)fiber_secure_gateway_c55s_v1_context_feature_mask,
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_abi_version,
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_stack_alignment,
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_max_contexts,
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_max_stack_bytes,
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_initialize,
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_allocate,
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_load,
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_save
};
__attribute__((noinline,noclone,used,externally_visible))
void runtime_secure_retain(void)
{
    const volatile uintptr_t *const addresses=runtime_secure_roots;
    volatile uintptr_t fold=0;
    for(uint32_t i=0;i<12u;++i){fold^=addresses[i];}
    (void)fold;
}
