/* Static-link provider only. Executed Secure boot remains the runtime fixture. */
#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_gateway_abi.h"
__attribute__((used, section(".proof_roots")))
static const uintptr_t roots[] = {
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
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_save,
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_load
};
void Secure_Reset_Handler(void) { for (;;) {} }
