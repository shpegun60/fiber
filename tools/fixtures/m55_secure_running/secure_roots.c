#include <stdint.h>
#ifdef RUNNING_REFERENCE
#include "secure_context.h"
#include "secure_init.h"
#define ROOTS \
    (uintptr_t)SecureInit_DePrioritizeNSExceptions,(uintptr_t)SecureInit_EnableNSFPUAccess, \
    (uintptr_t)SecureContext_Init,(uintptr_t)SecureContext_AllocateContext, \
    (uintptr_t)SecureContext_FreeContext,(uintptr_t)SecureContext_LoadContext, \
    (uintptr_t)SecureContext_SaveContext
#else
#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_gateway_abi.h"
#define ROOTS \
    (uintptr_t)fiber_secure_gateway_c55s_v1_abi_version, \
    (uintptr_t)fiber_secure_gateway_c55s_v1_context_port_id, \
    (uintptr_t)fiber_secure_gateway_c55s_v1_context_layout_version, \
    (uintptr_t)fiber_secure_gateway_c55s_v1_context_feature_mask, \
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_abi_version, \
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_stack_alignment, \
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_max_contexts, \
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_max_stack_bytes, \
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_initialize, \
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_allocate, \
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_load, \
    (uintptr_t)fiber_secure_context_gateway_c55s_v1_save
#endif
/* Genuine ABI references for archive extraction. Never called as adapters. */
__attribute__((used,externally_visible))
const uintptr_t first_secure_roots[]={ROOTS};
__attribute__((noinline,noclone,used,externally_visible))
void running_secure_retain(void)
{
    const volatile uintptr_t *const addresses=first_secure_roots;
    volatile uintptr_t fold=0;
    for(uint32_t i=0;i<sizeof(first_secure_roots)/sizeof(first_secure_roots[0]);++i){fold^=addresses[i];}
    (void)fold;
}
