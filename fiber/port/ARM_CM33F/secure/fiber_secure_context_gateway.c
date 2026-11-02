/* Configured future capacity, not physical discovery or pool allocation. */
#include "fiber_secure_context_gateway_abi.h"
#include "fiber_secure_context_cohort.h"
uint32_t fiber_secure_context_gateway_c3fs_v1_abi_version(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_ABI_VERSION;
}
uint32_t fiber_secure_context_gateway_c3fs_v1_stack_alignment(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_CONTEXT_GATEWAY_STACK_ALIGNMENT;
}
uint32_t fiber_secure_context_gateway_c3fs_v1_max_stack_bytes(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_STACK_BYTES;
}
uint32_t fiber_secure_context_gateway_c3fs_v1_max_contexts(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_CONTEXT_MAX_COUNT;
}
