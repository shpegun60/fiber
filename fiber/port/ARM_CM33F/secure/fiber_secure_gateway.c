/* Identity queries only; not a Secure initializer or a runtime provider. */
#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_cohort.h"
uint32_t fiber_secure_gateway_c3fs_v1_abi_version(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_GATEWAY_ABI_VERSION;
}
uint32_t fiber_secure_gateway_c3fs_v1_context_port_id(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_GATEWAY_CONTEXT_PORT_ID;
}
uint32_t fiber_secure_gateway_c3fs_v1_context_layout_version(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION;
}
uint32_t fiber_secure_gateway_c3fs_v1_context_feature_mask(void)
{
    fiber_secure_c3fs_query_preflight();
    FIBER_C3FS_PRIVATE_COHORT_RETAIN();
    return FIBER_ARM_CM33F_SECURE_GATEWAY_CONTEXT_FEATURE_MASK;
}
