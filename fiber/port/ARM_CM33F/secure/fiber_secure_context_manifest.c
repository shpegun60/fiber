/* Pure C archive root plus one read-only exact-manifest provider; no BSS. */
#include "fiber_secure_gateway_abi.h"
#include "fiber_secure_context_cohort.h"

void fiber_secure_context_manifest_c3fs_v1_cohort_provider(void)
{
    FIBER_C3FS_PRIVATE_COHORT_DEFINE();
}
