#include "layout.h"

#define PROOF_STRING_I(x) #x
#define PROOF_STRING(x) PROOF_STRING_I(x)

/* No expectation/provider anchor: this stage proves the type declaration only. */
const char cm33f_public_storage_name[] __attribute__((used, section(".manifest_storage"))) =
        PROOF_STRING(FIBER_PORT_STORAGE_COHORT_SYMBOL);
FiberContext cm33f_public_storage_object;

PROOF_ASSERT(FIBER_PORT_STORAGE_COHORT_REVISION == 1, "storage revision 1");
PROOF_ASSERT(FIBER_PORT_STORAGE_COHORT_REGIONS == FIBER_PORT_CM33F_MPU_TOTAL_REGIONS,
        "storage region identity");
