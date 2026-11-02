#include "fiber_port_types.h"
/* A synthetic old storage revision is an identity negative, not a claim of a
 * historical CM33F layout. Region mismatch cases use actual public geometry. */
#if STALE_REVISION
#undef FIBER_PORT_STORAGE_COHORT_REVISION
#define FIBER_PORT_STORAGE_COHORT_REVISION 0
extern const unsigned char FIBER_PORT_STORAGE_COHORT_SYMBOL;
#endif
#include "fiber/port/fiber_port_storage_cohort_expectation.h"
FiberContext fixture_external_storage;
