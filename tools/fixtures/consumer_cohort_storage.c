/* Deliberately allocate storage without calling any public operation. */
#ifdef FIBER_CONSUMER_DIRECT_TYPES
# include "fiber_port_types.h"
# ifdef FIBER_CONSUMER_DIRECT_EXPECTATION
#  include "fiber_port_storage_cohort_expectation.h"
# endif
#else
# include "fiber/fiber_core.h"
# include "fiber/fiber_core.h"
# include "fiber/fiber_types.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((used, externally_visible)) FiberContext fiber_consumer_storage;

__attribute__((noinline, used, externally_visible))
FiberContext *fiber_consumer_get(void)
{
	return &fiber_consumer_storage;
}

#ifdef __cplusplus
}
#endif
