#include "fiber_portmacro.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM23_NTZ staging state changed");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_PSPLIM_SLOT == 1,
		"[fiber]: ARM_CM23_NTZ lost its PSPLIM context slot");
FIBER_STATIC_ASSERT(FIBER_PORT_USES_PSPLIM_REGISTER == 0,
		"[fiber]: Non-secure Cortex-M23 must not access PSPLIM");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_EXC_RETURN == 0xFFFFFFBCu,
		"[fiber]: ARM_CM23_NTZ Non-secure EXC_RETURN changed");

int fiber_arm_cm23_ntz_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
