#include "fiber_portmacro.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM33_NTZ runtime must remain staged");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_BASEPRI == 1,
		"[fiber]: ARM_CM33_NTZ requires BASEPRI");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_FAULTMASK == 1,
		"[fiber]: ARM_CM33_NTZ requires FAULTMASK");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_PSPLIM == 1,
		"[fiber]: ARM_CM33_NTZ requires PSPLIM");
FIBER_STATIC_ASSERT(FIBER_PORT_USES_PSPLIM_REGISTER == 1,
		"[fiber]: ARM_CM33_NTZ must save and restore PSPLIM");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_FPU == 0,
		"[fiber]: ARM_CM33_NTZ first profile is no-FPU");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 0,
		"[fiber]: ARM_CM33_NTZ first profile has no extended FP frame");
FIBER_STATIC_ASSERT(FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI,
		"[fiber]: ARM_CM33_NTZ scheduler must use BASEPRI");
FIBER_STATIC_ASSERT(FIBER_PORT_SCHEDULER_BASEPRI == 32u,
		"[fiber]: ARM_CM33_NTZ default BASEPRI changed for three priority bits");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_EXC_RETURN == 0xFFFFFFBCu,
		"[fiber]: ARM_CM33_NTZ Non-secure EXC_RETURN changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x82u,
		"[fiber]: ARM_CM33_NTZ exact feature identity changed");

int fiber_arm_cm33_ntz_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
