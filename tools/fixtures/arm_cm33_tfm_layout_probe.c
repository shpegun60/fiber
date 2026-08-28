#include "fiber_portmacro.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 1,
		"[fiber]: ARM_CM33_TFM runtime must remain selectable");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_BASEPRI == 1,
		"[fiber]: ARM_CM33_TFM requires BASEPRI");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_FAULTMASK == 1,
		"[fiber]: ARM_CM33_TFM requires FAULTMASK");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_PSPLIM == 1,
		"[fiber]: ARM_CM33_TFM requires PSPLIM");
FIBER_STATIC_ASSERT(FIBER_PORT_USES_PSPLIM_REGISTER == 1,
		"[fiber]: ARM_CM33_TFM must save and restore PSPLIM");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_FPU == 0,
		"[fiber]: ARM_CM33_TFM first profile is no-FPU");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 0,
		"[fiber]: ARM_CM33_TFM has no extended FP frame");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 0,
		"[fiber]: TF-M and fiber SecureContext must remain separate");
FIBER_STATIC_ASSERT(FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI,
		"[fiber]: ARM_CM33_TFM scheduler must use BASEPRI");
FIBER_STATIC_ASSERT(FIBER_PORT_SCHEDULER_BASEPRI == 32u,
		"[fiber]: ARM_CM33_TFM default BASEPRI changed");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_EXC_RETURN == 0xFFFFFFBCu,
		"[fiber]: ARM_CM33_TFM Non-secure EXC_RETURN changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_PORT_ID == 0x43335446u,
		"[fiber]: ARM_CM33_TFM exact port identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x82u,
		"[fiber]: ARM_CM33_TFM frame feature identity changed");

int fiber_arm_cm33_tfm_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
