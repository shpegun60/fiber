#include "fiber_portmacro.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM55_MVEF_NTZ construction slice must be non-selectable");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_BASEPRI == 1,
		"[fiber]: ARM_CM55_MVEF_NTZ requires BASEPRI");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_FAULTMASK == 1,
		"[fiber]: ARM_CM55_MVEF_NTZ requires FAULTMASK");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_PSPLIM == 1,
		"[fiber]: ARM_CM55_MVEF_NTZ requires PSPLIM");
FIBER_STATIC_ASSERT(FIBER_PORT_USES_PSPLIM_REGISTER == 1,
		"[fiber]: ARM_CM55_MVEF_NTZ must save and restore PSPLIM");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_FPU == 1,
		"[fiber]: ARM_CM55_MVEF_NTZ requires an enabled FPU");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 1,
		"[fiber]: ARM_CM55_MVEF_NTZ must own extended FP frames");
FIBER_STATIC_ASSERT(FIBER_PORT_BOOT_CLEARS_FPCA == 1,
		"[fiber]: ARM_CM55_MVEF_NTZ first start must clear stale FPCA");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_MVE == 1,
		"[fiber]: ARM_CM55_MVEF_NTZ requires MVE FP");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_EXC_RETURN == 0xFFFFFFBCu,
		"[fiber]: ARM_CM55_MVEF_NTZ initial basic EXC_RETURN changed");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_CONTEXT_BYTES == 72u,
		"[fiber]: ARM_CM55_MVEF_NTZ initial frame size changed");
FIBER_STATIC_ASSERT(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 212u,
		"[fiber]: ARM_CM55_MVEF_NTZ extended frame bound changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_PORT_ID == 0x43353556u,
		"[fiber]: ARM_CM55_MVEF_NTZ exact port identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x93u,
		"[fiber]: ARM_CM55_MVEF_NTZ exact feature identity changed");

int fiber_arm_cm55_mvef_ntz_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
