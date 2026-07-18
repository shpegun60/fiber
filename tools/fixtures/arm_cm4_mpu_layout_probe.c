#include "fiber_portmacro.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 1,
		"[fiber]: ARM_CM4_MPU build-selected activation changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C05u,
		"[fiber]: ARM_CM4_MPU feature identity changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_REGION_COUNT ==
		(FIBER_PORT_CM4_MPU_TOTAL_REGIONS - 4u),
		"[fiber]: ARM_CM4_MPU context region formula changed");
FIBER_STATIC_ASSERT(fiber_portMPU_STACK_REGION ==
		(FIBER_PORT_CM4_MPU_TOTAL_REGIONS - 5u),
		"[fiber]: ARM_CM4_MPU stack region formula changed");
FIBER_STATIC_ASSERT(fiber_portMPU_PRIVILEGED_DATA_REGION ==
		(FIBER_PORT_CM4_MPU_TOTAL_REGIONS - 1u),
		"[fiber]: ARM_CM4_MPU privileged data region changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedContext) == (53u * 4u),
		"[fiber]: ARM_CM4_MPU protected context size changed");

int fiber_arm_cm4_mpu_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
