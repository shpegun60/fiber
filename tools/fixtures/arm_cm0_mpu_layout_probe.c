#include "fiber_portmacro.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 1,
		"[fiber]: ARM_CM0_MPU must expose the complete forward runtime ABI");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C04u,
		"[fiber]: ARM_CM0_MPU feature identity changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_REGION_COUNT == 4u,
		"[fiber]: ARM_CM0_MPU context image region count changed");
FIBER_STATIC_ASSERT(fiber_portMPU_STACK_REGION == 3u &&
		fiber_portMPU_CURRENT_CONTEXT_REGION == 4u,
		"[fiber]: ARM_CM0_MPU safe global region boundary changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedContext) == (20u * 4u),
		"[fiber]: ARM_CM0_MPU protected context size changed");

int fiber_arm_cm0_mpu_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
