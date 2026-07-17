#include "fiber_portmacro.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 1,
		"[fiber]: layout probe requires active ARM_CM3_MPU build selection");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C04u,
		"[fiber]: ARM_CM3_MPU feature identity changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_READ_WRITE == 0x03000000u,
		"[fiber]: ARM_CM3_MPU RW permission encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_PRIVILEGED_READ_ONLY == 0x05000000u,
		"[fiber]: ARM_CM3_MPU privileged RO encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_READ_ONLY == 0x06000000u,
		"[fiber]: ARM_CM3_MPU RO permission encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_PRIVILEGED_READ_WRITE == 0x01000000u,
		"[fiber]: ARM_CM3_MPU privileged RW encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_CACHEABLE_BUFFERABLE == 0x00070000u,
		"[fiber]: ARM_CM3_MPU memory attribute encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_EXECUTE_NEVER == 0x10000000u,
		"[fiber]: ARM_CM3_MPU XN encoding changed");
FIBER_STATIC_ASSERT(fiber_portMPU_FIRST_CONFIGURABLE_REGION == 0u &&
		fiber_portMPU_LAST_CONFIGURABLE_REGION == 2u &&
		fiber_portMPU_STACK_REGION == 3u &&
		fiber_portMPU_CURRENT_CONTEXT_REGION == 4u &&
		fiber_portMPU_UNPRIVILEGED_CODE_REGION == 5u &&
		fiber_portMPU_PRIVILEGED_CODE_REGION == 6u &&
		fiber_portMPU_PRIVILEGED_DATA_REGION == 7u,
		"[fiber]: ARM_CM3_MPU region numbering changed");

int fiber_arm_cm3_mpu_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
