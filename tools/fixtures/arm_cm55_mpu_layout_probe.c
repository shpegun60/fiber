#include <stddef.h>

#include "fiber_portmacro.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 1,
		"[fiber]: ARM_CM55_MPU selected layout must expose runtime operations");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_CONTEXT_WORDS == 21u,
		"[fiber]: ARM_CM55_MPU protected context word count changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedContext) == 84u,
		"[fiber]: ARM_CM55_MPU protected context size changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) == 88u,
		"[fiber]: ARM_CM55_MPU boot record size changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r4) == 0u,
		"[fiber]: ARM_CM55_MPU r4 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r0) == 32u,
		"[fiber]: ARM_CM55_MPU copied hardware frame offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, psp) == 64u,
		"[fiber]: ARM_CM55_MPU saved PSP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, psplim) == 68u,
		"[fiber]: ARM_CM55_MPU saved PSPLIM offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, control) == 72u,
		"[fiber]: ARM_CM55_MPU saved CONTROL offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, exc_return) == 76u,
		"[fiber]: ARM_CM55_MPU saved EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, cursor_limit) == 80u,
		"[fiber]: ARM_CM55_MPU one-past cursor target changed");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 0,
		"[fiber]: ARM_CM55_MPU layout slice must not expose SecureContext");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNS_NONSECURE == 1,
		"[fiber]: ARM_CM55_MPU must remain a Non-secure profile");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C86u,
		"[fiber]: ARM_CM55_MPU context feature identity changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CURRENT_CONTEXT_REGION_NUMBER == 5u &&
		fiber_portMPU_FIRST_CONFIGURABLE_REGION_NUMBER == 6u &&
		fiber_portMPU_CONTEXT_CURRENT_CONTEXT_INDEX == 1u &&
		fiber_portMPU_CONTEXT_FIRST_CONFIGURABLE_INDEX == 2u,
		"[fiber]: ARM_CM55_MPU current-slot MPU policy changed");

#if FIBER_PORT_CM55_MPU_TOTAL_REGIONS == 8
FIBER_STATIC_ASSERT(FIBER_PORT_CM55_MPU_CONTEXT_REGION_COUNT == 4u,
		"[fiber]: ARM_CM55_MPU 8-region context image changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context_cursor) == 0u,
		"[fiber]: ARM_CM55_MPU 8-region cursor offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, mair0) == 4u,
		"[fiber]: ARM_CM55_MPU 8-region MAIR0 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, mpu_regions) == 8u,
		"[fiber]: ARM_CM55_MPU 8-region MPU image offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context) == 40u,
		"[fiber]: ARM_CM55_MPU 8-region protected context offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, runtime_flags) == 124u,
		"[fiber]: ARM_CM55_MPU 8-region flags offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, boot) == 128u,
		"[fiber]: ARM_CM55_MPU 8-region boot offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberContext) == 216u,
		"[fiber]: ARM_CM55_MPU 8-region context size changed");
#else
FIBER_STATIC_ASSERT(FIBER_PORT_CM55_MPU_CONTEXT_REGION_COUNT == 12u,
		"[fiber]: ARM_CM55_MPU 16-region context image changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context_cursor) == 0u,
		"[fiber]: ARM_CM55_MPU 16-region cursor offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, mair0) == 4u,
		"[fiber]: ARM_CM55_MPU 16-region MAIR0 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, mpu_regions) == 8u,
		"[fiber]: ARM_CM55_MPU 16-region MPU image offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context) == 104u,
		"[fiber]: ARM_CM55_MPU 16-region protected context offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, runtime_flags) == 188u,
		"[fiber]: ARM_CM55_MPU 16-region flags offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, boot) == 192u,
		"[fiber]: ARM_CM55_MPU 16-region boot offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberContext) == 280u,
		"[fiber]: ARM_CM55_MPU 16-region context size changed");
#endif

FIBER_STATIC_ASSERT(alignof(FiberContext) == 8u,
		"[fiber]: ARM_CM55_MPU context alignment changed");

int fiber_arm_cm55_mpu_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
