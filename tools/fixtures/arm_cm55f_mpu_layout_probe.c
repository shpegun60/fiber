#include <stddef.h>

#include "fiber_portmacro.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM55F_MPU construction slice must not expose runtime operations");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_CONTEXT_WORDS == 54u,
		"[fiber]: ARM_CM55F_MPU protected context word count changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedContext) == 216u,
		"[fiber]: ARM_CM55F_MPU protected context size changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) == 88u,
		"[fiber]: ARM_CM55F_MPU boot record size changed");

/* FreeRTOS ARM_CM55_NTZ MPU/FPU uses two intentional views of one 54-word
 * ulContext array. Basic first start ends at word 20; an FP save overwrites
 * the same array from word zero and ends at word 53. */
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedBasicContext, r4) == 0u &&
		offsetof(FiberPortProtectedBasicContext, r0) == 32u &&
		offsetof(FiberPortProtectedBasicContext, psp) == 64u &&
		offsetof(FiberPortProtectedBasicContext, psplim) == 68u &&
		offsetof(FiberPortProtectedBasicContext, control) == 72u &&
		offsetof(FiberPortProtectedBasicContext, exc_return) == 76u &&
		offsetof(FiberPortProtectedBasicContext, cursor_limit) == 80u,
		"[fiber]: ARM_CM55F_MPU basic FreeRTOS cursor view changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedExtendedContext,
		high_fp_s16_s31) == 0u &&
		offsetof(FiberPortProtectedExtendedContext,
		low_fp_s0_s15_fpscr) == 64u &&
		offsetof(FiberPortProtectedExtendedContext, r4) == 132u &&
		offsetof(FiberPortProtectedExtendedContext, r0) == 164u &&
		offsetof(FiberPortProtectedExtendedContext, psp) == 196u &&
		offsetof(FiberPortProtectedExtendedContext, psplim) == 200u &&
		offsetof(FiberPortProtectedExtendedContext, control) == 204u &&
		offsetof(FiberPortProtectedExtendedContext, exc_return) == 208u &&
		offsetof(FiberPortProtectedExtendedContext, cursor_limit) == 212u,
		"[fiber]: ARM_CM55F_MPU extended FreeRTOS cursor view changed");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_BASIC_RESTORE_WORDS == 20u &&
		fiber_portPROTECTED_EXTENDED_RESTORE_WORDS == 53u &&
		fiber_portPROTECTED_EXTENDED_ADDITIONAL_WORDS == 33u &&
		fiber_portPROTECTED_HIGH_FP_WORDS == 16u &&
		fiber_portPROTECTED_LOW_FP_WORDS == 17u,
		"[fiber]: ARM_CM55F_MPU FreeRTOS FPU save geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS == 20u &&
		FIBER_PORT_EXC_RETURN_WORD_INDEX == 19u &&
		FIBER_PORT_HIGH_FP_SOFTWARE_BYTES == 132u &&
		FIBER_PORT_INITIAL_CONTEXT_BYTES == 112u &&
		FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 320u,
		"[fiber]: ARM_CM55F_MPU generic protected-frame geometry changed");

FIBER_STATIC_ASSERT(FIBER_PORT_HAS_FPU == 1 &&
		FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 1 &&
		FIBER_PORT_HAS_MVE == 0 && FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 0 &&
		FIBER_PORT_RUNS_NONSECURE == 1,
		"[fiber]: ARM_CM55F_MPU selected feature profile changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C87u,
		"[fiber]: ARM_CM55F_MPU context feature identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM55F_MPU_PSP_INITIAL_FRAME_BYTES == 32u &&
		FIBER_PORT_CM55F_MPU_PSP_MAX_FRAME_BYTES == 108u &&
		FIBER_PORT_CM55F_MPU_STACK_REQUIRED_BYTES == 112u,
		"[fiber]: ARM_CM55F_MPU physical PSP admission changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CURRENT_CONTEXT_REGION_NUMBER == 5u &&
		fiber_portMPU_FIRST_CONFIGURABLE_REGION_NUMBER == 6u &&
		fiber_portMPU_CONTEXT_CURRENT_CONTEXT_INDEX == 1u &&
		fiber_portMPU_CONTEXT_FIRST_CONFIGURABLE_INDEX == 2u,
		"[fiber]: ARM_CM55F_MPU current-slot MPU policy changed");

#if FIBER_PORT_CM55F_MPU_TOTAL_REGIONS == 8
FIBER_STATIC_ASSERT(FIBER_PORT_CM55F_MPU_CONTEXT_REGION_COUNT == 4u &&
		offsetof(FiberContext, protected_context_cursor) == 0u &&
		offsetof(FiberContext, mair0) == 4u &&
		offsetof(FiberContext, mpu_regions) == 8u &&
		offsetof(FiberContext, protected_context) == 40u &&
		offsetof(FiberContext, runtime_flags) == 256u &&
		offsetof(FiberContext, boot) == 260u &&
		sizeof(FiberContext) == 352u,
		"[fiber]: ARM_CM55F_MPU 8-region context layout changed");
#else
FIBER_STATIC_ASSERT(FIBER_PORT_CM55F_MPU_CONTEXT_REGION_COUNT == 12u &&
		offsetof(FiberContext, protected_context_cursor) == 0u &&
		offsetof(FiberContext, mair0) == 4u &&
		offsetof(FiberContext, mpu_regions) == 8u &&
		offsetof(FiberContext, protected_context) == 104u &&
		offsetof(FiberContext, runtime_flags) == 320u &&
		offsetof(FiberContext, boot) == 324u &&
		sizeof(FiberContext) == 416u,
		"[fiber]: ARM_CM55F_MPU 16-region context layout changed");
#endif

FIBER_STATIC_ASSERT(alignof(FiberContext) == 8u,
		"[fiber]: ARM_CM55F_MPU context alignment changed");

int fiber_arm_cm55f_mpu_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
