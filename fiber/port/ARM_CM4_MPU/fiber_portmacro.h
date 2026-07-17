/*
 * fiber_portmacro.h
 *
 * Compile-only ARM_CM4_MPU dictionary, implementation slice 1. The directory
 * deliberately provides no runtime source or handlers yet. Both Cortex-M4F
 * and Cortex-M7F manifests are accepted because the pinned FreeRTOS port owns
 * both cases; their exact cohort identities remain distinct.
 */

#ifndef FIBER_PORT_ARM_CM4_MPU_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM4_MPU_FIBER_PORTMACRO_H_

#include <stddef.h>
#include <stdint.h>

#ifdef FIBER_PORT_NAME
# error "[fiber]: ARM_CM4_MPU port name must not be predefined"
#endif
#define FIBER_PORT_NAME "ARM_CM4_MPU"

#include "../fiber_port_select.h"
#include "../fiber_settings.h"
#include "../fiber_compiler.h"
#include "fiber_port_types.h"

#if !FIBER_PORT_BUILD_SELECTED
# error "[fiber]: ARM_CM4_MPU is build-selected only"
#endif

#if !FIBER_PORT_ARMV7EM
# error "[fiber]: ARM_CM4_MPU requires the ARMv7E-M architecture result"
#endif

#if !defined(__ARM_ARCH_7EM__)
# error "[fiber]: ARM_CM4_MPU requires an ARMv7E-M compiler target"
#endif

#if !defined(__CORTEX_M) || ((__CORTEX_M != 4) && (__CORTEX_M != 7))
# error "[fiber]: ARM_CM4_MPU manifest requires CMSIS __CORTEX_M 4 or 7"
#endif

#if !defined(__MPU_PRESENT) || (__MPU_PRESENT != 1)
# error "[fiber]: ARM_CM4_MPU manifest requires __MPU_PRESENT == 1"
#endif

#if !defined(__VTOR_PRESENT) || (__VTOR_PRESENT != 1)
# error "[fiber]: ARM_CM4_MPU manifest requires __VTOR_PRESENT == 1"
#endif

#if !defined(__FPU_PRESENT) || (__FPU_PRESENT != 1)
# error "[fiber]: ARM_CM4_MPU manifest requires __FPU_PRESENT == 1"
#endif

#if !defined(__FPU_USED) || (__FPU_USED != 1)
# error "[fiber]: ARM_CM4_MPU manifest requires __FPU_USED == 1"
#endif

#if !defined(__ARM_FP) || (__ARM_FP == 0)
# error "[fiber]: ARM_CM4_MPU requires an enabled compiler FP register ABI"
#endif

#if !defined(__NVIC_PRIO_BITS) || (__NVIC_PRIO_BITS < 1) || \
		(__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM4_MPU requires 1..8 implemented NVIC priority bits"
#endif

#ifdef FIBER_PORT_RUNTIME_SELECTABLE
# error "[fiber]: ARM_CM4_MPU runtime-selectable state must not be predefined"
#endif
#define FIBER_PORT_RUNTIME_SELECTABLE 0

/* Reference context and MPU geometry. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFFDu
#define fiber_portINITIAL_CONTROL_PRIVILEGED 0x00000002u
#define fiber_portINITIAL_CONTROL_UNPRIVILEGED 0x00000003u

#define fiber_portMPU_TOTAL_REGIONS FIBER_PORT_CM4_MPU_TOTAL_REGIONS
#define fiber_portMPU_FIRST_CONFIGURABLE_REGION 0u
#define fiber_portMPU_LAST_CONFIGURABLE_REGION \
	(fiber_portMPU_TOTAL_REGIONS - 6u)
#define fiber_portMPU_CONFIGURABLE_REGION_COUNT \
	(fiber_portMPU_TOTAL_REGIONS - 5u)
#define fiber_portMPU_CONTEXT_REGION_COUNT \
	(fiber_portMPU_CONFIGURABLE_REGION_COUNT + 1u)
#define fiber_portMPU_STACK_REGION (fiber_portMPU_TOTAL_REGIONS - 5u)
#define fiber_portMPU_CURRENT_CONTEXT_REGION \
	(fiber_portMPU_TOTAL_REGIONS - 4u)
#define fiber_portMPU_UNPRIVILEGED_CODE_REGION \
	(fiber_portMPU_TOTAL_REGIONS - 3u)
#define fiber_portMPU_PRIVILEGED_CODE_REGION \
	(fiber_portMPU_TOTAL_REGIONS - 2u)
#define fiber_portMPU_PRIVILEGED_DATA_REGION \
	(fiber_portMPU_TOTAL_REGIONS - 1u)
#define fiber_portMPU_GLOBAL_REGION_COUNT 4u

#define fiber_portMPU_REGION_READ_WRITE (0x03u << 24u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_ONLY (0x05u << 24u)
#define fiber_portMPU_REGION_READ_ONLY (0x06u << 24u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_WRITE (0x01u << 24u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_WRITE_UNPRIV_READ_ONLY \
	(0x02u << 24u)
#define fiber_portMPU_REGION_CACHEABLE_BUFFERABLE (0x07u << 16u)
#define fiber_portMPU_REGION_EXECUTE_NEVER 0x10000000u
#define fiber_portMPU_RASR_TEX_S_C_B_LOCATION 16u
#define fiber_portMPU_RASR_TEX_S_C_B_MASK 0x3Fu

#define fiber_portPROTECTED_CONTEXT_WORDS 53u
#define fiber_portPROTECTED_HIGH_FP_WORDS 16u
#define fiber_portPROTECTED_LOW_FP_WORDS 17u
#define fiber_portPROTECTED_CORE_WORDS 10u
#define fiber_portPROTECTED_HARDWARE_WORDS 9u
#define fiber_portSTACK_FRAME_HAS_PADDING_FLAG (1u << 0u)
#define fiber_portTASK_IS_PRIVILEGED_FLAG (1u << 1u)

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1
#define FIBER_PORT_HAS_VTOR 1
#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_HAS_FPU 1
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 1
#define FIBER_PORT_STACK_ALIGNMENT fiber_portBYTE_ALIGNMENT
#define FIBER_PORT_BOOT_CLEARS_FPCA 1
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN fiber_portINITIAL_EXC_RETURN
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_BASEPRI

#ifndef FIBER_PORT_SCHEDULER_BASEPRI
# ifdef FIBER_SCHEDULER_BASEPRI
#  define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI
# elif __NVIC_PRIO_BITS == 8
#  define FIBER_PORT_SCHEDULER_BASEPRI 2u
# else
#  define FIBER_PORT_SCHEDULER_BASEPRI (1u << (8u - __NVIC_PRIO_BITS))
# endif
#endif
#ifndef FIBER_SCHEDULER_BASEPRI
# define FIBER_SCHEDULER_BASEPRI FIBER_PORT_SCHEDULER_BASEPRI
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI == 0u
# error "[fiber]: ARM_CM4_MPU scheduler BASEPRI threshold must be non-zero"
#endif
#if FIBER_PORT_SCHEDULER_BASEPRI > 255u
# error "[fiber]: ARM_CM4_MPU scheduler BASEPRI threshold must fit in 8 bits"
#endif
FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI &
		((1u << (8u - __NVIC_PRIO_BITS)) - 1u)) == 0u,
		"[fiber]: ARM_CM4_MPU BASEPRI uses unimplemented priority bits");
#if __NVIC_PRIO_BITS == 8
FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI & 1u) == 0u,
		"[fiber]: ARM_CM4_MPU BASEPRI bit 0 is subpriority");
#endif

#if __CORTEX_M == 7
# define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 1
# define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 1
# define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x434D374Du
#else
# define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
# define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0
# define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x434D344Du
#endif

#ifndef FIBER_PORT_IS_V8M
# define FIBER_PORT_IS_V8M 0
#endif
#define FIBER_PORT_HAS_SECURITY_EXT 0
#define FIBER_PORT_RUNS_NONSECURE 0
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 1
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0

#if FIBER_PORT_CM4_MPU_TOTAL_REGIONS == 8
# define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010008u
# define FIBER_PORT_CM4_MPU_PROTECTED_CONTEXT_OFFSET 36u
# define FIBER_PORT_CM4_MPU_RUNTIME_FLAGS_OFFSET 248u
# define FIBER_PORT_CM4_MPU_BOOT_OFFSET 252u
# define FIBER_PORT_CM4_MPU_CONTEXT_SIZE 344u
#else
# define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010010u
# define FIBER_PORT_CM4_MPU_PROTECTED_CONTEXT_OFFSET 100u
# define FIBER_PORT_CM4_MPU_RUNTIME_FLAGS_OFFSET 312u
# define FIBER_PORT_CM4_MPU_BOOT_OFFSET 316u
# define FIBER_PORT_CM4_MPU_CONTEXT_SIZE 408u
#endif

#define FIBER_PORT_CONTEXT_FEATURE_EXTENDED_FP 0x00000001u
#define FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT 0x00000004u
#define FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE 0x00000400u
#define FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME 0x00000800u
#define FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED 0x00001000u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	(FIBER_PORT_CONTEXT_FEATURE_EXTENDED_FP | \
	 FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE | \
	 FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME | \
	 FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED)

/* Conservative generic stack geometry; protected register storage is larger
 * than the unprivileged hardware frame and remains outside the user stack. */
#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES (18u * 4u)
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES)
#define FIBER_PORT_SOFTWARE_FRAME_WORDS fiber_portPROTECTED_CORE_WORDS
#define FIBER_PORT_SOFTWARE_FRAME_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX 9u
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES (16u * 4u)
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_BASE_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + \
	 FIBER_PORT_HIGH_FP_SOFTWARE_BYTES + \
	 FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 0u

/* Frozen 32-bit GCC type layout. */
#define FIBER_PORT_CM4_MPU_REGION_RBAR_OFFSET 0u
#define FIBER_PORT_CM4_MPU_REGION_RASR_OFFSET 4u
#define FIBER_PORT_CM4_MPU_REGION_SIZE 8u
#define FIBER_PORT_CM4_MPU_CORE_CONTROL_OFFSET 0u
#define FIBER_PORT_CM4_MPU_CORE_R4_OFFSET 4u
#define FIBER_PORT_CM4_MPU_CORE_R5_OFFSET 8u
#define FIBER_PORT_CM4_MPU_CORE_R6_OFFSET 12u
#define FIBER_PORT_CM4_MPU_CORE_R7_OFFSET 16u
#define FIBER_PORT_CM4_MPU_CORE_R8_OFFSET 20u
#define FIBER_PORT_CM4_MPU_CORE_R9_OFFSET 24u
#define FIBER_PORT_CM4_MPU_CORE_R10_OFFSET 28u
#define FIBER_PORT_CM4_MPU_CORE_R11_OFFSET 32u
#define FIBER_PORT_CM4_MPU_CORE_EXC_RETURN_OFFSET 36u
#define FIBER_PORT_CM4_MPU_CORE_SIZE 40u
#define FIBER_PORT_CM4_MPU_HARDWARE_PSP_OFFSET 0u
#define FIBER_PORT_CM4_MPU_HARDWARE_R0_OFFSET 4u
#define FIBER_PORT_CM4_MPU_HARDWARE_R1_OFFSET 8u
#define FIBER_PORT_CM4_MPU_HARDWARE_R2_OFFSET 12u
#define FIBER_PORT_CM4_MPU_HARDWARE_R3_OFFSET 16u
#define FIBER_PORT_CM4_MPU_HARDWARE_R12_OFFSET 20u
#define FIBER_PORT_CM4_MPU_HARDWARE_LR_OFFSET 24u
#define FIBER_PORT_CM4_MPU_HARDWARE_PC_OFFSET 28u
#define FIBER_PORT_CM4_MPU_HARDWARE_XPSR_OFFSET 32u
#define FIBER_PORT_CM4_MPU_HARDWARE_SIZE 36u
#define FIBER_PORT_CM4_MPU_BASIC_CORE_OFFSET 0u
#define FIBER_PORT_CM4_MPU_BASIC_HARDWARE_OFFSET 40u
#define FIBER_PORT_CM4_MPU_BASIC_CURSOR_LIMIT_OFFSET 76u
#define FIBER_PORT_CM4_MPU_BASIC_RESERVED_OFFSET 80u
#define FIBER_PORT_CM4_MPU_EXTENDED_HIGH_FP_OFFSET 0u
#define FIBER_PORT_CM4_MPU_EXTENDED_LOW_FP_OFFSET 64u
#define FIBER_PORT_CM4_MPU_EXTENDED_CORE_OFFSET 132u
#define FIBER_PORT_CM4_MPU_EXTENDED_HARDWARE_OFFSET 172u
#define FIBER_PORT_CM4_MPU_EXTENDED_CURSOR_LIMIT_OFFSET 208u
#define FIBER_PORT_CM4_MPU_PROTECTED_CONTEXT_SIZE 212u
#define FIBER_PORT_CM4_MPU_CURSOR_OFFSET 0u
#define FIBER_PORT_CM4_MPU_REGIONS_OFFSET 4u
#define FIBER_PORT_CM4_MPU_CONTEXT_ALIGNMENT 8u

#define FIBER_PORT_CM4_MPU_BOOT_BEGIN_OFFSET 0u
#define FIBER_PORT_CM4_MPU_BOOT_END_OFFSET 4u
#define FIBER_PORT_CM4_MPU_BOOT_STACK_BASE_OFFSET 8u
#define FIBER_PORT_CM4_MPU_BOOT_STACK_TOP_OFFSET 12u
#define FIBER_PORT_CM4_MPU_BOOT_AVAIL_OFFSET 16u
#define FIBER_PORT_CM4_MPU_BOOT_ENTRY_OFFSET 20u
#define FIBER_PORT_CM4_MPU_BOOT_ARG_OFFSET 24u
#define FIBER_PORT_CM4_MPU_BOOT_PORT_ID_OFFSET 28u
#define FIBER_PORT_CM4_MPU_BOOT_LAYOUT_VERSION_OFFSET 32u
#define FIBER_PORT_CM4_MPU_BOOT_CONTEXT_SIZE_OFFSET 36u
#define FIBER_PORT_CM4_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET 40u
#define FIBER_PORT_CM4_MPU_BOOT_FEATURE_MASK_OFFSET 44u
#define FIBER_PORT_CM4_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET 48u
#define FIBER_PORT_CM4_MPU_BOOT_INITIAL_CONTROL_OFFSET 52u
#define FIBER_PORT_CM4_MPU_BOOT_TOTAL_REGIONS_OFFSET 56u
#define FIBER_PORT_CM4_MPU_BOOT_CONTEXT_REGIONS_OFFSET 60u
#define FIBER_PORT_CM4_MPU_BOOT_PROTECTED_WORDS_OFFSET 64u
#define FIBER_PORT_CM4_MPU_BOOT_MAGIC_OFFSET 68u
#define FIBER_PORT_CM4_MPU_BOOT_VERSION_OFFSET 72u
#define FIBER_PORT_CM4_MPU_BOOT_SEALED_OFFSET 74u
#define FIBER_PORT_CM4_MPU_BOOT_GUARD_LO_OFFSET 76u
#define FIBER_PORT_CM4_MPU_BOOT_GUARD_HI_OFFSET 80u
#define FIBER_PORT_CM4_MPU_BOOT_HASH_OFFSET 84u
#define FIBER_PORT_CM4_MPU_BOOT_SIZE 88u

FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: ARM_CM4_MPU requires 32-bit pointers");
FIBER_STATIC_ASSERT(sizeof(size_t) == 4u,
		"[fiber]: ARM_CM4_MPU requires 32-bit size_t");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM4_MPU slice 1 must remain non-selectable");
FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_REGION_COUNT ==
		FIBER_PORT_CM4_MPU_CONTEXT_REGION_COUNT,
		"[fiber]: ARM_CM4_MPU per-context region count changed");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_CONTEXT_WORDS == 53u,
		"[fiber]: ARM_CM4_MPU protected context must contain 53 words");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C05u,
		"[fiber]: ARM_CM4_MPU feature identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 212u,
		"[fiber]: ARM_CM4_MPU maximum protected context geometry changed");

FIBER_STATIC_ASSERT(offsetof(FiberPortMpuRegionRegisters, rbar) ==
		FIBER_PORT_CM4_MPU_REGION_RBAR_OFFSET,
		"[fiber]: ARM_CM4_MPU RBAR offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortMpuRegionRegisters, rasr) ==
		FIBER_PORT_CM4_MPU_REGION_RASR_OFFSET,
		"[fiber]: ARM_CM4_MPU RASR offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortMpuRegionRegisters) ==
		FIBER_PORT_CM4_MPU_REGION_SIZE,
		"[fiber]: ARM_CM4_MPU region pair size changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, control) ==
		FIBER_PORT_CM4_MPU_CORE_CONTROL_OFFSET,
		"[fiber]: ARM_CM4_MPU CONTROL offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, r4) ==
		FIBER_PORT_CM4_MPU_CORE_R4_OFFSET,
		"[fiber]: ARM_CM4_MPU r4 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, r5) ==
		FIBER_PORT_CM4_MPU_CORE_R5_OFFSET,
		"[fiber]: ARM_CM4_MPU r5 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, r6) ==
		FIBER_PORT_CM4_MPU_CORE_R6_OFFSET,
		"[fiber]: ARM_CM4_MPU r6 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, r7) ==
		FIBER_PORT_CM4_MPU_CORE_R7_OFFSET,
		"[fiber]: ARM_CM4_MPU r7 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, r8) ==
		FIBER_PORT_CM4_MPU_CORE_R8_OFFSET,
		"[fiber]: ARM_CM4_MPU r8 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, r9) ==
		FIBER_PORT_CM4_MPU_CORE_R9_OFFSET,
		"[fiber]: ARM_CM4_MPU r9 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, r10) ==
		FIBER_PORT_CM4_MPU_CORE_R10_OFFSET,
		"[fiber]: ARM_CM4_MPU r10 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, r11) ==
		FIBER_PORT_CM4_MPU_CORE_R11_OFFSET,
		"[fiber]: ARM_CM4_MPU r11 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedCoreContext, exc_return) ==
		FIBER_PORT_CM4_MPU_CORE_EXC_RETURN_OFFSET,
		"[fiber]: ARM_CM4_MPU EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedCoreContext) ==
		FIBER_PORT_CM4_MPU_CORE_SIZE,
		"[fiber]: ARM_CM4_MPU core context size changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedHardwareFrame, psp) ==
		FIBER_PORT_CM4_MPU_HARDWARE_PSP_OFFSET,
		"[fiber]: ARM_CM4_MPU PSP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedHardwareFrame, r0) ==
		FIBER_PORT_CM4_MPU_HARDWARE_R0_OFFSET,
		"[fiber]: ARM_CM4_MPU r0 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedHardwareFrame, r1) ==
		FIBER_PORT_CM4_MPU_HARDWARE_R1_OFFSET,
		"[fiber]: ARM_CM4_MPU r1 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedHardwareFrame, r2) ==
		FIBER_PORT_CM4_MPU_HARDWARE_R2_OFFSET,
		"[fiber]: ARM_CM4_MPU r2 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedHardwareFrame, r3) ==
		FIBER_PORT_CM4_MPU_HARDWARE_R3_OFFSET,
		"[fiber]: ARM_CM4_MPU r3 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedHardwareFrame, r12) ==
		FIBER_PORT_CM4_MPU_HARDWARE_R12_OFFSET,
		"[fiber]: ARM_CM4_MPU r12 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedHardwareFrame, lr) ==
		FIBER_PORT_CM4_MPU_HARDWARE_LR_OFFSET,
		"[fiber]: ARM_CM4_MPU LR offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedHardwareFrame, pc) ==
		FIBER_PORT_CM4_MPU_HARDWARE_PC_OFFSET,
		"[fiber]: ARM_CM4_MPU PC offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedHardwareFrame, xpsr) ==
		FIBER_PORT_CM4_MPU_HARDWARE_XPSR_OFFSET,
		"[fiber]: ARM_CM4_MPU xPSR offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedHardwareFrame) ==
		FIBER_PORT_CM4_MPU_HARDWARE_SIZE,
		"[fiber]: ARM_CM4_MPU copied hardware frame size changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedBasicContext, core) ==
		FIBER_PORT_CM4_MPU_BASIC_CORE_OFFSET,
		"[fiber]: ARM_CM4_MPU basic core offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedBasicContext, hardware) ==
		FIBER_PORT_CM4_MPU_BASIC_HARDWARE_OFFSET,
		"[fiber]: ARM_CM4_MPU basic hardware offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedBasicContext, cursor_limit) ==
		FIBER_PORT_CM4_MPU_BASIC_CURSOR_LIMIT_OFFSET,
		"[fiber]: ARM_CM4_MPU basic cursor offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedBasicContext, reserved) ==
		FIBER_PORT_CM4_MPU_BASIC_RESERVED_OFFSET,
		"[fiber]: ARM_CM4_MPU basic reserved offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedExtendedContext,
		high_fp_s16_s31) == FIBER_PORT_CM4_MPU_EXTENDED_HIGH_FP_OFFSET,
		"[fiber]: ARM_CM4_MPU high-FP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedExtendedContext,
		low_fp_s0_s15_fpscr) == FIBER_PORT_CM4_MPU_EXTENDED_LOW_FP_OFFSET,
		"[fiber]: ARM_CM4_MPU low-FP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedExtendedContext, core) ==
		FIBER_PORT_CM4_MPU_EXTENDED_CORE_OFFSET,
		"[fiber]: ARM_CM4_MPU extended core offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedExtendedContext, hardware) ==
		FIBER_PORT_CM4_MPU_EXTENDED_HARDWARE_OFFSET,
		"[fiber]: ARM_CM4_MPU extended hardware offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedExtendedContext, cursor_limit) ==
		FIBER_PORT_CM4_MPU_EXTENDED_CURSOR_LIMIT_OFFSET,
		"[fiber]: ARM_CM4_MPU extended cursor offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedContext) ==
		FIBER_PORT_CM4_MPU_PROTECTED_CONTEXT_SIZE,
		"[fiber]: ARM_CM4_MPU protected union size changed");

FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context_cursor) ==
		FIBER_PORT_CM4_MPU_CURSOR_OFFSET,
		"[fiber]: ARM_CM4_MPU cursor offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, mpu_regions) ==
		FIBER_PORT_CM4_MPU_REGIONS_OFFSET,
		"[fiber]: ARM_CM4_MPU region image offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context) ==
		FIBER_PORT_CM4_MPU_PROTECTED_CONTEXT_OFFSET,
		"[fiber]: ARM_CM4_MPU protected context offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, runtime_flags) ==
		FIBER_PORT_CM4_MPU_RUNTIME_FLAGS_OFFSET,
		"[fiber]: ARM_CM4_MPU runtime flags offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, boot) ==
		FIBER_PORT_CM4_MPU_BOOT_OFFSET,
		"[fiber]: ARM_CM4_MPU boot offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberContext) == FIBER_PORT_CM4_MPU_CONTEXT_SIZE,
		"[fiber]: ARM_CM4_MPU context size changed");
FIBER_STATIC_ASSERT(alignof(FiberContext) ==
		FIBER_PORT_CM4_MPU_CONTEXT_ALIGNMENT,
		"[fiber]: ARM_CM4_MPU context alignment changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) == FIBER_PORT_CM4_MPU_BOOT_SIZE,
		"[fiber]: ARM_CM4_MPU boot size changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, begin) ==
		FIBER_PORT_CM4_MPU_BOOT_BEGIN_OFFSET,
		"[fiber]: ARM_CM4_MPU boot begin offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, end) ==
		FIBER_PORT_CM4_MPU_BOOT_END_OFFSET,
		"[fiber]: ARM_CM4_MPU boot end offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, stack_base) ==
		FIBER_PORT_CM4_MPU_BOOT_STACK_BASE_OFFSET,
		"[fiber]: ARM_CM4_MPU boot stack-base offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, stack_top) ==
		FIBER_PORT_CM4_MPU_BOOT_STACK_TOP_OFFSET,
		"[fiber]: ARM_CM4_MPU boot stack-top offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, avail) ==
		FIBER_PORT_CM4_MPU_BOOT_AVAIL_OFFSET,
		"[fiber]: ARM_CM4_MPU boot avail offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, entry) ==
		FIBER_PORT_CM4_MPU_BOOT_ENTRY_OFFSET,
		"[fiber]: ARM_CM4_MPU boot entry offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, arg) ==
		FIBER_PORT_CM4_MPU_BOOT_ARG_OFFSET,
		"[fiber]: ARM_CM4_MPU boot arg offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_port_id) ==
		FIBER_PORT_CM4_MPU_BOOT_PORT_ID_OFFSET,
		"[fiber]: ARM_CM4_MPU boot port-ID offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_layout_version) ==
		FIBER_PORT_CM4_MPU_BOOT_LAYOUT_VERSION_OFFSET,
		"[fiber]: ARM_CM4_MPU boot layout offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_context_size) ==
		FIBER_PORT_CM4_MPU_BOOT_CONTEXT_SIZE_OFFSET,
		"[fiber]: ARM_CM4_MPU boot context-size offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_context_alignment) ==
		FIBER_PORT_CM4_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET,
		"[fiber]: ARM_CM4_MPU boot alignment offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_feature_mask) ==
		FIBER_PORT_CM4_MPU_BOOT_FEATURE_MASK_OFFSET,
		"[fiber]: ARM_CM4_MPU boot feature offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_initial_exc_return) ==
		FIBER_PORT_CM4_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET,
		"[fiber]: ARM_CM4_MPU boot EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_initial_control) ==
		FIBER_PORT_CM4_MPU_BOOT_INITIAL_CONTROL_OFFSET,
		"[fiber]: ARM_CM4_MPU boot CONTROL offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_mpu_total_regions) ==
		FIBER_PORT_CM4_MPU_BOOT_TOTAL_REGIONS_OFFSET,
		"[fiber]: ARM_CM4_MPU boot total-region offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_mpu_context_regions) ==
		FIBER_PORT_CM4_MPU_BOOT_CONTEXT_REGIONS_OFFSET,
		"[fiber]: ARM_CM4_MPU boot context-region offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_protected_context_words) ==
		FIBER_PORT_CM4_MPU_BOOT_PROTECTED_WORDS_OFFSET,
		"[fiber]: ARM_CM4_MPU boot protected-word offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, magic) ==
		FIBER_PORT_CM4_MPU_BOOT_MAGIC_OFFSET,
		"[fiber]: ARM_CM4_MPU boot magic offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, version) ==
		FIBER_PORT_CM4_MPU_BOOT_VERSION_OFFSET,
		"[fiber]: ARM_CM4_MPU boot version offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, sealed) ==
		FIBER_PORT_CM4_MPU_BOOT_SEALED_OFFSET,
		"[fiber]: ARM_CM4_MPU boot sealed offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, guard_lo) ==
		FIBER_PORT_CM4_MPU_BOOT_GUARD_LO_OFFSET,
		"[fiber]: ARM_CM4_MPU boot low-guard offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, guard_hi) ==
		FIBER_PORT_CM4_MPU_BOOT_GUARD_HI_OFFSET,
		"[fiber]: ARM_CM4_MPU boot high-guard offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, hash) ==
		FIBER_PORT_CM4_MPU_BOOT_HASH_OFFSET,
		"[fiber]: ARM_CM4_MPU boot hash offset changed");

#include "../fiber_port_traits.h"
#include "../fiber_port_context_cohort.h"

#endif /* FIBER_PORT_ARM_CM4_MPU_FIBER_PORTMACRO_H_ */
