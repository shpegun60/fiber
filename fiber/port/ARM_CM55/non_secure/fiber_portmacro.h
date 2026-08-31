/*
 * Exact Cortex-M55 TrustZone Non-secure selected-port dictionary.
 *
 * Slice 1 freezes the no-MPU, no-FPU, no-MVE frame and companion boundary.
 * It is not a runtime port: SVC/PendSV, Secure gateway, pool, and attachment
 * mechanics remain absent until their dedicated follow-up slices.
 */
#ifndef FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORTMACRO_H_

#include <stddef.h>
#include <stdint.h>

#ifdef FIBER_PORT_NAME
# error "[fiber]: ARM_CM55 port name must not be predefined"
#endif
#define FIBER_PORT_NAME "ARM_CM55"

#include "../../fiber_port_select.h"
#include "../../fiber_settings.h"
#include "../../fiber_compiler.h"
#include "fiber_port_types.h"

#if !FIBER_PORT_BUILD_SELECTED
# error "[fiber]: ARM_CM55 is build-selected only"
#endif

#if !FIBER_PORT_ARMV81M_MAINLINE
# error "[fiber]: ARM_CM55 requires the ARMv8.1-M Mainline architecture result"
#endif

/* GCC emits __ARM_ARCH_8M_MAIN__ for the scalar soft-float M55 target.
 * CMSIS __CORTEX_M == 55 closes the M33-versus-M55 distinction. */
#if !defined(__ARM_ARCH_8M_MAIN__) && !defined(__ARM_ARCH_8_1M_MAIN__)
# error "[fiber]: ARM_CM55 requires an ARMv8.1-M Mainline compiler target"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 55)
# error "[fiber]: ARM_CM55 manifest requires CMSIS __CORTEX_M == 55"
#endif

/* Non-secure GCC CMSE is level 1. Secure -mcmse builds report level 3 and
 * belong to the companion image, never to this scheduler/context image. */
#if !defined(__ARM_FEATURE_CMSE) || ((__ARM_FEATURE_CMSE + 0) != 1)
# error "[fiber]: ARM_CM55 requires a Non-secure CMSE level 1 build"
#endif

#if !defined(__VTOR_PRESENT) || (__VTOR_PRESENT != 1)
# error "[fiber]: ARM_CM55 requires __VTOR_PRESENT == 1"
#endif

#if defined(__FPU_PRESENT) && ((__FPU_PRESENT + 0) != 0) && \
		((__FPU_PRESENT + 0) != 1)
# error "[fiber]: ARM_CM55 CMSIS __FPU_PRESENT must be 0 or 1"
#endif

/* This exact scalar SecureContext cohort is intentionally not M55F. */
#if defined(__FPU_USED) && ((__FPU_USED + 0) != 0)
# error "[fiber]: ARM_CM55 requires __FPU_USED == 0"
#endif

#if defined(__ARM_FP) && ((__ARM_FP + 0) != 0)
# error "[fiber]: ARM_CM55 does not permit an FP register ABI"
#endif

#if defined(__VFP_FP__) && !defined(__SOFTFP__)
# error "[fiber]: ARM_CM55 does not permit a hard-FP compiler ABI"
#endif

#if defined(__ARM_FEATURE_MVE) && ((__ARM_FEATURE_MVE + 0) != 0)
# error "[fiber]: ARM_CM55 does not permit MVE"
#endif

#if defined(__ARM_FEATURE_PAC_DEFAULT) || defined(__ARM_FEATURE_PAUTH) || \
		defined(__ARM_FEATURE_PAUTH_DEFAULT)
# error "[fiber]: ARM_CM55 does not permit PAC"
#endif

#if defined(__ARM_FEATURE_BTI_DEFAULT) || defined(__ARM_FEATURE_BTI)
# error "[fiber]: ARM_CM55 does not permit BTI"
#endif

#if defined(FIBER_PORT_CM55_MPU_TOTAL_REGIONS) || \
		defined(FIBER_PORT_CM55F_MPU_TOTAL_REGIONS) || \
		defined(FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS) || \
		defined(FIBER_PORT_MPU_TOTAL_REGIONS)
# error "[fiber]: ARM_CM55 is non-MPU; select a separate MPU profile"
#endif

#if !defined(__NVIC_PRIO_BITS) || (__NVIC_PRIO_BITS < 1) || \
		(__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM55 requires 1..8 implemented NVIC priority bits"
#endif

#ifdef FIBER_PORT_RUNTIME_SELECTABLE
# error "[fiber]: ARM_CM55 runtime-selectable state must not be predefined"
#endif
#define FIBER_PORT_RUNTIME_SELECTABLE 0

/* Pinned FreeRTOS ARM_CM55/non_secure no-MPU/no-FPU/no-MVE SecureContext
 * frame: [SecureContext handle][PSPLIM][EXC_RETURN][r4-r11]. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portSTART_ADDRESS_MASK 0xFFFFFFFEu
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFBCu
#define fiber_portSVC_ORIGIN_EXC_RETURN 0xFFFFFFB8u
#define fiber_portNO_SECURE_CONTEXT 0u
#define fiber_portSECURE_CONTEXT_SLOT_WORDS 1u
#define fiber_portPSPLIM_SLOT_WORDS 1u
#define fiber_portCORE_SOFTWARE_WORDS 9u
#define fiber_portSOFTWARE_FRAME_WORDS \
	(fiber_portSECURE_CONTEXT_SLOT_WORDS + fiber_portPSPLIM_SLOT_WORDS + \
	 fiber_portCORE_SOFTWARE_WORDS)
#define fiber_portEXC_RETURN_WORD_INDEX \
	(fiber_portSECURE_CONTEXT_SLOT_WORDS + fiber_portPSPLIM_SLOT_WORDS)

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1
#define FIBER_PORT_HAS_VTOR 1
#define FIBER_PORT_HAS_PSPLIM 1
#define FIBER_PORT_HAS_FPU 0
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#define FIBER_PORT_STACK_ALIGNMENT fiber_portBYTE_ALIGNMENT
#define FIBER_PORT_BOOT_CLEARS_FPCA 0
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
#define FIBER_PORT_USES_PSPLIM_REGISTER 1
#define FIBER_PORT_INITIAL_EXC_RETURN fiber_portINITIAL_EXC_RETURN
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_BASEPRI
#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0
#ifndef FIBER_PORT_IS_V8M
# define FIBER_PORT_IS_V8M 1
#endif
#define FIBER_PORT_HAS_SECURITY_EXT 1
#define FIBER_PORT_RUNS_NONSECURE 1
/* Standard names address the currently executing Non-secure bank. */
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 1
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 1
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0

#ifndef FIBER_PORT_SCHEDULER_BASEPRI
# ifdef FIBER_SCHEDULER_BASEPRI
#  define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI
# else
#  if __NVIC_PRIO_BITS == 8
#   define FIBER_PORT_SCHEDULER_BASEPRI 2u
#  else
#   define FIBER_PORT_SCHEDULER_BASEPRI \
	(1u << (8u - __NVIC_PRIO_BITS))
#  endif
# endif
#endif

#ifndef FIBER_SCHEDULER_BASEPRI
# define FIBER_SCHEDULER_BASEPRI FIBER_PORT_SCHEDULER_BASEPRI
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI == 0u
# error "[fiber]: ARM_CM55 scheduler BASEPRI threshold must be non-zero"
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI > 255u
# error "[fiber]: ARM_CM55 scheduler BASEPRI threshold must fit in 8 bits"
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI &
		((1u << (8u - __NVIC_PRIO_BITS)) - 1u)) == 0u,
		"[fiber]: ARM_CM55 scheduler BASEPRI uses unimplemented priority bits");
#if __NVIC_PRIO_BITS == 8
FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI & 1u) == 0u,
		"[fiber]: ARM_CM55 BASEPRI bit 0 is subpriority when all 8 bits exist");
#endif

/* ASCII "C55S" identifies the scalar M55 TrustZone/SecureContext cohort. */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x43353553u
#define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010001u
#define FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT 0x00000002u
#define FIBER_PORT_CONTEXT_FEATURE_SECURE_CONTEXT_SLOT 0x00000008u
#define FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE 0x00000080u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	(FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_SECURE_CONTEXT_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE)

#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES 0u
#define FIBER_PORT_EXC_PER_LEVEL_BYTES FIBER_PORT_EXC_BASE_BYTES
#define FIBER_PORT_SOFTWARE_FRAME_WORDS fiber_portSOFTWARE_FRAME_WORDS
#define FIBER_PORT_SOFTWARE_FRAME_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX fiber_portEXC_RETURN_WORD_INDEX
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES 0u
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_BASE_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 4u

/* Frozen 32-bit public storage layout. */
#define FIBER_PORT_CM55_CONTEXT_SP_OFFSET 0u
#define FIBER_PORT_CM55_CONTEXT_BOOT_OFFSET 4u
#define FIBER_PORT_CM55_CONTEXT_SIZE 80u
#define FIBER_PORT_CM55_CONTEXT_ALIGNMENT 4u
#define FIBER_PORT_CM55_BOOT_SIZE 76u
#define FIBER_PORT_CM55_BOOT_SECURE_STACK_BYTES_OFFSET 28u

FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: ARM_CM55 requires 32-bit pointers");
FIBER_STATIC_ASSERT(sizeof(size_t) == 4u,
		"[fiber]: ARM_CM55 requires 32-bit size_t");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM55 Slice 1 must not claim a runtime");
FIBER_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS == 11u,
		"[fiber]: ARM_CM55 software frame must contain eleven words");
FIBER_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX == 2u,
		"[fiber]: ARM_CM55 EXC_RETURN must follow SecureContext and PSPLIM");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x8Au,
		"[fiber]: ARM_CM55 context feature identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_CONTEXT_BYTES == 76u,
		"[fiber]: ARM_CM55 initial context geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 80u,
		"[fiber]: ARM_CM55 maximum context geometry changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, sp) ==
		FIBER_PORT_CM55_CONTEXT_SP_OFFSET,
		"[fiber]: ARM_CM55 saved-SP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, boot) ==
		FIBER_PORT_CM55_CONTEXT_BOOT_OFFSET,
		"[fiber]: ARM_CM55 boot offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberContext) == FIBER_PORT_CM55_CONTEXT_SIZE,
		"[fiber]: ARM_CM55 context size changed");
FIBER_STATIC_ASSERT(alignof(FiberContext) == FIBER_PORT_CM55_CONTEXT_ALIGNMENT,
		"[fiber]: ARM_CM55 context alignment changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) == FIBER_PORT_CM55_BOOT_SIZE,
		"[fiber]: ARM_CM55 boot size changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, secure_stack_bytes) ==
		FIBER_PORT_CM55_BOOT_SECURE_STACK_BYTES_OFFSET,
		"[fiber]: ARM_CM55 secure-stack request offset changed");
FIBER_STATIC_ASSERT(fiber_portSVC_ORIGIN_EXC_RETURN == 0xFFFFFFB8u,
		"[fiber]: ARM_CM55 first-start SVC origin changed");
FIBER_STATIC_ASSERT((fiber_portINITIAL_EXC_RETURN & ~4u) ==
		fiber_portSVC_ORIGIN_EXC_RETURN,
		"[fiber]: ARM_CM55 SVC/PSP EXC_RETURN relationship changed");

#include "../../fiber_port_traits.h"
#include "../../fiber_port_context_cohort.h"
#include "../../fiber_port_geometry.h"

#endif /* FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORTMACRO_H_ */
