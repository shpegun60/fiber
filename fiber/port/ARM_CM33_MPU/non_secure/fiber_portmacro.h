/*
 * fiber_portmacro.h
 *
 * Exact Cortex-M33 MPU Non-secure dictionary, implementation slice 1.
 * This is the FreeRTOS ARM_CM33_NTZ no-FPU/no-TrustZone/no-SecureContext
 * profile with an explicit 8- or 16-region manifest. It intentionally exports
 * types and traits only; SVC/PendSV and the forward runtime ABI arrive in
 * later separately validated slices.
 */
#ifndef FIBER_PORT_ARM_CM33_MPU_NON_SECURE_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM33_MPU_NON_SECURE_FIBER_PORTMACRO_H_

#include <stddef.h>
#include <stdint.h>

#ifdef FIBER_PORT_NAME
# error "[fiber]: ARM_CM33_MPU port name must not be predefined"
#endif
#define FIBER_PORT_NAME "ARM_CM33_MPU"

#include "../../fiber_port_select.h"
#include "../../fiber_settings.h"
#include "../../fiber_compiler.h"

#if !FIBER_PORT_BUILD_SELECTED
# error "[fiber]: ARM_CM33_MPU is build-selected only"
#endif

#if !FIBER_PORT_ARMV8M_MAINLINE
# error "[fiber]: ARM_CM33_MPU requires the ARMv8-M Mainline architecture result"
#endif

#if !defined(__ARM_ARCH_8M_MAIN__)
# error "[fiber]: ARM_CM33_MPU requires an ARMv8-M Mainline compiler target"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 33)
# error "[fiber]: ARM_CM33_MPU manifest requires CMSIS __CORTEX_M == 33"
#endif

#if !defined(__MPU_PRESENT) || (__MPU_PRESENT != 1)
# error "[fiber]: ARM_CM33_MPU manifest requires __MPU_PRESENT == 1"
#endif

#if !defined(__VTOR_PRESENT) || (__VTOR_PRESENT != 1)
# error "[fiber]: ARM_CM33_MPU manifest requires __VTOR_PRESENT == 1"
#endif

#if defined(__ARM_FEATURE_CMSE) && ((__ARM_FEATURE_CMSE + 0) >= 3)
# error "[fiber]: ARM_CM33_MPU slice 1 excludes Secure CMSE builds"
#endif

#if defined(__FPU_PRESENT) && ((__FPU_PRESENT + 0) != 0) && \
		((__FPU_PRESENT + 0) != 1)
# error "[fiber]: ARM_CM33_MPU CMSIS __FPU_PRESENT must be 0 or 1"
#endif

#if defined(__FPU_USED) && ((__FPU_USED + 0) != 0)
# error "[fiber]: ARM_CM33_MPU slice 1 requires __FPU_USED == 0"
#endif

#if defined(__ARM_FP) && ((__ARM_FP + 0) != 0)
# error "[fiber]: ARM_CM33_MPU slice 1 does not permit an FP register ABI"
#endif

#if defined(__VFP_FP__) && !defined(__SOFTFP__)
# error "[fiber]: ARM_CM33_MPU slice 1 does not permit a hard-FP compiler ABI"
#endif

#if defined(__ARM_FEATURE_MVE) && ((__ARM_FEATURE_MVE + 0) != 0)
# error "[fiber]: ARM_CM33_MPU slice 1 does not permit MVE"
#endif

#if defined(__ARM_FEATURE_PAC_DEFAULT) || defined(__ARM_FEATURE_PAUTH) || \
		defined(__ARM_FEATURE_PAUTH_DEFAULT)
# error "[fiber]: ARM_CM33_MPU slice 1 does not permit PAC"
#endif

#if defined(__ARM_FEATURE_BTI_DEFAULT) || defined(__ARM_FEATURE_BTI)
# error "[fiber]: ARM_CM33_MPU slice 1 does not permit BTI"
#endif

#if !defined(__NVIC_PRIO_BITS) || (__NVIC_PRIO_BITS < 1) || \
		(__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM33_MPU requires 1..8 implemented NVIC priority bits"
#endif

#ifndef FIBER_PORT_CM33_MPU_TOTAL_REGIONS
# error "[fiber]: ARM_CM33_MPU requires FIBER_PORT_CM33_MPU_TOTAL_REGIONS=8 or 16"
#endif

#if (FIBER_PORT_CM33_MPU_TOTAL_REGIONS != 8) && \
		(FIBER_PORT_CM33_MPU_TOTAL_REGIONS != 16)
# error "[fiber]: ARM_CM33_MPU supports exactly 8 or 16 MPU regions"
#endif

#ifdef FIBER_PORT_RUNTIME_SELECTABLE
# error "[fiber]: ARM_CM33_MPU runtime-selectable state must not be predefined"
#endif
#define FIBER_PORT_RUNTIME_SELECTABLE 0

#include "fiber_port_types.h"

#ifndef fiber_portFORCE_INLINE
# if defined(__GNUC__) || defined(__clang__)
#  define fiber_portFORCE_INLINE static inline __attribute__((always_inline))
# else
#  define fiber_portFORCE_INLINE static inline
# endif
#endif

#ifndef fiber_portASM
# define fiber_portASM __asm
#endif

#define fiber_portCOMPILER_BARRIER() \
	fiber_portASM volatile("" ::: "memory")
#define fiber_portDATA_SYNC_BARRIER() \
	fiber_portASM volatile("dsb" ::: "memory")
#define fiber_portINST_SYNC_BARRIER() \
	fiber_portASM volatile("isb" ::: "memory")

/* Port-owned SVC namespace, reserved now so later runtime slices cannot drift
 * from the protected first-start/yield/task-return provenance contract. */
#ifdef FIBER_SVC_START_NUMBER
# error "[fiber]: ARM_CM33_MPU owns its complete SVC namespace"
#endif
#define FIBER_SVC_START_NUMBER 70u
#define fiber_portSVC_START FIBER_SVC_START_NUMBER
#define fiber_portSVC_YIELD 71u
#define fiber_portSVC_RETURN 72u

/* Exact ARMv8-M Mainline MPU layout used by the pinned GCC ARM_CM33_NTZ port. */
#define fiber_portMPU_TOTAL_REGIONS FIBER_PORT_CM33_MPU_TOTAL_REGIONS
#define fiber_portMPU_PRIVILEGED_FLASH_REGION 0u
#define fiber_portMPU_UNPRIVILEGED_FLASH_REGION 1u
#define fiber_portMPU_UNPRIVILEGED_SYSCALLS_REGION 2u
#define fiber_portMPU_PRIVILEGED_DATA_REGION 3u
#define fiber_portMPU_STACK_REGION 4u
#define fiber_portMPU_FIRST_CONFIGURABLE_REGION 5u
#define fiber_portMPU_LAST_CONFIGURABLE_REGION \
	(fiber_portMPU_TOTAL_REGIONS - 1u)
#define fiber_portMPU_CONFIGURABLE_REGION_COUNT \
	(fiber_portMPU_TOTAL_REGIONS - fiber_portMPU_FIRST_CONFIGURABLE_REGION)
#define fiber_portMPU_CONTEXT_REGION_COUNT \
	FIBER_PORT_CM33_MPU_CONTEXT_REGION_COUNT
#define fiber_portMPU_GLOBAL_REGION_COUNT 4u
#define fiber_portMPU_EXPECTED_TYPE (fiber_portMPU_TOTAL_REGIONS << 8u)
#define fiber_portMPU_CTRL_ENABLE 0x00000001u
#define fiber_portMPU_CTRL_PRIVDEFENA 0x00000004u
#define fiber_portMPU_CTRL_REQUIRED \
	(fiber_portMPU_CTRL_ENABLE | fiber_portMPU_CTRL_PRIVDEFENA)

#define fiber_portMPU_RBAR_ADDRESS_MASK UINT32_C(0xFFFFFFE0)
#define fiber_portMPU_RLAR_ADDRESS_MASK UINT32_C(0xFFFFFFE0)
#define fiber_portMPU_RBAR_ACCESS_MASK (3u << 1u)
#define fiber_portMPU_REGION_NON_SHAREABLE (0u << 3u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_WRITE (0u << 1u)
#define fiber_portMPU_REGION_READ_WRITE (1u << 1u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_ONLY (2u << 1u)
#define fiber_portMPU_REGION_READ_ONLY (3u << 1u)
#define fiber_portMPU_REGION_EXECUTE_NEVER 1u
#define fiber_portMPU_RLAR_ATTR_INDEX0 (0u << 1u)
#define fiber_portMPU_RLAR_ATTR_INDEX1 (1u << 1u)
#define fiber_portMPU_RLAR_REGION_ENABLE 1u
#define fiber_portMPU_MAIR_NORMAL_MEMORY_BUFFERABLE_CACHEABLE 0xFFu
#define fiber_portMPU_MAIR_DEVICE_MEMORY_NGNRE 0x04u
#define fiber_portMPU_MAIR0_DEFAULT \
	(fiber_portMPU_MAIR_NORMAL_MEMORY_BUFFERABLE_CACHEABLE | \
	 (fiber_portMPU_MAIR_DEVICE_MEMORY_NGNRE << 8u))

/* Frame and selected-port trait facts. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portSTART_ADDRESS_MASK 0xFFFFFFFEu
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFBCu
#define fiber_portSVC_ORIGIN_EXC_RETURN 0xFFFFFFB8u
#define fiber_portINITIAL_CONTROL_PRIVILEGED 0x00000002u
#define fiber_portINITIAL_CONTROL_UNPRIVILEGED 0x00000003u
#define fiber_portPROTECTED_CONTEXT_WORDS 21u
#define fiber_portPROTECTED_RESTORE_WORDS 20u
#define fiber_portPROTECTED_HARDWARE_WORDS 8u
#define fiber_portSTACK_FRAME_HAS_PADDING_FLAG (1u << 0u)
#define fiber_portTASK_IS_PRIVILEGED_FLAG (1u << 1u)

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
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 1
#define FIBER_PORT_HAS_PSPLIM_SLOT 1
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0

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
# error "[fiber]: ARM_CM33_MPU scheduler BASEPRI threshold must be non-zero"
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI > 255u
# error "[fiber]: ARM_CM33_MPU scheduler BASEPRI threshold must fit in 8 bits"
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI &
		((1u << (8u - __NVIC_PRIO_BITS)) - 1u)) == 0u,
		"[fiber]: ARM_CM33_MPU BASEPRI uses unimplemented priority bits");
#if __NVIC_PRIO_BITS == 8
FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI & 1u) == 0u,
		"[fiber]: ARM_CM33_MPU BASEPRI bit 0 is subpriority");
#endif

#if FIBER_PORT_CM33_MPU_TOTAL_REGIONS == 8
# define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010008u
# define FIBER_PORT_CM33_MPU_PROTECTED_CONTEXT_OFFSET 40u
# define FIBER_PORT_CM33_MPU_RUNTIME_FLAGS_OFFSET 124u
# define FIBER_PORT_CM33_MPU_BOOT_OFFSET 128u
# define FIBER_PORT_CM33_MPU_CONTEXT_SIZE 216u
#else
# define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010010u
# define FIBER_PORT_CM33_MPU_PROTECTED_CONTEXT_OFFSET 104u
# define FIBER_PORT_CM33_MPU_RUNTIME_FLAGS_OFFSET 188u
# define FIBER_PORT_CM33_MPU_BOOT_OFFSET 192u
# define FIBER_PORT_CM33_MPU_CONTEXT_SIZE 280u
#endif

/* ASCII "C33M". This no-TrustZone cohort has a one-past context cursor
 * target, not a SecureContext slot. */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x4333334Du
#define FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT 0x00000002u
#define FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT 0x00000004u
#define FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE 0x00000080u
#define FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE 0x00000400u
#define FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME 0x00000800u
#define FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED 0x00001000u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	(FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE | \
	 FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE | \
	 FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME | \
	 FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED)

/* The protected image owns all active saved words. cursor_limit is a one-past
 * cursor target, as in the FreeRTOS xMPU_SETTINGS ulContext array. The generic
 * geometry is conservative; protected storage itself never lives on the user
 * PSP stack. */
#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES 0u
#define FIBER_PORT_EXC_PER_LEVEL_BYTES FIBER_PORT_EXC_BASE_BYTES
#define FIBER_PORT_SOFTWARE_FRAME_WORDS fiber_portPROTECTED_RESTORE_WORDS
#define FIBER_PORT_SOFTWARE_FRAME_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX 19u
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES 0u
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_BASE_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 0u

/* Physical user-PSP geometry. The protected image is copied to and from
 * privileged storage, so raw stack admission must not count its 20 active
 * words. */
#define FIBER_PORT_CM33_MPU_PSP_INITIAL_FRAME_BYTES \
	FIBER_PORT_EXC_BASE_BYTES
#define FIBER_PORT_CM33_MPU_PSP_MAX_FRAME_BYTES \
	(FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_CM33_MPU_STACK_REQUIRED_BYTES \
	((FIBER_PORT_CM33_MPU_PSP_MAX_FRAME_BYTES + \
	  FIBER_PORT_STACK_ALIGNMENT - 1u) & \
	 ~((uint32_t)FIBER_PORT_STACK_ALIGNMENT - 1u))

/* Frozen GCC 32-bit storage offsets consumed by later protected assembly. */
#define FIBER_PORT_CM33_MPU_REGION_RBAR_OFFSET 0u
#define FIBER_PORT_CM33_MPU_REGION_RLAR_OFFSET 4u
#define FIBER_PORT_CM33_MPU_REGION_SIZE 8u
#define FIBER_PORT_CM33_MPU_PROTECTED_R4_OFFSET 0u
#define FIBER_PORT_CM33_MPU_PROTECTED_R5_OFFSET 4u
#define FIBER_PORT_CM33_MPU_PROTECTED_R6_OFFSET 8u
#define FIBER_PORT_CM33_MPU_PROTECTED_R7_OFFSET 12u
#define FIBER_PORT_CM33_MPU_PROTECTED_R8_OFFSET 16u
#define FIBER_PORT_CM33_MPU_PROTECTED_R9_OFFSET 20u
#define FIBER_PORT_CM33_MPU_PROTECTED_R10_OFFSET 24u
#define FIBER_PORT_CM33_MPU_PROTECTED_R11_OFFSET 28u
#define FIBER_PORT_CM33_MPU_PROTECTED_R0_OFFSET 32u
#define FIBER_PORT_CM33_MPU_PROTECTED_R1_OFFSET 36u
#define FIBER_PORT_CM33_MPU_PROTECTED_R2_OFFSET 40u
#define FIBER_PORT_CM33_MPU_PROTECTED_R3_OFFSET 44u
#define FIBER_PORT_CM33_MPU_PROTECTED_R12_OFFSET 48u
#define FIBER_PORT_CM33_MPU_PROTECTED_LR_OFFSET 52u
#define FIBER_PORT_CM33_MPU_PROTECTED_PC_OFFSET 56u
#define FIBER_PORT_CM33_MPU_PROTECTED_XPSR_OFFSET 60u
#define FIBER_PORT_CM33_MPU_PROTECTED_PSP_OFFSET 64u
#define FIBER_PORT_CM33_MPU_PROTECTED_PSPLIM_OFFSET 68u
#define FIBER_PORT_CM33_MPU_PROTECTED_CONTROL_OFFSET 72u
#define FIBER_PORT_CM33_MPU_PROTECTED_EXC_RETURN_OFFSET 76u
#define FIBER_PORT_CM33_MPU_PROTECTED_CURSOR_LIMIT_OFFSET 80u
#define FIBER_PORT_CM33_MPU_PROTECTED_CONTEXT_SIZE 84u
#define FIBER_PORT_CM33_MPU_CURSOR_OFFSET 0u
#define FIBER_PORT_CM33_MPU_MAIR0_OFFSET 4u
#define FIBER_PORT_CM33_MPU_REGIONS_OFFSET 8u
#define FIBER_PORT_CM33_MPU_CONTEXT_ALIGNMENT 8u

#define FIBER_PORT_CM33_MPU_BOOT_BEGIN_OFFSET 0u
#define FIBER_PORT_CM33_MPU_BOOT_END_OFFSET 4u
#define FIBER_PORT_CM33_MPU_BOOT_STACK_BASE_OFFSET 8u
#define FIBER_PORT_CM33_MPU_BOOT_STACK_TOP_OFFSET 12u
#define FIBER_PORT_CM33_MPU_BOOT_AVAIL_OFFSET 16u
#define FIBER_PORT_CM33_MPU_BOOT_ENTRY_OFFSET 20u
#define FIBER_PORT_CM33_MPU_BOOT_ARG_OFFSET 24u
#define FIBER_PORT_CM33_MPU_BOOT_PORT_ID_OFFSET 28u
#define FIBER_PORT_CM33_MPU_BOOT_LAYOUT_VERSION_OFFSET 32u
#define FIBER_PORT_CM33_MPU_BOOT_CONTEXT_SIZE_OFFSET 36u
#define FIBER_PORT_CM33_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET 40u
#define FIBER_PORT_CM33_MPU_BOOT_FEATURE_MASK_OFFSET 44u
#define FIBER_PORT_CM33_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET 48u
#define FIBER_PORT_CM33_MPU_BOOT_INITIAL_CONTROL_OFFSET 52u
#define FIBER_PORT_CM33_MPU_BOOT_TOTAL_REGIONS_OFFSET 56u
#define FIBER_PORT_CM33_MPU_BOOT_CONTEXT_REGIONS_OFFSET 60u
#define FIBER_PORT_CM33_MPU_BOOT_PROTECTED_WORDS_OFFSET 64u
#define FIBER_PORT_CM33_MPU_BOOT_MAGIC_OFFSET 68u
#define FIBER_PORT_CM33_MPU_BOOT_VERSION_OFFSET 72u
#define FIBER_PORT_CM33_MPU_BOOT_SEALED_OFFSET 74u
#define FIBER_PORT_CM33_MPU_BOOT_GUARD_LO_OFFSET 76u
#define FIBER_PORT_CM33_MPU_BOOT_GUARD_HI_OFFSET 80u
#define FIBER_PORT_CM33_MPU_BOOT_HASH_OFFSET 84u
#define FIBER_PORT_CM33_MPU_BOOT_SIZE 88u

FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: ARM_CM33_MPU requires 32-bit pointers");
FIBER_STATIC_ASSERT(sizeof(size_t) == 4u,
		"[fiber]: ARM_CM33_MPU requires 32-bit size_t");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM33_MPU slice 1 must not expose runtime operations");
FIBER_STATIC_ASSERT(fiber_portSVC_START == 70u,
		"[fiber]: ARM_CM33_MPU first-start SVC changed");
FIBER_STATIC_ASSERT(fiber_portSVC_YIELD == 71u,
		"[fiber]: ARM_CM33_MPU yield SVC changed");
FIBER_STATIC_ASSERT(fiber_portSVC_RETURN == 72u,
		"[fiber]: ARM_CM33_MPU task-return SVC changed");
FIBER_STATIC_ASSERT((fiber_portSVC_START != fiber_portSVC_YIELD) &&
		(fiber_portSVC_START != fiber_portSVC_RETURN) &&
		(fiber_portSVC_YIELD != fiber_portSVC_RETURN),
		"[fiber]: ARM_CM33_MPU SVC namespace collided");
FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_REGION_COUNT ==
		FIBER_PORT_CM33_MPU_CONTEXT_REGION_COUNT,
		"[fiber]: ARM_CM33_MPU per-context region count changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_REGION_COUNT ==
		(fiber_portMPU_TOTAL_REGIONS - 4u),
		"[fiber]: ARM_CM33_MPU global/per-context region geometry changed");
FIBER_STATIC_ASSERT(fiber_portMPU_STACK_REGION == 4u,
		"[fiber]: ARM_CM33_MPU stack region changed");
FIBER_STATIC_ASSERT(fiber_portMPU_FIRST_CONFIGURABLE_REGION == 5u,
		"[fiber]: ARM_CM33_MPU configurable region origin changed");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_CONTEXT_WORDS == 21u,
		"[fiber]: ARM_CM33_MPU protected context must contain 21 words");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_RESTORE_WORDS == 20u,
		"[fiber]: ARM_CM33_MPU protected restore image changed");
FIBER_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX == 19u &&
		FIBER_PORT_INITIAL_CONTEXT_BYTES == 112u &&
		FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 116u,
		"[fiber]: ARM_CM33_MPU logical restore geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_CONTROL_SLOT == 1,
		"[fiber]: ARM_CM33_MPU must preserve CONTROL per context");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_PSPLIM_SLOT == 1,
		"[fiber]: ARM_CM33_MPU must preserve PSPLIM per context");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 0,
		"[fiber]: ARM_CM33_MPU slice 1 must not expose SecureContext");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_PAC_KEY_SLOT == 0,
		"[fiber]: ARM_CM33_MPU slice 1 must not expose PAC state");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_FPU == 0 &&
		FIBER_PORT_HAS_MVE == 0 && FIBER_PORT_HAS_PAC == 0 &&
		FIBER_PORT_HAS_BTI == 0,
		"[fiber]: ARM_CM33_MPU slice 1 feature cohort changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C86u,
		"[fiber]: ARM_CM33_MPU context feature identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM33_MPU_PSP_INITIAL_FRAME_BYTES == 32u &&
		FIBER_PORT_CM33_MPU_PSP_MAX_FRAME_BYTES == 36u &&
		FIBER_PORT_CM33_MPU_STACK_REQUIRED_BYTES == 40u,
		"[fiber]: ARM_CM33_MPU physical PSP geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM33_MPU_PROTECTED_CONTEXT_OFFSET ==
		(FIBER_PORT_CM33_MPU_REGIONS_OFFSET +
		 (FIBER_PORT_CM33_MPU_CONTEXT_REGION_COUNT *
		  FIBER_PORT_CM33_MPU_REGION_SIZE)),
		"[fiber]: ARM_CM33_MPU protected context offset changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM33_MPU_BOOT_OFFSET ==
		(FIBER_PORT_CM33_MPU_RUNTIME_FLAGS_OFFSET + 4u),
		"[fiber]: ARM_CM33_MPU boot offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortMpuRegionRegisters, rbar) ==
		FIBER_PORT_CM33_MPU_REGION_RBAR_OFFSET &&
		offsetof(FiberPortMpuRegionRegisters, rlar) ==
		FIBER_PORT_CM33_MPU_REGION_RLAR_OFFSET &&
		sizeof(FiberPortMpuRegionRegisters) == FIBER_PORT_CM33_MPU_REGION_SIZE,
		"[fiber]: ARM_CM33_MPU MPU region layout changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r4) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R4_OFFSET &&
		offsetof(FiberPortProtectedContext, r5) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R5_OFFSET &&
		offsetof(FiberPortProtectedContext, r6) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R6_OFFSET &&
		offsetof(FiberPortProtectedContext, r7) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R7_OFFSET &&
		offsetof(FiberPortProtectedContext, r8) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R8_OFFSET &&
		offsetof(FiberPortProtectedContext, r9) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R9_OFFSET &&
		offsetof(FiberPortProtectedContext, r10) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R10_OFFSET &&
		offsetof(FiberPortProtectedContext, r11) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R11_OFFSET,
		"[fiber]: ARM_CM33_MPU callee-saved context offsets changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r0) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R0_OFFSET &&
		offsetof(FiberPortProtectedContext, r1) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R1_OFFSET &&
		offsetof(FiberPortProtectedContext, r2) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R2_OFFSET &&
		offsetof(FiberPortProtectedContext, r3) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R3_OFFSET &&
		offsetof(FiberPortProtectedContext, r12) ==
		FIBER_PORT_CM33_MPU_PROTECTED_R12_OFFSET &&
		offsetof(FiberPortProtectedContext, lr) ==
		FIBER_PORT_CM33_MPU_PROTECTED_LR_OFFSET &&
		offsetof(FiberPortProtectedContext, pc) ==
		FIBER_PORT_CM33_MPU_PROTECTED_PC_OFFSET &&
		offsetof(FiberPortProtectedContext, xpsr) ==
		FIBER_PORT_CM33_MPU_PROTECTED_XPSR_OFFSET,
		"[fiber]: ARM_CM33_MPU copied hardware-frame offsets changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, psp) ==
		FIBER_PORT_CM33_MPU_PROTECTED_PSP_OFFSET &&
		offsetof(FiberPortProtectedContext, psplim) ==
		FIBER_PORT_CM33_MPU_PROTECTED_PSPLIM_OFFSET &&
		offsetof(FiberPortProtectedContext, control) ==
		FIBER_PORT_CM33_MPU_PROTECTED_CONTROL_OFFSET &&
		offsetof(FiberPortProtectedContext, exc_return) ==
		FIBER_PORT_CM33_MPU_PROTECTED_EXC_RETURN_OFFSET &&
		offsetof(FiberPortProtectedContext, cursor_limit) ==
		FIBER_PORT_CM33_MPU_PROTECTED_CURSOR_LIMIT_OFFSET &&
		sizeof(FiberPortProtectedContext) ==
		FIBER_PORT_CM33_MPU_PROTECTED_CONTEXT_SIZE,
		"[fiber]: ARM_CM33_MPU special-context offsets changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM33_MPU_PROTECTED_CURSOR_LIMIT_OFFSET ==
		(FIBER_PORT_CM33_MPU_PROTECTED_CONTEXT_SIZE - 4u),
		"[fiber]: ARM_CM33_MPU cursor limit must remain final");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, begin) ==
		FIBER_PORT_CM33_MPU_BOOT_BEGIN_OFFSET &&
		offsetof(FiberPortBoot, end) == FIBER_PORT_CM33_MPU_BOOT_END_OFFSET &&
		offsetof(FiberPortBoot, stack_base) ==
		FIBER_PORT_CM33_MPU_BOOT_STACK_BASE_OFFSET &&
		offsetof(FiberPortBoot, stack_top) ==
		FIBER_PORT_CM33_MPU_BOOT_STACK_TOP_OFFSET &&
		offsetof(FiberPortBoot, avail) ==
		FIBER_PORT_CM33_MPU_BOOT_AVAIL_OFFSET &&
		offsetof(FiberPortBoot, entry) ==
		FIBER_PORT_CM33_MPU_BOOT_ENTRY_OFFSET &&
		offsetof(FiberPortBoot, arg) == FIBER_PORT_CM33_MPU_BOOT_ARG_OFFSET,
		"[fiber]: ARM_CM33_MPU boot base offsets changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_port_id) ==
		FIBER_PORT_CM33_MPU_BOOT_PORT_ID_OFFSET &&
		offsetof(FiberPortBoot, abi_layout_version) ==
		FIBER_PORT_CM33_MPU_BOOT_LAYOUT_VERSION_OFFSET &&
		offsetof(FiberPortBoot, abi_context_size) ==
		FIBER_PORT_CM33_MPU_BOOT_CONTEXT_SIZE_OFFSET &&
		offsetof(FiberPortBoot, abi_context_alignment) ==
		FIBER_PORT_CM33_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET &&
		offsetof(FiberPortBoot, abi_feature_mask) ==
		FIBER_PORT_CM33_MPU_BOOT_FEATURE_MASK_OFFSET &&
		offsetof(FiberPortBoot, abi_initial_exc_return) ==
		FIBER_PORT_CM33_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET &&
		offsetof(FiberPortBoot, abi_initial_control) ==
		FIBER_PORT_CM33_MPU_BOOT_INITIAL_CONTROL_OFFSET &&
		offsetof(FiberPortBoot, abi_mpu_total_regions) ==
		FIBER_PORT_CM33_MPU_BOOT_TOTAL_REGIONS_OFFSET &&
		offsetof(FiberPortBoot, abi_mpu_context_regions) ==
		FIBER_PORT_CM33_MPU_BOOT_CONTEXT_REGIONS_OFFSET &&
		offsetof(FiberPortBoot, abi_protected_context_words) ==
		FIBER_PORT_CM33_MPU_BOOT_PROTECTED_WORDS_OFFSET,
		"[fiber]: ARM_CM33_MPU boot ABI offsets changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, magic) ==
		FIBER_PORT_CM33_MPU_BOOT_MAGIC_OFFSET &&
		offsetof(FiberPortBoot, version) ==
		FIBER_PORT_CM33_MPU_BOOT_VERSION_OFFSET &&
		offsetof(FiberPortBoot, sealed) ==
		FIBER_PORT_CM33_MPU_BOOT_SEALED_OFFSET &&
		offsetof(FiberPortBoot, guard_lo) ==
		FIBER_PORT_CM33_MPU_BOOT_GUARD_LO_OFFSET &&
		offsetof(FiberPortBoot, guard_hi) ==
		FIBER_PORT_CM33_MPU_BOOT_GUARD_HI_OFFSET &&
		offsetof(FiberPortBoot, hash) == FIBER_PORT_CM33_MPU_BOOT_HASH_OFFSET &&
		sizeof(FiberPortBoot) == FIBER_PORT_CM33_MPU_BOOT_SIZE,
		"[fiber]: ARM_CM33_MPU boot seal offsets changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context_cursor) ==
		FIBER_PORT_CM33_MPU_CURSOR_OFFSET &&
		offsetof(FiberContext, mair0) == FIBER_PORT_CM33_MPU_MAIR0_OFFSET &&
		offsetof(FiberContext, mpu_regions) ==
		FIBER_PORT_CM33_MPU_REGIONS_OFFSET &&
		offsetof(FiberContext, protected_context) ==
		FIBER_PORT_CM33_MPU_PROTECTED_CONTEXT_OFFSET &&
		offsetof(FiberContext, runtime_flags) ==
		FIBER_PORT_CM33_MPU_RUNTIME_FLAGS_OFFSET &&
		offsetof(FiberContext, boot) == FIBER_PORT_CM33_MPU_BOOT_OFFSET &&
		sizeof(FiberContext) == FIBER_PORT_CM33_MPU_CONTEXT_SIZE &&
		alignof(FiberContext) == FIBER_PORT_CM33_MPU_CONTEXT_ALIGNMENT,
		"[fiber]: ARM_CM33_MPU FiberContext layout changed");

/* The selected-port dictionary owns the full trait and exact-cohort contract
 * even before a runtime source exists. */
#include "../../fiber_port_traits.h"
#include "../../fiber_port_context_cohort.h"
#include "../../fiber_port_geometry.h"

#endif /* FIBER_PORT_ARM_CM33_MPU_NON_SECURE_FIBER_PORTMACRO_H_ */
