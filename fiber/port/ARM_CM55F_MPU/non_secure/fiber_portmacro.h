/*
 * fiber_portmacro.h
 *
 * Exact Cortex-M55 scalar-FP MPU Non-secure dictionary, implementation slice 1.
 * This is the FreeRTOS ARM_CM55_NTZ FPU/MPU/no-MVE/no-TrustZone/no-PAC
 * protected profile with an explicit 8- or 16-region manifest. It freezes the
 * overlapping basic/extended protected image, construction and linker policy;
 * SVC/PendSV and the forward runtime ABI arrive in later slices.
 */
#ifndef FIBER_PORT_ARM_CM55F_MPU_NON_SECURE_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM55F_MPU_NON_SECURE_FIBER_PORTMACRO_H_

#include <stddef.h>
#include <stdint.h>

#ifdef FIBER_PORT_NAME
# error "[fiber]: ARM_CM55F_MPU port name must not be predefined"
#endif
#define FIBER_PORT_NAME "ARM_CM55F_MPU"

#include "../../fiber_port_select.h"
#include "../../fiber_settings.h"
#include "../../fiber_compiler.h"

#if !FIBER_PORT_BUILD_SELECTED
# error "[fiber]: ARM_CM55F_MPU is build-selected only"
#endif

#if !FIBER_PORT_ARMV81M_MAINLINE
# error "[fiber]: ARM_CM55F_MPU requires the ARMv8.1-M Mainline selected profile"
#endif

/* GNU Arm reports the same Armv8-M Mainline preprocessor result for several
 * Mainline targets. The selected profile and generated CMSIS M55 identity are
 * both required; the compiler FPU result below then binds scalar FP exactly. */
#if !defined(__ARM_ARCH_8M_MAIN__) && !defined(__ARM_ARCH_8_1M_MAIN__)
# error "[fiber]: ARM_CM55F_MPU requires an ARMv8-M Mainline compiler target"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 55)
# error "[fiber]: ARM_CM55F_MPU manifest requires CMSIS __CORTEX_M == 55"
#endif

#if !defined(__MPU_PRESENT) || (__MPU_PRESENT != 1)
# error "[fiber]: ARM_CM55F_MPU manifest requires __MPU_PRESENT == 1"
#endif

#if !defined(__VTOR_PRESENT) || (__VTOR_PRESENT != 1)
# error "[fiber]: ARM_CM55F_MPU manifest requires __VTOR_PRESENT == 1"
#endif

#if defined(__ARM_FEATURE_CMSE) && ((__ARM_FEATURE_CMSE + 0) >= 3)
# error "[fiber]: ARM_CM55F_MPU selected profile excludes Secure CMSE builds"
#endif

#if defined(FIBER_PORT_TOOLCHAIN_HAS_FP) || \
		defined(FIBER_PORT_SILICON_HAS_FPU) || \
		defined(FIBER_PORT_CMSIS_FPU_USED) || \
		defined(FIBER_PORT_HAS_FPU) || \
		defined(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT)
# error "[fiber]: ARM_CM55F_MPU FPU facts are selected-port-owned"
#endif

#if !defined(__FPU_PRESENT) || ((__FPU_PRESENT + 0) != 1)
# error "[fiber]: ARM_CM55F_MPU requires CMSIS __FPU_PRESENT == 1"
#endif

#if !defined(__FPU_USED) || ((__FPU_USED + 0) != 1)
# error "[fiber]: ARM_CM55F_MPU requires CMSIS __FPU_USED == 1"
#endif

#if !defined(__ARM_FP) || ((__ARM_FP + 0) == 0)
# error "[fiber]: ARM_CM55F_MPU requires compiler FP code generation"
#endif

#define FIBER_PORT_TOOLCHAIN_HAS_FP 1
#define FIBER_PORT_SILICON_HAS_FPU 1
#define FIBER_PORT_CMSIS_FPU_USED 1

#if defined(__ARM_FEATURE_MVE) && ((__ARM_FEATURE_MVE + 0) != 0)
# error "[fiber]: ARM_CM55F_MPU selected profile does not permit MVE"
#endif

#if defined(__ARM_FEATURE_PAC_DEFAULT) || defined(__ARM_FEATURE_PAUTH) || \
		defined(__ARM_FEATURE_PAUTH_DEFAULT)
# error "[fiber]: ARM_CM55F_MPU selected profile does not permit PAC"
#endif

#if defined(__ARM_FEATURE_BTI_DEFAULT) || defined(__ARM_FEATURE_BTI)
# error "[fiber]: ARM_CM55F_MPU selected profile does not permit BTI"
#endif

#if !defined(__NVIC_PRIO_BITS) || (__NVIC_PRIO_BITS < 1) || \
		(__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM55F_MPU requires 1..8 implemented NVIC priority bits"
#endif

#ifndef FIBER_PORT_CM55F_MPU_TOTAL_REGIONS
# error "[fiber]: ARM_CM55F_MPU requires FIBER_PORT_CM55F_MPU_TOTAL_REGIONS=8 or 16"
#endif

#if defined(FIBER_PORT_CM55_MPU_TOTAL_REGIONS) || \
		defined(FIBER_PORT_MPU_TOTAL_REGIONS)
# error "[fiber]: ARM_CM55F_MPU requires its own MPU-region manifest macro"
#endif

#if (FIBER_PORT_CM55F_MPU_TOTAL_REGIONS != 8) && \
		(FIBER_PORT_CM55F_MPU_TOTAL_REGIONS != 16)
# error "[fiber]: ARM_CM55F_MPU supports exactly 8 or 16 MPU regions"
#endif

#ifdef FIBER_PORT_RUNTIME_SELECTABLE
# error "[fiber]: ARM_CM55F_MPU runtime-selectable state must not be predefined"
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
# error "[fiber]: ARM_CM55F_MPU owns its complete SVC namespace"
#endif
#define FIBER_SVC_START_NUMBER 70u
#define fiber_portSVC_START FIBER_SVC_START_NUMBER
#define fiber_portSVC_YIELD 71u
#define fiber_portSVC_RETURN 72u

/* ARMv8.1-M Mainline system-control and MPU register dictionary. Keep these
 * selected-port facts explicit instead of relying on device-header aliases;
 * the exact addresses are part of the protected first-start assembly ABI. */
#define fiber_portNVIC_INT_CTRL_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED04u))
#define fiber_portNVIC_PENDSVSET_BIT (1u << 28u)
#define fiber_portNVIC_PENDSVCLEAR_BIT (1u << 27u)
#define fiber_portSCB_VTOR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED08u))
#define fiber_portSCB_CCR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED14u))
#define fiber_portSCB_SHCSR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED24u))
#define fiber_portSCB_CCR_STKALIGN_BIT (1u << 9u)
#define fiber_portSCB_MEMFAULTENA_BIT (1u << 16u)
#define fiber_portCPACR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED88u))
#define fiber_portFPCCR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000EF34u))
#define fiber_portCPACR_CP10_CP11_FULL (0x0Fu << 20u)
#define fiber_portFPCCR_LSPACT_BIT (1u << 0u)
#define fiber_portFPCCR_LSPEN_BIT (1u << 30u)
#define fiber_portFPCCR_ASPEN_BIT (1u << 31u)

#define fiber_portMPU_TYPE_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED90u))
#define fiber_portMPU_CTRL_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED94u))
#define fiber_portMPU_RNR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED98u))
#define fiber_portMPU_RBAR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED9Cu))
#define fiber_portMPU_RLAR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000EDA0u))
#define fiber_portMPU_MAIR0_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000EDC0u))
#define fiber_portMPU_TYPE_DREGION_MASK 0x0000FF00u

#define fiber_portVECTOR_INDEX_SVC 11u
#define fiber_portVECTOR_INDEX_PENDSV 14u
#define fiber_portVECTOR_ALIGNMENT 128u
#define fiber_portXPSR_IPSR_MASK 0x000001FFu
#define fiber_portXPSR_STACK_ALIGN_BIT (1u << 9u)
#define fiber_portXPSR_THUMB_BIT (1u << 24u)

#define fiber_portBASEPRI_SYM "BASEPRI"
#define fiber_portASM_WRITE_BASEPRI_R0 \
	"msr   " fiber_portBASEPRI_SYM ", r0           \n"
#define fiber_portASM_WRITE_BASEPRI_R0_SYNC \
	fiber_portASM_WRITE_BASEPRI_R0 \
	"dsb                                  \n" \
	"isb                                  \n"

/* Exact ARMv8.1-M Mainline MPU layout used by the pinned GCC ARM_CM55_NTZ port.
 *
 * Hardware region numbers and FiberContext::mpu_regions[] indexes are
 * intentionally named separately.  FreeRTOS programs the first context pair
 * through RNR 4, but stores it at xRegionsSettings[0].  Treating both as
 * "stack region" would index four words past the 8-region context image. */
#define fiber_portMPU_TOTAL_REGIONS FIBER_PORT_CM55F_MPU_TOTAL_REGIONS
#define fiber_portMPU_PRIVILEGED_FLASH_REGION_NUMBER 0u
#define fiber_portMPU_UNPRIVILEGED_FLASH_REGION_NUMBER 1u
#define fiber_portMPU_UNPRIVILEGED_SYSCALLS_REGION_NUMBER 2u
#define fiber_portMPU_PRIVILEGED_DATA_REGION_NUMBER 3u
#define fiber_portMPU_STACK_REGION_NUMBER 4u
/*
 * ARMv8-M has no MPU access encoding for privileged-RW plus
 * unprivileged-RO.  The current-context aperture therefore uses an exact
 * read-only/XN overlay while a protected switch updates the common slot only
 * while MPU_CTRL is disabled.  It is stored in every per-context image so it
 * overrides global privileged SRAM by region-number priority without consuming
 * a fifth immutable global region.
 */
#define fiber_portMPU_CURRENT_CONTEXT_REGION_NUMBER 5u
#define fiber_portMPU_FIRST_CONFIGURABLE_REGION_NUMBER 6u
#define fiber_portMPU_LAST_CONFIGURABLE_REGION_NUMBER \
	(fiber_portMPU_TOTAL_REGIONS - 1u)
#define fiber_portMPU_CONFIGURABLE_REGION_COUNT \
	(fiber_portMPU_TOTAL_REGIONS - \
	 fiber_portMPU_FIRST_CONFIGURABLE_REGION_NUMBER)
#define fiber_portMPU_CONTEXT_REGION_COUNT \
	FIBER_PORT_CM55F_MPU_CONTEXT_REGION_COUNT
#define fiber_portMPU_CONTEXT_STACK_INDEX 0u
#define fiber_portMPU_CONTEXT_CURRENT_CONTEXT_INDEX 1u
#define fiber_portMPU_CONTEXT_FIRST_CONFIGURABLE_INDEX 2u
#define fiber_portMPU_CONTEXT_LAST_CONFIGURABLE_INDEX \
	(fiber_portMPU_CONTEXT_REGION_COUNT - 1u)
#define fiber_portMPU_GLOBAL_REGION_COUNT 4u
#define fiber_portMPU_EXPECTED_TYPE (fiber_portMPU_TOTAL_REGIONS << 8u)
#define fiber_portMPU_CTRL_ENABLE 0x00000001u
#define fiber_portMPU_CTRL_PRIVDEFENA 0x00000004u
#define fiber_portMPU_CTRL_REQUIRED \
	(fiber_portMPU_CTRL_ENABLE | fiber_portMPU_CTRL_PRIVDEFENA)
#define fiber_portMPU_LAST_CONTEXT_BLOCK_REGION \
	(fiber_portMPU_TOTAL_REGIONS - 4u)

#define fiber_portMPU_RBAR_ADDRESS_MASK UINT32_C(0xFFFFFFE0)
#define fiber_portMPU_RLAR_ADDRESS_MASK UINT32_C(0xFFFFFFE0)
#define fiber_portMPU_RBAR_ACCESS_MASK (3u << 1u)
#define fiber_portMPU_RBAR_SHAREABILITY_MASK (3u << 3u)
#define fiber_portMPU_REGION_NON_SHAREABLE (0u << 3u)
#define fiber_portMPU_REGION_INNER_SHAREABLE (1u << 3u)
#define fiber_portMPU_REGION_OUTER_SHAREABLE (2u << 3u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_WRITE (0u << 1u)
#define fiber_portMPU_REGION_READ_WRITE (1u << 1u)
#define fiber_portMPU_REGION_PRIVILEGED_READ_ONLY (2u << 1u)
#define fiber_portMPU_REGION_READ_ONLY (3u << 1u)
#define fiber_portMPU_REGION_EXECUTE_NEVER 1u
#define fiber_portMPU_RLAR_ATTR_INDEX_MASK (7u << 1u)
#define fiber_portMPU_RLAR_ATTR_INDEX0 (0u << 1u)
#define fiber_portMPU_RLAR_ATTR_INDEX1 (1u << 1u)
#define fiber_portMPU_RLAR_REGION_ENABLE 1u
/* ARMv8.1-M adds RLAR.PXN. It is not used by the fixed base image, but the
 * selected port must retain the capability for a later configurable-region
 * ABI instead of silently behaving like the ARMv8-M.0 CM33 profile. */
#define fiber_portARMV8M_MINOR_VERSION 1u
#define fiber_portMPU_RLAR_PRIVILEGED_EXECUTE_NEVER (1u << 4u)
#define fiber_portMPU_MAIR_NORMAL_MEMORY_BUFFERABLE_CACHEABLE 0xFFu
#define fiber_portMPU_MAIR_DEVICE_MEMORY_NGNRE 0x04u
#define fiber_portMPU_MAIR0_DEFAULT \
	(fiber_portMPU_MAIR_NORMAL_MEMORY_BUFFERABLE_CACHEABLE | \
	 (fiber_portMPU_MAIR_DEVICE_MEMORY_NGNRE << 8u))
#define fiber_portMPU_CURRENT_CONTEXT_APERTURE_BYTES 32u

/* Exact linker sections consumed by the protected MPU construction and later
 * SVC/PendSV slices.  The application linker script owns their addresses. */
#define fiber_portPRIVILEGED_FUNCTION \
	__attribute__((section(".fiber_port_privileged_functions")))
#define fiber_portUNPRIVILEGED_FUNCTION \
	__attribute__((section(".fiber_port_unprivileged_functions")))
#define fiber_portSYSCALL_FUNCTION \
	__attribute__((section(".fiber_port_syscalls")))
#define fiber_portPRIVILEGED_DATA \
	__attribute__((section(".fiber_port_privileged_data")))

#ifdef __cplusplus
extern "C" {
#endif

/* Preserve r9 because an integration may use it as the platform/static-base
 * register even though the pinned FreeRTOS debug seed uses a marker value. */
fiber_portFORCE_INLINE uint32_t fiber_port_read_r9(void)
{
	uint32_t value;
	fiber_portASM volatile("mov %0, r9" : "=r"(value));
	return value;
}

fiber_portFORCE_INLINE uint32_t fiber_port_basepri_read(void)
{
	uint32_t value;
	fiber_portASM volatile("mrs %0, " fiber_portBASEPRI_SYM
			: "=r"(value));
	return value;
}

fiber_portFORCE_INLINE void fiber_port_basepri_write(uint32_t value)
{
	fiber_portASM volatile("msr " fiber_portBASEPRI_SYM ", %0"
			:: "r"(value) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}

fiber_portFORCE_INLINE uintptr_t fiber_port_vectors_base_addr(void)
{
	return (uintptr_t)fiber_portSCB_VTOR_REG &
		~((uintptr_t)fiber_portVECTOR_ALIGNMENT - 1u);
}

fiber_portFORCE_INLINE const uint32_t *fiber_port_vectors_base_ptr(void)
{
	return (const uint32_t *)fiber_port_vectors_base_addr();
}

fiber_portFORCE_INLINE uint32_t fiber_port_read_vector_slot(uint32_t index)
{
	return *(const volatile uint32_t *)(fiber_port_vectors_base_addr() +
			((uintptr_t)index * sizeof(uint32_t)));
}

fiber_portFORCE_INLINE uint32_t fiber_port_read_initial_msp(void)
{
	return fiber_port_read_vector_slot(0u);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

/* Frame and selected-port trait facts. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portSTART_ADDRESS_MASK 0xFFFFFFFEu
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFBCu
#define fiber_portEXTENDED_EXC_RETURN 0xFFFFFFACu
#define fiber_portSVC_ORIGIN_EXC_RETURN 0xFFFFFFB8u
#define fiber_portINITIAL_CONTROL_PRIVILEGED 0x00000002u
#define fiber_portINITIAL_CONTROL_UNPRIVILEGED 0x00000003u
#define fiber_portPROTECTED_CONTEXT_WORDS 54u
#define fiber_portPROTECTED_BASIC_RESTORE_WORDS 20u
#define fiber_portPROTECTED_EXTENDED_RESTORE_WORDS 53u
#define fiber_portPROTECTED_EXTENDED_ADDITIONAL_WORDS \
	(fiber_portPROTECTED_EXTENDED_RESTORE_WORDS - \
	 fiber_portPROTECTED_BASIC_RESTORE_WORDS)
#define fiber_portPROTECTED_HIGH_FP_WORDS 16u
#define fiber_portPROTECTED_LOW_FP_WORDS 17u
#define fiber_portPROTECTED_HARDWARE_WORDS 8u
#define fiber_portPROTECTED_SPECIAL_WORDS 4u
#define fiber_portSTACK_FRAME_HAS_PADDING_FLAG (1u << 0u)
#define fiber_portTASK_IS_PRIVILEGED_FLAG (1u << 1u)

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1
#define FIBER_PORT_HAS_VTOR 1
#define FIBER_PORT_HAS_PSPLIM 1
#define FIBER_PORT_HAS_FPU 1
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 1
#define FIBER_PORT_STACK_ALIGNMENT fiber_portBYTE_ALIGNMENT
#define FIBER_PORT_BOOT_CLEARS_FPCA 1
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
# error "[fiber]: ARM_CM55F_MPU scheduler BASEPRI threshold must be non-zero"
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI > 255u
# error "[fiber]: ARM_CM55F_MPU scheduler BASEPRI threshold must fit in 8 bits"
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI &
		((1u << (8u - __NVIC_PRIO_BITS)) - 1u)) == 0u,
		"[fiber]: ARM_CM55F_MPU BASEPRI uses unimplemented priority bits");
#if __NVIC_PRIO_BITS == 8
FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI & 1u) == 0u,
		"[fiber]: ARM_CM55F_MPU BASEPRI bit 0 is subpriority");
#endif

#if FIBER_PORT_CM55F_MPU_TOTAL_REGIONS == 8
# define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010008u
# define FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_OFFSET 40u
# define FIBER_PORT_CM55F_MPU_RUNTIME_FLAGS_OFFSET 256u
# define FIBER_PORT_CM55F_MPU_BOOT_OFFSET 260u
# define FIBER_PORT_CM55F_MPU_CONTEXT_SIZE 352u
#else
# define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010010u
# define FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_OFFSET 104u
# define FIBER_PORT_CM55F_MPU_RUNTIME_FLAGS_OFFSET 320u
# define FIBER_PORT_CM55F_MPU_BOOT_OFFSET 324u
# define FIBER_PORT_CM55F_MPU_CONTEXT_SIZE 416u
#endif

/* ASCII "C55P": scalar-FP protected M55. This no-TrustZone cohort has a
 * one-past context cursor target, not a SecureContext slot. */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x43353550u
#define FIBER_PORT_CONTEXT_FEATURE_EXTENDED_FP 0x00000001u
#define FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT 0x00000002u
#define FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT 0x00000004u
#define FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE 0x00000080u
#define FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE 0x00000400u
#define FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME 0x00000800u
#define FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED 0x00001000u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	(FIBER_PORT_CONTEXT_FEATURE_EXTENDED_FP | \
	 FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE | \
	 FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE | \
	 FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME | \
	 FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED)

/* The protected image owns all active saved words. Its basic and extended
 * views overlap exactly as FreeRTOS xMPU_SETTINGS.ulContext does. The generic
 * initial geometry uses the 20-word basic protected restore image. For the
 * extended form, HIGH_FP_SOFTWARE_BYTES denotes every extra protected FP word
 * beyond that basic image: s16-s31 plus the copied s0-s15/FPSCR words. The
 * separately named PSP geometry governs physical user-stack admission. */
#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES (18u * 4u)
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES)
/* r4-r11, copied basic hardware frame, PSP, PSPLIM, CONTROL, EXC_RETURN. */
#define FIBER_PORT_SOFTWARE_FRAME_WORDS fiber_portPROTECTED_BASIC_RESTORE_WORDS
#define FIBER_PORT_SOFTWARE_FRAME_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX \
	(fiber_portPROTECTED_BASIC_RESTORE_WORDS - 1u)
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES \
	(fiber_portPROTECTED_EXTENDED_ADDITIONAL_WORDS * 4u)
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_BASE_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_HIGH_FP_SOFTWARE_BYTES + \
	 FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 0u

/* Physical user-PSP geometry. The protected image is copied to and from
 * privileged storage, so raw stack admission must not count its 54 words. */
#define FIBER_PORT_CM55F_MPU_PSP_INITIAL_FRAME_BYTES \
	FIBER_PORT_EXC_BASE_BYTES
#define FIBER_PORT_CM55F_MPU_PSP_MAX_FRAME_BYTES \
	(FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_CM55F_MPU_STACK_REQUIRED_BYTES \
	((FIBER_PORT_CM55F_MPU_PSP_MAX_FRAME_BYTES + \
	  FIBER_PORT_STACK_ALIGNMENT - 1u) & \
	 ~((uint32_t)FIBER_PORT_STACK_ALIGNMENT - 1u))

/* Frozen GCC 32-bit storage offsets consumed by later protected assembly. */
#define FIBER_PORT_CM55F_MPU_REGION_RBAR_OFFSET 0u
#define FIBER_PORT_CM55F_MPU_REGION_RLAR_OFFSET 4u
#define FIBER_PORT_CM55F_MPU_REGION_SIZE 8u
#define FIBER_PORT_CM55F_MPU_BASIC_R4_OFFSET 0u
#define FIBER_PORT_CM55F_MPU_BASIC_R9_OFFSET 20u
#define FIBER_PORT_CM55F_MPU_BASIC_R0_OFFSET 32u
#define FIBER_PORT_CM55F_MPU_BASIC_LR_OFFSET 52u
#define FIBER_PORT_CM55F_MPU_BASIC_PC_OFFSET 56u
#define FIBER_PORT_CM55F_MPU_BASIC_XPSR_OFFSET 60u
#define FIBER_PORT_CM55F_MPU_BASIC_PSP_OFFSET 64u
#define FIBER_PORT_CM55F_MPU_BASIC_PSPLIM_OFFSET 68u
#define FIBER_PORT_CM55F_MPU_BASIC_CONTROL_OFFSET 72u
#define FIBER_PORT_CM55F_MPU_BASIC_EXC_RETURN_OFFSET 76u
#define FIBER_PORT_CM55F_MPU_BASIC_CURSOR_LIMIT_OFFSET 80u
#define FIBER_PORT_CM55F_MPU_BASIC_RESERVED_OFFSET 84u
#define FIBER_PORT_CM55F_MPU_EXTENDED_HIGH_FP_OFFSET 0u
#define FIBER_PORT_CM55F_MPU_EXTENDED_LOW_FP_OFFSET 64u
#define FIBER_PORT_CM55F_MPU_EXTENDED_R4_OFFSET 132u
#define FIBER_PORT_CM55F_MPU_EXTENDED_R0_OFFSET 164u
#define FIBER_PORT_CM55F_MPU_EXTENDED_PSP_OFFSET 196u
#define FIBER_PORT_CM55F_MPU_EXTENDED_PSPLIM_OFFSET 200u
#define FIBER_PORT_CM55F_MPU_EXTENDED_CONTROL_OFFSET 204u
#define FIBER_PORT_CM55F_MPU_EXTENDED_EXC_RETURN_OFFSET 208u
#define FIBER_PORT_CM55F_MPU_EXTENDED_CURSOR_LIMIT_OFFSET 212u
#define FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_SIZE 216u
#define FIBER_PORT_CM55F_MPU_CURSOR_OFFSET 0u
#define FIBER_PORT_CM55F_MPU_MAIR0_OFFSET 4u
#define FIBER_PORT_CM55F_MPU_REGIONS_OFFSET 8u
#define FIBER_PORT_CM55F_MPU_CONTEXT_ALIGNMENT 8u

#define FIBER_PORT_CM55F_MPU_BOOT_BEGIN_OFFSET 0u
#define FIBER_PORT_CM55F_MPU_BOOT_END_OFFSET 4u
#define FIBER_PORT_CM55F_MPU_BOOT_STACK_BASE_OFFSET 8u
#define FIBER_PORT_CM55F_MPU_BOOT_STACK_TOP_OFFSET 12u
#define FIBER_PORT_CM55F_MPU_BOOT_AVAIL_OFFSET 16u
#define FIBER_PORT_CM55F_MPU_BOOT_ENTRY_OFFSET 20u
#define FIBER_PORT_CM55F_MPU_BOOT_ARG_OFFSET 24u
#define FIBER_PORT_CM55F_MPU_BOOT_PORT_ID_OFFSET 28u
#define FIBER_PORT_CM55F_MPU_BOOT_LAYOUT_VERSION_OFFSET 32u
#define FIBER_PORT_CM55F_MPU_BOOT_CONTEXT_SIZE_OFFSET 36u
#define FIBER_PORT_CM55F_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET 40u
#define FIBER_PORT_CM55F_MPU_BOOT_FEATURE_MASK_OFFSET 44u
#define FIBER_PORT_CM55F_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET 48u
#define FIBER_PORT_CM55F_MPU_BOOT_INITIAL_CONTROL_OFFSET 52u
#define FIBER_PORT_CM55F_MPU_BOOT_TOTAL_REGIONS_OFFSET 56u
#define FIBER_PORT_CM55F_MPU_BOOT_CONTEXT_REGIONS_OFFSET 60u
#define FIBER_PORT_CM55F_MPU_BOOT_PROTECTED_WORDS_OFFSET 64u
#define FIBER_PORT_CM55F_MPU_BOOT_MAGIC_OFFSET 68u
#define FIBER_PORT_CM55F_MPU_BOOT_VERSION_OFFSET 72u
#define FIBER_PORT_CM55F_MPU_BOOT_SEALED_OFFSET 74u
#define FIBER_PORT_CM55F_MPU_BOOT_GUARD_LO_OFFSET 76u
#define FIBER_PORT_CM55F_MPU_BOOT_GUARD_HI_OFFSET 80u
#define FIBER_PORT_CM55F_MPU_BOOT_HASH_OFFSET 84u
#define FIBER_PORT_CM55F_MPU_BOOT_SIZE 88u

FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: ARM_CM55F_MPU requires 32-bit pointers");
FIBER_STATIC_ASSERT(sizeof(size_t) == 4u,
		"[fiber]: ARM_CM55F_MPU requires 32-bit size_t");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM55F_MPU construction cohort must not expose runtime operations");
FIBER_STATIC_ASSERT(fiber_portSVC_START == 70u,
		"[fiber]: ARM_CM55F_MPU first-start SVC changed");
FIBER_STATIC_ASSERT(fiber_portSVC_YIELD == 71u,
		"[fiber]: ARM_CM55F_MPU yield SVC changed");
FIBER_STATIC_ASSERT(fiber_portSVC_RETURN == 72u,
		"[fiber]: ARM_CM55F_MPU task-return SVC changed");
FIBER_STATIC_ASSERT((fiber_portSVC_START != fiber_portSVC_YIELD) &&
		(fiber_portSVC_START != fiber_portSVC_RETURN) &&
		(fiber_portSVC_YIELD != fiber_portSVC_RETURN),
		"[fiber]: ARM_CM55F_MPU SVC namespace collided");
FIBER_STATIC_ASSERT(fiber_portVECTOR_INDEX_SVC == 11u &&
		fiber_portVECTOR_INDEX_PENDSV == 14u &&
		fiber_portVECTOR_ALIGNMENT == 128u,
		"[fiber]: ARM_CM55F_MPU vector facts changed");
FIBER_STATIC_ASSERT((fiber_portMPU_LAST_CONTEXT_BLOCK_REGION == 4u) ||
		(fiber_portMPU_LAST_CONTEXT_BLOCK_REGION == 12u),
		"[fiber]: ARM_CM55F_MPU context MPU block geometry changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_REGION_COUNT ==
		FIBER_PORT_CM55F_MPU_CONTEXT_REGION_COUNT,
		"[fiber]: ARM_CM55F_MPU per-context region count changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_REGION_COUNT ==
		(fiber_portMPU_TOTAL_REGIONS - 4u),
		"[fiber]: ARM_CM55F_MPU global/per-context region geometry changed");
FIBER_STATIC_ASSERT(fiber_portMPU_PRIVILEGED_FLASH_REGION_NUMBER == 0u &&
		fiber_portMPU_UNPRIVILEGED_FLASH_REGION_NUMBER == 1u &&
		fiber_portMPU_UNPRIVILEGED_SYSCALLS_REGION_NUMBER == 2u &&
		fiber_portMPU_PRIVILEGED_DATA_REGION_NUMBER == 3u &&
		fiber_portMPU_STACK_REGION_NUMBER == 4u &&
		fiber_portMPU_CURRENT_CONTEXT_REGION_NUMBER == 5u &&
		fiber_portMPU_FIRST_CONFIGURABLE_REGION_NUMBER == 6u,
		"[fiber]: ARM_CM55F_MPU hardware MPU region numbering changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_STACK_INDEX == 0u &&
		fiber_portMPU_CONTEXT_CURRENT_CONTEXT_INDEX == 1u &&
		fiber_portMPU_CONTEXT_FIRST_CONFIGURABLE_INDEX == 2u &&
		fiber_portMPU_CONTEXT_LAST_CONFIGURABLE_INDEX ==
			(fiber_portMPU_CONTEXT_REGION_COUNT - 1u),
		"[fiber]: ARM_CM55F_MPU context-image indexes changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_REGION_COUNT ==
		(2u + fiber_portMPU_CONFIGURABLE_REGION_COUNT) &&
		fiber_portMPU_LAST_CONFIGURABLE_REGION_NUMBER ==
			(fiber_portMPU_TOTAL_REGIONS - 1u),
		"[fiber]: ARM_CM55F_MPU context/hardware region mapping changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CURRENT_CONTEXT_APERTURE_BYTES == 32u,
		"[fiber]: ARM_CM55F_MPU current-slot aperture must be one MPU granule");
FIBER_STATIC_ASSERT(fiber_portARMV8M_MINOR_VERSION == 1u &&
		fiber_portMPU_RLAR_PRIVILEGED_EXECUTE_NEVER == (1u << 4u),
		"[fiber]: ARM_CM55F_MPU must retain the ARMv8.1-M MPU PXN capability");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_CONTEXT_WORDS == 54u &&
		fiber_portPROTECTED_BASIC_RESTORE_WORDS == 20u &&
		fiber_portPROTECTED_EXTENDED_RESTORE_WORDS == 53u &&
		fiber_portPROTECTED_HIGH_FP_WORDS == 16u &&
		fiber_portPROTECTED_LOW_FP_WORDS == 17u &&
		fiber_portPROTECTED_HARDWARE_WORDS == 8u &&
		fiber_portPROTECTED_SPECIAL_WORDS == 4u,
		"[fiber]: ARM_CM55F_MPU protected context word geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS == 20u &&
		FIBER_PORT_EXC_RETURN_WORD_INDEX == 19u &&
		FIBER_PORT_HIGH_FP_SOFTWARE_BYTES == 132u &&
		FIBER_PORT_INITIAL_CONTEXT_BYTES == 112u &&
		FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 320u,
		"[fiber]: ARM_CM55F_MPU logical restore geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_CONTROL_SLOT == 1,
		"[fiber]: ARM_CM55F_MPU must preserve CONTROL per context");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_PSPLIM_SLOT == 1,
		"[fiber]: ARM_CM55F_MPU must preserve PSPLIM per context");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 0,
		"[fiber]: ARM_CM55F_MPU selected profile must not expose SecureContext");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_PAC_KEY_SLOT == 0,
		"[fiber]: ARM_CM55F_MPU selected profile must not expose PAC state");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_FPU == 1 &&
		FIBER_PORT_HAS_EXTENDED_FP_CONTEXT == 1 &&
		FIBER_PORT_BOOT_CLEARS_FPCA == 1 && FIBER_PORT_HAS_MVE == 0 &&
		FIBER_PORT_HAS_PAC == 0 &&
		FIBER_PORT_HAS_BTI == 0,
		"[fiber]: ARM_CM55F_MPU selected feature cohort changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C87u,
		"[fiber]: ARM_CM55F_MPU context feature identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM55F_MPU_PSP_INITIAL_FRAME_BYTES == 32u &&
		FIBER_PORT_CM55F_MPU_PSP_MAX_FRAME_BYTES == 108u &&
		FIBER_PORT_CM55F_MPU_STACK_REQUIRED_BYTES == 112u,
		"[fiber]: ARM_CM55F_MPU physical PSP geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_OFFSET ==
		(FIBER_PORT_CM55F_MPU_REGIONS_OFFSET +
		 (FIBER_PORT_CM55F_MPU_CONTEXT_REGION_COUNT *
		  FIBER_PORT_CM55F_MPU_REGION_SIZE)),
		"[fiber]: ARM_CM55F_MPU protected context offset changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM55F_MPU_BOOT_OFFSET ==
		(FIBER_PORT_CM55F_MPU_RUNTIME_FLAGS_OFFSET + 4u),
		"[fiber]: ARM_CM55F_MPU boot offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortMpuRegionRegisters, rbar) ==
		FIBER_PORT_CM55F_MPU_REGION_RBAR_OFFSET &&
		offsetof(FiberPortMpuRegionRegisters, rlar) ==
		FIBER_PORT_CM55F_MPU_REGION_RLAR_OFFSET &&
		sizeof(FiberPortMpuRegionRegisters) == FIBER_PORT_CM55F_MPU_REGION_SIZE,
		"[fiber]: ARM_CM55F_MPU MPU region layout changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedBasicContext) ==
		FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_SIZE &&
		sizeof(FiberPortProtectedExtendedContext) ==
		FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_SIZE &&
		sizeof(FiberPortProtectedContext) ==
		FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_SIZE,
		"[fiber]: ARM_CM55F_MPU overlapping protected image size changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedBasicContext, r4) ==
		FIBER_PORT_CM55F_MPU_BASIC_R4_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, r9) ==
		FIBER_PORT_CM55F_MPU_BASIC_R9_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, r0) ==
		FIBER_PORT_CM55F_MPU_BASIC_R0_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, lr) ==
		FIBER_PORT_CM55F_MPU_BASIC_LR_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, pc) ==
		FIBER_PORT_CM55F_MPU_BASIC_PC_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, xpsr) ==
		FIBER_PORT_CM55F_MPU_BASIC_XPSR_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, psp) ==
		FIBER_PORT_CM55F_MPU_BASIC_PSP_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, psplim) ==
		FIBER_PORT_CM55F_MPU_BASIC_PSPLIM_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, control) ==
		FIBER_PORT_CM55F_MPU_BASIC_CONTROL_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, exc_return) ==
		FIBER_PORT_CM55F_MPU_BASIC_EXC_RETURN_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, cursor_limit) ==
		FIBER_PORT_CM55F_MPU_BASIC_CURSOR_LIMIT_OFFSET &&
		offsetof(FiberPortProtectedBasicContext, reserved) ==
		FIBER_PORT_CM55F_MPU_BASIC_RESERVED_OFFSET,
		"[fiber]: ARM_CM55F_MPU basic protected offsets changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedExtendedContext,
		high_fp_s16_s31) == FIBER_PORT_CM55F_MPU_EXTENDED_HIGH_FP_OFFSET &&
		offsetof(FiberPortProtectedExtendedContext,
		low_fp_s0_s15_fpscr) == FIBER_PORT_CM55F_MPU_EXTENDED_LOW_FP_OFFSET &&
		offsetof(FiberPortProtectedExtendedContext, r4) ==
		FIBER_PORT_CM55F_MPU_EXTENDED_R4_OFFSET &&
		offsetof(FiberPortProtectedExtendedContext, r0) ==
		FIBER_PORT_CM55F_MPU_EXTENDED_R0_OFFSET &&
		offsetof(FiberPortProtectedExtendedContext, psp) ==
		FIBER_PORT_CM55F_MPU_EXTENDED_PSP_OFFSET &&
		offsetof(FiberPortProtectedExtendedContext, psplim) ==
		FIBER_PORT_CM55F_MPU_EXTENDED_PSPLIM_OFFSET &&
		offsetof(FiberPortProtectedExtendedContext, control) ==
		FIBER_PORT_CM55F_MPU_EXTENDED_CONTROL_OFFSET &&
		offsetof(FiberPortProtectedExtendedContext, exc_return) ==
		FIBER_PORT_CM55F_MPU_EXTENDED_EXC_RETURN_OFFSET &&
		offsetof(FiberPortProtectedExtendedContext, cursor_limit) ==
		FIBER_PORT_CM55F_MPU_EXTENDED_CURSOR_LIMIT_OFFSET,
		"[fiber]: ARM_CM55F_MPU extended protected offsets changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM55F_MPU_BASIC_RESERVED_OFFSET ==
		(FIBER_PORT_CM55F_MPU_BASIC_CURSOR_LIMIT_OFFSET + 4u) &&
		(FIBER_PORT_CM55F_MPU_BASIC_RESERVED_OFFSET + (33u * 4u)) ==
			FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_SIZE,
		"[fiber]: ARM_CM55F_MPU basic protected capacity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM55F_MPU_EXTENDED_CURSOR_LIMIT_OFFSET ==
		(FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_SIZE - 4u),
		"[fiber]: ARM_CM55F_MPU extended cursor limit must remain final");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, begin) ==
		FIBER_PORT_CM55F_MPU_BOOT_BEGIN_OFFSET &&
		offsetof(FiberPortBoot, end) == FIBER_PORT_CM55F_MPU_BOOT_END_OFFSET &&
		offsetof(FiberPortBoot, stack_base) ==
		FIBER_PORT_CM55F_MPU_BOOT_STACK_BASE_OFFSET &&
		offsetof(FiberPortBoot, stack_top) ==
		FIBER_PORT_CM55F_MPU_BOOT_STACK_TOP_OFFSET &&
		offsetof(FiberPortBoot, avail) ==
		FIBER_PORT_CM55F_MPU_BOOT_AVAIL_OFFSET &&
		offsetof(FiberPortBoot, entry) ==
		FIBER_PORT_CM55F_MPU_BOOT_ENTRY_OFFSET &&
		offsetof(FiberPortBoot, arg) == FIBER_PORT_CM55F_MPU_BOOT_ARG_OFFSET,
		"[fiber]: ARM_CM55F_MPU boot base offsets changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_port_id) ==
		FIBER_PORT_CM55F_MPU_BOOT_PORT_ID_OFFSET &&
		offsetof(FiberPortBoot, abi_layout_version) ==
		FIBER_PORT_CM55F_MPU_BOOT_LAYOUT_VERSION_OFFSET &&
		offsetof(FiberPortBoot, abi_context_size) ==
		FIBER_PORT_CM55F_MPU_BOOT_CONTEXT_SIZE_OFFSET &&
		offsetof(FiberPortBoot, abi_context_alignment) ==
		FIBER_PORT_CM55F_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET &&
		offsetof(FiberPortBoot, abi_feature_mask) ==
		FIBER_PORT_CM55F_MPU_BOOT_FEATURE_MASK_OFFSET &&
		offsetof(FiberPortBoot, abi_initial_exc_return) ==
		FIBER_PORT_CM55F_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET &&
		offsetof(FiberPortBoot, abi_initial_control) ==
		FIBER_PORT_CM55F_MPU_BOOT_INITIAL_CONTROL_OFFSET &&
		offsetof(FiberPortBoot, abi_mpu_total_regions) ==
		FIBER_PORT_CM55F_MPU_BOOT_TOTAL_REGIONS_OFFSET &&
		offsetof(FiberPortBoot, abi_mpu_context_regions) ==
		FIBER_PORT_CM55F_MPU_BOOT_CONTEXT_REGIONS_OFFSET &&
		offsetof(FiberPortBoot, abi_protected_context_words) ==
		FIBER_PORT_CM55F_MPU_BOOT_PROTECTED_WORDS_OFFSET,
		"[fiber]: ARM_CM55F_MPU boot ABI offsets changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, magic) ==
		FIBER_PORT_CM55F_MPU_BOOT_MAGIC_OFFSET &&
		offsetof(FiberPortBoot, version) ==
		FIBER_PORT_CM55F_MPU_BOOT_VERSION_OFFSET &&
		offsetof(FiberPortBoot, sealed) ==
		FIBER_PORT_CM55F_MPU_BOOT_SEALED_OFFSET &&
		offsetof(FiberPortBoot, guard_lo) ==
		FIBER_PORT_CM55F_MPU_BOOT_GUARD_LO_OFFSET &&
		offsetof(FiberPortBoot, guard_hi) ==
		FIBER_PORT_CM55F_MPU_BOOT_GUARD_HI_OFFSET &&
		offsetof(FiberPortBoot, hash) == FIBER_PORT_CM55F_MPU_BOOT_HASH_OFFSET &&
		sizeof(FiberPortBoot) == FIBER_PORT_CM55F_MPU_BOOT_SIZE,
		"[fiber]: ARM_CM55F_MPU boot seal offsets changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context_cursor) ==
		FIBER_PORT_CM55F_MPU_CURSOR_OFFSET &&
		offsetof(FiberContext, mair0) == FIBER_PORT_CM55F_MPU_MAIR0_OFFSET &&
		offsetof(FiberContext, mpu_regions) ==
		FIBER_PORT_CM55F_MPU_REGIONS_OFFSET &&
		offsetof(FiberContext, protected_context) ==
		FIBER_PORT_CM55F_MPU_PROTECTED_CONTEXT_OFFSET &&
		offsetof(FiberContext, runtime_flags) ==
		FIBER_PORT_CM55F_MPU_RUNTIME_FLAGS_OFFSET &&
		offsetof(FiberContext, boot) == FIBER_PORT_CM55F_MPU_BOOT_OFFSET &&
		sizeof(FiberContext) == FIBER_PORT_CM55F_MPU_CONTEXT_SIZE &&
		alignof(FiberContext) == FIBER_PORT_CM55F_MPU_CONTEXT_ALIGNMENT,
		"[fiber]: ARM_CM55F_MPU FiberContext layout changed");

/* The selected-port dictionary owns the full trait and exact-cohort contract
 * even before a runtime source exists. */
#include "../../fiber_port_traits.h"
#include "../../fiber_port_context_cohort.h"
#include "../../fiber_port_geometry.h"

#endif /* FIBER_PORT_ARM_CM55F_MPU_NON_SECURE_FIBER_PORTMACRO_H_ */
