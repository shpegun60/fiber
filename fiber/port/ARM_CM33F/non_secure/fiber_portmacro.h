/*
 * fiber_portmacro.h
 *
 * Exact Cortex-M33 TrustZone Non-secure selected-port dictionary.
 * Staged scalar-SP TrustZone construction and attachment; no runtime provider.
 */
#ifndef FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORTMACRO_H_

#include <stddef.h>
#include <stdint.h>

#ifdef FIBER_PORT_NAME
# error "[fiber]: ARM_CM33F port name must not be predefined"
#endif
#define FIBER_PORT_NAME "ARM_CM33F"

#include "../../fiber_port_select.h"
#include "../../fiber_settings.h"
#include "../../fiber_compiler.h"
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

#if !FIBER_PORT_BUILD_SELECTED
# error "[fiber]: ARM_CM33F is build-selected only"
#endif

#if !FIBER_PORT_ARMV8M_MAINLINE
# error "[fiber]: ARM_CM33F requires the ARMv8-M Mainline architecture result"
#endif

#if !defined(__ARM_ARCH_8M_MAIN__)
# error "[fiber]: ARM_CM33F requires an ARMv8-M Mainline compiler target"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 33)
# error "[fiber]: ARM_CM33F manifest requires CMSIS __CORTEX_M == 33"
#endif

#if !defined(__ARM_FEATURE_CMSE) || ((__ARM_FEATURE_CMSE + 0) != 1)
# error "[fiber]: ARM_CM33F requires a Non-secure CMSE level 1 build"
#endif

#if !defined(__VTOR_PRESENT) || (__VTOR_PRESENT != 1)
# error "[fiber]: ARM_CM33F requires __VTOR_PRESENT == 1"
#endif

#if !defined(__FPU_PRESENT) || (__FPU_PRESENT != 1) || \
        !defined(__FPU_USED) || (__FPU_USED != 1) || \
        !defined(__ARM_FP) || (__ARM_FP != 4)
# error "[fiber]: ARM_CM33F requires CMSIS FPU present/used and scalar-SP __ARM_FP == 4"
#endif
#if defined(__ARM_ARCH_8_1M_MAIN__) || defined(__ARM_FEATURE_PAC_DEFAULT) || \
        defined(__ARM_FEATURE_PAUTH) || defined(__ARM_FEATURE_PAUTH_DEFAULT) || \
        defined(__ARM_FEATURE_BTI) || defined(__ARM_FEATURE_BTI_DEFAULT)
# error "[fiber]: ARM_CM33F excludes ARMv8.1-M, PAC and BTI"
#endif
#if defined(FIBER_PORT_CM33F_MPU_TOTAL_REGIONS) || \
        defined(FIBER_PORT_CM33_MPU_TOTAL_REGIONS) || \
        defined(FIBER_PORT_CM55_MPU_TOTAL_REGIONS) || \
        defined(FIBER_PORT_CM55F_MPU_TOTAL_REGIONS) || \
        defined(FIBER_PORT_CM55_MVEF_MPU_TOTAL_REGIONS)
# error "[fiber]: ARM_CM33F does not accept an MPU region manifest"
#endif

#if defined(__ARM_FEATURE_MVE) && ((__ARM_FEATURE_MVE + 0) != 0)
# error "[fiber]: ARM_CM33F does not permit MVE"
#endif

#if !defined(__NVIC_PRIO_BITS) || (__NVIC_PRIO_BITS < 1) || \
		(__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM33F requires 1..8 implemented NVIC priority bits"
#endif

#ifdef FIBER_PORT_RUNTIME_SELECTABLE
# error "[fiber]: ARM_CM33F runtime-selectable state must not be predefined"
#endif
#define FIBER_PORT_RUNTIME_SELECTABLE 0

/* Pinned FreeRTOS ARM_CM33/non_secure non-MPU, scalar-SP TrustZone frame
 * dictionary. xSecureContext occupies the low word so PendSV can save and
 * restore it before touching ordinary Non-secure register state. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portSTART_ADDRESS_MASK 0xFFFFFFFEu
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFBCu
#define fiber_portSECURE_HEADER_WORDS 3u
#define fiber_portSECURE_HEADER_BYTES (fiber_portSECURE_HEADER_WORDS * 4u)
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
/* The CPU implements the Security Extension; this exact role is Non-secure
 * with a fiber-owned SecureContext companion. */
#define FIBER_PORT_HAS_SECURITY_EXT 1
#define FIBER_PORT_RUNS_NONSECURE 1
/* Standard register names address the executing Non-secure bank. */
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
# error "[fiber]: ARM_CM33F scheduler BASEPRI threshold must be non-zero"
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI > 255u
# error "[fiber]: ARM_CM33F scheduler BASEPRI threshold must fit in 8 bits"
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI &
		((1u << (8u - __NVIC_PRIO_BITS)) - 1u)) == 0u,
		"[fiber]: ARM_CM33F scheduler BASEPRI uses unimplemented priority bits");
#if __NVIC_PRIO_BITS == 8
FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI & 1u) == 0u,
		"[fiber]: ARM_CM33F BASEPRI bit 0 is subpriority when all 8 bits exist");
#endif

/* New C3FS identity: corrected semantics start at generation 1. */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x43334653u
#define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010001u
#define FIBER_PORT_CONTEXT_FEATURE_EXTENDED_FP 0x00000001u
#define FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT 0x00000002u
#define FIBER_PORT_CONTEXT_FEATURE_SECURE_CONTEXT_SLOT 0x00000008u
#define FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE 0x00000080u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	(FIBER_PORT_CONTEXT_FEATURE_EXTENDED_FP | \
	 FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_SECURE_CONTEXT_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE)

#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES (18u * 4u)
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES)
#define FIBER_PORT_SOFTWARE_FRAME_WORDS fiber_portSOFTWARE_FRAME_WORDS
#define FIBER_PORT_SOFTWARE_FRAME_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX fiber_portEXC_RETURN_WORD_INDEX
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES (16u * 4u)
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_BASE_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_HIGH_FP_SOFTWARE_BYTES + \
	 FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 4u

#define fiber_portBASEPRI_SYM "BASEPRI"

#ifdef __cplusplus
extern "C" {
#endif

fiber_portFORCE_INLINE FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_read_r9(void)
{
	uint32_t value;
	/* Local binding marks the actual sample, not unrelated compiler moves.
	 * It adds no instruction, callable API or public-entry r9 guarantee. */
	fiber_portASM volatile("fiber_c3fs_r9_capture_%=:\n\tmov %0, r9"
			: "=r"(value));
	return value;
}

fiber_portFORCE_INLINE FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_initial_xpsr(void)
{
	return fiber_portINITIAL_XPSR;
}

fiber_portFORCE_INLINE FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_stacked_pc(uintptr_t entry)
{
	return (uint32_t)(entry & (uintptr_t)fiber_portSTART_ADDRESS_MASK);
}

fiber_portFORCE_INLINE FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_basepri_read(void)
{
	uint32_t value;
	fiber_portASM volatile("mrs %0, " fiber_portBASEPRI_SYM
			: "=r"(value) :: "memory");
	return value;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

/* Frozen 32-bit GCC public storage layout. */
#define FIBER_PORT_CM33F_CONTEXT_SP_OFFSET 0u
#define FIBER_PORT_CM33F_CONTEXT_BOOT_OFFSET 4u
#define FIBER_PORT_CM33F_CONTEXT_SIZE 80u
#define FIBER_PORT_CM33F_CONTEXT_ALIGNMENT 4u
#define FIBER_PORT_CM33F_BOOT_SIZE 76u
#define FIBER_PORT_CM33F_BOOT_SECURE_STACK_BYTES_OFFSET 28u

FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: ARM_CM33F requires 32-bit pointers");
FIBER_STATIC_ASSERT(sizeof(size_t) == 4u,
		"[fiber]: ARM_CM33F requires 32-bit size_t");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM33F staged profile must not expose runtime operations");
FIBER_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS == 11u,
		"[fiber]: ARM_CM33F software frame must contain eleven words");
FIBER_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX == 2u,
		"[fiber]: ARM_CM33F EXC_RETURN must follow SecureContext and PSPLIM");
FIBER_STATIC_ASSERT(fiber_portSECURE_HEADER_WORDS == 3u &&
		fiber_portSECURE_HEADER_BYTES == 12u,
		"[fiber]: ARM_CM33F Secure-origin header geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x8Bu,
		"[fiber]: ARM_CM33F context feature identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_CONTEXT_BYTES == 76u,
		"[fiber]: ARM_CM33F initial context geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 216u,
		"[fiber]: ARM_CM33F maximum context geometry changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, sp) ==
		FIBER_PORT_CM33F_CONTEXT_SP_OFFSET,
		"[fiber]: ARM_CM33F saved-SP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, boot) ==
		FIBER_PORT_CM33F_CONTEXT_BOOT_OFFSET,
		"[fiber]: ARM_CM33F boot offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberContext) ==
		FIBER_PORT_CM33F_CONTEXT_SIZE,
		"[fiber]: ARM_CM33F context size changed");
FIBER_STATIC_ASSERT(alignof(FiberContext) ==
		FIBER_PORT_CM33F_CONTEXT_ALIGNMENT,
		"[fiber]: ARM_CM33F context alignment changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) ==
		FIBER_PORT_CM33F_BOOT_SIZE,
		"[fiber]: ARM_CM33F boot size changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, secure_stack_bytes) ==
		FIBER_PORT_CM33F_BOOT_SECURE_STACK_BYTES_OFFSET,
		"[fiber]: ARM_CM33F secure-stack request offset changed");
#include "../../fiber_port_traits.h"
#include "../../fiber_port_context_cohort.h"
#include "../../fiber_port_geometry.h"

#endif /* FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORTMACRO_H_ */
