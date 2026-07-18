/*
 * fiber_portmacro.h
 *
 * Exact Cortex-M23 NTZ Non-secure dictionary, implementation slices 1-2.
 * These slices freeze the privileged non-MPU context layout and construct its
 * initial frame, but deliberately provide no exception handlers or switching
 * runtime yet.
 */
#ifndef FIBER_PORT_ARM_CM23_NTZ_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM23_NTZ_FIBER_PORTMACRO_H_

#include <stddef.h>
#include <stdint.h>

#ifdef FIBER_PORT_NAME
# error "[fiber]: ARM_CM23_NTZ port name must not be predefined"
#endif
#define FIBER_PORT_NAME "ARM_CM23_NTZ"

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
# error "[fiber]: ARM_CM23_NTZ is build-selected only"
#endif

#if !FIBER_PORT_ARMV8M_BASELINE
# error "[fiber]: ARM_CM23_NTZ requires the ARMv8-M Baseline architecture result"
#endif

#if !defined(__ARM_ARCH_8M_BASE__)
# error "[fiber]: ARM_CM23_NTZ requires an ARMv8-M Baseline compiler target"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 23)
# error "[fiber]: ARM_CM23_NTZ manifest requires CMSIS __CORTEX_M == 23"
#endif

#if defined(__ARM_FEATURE_CMSE) && ((__ARM_FEATURE_CMSE + 0) >= 3)
# error "[fiber]: ARM_CM23_NTZ does not accept a Secure CMSE build"
#endif

#if !defined(__VTOR_PRESENT) || (__VTOR_PRESENT != 1)
# error "[fiber]: ARM_CM23_NTZ requires __VTOR_PRESENT == 1"
#endif

#if defined(__FPU_PRESENT) && (__FPU_PRESENT != 0)
# error "[fiber]: Cortex-M23 has no FPU"
#endif

#if defined(__FPU_USED) && (__FPU_USED != 0)
# error "[fiber]: ARM_CM23_NTZ requires __FPU_USED == 0"
#endif

#if defined(__ARM_FP) && ((__ARM_FP + 0) != 0)
# error "[fiber]: ARM_CM23_NTZ does not permit an FP register ABI"
#endif

#if !defined(__NVIC_PRIO_BITS) || (__NVIC_PRIO_BITS < 1) || \
		(__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM23_NTZ requires 1..8 implemented NVIC priority bits"
#endif

#ifdef FIBER_PORT_RUNTIME_SELECTABLE
# error "[fiber]: ARM_CM23_NTZ runtime-selectable state must not be predefined"
#endif
#define FIBER_PORT_RUNTIME_SELECTABLE 0

/* Pinned FreeRTOS ARM_CM23_NTZ non-MPU frame dictionary. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portSTART_ADDRESS_MASK 0xFFFFFFFEu
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFBCu
#define fiber_portPSPLIM_SLOT_WORDS 1u
#define fiber_portCORE_SOFTWARE_WORDS 9u
#define fiber_portSOFTWARE_FRAME_WORDS \
	(fiber_portPSPLIM_SLOT_WORDS + fiber_portCORE_SOFTWARE_WORDS)
#define fiber_portEXC_RETURN_WORD_INDEX 1u

#define FIBER_PORT_HAS_BASEPRI 0
#define FIBER_PORT_HAS_FAULTMASK 0
#define FIBER_PORT_HAS_VTOR 1
/* Non-secure Cortex-M23 has no accessible Non-secure PSPLIM register. */
#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_HAS_FPU 0
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#define FIBER_PORT_STACK_ALIGNMENT fiber_portBYTE_ALIGNMENT
#define FIBER_PORT_BOOT_CLEARS_FPCA 0
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN fiber_portINITIAL_EXC_RETURN
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_PRIMASK
#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0
#ifndef FIBER_PORT_IS_V8M
# define FIBER_PORT_IS_V8M 1
#endif
#define FIBER_PORT_HAS_SECURITY_EXT 1
#define FIBER_PORT_RUNS_NONSECURE 1
/* Standard register names already address the executing Non-secure bank. */
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 1
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0

/* ASCII "C23N" distinguishes this NTZ profile from future ARM_CM23 roles. */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x4332334Eu
#define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010001u
#define FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT 0x00000002u
#define FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE 0x00000080u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	(FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT | \
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
#define FIBER_PORT_SAVED_SP_MOD8 0u

#ifndef FIBER_SCHEDULER_BASEPRI
# define FIBER_SCHEDULER_BASEPRI 0u
#endif
#if FIBER_SCHEDULER_BASEPRI != 0u
# error "[fiber]: ARM_CM23_NTZ has no BASEPRI; FIBER_SCHEDULER_BASEPRI must be zero"
#endif

#ifdef __cplusplus
extern "C" {
#endif

fiber_portFORCE_INLINE uint32_t fiber_port_read_r9(void)
{
	uint32_t value;
	fiber_portASM volatile("mov %0, r9" : "=r"(value));
	return value;
}

fiber_portFORCE_INLINE uint32_t fiber_port_initial_xpsr(void)
{
	return fiber_portINITIAL_XPSR;
}

fiber_portFORCE_INLINE uint32_t fiber_port_stacked_pc(uintptr_t entry)
{
	return (uint32_t)(entry & (uintptr_t)fiber_portSTART_ADDRESS_MASK);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

/* Frozen 32-bit GCC public storage layout. */
#define FIBER_PORT_CM23_NTZ_CONTEXT_SP_OFFSET 0u
#define FIBER_PORT_CM23_NTZ_CONTEXT_BOOT_OFFSET 4u
#define FIBER_PORT_CM23_NTZ_CONTEXT_SIZE 76u
#define FIBER_PORT_CM23_NTZ_CONTEXT_ALIGNMENT 4u
#define FIBER_PORT_CM23_NTZ_BOOT_SIZE 72u

FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: ARM_CM23_NTZ requires 32-bit pointers");
FIBER_STATIC_ASSERT(sizeof(size_t) == 4u,
		"[fiber]: ARM_CM23_NTZ requires 32-bit size_t");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: incomplete ARM_CM23_NTZ runtime must remain non-selectable");
FIBER_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS == 10u,
		"[fiber]: ARM_CM23_NTZ software frame must contain ten words");
FIBER_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX == 1u,
		"[fiber]: ARM_CM23_NTZ EXC_RETURN must follow the PSPLIM slot");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x82u,
		"[fiber]: ARM_CM23_NTZ context feature identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_CONTEXT_BYTES == 72u,
		"[fiber]: ARM_CM23_NTZ initial context geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 76u,
		"[fiber]: ARM_CM23_NTZ maximum context geometry changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, sp) ==
		FIBER_PORT_CM23_NTZ_CONTEXT_SP_OFFSET,
		"[fiber]: ARM_CM23_NTZ saved-SP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, boot) ==
		FIBER_PORT_CM23_NTZ_CONTEXT_BOOT_OFFSET,
		"[fiber]: ARM_CM23_NTZ boot offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberContext) ==
		FIBER_PORT_CM23_NTZ_CONTEXT_SIZE,
		"[fiber]: ARM_CM23_NTZ context size changed");
FIBER_STATIC_ASSERT(alignof(FiberContext) ==
		FIBER_PORT_CM23_NTZ_CONTEXT_ALIGNMENT,
		"[fiber]: ARM_CM23_NTZ context alignment changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) ==
		FIBER_PORT_CM23_NTZ_BOOT_SIZE,
		"[fiber]: ARM_CM23_NTZ boot size changed");

#include "../../fiber_port_traits.h"
#include "../../fiber_port_context_cohort.h"
#include "fiber_port_boot.h"
#include "../../fiber_port_geometry.h"

#endif /* FIBER_PORT_ARM_CM23_NTZ_FIBER_PORTMACRO_H_ */
