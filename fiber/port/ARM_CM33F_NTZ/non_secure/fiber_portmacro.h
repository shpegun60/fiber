/*
 * fiber_portmacro.h
 *
 * Exact Cortex-M33F NTZ Non-secure dictionary, implementation slices 1-3.
 * This profile freezes the non-MPU FP-capable context identity and constructs
 * the same basic initial frame as the pinned FreeRTOS ARM_CM33_NTZ port.
 * It owns the fail-closed FPU setup, SVC first-start, and FP-aware PendSV
 * save/select/restore path for this exact Non-secure profile.
 */
#ifndef FIBER_PORT_ARM_CM33F_NTZ_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM33F_NTZ_FIBER_PORTMACRO_H_

#include <stddef.h>
#include <stdint.h>

#ifdef FIBER_PORT_NAME
# error "[fiber]: ARM_CM33F_NTZ port name must not be predefined"
#endif
#define FIBER_PORT_NAME "ARM_CM33F_NTZ"

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
# error "[fiber]: ARM_CM33F_NTZ is build-selected only"
#endif

#if !FIBER_PORT_ARMV8M_MAINLINE
# error "[fiber]: ARM_CM33F_NTZ requires the ARMv8-M Mainline architecture result"
#endif

#if !defined(__ARM_ARCH_8M_MAIN__)
# error "[fiber]: ARM_CM33F_NTZ requires an ARMv8-M Mainline compiler target"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 33)
# error "[fiber]: ARM_CM33F_NTZ manifest requires CMSIS __CORTEX_M == 33"
#endif

#if defined(__ARM_FEATURE_CMSE) && ((__ARM_FEATURE_CMSE + 0) >= 3)
# error "[fiber]: ARM_CM33F_NTZ does not accept a Secure CMSE build"
#endif

#if !defined(__VTOR_PRESENT) || (__VTOR_PRESENT != 1)
# error "[fiber]: ARM_CM33F_NTZ requires __VTOR_PRESENT == 1"
#endif

#if defined(FIBER_PORT_TOOLCHAIN_HAS_FP) || \
		defined(FIBER_PORT_SILICON_HAS_FPU) || \
		defined(FIBER_PORT_CMSIS_FPU_USED) || \
		defined(FIBER_PORT_HAS_FPU) || \
		defined(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT)
# error "[fiber]: ARM_CM33F_NTZ FPU facts are selected-port-owned"
#endif

#if !defined(__FPU_PRESENT) || ((__FPU_PRESENT + 0) != 1)
# error "[fiber]: ARM_CM33F_NTZ requires CMSIS __FPU_PRESENT == 1"
#endif

#if !defined(__FPU_USED) || ((__FPU_USED + 0) != 1)
# error "[fiber]: ARM_CM33F_NTZ requires CMSIS __FPU_USED == 1"
#endif

#if !defined(__ARM_FP) || ((__ARM_FP + 0) == 0)
# error "[fiber]: ARM_CM33F_NTZ requires compiler FP code generation"
#endif

#define FIBER_PORT_TOOLCHAIN_HAS_FP 1
#define FIBER_PORT_SILICON_HAS_FPU 1
#define FIBER_PORT_CMSIS_FPU_USED 1

#if defined(__ARM_FEATURE_MVE) && ((__ARM_FEATURE_MVE + 0) != 0)
# error "[fiber]: ARM_CM33F_NTZ does not permit MVE"
#endif

#if defined(__ARM_FEATURE_PAC_DEFAULT) || defined(__ARM_FEATURE_PAUTH) || \
		defined(__ARM_FEATURE_PAUTH_DEFAULT)
# error "[fiber]: ARM_CM33F_NTZ does not permit PAC"
#endif

#if defined(__ARM_FEATURE_BTI_DEFAULT) || defined(__ARM_FEATURE_BTI)
# error "[fiber]: ARM_CM33F_NTZ does not permit BTI"
#endif

#if defined(FIBER_PORT_CM33_MPU_TOTAL_REGIONS) || \
		defined(FIBER_PORT_MPU_TOTAL_REGIONS)
# error "[fiber]: ARM_CM33F_NTZ is non-MPU; select a separate MPU profile"
#endif

#if !defined(__NVIC_PRIO_BITS) || (__NVIC_PRIO_BITS < 1) || \
		(__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM33F_NTZ requires 1..8 implemented NVIC priority bits"
#endif

#ifdef FIBER_PORT_RUNTIME_SELECTABLE
# error "[fiber]: ARM_CM33F_NTZ runtime-selectable state must not be predefined"
#endif
#define FIBER_PORT_RUNTIME_SELECTABLE 1

/* Pinned FreeRTOS non-MPU frame dictionary. New tasks start with a basic
 * hardware frame. PendSV later adds s16-s31 only when EXC_RETURN bit 4 is 0. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portSTART_ADDRESS_MASK 0xFFFFFFFEu
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFBCu
#define fiber_portEXTENDED_EXC_RETURN 0xFFFFFFACu
#define fiber_portSVC_ORIGIN_EXC_RETURN 0xFFFFFFB8u
#define fiber_portPSPLIM_SLOT_WORDS 1u
#define fiber_portCORE_SOFTWARE_WORDS 9u
#define fiber_portSOFTWARE_FRAME_WORDS \
	(fiber_portPSPLIM_SLOT_WORDS + fiber_portCORE_SOFTWARE_WORDS)
#define fiber_portEXC_RETURN_WORD_INDEX 1u

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
#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 1
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
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
# error "[fiber]: ARM_CM33F_NTZ scheduler BASEPRI threshold must be non-zero"
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI > 255u
# error "[fiber]: ARM_CM33F_NTZ scheduler BASEPRI threshold must fit in 8 bits"
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI &
		((1u << (8u - __NVIC_PRIO_BITS)) - 1u)) == 0u,
		"[fiber]: ARM_CM33F_NTZ scheduler BASEPRI uses unimplemented priority bits");
#if __NVIC_PRIO_BITS == 8
FIBER_STATIC_ASSERT((FIBER_PORT_SCHEDULER_BASEPRI & 1u) == 0u,
		"[fiber]: ARM_CM33F_NTZ BASEPRI bit 0 is subpriority when all 8 bits exist");
#endif

/* ASCII "C3FN" is distinct from the no-FPU "C33N" cohort. */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x4333464Eu
#define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010001u
#define FIBER_PORT_CONTEXT_FEATURE_EXTENDED_FP 0x00000001u
#define FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT 0x00000002u
#define FIBER_PORT_CONTEXT_FEATURE_RUNS_NONSECURE 0x00000080u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	(FIBER_PORT_CONTEXT_FEATURE_EXTENDED_FP | \
	 FIBER_PORT_CONTEXT_FEATURE_PSPLIM_SLOT | \
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
#define FIBER_PORT_SAVED_SP_MOD8 0u

/* ARMv8-M Mainline system-control and FPU register dictionary. These are the
 * same CPACR/FPCCR encodings used by the pinned FreeRTOS ARM_CM33_NTZ port.
 * The selected Non-secure profile addresses its executing register bank. */
#define fiber_portNVIC_INT_CTRL_REG (*((volatile uint32_t *)0xE000ED04u))
#define fiber_portNVIC_PENDSVSET_BIT (1u << 28u)
#define fiber_portNVIC_PENDSVCLEAR_BIT (1u << 27u)
#define fiber_portVECTOR_INDEX_SVC 11u
#define fiber_portVECTOR_INDEX_PENDSV 14u
#define fiber_portLOWEST_EXCEPTION_PRIORITY \
	((1u << __NVIC_PRIO_BITS) - 1u)
#define fiber_portBASEPRI_SYM "BASEPRI"
#define fiber_portCPACR_REG (*((volatile uint32_t *)0xE000ED88u))
#define fiber_portFPCCR_REG (*((volatile uint32_t *)0xE000EF34u))
#define fiber_portCPACR_CP10_CP11_FULL (0x0Fu << 20u)
#define fiber_portFPCCR_LSPACT_BIT (1u << 0u)
#define fiber_portFPCCR_LSPEN_BIT (1u << 30u)
#define fiber_portFPCCR_ASPEN_BIT (1u << 31u)

#define fiber_portASM_WRITE_BASEPRI_R0 \
	"msr   " fiber_portBASEPRI_SYM ", r0           \n"
#define fiber_portASM_WRITE_BASEPRI_R2 \
	"msr   " fiber_portBASEPRI_SYM ", r2           \n"
#define fiber_portASM_WRITE_BASEPRI_R3 \
	"msr   " fiber_portBASEPRI_SYM ", r3           \n"
#define fiber_portASM_SNAP_BASEPRI_R3 \
	"mrs   r3, " fiber_portBASEPRI_SYM "            \n"

/* ARMv8-M Mainline has no Cortex-M7 r0p1 BASEPRI erratum. */
#define fiber_portASM_WRITE_BASEPRI_R0_SYNC \
	fiber_portASM_WRITE_BASEPRI_R0 \
	"dsb                                  \n" \
	"isb                                  \n"

#define fiber_portASM_WRITE_BASEPRI_R2_SYNC \
	fiber_portASM_WRITE_BASEPRI_R2 \
	"dsb                                  \n" \
	"isb                                  \n"

#define fiber_portASM_WRITE_BASEPRI_R3_SYNC \
	fiber_portASM_WRITE_BASEPRI_R3 \
	"dsb                                  \n" \
	"isb                                  \n"

#define fiber_portASM_ENTER_SCHEDULER_CRITICAL \
	fiber_portASM_SNAP_BASEPRI_R3 \
	"movs  r2, %[sched_basepri]           \n" \
	"stmdb sp!, {r2, r3}                  \n" \
	fiber_portASM_WRITE_BASEPRI_R2_SYNC

#define fiber_portASM_EXIT_SCHEDULER_CRITICAL \
	"ldmia sp!, {r2, r3}                  \n" \
	fiber_portASM_WRITE_BASEPRI_R3_SYNC

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

fiber_portFORCE_INLINE uint32_t fiber_port_basepri_read(void)
{
	uint32_t value;
	fiber_portASM volatile("mrs %0, " fiber_portBASEPRI_SYM
			: "=r"(value) :: "memory");
	return value;
}

fiber_portFORCE_INLINE void fiber_port_basepri_write(uint32_t value)
{
	fiber_portASM volatile("msr " fiber_portBASEPRI_SYM ", %0"
			:: "r"(value) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}

fiber_portFORCE_INLINE uint32_t fiber_port_scheduler_critical_enter(void)
{
	const uint32_t previous = fiber_port_basepri_read();
	fiber_port_basepri_write((uint32_t)FIBER_PORT_SCHEDULER_BASEPRI);
	return previous;
}

fiber_portFORCE_INLINE void fiber_port_scheduler_critical_exit(uint32_t state)
{
	fiber_port_basepri_write(state);
}

fiber_portFORCE_INLINE uintptr_t fiber_port_vectors_base_addr(void)
{
	uintptr_t value = (uintptr_t)SCB->VTOR;
#if defined(SCB_VTOR_TBLOFF_Msk)
	value &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
#endif
	return value;
}

fiber_portFORCE_INLINE const uint32_t *fiber_port_vectors_base_ptr(void)
{
	return (const uint32_t *)fiber_port_vectors_base_addr();
}

fiber_portFORCE_INLINE uint32_t fiber_port_read_initial_msp(void)
{
	return fiber_port_vectors_base_ptr()[0];
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#define FIBER_PORT_CM33F_NTZ_CONTEXT_SP_OFFSET 0u
#define FIBER_PORT_CM33F_NTZ_CONTEXT_BOOT_OFFSET 4u
#define FIBER_PORT_CM33F_NTZ_CONTEXT_SIZE 76u
#define FIBER_PORT_CM33F_NTZ_CONTEXT_ALIGNMENT 4u
#define FIBER_PORT_CM33F_NTZ_BOOT_SIZE 72u

FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: ARM_CM33F_NTZ requires 32-bit pointers");
FIBER_STATIC_ASSERT(sizeof(size_t) == 4u,
		"[fiber]: ARM_CM33F_NTZ requires 32-bit size_t");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 1,
		"[fiber]: ARM_CM33F_NTZ runtime must be selectable");
FIBER_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS == 10u,
		"[fiber]: ARM_CM33F_NTZ core software frame must contain ten words");
FIBER_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX == 1u,
		"[fiber]: ARM_CM33F_NTZ EXC_RETURN must follow the PSPLIM slot");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x83u,
		"[fiber]: ARM_CM33F_NTZ context feature identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_CONTEXT_BYTES == 72u,
		"[fiber]: ARM_CM33F_NTZ initial context geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 212u,
		"[fiber]: ARM_CM33F_NTZ maximum context geometry changed");
FIBER_STATIC_ASSERT(fiber_portEXTENDED_EXC_RETURN ==
		(fiber_portINITIAL_EXC_RETURN & ~0x10u),
		"[fiber]: ARM_CM33F_NTZ extended EXC_RETURN changed");
FIBER_STATIC_ASSERT(fiber_portSVC_ORIGIN_EXC_RETURN == 0xFFFFFFB8u,
		"[fiber]: ARM_CM33F_NTZ first-start SVC origin changed");
FIBER_STATIC_ASSERT((fiber_portINITIAL_EXC_RETURN & ~4u) ==
		fiber_portSVC_ORIGIN_EXC_RETURN,
		"[fiber]: ARM_CM33F_NTZ SVC/PSP EXC_RETURN relationship changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, sp) ==
		FIBER_PORT_CM33F_NTZ_CONTEXT_SP_OFFSET,
		"[fiber]: ARM_CM33F_NTZ saved-SP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, boot) ==
		FIBER_PORT_CM33F_NTZ_CONTEXT_BOOT_OFFSET,
		"[fiber]: ARM_CM33F_NTZ boot offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberContext) ==
		FIBER_PORT_CM33F_NTZ_CONTEXT_SIZE,
		"[fiber]: ARM_CM33F_NTZ context size changed");
FIBER_STATIC_ASSERT(alignof(FiberContext) ==
		FIBER_PORT_CM33F_NTZ_CONTEXT_ALIGNMENT,
		"[fiber]: ARM_CM33F_NTZ context alignment changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) == FIBER_PORT_CM33F_NTZ_BOOT_SIZE,
		"[fiber]: ARM_CM33F_NTZ boot size changed");

#ifndef FIBER_SVC_START_NUMBER
# define FIBER_SVC_START_NUMBER 70
#endif

#if defined(FIBER_PENDSV_VECTOR_DIRECT) || defined(FIBER_SVC_VECTOR_DIRECT) || \
		defined(FIBER_PENDSV_WIRED) || defined(FIBER_SVC_WIRED)
# error "[fiber]: vector routing macros were removed; the selected port owns strong handlers"
#endif

FIBER_STATIC_ASSERT((FIBER_SVC_START_NUMBER >= 0) &&
		(FIBER_SVC_START_NUMBER <= 255),
		"[fiber]: FIBER_SVC_START_NUMBER must fit in an 8-bit SVC immediate");

#include "../../fiber_port_traits.h"
#include "../../fiber_port_context_cohort.h"
#include "../../fiber_port_geometry.h"

#endif /* FIBER_PORT_ARM_CM33F_NTZ_FIBER_PORTMACRO_H_ */
