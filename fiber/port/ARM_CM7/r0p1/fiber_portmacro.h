/*
 * fiber_portmacro.h
 *
 * ARM_CM7 r0p1 selected port contract.
 */

#ifndef FIBER_PORT_ARM_CM7_R0P1_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM7_R0P1_FIBER_PORTMACRO_H_

/*
 * This selected port follows the FreeRTOS ARM_CM7/r0p1 CPU contract while
 * dropping the extra toolchain directory level. The build selects this include
 * directory and exactly one matching source file. The public macro names remain
 * fiber-owned and are intentionally not FreeRTOS ABI names.
 */
#include <stdint.h>

#include "fiber_port_types.h"
#include "mcu_core.h"
#include "../../fiber_settings.h"
#include "../../fiber_compiler.h"
#include "../../../fiber_panic.h"
#include "fiber_port_boot.h"

/*
 * Keep this header close to the FreeRTOS portmacro.h model: selected-port CPU
 * facts, CMSIS view, compiler helpers, and the panic/require diagnostic
 * contract live here. The matching fiber_port.c includes only root runtime
 * headers it needs for FiberContext, boot records, and scheduler bridge state.
 */
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

#ifndef FIBER_SVC_START_NUMBER
# define FIBER_SVC_START_NUMBER 70
#endif

#ifndef FIBER_PENDSV_VECTOR_DIRECT
# define FIBER_PENDSV_VECTOR_DIRECT 0
#endif

#ifndef FIBER_SVC_VECTOR_DIRECT
# define FIBER_SVC_VECTOR_DIRECT 0
#endif

#if defined(FIBER_FORCE_PRIGROUP) || defined(FIBER_TUNE_SYSTICK) || \
		defined(FIBER_TUNE_SVCALL)
# error "[fiber]: ARM_CM7/r0p1 owns neither PRIGROUP nor SysTick; SVCall priority setup is mandatory"
#endif

#if defined(FIBER_VALIDATE_EXCEPTION_SETUP) || \
		defined(FIBER_VALIDATE_VECTOR_WIRING) || \
		defined(FIBER_VALIDATE_PENDSV_VECTOR) || \
		defined(FIBER_VALIDATE_SVC_VECTOR) || \
		defined(FIBER_VALIDATE_BASEPRI_PRIORITY_MASK) || \
		defined(FIBER_VALIDATE_PRIORITY_GROUPING) || \
		defined(FIBER_VALIDATE_M7_R0P1_ERRATA_POLICY) || \
		defined(FIBER_VALIDATE_SVC_PRIORITY)
# error "[fiber]: ARM_CM7/r0p1 startup validation is mandatory and has no user switch"
#endif

FIBER_STATIC_ASSERT((FIBER_SVC_START_NUMBER >= 0) &&
		(FIBER_SVC_START_NUMBER <= 255),
		"[fiber]: FIBER_SVC_START_NUMBER must fit in an 8-bit SVC immediate");

#if (FIBER_FPU_LAZY != 0) && (FIBER_FPU_LAZY != 1)
# error "[fiber]: ARM_CM7/r0p1 FIBER_FPU_LAZY must be 0 or 1"
#endif
#if (FIBER_PENDSV_VECTOR_DIRECT != 0) && (FIBER_PENDSV_VECTOR_DIRECT != 1)
# error "[fiber]: ARM_CM7/r0p1 FIBER_PENDSV_VECTOR_DIRECT must be 0 or 1"
#endif
#if (FIBER_SVC_VECTOR_DIRECT != 0) && (FIBER_SVC_VECTOR_DIRECT != 1)
# error "[fiber]: ARM_CM7/r0p1 FIBER_SVC_VECTOR_DIRECT must be 0 or 1"
#endif

#ifndef FIBER_PORT_MASK_PRIMASK
# define FIBER_PORT_MASK_PRIMASK 1
#endif

#ifndef FIBER_PORT_MASK_BASEPRI
# define FIBER_PORT_MASK_BASEPRI 2
#endif

/*-----------------------------------------------------------
 * FPU discovery.
 *
 * Keep the detection local to this selected port. The common runtime consumes
 * only the resulting traits.
 *----------------------------------------------------------*/

#if defined(FIBER_PORT_TOOLCHAIN_HAS_FP) || \
		defined(FIBER_PORT_SILICON_HAS_FPU) || \
		defined(FIBER_PORT_CMSIS_FPU_USED) || \
		defined(FIBER_PORT_HAS_FPU) || \
		defined(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT)
# error "[fiber]: ARM_CM7/r0p1 FPU facts are selected-port-owned and must not be predefined"
#endif

#if defined(__ARM_FP) && ((__ARM_FP + 0) != 0)
# define FIBER_PORT_TOOLCHAIN_HAS_FP 1
#elif defined(__VFP_FP__) && !defined(__SOFTFP__)
# define FIBER_PORT_TOOLCHAIN_HAS_FP 1
#else
# define FIBER_PORT_TOOLCHAIN_HAS_FP 0
#endif

#if defined(__FPU_PRESENT) && ((__FPU_PRESENT + 0) != 0) && \
		((__FPU_PRESENT + 0) != 1)
# error "[fiber]: ARM_CM7 CMSIS __FPU_PRESENT must be 0 or 1"
#endif

#if defined(__FPU_USED) && ((__FPU_USED + 0) != 0) && \
		((__FPU_USED + 0) != 1)
# error "[fiber]: ARM_CM7 CMSIS __FPU_USED must be 0 or 1"
#endif

#if defined(__FPU_PRESENT) && (__FPU_PRESENT == 1)
# define FIBER_PORT_SILICON_HAS_FPU 1
#else
# define FIBER_PORT_SILICON_HAS_FPU 0
#endif

#if defined(__FPU_USED)
# define FIBER_PORT_CMSIS_FPU_USED ((__FPU_USED + 0) == 1)
#else
# define FIBER_PORT_CMSIS_FPU_USED 0
#endif

#if (FIBER_PORT_TOOLCHAIN_HAS_FP == 1) && (FIBER_PORT_SILICON_HAS_FPU == 0)
# error "[fiber]: ARM_CM7 compiler emits FP instructions but CMSIS reports no silicon FPU"
#endif
#if defined(__FPU_USED) && \
		(FIBER_PORT_CMSIS_FPU_USED != FIBER_PORT_TOOLCHAIN_HAS_FP)
# error "[fiber]: ARM_CM7 CMSIS __FPU_USED disagrees with compiler FP code generation"
#endif

#if (FIBER_PORT_SILICON_HAS_FPU == 1) && (FIBER_PORT_TOOLCHAIN_HAS_FP == 1)
# define FIBER_PORT_HAS_FPU 1
# define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 1
#else
# define FIBER_PORT_HAS_FPU 0
# define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 7)
# error "[fiber]: ARM_CM7/r0p1 selected port requires Cortex-M7"
#endif

#ifndef __NVIC_PRIO_BITS
# error "[fiber]: ARM_CM7/r0p1 requires CMSIS __NVIC_PRIO_BITS"
#endif
#if (__NVIC_PRIO_BITS < 2) || (__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM7/r0p1 __NVIC_PRIO_BITS must be in [2, 8]"
#endif

#ifndef FIBER_SCHEDULER_BASEPRI
# if __NVIC_PRIO_BITS == 8
/* PRIGROUP necessarily leaves bit 0 as subpriority on an 8-bit implementation. */
#  define FIBER_SCHEDULER_BASEPRI 2u
# else
#  define FIBER_SCHEDULER_BASEPRI (1u << (8u - __NVIC_PRIO_BITS))
# endif
#endif

#if FIBER_SCHEDULER_BASEPRI == 0u
# error "[fiber]: ARM_CM7/r0p1 scheduler BASEPRI threshold must be non-zero"
#endif

#if FIBER_SCHEDULER_BASEPRI > 255u
# error "[fiber]: ARM_CM7/r0p1 scheduler BASEPRI threshold must fit in 8 bits"
#endif

FIBER_STATIC_ASSERT((FIBER_SCHEDULER_BASEPRI &
		((1u << (8u - __NVIC_PRIO_BITS)) - 1u)) == 0u,
		"[fiber]: ARM_CM7/r0p1 scheduler BASEPRI uses unimplemented priority bits");
#if __NVIC_PRIO_BITS == 8
FIBER_STATIC_ASSERT((FIBER_SCHEDULER_BASEPRI & 1u) == 0u,
		"[fiber]: ARM_CM7/r0p1 scheduler BASEPRI bit 0 is subpriority when all 8 bits are implemented");
#endif

/*-----------------------------------------------------------
 * Port specific definitions.
 *
 * This mirrors the role of FreeRTOS portmacro.h constants, but uses the
 * fiber_portXXX namespace to avoid exporting FreeRTOS ABI names.
 *----------------------------------------------------------*/

#ifndef FIBER_PORT_NAME
# define FIBER_PORT_NAME "ARM_CM7/r0p1"
#endif

#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portSTART_ADDRESS_MASK 0xFFFFFFFEu
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFFDu

#define fiber_portNVIC_INT_CTRL_REG \
	(*((volatile uint32_t *)0xE000ED04u))
#define fiber_portNVIC_PENDSVSET_BIT (1u << 28u)
#define fiber_portNVIC_PENDSVCLEAR_BIT (1u << 27u)
#define fiber_portNVIC_PEND_SYSTICK_SET_BIT (1u << 26u)
#define fiber_portNVIC_PEND_SYSTICK_CLEAR_BIT (1u << 25u)

#define fiber_portNVIC_SHPR2_REG (*((volatile uint32_t *)0xE000ED1Cu))
#define fiber_portNVIC_SHPR3_REG (*((volatile uint32_t *)0xE000ED20u))
#define fiber_portSCB_VTOR_REG (*((volatile uint32_t *)0xE000ED08u))
#define fiber_portAIRCR_REG (*((volatile uint32_t *)0xE000ED0Cu))
#define fiber_portNVIC_IP_REGISTERS_OFFSET_16 0xE000E3F0u

#define fiber_portVECTOR_INDEX_SVC 11u
#define fiber_portVECTOR_INDEX_PENDSV 14u
#define fiber_portFIRST_USER_INTERRUPT_NUMBER 16u
#define fiber_portMIN_INTERRUPT_PRIORITY 255u
#define fiber_portMAX_8_BIT_VALUE ((uint8_t)0xFFu)
#define fiber_portTOP_BIT_OF_BYTE ((uint8_t)0x80u)
#define fiber_portMAX_PRIGROUP_BITS ((uint8_t)7u)
#define fiber_portPRIORITY_GROUP_MASK (0x07u << 8u)
#define fiber_portPRIGROUP_SHIFT 8u
#define fiber_portVECTACTIVE_MASK 0xFFu

#define fiber_portFPCCR (*((volatile uint32_t *)0xE000EF34u))
#define fiber_portASPEN_AND_LSPEN_BITS (0x3u << 30u)

#define fiber_portEXC_BASE_BYTES (8u * 4u)
#define fiber_portEXC_FP_EXT_BYTES \
	(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT ? (18u * 4u) : 0u)
#define fiber_portEXC_PER_LEVEL \
	(fiber_portEXC_BASE_BYTES + \
	 fiber_portEXC_FP_EXT_BYTES)

#define fiber_portSOFTWARE_FRAME_WORDS 9u
#define fiber_portSOFTWARE_FRAME_BYTES \
	(fiber_portSOFTWARE_FRAME_WORDS * 4u)
#define fiber_portEXC_RETURN_WORD_INDEX 8u

/*-----------------------------------------------------------
 * Selected-port trait bridge.
 *
 * The FIBER_PORT_* names are the generic contract consumed by common fiber
 * runtime code. Keep them separate from the fiber_portXXX CPU dictionary above.
 *----------------------------------------------------------*/

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1
#define FIBER_PORT_HAS_VTOR 1
#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_STACK_ALIGNMENT fiber_portBYTE_ALIGNMENT
#define FIBER_PORT_BOOT_CLEARS_FPCA FIBER_PORT_HAS_FPU
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN \
	fiber_portINITIAL_EXC_RETURN
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_BASEPRI
#define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI
#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 1
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 1
#ifndef FIBER_PORT_IS_V8M
# define FIBER_PORT_IS_V8M 0
#endif
#define FIBER_PORT_HAS_SECURITY_EXT 0
#define FIBER_PORT_RUNS_NONSECURE 0
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0

#define FIBER_PORT_EXC_BASE_BYTES \
	fiber_portEXC_BASE_BYTES
#define FIBER_PORT_EXC_FP_EXT_BYTES \
	fiber_portEXC_FP_EXT_BYTES
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
	fiber_portEXC_PER_LEVEL

#define FIBER_PORT_SOFTWARE_FRAME_WORDS \
	fiber_portSOFTWARE_FRAME_WORDS
#define FIBER_PORT_SOFTWARE_FRAME_BYTES \
	fiber_portSOFTWARE_FRAME_BYTES
#define FIBER_PORT_EXC_RETURN_WORD_INDEX \
	fiber_portEXC_RETURN_WORD_INDEX
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES \
	(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT ? (16u * 4u) : 0u)
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_SOFTWARE_FRAME_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_HIGH_FP_SOFTWARE_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 4u

FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_CONTEXT_BYTES == 68u,
		"[fiber]: ARM_CM7/r0p1 initial saved context must be 68 bytes");
#if FIBER_PORT_HAS_EXTENDED_FP_CONTEXT
FIBER_STATIC_ASSERT(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 208u,
		"[fiber]: ARM_CM7/r0p1 FP saved-context maximum must be 208 bytes");
#else
FIBER_STATIC_ASSERT(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 72u,
		"[fiber]: ARM_CM7/r0p1 core-only saved-context maximum must be 72 bytes");
#endif

/*-----------------------------------------------------------
 * Critical section management.
 *
 * Cortex-M7 r0p1 errata 837070 requires synchronized BASEPRI writes. The
 * selected port uses PRIMASK-preserving snippets so an already-masked caller is
 * not accidentally unmasked by the workaround sequence.
 *----------------------------------------------------------*/

#define fiber_portBASEPRI_SYM "BASEPRI"

#define fiber_portASM_SNAP_BASEPRI_R3 \
	"mrs   r3, " fiber_portBASEPRI_SYM "           \n"
#define fiber_portASM_WRITE_BASEPRI_R0 \
	"msr   " fiber_portBASEPRI_SYM ", r0           \n"
#define fiber_portASM_WRITE_BASEPRI_R2 \
	"msr   " fiber_portBASEPRI_SYM ", r2           \n"
#define fiber_portASM_WRITE_BASEPRI_R3 \
	"msr   " fiber_portBASEPRI_SYM ", r3           \n"

/*
 * Cortex-M7 r0p1 errata 837070 policy is local to this selected port.
 * These snippets clobber r12 to preserve the previous PRIMASK around BASEPRI
 * writes instead of unconditionally enabling IRQs.
 */
#define fiber_portASM_WRITE_BASEPRI_R0_SYNC \
	"mrs   r12, primask                  \n" \
	"cpsid i                              \n" \
	fiber_portASM_WRITE_BASEPRI_R0 \
	"dsb                                  \n" \
	"isb                                  \n" \
	"msr   primask, r12                  \n" \
	"dsb                                  \n" \
	"isb                                  \n"

#define fiber_portASM_WRITE_BASEPRI_R2_SYNC \
	"mrs   r12, primask                  \n" \
	"cpsid i                              \n" \
	fiber_portASM_WRITE_BASEPRI_R2 \
	"dsb                                  \n" \
	"isb                                  \n" \
	"msr   primask, r12                  \n" \
	"dsb                                  \n" \
	"isb                                  \n"

#define fiber_portASM_WRITE_BASEPRI_R3_SYNC \
	"mrs   r12, primask                  \n" \
	"cpsid i                              \n" \
	fiber_portASM_WRITE_BASEPRI_R3 \
	"dsb                                  \n" \
	"isb                                  \n" \
	"msr   primask, r12                  \n" \
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

#define FBR_ASM_MSR_PSPLIM(_reg) /* ARM_CM7/r0p1 has no PSPLIM. */

/*-----------------------------------------------------------
 * Port helper functions.
 *----------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

fiber_portFORCE_INLINE uint8_t fiber_arm_cm7_r0p1_count_leading_zeros(uint32_t bitmap)
{
	uint32_t result;
	fiber_portASM volatile("clz %0, %1" : "=r"(result) : "r"(bitmap) : "memory");
	return (uint8_t)result;
}

fiber_portFORCE_INLINE uint32_t fiber_arm_cm7_r0p1_read_r9(void)
{
	uint32_t value;
	fiber_portASM volatile("mov %0, r9" : "=r"(value));
	return value;
}

fiber_portFORCE_INLINE uint32_t fiber_port_read_r9(void)
{
	return fiber_arm_cm7_r0p1_read_r9();
}

fiber_portFORCE_INLINE uint32_t fiber_port_initial_xpsr(void)
{
	return fiber_portINITIAL_XPSR;
}

fiber_portFORCE_INLINE uint32_t fiber_arm_cm7_r0p1_stacked_pc(uintptr_t entry)
{
	return (uint32_t)(entry & (uintptr_t)fiber_portSTART_ADDRESS_MASK);
}

fiber_portFORCE_INLINE uint32_t fiber_port_stacked_pc(uintptr_t entry)
{
	return fiber_arm_cm7_r0p1_stacked_pc(entry);
}

fiber_portFORCE_INLINE uint32_t fiber_arm_cm7_r0p1_is_inside_interrupt(void)
{
	uint32_t ipsr;
	fiber_portASM volatile("mrs %0, ipsr" : "=r"(ipsr) :: "memory");
	return (ipsr == 0u) ? 0u : 1u;
}

fiber_portFORCE_INLINE uint32_t fiber_arm_cm7_r0p1_basepri_read(void)
{
	uint32_t value;
	fiber_portASM volatile("mrs %0, BASEPRI" : "=r"(value) :: "memory");
	return value;
}

fiber_portFORCE_INLINE void fiber_arm_cm7_r0p1_basepri_write(uint32_t value)
{
	uint32_t primask;

	fiber_portASM volatile("mrs %0, primask" : "=r"(primask) :: "memory");
	fiber_portASM volatile("cpsid i" ::: "memory");
	fiber_portASM volatile("msr BASEPRI, %0" :: "r"(value) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}

fiber_portFORCE_INLINE uint32_t fiber_port_basepri_read(void)
{
	return fiber_arm_cm7_r0p1_basepri_read();
}

fiber_portFORCE_INLINE void fiber_port_basepri_write(uint32_t value)
{
	fiber_arm_cm7_r0p1_basepri_write(value);
}

fiber_portFORCE_INLINE uint32_t fiber_port_scheduler_critical_enter(void)
{
	const uint32_t old_basepri = fiber_arm_cm7_r0p1_basepri_read();
	fiber_arm_cm7_r0p1_basepri_write((uint32_t)FIBER_PORT_SCHEDULER_BASEPRI);
	return old_basepri;
}

fiber_portFORCE_INLINE void fiber_port_scheduler_critical_exit(uint32_t state)
{
	fiber_arm_cm7_r0p1_basepri_write(state);
}

fiber_portFORCE_INLINE void fiber_arm_cm7_r0p1_memory_barrier(void)
{
	fiber_portCOMPILER_BARRIER();
}

fiber_portFORCE_INLINE void fiber_port_fpu_enable_early(void)
{
#if FIBER_PORT_HAS_FPU
# if !defined(FPU) || !defined(FPU_FPCCR_ASPEN_Msk) || \
		!defined(FPU_FPCCR_LSPEN_Msk)
#  error "[fiber]: CM7 FPU port requires CMSIS FPU/FPCCR definitions"
# endif
	const uint32_t cpacr_cp10_cp11_full = (0xFu << 20);
#  ifdef SCB
	volatile uint32_t *const cpacr_reg = &SCB->CPACR;
#  else
	volatile uint32_t *const cpacr_reg = (uint32_t *)0xE000ED88u;
#  endif

	uint32_t value = *cpacr_reg;
	if ((value & cpacr_cp10_cp11_full) != cpacr_cp10_cp11_full) {
		value = (value & ~cpacr_cp10_cp11_full) | cpacr_cp10_cp11_full;
		*cpacr_reg = value;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
	}
	FIBER_REQUIRE((*cpacr_reg & cpacr_cp10_cp11_full) ==
			cpacr_cp10_cp11_full, 'e');

	volatile uint32_t fpccr = FPU->FPCCR;
	uint32_t fpccr_policy_mask = 0u;

#  ifdef FPU_FPCCR_ASPEN_Msk
	fpccr_policy_mask |= FPU_FPCCR_ASPEN_Msk;
	fpccr |= FPU_FPCCR_ASPEN_Msk;
#  endif

#  ifdef FPU_FPCCR_LSPEN_Msk
	fpccr_policy_mask |= FPU_FPCCR_LSPEN_Msk;
#   if FIBER_FPU_LAZY
	fpccr |= FPU_FPCCR_LSPEN_Msk;
#   else
	fpccr &= ~FPU_FPCCR_LSPEN_Msk;
#   endif
#  endif

	if (fpccr != FPU->FPCCR) {
		FPU->FPCCR = fpccr;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
	}
	FIBER_REQUIRE(fpccr_policy_mask != 0u, 'E');
	FIBER_REQUIRE((FPU->FPCCR & fpccr_policy_mask) ==
			(fpccr & fpccr_policy_mask), 'E');
#else
	(void)0;
#endif
}

fiber_portFORCE_INLINE uint32_t fiber_port_psplim_read(void)
{
	return 0u;
}

fiber_portFORCE_INLINE void fiber_port_psplim_write(uint32_t limit)
{
	(void)limit;
}

fiber_portFORCE_INLINE void fiber_port_psplim_config(uint32_t stack_low_addr)
{
	(void)stack_low_addr;
}

fiber_portFORCE_INLINE uintptr_t fiber_arm_cm7_r0p1_vectors_base_addr(void)
{
	uintptr_t value = (uintptr_t)fiber_portSCB_VTOR_REG;
	value &= ~((uintptr_t)0x7Fu);
	return value;
}

fiber_portFORCE_INLINE uintptr_t fiber_port_vectors_base_addr(void)
{
	return fiber_arm_cm7_r0p1_vectors_base_addr();
}

fiber_portFORCE_INLINE const uint32_t *fiber_port_vectors_base_ptr(void)
{
	return (const uint32_t *)fiber_port_vectors_base_addr();
}

fiber_portFORCE_INLINE uint32_t fiber_port_read_initial_msp(void)
{
	const uint32_t *const vectors = fiber_port_vectors_base_ptr();
	return vectors[0];
}

fiber_portFORCE_INLINE void fiber_port_set_vectors_base_addr(uintptr_t base)
{
	base &= ~((uintptr_t)0x7Fu);
	fiber_portSCB_VTOR_REG = (uint32_t)base;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}

fiber_portFORCE_INLINE void fiber_arm_cm7_r0p1_yield_request(void)
{
	fiber_portNVIC_INT_CTRL_REG =
		fiber_portNVIC_PENDSVSET_BIT;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
}

struct FiberContext;

void fiber_port_init_context_frame(struct FiberContext *ctx);

/* Thread-mode schedule boundary. These are selected-port ABI entry points,
 * deliberately out-of-line so common runtime objects do not inherit CPU
 * register access or direct ICSR writes. */
FIBER_NOINLINE
void fiber_port_require_schedule_environment(void);

FIBER_NOINLINE
void fiber_port_request_schedule(void);

void fiber_exception_runtime_check(void);

void fiber_pendsv_init_lowest_priority(void);

void fiber_port_start_first_context(uintptr_t msp_top);

void fiber_svc(void);

void fiber_pendsv(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM7_R0P1_FIBER_PORTMACRO_H_ */
