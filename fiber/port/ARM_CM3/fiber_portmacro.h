/*
 * fiber_portmacro.h
 *
 * ARM_CM3 selected portmacro facade.
 *
 * This concrete port covers Cortex-M3. This header owns the CPU dictionary,
 * traits, inline helpers, and selected-port ABI.
 */

#ifndef FIBER_PORT_ARM_CM3_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM3_FIBER_PORTMACRO_H_

/* Keep the selected-port compiler/asm contract identical to ARM_CM7. */
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

#if FIBER_PORT_ARMV7M
# include "fiber_port_types.h"
#endif
#include <stdint.h>
#include "mcu_core.h"
#include "../fiber_settings.h"
#include "../fiber_compiler.h"
#include "../../fiber_panic.h"

#if FIBER_PORT_ARMV7M

#ifndef FIBER_PORT_NAME
# define FIBER_PORT_NAME "ARM_CM3"
#endif

/* FreeRTOS-style CPU dictionary, owned by this concrete port. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portSTART_ADDRESS_MASK 0xFFFFFFFEu
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFFDu

#define fiber_portNVIC_INT_CTRL_REG (*((volatile uint32_t *)0xE000ED04u))
#define fiber_portNVIC_PENDSVSET_BIT (1u << 28u)
#define fiber_portNVIC_PENDSVCLEAR_BIT (1u << 27u)
#define fiber_portNVIC_SHPR2_REG (*((volatile uint32_t *)0xE000ED1Cu))
#define fiber_portNVIC_SHPR3_REG (*((volatile uint32_t *)0xE000ED20u))
#define fiber_portSCB_VTOR_REG (*((volatile uint32_t *)0xE000ED08u))
#define fiber_portVECTOR_INDEX_SVC 11u
#define fiber_portVECTOR_INDEX_PENDSV 14u

#define fiber_portEXC_BASE_BYTES (8u * 4u)
#define fiber_portEXC_FP_EXT_BYTES 0u
#define fiber_portEXC_PER_LEVEL \
	(fiber_portEXC_BASE_BYTES + fiber_portEXC_FP_EXT_BYTES)
#define fiber_portSOFTWARE_FRAME_WORDS 9u
#define fiber_portSOFTWARE_FRAME_BYTES (fiber_portSOFTWARE_FRAME_WORDS * 4u)
#define fiber_portEXC_RETURN_WORD_INDEX 8u

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1

#define FIBER_PORT_HAS_VTOR 1

#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_TOOLCHAIN_HAS_FP 0
#define FIBER_PORT_SILICON_HAS_FPU 0
#define FIBER_PORT_CMSIS_FPU_USED 0
#define FIBER_PORT_HAS_FPU 0
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#define FIBER_PORT_STACK_ALIGNMENT fiber_portBYTE_ALIGNMENT
#define FIBER_PORT_BOOT_CLEARS_FPCA 0
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN fiber_portINITIAL_EXC_RETURN
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_BASEPRI

#ifndef FIBER_PORT_SCHEDULER_BASEPRI
# ifdef FIBER_SCHEDULER_BASEPRI
#  define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI
# else
#  ifndef __NVIC_PRIO_BITS
#   error "[fiber]: __NVIC_PRIO_BITS is required to default ARMv7-M scheduler BASEPRI"
#  endif
#  define FIBER_PORT_SCHEDULER_BASEPRI (1u << (8u - __NVIC_PRIO_BITS))
# endif
#endif

#ifndef FIBER_SCHEDULER_BASEPRI
# define FIBER_SCHEDULER_BASEPRI FIBER_PORT_SCHEDULER_BASEPRI
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI == 0u
# error "[fiber]: ARMv7-M scheduler BASEPRI threshold must be non-zero"
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI > 255u
# error "[fiber]: ARMv7-M scheduler BASEPRI threshold must fit in 8 bits"
#endif

#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0
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

/* Immutable seal identity. A context must never be restored by a port with a
 * different saved-frame layout or selected CPU feature contract. */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x434D3033u
#define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010001u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	((FIBER_PORT_HAS_EXTENDED_FP_CONTEXT ? 1u : 0u) | \
	 (FIBER_PORT_USES_PSPLIM_REGISTER ? 2u : 0u) | \
	 (FIBER_PORT_HAS_CONTROL_SLOT ? 4u : 0u) | \
	 (FIBER_PORT_HAS_SECURE_CONTEXT_SLOT ? 8u : 0u) | \
	 (FIBER_PORT_HAS_MVE ? 16u : 0u) | \
	 (FIBER_PORT_HAS_PAC ? 32u : 0u) | \
	 (FIBER_PORT_HAS_BTI ? 64u : 0u) | \
	 (FIBER_PORT_RUNS_NONSECURE ? 128u : 0u) | \
	 (FIBER_PORT_TARGETS_NS_BANK ? 256u : 0u) | \
	 (FIBER_PORT_HAS_PAC_KEY_SLOT ? 512u : 0u))

#define FIBER_PORT_EXC_BASE_BYTES fiber_portEXC_BASE_BYTES
#define FIBER_PORT_EXC_FP_EXT_BYTES fiber_portEXC_FP_EXT_BYTES
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
	fiber_portEXC_PER_LEVEL

#define FIBER_PORT_SOFTWARE_FRAME_WORDS fiber_portSOFTWARE_FRAME_WORDS
#define FIBER_PORT_SOFTWARE_FRAME_BYTES fiber_portSOFTWARE_FRAME_BYTES
#define FIBER_PORT_EXC_RETURN_WORD_INDEX fiber_portEXC_RETURN_WORD_INDEX
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES 0u
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_SOFTWARE_FRAME_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_HIGH_FP_SOFTWARE_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 4u

#define fiber_portBASEPRI_SYM "BASEPRI"
#define fiber_portASM_SNAP_BASEPRI_R3      "mrs   r3, " fiber_portBASEPRI_SYM "           \n"
#define fiber_portASM_WRITE_BASEPRI_R0     "msr   " fiber_portBASEPRI_SYM ", r0           \n"
#define fiber_portASM_WRITE_BASEPRI_R2     "msr   " fiber_portBASEPRI_SYM ", r2           \n"
#define fiber_portASM_WRITE_BASEPRI_R3     "msr   " fiber_portBASEPRI_SYM ", r3           \n"

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

#define fiber_portASM_ENTER_SCHEDULER_BASEPRI \
	fiber_portASM_SNAP_BASEPRI_R3 \
	"movs  r2, %[sched_basepri]           \n" \
	"stmdb sp!, {r2, r3}                  \n" \
	fiber_portASM_WRITE_BASEPRI_R2_SYNC

#define fiber_portASM_EXIT_SCHEDULER_BASEPRI \
	"ldmia sp!, {r2, r3}                  \n" \
	fiber_portASM_WRITE_BASEPRI_R3_SYNC

#define fiber_portASM_ENTER_SCHEDULER_CRITICAL fiber_portASM_ENTER_SCHEDULER_BASEPRI
#define fiber_portASM_EXIT_SCHEDULER_CRITICAL fiber_portASM_EXIT_SCHEDULER_BASEPRI

#define fiber_portASM_MSR_PSPLIM(_reg) /* ARMv7-M has no PSPLIM. */

#ifdef __cplusplus
extern "C" {
#endif

fiber_portFORCE_INLINE uint32_t fiber_port_read_r9(void)
{
	uint32_t v;
	fiber_portASM volatile("mov %0, r9" : "=r"(v));
	return v;
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
	fiber_portASM volatile("mrs %0, " fiber_portBASEPRI_SYM : "=r"(value) :: "memory");
	return value;
}

fiber_portFORCE_INLINE void fiber_port_basepri_write(uint32_t value)
{
	fiber_portASM volatile("msr " fiber_portBASEPRI_SYM ", %0" :: "r"(value) : "memory");
	{ __DSB(); __ISB(); }
}

fiber_portFORCE_INLINE uint32_t fiber_port_scheduler_critical_enter(void)
{
	const uint32_t scheduler_basepri = (uint32_t)FIBER_PORT_SCHEDULER_BASEPRI;
	const uint32_t old_basepri = fiber_port_basepri_read();
	fiber_port_basepri_write(scheduler_basepri);
	return old_basepri;
}

fiber_portFORCE_INLINE void fiber_port_scheduler_critical_exit(uint32_t state)
{
	fiber_port_basepri_write(state);
}

fiber_portFORCE_INLINE void fiber_port_fpu_enable_early(void)
{
	/* ARMv7-M has no architectural FPU. */
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

fiber_portFORCE_INLINE uintptr_t fiber_port_vectors_base_addr(void)
{
	uintptr_t value = (uintptr_t)SCB->VTOR;
# if defined(SCB_VTOR_TBLOFF_Msk)
	value &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
# endif
	return value;
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
# if defined(SCB_VTOR_TBLOFF_Msk)
	base &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
# endif
	SCB->VTOR = (uint32_t)base;
	{ __DSB(); __ISB(); }
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARMV7M */
#if FIBER_PORT_ARMV7M
# include "fiber_port_boot.h"
# include "../fiber_port_traits.h"
# include "../fiber_port_geometry.h"
# include "../fiber_feature_policy.h"
#endif

#ifndef FIBER_SVC_START_NUMBER
# define FIBER_SVC_START_NUMBER 70
#endif

#if defined(FIBER_PENDSV_VECTOR_DIRECT) || defined(FIBER_SVC_VECTOR_DIRECT) || \
		defined(FIBER_PENDSV_WIRED) || defined(FIBER_SVC_WIRED)
# error "[fiber]: vector routing macros were removed; the selected port owns strong SVC_Handler and PendSV_Handler symbols"
#endif

#if defined(FIBER_FORCE_PRIGROUP) || defined(FIBER_TUNE_SYSTICK) || \
		defined(FIBER_TUNE_SVCALL)
# error "[fiber]: exception ownership is fixed by the selected port"
#endif

#if defined(FIBER_VALIDATE_EXCEPTION_SETUP) || \
		defined(FIBER_VALIDATE_VECTOR_WIRING) || \
		defined(FIBER_VALIDATE_PENDSV_VECTOR) || \
		defined(FIBER_VALIDATE_SVC_VECTOR) || \
		defined(FIBER_VALIDATE_BASEPRI_PRIORITY_MASK) || \
		defined(FIBER_VALIDATE_PRIORITY_GROUPING) || \
		defined(FIBER_VALIDATE_M7_R0P1_ERRATA_POLICY) || \
		defined(FIBER_VALIDATE_SVC_PRIORITY)
# error "[fiber]: selected-port exception validation is mandatory"
#endif

FIBER_STATIC_ASSERT((FIBER_SVC_START_NUMBER >= 0) &&
		(FIBER_SVC_START_NUMBER <= 255),
		"[fiber]: FIBER_SVC_START_NUMBER must fit in an 8-bit SVC immediate");

#endif /* FIBER_PORT_ARM_CM3_FIBER_PORTMACRO_H_ */
