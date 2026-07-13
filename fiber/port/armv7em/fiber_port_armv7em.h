/*
 * fiber_port_armv7em.h
 *
 * ARMv7E-M selected port interface.
 */

#ifndef FIBER_PORT_ARMV7EM_FIBER_PORT_ARMV7EM_H_
#define FIBER_PORT_ARMV7EM_FIBER_PORT_ARMV7EM_H_

#include "../fiber_settings.h"
#include "../fiber_compiler.h"
#include "../fiber_port_select.h"
#include "mcu_core.h"
#include "../../fiber_panic.h"

#if FIBER_PORT_ARMV7EM

#if !defined(__CORTEX_M) || (__CORTEX_M != 4)
# error "[fiber]: generic ARMv7E-M port currently supports Cortex-M4/M4F only"
#endif

#ifndef FIBER_PORT_NAME
# define FIBER_PORT_NAME "armv7em"
#endif

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1

#define FIBER_PORT_HAS_VTOR 1
#define FIBER_PORT_HAS_PSPLIM 0

#if defined(FIBER_PORT_TOOLCHAIN_HAS_FP) || \
		defined(FIBER_PORT_SILICON_HAS_FPU) || \
		defined(FIBER_PORT_CMSIS_FPU_USED) || \
		defined(FIBER_PORT_HAS_FPU) || \
		defined(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT)
# error "[fiber]: ARMv7E-M FPU facts are selected-port-owned and must not be predefined"
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
# error "[fiber]: ARMv7E-M CMSIS __FPU_PRESENT must be 0 or 1"
#endif

#if defined(__FPU_USED) && ((__FPU_USED + 0) != 0) && \
		((__FPU_USED + 0) != 1)
# error "[fiber]: ARMv7E-M CMSIS __FPU_USED must be 0 or 1"
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
# error "[fiber]: ARMv7E-M compiler emits FP instructions but CMSIS reports no silicon FPU"
#endif
#if defined(__FPU_USED) && \
		(FIBER_PORT_CMSIS_FPU_USED != FIBER_PORT_TOOLCHAIN_HAS_FP)
# error "[fiber]: ARMv7E-M CMSIS __FPU_USED disagrees with compiler FP code generation"
#endif

#if (FIBER_PORT_SILICON_HAS_FPU == 1) && \
		(FIBER_PORT_TOOLCHAIN_HAS_FP == 1)
# define FIBER_PORT_HAS_FPU 1
# define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 1
#else
# define FIBER_PORT_HAS_FPU 0
# define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#endif

#define FIBER_PORT_STACK_ALIGNMENT 8u
#define FIBER_PORT_BOOT_CLEARS_FPCA FIBER_PORT_HAS_FPU
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN 0xFFFFFFFDu
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_BASEPRI

#ifndef FIBER_PORT_SCHEDULER_BASEPRI
# ifdef FIBER_SCHEDULER_BASEPRI
#  define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI
# else
#  ifndef __NVIC_PRIO_BITS
#   error "[fiber]: __NVIC_PRIO_BITS is required to default ARMv7E-M scheduler BASEPRI"
#  endif
#  define FIBER_PORT_SCHEDULER_BASEPRI (1u << (8u - __NVIC_PRIO_BITS))
# endif
#endif

#ifndef FIBER_SCHEDULER_BASEPRI
# define FIBER_SCHEDULER_BASEPRI FIBER_PORT_SCHEDULER_BASEPRI
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI == 0u
# error "[fiber]: ARMv7E-M scheduler BASEPRI threshold must be non-zero"
#endif

#if FIBER_PORT_SCHEDULER_BASEPRI > 255u
# error "[fiber]: ARMv7E-M scheduler BASEPRI threshold must fit in 8 bits"
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

#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES \
	(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT ? (18u * 4u) : 0u)
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES)

#define FIBER_PORT_SOFTWARE_FRAME_WORDS 9u
#define FIBER_PORT_SOFTWARE_FRAME_BYTES (FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX 8u
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

#define FBR_BASEPRI_SYM "BASEPRI"
#define FBR_ASM_SNAP_BASEPRI_R3      "mrs   r3, " FBR_BASEPRI_SYM "           \n"
#define FBR_ASM_WRITE_BASEPRI_R0     "msr   " FBR_BASEPRI_SYM ", r0           \n"
#define FBR_ASM_WRITE_BASEPRI_R2     "msr   " FBR_BASEPRI_SYM ", r2           \n"
#define FBR_ASM_WRITE_BASEPRI_R3     "msr   " FBR_BASEPRI_SYM ", r3           \n"

#if FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND
# define FBR_ASM_WRITE_BASEPRI_R0_SYNC \
	"mrs   r12, primask                  \n" \
	"cpsid i                              \n" \
	FBR_ASM_WRITE_BASEPRI_R0 \
	"dsb                                  \n" \
	"isb                                  \n" \
	"msr   primask, r12                  \n" \
	"dsb                                  \n" \
	"isb                                  \n"
# define FBR_ASM_WRITE_BASEPRI_R2_SYNC \
	"mrs   r12, primask                  \n" \
	"cpsid i                              \n" \
	FBR_ASM_WRITE_BASEPRI_R2 \
	"dsb                                  \n" \
	"isb                                  \n" \
	"msr   primask, r12                  \n" \
	"dsb                                  \n" \
	"isb                                  \n"
# define FBR_ASM_WRITE_BASEPRI_R3_SYNC \
	"mrs   r12, primask                  \n" \
	"cpsid i                              \n" \
	FBR_ASM_WRITE_BASEPRI_R3 \
	"dsb                                  \n" \
	"isb                                  \n" \
	"msr   primask, r12                  \n" \
	"dsb                                  \n" \
	"isb                                  \n"
#else
# define FBR_ASM_WRITE_BASEPRI_R0_SYNC \
	FBR_ASM_WRITE_BASEPRI_R0 \
	"dsb                                  \n" \
	"isb                                  \n"
# define FBR_ASM_WRITE_BASEPRI_R2_SYNC \
	FBR_ASM_WRITE_BASEPRI_R2 \
	"dsb                                  \n" \
	"isb                                  \n"
# define FBR_ASM_WRITE_BASEPRI_R3_SYNC \
	FBR_ASM_WRITE_BASEPRI_R3 \
	"dsb                                  \n" \
	"isb                                  \n"
#endif

#define FBR_ASM_ENTER_SCHEDULER_BASEPRI \
	FBR_ASM_SNAP_BASEPRI_R3 \
	"movs  r2, %[sched_basepri]           \n" \
	"stmdb sp!, {r2, r3}                  \n" \
	FBR_ASM_WRITE_BASEPRI_R2_SYNC

#define FBR_ASM_EXIT_SCHEDULER_BASEPRI \
	"ldmia sp!, {r2, r3}                  \n" \
	FBR_ASM_WRITE_BASEPRI_R3_SYNC

#define FBR_ASM_ENTER_SCHEDULER_CRITICAL FBR_ASM_ENTER_SCHEDULER_BASEPRI
#define FBR_ASM_EXIT_SCHEDULER_CRITICAL FBR_ASM_EXIT_SCHEDULER_BASEPRI

#define FBR_ASM_MSR_PSPLIM(_reg) /* ARMv7E-M has no PSPLIM. */

#ifdef __cplusplus
extern "C" {
#endif

__STATIC_FORCEINLINE uint32_t fiber_port_read_r9(void)
{
	uint32_t v;
	__ASM volatile("mov %0, r9" : "=r"(v));
	return v;
}

__STATIC_FORCEINLINE uint32_t fiber_port_initial_xpsr(void)
{
	return 0x01000000u;
}

__STATIC_FORCEINLINE uint32_t fiber_port_stacked_pc(uintptr_t entry)
{
	return (uint32_t)(entry & ~(uintptr_t)1u);
}

__STATIC_FORCEINLINE uint32_t fiber_port_basepri_read(void)
{
	uint32_t value;
	__ASM volatile("mrs %0, " FBR_BASEPRI_SYM : "=r"(value) :: "memory");
	return value;
}

__STATIC_FORCEINLINE void fiber_port_basepri_write(uint32_t value)
{
#if FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND
	const uint32_t primask = __get_PRIMASK();
	__disable_irq();
	__ASM volatile("msr " FBR_BASEPRI_SYM ", %0" :: "r"(value) : "memory");
	__DSB();
	__ISB();
	__set_PRIMASK(primask);
	__DSB();
	__ISB();
#else
	__ASM volatile("msr " FBR_BASEPRI_SYM ", %0" :: "r"(value) : "memory");
	{ __DSB(); __ISB(); }
#endif
}

__STATIC_FORCEINLINE uint32_t fiber_port_scheduler_critical_enter(void)
{
	const uint32_t scheduler_basepri = (uint32_t)FIBER_PORT_SCHEDULER_BASEPRI;
	const uint32_t old_basepri = fiber_port_basepri_read();
	fiber_port_basepri_write(scheduler_basepri);
	return old_basepri;
}

__STATIC_FORCEINLINE void fiber_port_scheduler_critical_exit(uint32_t state)
{
	fiber_port_basepri_write(state);
}

__STATIC_FORCEINLINE void fiber_port_fpu_enable_early(void)
{
#if FIBER_PORT_HAS_FPU
# if !defined(FPU) || !defined(FPU_FPCCR_ASPEN_Msk) || \
		!defined(FPU_FPCCR_LSPEN_Msk)
#  error "[fiber]: ARMv7E-M FPU port requires CMSIS FPU/FPCCR definitions"
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
		{ __DSB(); __ISB(); }
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
		{ __DSB(); __ISB(); }
	}
	FIBER_REQUIRE(fpccr_policy_mask != 0u, 'E');
	FIBER_REQUIRE((FPU->FPCCR & fpccr_policy_mask) ==
			(fpccr & fpccr_policy_mask), 'E');
#else
	(void)0;
#endif
}

__STATIC_FORCEINLINE uint32_t fiber_port_psplim_read(void)
{
	return 0u;
}

__STATIC_FORCEINLINE void fiber_port_psplim_write(uint32_t limit)
{
	(void)limit;
}

__STATIC_FORCEINLINE void fiber_port_psplim_config(uint32_t stack_low_addr)
{
	(void)stack_low_addr;
}

__STATIC_FORCEINLINE uintptr_t fiber_port_vectors_base_addr(void)
{
	uintptr_t value = (uintptr_t)SCB->VTOR;
# if defined(SCB_VTOR_TBLOFF_Msk)
	value &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
# endif
	return value;
}

__STATIC_FORCEINLINE const uint32_t *fiber_port_vectors_base_ptr(void)
{
	return (const uint32_t *)fiber_port_vectors_base_addr();
}

__STATIC_FORCEINLINE uint32_t fiber_port_read_initial_msp(void)
{
	const uint32_t *const vectors = fiber_port_vectors_base_ptr();
	return vectors[0];
}

__STATIC_FORCEINLINE void fiber_port_set_vectors_base_addr(uintptr_t base)
{
# if defined(SCB_VTOR_TBLOFF_Msk)
	base &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
# endif
	SCB->VTOR = (uint32_t)base;
	{ __DSB(); __ISB(); }
}

void fiber_port_init_context_frame(FiberContext *ctx);

FIBER_NOINLINE
void fiber_port_require_schedule_environment(void);

FIBER_NOINLINE
void fiber_port_request_schedule(void);

void fiber_exception_runtime_check(void);

void fiber_pendsv_init_lowest_priority(void);

FIBER_NORETURN
void fiber_port_start_first_context(uintptr_t msp_top);

FIBER_ATTR_NAKED_ASM
void fiber_svc(void);

FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARMV7EM */

#endif /* FIBER_PORT_ARMV7EM_FIBER_PORT_ARMV7EM_H_ */
