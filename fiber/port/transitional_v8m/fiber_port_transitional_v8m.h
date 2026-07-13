/*
 * fiber_port_transitional_v8m.h
 *
 * Transitional selected-port interface for v8-M profiles that do not yet have
 * concrete FreeRTOS-style port sources.
 */

#ifndef FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORT_TRANSITIONAL_V8M_H_
#define FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORT_TRANSITIONAL_V8M_H_

#include "../fiber_settings.h"
#include "../fiber_compiler.h"
#include "../fiber_port_select.h"
#include "mcu_core.h"
#include "../../fiber_panic.h"

#if FIBER_PORT_ARMV8M_BASELINE || FIBER_PORT_ARMV8M_MAINLINE || FIBER_PORT_ARMV81M_MAINLINE

#ifndef FIBER_PORT_NAME
# define FIBER_PORT_NAME "transitional_v8m"
#endif

#define FIBER_PORT_HAS_BASEPRI (FIBER_PORT_IS_MAINLINE ? 1 : 0)
#define FIBER_PORT_HAS_FAULTMASK FIBER_PORT_IS_MAINLINE

#ifndef FIBER_PORT_HAS_VTOR
# if FIBER_PORT_IS_MAINLINE
#  define FIBER_PORT_HAS_VTOR 1
# elif defined(SCB_VTOR_TBLOFF_Msk) || \
		(defined(__VTOR_PRESENT) && ((__VTOR_PRESENT + 0) != 0))
#  define FIBER_PORT_HAS_VTOR 1
# else
#  define FIBER_PORT_HAS_VTOR 0
# endif
#endif

#ifndef FIBER_TRANSITIONAL_V8M_RUN_NONSECURE
# define FIBER_TRANSITIONAL_V8M_RUN_NONSECURE 0
#endif

#ifndef FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK
# if defined(FIBER_TZ_NS) && ((FIBER_TZ_NS + 0) != 0)
#  define FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK 1
# else
#  define FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK 0
# endif
#endif

#if (FIBER_TRANSITIONAL_V8M_RUN_NONSECURE != 0) && \
		(FIBER_TRANSITIONAL_V8M_RUN_NONSECURE != 1)
# error "[fiber]: FIBER_TRANSITIONAL_V8M_RUN_NONSECURE must be 0 or 1"
#endif

#if (FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK != 0) && \
		(FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK != 1)
# error "[fiber]: FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK must be 0 or 1"
#endif

#if FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK
# if defined(__ARM_FEATURE_CMSE) && ((__ARM_FEATURE_CMSE + 0) >= 3)
#  define FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK_VALIDATED 1
# else
#  define FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK_VALIDATED 0
#  error "[fiber]: targeting the Non-secure register bank requires a Secure CMSE level 3 build"
# endif
#else
# define FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK_VALIDATED 0
#endif

#if !FIBER_PORT_HAS_VTOR && !FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK_VALIDATED
FIBER_DIAG_WARN("[fiber] Selected transitional v8-M port has no SCB->VTOR; falling back to base table at 0x00000000.")
#endif

#if FIBER_PORT_ARMV8M_MAINLINE || FIBER_PORT_ARMV81M_MAINLINE
# define FIBER_PORT_HAS_PSPLIM 1
#else
# define FIBER_PORT_HAS_PSPLIM 0
#endif

#if defined(FIBER_PORT_TOOLCHAIN_HAS_FP) || \
		defined(FIBER_PORT_SILICON_HAS_FPU) || \
		defined(FIBER_PORT_CMSIS_FPU_USED) || \
		defined(FIBER_PORT_HAS_FPU) || \
		defined(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT)
# error "[fiber]: transitional v8-M FPU facts are selected-port-owned and must not be predefined"
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
# error "[fiber]: transitional v8-M CMSIS __FPU_PRESENT must be 0 or 1"
#endif

#if defined(__FPU_USED) && ((__FPU_USED + 0) != 0) && \
		((__FPU_USED + 0) != 1)
# error "[fiber]: transitional v8-M CMSIS __FPU_USED must be 0 or 1"
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
# error "[fiber]: transitional v8-M compiler emits FP instructions but CMSIS reports no silicon FPU"
#endif
#if defined(__FPU_USED) && \
		(FIBER_PORT_CMSIS_FPU_USED != FIBER_PORT_TOOLCHAIN_HAS_FP)
# error "[fiber]: transitional v8-M CMSIS __FPU_USED disagrees with compiler FP code generation"
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

#if defined(__ARM_FEATURE_MVE) && ((__ARM_FEATURE_MVE + 0) > 0)
# define FIBER_PORT_HAS_MVE 1
#else
# define FIBER_PORT_HAS_MVE 0
#endif

#ifndef FIBER_PORT_HAS_PAC
# if defined(__ARM_FEATURE_PAC_DEFAULT) || defined(__ARM_FEATURE_PAUTH) || \
		defined(__ARM_FEATURE_PAUTH_DEFAULT)
#  define FIBER_PORT_HAS_PAC 1
# else
#  define FIBER_PORT_HAS_PAC 0
# endif
#endif

#ifndef FIBER_PORT_HAS_BTI
# if defined(__ARM_FEATURE_BTI_DEFAULT) || defined(__ARM_FEATURE_BTI)
#  define FIBER_PORT_HAS_BTI 1
# else
#  define FIBER_PORT_HAS_BTI 0
# endif
#endif

#ifndef FIBER_PORT_USES_PSPLIM_REGISTER
# if FIBER_PORT_HAS_PSPLIM
#  define FIBER_PORT_USES_PSPLIM_REGISTER 1
# else
#  define FIBER_PORT_USES_PSPLIM_REGISTER 0
# endif
#endif

#if FIBER_TRANSITIONAL_V8M_RUN_NONSECURE
# define FIBER_PORT_INITIAL_EXC_RETURN 0xFFFFFFBCu
#else
# define FIBER_PORT_INITIAL_EXC_RETURN 0xFFFFFFFDu
#endif
#define FIBER_PORT_SCHEDULER_MASK_KIND \
	(FIBER_PORT_IS_BASELINE ? FIBER_PORT_MASK_PRIMASK : FIBER_PORT_MASK_BASEPRI)

#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
# ifndef FIBER_PORT_SCHEDULER_BASEPRI
#  ifdef FIBER_SCHEDULER_BASEPRI
#   define FIBER_PORT_SCHEDULER_BASEPRI FIBER_SCHEDULER_BASEPRI
#  else
#   ifndef __NVIC_PRIO_BITS
#    error "[fiber]: __NVIC_PRIO_BITS is required to default v8-M scheduler BASEPRI"
#   endif
#   define FIBER_PORT_SCHEDULER_BASEPRI (1u << (8u - __NVIC_PRIO_BITS))
#  endif
# endif
# ifndef FIBER_SCHEDULER_BASEPRI
#  define FIBER_SCHEDULER_BASEPRI FIBER_PORT_SCHEDULER_BASEPRI
# endif
# if FIBER_PORT_SCHEDULER_BASEPRI == 0u
#  error "[fiber]: v8-M scheduler BASEPRI threshold must be non-zero"
# endif
# if FIBER_PORT_SCHEDULER_BASEPRI > 255u
#  error "[fiber]: v8-M scheduler BASEPRI threshold must fit in 8 bits"
# endif
#else
# ifndef FIBER_SCHEDULER_BASEPRI
#  define FIBER_SCHEDULER_BASEPRI 0u
# endif
#endif

#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0
#ifndef FIBER_PORT_IS_V8M
# define FIBER_PORT_IS_V8M 1
#endif

#ifndef FIBER_PORT_HAS_SECURITY_EXT
# if defined(__ARM_FEATURE_CMSE) && ((__ARM_FEATURE_CMSE + 0) >= 3)
#  define FIBER_PORT_HAS_SECURITY_EXT 1
# else
#  define FIBER_PORT_HAS_SECURITY_EXT 0
# endif
#endif

#define FIBER_PORT_RUNS_NONSECURE FIBER_TRANSITIONAL_V8M_RUN_NONSECURE

#define FIBER_PORT_TARGETS_NS_BANK FIBER_TRANSITIONAL_V8M_TARGET_NS_BANK_VALIDATED

#define FIBER_PORT_HAS_CONTROL_SLOT 0
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0

/* Immutable seal identity. This fixture remains fail-closed until a concrete
 * v8-M selected port replaces it. */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x56384D54u
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

#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES \
	(FIBER_PORT_HAS_EXTENDED_FP_CONTEXT ? (18u * 4u) : 0u)
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES)

#define FIBER_PORT_SOFTWARE_FRAME_WORDS 9u
#define FIBER_PORT_SOFTWARE_FRAME_BYTES (FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX (FIBER_PORT_IS_BASELINE ? 0u : 8u)
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

#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
# if FIBER_PORT_HAS_SECURITY_EXT && FIBER_PORT_TARGETS_NS_BANK
#  define FBR_BASEPRI_SYM "BASEPRI_NS"
# else
#  define FBR_BASEPRI_SYM "BASEPRI"
# endif

# define FBR_ASM_SNAP_BASEPRI_R3      "mrs   r3, " FBR_BASEPRI_SYM "           \n"
# define FBR_ASM_WRITE_BASEPRI_R0     "msr   " FBR_BASEPRI_SYM ", r0           \n"
# define FBR_ASM_WRITE_BASEPRI_R2     "msr   " FBR_BASEPRI_SYM ", r2           \n"
# define FBR_ASM_WRITE_BASEPRI_R3     "msr   " FBR_BASEPRI_SYM ", r3           \n"

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

# define FBR_ASM_ENTER_SCHEDULER_BASEPRI \
	FBR_ASM_SNAP_BASEPRI_R3 \
	"movs  r2, %[sched_basepri]           \n" \
	"stmdb sp!, {r2, r3}                  \n" \
	FBR_ASM_WRITE_BASEPRI_R2_SYNC

# define FBR_ASM_EXIT_SCHEDULER_BASEPRI \
	"ldmia sp!, {r2, r3}                  \n" \
	FBR_ASM_WRITE_BASEPRI_R3_SYNC

# define FBR_ASM_ENTER_SCHEDULER_CRITICAL FBR_ASM_ENTER_SCHEDULER_BASEPRI
# define FBR_ASM_EXIT_SCHEDULER_CRITICAL FBR_ASM_EXIT_SCHEDULER_BASEPRI
#else
# define FBR_ASM_ENTER_SCHEDULER_CRITICAL \
	"mrs   r3, primask                    \n" \
	"cpsid i                              \n" \
	"dsb                                  \n" \
	"isb                                  \n" \
	"push  {r2, r3}                       \n"

# define FBR_ASM_EXIT_SCHEDULER_CRITICAL \
	"pop   {r2, r3}                       \n" \
	"msr   primask, r3                    \n" \
	"dsb                                  \n" \
	"isb                                  \n"

# define FBR_ASM_ENTER_SCHEDULER_BASEPRI FBR_ASM_ENTER_SCHEDULER_CRITICAL
# define FBR_ASM_EXIT_SCHEDULER_BASEPRI FBR_ASM_EXIT_SCHEDULER_CRITICAL
#endif

#ifndef FBR_PSPLIM_SYM
# if FIBER_PORT_USES_PSPLIM_REGISTER
#  if FIBER_PORT_HAS_SECURITY_EXT && FIBER_PORT_TARGETS_NS_BANK
#   define FBR_PSPLIM_SYM "psplim_ns"
#  else
#   define FBR_PSPLIM_SYM "psplim"
#  endif
# endif
#endif

#ifndef FBR_ASM_MSR_PSPLIM
# if FIBER_PORT_USES_PSPLIM_REGISTER
#  define FBR_ASM_MSR_PSPLIM(_reg) "msr   " FBR_PSPLIM_SYM ", " _reg " \n"
# else
#  define FBR_ASM_MSR_PSPLIM(_reg) /* selected v8-M port does not use PSPLIM */
# endif
#endif

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

__STATIC_FORCEINLINE uint32_t fiber_transitional_v8m_primask_save_disable(void)
{
	uint32_t primask;
	__ASM volatile(
			"mrs %0, primask \n"
			"cpsid i         \n"
			: "=r"(primask)
			:
			: "memory");
	{ __DSB(); __ISB(); }
	return primask;
}

__STATIC_FORCEINLINE void fiber_transitional_v8m_primask_restore(uint32_t primask)
{
	{ __DSB(); __ISB(); }
	__ASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	{ __DSB(); __ISB(); }
}

__STATIC_FORCEINLINE uint32_t fiber_port_basepri_read(void)
{
#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
	uint32_t value;
	__ASM volatile("mrs %0, " FBR_BASEPRI_SYM : "=r"(value) :: "memory");
	return value;
#else
	return 0u;
#endif
}

__STATIC_FORCEINLINE void fiber_port_basepri_write(uint32_t value)
{
#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
	__ASM volatile("msr " FBR_BASEPRI_SYM ", %0" :: "r"(value) : "memory");
	{ __DSB(); __ISB(); }
#else
	(void)value;
#endif
}

__STATIC_FORCEINLINE uint32_t fiber_port_scheduler_critical_enter(void)
{
#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
	const uint32_t scheduler_basepri = (uint32_t)FIBER_PORT_SCHEDULER_BASEPRI;
	const uint32_t old_basepri = fiber_port_basepri_read();
	fiber_port_basepri_write(scheduler_basepri);
	return old_basepri;
#else
	return fiber_transitional_v8m_primask_save_disable();
#endif
}

__STATIC_FORCEINLINE void fiber_port_scheduler_critical_exit(uint32_t state)
{
#if FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_BASEPRI
	fiber_port_basepri_write(state);
#else
	fiber_transitional_v8m_primask_restore(state);
#endif
}

__STATIC_FORCEINLINE void fiber_port_fpu_enable_early(void)
{
#if FIBER_PORT_HAS_FPU
# if !defined(FPU) || !defined(FPU_FPCCR_ASPEN_Msk) || \
		!defined(FPU_FPCCR_LSPEN_Msk)
#  error "[fiber]: transitional v8-M FPU path requires CMSIS FPU/FPCCR definitions"
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

# if defined(__ARM_ARCH_8M_MAIN__) && defined(__ARM_FEATURE_CMSE) && \
		(__ARM_FEATURE_CMSE == 3U)
#  if defined(SCB_NSACR_CP10_Pos) && defined(SCB_NSACR_CP11_Pos)
	const uint32_t nsacr_cp10_cp11_full =
		(1u << SCB_NSACR_CP10_Pos) | (1u << SCB_NSACR_CP11_Pos);
#  else
	const uint32_t nsacr_cp10_cp11_full = (3u << 10);
#  endif

#  ifdef SCB
	volatile uint32_t nsacr = SCB->NSACR;
	if ((nsacr & nsacr_cp10_cp11_full) != nsacr_cp10_cp11_full) {
		nsacr |= nsacr_cp10_cp11_full;
		SCB->NSACR = nsacr;
		{ __DSB(); __ISB(); }
	}
	FIBER_REQUIRE((SCB->NSACR & nsacr_cp10_cp11_full) ==
			nsacr_cp10_cp11_full, 'e');
#  endif

#  ifdef SCB_NS
	volatile uint32_t nscpacr = SCB_NS->CPACR;
	if ((nscpacr & cpacr_cp10_cp11_full) != cpacr_cp10_cp11_full) {
		nscpacr = (nscpacr & ~cpacr_cp10_cp11_full) | cpacr_cp10_cp11_full;
		SCB_NS->CPACR = nscpacr;
		{ __DSB(); __ISB(); }
	}
	FIBER_REQUIRE((SCB_NS->CPACR & cpacr_cp10_cp11_full) ==
			cpacr_cp10_cp11_full, 'e');
#  endif
# endif

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
#if FIBER_PORT_USES_PSPLIM_REGISTER
	uint32_t value;
	__ASM volatile("mrs %0, " FBR_PSPLIM_SYM : "=r"(value) :: "memory");
	return value;
#else
	return 0u;
#endif
}

__STATIC_FORCEINLINE void fiber_port_psplim_write(uint32_t limit)
{
#if FIBER_PORT_USES_PSPLIM_REGISTER
	__ASM volatile("msr " FBR_PSPLIM_SYM ", %0" :: "r"(limit) : "memory");
	{ __DSB(); __ISB(); }
#else
	(void)limit;
#endif
}

__STATIC_FORCEINLINE void fiber_port_psplim_config(uint32_t stack_low_addr)
{
#if FIBER_PORT_USES_PSPLIM_REGISTER
	const uint32_t current = fiber_port_psplim_read();
	if (current != stack_low_addr) {
		fiber_port_psplim_write(stack_low_addr);
		volatile uint32_t readback = fiber_port_psplim_read();
		(void)readback;
	}
#else
	(void)stack_low_addr;
#endif
}

__STATIC_FORCEINLINE uintptr_t fiber_port_vectors_base_addr(void)
{
#if FIBER_PORT_TARGETS_NS_BANK
# ifdef SCB_NS
	uintptr_t value = (uintptr_t)SCB_NS->VTOR;
#  if defined(SCB_VTOR_TBLOFF_Msk)
	value &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
#  endif
	return value;
# else
#  error "[fiber]: SCB_NS is unavailable; transitional v8-M port cannot read Non-secure VTOR"
# endif
#elif FIBER_PORT_HAS_VTOR
	uintptr_t value = (uintptr_t)SCB->VTOR;
# if defined(SCB_VTOR_TBLOFF_Msk)
	value &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
# endif
	return value;
#else
	return (uintptr_t)0x00000000u;
#endif
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
#if FIBER_PORT_TARGETS_NS_BANK
# ifdef SCB_NS
#  if defined(SCB_VTOR_TBLOFF_Msk)
	base &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
#  endif
	SCB_NS->VTOR = (uint32_t)base;
	{ __DSB(); __ISB(); }
# else
#  error "[fiber]: SCB_NS is unavailable; transitional v8-M port cannot write Non-secure VTOR"
# endif
#elif FIBER_PORT_HAS_VTOR
# if defined(SCB_VTOR_TBLOFF_Msk)
	base &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
# endif
	SCB->VTOR = (uint32_t)base;
	{ __DSB(); __ISB(); }
#else
	(void)base;
#endif
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

#endif /* FIBER_PORT_ARMV8M_BASELINE || FIBER_PORT_ARMV8M_MAINLINE || FIBER_PORT_ARMV81M_MAINLINE */

#endif /* FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORT_TRANSITIONAL_V8M_H_ */
