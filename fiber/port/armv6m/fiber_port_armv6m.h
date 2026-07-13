/*
 * fiber_port_armv6m.h
 *
 * ARMv6-M selected port interface.
 */

#ifndef FIBER_PORT_ARMV6M_FIBER_PORT_ARMV6M_H_
#define FIBER_PORT_ARMV6M_FIBER_PORT_ARMV6M_H_

#include "../fiber_settings.h"
#include "../fiber_compiler.h"
#include "../fiber_port_select.h"
#include "mcu_core.h"

#if FIBER_PORT_ARMV6M

#ifndef FIBER_PORT_NAME
# define FIBER_PORT_NAME "armv6m"
#endif

#define FIBER_PORT_HAS_BASEPRI 0
#define FIBER_PORT_HAS_FAULTMASK 0

#ifndef FIBER_PORT_HAS_VTOR
# if defined(SCB_VTOR_TBLOFF_Msk) || \
		(defined(__VTOR_PRESENT) && ((__VTOR_PRESENT + 0) != 0))
#  define FIBER_PORT_HAS_VTOR 1
# else
#  define FIBER_PORT_HAS_VTOR 0
# endif
#endif

#if !FIBER_PORT_HAS_VTOR
FIBER_DIAG_WARN("[fiber] Selected ARMv6-M port has no SCB->VTOR; falling back to base table at 0x00000000.")
#endif

#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_TOOLCHAIN_HAS_FP 0
#define FIBER_PORT_SILICON_HAS_FPU 0
#define FIBER_PORT_CMSIS_FPU_USED 0
#define FIBER_PORT_HAS_FPU 0
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#define FIBER_PORT_STACK_ALIGNMENT 8u
#define FIBER_PORT_BOOT_CLEARS_FPCA 0
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN 0xFFFFFFFDu
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_PRIMASK
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
#define FIBER_PORT_EXC_FP_EXT_BYTES 0u
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES)

#define FIBER_PORT_SOFTWARE_FRAME_WORDS 9u
#define FIBER_PORT_SOFTWARE_FRAME_BYTES (FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX 0u
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES 0u
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_SOFTWARE_FRAME_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_HIGH_FP_SOFTWARE_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 4u

#ifndef FIBER_SCHEDULER_BASEPRI
# define FIBER_SCHEDULER_BASEPRI 0u
#endif

#define FBR_ASM_ENTER_SCHEDULER_CRITICAL \
	"mrs   r3, primask                    \n" \
	"cpsid i                              \n" \
	"dsb                                  \n" \
	"isb                                  \n" \
	"push  {r2, r3}                       \n"

#define FBR_ASM_EXIT_SCHEDULER_CRITICAL \
	"pop   {r2, r3}                       \n" \
	"msr   primask, r3                    \n" \
	"dsb                                  \n" \
	"isb                                  \n"

#define FBR_ASM_ENTER_SCHEDULER_BASEPRI FBR_ASM_ENTER_SCHEDULER_CRITICAL
#define FBR_ASM_EXIT_SCHEDULER_BASEPRI FBR_ASM_EXIT_SCHEDULER_CRITICAL

#define FBR_ASM_MSR_PSPLIM(_reg) /* ARMv6-M has no PSPLIM. */

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

__STATIC_FORCEINLINE uint32_t fiber_armv6m_primask_save_disable(void)
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

__STATIC_FORCEINLINE void fiber_armv6m_primask_restore(uint32_t primask)
{
	{ __DSB(); __ISB(); }
	__ASM volatile("msr primask, %0" :: "r"(primask) : "memory");
	{ __DSB(); __ISB(); }
}

__STATIC_FORCEINLINE uint32_t fiber_port_basepri_read(void)
{
	return 0u;
}

__STATIC_FORCEINLINE void fiber_port_basepri_write(uint32_t state)
{
	(void)state;
}

__STATIC_FORCEINLINE uint32_t fiber_port_scheduler_critical_enter(void)
{
	return fiber_armv6m_primask_save_disable();
}

__STATIC_FORCEINLINE void fiber_port_scheduler_critical_exit(uint32_t state)
{
	fiber_armv6m_primask_restore(state);
}

__STATIC_FORCEINLINE void fiber_port_fpu_enable_early(void)
{
	/* ARMv6-M has no architectural FPU. */
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
#if FIBER_PORT_HAS_VTOR
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
#if FIBER_PORT_HAS_VTOR
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

#endif /* FIBER_PORT_ARMV6M */

#endif /* FIBER_PORT_ARMV6M_FIBER_PORT_ARMV6M_H_ */
