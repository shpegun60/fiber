/*
 * fiber_port_armv7m.h
 *
 * ARMv7-M selected port interface.
 */

#ifndef FIBER_PORT_ARMV7M_FIBER_PORT_ARMV7M_H_
#define FIBER_PORT_ARMV7M_FIBER_PORT_ARMV7M_H_

#include "../fiber_settings.h"
#include "../fiber_compiler.h"
#include "../fiber_port_select.h"
#include "mcu_core.h"
#include "../../fiber_types.h"

#if FIBER_PORT_ARMV7M

#ifndef FIBER_PORT_NAME
# define FIBER_PORT_NAME "armv7m"
#endif

#define FIBER_PORT_HAS_BASEPRI 1
#define FIBER_PORT_HAS_FAULTMASK 1

#define FIBER_PORT_HAS_VTOR 1

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

#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES 0u
#define FIBER_PORT_EXC_PER_LEVEL_BYTES \
	(FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES)

#define FIBER_PORT_SOFTWARE_FRAME_WORDS 9u
#define FIBER_PORT_SOFTWARE_FRAME_BYTES (FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX 8u
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES 0u
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

#define FBR_ASM_WRITE_BASEPRI_R0_SYNC \
	FBR_ASM_WRITE_BASEPRI_R0 \
	"dsb                                  \n" \
	"isb                                  \n"

#define FBR_ASM_WRITE_BASEPRI_R2_SYNC \
	FBR_ASM_WRITE_BASEPRI_R2 \
	"dsb                                  \n" \
	"isb                                  \n"

#define FBR_ASM_WRITE_BASEPRI_R3_SYNC \
	FBR_ASM_WRITE_BASEPRI_R3 \
	"dsb                                  \n" \
	"isb                                  \n"

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

#define FBR_ASM_MSR_PSPLIM(_reg) /* ARMv7-M has no PSPLIM. */

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
	__ASM volatile("msr " FBR_BASEPRI_SYM ", %0" :: "r"(value) : "memory");
	{ __DSB(); __ISB(); }
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
	/* ARMv7-M has no architectural FPU. */
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

__STATIC_FORCEINLINE void fiber_port_pend_switch(void)
{
	SCB->ICSR = SCB_ICSR_PENDSVSET_Msk;
	__DSB();
	__ISB();
}

void fiber_port_init_context_frame(FiberContext *ctx);

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

#endif /* FIBER_PORT_ARMV7M */

#endif /* FIBER_PORT_ARMV7M_FIBER_PORT_ARMV7M_H_ */
