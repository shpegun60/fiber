#ifndef FIBER_TARGET_FIBER_VTOR_H_
#define FIBER_TARGET_FIBER_VTOR_H_

#include "fiber_diagnostics.h"
#include "fiber_dependency.h"
#include "fiber_settings.h"

/* Detect VTOR presence robustly across CMSIS variations and spotty vendor headers */
#ifndef FIBER_HAS_VTOR
/* 0) User override wins: pass -DFIBER_FORCE_VTOR=0/1 */
# if defined(FIBER_FORCE_VTOR)
#  define FIBER_HAS_VTOR (!!(FIBER_FORCE_VTOR+0))

/* 1) Trust the device header if it states it explicitly */
# elif defined(__VTOR_PRESENT)
#  define FIBER_HAS_VTOR (!!(__VTOR_PRESENT+0))

/* 2) Infer from CMSIS-core masks that only exist when VTOR is available */
# elif defined(SCB_VTOR_TBLOFF_Msk) || defined(SCB_VTOR_TBLOFF_Pos) || defined(SCB_VTOR_TBLOFF)
#  define FIBER_HAS_VTOR 1

/* 3) Architecture defaults (ARM ARM): v7-M / v7E-M / v8-M Mainline always have VTOR */
# elif defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__)
#  define FIBER_HAS_VTOR 1

/* 4) STM32 family hints (vendor reality checks) */
# elif defined(STM32F0)    || defined(STM32F0xx)          /* Cortex-M0: no VTOR */
#  define FIBER_HAS_VTOR 0
# elif defined(STM32G0)    || defined(STM32G0xx) || 	\
		defined(STM32L0)    || defined(STM32L0xx) || 	\
		defined(STM32WB)    || defined(STM32WBxx) || 	\
		defined(STM32WL)    || defined(STM32WLxx) || 	\
		defined(STM32C0)    || defined(STM32C0xx)           /* M0+: VTOR present */
#  define FIBER_HAS_VTOR 1
# elif defined(STM32F1)    || defined(STM32F1xx) || 	\
		defined(STM32F2)    || defined(STM32F2xx) ||	\
		defined(STM32F3)    || defined(STM32F3xx) || 	\
		defined(STM32F4)    || defined(STM32F4xx) || 	\
		defined(STM32F7)    || defined(STM32F7xx) || 	\
		defined(STM32G4)    || defined(STM32G4xx) || 	\
		defined(STM32H5)    || defined(STM32H5xx) || 	\
		defined(STM32H7)    || defined(STM32H7xx) || 	\
		defined(STM32L1)    || defined(STM32L1xx) || 	\
		defined(STM32L4)    || defined(STM32L4xx) || 	\
		defined(STM32L4P)   || defined(STM32L4Pxx)|| 	\
		defined(STM32L5)    || defined(STM32L5xx) || 	\
		defined(STM32U5)    || defined(STM32U5xx)
#  define FIBER_HAS_VTOR 1

/* 5) Conservative fallback:
        v6-M (M0/M0+) and v8-M Baseline (M23) might lack VTOR.
        If your specific chip does have VTOR, pass -DFIBER_FORCE_VTOR=1. */
# else
#  define FIBER_HAS_VTOR 0
# endif
#endif /* FIBER_HAS_VTOR */


/* -------- VTOR selector (current or Non-secure bank) -------------------- */

/* Default: read current bank VTOR; set to 1 to force Non-secure bank from Secure */
#ifndef FIBER_VTOR_USE_NS
#  define FIBER_VTOR_USE_NS 0
#endif

#if FIBER_VTOR_USE_NS
#  if defined(SCB_NS)
#    define FIBER_SCB_VTOR_PTR ((volatile uint32_t *)&SCB_NS->VTOR)
#  else
#    error "[fiber]: SCB_NS is unavailable in this CMSIS; cannot read Non-secure VTOR"
#  endif
#elif FIBER_HAS_VTOR
/* Current bank, works in both Secure and Non-secure */
#  define FIBER_SCB_VTOR_PTR   ((volatile uint32_t *)&SCB->VTOR)
#else
#  define FIBER_SCB_VTOR_PTR   ((volatile uint32_t *)0)
	FIBER_DIAG_WARN("[fiber] Device has no SCB->VTOR; falling back to base table at 0x00000000.")
#endif


/* Return active vector-table base: VTOR (masked to TBLOFF) if present, else 0x00000000. */
__STATIC_FORCEINLINE uintptr_t fiber_vectors_base_addr(void)
{
#if FIBER_VTOR_USE_NS || FIBER_HAS_VTOR
	uintptr_t v = (uintptr_t)(*FIBER_SCB_VTOR_PTR);
# if defined(SCB_VTOR_TBLOFF_Msk)
	/* Keep only the table base (TBLOFF field); low bits are reserved/zero by spec. */
	v &= (uintptr_t)SCB_VTOR_TBLOFF_Msk;
# endif
	return v;
#else
	/* No VTOR on this core/family: vector table is at 0x00000000. */
	return (uintptr_t)0x00000000u;
#endif
}

__STATIC_FORCEINLINE const uint32_t* fiber_vectors_base_ptr(void)
{
	return (const uint32_t*)fiber_vectors_base_addr();
}

/* Read initial MSP from the current vector table (word 0). */
__STATIC_FORCEINLINE uint32_t fiber_read_initial_msp(void)
{
	const uint32_t *vt = (const uint32_t *)fiber_vectors_base_addr();
	/* First word of the vector table is initial MSP per ARM. */
	return vt[0];
}


#endif /* FIBER_TARGET_FIBER_VTOR_H_ */
