/*
 * fiber_pslim.h
 *
 *  PSPLIM feature detection and minimal helpers for Cortex-M v8/v8.1 Mainline.
 *  - FIBER_HAS_PSPLIM: compile-time flag (1 if PSPLIM is available)
 *  - Helpers to read/write PSPLIM with CMSIS intrinsics or ASM fallback
 *
 *  Notes:
 *    - PSPLIM defines the lower bound for the Process Stack Pointer (PSP).
 *      On downward-growing stacks, set PSPLIM to the lowest valid stack address.
 *    - Access requires v8-M Mainline or newer cores (e.g. M33/M35P/M55/M85).
 *    - Registers are banked by Security state; helpers act on the current state.
 */

#ifndef FIBER_TOOLS_FIBER_PSLIM_H_
#define FIBER_TOOLS_FIBER_PSLIM_H_

#include "fiber_diagnostics.h"
#include "mcu_core.h"

/* --------- PSPLIM feature (compile-time) ---------------------------------- */
/* Allow user/project override first */
#if !defined(FIBER_HAS_PSPLIM)

/* Prefer architectural feature macros (toolchain-defined) */
# if defined(__ARM_ARCH_8_1M_MAIN__) || defined(__ARM_ARCH_8M_MAIN__)
#  define FIBER_HAS_PSPLIM 1
# else
#  define FIBER_HAS_PSPLIM 0
# endif

/* Fallback for spotty toolchains: infer from CMSIS __CORTEX_M IDs */
# if (FIBER_HAS_PSPLIM == 0) && defined(__CORTEX_M)
#  if  (__CORTEX_M == 33)  /* Cortex-M33 (v8-M Mainline) 	*/      \
		|| (__CORTEX_M == 35)  /* Cortex-M35P (v8-M Mainline) 	*/		\
		|| (__CORTEX_M == 52)  /* Cortex-M52  (v8.1-M Mainline) */   	\
		|| (__CORTEX_M == 55)  /* Cortex-M55  (v8.1-M Mainline) */   	\
		|| (__CORTEX_M == 85)  /* Cortex-M85  (v8.1-M Mainline) */
#   undef  FIBER_HAS_PSPLIM
#   define FIBER_HAS_PSPLIM 1
#  endif
# endif

#endif /* FIBER_HAS_PSPLIM */

/* --------- PSPLIM access helpers ------------------------------------------ */
/* Use CMSIS intrinsics when available; otherwise use minimal inline-ASM.
 * These helpers act only when FIBER_HAS_PSPLIM==1. On older cores they compile
 * to stubs to avoid illegal instruction faults at runtime.
 */

#if FIBER_HAS_PSPLIM

/* Read PSPLIM (current Security state). */
__STATIC_FORCEINLINE uint32_t fiber_get_psplim(void)
{
	/* Prefer CMSIS intrinsic if present (core_cm33.h / core_cm85.h etc.) */
#  if defined(__ASM)
	return __get_PSPLIM();
#  else
	uint32_t v;
	__asm volatile ("mrs %0, psplim" : "=r"(v));
	return v;
#  endif
}

/* Write PSPLIM (current Security state). Call in privileged Thread mode. */
__STATIC_FORCEINLINE void fiber_set_psplim(uint32_t limit)
{
#  if defined(__ASM)
	__set_PSPLIM(limit);
#  else
	__asm volatile ("msr psplim, %0" :: "r"(limit) : "memory");
#  endif
	/* Serialize so the new limit is effective before subsequent stacking. */
	{ __DSB(); __ISB(); }
}

/* Convenience: configure PSPLIM for a downward-growing stack.
 * Pass the lowest valid address of the PSP stack region.
 */
__STATIC_FORCEINLINE void fiber_psplim_config(uint32_t stack_low_addr)
{
	/* RMW-like semantics: write only if different, then barrier. */
	uint32_t cur = fiber_get_psplim();
	if (cur != stack_low_addr) {
		fiber_set_psplim(stack_low_addr);
		/* Read-back to calm down nervous toolchains and humans alike. */
		volatile uint32_t rb = fiber_get_psplim(); (void)rb;
	}
}
#endif /* FIBER_HAS_PSPLIM */

/* ---------- PSPLIM symbol alias for TrustZone (optional) ---------- */
/* Define FIBER_TZ_NS=1 for non-secure builds to target psplim_ns */
#ifndef FBR_PSPLIM_SYM
# if FIBER_HAS_PSPLIM
#  if defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE >= 3) && defined(FIBER_TZ_NS)
#   define FBR_PSPLIM_SYM "psplim_ns"
#  else
#   define FBR_PSPLIM_SYM "psplim"
#  endif
# endif
#endif

/* ---------- Inline ASM helpers ---------- */
#ifndef FBR_ASM_MSR_PSPLIM
# if FIBER_HAS_PSPLIM
#  define FBR_ASM_MSR_PSPLIM(_reg)  "msr   " FBR_PSPLIM_SYM ", " _reg " \n"
# else
#  define FBR_ASM_MSR_PSPLIM(_reg)  /* no-op */
# endif
#endif

#endif /* FIBER_TOOLS_FIBER_PSLIM_H_ */
