/*
 * fiber_basepri.h
 *
 *  Created on: Oct 9, 2025
 *      Author: admin
 */

#ifndef MCU_FIBER_TARGET_FIBER_BASEPRI_H_
#define MCU_FIBER_TARGET_FIBER_BASEPRI_H_

#include "mcu_core.h"

/* --------------------------------------------------------------------------
 * Scheduler critical-section policy for handler-side scheduler calls.
 *
 * BASEPRI is not part of FiberContext. It is a temporary handler-mode critical
 * section around the scheduler bridge, matching the FreeRTOS port discipline.
 * Cores without BASEPRI use PRIMASK around the scheduler bridge, matching the
 * FreeRTOS Cortex-M0-style PendSV discipline.
 *
 * Define FIBER_TZ_NS=1 in Secure builds that must target the Non-secure
 * BASEPRI bank on v8-M Mainline. On cores without BASEPRI (M0/M0+, M23) these
 * helpers never emit MRS/MSR BASEPRI.
 * -------------------------------------------------------------------------- */
#ifndef FIBER_HAS_BASEPRI
# if defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_8M_BASE__) \
		|| (defined(__CORTEX_M) && (__CORTEX_M == 23))
#  define FIBER_HAS_BASEPRI 0
# else
#  define FIBER_HAS_BASEPRI 1
# endif
#endif

#ifndef FIBER_SCHEDULER_BASEPRI
# if FIBER_HAS_BASEPRI
#  ifndef __NVIC_PRIO_BITS
#   error "[fiber]: __NVIC_PRIO_BITS is required to default FIBER_SCHEDULER_BASEPRI"
#  endif
/*
 * Highest non-zero hardware priority threshold. Priority 0 remains unmasked;
 * scheduler-aware ISR APIs must run at numerically lower urgency than this
 * threshold. Applications may override this to match their NVIC policy.
 */
#  define FIBER_SCHEDULER_BASEPRI (1u << (8u - __NVIC_PRIO_BITS))
# else
#  define FIBER_SCHEDULER_BASEPRI 0u
# endif
#endif

#if FIBER_HAS_BASEPRI && (FIBER_SCHEDULER_BASEPRI == 0u)
# error "[fiber]: FIBER_SCHEDULER_BASEPRI must be non-zero on BASEPRI-capable ports"
#endif

#if FIBER_HAS_BASEPRI && (FIBER_SCHEDULER_BASEPRI > 255u)
# error "[fiber]: FIBER_SCHEDULER_BASEPRI must fit in an 8-bit BASEPRI value"
#endif

#ifndef FIBER_CORTEX_M7_R0P1_ERRATA_837070
# define FIBER_CORTEX_M7_R0P1_ERRATA_837070 0
#endif

#if FIBER_CORTEX_M7_R0P1_ERRATA_837070
# if !defined(__CORTEX_M) || (__CORTEX_M != 7)
#  error "[fiber]: FIBER_CORTEX_M7_R0P1_ERRATA_837070 is only valid for Cortex-M7"
# endif
# if !FIBER_HAS_BASEPRI
#  error "[fiber]: Cortex-M7 r0p1 errata workaround requires BASEPRI support"
# endif
#endif

/* TrustZone-aware BASEPRI register spelling. */
#if defined(__ARM_ARCH_8M_MAIN__) && FIBER_HAS_BASEPRI
# if defined(FIBER_TZ_NS) && (FIBER_TZ_NS+0)
#  define FBR_BASEPRI_SYM "BASEPRI_NS"
# else
#  define FBR_BASEPRI_SYM "BASEPRI"
# endif
#endif

#if FIBER_HAS_BASEPRI && !defined(FBR_BASEPRI_SYM)
# define FBR_BASEPRI_SYM "BASEPRI"
#endif

#if FIBER_HAS_BASEPRI
# define FBR_ASM_SNAP_BASEPRI_R3      "mrs   r3, " FBR_BASEPRI_SYM "           \n"
# define FBR_ASM_WRITE_BASEPRI_R2     "msr   " FBR_BASEPRI_SYM ", r2           \n"
# define FBR_ASM_WRITE_BASEPRI_R3     "msr   " FBR_BASEPRI_SYM ", r3           \n"

# if FIBER_CORTEX_M7_R0P1_ERRATA_837070
#  define FBR_ASM_RAISE_SCHEDULER_BASEPRI \
	"cpsid i                              \n" \
	FBR_ASM_WRITE_BASEPRI_R2 \
	"dsb                                  \n" \
	"isb                                  \n" \
	"cpsie i                              \n"
# else
#  define FBR_ASM_RAISE_SCHEDULER_BASEPRI \
	FBR_ASM_WRITE_BASEPRI_R2 \
	"dsb                                  \n" \
	"isb                                  \n"
# endif

# define FBR_ASM_ENTER_SCHEDULER_BASEPRI \
	FBR_ASM_SNAP_BASEPRI_R3 \
	"movs  r2, %[sched_basepri]           \n" \
	"stmdb sp!, {r2, r3}                  \n" \
	FBR_ASM_RAISE_SCHEDULER_BASEPRI

# define FBR_ASM_EXIT_SCHEDULER_BASEPRI \
	"ldmia sp!, {r2, r3}                  \n" \
	FBR_ASM_WRITE_BASEPRI_R3 \
	"dsb                                  \n" \
	"isb                                  \n"

# define FBR_ASM_ENTER_SCHEDULER_CRITICAL FBR_ASM_ENTER_SCHEDULER_BASEPRI
# define FBR_ASM_EXIT_SCHEDULER_CRITICAL  FBR_ASM_EXIT_SCHEDULER_BASEPRI
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
# define FBR_ASM_EXIT_SCHEDULER_BASEPRI  FBR_ASM_EXIT_SCHEDULER_CRITICAL
#endif


#endif /* MCU_FIBER_TARGET_FIBER_BASEPRI_H_ */
