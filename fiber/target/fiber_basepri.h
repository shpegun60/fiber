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
 * BASEPRI aliasing for TrustZone and absence-safe snapshots
 *  - Define FIBER_TZ_NS=1 for Non-secure builds on v8-M Mainline.
 *  - On cores without BASEPRI (M0/M0+, M23) we never emit MRS/MSR BASEPRI.
 * -------------------------------------------------------------------------- */
#ifndef FIBER_HAS_BASEPRI
# if defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_8M_BASE__) \
		|| (defined(__CORTEX_M) && (__CORTEX_M == 23))
#  define FIBER_HAS_BASEPRI 0
# else
#  define FIBER_HAS_BASEPRI 1
# endif
#endif


/* TrustZone-aware BASEPRI aliases */
#if defined(__ARM_ARCH_8M_MAIN__) && FIBER_HAS_BASEPRI
# if defined(FIBER_TZ_NS) && (FIBER_TZ_NS+0)
#  define FBR_BASEPRI_SYM "BASEPRI_NS"
# else
#  define FBR_BASEPRI_SYM "BASEPRI"
# endif
#endif

#ifndef FBR_ASM_SNAP_BASEPRI
# if FIBER_HAS_BASEPRI
#  if defined(FBR_BASEPRI_SYM)
#   define FBR_ASM_SNAP_BASEPRI     "mrs   r3,  " FBR_BASEPRI_SYM "   \n"
#   define FBR_ASM_RESTORE_BASEPRI  "msr   " FBR_BASEPRI_SYM ", r3    \n"
#  else
#   define FBR_ASM_SNAP_BASEPRI     "mrs   r3,  BASEPRI          \n"
#   define FBR_ASM_RESTORE_BASEPRI  /*"msr   BASEPRI, r3           \n"*/
#  endif
# else
#  define FBR_ASM_SNAP_BASEPRI      "movs  r3,  #0               \n"  /* pad slot */
#  define FBR_ASM_RESTORE_BASEPRI   /* no-op */
# endif
#endif


#endif /* MCU_FIBER_TARGET_FIBER_BASEPRI_H_ */
