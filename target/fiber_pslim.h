/*
 * fiber_pslim.h
 *
 *  Created on: Sep 6, 2025
 *      Author: admin
 */

#ifndef FIBER_TOOLS_FIBER_PSLIM_H_
#define FIBER_TOOLS_FIBER_PSLIM_H_

#include "fiber_diagnostics.h"
#include "fiber_dependency.h"

/* --------- PSPLIM feature (compile-time) --------- */
/* Allow user/project override first */
#if !defined(FIBER_HAS_PSPLIM)

  /* Prefer architectural feature macros (toolchain-defined) */
# if defined(__ARM_ARCH_8_1M_MAIN__) || defined(__ARM_ARCH_8M_MAIN__)
#  define FIBER_HAS_PSPLIM 1
# else
#  define FIBER_HAS_PSPLIM 0
# endif

/* Fallback for spotty toolchains: infer from core IDs (CMSIS __CORTEX_M) */
# if (FIBER_HAS_PSPLIM == 0) && defined(__CORTEX_M)
#  if  (__CORTEX_M == 33)  /* Cortex-M33 (v8-M Mainline) */ \
      || (__CORTEX_M == 35)  /* Cortex-M35P (v8-M Mainline) */ \
      || (__CORTEX_M == 52)  /* Cortex-M52 (v8.1-M Mainline) */ \
      || (__CORTEX_M == 55)  /* Cortex-M55 (v8.1-M Mainline) */ \
      || (__CORTEX_M == 85)  /* Cortex-M85 (v8.1-M Mainline) */
#   undef  FIBER_HAS_PSPLIM
#   define FIBER_HAS_PSPLIM 1
#  endif
# endif

#endif /* FIBER_HAS_PSPLIM */


#endif /* FIBER_TOOLS_FIBER_PSLIM_H_ */
