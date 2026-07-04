/*
 * fiber_fpu.h
 *
 *  Minimal, robust FPU detection and enable helper for Cortex-M.
 *  - No hard build failures; diagnostics are warnings only.
 *  - Final policy flag: FIBER_HAS_FPU (controls FP save/restore in context switch).
 *  - Early enable helper: fiber_fpu_enable_early().
 *
 *  This header assumes CMSIS core is available via "mcu_core.h".
 *  If not, SCB and barrier intrinsics are accessed via addresses/fallbacks.
 */

#ifndef FIBER_FIBER_FPU_H_
#define FIBER_FIBER_FPU_H_

#include "fiber_diagnostics.h"
#include "fiber_settings.h"
#include "mcu_core.h"

/* -----------------------------------------------------------------------------
 * Toolchain FP capability probe
 *   Modern compilers define __ARM_FP != 0 when FP instructions may be emitted.
 *   Some older/alt toolchains define __VFP_FP__.
 * ---------------------------------------------------------------------------*/
#ifndef FIBER_TOOLCHAIN_HAS_FP
# if (defined(__ARM_FP) && ((__ARM_FP + 0) != 0)) || defined(__VFP_FP__)
#  define FIBER_TOOLCHAIN_HAS_FP 1
# else
#  define FIBER_TOOLCHAIN_HAS_FP 0
# endif
#endif

/* -----------------------------------------------------------------------------
 * Silicon FPU capability probe (CMSIS device header)
 *   __FPU_PRESENT must be 0 or 1. Treat anything else as "no FPU".
 * ---------------------------------------------------------------------------*/
#ifndef FIBER_SILICON_HAS_FPU
# if defined(__FPU_PRESENT) && (__FPU_PRESENT == 1)
#  define FIBER_SILICON_HAS_FPU 1
# else
#  define FIBER_SILICON_HAS_FPU 0
# endif
#endif

/* -----------------------------------------------------------------------------
 * Optional hard override: force FP save/restore even if toolchain says "no".
 *   Use when you absolutely want to save S16..S31/FPSCR on FPU silicon,
 *   regardless of softfp flags or odd pack definitions.
 * ---------------------------------------------------------------------------*/
#ifndef FIBER_FORCE_SAVE_FPU
# define FIBER_FORCE_SAVE_FPU 0
#endif

/* -----------------------------------------------------------------------------
 * Consider CMSIS __FPU_USED if present as an additional "toolchain says FP" hint.
 *   Some packs leave it undefined; some set it to 0 in softfp even when FP regs
 *   might appear. We treat it as an OR with the primary toolchain signal.
 * ---------------------------------------------------------------------------*/
#if defined(__FPU_USED)
# define FIBER__CMSIS_USED_FLAG ((__FPU_USED + 0) == 1)
#else
# define FIBER__CMSIS_USED_FLAG 0
#endif

/* -----------------------------------------------------------------------------
 * Final policy: should context switch save/restore FP regs?
 *   YES if:
 *     - silicon advertises an FPU, and
 *     - toolchain may emit FP instructions (or CMSIS claims FPU is used),
 *   OR if explicitly forced by FIBER_FORCE_SAVE_FPU.
 * ---------------------------------------------------------------------------*/
#ifndef FIBER_HAS_FPU
# if FIBER_FORCE_SAVE_FPU
#  define FIBER_HAS_FPU 1
# else
#  if (FIBER_SILICON_HAS_FPU == 1) && ( (FIBER_TOOLCHAIN_HAS_FP == 1) || (FIBER__CMSIS_USED_FLAG == 1) )
#   define FIBER_HAS_FPU 1
#  else
#   define FIBER_HAS_FPU 0
#  endif
# endif
#endif

/* -----------------------------------------------------------------------------
 * Provide a sane __FPU_USED if vendor pack forgot it.
 *   This avoids downstream headers branching on an undefined macro.
 * ---------------------------------------------------------------------------*/
#ifndef __FPU_USED
# if (FIBER_HAS_FPU == 1)
#  define __FPU_USED 1U
# else
#  define __FPU_USED 0U
# endif
#endif /* __FPU_USED */

/* Early FPU gate-up: enable CP10/CP11 and optional lazy stacking.
 * Must run in privileged Thread mode before any FP instruction executes. */
void fiber_fpu_enable_early(void);


#endif /* FIBER_FIBER_FPU_H_ */
