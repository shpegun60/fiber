/*
 * fiber_fpu.h
 *
 *  Created on: Sep 6, 2025
 *      Author: admin
 */

#ifndef FIBER_FIBER_FPU_H_
#define FIBER_FIBER_FPU_H_

#include "fiber_diagnostics.h"
#include "fiber_dependency.h"

/* --------- FIBER_HAS_FPU (compile-time) --------- */
/* =========================================================================
 *  Portable compile-time warnings for FPU config mismatches
 *  - Emits a warning if silicon has FPU but compiler won't use it
 *  - Emits a warning if compiler plans FP code but silicon header says no FPU
 *  Toolchains covered: GCC, Clang/armclang, IAR. Others: no-op.
 * ========================================================================= */

/* FPU settings ------------------------------------------------------------*/
#if (__FPU_PRESENT == 1) && (__FPU_USED == 1)

#endif




/* ---- Normalized feature probes ---- */
#ifndef FIBER_TOOLCHAIN_HAS_FP
/* __ARM_FP != 0 means the toolchain may emit VFP/FP instructions.
     __VFP_FP__ is an older/alt macro sometimes defined by vendors. */
# if (defined(__ARM_FP) && ((__ARM_FP + 0) != 0)) || defined(__VFP_FP__)
#  define FIBER_TOOLCHAIN_HAS_FP 1
# else
#  define FIBER_TOOLCHAIN_HAS_FP 0
# endif
#endif

#ifndef FIBER_SILICON_HAS_FPU
/* CMSIS device header should define __FPU_PRESENT to 0 or 1 */
# if defined(__FPU_PRESENT) && (__FPU_PRESENT == 1)
#  define FIBER_SILICON_HAS_FPU 1
# else
#  define FIBER_SILICON_HAS_FPU 0
# endif
#endif

/* --------- FIBER_HAS_FPU (compile-time) --------- */
# ifndef FIBER_HAS_FPU
#  if (FIBER_TOOLCHAIN_HAS_FP == 1) && (FIBER_SILICON_HAS_FPU == 1)
#   define FIBER_HAS_FPU 1
#  else
#   define FIBER_HAS_FPU 0
#  endif
# endif

/* ---- Hint 1: Silicon has FPU, compiler doesn't plan to use it ----
   Typical fix: add -mfpu=... and -mfloat-abi=hard|softfp, or enable FP in project. */
# if (FIBER_SILICON_HAS_FPU == 1) && (FIBER_TOOLCHAIN_HAS_FP == 0)
	FIBER_DIAG_WARN("[fiber] Device has FPU but compiler isn't using it.\n"
			"        Fix: add -mfpu=... and -mfloat-abi=hard|softfp.\n"
			"        Note: FP context will NOT be saved.");
# endif

/* ---- Hint 2: Compiler plans FP code, silicon header says NO FPU ----
   This will fault at runtime on non-FPU silicon. Fix your flags or device header. */
# if (FIBER_TOOLCHAIN_HAS_FP == 1) && (FIBER_SILICON_HAS_FPU == 0)
	FIBER_DIAG_WARN("[fiber] Compiler may emit FP instructions but __FPU_PRESENT==0.\n"
			"        Expect runtime faults on non-FPU silicon.");
# endif

#endif /* FIBER_FIBER_FPU_H_ */
