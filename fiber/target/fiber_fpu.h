/*
 * fiber_fpu.h
 *
 *  Minimal, robust FPU detection and enable helper for Cortex-M.
 *  - No hard build failures; diagnostics are warnings only.
 *  - Final policy flag: FIBER_HAS_FPU (controls FP save/restore in context switch).
 *  - Early enable helper: fiber_fpu_enable_early().
 *
 *  This header assumes CMSIS core is available via "mcu/mcu_core.h".
 *  If not, SCB and barrier intrinsics are accessed via addresses/fallbacks.
 */

#ifndef FIBER_FIBER_FPU_H_
#define FIBER_FIBER_FPU_H_

#include "fiber_diagnostics.h"
#include "fiber_settings.h"
#include "mcu/mcu_core.h"

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
#endif

/* -----------------------------------------------------------------------------
 * Friendly build-time nudges (non-fatal).
 * ---------------------------------------------------------------------------*/
#if (FIBER_SILICON_HAS_FPU == 1) && (FIBER_TOOLCHAIN_HAS_FP == 0) && (FIBER__CMSIS_USED_FLAG == 0)
FIBER_DIAG_WARN("[fiber][FPU] Device has an FPU but the compiler is not using it.\n"
		"               Add -mfpu=... and -mfloat-abi=hard|softfp if you need FP.\n"
		"               Note: FP context will NOT be saved/restored.");
#endif

#if ((FIBER_TOOLCHAIN_HAS_FP == 1) || (FIBER__CMSIS_USED_FLAG == 1)) && (FIBER_SILICON_HAS_FPU == 0)
FIBER_DIAG_WARN("[fiber][FPU] Compiler may emit FP instructions but __FPU_PRESENT==0.\n"
		"               Expect runtime faults on non-FPU silicon.");
#endif

/* -----------------------------------------------------------------------------
 * Early FPU enable helper
 *   Call once at startup (privileged Thread mode) before any FP instruction or
 *   context switch that touches FP regs. Enables CP10/CP11 full access.
 *   Optionally enables lazy stacking (not required for cooperative switch).
 * ---------------------------------------------------------------------------*/
/* Compile-time knobs with sane defaults */
#ifndef FIBER_ENABLE_CPACR
# define FIBER_ENABLE_CPACR 1   /* write SCB->CPACR if FIBER_HAS_FPU */
#endif

#ifndef FIBER_FPU_LAZY
# define FIBER_FPU_LAZY     0   /* 1: enable lazy stacking (LSPEN), 0: eager */
#endif

/* Early FPU gate-up: enable CP10/CP11 and optional lazy stacking.
 * Must run in privileged Thread mode before any FP instruction executes. */
static inline void fiber_fpu_enable_early(void)
{
#if FIBER_HAS_FPU
	/* ---------------- CPACR in current (Secure or Non-secure) world ---------------- */
# if FIBER_ENABLE_CPACR
	/* Optionally enable FPU access (CP10/CP11) if an FPU exists and the build may emit FP instructions.
     Use architectural bit positions instead of vendor-specific masks; do a read-back and only write if needed. */

	/* CP11[23:22]=0b11, CP10[21:20]=0b11 => full access */
	const uint32_t CPACR_CP10_CP11_FULL = (0xFu << 20);

#  ifdef SCB
	/* Secure CPACR (current world): enable only if not already enabled */
	volatile uint32_t cpacr = SCB->CPACR;
	if ((cpacr & CPACR_CP10_CP11_FULL) != CPACR_CP10_CP11_FULL) {
		cpacr = (cpacr & ~CPACR_CP10_CP11_FULL) | CPACR_CP10_CP11_FULL;
		SCB->CPACR = cpacr;                  /* enable CP10/CP11 full access in Secure */
		{ __DSB(); __ISB(); }                /* ensure the change is visible before any FP usage */
		/* paranoid read-back */
		volatile uint32_t cpacr_rb = SCB->CPACR; (void)cpacr_rb;
	}
#  else
	/* Fallback if CMSIS SCB is not visible: write CPACR by address */
	volatile uint32_t* const CPACR = (uint32_t*)0xE000ED88u;

	volatile uint32_t v = *CPACR;
	if ((v & CPACR_CP10_CP11_FULL) != CPACR_CP10_CP11_FULL) {
		*CPACR = (v & ~CPACR_CP10_CP11_FULL) | CPACR_CP10_CP11_FULL;  /* enable CP10/CP11 full access in Secure */
		{ __DSB(); __ISB(); }                /* make CP enablement effective before any FP op */
		/* paranoid read-back */
		volatile uint32_t v_rb = *CPACR; (void)v_rb;
	}
#  endif
# endif /* FIBER_ENABLE_CPACR */

	/* ---------------- TrustZone permissions (Secure build only) ---------------- */
# if defined(__ARM_ARCH_8M_MAIN__) && defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)

	/* 1) Allow NS world to access FP (NSACR). CP10 and CP11 are single permission bits. */
#  if defined(SCB_NSACR_CP10_Pos) && defined(SCB_NSACR_CP11_Pos)
	/* Set both CP10 and CP11 bits to 1 (allow NS FP access) */
	const uint32_t NSACR_CP10_CP11_FULL = (1u << SCB_NSACR_CP10_Pos) | (1u << SCB_NSACR_CP11_Pos);
#  else
	/* Fallback to architectural positions: CP10=bit10, CP11=bit11 */
	const uint32_t NSACR_CP10_CP11_FULL = (3u << 10);
#  endif

#  ifdef SCB
	volatile uint32_t nsacr = SCB->NSACR;
	if ((nsacr & NSACR_CP10_CP11_FULL) != NSACR_CP10_CP11_FULL) {
		nsacr |= NSACR_CP10_CP11_FULL;       /* RMW to avoid touching other bits */
		SCB->NSACR = nsacr;
		{ __DSB(); __ISB(); }                /* serialize before touching NS CPACR */
		/* paranoid read-back */
		volatile uint32_t nsacr_rb = SCB->NSACR; (void)nsacr_rb;
	}
#  endif

	/* 2) Program Non-secure CPACR via Secure alias (if provided by CMSIS). */
#  ifdef SCB_NS
	volatile uint32_t nscpacr = SCB_NS->CPACR;
	if ((nscpacr & CPACR_CP10_CP11_FULL) != CPACR_CP10_CP11_FULL) {
		nscpacr = (nscpacr & ~CPACR_CP10_CP11_FULL) | CPACR_CP10_CP11_FULL;
		SCB_NS->CPACR = nscpacr;             /* enable CP10/CP11 full access in Non-secure */
		{ __DSB(); __ISB(); }                /* make effective before NS code runs FP */
		/* paranoid read-back */
		volatile uint32_t nscpacr_rb = SCB_NS->CPACR; (void)nscpacr_rb;
	}
#  endif
# endif /* TrustZone secure build */

	/* ---------------- FPCCR lazy/eager stacking policy ---------------- */
# ifdef FPU
	/* Read-modify-write FPCCR; do not touch unrelated bits. */
	volatile uint32_t fpccr = FPU->FPCCR;

#  ifdef FPU_FPCCR_ASPEN_Msk
	fpccr |= FPU_FPCCR_ASPEN_Msk;          /* enable automatic FP context management */
#  endif /* FPU_FPCCR_ASPEN_Msk */

#  ifdef FPU_FPCCR_LSPEN_Msk
#   if FIBER_FPU_LAZY
	fpccr |= FPU_FPCCR_LSPEN_Msk;          /* enable lazy FP context stacking */
#   else
	fpccr &= ~FPU_FPCCR_LSPEN_Msk;         /* disable lazy stacking (eager) */
#   endif /* FIBER_FPU_LAZY */
#  endif /* FPU_FPCCR_LSPEN_Msk */

	if (fpccr != FPU->FPCCR) {
		FPU->FPCCR = fpccr;
		{ __DSB(); __ISB(); }
		/* paranoid read-back */
		volatile uint32_t fpccr_rb = FPU->FPCCR; (void)fpccr_rb;
	}
# endif /* FPU */
#else
	(void)0; /* No FPU on this silicon; nothing to do. */
#endif /* FIBER_HAS_FPU */
}


#endif /* FIBER_FIBER_FPU_H_ */
