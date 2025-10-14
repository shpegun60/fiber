/*
 * fiber_settings.h
 *
 *  Created on: Aug 28, 2025
 *      Author: admin
 */

#ifndef FIBER_FIBER_SETTINGS_H_
#define FIBER_FIBER_SETTINGS_H_


/* -----------------------------------------------------------------------------
 * FPU
 * ---------------------------------------------------------------------------*/

//Optionally enable FPU access (CP10/CP11) if an FPU exists and the build may emit FP instructions.
#ifndef FIBER_ENABLE_CPACR
# define FIBER_ENABLE_CPACR 1   /* write SCB->CPACR if FIBER_HAS_FPU */
#endif

/* Control lazy FP stacking in exceptions.
 * 0 = LSPEN off (deterministic), 1 = LSPEN on (potentially lower entry latency).
 * Default: 0, бо ти будуєш детермінічний світ без сюрпризів.
 */
/* Control lazy FPU stacking policy at boot: 0 = off, 1 = on (if FPU present). */
/* 1: enable lazy stacking (LSPEN), 0: eager */

#ifndef FIBER_FPU_LAZY
# define FIBER_FPU_LAZY     1   /* 1: enable lazy stacking (LSPEN), 0: eager */
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
 * VTOR
 * ---------------------------------------------------------------------------*/
/* 0) User override wins: pass -DFIBER_FORCE_VTOR=0/1 */
//# if !defined(FIBER_FORCE_VTOR)
//#  define FIBER_FORCE_VTOR 1
//#endif

/* -------- VTOR selector (current or Non-secure bank) -------------------- */

/* 0: бери VTOR поточного домену (рекомендовано для трампліна)
   1: з Secure коду насильно лізь у Non-secure VTOR */
#ifndef FIBER_VTOR_USE_NS
#  define FIBER_VTOR_USE_NS 0
#endif


/* -----------------------------------------------------------------------------
 * Main-SP
 * ---------------------------------------------------------------------------*/
/* Optionally rewind MSP to initial top-of-stack from vector table */
#ifndef FIBER_REWIND_MSP
#   define FIBER_REWIND_MSP 1
#endif


/* -----------------------------------------------------------------------------
 * CORE
 * ---------------------------------------------------------------------------*/
#ifndef FIBER_SWITCH_STRICT_BARRIERS
#  define FIBER_SWITCH_STRICT_BARRIERS 1  /* 1: add extra DSBs around SP/PSPLIM */
#endif




/* -----------------------------------------------------------------------------
 * OTHER
 * ---------------------------------------------------------------------------*/

/* Public stack alignment rule (AAPCS): 8-byte */
#ifndef FIBER_STACK_ALIGN
# define FIBER_STACK_ALIGN 8u  /* з settings.h; >=8 */
#endif


#ifndef FIBER_STACK_CANARY
#  define FIBER_STACK_CANARY 1
#endif

/* Optional stack canary debugging (enable by defining FIBER_STACK_CANARY) */
#ifdef FIBER_STACK_CANARY
#  define FIBER_CANARY_VALUE 0xDEADBEEFu
#endif


/* Мінімально потрібний розмір: редзона + 1 рівень exception frame на PSP + буфер старту */
#ifndef FIBER_EXC_LEVELS_ON_PSP
# define FIBER_EXC_LEVELS_ON_PSP 1u
#endif

/* --------------------------------------------------------------------------
 * Configuration defaults (override in fiber_settings.h if needed)
 * -------------------------------------------------------------------------- */

/* Safety red zone above the bottom of the stack (useful with PSPLIM/canaries). */
# ifndef FIBER_STACK_REDZONE_BYTES
#  define FIBER_STACK_REDZONE_BYTES 32u
# endif

/* Small extra margin for tiny prologues or locals when first entering PSP code. */
/* 48 = 36 (r4..r11 + lr) + 4 bytes headroom + 8 bytes align */
#ifndef FIBER_BOOT_EXTRA_BYTES
#  define FIBER_BOOT_EXTRA_BYTES 48u
#endif



/* Platform hygiene toggles */
#ifndef FIBER_ENABLE_UNALIGNED_TRAP
# define FIBER_ENABLE_UNALIGNED_TRAP 0
#endif
#ifndef FIBER_ENABLE_DIV0_TRAP
# define FIBER_ENABLE_DIV0_TRAP 1
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* ---- Defaults (if not in settings) ---------------------------------------- */
////////////////////////////////////////////////////////////////////////////////////////////////////////////






#endif /* FIBER_FIBER_SETTINGS_H_ */
