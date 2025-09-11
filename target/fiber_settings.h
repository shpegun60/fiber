/*
 * fiber_settings.h
 *
 *  Created on: Aug 28, 2025
 *      Author: admin
 */

#ifndef FIBER_FIBER_SETTINGS_H_
#define FIBER_FIBER_SETTINGS_H_

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
# ifndef FIBER_BOOT_EXTRA_BYTES
#  define FIBER_BOOT_EXTRA_BYTES 32u
# endif

/* Control lazy FP stacking in exceptions.
 * 0 = LSPEN off (deterministic), 1 = LSPEN on (potentially lower entry latency).
 * Default: 0, бо ти будуєш детермінічний світ без сюрпризів.
 */
/* Control lazy FPU stacking policy at boot: 0 = off, 1 = on (if FPU present). */
# ifndef FIBER_FPU_LAZY
#  define FIBER_FPU_LAZY 1
# endif

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

//Optionally enable FPU access (CP10/CP11) if an FPU exists and the build may emit FP instructions.
#ifndef FIBER_ENABLE_CPACR
# define FIBER_ENABLE_CPACR 1
#endif



/* -------- VTOR selector (current or Non-secure bank) -------------------- */

/* 0: бери VTOR поточного домену (рекомендовано для трампліна)
   1: з Secure коду насильно лізь у Non-secure VTOR */
#ifndef FIBER_VTOR_USE_NS
#  define FIBER_VTOR_USE_NS 0
#endif



	/* Optionally rewind MSP to initial top-of-stack from vector table */
#ifndef FIBER_REWIND_MSP
#   define FIBER_REWIND_MSP 1
#endif


#endif /* FIBER_FIBER_SETTINGS_H_ */
