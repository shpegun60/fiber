/*
 * fiber_settings.h
 *
 * User policy defaults shared by the STM32/Cortex-M fiber ports.
 *
 * Genuine integration, safety, and performance policy is listed first. CPU
 * facts such as EXC_RETURN encodings, FPCA handling, security-bank selection,
 * and software-frame layout belong to the selected port. A final transitional
 * block exists only for unfinished v8-M ports and is rejected by production
 * ports when it conflicts with their fixed ABI. See FIBER_SETTINGS.md.
 */

#ifndef FIBER_FIBER_SETTINGS_H_
#define FIBER_FIBER_SETTINGS_H_

/* -----------------------------------------------------------------------------
 * FPU
 * ---------------------------------------------------------------------------*/

#ifndef FIBER_ENABLE_CPACR
# define FIBER_ENABLE_CPACR 1   /* 0 requires the application to enable CP10/CP11 before fiber_start(). */
#endif

/* 0 = eager/deterministic stacking, 1 = lazy stacking (LSPEN) if FPU present. */
#ifndef FIBER_FPU_LAZY
# define FIBER_FPU_LAZY 0
#endif

/* -----------------------------------------------------------------------------
 * Main SP
 * ---------------------------------------------------------------------------*/

/* Optionally rewind MSP to the initial top-of-stack from the vector table.
 * On M0/M0+, set this to 0 unless the platform has a reliable initial MSP source. */
#ifndef FIBER_REWIND_MSP
# define FIBER_REWIND_MSP 1
#endif

/* -----------------------------------------------------------------------------
 * Core switch
 * ---------------------------------------------------------------------------*/

#ifndef FIBER_SWITCH_STRICT_BARRIERS
# define FIBER_SWITCH_STRICT_BARRIERS 1  /* add extra DSB/ISB around SP/PSPLIM */
#endif

#ifndef FIBER_SWITCH_MASK_IRQS
# define FIBER_SWITCH_MASK_IRQS 1        /* mask IRQs while pending a scheduler switch */
#endif

/* Current ownership and restore-target checks are always active.
 * Set this to 1 to additionally recompute the sealed FiberBoot hash on every
 * scheduled restore. Leave 0 to use mandatory metadata and structural checks;
 * full hash checks still run during init/start.
 */
#ifndef FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH
# define FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH 0
#endif

/* -----------------------------------------------------------------------------
 * Stack
 * ---------------------------------------------------------------------------*/

#ifndef FIBER_STACK_ALIGN
# define FIBER_STACK_ALIGN 8u
#endif

#ifndef FIBER_STACK_CANARY
# define FIBER_STACK_CANARY 1
#endif

#if (FIBER_STACK_CANARY != 0) && (FIBER_STACK_CANARY != 1)
# error "[fiber]: FIBER_STACK_CANARY must be 0 or 1"
#endif

#if FIBER_STACK_CANARY
# ifndef FIBER_CANARY_VALUE
#  define FIBER_CANARY_VALUE 0xDEADBEEFu
# endif
#endif

/* Restore-target validation is a runtime invariant, not a tuning option.
 * Reject obsolete knobs so an old build cannot appear to disable checks that
 * are now mandatory in the scheduler bridge and SVC path.
 */
#ifdef FIBER_VALIDATE_SCHEDULED_CONTEXT
# error "[fiber]: FIBER_VALIDATE_SCHEDULED_CONTEXT was removed; restore-context validation is mandatory"
#endif

#ifdef FIBER_VALIDATE_CURRENT
# error "[fiber]: FIBER_VALIDATE_CURRENT was removed; runtime current-context ownership is always enforced"
#endif

#ifdef FIBER_EXC_LEVELS_ON_PSP
# error "[fiber]: FIBER_EXC_LEVELS_ON_PSP was removed; nested handlers use MSP and the top guard is fixed"
#endif

/* Safety red zone above the bottom of the stack. Useful with PSPLIM/canaries. */
#ifndef FIBER_STACK_REDZONE_BYTES
# define FIBER_STACK_REDZONE_BYTES 32u
#endif

/*
 * Minimum context area below the top-of-stack reserve. The default is derived
 * from the selected port and covers its software frame, maximum hardware frame,
 * high FP registers when present, and one architectural stack-alignment word.
 * Applications may increase this reserve but may not reduce it.
 */
#ifndef FIBER_BOOT_EXTRA_BYTES
# define FIBER_BOOT_EXTRA_BYTES \
		(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_PER_LEVEL_BYTES + \
		 (FIBER_PORT_HAS_EXTENDED_FP_CONTEXT ? (16u * 4u) : 0u) + 4u)
#endif

/* -----------------------------------------------------------------------------
 * Platform hygiene
 * ---------------------------------------------------------------------------*/

#ifndef FIBER_ENABLE_UNALIGNED_TRAP
# define FIBER_ENABLE_UNALIGNED_TRAP 0
#endif

#ifndef FIBER_ENABLE_DIV0_TRAP
# define FIBER_ENABLE_DIV0_TRAP 1
#endif

/* -----------------------------------------------------------------------------
 * Transitional v8-M bring-up inputs
 *
 * These are not normal application tuning options. Native production ports own
 * the corresponding CPU facts and reject incompatible overrides.
 * ---------------------------------------------------------------------------*/

#ifndef FIBER_FORCE_SAVE_FPU
# define FIBER_FORCE_SAVE_FPU 0
#endif

#ifndef FIBER_VTOR_USE_NS
# define FIBER_VTOR_USE_NS 0
#endif

#ifndef FIBER_RUN_NONSECURE
# define FIBER_RUN_NONSECURE 0
#endif

#ifndef FIBER_INITIAL_EXC_RETURN
# if FIBER_RUN_NONSECURE
#  define FIBER_INITIAL_EXC_RETURN 0xFFFFFFBCu
# else
#  define FIBER_INITIAL_EXC_RETURN 0xFFFFFFFDu
# endif
#endif

#ifndef FIBER_BOOT_CLEAR_FPCA
# define FIBER_BOOT_CLEAR_FPCA 1
#endif

/* -----------------------------------------------------------------------------
 * User-policy validation
 * ---------------------------------------------------------------------------*/

#if (FIBER_ENABLE_CPACR != 0) && (FIBER_ENABLE_CPACR != 1)
# error "[fiber]: FIBER_ENABLE_CPACR must be 0 or 1"
#endif
#if (FIBER_FPU_LAZY != 0) && (FIBER_FPU_LAZY != 1)
# error "[fiber]: FIBER_FPU_LAZY must be 0 or 1"
#endif
#if (FIBER_FORCE_SAVE_FPU != 0) && (FIBER_FORCE_SAVE_FPU != 1)
# error "[fiber]: FIBER_FORCE_SAVE_FPU must be 0 or 1"
#endif
#if (FIBER_VTOR_USE_NS != 0) && (FIBER_VTOR_USE_NS != 1)
# error "[fiber]: FIBER_VTOR_USE_NS must be 0 or 1"
#endif
#if (FIBER_REWIND_MSP != 0) && (FIBER_REWIND_MSP != 1)
# error "[fiber]: FIBER_REWIND_MSP must be 0 or 1"
#endif
#if (FIBER_SWITCH_STRICT_BARRIERS != 0) && (FIBER_SWITCH_STRICT_BARRIERS != 1)
# error "[fiber]: FIBER_SWITCH_STRICT_BARRIERS must be 0 or 1"
#endif
#if (FIBER_SWITCH_MASK_IRQS != 0) && (FIBER_SWITCH_MASK_IRQS != 1)
# error "[fiber]: FIBER_SWITCH_MASK_IRQS must be 0 or 1"
#endif
#if (FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH != 0) && \
		(FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH != 1)
# error "[fiber]: FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH must be 0 or 1"
#endif
#if (FIBER_RUN_NONSECURE != 0) && (FIBER_RUN_NONSECURE != 1)
# error "[fiber]: FIBER_RUN_NONSECURE must be 0 or 1"
#endif
#if (FIBER_BOOT_CLEAR_FPCA != 0) && (FIBER_BOOT_CLEAR_FPCA != 1)
# error "[fiber]: FIBER_BOOT_CLEAR_FPCA must be 0 or 1"
#endif
#if (FIBER_ENABLE_UNALIGNED_TRAP != 0) && (FIBER_ENABLE_UNALIGNED_TRAP != 1)
# error "[fiber]: FIBER_ENABLE_UNALIGNED_TRAP must be 0 or 1"
#endif
#if (FIBER_ENABLE_DIV0_TRAP != 0) && (FIBER_ENABLE_DIV0_TRAP != 1)
# error "[fiber]: FIBER_ENABLE_DIV0_TRAP must be 0 or 1"
#endif

#endif /* FIBER_FIBER_SETTINGS_H_ */
