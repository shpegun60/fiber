/*
 * fiber_settings.h
 *
 * Project defaults for the STM32/Cortex-M fiber port.
 * Every option can be overridden by defining it before including fiber headers
 * or by passing -DNAME=value from the build system.
 */

#ifndef FIBER_FIBER_SETTINGS_H_
#define FIBER_FIBER_SETTINGS_H_

/* -----------------------------------------------------------------------------
 * FPU
 * ---------------------------------------------------------------------------*/

#ifndef FIBER_ENABLE_CPACR
# define FIBER_ENABLE_CPACR 1   /* write SCB->CPACR if FIBER_HAS_FPU */
#endif

/* 0 = eager/deterministic stacking, 1 = lazy stacking (LSPEN) if FPU present. */
#ifndef FIBER_FPU_LAZY
# define FIBER_FPU_LAZY 0
#endif

/* Force FP save/restore even when the toolchain does not advertise FP usage. */
#ifndef FIBER_FORCE_SAVE_FPU
# define FIBER_FORCE_SAVE_FPU 0
#endif

/* -----------------------------------------------------------------------------
 * VTOR
 * ---------------------------------------------------------------------------*/

/* 0 = use current-domain VTOR, 1 = target Non-secure VTOR from Secure code. */
#ifndef FIBER_VTOR_USE_NS
# define FIBER_VTOR_USE_NS 0
#endif

/* -----------------------------------------------------------------------------
 * Main SP
 * ---------------------------------------------------------------------------*/

/* Optionally rewind MSP to the initial top-of-stack from the vector table. */
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
# define FIBER_SWITCH_MASK_IRQS 1        /* mask IRQs while publishing switch slots */
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

#ifdef FIBER_STACK_CANARY
# define FIBER_CANARY_VALUE 0xDEADBEEFu
#endif

/* Exception-frame headroom reserved on the process stack. */
#ifndef FIBER_EXC_LEVELS_ON_PSP
# define FIBER_EXC_LEVELS_ON_PSP 1u
#endif

/* Safety red zone above the bottom of the stack. Useful with PSPLIM/canaries. */
#ifndef FIBER_STACK_REDZONE_BYTES
# define FIBER_STACK_REDZONE_BYTES 32u
#endif

/* Small extra margin for tiny prologues or locals when first entering PSP code.
 * 48 = 36 bytes software frame + 4 bytes headroom + 8 bytes alignment.
 */
#ifndef FIBER_BOOT_EXTRA_BYTES
# define FIBER_BOOT_EXTRA_BYTES 48u
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

#endif /* FIBER_FIBER_SETTINGS_H_ */
