/*
 * fiber_compiler.h
 *
 *  Created on: Aug 27, 2025
 *      Author: admin
 */

#ifndef FIBER_FIBER_COMPILER_H_
#define FIBER_FIBER_COMPILER_H_

/* Pull compiler/device traits (brings __WEAK, __NO_RETURN, etc.) */
#include "fiber_diagnostics.h"
#include "fiber_dependency.h"

/* ---- Cross-toolchain attribute mapping (STM32 toolchains) ------------------ */
/* Supported: GCC (arm-none-eabi-gcc), Clang/armclang (Keil AC6), ARMCC5 (Keil), IAR (ICCARM) */

/*
 * *****************************************************
 * alignof / alignas
 *
 *  C-only: provide alignas/alignof reliably.
 *  In C++ they are keywords; no header is needed.
 * *****************************************************
 */
#if !defined(__cplusplus)
# if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
  /* Prefer <stdalign.h> if available; otherwise fall back to C11 built-ins. */
#  if defined(__has_include)
#   if __has_include(<stdalign.h>)
#    include <stdalign.h>
#   else
#    ifndef alignas
#     define alignas _Alignas
#    endif
#    ifndef alignof
#     define alignof _Alignof
#    endif
#   endif
#  else
#   include <stdalign.h>
#  endif
# else
#  error "[fiber]: C11 required for alignas/alignof/static_assert. Use -std=c11 or -std=gnu11."
# endif
#endif /* !__cplusplus */

/*
 * *****************************************************
 * FIBER_HAS_ATTR
 *
 *  Attribute feature probe (Clang/GCC/armclang)
 * *****************************************************
 */
#ifndef __has_attribute
# define __has_attribute(x) 0
#endif
#ifndef FIBER_HAS_ATTR
# define FIBER_HAS_ATTR(x) __has_attribute(x)
#endif

/*
 * *****************************************************
 * FIBER_NORETURN / FIBER_WEAK / FIBER_ASM / FIBER_USED
 *
 * Prefer CMSIS-provided macros when present.
 * *****************************************************
 */
#ifndef FIBER_NORETURN
# if defined(__NO_RETURN)
#  define FIBER_NORETURN __NO_RETURN
# elif FIBER_HAS_ATTR(noreturn) || defined(__GNUC__)
#  define FIBER_NORETURN __attribute__((noreturn))
# else
#  define FIBER_NORETURN
# endif
#endif

#ifndef FIBER_WEAK
# if defined(__WEAK)
#  define FIBER_WEAK __WEAK
# elif FIBER_HAS_ATTR(weak) || defined(__GNUC__)
#  define FIBER_WEAK __attribute__((weak))
# else
#  define FIBER_WEAK
# endif
#endif

#ifndef FIBER_ASM
# if defined(__ASM)
#  define FIBER_ASM __ASM
# else
#  define FIBER_ASM __asm
# endif
#endif

#ifndef FIBER_USED
# if defined(__USED)
#  define FIBER_USED __USED
# elif FIBER_HAS_ATTR(used) || defined(__GNUC__)
#  define FIBER_USED __attribute__((used))
# else
#  define FIBER_USED
# endif
#endif

/*
 * *****************************************************
 * FIBER_NOINLINE — "do not inline" on STM32 toolchains
 * *****************************************************
 */
#ifndef FIBER_NOINLINE
# if defined(__ICCARM__)
#  define FIBER_NOINLINE _Pragma("inline=never")
# elif defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
/* ArmClang (Keil AC6) */
#  define FIBER_NOINLINE __attribute__((noinline))
# elif defined(__CC_ARM)
/* ARMCC5 (legacy Keil) */
#  define FIBER_NOINLINE __attribute__((noinline))
# elif defined(__clang__)
#  if FIBER_HAS_ATTR(noinline)
#   define FIBER_NOINLINE __attribute__((noinline))
#  else
#   define FIBER_NOINLINE /* noinline unavailable */
#  endif
# elif defined(__GNUC__)
#  define FIBER_NOINLINE __attribute__((noinline))
# else
#  define FIBER_NOINLINE /* noinline unavailable */
# endif
#endif /* FIBER_NOINLINE */

/* Optional compiler barrier if CMSIS didn’t provide one */
#ifndef __COMPILER_BARRIER
# define __COMPILER_BARRIER() FIBER_ASM volatile("" ::: "memory")
#endif

/*
 * *****************************************************
 * FIBER_NAKED / FIBER_NOINSTR
 *
 * CMSIS does not provide portable macros for these.
 * Map per toolchain; if unavailable, leave empty.
 * *****************************************************
 */
#if defined(__ICCARM__)                 /* IAR EWARM */
# ifndef FIBER_NAKED
#  define FIBER_NAKED __naked
# endif
# ifndef FIBER_NOINSTR
#  define FIBER_NOINSTR
# endif

#elif defined(__CC_ARM) || (defined(__ARMCC_VERSION) && !defined(__clang__)) /* ARMCC5 */
# ifndef FIBER_NAKED
#  define FIBER_NAKED __attribute__((naked))
# endif
# ifndef FIBER_NOINSTR
#  define FIBER_NOINSTR
# endif

#elif defined(__clang__) || defined(__GNUC__)      /* GCC, Clang, ArmClang */
# ifndef FIBER_NAKED
#  define FIBER_NAKED __attribute__((naked))
# endif
# ifndef FIBER_NOINSTR
#  if FIBER_HAS_ATTR(no_instrument_function) || defined(__GNUC__)
#   define FIBER_NOINSTR __attribute__((no_instrument_function))
#  else
#   define FIBER_NOINSTR
#  endif
# endif

#else                                              /* Unknown toolchain */
# ifndef FIBER_NAKED
#  define FIBER_NAKED
# endif
# ifndef FIBER_NOINSTR
#  define FIBER_NOINSTR
# endif
# if defined(__GNUC__) || defined(__clang__)
#  warning "[fiber] FIBER_NAKED/FIBER_NOINSTR are empty on this toolchain"
# endif
#endif

/*
 * *********************************************************************************
 * FIBER_NOSAN — sanitizer-friendly attributes (harmlessly empty on bare-metal)
 * *********************************************************************************
 */
#if FIBER_HAS_ATTR(no_sanitize)
# define FIBER_NOSAN_ALL __attribute__((no_sanitize("address","undefined","thread")))
#else
# define FIBER_NOSAN_ALL
#endif

#if FIBER_HAS_ATTR(no_sanitize_address)
# define FIBER_NOSAN_ADDR __attribute__((no_sanitize_address))
#else
# define FIBER_NOSAN_ADDR
#endif

#if FIBER_HAS_ATTR(no_sanitize_undefined)
# define FIBER_NOSAN_UB __attribute__((no_sanitize_undefined))
#else
# define FIBER_NOSAN_UB
#endif

#if FIBER_HAS_ATTR(no_sanitize_thread)
# define FIBER_NOSAN_TSAN __attribute__((no_sanitize_thread))
#else
# define FIBER_NOSAN_TSAN
#endif

#define FIBER_NOSAN FIBER_NOSAN_ALL FIBER_NOSAN_ADDR FIBER_NOSAN_UB FIBER_NOSAN_TSAN

/*
 * *********************************************************************************
 * FIBER_NOPROF — disable profiling/coverage if supported
 * *********************************************************************************
 */
#if FIBER_HAS_ATTR(no_profile_instrument_function)
# define FIBER_NOPROFILE __attribute__((no_profile_instrument_function))
#else
# define FIBER_NOPROFILE
#endif

#if FIBER_HAS_ATTR(no_sanitize_coverage)
# define FIBER_NOCOVERAGE __attribute__((no_sanitize_coverage))
#else
# define FIBER_NOCOVERAGE
#endif

#define FIBER_NOPROF FIBER_NOPROFILE FIBER_NOCOVERAGE

/*
 * *********************************************************************************
 * FIBER_NOSSP — disable stack protector if available
 * *********************************************************************************
 */
#if FIBER_HAS_ATTR(no_stack_protector)
# define FIBER_NOSSP __attribute__((no_stack_protector))
#else
# define FIBER_NOSSP
#endif

/*
 * *********************************************************************************
 * Attribute bundles
 * *********************************************************************************
 */
#ifndef FIBER_ATTR_KEEP
# define FIBER_ATTR_KEEP \
  FIBER_NOSSP FIBER_NOSAN FIBER_NOPROF
#endif

#ifndef FIBER_ATTR_SENSITIVE
/* Non-naked sensitive routines: keep symbol, avoid inlining/instrumentation/sanitizers/SSP */
# define FIBER_ATTR_SENSITIVE \
  FIBER_NOINSTR FIBER_NOINLINE FIBER_USED FIBER_ATTR_KEEP
#endif

#ifndef FIBER_ATTR_NAKED_ASM
/* Naked ASM trampolines: naked + everything from sensitive */
# define FIBER_ATTR_NAKED_ASM \
  FIBER_NAKED FIBER_ATTR_SENSITIVE
#endif

#endif /* FIBER_FIBER_COMPILER_H_ */
