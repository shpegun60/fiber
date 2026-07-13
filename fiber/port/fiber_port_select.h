/*
 * fiber_port_select.h
 *
 * Deterministic Cortex-M port selection and architecture feature gates.
 */

#ifndef FIBER_FIBER_PORT_SELECT_H_
#define FIBER_FIBER_PORT_SELECT_H_

#include "fiber_static_assert.h"

/*
 * FreeRTOS-style explicit profile selection. AUTO keeps the small-library
 * convenience path and derives the profile from compiler-provided
 * __ARM_ARCH_* macros. Production integrations may define FIBER_PORT_PROFILE
 * to one of the named values below.
 *
 * A build-system selected mode is also available through
 * FIBER_PORT_BUILD_SELECTED=1. In that mode the build defines exactly one
 * FIBER_PORT_ARMV* result macro directly and includes only the matching port
 * source group, closer to the FreeRTOS include-path/source-selection model.
 * This header still validates and normalizes the selection while v2 migrates
 * toward fully selected portmacro headers.
 *
 * Selection is intentionally strict:
 * - users select profiles with FIBER_PORT_PROFILE, not the internal
 *   FIBER_PORT_* result macros;
 * - explicit profiles are checked against compiler architecture macros when
 *   those macros are available;
 * - ambiguous or conflicting inputs fail at compile time.
 */
#define FIBER_PORT_PROFILE_AUTO             0
#define FIBER_PORT_PROFILE_ARMV6M           1
#define FIBER_PORT_PROFILE_ARMV7M           2
#define FIBER_PORT_PROFILE_ARMV7EM          3
#define FIBER_PORT_PROFILE_ARMV8M_BASELINE  4
#define FIBER_PORT_PROFILE_ARMV8M_MAINLINE  5
#define FIBER_PORT_PROFILE_ARMV81M_MAINLINE 6

#ifndef FIBER_PORT_MASK_PRIMASK
# define FIBER_PORT_MASK_PRIMASK 1
#endif

#ifndef FIBER_PORT_MASK_BASEPRI
# define FIBER_PORT_MASK_BASEPRI 2
#endif

#ifndef FIBER_PORT_BUILD_SELECTED
# define FIBER_PORT_BUILD_SELECTED 0
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_BUILD_SELECTED == 0) || (FIBER_PORT_BUILD_SELECTED == 1),
                 "[fiber]: FIBER_PORT_BUILD_SELECTED must be 0 or 1");

#ifndef FIBER_PORT_PROFILE
# define FIBER_PORT_PROFILE FIBER_PORT_PROFILE_AUTO
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_AUTO) ||
                 (FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV6M) ||
                 (FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV7M) ||
                 (FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV7EM) ||
                 (FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV8M_BASELINE) ||
                 (FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV8M_MAINLINE) ||
                 (FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV81M_MAINLINE),
                 "[fiber]: unsupported FIBER_PORT_PROFILE");

#define FIBER_PORT_PROFILE_IS_EXPLICIT \
    (FIBER_PORT_PROFILE != FIBER_PORT_PROFILE_AUTO)

FIBER_STATIC_ASSERT((FIBER_PORT_PROFILE_IS_EXPLICIT == 0) || (FIBER_PORT_PROFILE_IS_EXPLICIT == 1),
                 "[fiber]: FIBER_PORT_PROFILE_IS_EXPLICIT must be 0 or 1");

FIBER_STATIC_ASSERT((FIBER_PORT_BUILD_SELECTED == 0) || (FIBER_PORT_PROFILE_IS_EXPLICIT == 0),
                 "[fiber]: build-selected port mode must not also use FIBER_PORT_PROFILE");

/*
 * Compiler detection layer.
 *
 * These macros are normalized to 0/1 before any selection logic uses them.
 * ARMv8.1-M handling is deliberately conservative: some GCC configurations for
 * Cortex-M55 report __ARM_ARCH_8M_MAIN__ while enabling MVE through
 * __ARM_FEATURE_MVE. MVE is treated as ARMv8.1-M selection input, because MVE
 * changes the context-policy question even if the architecture macro is weak.
 */
#ifndef FIBER_PORT_DETECTED_ARMV6M
# if defined(__ARM_ARCH_6M__)
#  define FIBER_PORT_DETECTED_ARMV6M 1
# else
#  define FIBER_PORT_DETECTED_ARMV6M 0
# endif
#endif

#ifndef FIBER_PORT_DETECTED_ARMV7M
# if defined(__ARM_ARCH_7M__)
#  define FIBER_PORT_DETECTED_ARMV7M 1
# else
#  define FIBER_PORT_DETECTED_ARMV7M 0
# endif
#endif

#ifndef FIBER_PORT_DETECTED_ARMV7EM
# if defined(__ARM_ARCH_7EM__)
#  define FIBER_PORT_DETECTED_ARMV7EM 1
# else
#  define FIBER_PORT_DETECTED_ARMV7EM 0
# endif
#endif

#ifndef FIBER_PORT_DETECTED_ARMV8M_BASELINE
# if defined(__ARM_ARCH_8M_BASE__)
#  define FIBER_PORT_DETECTED_ARMV8M_BASELINE 1
# else
#  define FIBER_PORT_DETECTED_ARMV8M_BASELINE 0
# endif
#endif

#ifndef FIBER_PORT_DETECTED_ARMV8M_MAINLINE
/* ARMv8.1-M is a mainline superset. If MVE is enabled, detect v8.1-M. */
# if defined(__ARM_ARCH_8M_MAIN__) && \
     !defined(__ARM_ARCH_8_1M_MAIN__) && \
     !(defined(__ARM_FEATURE_MVE) && (__ARM_FEATURE_MVE > 0))
#  define FIBER_PORT_DETECTED_ARMV8M_MAINLINE 1
# else
#  define FIBER_PORT_DETECTED_ARMV8M_MAINLINE 0
# endif
#endif

#ifndef FIBER_PORT_DETECTED_ARMV81M_MAINLINE
# if defined(__ARM_ARCH_8_1M_MAIN__) || \
     (defined(__ARM_FEATURE_MVE) && (__ARM_FEATURE_MVE > 0))
#  define FIBER_PORT_DETECTED_ARMV81M_MAINLINE 1
# else
#  define FIBER_PORT_DETECTED_ARMV81M_MAINLINE 0
# endif
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_DETECTED_ARMV6M == 0) || (FIBER_PORT_DETECTED_ARMV6M == 1),
                 "[fiber]: FIBER_PORT_DETECTED_ARMV6M must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_DETECTED_ARMV7M == 0) || (FIBER_PORT_DETECTED_ARMV7M == 1),
                 "[fiber]: FIBER_PORT_DETECTED_ARMV7M must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_DETECTED_ARMV7EM == 0) || (FIBER_PORT_DETECTED_ARMV7EM == 1),
                 "[fiber]: FIBER_PORT_DETECTED_ARMV7EM must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_DETECTED_ARMV8M_BASELINE == 0) || (FIBER_PORT_DETECTED_ARMV8M_BASELINE == 1),
                 "[fiber]: FIBER_PORT_DETECTED_ARMV8M_BASELINE must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_DETECTED_ARMV8M_MAINLINE == 0) || (FIBER_PORT_DETECTED_ARMV8M_MAINLINE == 1),
                 "[fiber]: FIBER_PORT_DETECTED_ARMV8M_MAINLINE must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_DETECTED_ARMV81M_MAINLINE == 0) || (FIBER_PORT_DETECTED_ARMV81M_MAINLINE == 1),
                 "[fiber]: FIBER_PORT_DETECTED_ARMV81M_MAINLINE must be 0 or 1");

#define FIBER_PORT_DETECTED_COUNT \
    (FIBER_PORT_DETECTED_ARMV6M + \
     FIBER_PORT_DETECTED_ARMV7M + \
     FIBER_PORT_DETECTED_ARMV7EM + \
     FIBER_PORT_DETECTED_ARMV8M_BASELINE + \
     FIBER_PORT_DETECTED_ARMV8M_MAINLINE + \
     FIBER_PORT_DETECTED_ARMV81M_MAINLINE)

FIBER_STATIC_ASSERT(FIBER_PORT_DETECTED_COUNT <= 1,
                 "[fiber]: conflicting compiler ARM architecture macros");

/*
 * Mismatch escape hatch.
 *
 * Normal builds should never need this. It exists for nonstandard toolchains or
 * bring-up experiments where compiler architecture macros are missing or known
 * to be wrong. The older FIBER_PORT_PROFILE_ALLOW_MISMATCH name is kept as a
 * compatibility alias, but new code should use FIBER_PORT_SELECTION_ALLOW_MISMATCH.
 */
#ifndef FIBER_PORT_PROFILE_ALLOW_MISMATCH
# define FIBER_PORT_PROFILE_ALLOW_MISMATCH 0
#endif

#ifndef FIBER_PORT_SELECTION_ALLOW_MISMATCH
# define FIBER_PORT_SELECTION_ALLOW_MISMATCH FIBER_PORT_PROFILE_ALLOW_MISMATCH
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_PROFILE_ALLOW_MISMATCH == 0) || (FIBER_PORT_PROFILE_ALLOW_MISMATCH == 1),
                 "[fiber]: FIBER_PORT_PROFILE_ALLOW_MISMATCH must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_SELECTION_ALLOW_MISMATCH == 0) || (FIBER_PORT_SELECTION_ALLOW_MISMATCH == 1),
                 "[fiber]: FIBER_PORT_SELECTION_ALLOW_MISMATCH must be 0 or 1");

#define FIBER_PORT_PROFILE_MATCHES_DETECTED \
    ((FIBER_PORT_PROFILE_IS_EXPLICIT == 0) || \
     (FIBER_PORT_DETECTED_COUNT == 0) || \
     ((FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV6M) && FIBER_PORT_DETECTED_ARMV6M) || \
     ((FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV7M) && FIBER_PORT_DETECTED_ARMV7M) || \
     ((FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV7EM) && FIBER_PORT_DETECTED_ARMV7EM) || \
     ((FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV8M_BASELINE) && FIBER_PORT_DETECTED_ARMV8M_BASELINE) || \
     ((FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV8M_MAINLINE) && FIBER_PORT_DETECTED_ARMV8M_MAINLINE) || \
     ((FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV81M_MAINLINE) && FIBER_PORT_DETECTED_ARMV81M_MAINLINE))

FIBER_STATIC_ASSERT((FIBER_PORT_SELECTION_ALLOW_MISMATCH != 0) || FIBER_PORT_PROFILE_MATCHES_DETECTED,
                 "[fiber]: FIBER_PORT_PROFILE conflicts with compiler __ARM_ARCH_* macros");

/*
 * Internal result macros are normally generated by this header.
 *
 * In the default selector-driven mode, application builds must not predefine
 * FIBER_PORT_ARMV*. A direct override would bypass profile validation and make
 * the selected port harder to audit.
 *
 * In FIBER_PORT_BUILD_SELECTED mode, the build is the selector and must define
 * exactly one FIBER_PORT_ARMV* macro. This mirrors the FreeRTOS production
 * model where the build chooses one portmacro.h and one source group.
 *
 * Use FIBER_PORT_PROFILE for normal explicit selection, or FIBER_FORCE_PORT_*
 * only for legacy/unusual toolchain cases.
 */
#ifdef FIBER_PORT_ARMV6M
# define FIBER_PORT_PRESET_ARMV6M 1
#else
# define FIBER_PORT_PRESET_ARMV6M 0
#endif

#ifdef FIBER_PORT_ARMV7M
# define FIBER_PORT_PRESET_ARMV7M 1
#else
# define FIBER_PORT_PRESET_ARMV7M 0
#endif

#ifdef FIBER_PORT_ARMV7EM
# define FIBER_PORT_PRESET_ARMV7EM 1
#else
# define FIBER_PORT_PRESET_ARMV7EM 0
#endif

#ifdef FIBER_PORT_ARMV8M_BASELINE
# define FIBER_PORT_PRESET_ARMV8M_BASELINE 1
#else
# define FIBER_PORT_PRESET_ARMV8M_BASELINE 0
#endif

#ifdef FIBER_PORT_ARMV8M_MAINLINE
# define FIBER_PORT_PRESET_ARMV8M_MAINLINE 1
#else
# define FIBER_PORT_PRESET_ARMV8M_MAINLINE 0
#endif

#ifdef FIBER_PORT_ARMV81M_MAINLINE
# define FIBER_PORT_PRESET_ARMV81M_MAINLINE 1
#else
# define FIBER_PORT_PRESET_ARMV81M_MAINLINE 0
#endif

#define FIBER_PORT_PRESET_COUNT \
    (FIBER_PORT_PRESET_ARMV6M + \
     FIBER_PORT_PRESET_ARMV7M + \
     FIBER_PORT_PRESET_ARMV7EM + \
     FIBER_PORT_PRESET_ARMV8M_BASELINE + \
     FIBER_PORT_PRESET_ARMV8M_MAINLINE + \
     FIBER_PORT_PRESET_ARMV81M_MAINLINE)

FIBER_STATIC_ASSERT(((FIBER_PORT_BUILD_SELECTED == 0) && (FIBER_PORT_PRESET_COUNT == 0)) ||
                 ((FIBER_PORT_BUILD_SELECTED == 1) && (FIBER_PORT_PRESET_COUNT == 1)),
                 "[fiber]: selector mode must not predefine FIBER_PORT_*; build-selected mode must define exactly one");

/*
 * Legacy explicit override knobs for unusual toolchains. Prefer
 * FIBER_PORT_PROFILE for new projects.
 */
#ifndef FIBER_FORCE_PORT_ARMV6M
# define FIBER_FORCE_PORT_ARMV6M 0
#endif

#ifndef FIBER_FORCE_PORT_ARMV7M
# define FIBER_FORCE_PORT_ARMV7M 0
#endif

#ifndef FIBER_FORCE_PORT_ARMV7EM
# define FIBER_FORCE_PORT_ARMV7EM 0
#endif

#ifndef FIBER_FORCE_PORT_ARMV8M_BASELINE
# define FIBER_FORCE_PORT_ARMV8M_BASELINE 0
#endif

#ifndef FIBER_FORCE_PORT_ARMV8M_MAINLINE
# define FIBER_FORCE_PORT_ARMV8M_MAINLINE 0
#endif

#ifndef FIBER_FORCE_PORT_ARMV81M_MAINLINE
# define FIBER_FORCE_PORT_ARMV81M_MAINLINE 0
#endif

FIBER_STATIC_ASSERT((FIBER_FORCE_PORT_ARMV6M == 0) || (FIBER_FORCE_PORT_ARMV6M == 1),
                 "[fiber]: FIBER_FORCE_PORT_ARMV6M must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_FORCE_PORT_ARMV7M == 0) || (FIBER_FORCE_PORT_ARMV7M == 1),
                 "[fiber]: FIBER_FORCE_PORT_ARMV7M must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_FORCE_PORT_ARMV7EM == 0) || (FIBER_FORCE_PORT_ARMV7EM == 1),
                 "[fiber]: FIBER_FORCE_PORT_ARMV7EM must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_FORCE_PORT_ARMV8M_BASELINE == 0) || (FIBER_FORCE_PORT_ARMV8M_BASELINE == 1),
                 "[fiber]: FIBER_FORCE_PORT_ARMV8M_BASELINE must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_FORCE_PORT_ARMV8M_MAINLINE == 0) || (FIBER_FORCE_PORT_ARMV8M_MAINLINE == 1),
                 "[fiber]: FIBER_FORCE_PORT_ARMV8M_MAINLINE must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_FORCE_PORT_ARMV81M_MAINLINE == 0) || (FIBER_FORCE_PORT_ARMV81M_MAINLINE == 1),
                 "[fiber]: FIBER_FORCE_PORT_ARMV81M_MAINLINE must be 0 or 1");

#define FIBER_PORT_FORCE_COUNT \
    (FIBER_FORCE_PORT_ARMV6M + \
     FIBER_FORCE_PORT_ARMV7M + \
     FIBER_FORCE_PORT_ARMV7EM + \
     FIBER_FORCE_PORT_ARMV8M_BASELINE + \
     FIBER_FORCE_PORT_ARMV8M_MAINLINE + \
     FIBER_FORCE_PORT_ARMV81M_MAINLINE)

FIBER_STATIC_ASSERT(FIBER_PORT_FORCE_COUNT <= 1,
                 "[fiber]: at most one forced Cortex-M port may be selected");

FIBER_STATIC_ASSERT((FIBER_PORT_PROFILE_IS_EXPLICIT == 0) || (FIBER_PORT_FORCE_COUNT == 0),
                 "[fiber]: use either FIBER_PORT_PROFILE or FIBER_FORCE_PORT_*, not both");

FIBER_STATIC_ASSERT((FIBER_PORT_BUILD_SELECTED == 0) || (FIBER_PORT_FORCE_COUNT == 0),
                 "[fiber]: build-selected port mode must not also use FIBER_FORCE_PORT_*");

#define FIBER_PORT_FORCE_MATCHES_DETECTED \
    ((FIBER_PORT_FORCE_COUNT == 0) || \
     (FIBER_PORT_DETECTED_COUNT == 0) || \
     (FIBER_FORCE_PORT_ARMV6M && FIBER_PORT_DETECTED_ARMV6M) || \
     (FIBER_FORCE_PORT_ARMV7M && FIBER_PORT_DETECTED_ARMV7M) || \
     (FIBER_FORCE_PORT_ARMV7EM && FIBER_PORT_DETECTED_ARMV7EM) || \
     (FIBER_FORCE_PORT_ARMV8M_BASELINE && FIBER_PORT_DETECTED_ARMV8M_BASELINE) || \
     (FIBER_FORCE_PORT_ARMV8M_MAINLINE && FIBER_PORT_DETECTED_ARMV8M_MAINLINE) || \
     (FIBER_FORCE_PORT_ARMV81M_MAINLINE && FIBER_PORT_DETECTED_ARMV81M_MAINLINE))

FIBER_STATIC_ASSERT((FIBER_PORT_SELECTION_ALLOW_MISMATCH != 0) || FIBER_PORT_FORCE_MATCHES_DETECTED,
                 "[fiber]: FIBER_FORCE_PORT_* conflicts with compiler __ARM_ARCH_* macros");

/*
 * Final selected-port result.
 *
 * Selector-driven precedence is:
 * 1. FIBER_PORT_PROFILE, when explicit;
 * 2. FIBER_FORCE_PORT_*, for legacy/unusual toolchains;
 * 3. compiler auto-detection.
 *
 * Build-selected mode skips this precedence and preserves the one
 * FIBER_PORT_ARMV* result supplied by the build.
 *
 * Exactly one FIBER_PORT_ARMV* result must be 1 after this block.
 */
#if FIBER_PORT_BUILD_SELECTED

# ifndef FIBER_PORT_ARMV6M
#  define FIBER_PORT_ARMV6M 0
# endif

# ifndef FIBER_PORT_ARMV7M
#  define FIBER_PORT_ARMV7M 0
# endif

# ifndef FIBER_PORT_ARMV7EM
#  define FIBER_PORT_ARMV7EM 0
# endif

# ifndef FIBER_PORT_ARMV8M_BASELINE
#  define FIBER_PORT_ARMV8M_BASELINE 0
# endif

# ifndef FIBER_PORT_ARMV8M_MAINLINE
#  define FIBER_PORT_ARMV8M_MAINLINE 0
# endif

# ifndef FIBER_PORT_ARMV81M_MAINLINE
#  define FIBER_PORT_ARMV81M_MAINLINE 0
# endif

#else /* FIBER_PORT_BUILD_SELECTED */

#ifndef FIBER_PORT_ARMV6M
# if FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV6M
#  define FIBER_PORT_ARMV6M 1
# elif FIBER_PORT_PROFILE_IS_EXPLICIT
#  define FIBER_PORT_ARMV6M 0
# elif FIBER_PORT_FORCE_COUNT
#  define FIBER_PORT_ARMV6M FIBER_FORCE_PORT_ARMV6M
# elif FIBER_PORT_DETECTED_ARMV6M
#  define FIBER_PORT_ARMV6M 1
# else
#  define FIBER_PORT_ARMV6M 0
# endif
#endif

#ifndef FIBER_PORT_ARMV7M
# if FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV7M
#  define FIBER_PORT_ARMV7M 1
# elif FIBER_PORT_PROFILE_IS_EXPLICIT
#  define FIBER_PORT_ARMV7M 0
# elif FIBER_PORT_FORCE_COUNT
#  define FIBER_PORT_ARMV7M FIBER_FORCE_PORT_ARMV7M
# elif FIBER_PORT_DETECTED_ARMV7M
#  define FIBER_PORT_ARMV7M 1
# else
#  define FIBER_PORT_ARMV7M 0
# endif
#endif

#ifndef FIBER_PORT_ARMV7EM
# if FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV7EM
#  define FIBER_PORT_ARMV7EM 1
# elif FIBER_PORT_PROFILE_IS_EXPLICIT
#  define FIBER_PORT_ARMV7EM 0
# elif FIBER_PORT_FORCE_COUNT
#  define FIBER_PORT_ARMV7EM FIBER_FORCE_PORT_ARMV7EM
# elif FIBER_PORT_DETECTED_ARMV7EM
#  define FIBER_PORT_ARMV7EM 1
# else
#  define FIBER_PORT_ARMV7EM 0
# endif
#endif

#ifndef FIBER_PORT_ARMV8M_BASELINE
# if FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV8M_BASELINE
#  define FIBER_PORT_ARMV8M_BASELINE 1
# elif FIBER_PORT_PROFILE_IS_EXPLICIT
#  define FIBER_PORT_ARMV8M_BASELINE 0
# elif FIBER_PORT_FORCE_COUNT
#  define FIBER_PORT_ARMV8M_BASELINE FIBER_FORCE_PORT_ARMV8M_BASELINE
# elif FIBER_PORT_DETECTED_ARMV8M_BASELINE
#  define FIBER_PORT_ARMV8M_BASELINE 1
# else
#  define FIBER_PORT_ARMV8M_BASELINE 0
# endif
#endif

#ifndef FIBER_PORT_ARMV8M_MAINLINE
# if FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV8M_MAINLINE
#  define FIBER_PORT_ARMV8M_MAINLINE 1
# elif FIBER_PORT_PROFILE_IS_EXPLICIT
#  define FIBER_PORT_ARMV8M_MAINLINE 0
# elif FIBER_PORT_FORCE_COUNT
#  define FIBER_PORT_ARMV8M_MAINLINE FIBER_FORCE_PORT_ARMV8M_MAINLINE
# elif FIBER_PORT_DETECTED_ARMV8M_MAINLINE
#  define FIBER_PORT_ARMV8M_MAINLINE 1
# else
#  define FIBER_PORT_ARMV8M_MAINLINE 0
# endif
#endif

#ifndef FIBER_PORT_ARMV81M_MAINLINE
# if FIBER_PORT_PROFILE == FIBER_PORT_PROFILE_ARMV81M_MAINLINE
#  define FIBER_PORT_ARMV81M_MAINLINE 1
# elif FIBER_PORT_PROFILE_IS_EXPLICIT
#  define FIBER_PORT_ARMV81M_MAINLINE 0
# elif FIBER_PORT_FORCE_COUNT
#  define FIBER_PORT_ARMV81M_MAINLINE FIBER_FORCE_PORT_ARMV81M_MAINLINE
# elif FIBER_PORT_DETECTED_ARMV81M_MAINLINE
#  define FIBER_PORT_ARMV81M_MAINLINE 1
# else
#  define FIBER_PORT_ARMV81M_MAINLINE 0
# endif
#endif

#endif /* FIBER_PORT_BUILD_SELECTED */

FIBER_STATIC_ASSERT((FIBER_PORT_ARMV6M == 0) || (FIBER_PORT_ARMV6M == 1),
                 "[fiber]: FIBER_PORT_ARMV6M must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_ARMV7M == 0) || (FIBER_PORT_ARMV7M == 1),
                 "[fiber]: FIBER_PORT_ARMV7M must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_ARMV7EM == 0) || (FIBER_PORT_ARMV7EM == 1),
                 "[fiber]: FIBER_PORT_ARMV7EM must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_ARMV8M_BASELINE == 0) || (FIBER_PORT_ARMV8M_BASELINE == 1),
                 "[fiber]: FIBER_PORT_ARMV8M_BASELINE must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_ARMV8M_MAINLINE == 0) || (FIBER_PORT_ARMV8M_MAINLINE == 1),
                 "[fiber]: FIBER_PORT_ARMV8M_MAINLINE must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_ARMV81M_MAINLINE == 0) || (FIBER_PORT_ARMV81M_MAINLINE == 1),
                 "[fiber]: FIBER_PORT_ARMV81M_MAINLINE must be 0 or 1");

#define FIBER_PORT_COUNT \
    (FIBER_PORT_ARMV6M + \
     FIBER_PORT_ARMV7M + \
     FIBER_PORT_ARMV7EM + \
     FIBER_PORT_ARMV8M_BASELINE + \
     FIBER_PORT_ARMV8M_MAINLINE + \
     FIBER_PORT_ARMV81M_MAINLINE)

FIBER_STATIC_ASSERT(FIBER_PORT_COUNT == 1,
                 "[fiber]: exactly one Cortex-M port must be selected");

#define FIBER_PORT_BUILD_SELECTED_MATCHES_DETECTED \
    ((FIBER_PORT_BUILD_SELECTED == 0) || \
     (FIBER_PORT_DETECTED_COUNT == 0) || \
     (FIBER_PORT_ARMV6M && FIBER_PORT_DETECTED_ARMV6M) || \
     (FIBER_PORT_ARMV7M && FIBER_PORT_DETECTED_ARMV7M) || \
     (FIBER_PORT_ARMV7EM && FIBER_PORT_DETECTED_ARMV7EM) || \
     (FIBER_PORT_ARMV8M_BASELINE && FIBER_PORT_DETECTED_ARMV8M_BASELINE) || \
     (FIBER_PORT_ARMV8M_MAINLINE && FIBER_PORT_DETECTED_ARMV8M_MAINLINE) || \
     (FIBER_PORT_ARMV81M_MAINLINE && FIBER_PORT_DETECTED_ARMV81M_MAINLINE))

FIBER_STATIC_ASSERT((FIBER_PORT_SELECTION_ALLOW_MISMATCH != 0) ||
                 FIBER_PORT_BUILD_SELECTED_MATCHES_DETECTED,
                 "[fiber]: build-selected FIBER_PORT_ARMV* conflicts with compiler __ARM_ARCH_* macros");

/*
 * Aggregate gates are convenience facts derived from exactly one selected port.
 * They are also normalized to 0/1 so lower target headers can use plain
 * #if FIBER_PORT_IS_* without depending on undefined macros.
 */
#ifndef FIBER_PORT_IS_BASELINE
# define FIBER_PORT_IS_BASELINE (FIBER_PORT_ARMV6M || FIBER_PORT_ARMV8M_BASELINE)
#endif

#ifndef FIBER_PORT_IS_MAINLINE
# define FIBER_PORT_IS_MAINLINE \
    (FIBER_PORT_ARMV7M || FIBER_PORT_ARMV7EM || FIBER_PORT_ARMV8M_MAINLINE || FIBER_PORT_ARMV81M_MAINLINE)
#endif

#ifndef FIBER_PORT_IS_V8M
# define FIBER_PORT_IS_V8M \
    (FIBER_PORT_ARMV8M_BASELINE || FIBER_PORT_ARMV8M_MAINLINE || FIBER_PORT_ARMV81M_MAINLINE)
#endif

FIBER_STATIC_ASSERT((FIBER_PORT_IS_BASELINE == 0) || (FIBER_PORT_IS_BASELINE == 1),
                 "[fiber]: FIBER_PORT_IS_BASELINE must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_IS_MAINLINE == 0) || (FIBER_PORT_IS_MAINLINE == 1),
                 "[fiber]: FIBER_PORT_IS_MAINLINE must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_IS_V8M == 0) || (FIBER_PORT_IS_V8M == 1),
                 "[fiber]: FIBER_PORT_IS_V8M must be 0 or 1");
FIBER_STATIC_ASSERT((FIBER_PORT_IS_BASELINE + FIBER_PORT_IS_MAINLINE) == 1,
                 "[fiber]: selected port must be either baseline or mainline");

/*
 * Diagnostic name for compile logs, asserts, or future validation reports.
 * This is not a selection knob.
 */
#ifndef FIBER_PORT_NAME
# if FIBER_PORT_ARMV6M
#  define FIBER_PORT_NAME "ARM_CM0"
# elif FIBER_PORT_ARMV7M
#  define FIBER_PORT_NAME "ARM_CM3"
# elif FIBER_PORT_ARMV7EM
#  if defined(__CORTEX_M) && (__CORTEX_M == 7)
#   define FIBER_PORT_NAME "ARM_CM7/r0p1"
#  else
#   define FIBER_PORT_NAME "ARM_CM4"
#  endif
# elif FIBER_PORT_ARMV8M_BASELINE
#  define FIBER_PORT_NAME "armv8m_baseline"
# elif FIBER_PORT_ARMV8M_MAINLINE
#  define FIBER_PORT_NAME "armv8m_mainline"
# elif FIBER_PORT_ARMV81M_MAINLINE
#  define FIBER_PORT_NAME "armv81m_mainline"
# endif
#endif

#endif /* FIBER_FIBER_PORT_SELECT_H_ */
