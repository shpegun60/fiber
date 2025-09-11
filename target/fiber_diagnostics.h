/*
 * fiber_diagnostics.h
 *
 *  Created on: Sep 6, 2025
 *      Author: admin
 */

#ifndef FIBER_TOOLS_FIBER_DIAGNOSTICS_H_
#define FIBER_TOOLS_FIBER_DIAGNOSTICS_H_

/* ---------- Portable compile-time diagnostics ---------- */

/* Stringify helpers for _Pragma */
#define FIBER_PP_STR(x)   #x
#define FIBER_PP_XSTR(x)  FIBER_PP_STR(x)
#define FIBER_PRAGMA(x)   _Pragma(FIBER_PP_XSTR(x))

/* Emit notes/warnings/errors across toolchains.
   Usage:
     FIBER_DIAG_NOTE("info text");
     FIBER_DIAG_WARN("warn text");
     FIBER_DIAG_ERROR("fatal text");
*/
#if defined(__clang__)
  /* Clang/armclang: accepts both 'message' and 'GCC warning/error' forms */
# define FIBER_DIAG_NOTE(msg)   FIBER_PRAGMA(message msg)
# define FIBER_DIAG_WARN(msg)   FIBER_PRAGMA(GCC warning msg)
# define FIBER_DIAG_ERROR(msg)  FIBER_PRAGMA(GCC error msg)

#elif defined(__GNUC__)
  /* GCC: #pragma GCC warning|error "..." */
# define FIBER_DIAG_NOTE(msg)   FIBER_PRAGMA(message msg)
# define FIBER_DIAG_WARN(msg)   FIBER_PRAGMA(GCC warning msg)
# define FIBER_DIAG_ERROR(msg)  FIBER_PRAGMA(GCC error msg)

#elif defined(__ICCARM__)
  /* IAR: no portable 'error "text"' pragma; force a compile-time error with the same message */
# define FIBER_DIAG_NOTE(msg)   FIBER_PRAGMA(message (msg))
# define FIBER_DIAG_WARN(msg)   FIBER_PRAGMA(message (msg))
  /* Requires C11/C++11 or newer for static assert. Message must be a string literal. */
# if defined(__cplusplus)
#   define FIBER_DIAG_ERROR(msg) static_assert(0, msg)
# else
#   define FIBER_DIAG_ERROR(msg) _Static_assert(0, msg)
# endif

#else
  /* Unknown compiler: degrade gracefully */
# define FIBER_DIAG_NOTE(msg)
# define FIBER_DIAG_WARN(msg)
# if defined(__cplusplus)
#   define FIBER_DIAG_ERROR(msg) static_assert(0, msg)
# else
#   define FIBER_DIAG_ERROR(msg) _Static_assert(0, msg)
# endif
#endif

#endif /* FIBER_TOOLS_FIBER_DIAGNOSTICS_H_ */
