/*
 * fiber_panic.h
 *
 *  Created on: Sep 2, 2025
 *      Author: admin
 */

#ifndef FIBER_FIBER_PANIC_H_
#define FIBER_FIBER_PANIC_H_

#include "fiber_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Panic/require: if the app didn't provide a global one, ship a weak fallback.
 * -------------------------------------------------------------------------- */
#ifndef FIBER_REQUIRE
#  define FIBER_REQUIRE(cond, code) do { if (!(cond)) fiber_panic((code)); } while (0)
#endif

FIBER_WEAK FIBER_NORETURN
FIBER_ATTR_SENSITIVE
void fiber_panic(char code);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_PANIC_H_ */
