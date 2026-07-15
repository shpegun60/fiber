/*
 * fiber_panic.h
 *
 *  Created on: Sep 2, 2025
 *      Author: admin
 */

#ifndef FIBER_FIBER_PANIC_H_
#define FIBER_FIBER_PANIC_H_

#include "fiber_api_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical strong declaration. The bundled definition alone is weak so one
 * application definition may override it without weakening port references. */
#ifndef FIBER_REQUIRE
#  define FIBER_REQUIRE(cond, code) do { if (!(cond)) fiber_panic((code)); } while (0)
#endif

FIBER_API_NORETURN
FIBER_API_ATTR_SENSITIVE
FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_PANIC_H_ */
