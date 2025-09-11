/*
 * fiber_panic.c
 *
 *  Created on: Sep 2, 2025
 *      Author: admin
 */
#include "fiber_panic.h"

/* Weak fallback (overridden by any strong definition in the app) */
FIBER_WEAK FIBER_NORETURN
FIBER_ATTR_SENSITIVE
void fiber_panic(const char)
{
	Error_Handler();
	while(1) { __WFE(); /* never returns */ };
}

