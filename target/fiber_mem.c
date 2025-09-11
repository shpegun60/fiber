/*
 * fiber_mem.c
 *
 *  Created on: Sep 11, 2025
 *      Author: admin
 */

#include "fiber_mem.h"

/* --------------------------------------------------------------------------
 * Address plausibility hooks (override in the app for your memory map).
 * Defaults accept everything; override to enforce SRAM/FLASH windows, etc.
 * -------------------------------------------------------------------------- */
FIBER_WEAK int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end) {
	(void)start; (void)end; return 1; /* accept any range by default */
}

FIBER_WEAK int fiber_addr_plausible_code(uintptr_t addr) {
	(void)addr; return 1;             /* accept any code address by default */
}

/* Fallback if vector/VTOR is broken and initial MSP cannot be trusted. */
FIBER_WEAK uintptr_t fiber_fallback_initial_msp(void) {
	return (uintptr_t)0;              /* default: no usable fallback */
}

