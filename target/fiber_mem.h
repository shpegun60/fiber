/*
 * fiber_mem.h
 *
 *  Created on: Sep 11, 2025
 *      Author: admin
 */

#ifndef FIBER_TARGET_FIBER_MEM_H_
#define FIBER_TARGET_FIBER_MEM_H_

#include "fiber_compiler.h"


/* --------------------------------------------------------------------------
 * Address plausibility hooks (override in the app for your memory map).
 * Defaults accept everything; override to enforce SRAM/FLASH windows, etc.
 * -------------------------------------------------------------------------- */
FIBER_WEAK int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end);

FIBER_WEAK int fiber_addr_plausible_code(uintptr_t addr);

/* Fallback if vector/VTOR is broken and initial MSP cannot be trusted. */
FIBER_WEAK uintptr_t fiber_fallback_initial_msp(void);

#endif /* FIBER_TARGET_FIBER_MEM_H_ */
