/*
 * fiber_panic.c
 *
 *  Created on: Sep 2, 2025
 *      Author: admin
 */
#include "fiber_panic.h"
#include "port/fiber_port_runtime_abi.h"

/* Weak fallback is self-contained. Applications may override it, but the
 * library never requires a Cube/HAL Error_Handler symbol to link or stop. */
static volatile char fiber_internal_fallback_panic_code = 0;

FIBER_API_WEAK FIBER_API_NORETURN FIBER_GENERAL_REGS_ONLY
FIBER_API_ATTR_SENSITIVE
void fiber_panic(char code)
{
	fiber_internal_fallback_panic_code = code;
	fiber_port_runtime_memory_barrier();
	fiber_port_panic_wait();
	FIBER_API_UNREACHABLE();
}

