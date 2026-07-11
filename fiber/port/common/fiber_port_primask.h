/*
 * fiber_port_primask.h
 *
 * Shared low-level PRIMASK helpers for Cortex-M ports.
 */

#ifndef FIBER_PORT_COMMON_FIBER_PORT_PRIMASK_H_
#define FIBER_PORT_COMMON_FIBER_PORT_PRIMASK_H_

#include "../../target/fiber_target.h"

#ifdef __cplusplus
extern "C" {
#endif

__STATIC_FORCEINLINE uint32_t fiber_port_primask_save_disable(void)
{
	uint32_t pm;
	__ASM volatile(
			"mrs %0, primask \n"
			"cpsid i         \n"
			: "=r"(pm)
			:
			: "memory");
	{ __DSB(); __ISB(); }
	return pm;
}

__STATIC_FORCEINLINE void fiber_port_primask_restore(uint32_t pm)
{
	{ __DSB(); __ISB(); }
	__ASM volatile("msr primask, %0" :: "r"(pm) : "memory");
	{ __DSB(); __ISB(); }
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_COMMON_FIBER_PORT_PRIMASK_H_ */
