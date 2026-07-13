/*
 * fiber_port_types.h
 *
 * Type-only public context layout for the selected ARMv7-M port.
 */

#ifndef FIBER_PORT_ARMV7M_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARMV7M_FIBER_PORT_TYPES_H_

#include "../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct FiberContext {
	uint32_t *sp;
	FiberPortBoot boot;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARMV7M_FIBER_PORT_TYPES_H_ */
