/*
 * fiber_port_types.h
 *
 * Type-only public context layout for the selected ARM_CM7/r0p1 port.
 */

#ifndef FIBER_PORT_ARM_CM7_R0P1_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM7_R0P1_FIBER_PORT_TYPES_H_

#include "../../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Keep this transitional layout ABI-identical to the validated CM7 runtime.
 * Frame offsets and CPU save geometry remain private to the port source. */
struct FiberContext {
	uint32_t *sp;
	FiberPortBoot boot;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM7_R0P1_FIBER_PORT_TYPES_H_ */
