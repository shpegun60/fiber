/*
 * Type-only public storage for the exact ARM_CM55F_NTZ layout profile.
 *
 * Basic and extended FP state remain on the fiber stack. The selected port
 * owns both dynamic frame forms; the public context exposes only the saved SP
 * and immutable boot record.
 */
#ifndef FIBER_PORT_ARM_CM55F_NTZ_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM55F_NTZ_FIBER_PORT_TYPES_H_

#include "../../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifdef FIBER_PORT_NAME
# undef FIBER_PORT_NAME
#endif
#define FIBER_PORT_NAME "ARM_CM55F_NTZ"

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

#endif /* FIBER_PORT_ARM_CM55F_NTZ_FIBER_PORT_TYPES_H_ */
