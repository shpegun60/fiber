/*
 * Type-only public storage for the exact ARM_CM33F Non-secure profile.
 *
 * Saved registers, including the SecureContext handle, remain on the fiber
 * stack. The exact eleven-word software frame is a private port contract and
 * is frozen in fiber_portmacro.h.
 */
#ifndef FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORT_TYPES_H_

#include "../../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifdef FIBER_PORT_NAME
# undef FIBER_PORT_NAME
#endif
#define FIBER_PORT_NAME "ARM_CM33F"

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

#define FIBER_PORT_STORAGE_COHORT_PORT arm_cm33f
#define FIBER_PORT_STORAGE_COHORT_REVISION 1
#define FIBER_PORT_STORAGE_COHORT_REGIONS 0
#include "../../fiber_port_storage_cohort.h"

#endif /* FIBER_PORT_ARM_CM33F_NON_SECURE_FIBER_PORT_TYPES_H_ */
