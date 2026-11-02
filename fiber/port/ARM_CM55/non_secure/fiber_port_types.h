/*
 * Type-only public storage for the staged ARM_CM55 TrustZone profile.
 *
 * The exact eleven-word software frame, including the SecureContext handle,
 * remains private to this selected port. Construction and attachment do not
 * make this a runtime; the Secure companion is a separate artifact.
 */
#ifndef FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_TYPES_H_

#include "../../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifdef FIBER_PORT_NAME
# undef FIBER_PORT_NAME
#endif
#define FIBER_PORT_NAME "ARM_CM55"

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

#define FIBER_PORT_STORAGE_COHORT_PORT arm_cm55
#define FIBER_PORT_STORAGE_COHORT_REVISION 1
#define FIBER_PORT_STORAGE_COHORT_REGIONS 0
#include "../../fiber_port_storage_cohort.h"

#endif /* FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_TYPES_H_ */
