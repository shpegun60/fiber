/*
 * Type-only public storage for the exact ARM_CM33F_TFM runtime profile.
 *
 * Basic and extended FP state remain on the fiber stack. The selected port
 * owns both dynamic frame forms; the public context exposes only the saved SP
 * and immutable boot record.
 */
#ifndef FIBER_PORT_ARM_CM33F_TFM_FIBER_PORT_TYPES_H_
#define FIBER_PORT_ARM_CM33F_TFM_FIBER_PORT_TYPES_H_

#include "../../../fiber_api_types.h"
#include "fiber_port_boot_types.h"

#ifdef FIBER_PORT_NAME
# undef FIBER_PORT_NAME
#endif
#define FIBER_PORT_NAME "ARM_CM33F_TFM"

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

#define FIBER_PORT_STORAGE_COHORT_PORT arm_cm33f_tfm
#define FIBER_PORT_STORAGE_COHORT_REVISION 1
#define FIBER_PORT_STORAGE_COHORT_REGIONS 0
#include "../../fiber_port_storage_cohort.h"

#endif /* FIBER_PORT_ARM_CM33F_TFM_FIBER_PORT_TYPES_H_ */
