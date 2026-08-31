/* ARM_CM55F_MPU/non_secure declarations private to its staged implementation. */
#ifndef FIBER_PORT_ARM_CM55F_MPU_NON_SECURE_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM55F_MPU_NON_SECURE_FIBER_PORT_PRIVATE_H_

#include "fiber_port_boot.h"
#include "../../fiber_port_context_cohort.h"

/* Slice 1 deliberately has no forward runtime ABI, exception handlers, or
 * optional MPU API. Later slices extend this private boundary rather than
 * changing the public storage or construction contract. */

#endif /* FIBER_PORT_ARM_CM55F_MPU_NON_SECURE_FIBER_PORT_PRIVATE_H_ */
