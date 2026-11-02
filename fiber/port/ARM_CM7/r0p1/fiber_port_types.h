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

/* This selected port owns the complete context layout. Frame offsets and CPU
 * save geometry remain private and are guarded by its exact cohort identity. */
struct FiberContext {
	uint32_t *sp;
	FiberPortBoot boot;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#define FIBER_PORT_STORAGE_COHORT_PORT arm_cm7_r0p1
#define FIBER_PORT_STORAGE_COHORT_REVISION 1
#define FIBER_PORT_STORAGE_COHORT_REGIONS 0
#include "../../fiber_port_storage_cohort.h"

#endif /* FIBER_PORT_ARM_CM7_R0P1_FIBER_PORT_TYPES_H_ */
