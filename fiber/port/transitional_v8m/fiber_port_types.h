/*
 * fiber_port_types.h
 *
 * Type-only public context layout for transitional ARMv8-M coverage.
 */

#ifndef FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORT_TYPES_H_
#define FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORT_TYPES_H_

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

#define FIBER_PORT_STORAGE_COHORT_PORT transitional_v8m
#define FIBER_PORT_STORAGE_COHORT_REVISION 1
#define FIBER_PORT_STORAGE_COHORT_REGIONS 0
#include "../fiber_port_storage_cohort.h"

#endif /* FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORT_TYPES_H_ */
