/*
 * fiber_portmacro.h
 *
 * ARMv7E-M selected portmacro facade.
 *
 * This is a transitional selector-driven facade. Production FreeRTOS-style
 * selected ports should own their CPU dictionary directly in this file shape:
 * fiber_portXXX constants, FIBER_PORT_* traits, and one matching source group.
 */

#ifndef FIBER_PORT_ARMV7EM_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARMV7EM_FIBER_PORTMACRO_H_

#include "fiber_port_armv7em.h"
#include "../../fiber_panic.h"

#ifndef FIBER_SVC_START_NUMBER
# define FIBER_SVC_START_NUMBER 70
#endif
#ifndef FIBER_PENDSV_VECTOR_DIRECT
# define FIBER_PENDSV_VECTOR_DIRECT 0
#endif
#ifndef FIBER_SVC_VECTOR_DIRECT
# define FIBER_SVC_VECTOR_DIRECT 0
#endif

#if defined(FIBER_FORCE_PRIGROUP) || defined(FIBER_TUNE_SYSTICK) || \
		defined(FIBER_TUNE_SVCALL)
# error "[fiber]: exception ownership is fixed by the selected port"
#endif

#if defined(FIBER_VALIDATE_EXCEPTION_SETUP) || \
		defined(FIBER_VALIDATE_VECTOR_WIRING) || \
		defined(FIBER_VALIDATE_PENDSV_VECTOR) || \
		defined(FIBER_VALIDATE_SVC_VECTOR) || \
		defined(FIBER_VALIDATE_BASEPRI_PRIORITY_MASK) || \
		defined(FIBER_VALIDATE_PRIORITY_GROUPING) || \
		defined(FIBER_VALIDATE_M7_R0P1_ERRATA_POLICY) || \
		defined(FIBER_VALIDATE_SVC_PRIORITY)
# error "[fiber]: selected-port exception validation is mandatory"
#endif

FIBER_STATIC_ASSERT((FIBER_SVC_START_NUMBER >= 0) &&
		(FIBER_SVC_START_NUMBER <= 255),
		"[fiber]: FIBER_SVC_START_NUMBER must fit in an 8-bit SVC immediate");

#endif /* FIBER_PORT_ARMV7EM_FIBER_PORTMACRO_H_ */
