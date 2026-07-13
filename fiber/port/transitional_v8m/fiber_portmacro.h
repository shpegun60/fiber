/*
 * fiber_portmacro.h
 *
 * Transitional v8-M selected portmacro facade.
 *
 * This is a compile-coverage bridge, not a production support claim. Real v8-M
 * selected ports must own security/PSPLIM/MVE/PAC/BTI policy directly.
 */

#ifndef FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORTMACRO_H_
#define FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORTMACRO_H_

#if FIBER_PORT_ARMV8M_BASELINE || FIBER_PORT_ARMV8M_MAINLINE || FIBER_PORT_ARMV81M_MAINLINE
# include "fiber_port_types.h"
#endif
#include "fiber_port_transitional_v8m.h"
#include "../../fiber_panic.h"
#if FIBER_PORT_ARMV8M_BASELINE || FIBER_PORT_ARMV8M_MAINLINE || FIBER_PORT_ARMV81M_MAINLINE
# include "fiber_port_boot.h"
#endif

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

#endif /* FIBER_PORT_TRANSITIONAL_V8M_FIBER_PORTMACRO_H_ */
