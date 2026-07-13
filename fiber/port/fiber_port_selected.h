/*
 * fiber_port_selected.h
 *
 * Selected Cortex-M port facade.
 *
 * fiber_port_select.h normally decides which port profile is active. This
 * header then includes exactly one concrete public type definition.
 *
 * In FIBER_PORT_BUILD_SELECTED mode, the build system provides the selected
 * port include path and this facade includes fiber_port_types.h. Full selected
 * port contracts are private to port sources and are reached through the
 * callable fiber_port_runtime_abi.h boundary.
 */

#ifndef FIBER_FIBER_PORT_SELECTED_H_
#define FIBER_FIBER_PORT_SELECTED_H_

#include "fiber_port_select.h"

/* This is the only global port selector for the public complete type. */
#if FIBER_PORT_BUILD_SELECTED
# include "fiber_port_types.h"
#elif FIBER_PORT_ARMV6M
# include "ARM_CM0/fiber_port_types.h"
#elif FIBER_PORT_ARMV7M
# include "ARM_CM3/fiber_port_types.h"
#elif FIBER_PORT_ARMV7EM
# if !defined(__CORTEX_M)
#  error "[fiber]: ARMv7E-M selection requires CMSIS __CORTEX_M"
# elif (__CORTEX_M == 7)
#  include "ARM_CM7/r0p1/fiber_port_types.h"
# elif (__CORTEX_M == 4)
#  include "ARM_CM4/fiber_port_types.h"
# else
#  error "[fiber]: selected ARMv7E-M core has no concrete fiber port"
# endif
#else
# include "transitional_v8m/fiber_port_types.h"
#endif

#endif /* FIBER_FIBER_PORT_SELECTED_H_ */
