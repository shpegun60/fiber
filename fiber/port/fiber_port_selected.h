/*
 * fiber_port_selected.h
 *
 * Selected Cortex-M port facade.
 *
 * fiber_port_select.h normally decides which port profile is active. This
 * header then includes exactly one concrete port interface and applies common
 * trait checks for the selected port.
 *
 * In FIBER_PORT_BUILD_SELECTED mode, the build system provides the selected
 * port include path and this facade includes fiber_portmacro.h, matching the
 * FreeRTOS portmacro.h pattern. Common runtime code should include this facade
 * instead of including concrete architecture headers directly.
 */

#ifndef FIBER_PORT_FIBER_PORT_SELECTED_H_
#define FIBER_PORT_FIBER_PORT_SELECTED_H_

#include "../target/fiber_target.h"
#include "fiber_port_types.h"

#if FIBER_PORT_BUILD_SELECTED
# include "fiber_portmacro.h"
#elif FIBER_PORT_ARMV6M
# include "armv6m/fiber_port_armv6m.h"
#elif FIBER_PORT_ARMV7M
# include "armv7m/fiber_port_armv7m.h"
#elif FIBER_PORT_ARMV7EM
# include "armv7em/fiber_port_armv7em.h"
#else
# include "transitional_v8m/fiber_port_transitional_v8m.h"
#endif

#include "fiber_port_traits.h"

#endif /* FIBER_PORT_FIBER_PORT_SELECTED_H_ */
