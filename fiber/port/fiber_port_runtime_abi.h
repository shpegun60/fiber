/*
 * fiber_port_runtime_abi.h
 *
 * Opaque callable ABI between the common cooperative runtime and one selected
 * Cortex-M port. This header intentionally exposes no CPU traits, CMSIS
 * registers, frame geometry, or FiberContext layout.
 */

#ifndef FIBER_PORT_FIBER_PORT_RUNTIME_ABI_H_
#define FIBER_PORT_FIBER_PORT_RUNTIME_ABI_H_

#include "../fiber_api_attributes.h"
#include "../fiber_api_types.h"

#include "../../context/context_port_abi.h"

#endif /* FIBER_PORT_FIBER_PORT_RUNTIME_ABI_H_ */
