/*
 * fiber_port_state.c
 *
 * Runtime-owned switch publication slots used by PendSV ports.
 */

#include "fiber_port_state.h"

FiberContext *volatile fiber_internal_port_switch_from_slot = 0;
FiberContext *volatile fiber_internal_port_switch_to_slot = 0;
FiberContext *volatile fiber_internal_port_current_context = 0;
