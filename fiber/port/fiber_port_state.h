/*
 * fiber_port_state.h
 *
 * Internal switch-state symbols shared by common runtime and port code.
 */

#ifndef FIBER_PORT_FIBER_PORT_STATE_H_
#define FIBER_PORT_FIBER_PORT_STATE_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FiberContext FiberContext;

extern FiberContext *volatile fiber_internal_port_switch_from_slot;
extern FiberContext *volatile fiber_internal_port_switch_to_slot;
extern FiberContext *volatile fiber_internal_port_current_context;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_FIBER_PORT_STATE_H_ */
