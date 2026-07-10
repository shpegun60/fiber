/*
 * fiber_port.h
 *
 * Internal Cortex-M port boundary used by the common fiber runtime.
 */

#ifndef FIBER_PORT_FIBER_PORT_H_
#define FIBER_PORT_FIBER_PORT_H_

#include "fiber_port_state.h"
#include "../target/fiber_target.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Common runtime owns when these helpers are called. The port layer owns the
 * exact CPU-visible state slots and the PendSV trigger mechanism.
 */
__STATIC_FORCEINLINE FiberContext *fiber_port_load_current_context(void)
{
	__COMPILER_BARRIER();
	return fiber_internal_port_current_context;
}

__STATIC_FORCEINLINE void fiber_port_seed_current_context(FiberContext *ctx)
{
	__DMB();
	fiber_internal_port_current_context = ctx;
	__DMB();
}

__STATIC_FORCEINLINE void fiber_port_set_scheduler_pick_next(FiberSchedulerPickNextFn pick_next,
                                                             void *user)
{
	fiber_internal_port_scheduler_set_pick_next(pick_next, user);
}

__STATIC_FORCEINLINE uint32_t fiber_port_scheduler_is_configured(void)
{
	__COMPILER_BARRIER();
	return (fiber_internal_port_scheduler_pick_next != 0) ? 1u : 0u;
}

__STATIC_FORCEINLINE void fiber_port_pend_switch(void)
{
	SCB->ICSR = SCB_ICSR_PENDSVSET_Msk;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_FIBER_PORT_H_ */
