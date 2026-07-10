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
__STATIC_FORCEINLINE uint32_t fiber_port_read_r9(void)
{
	uint32_t v;
	__ASM volatile("mov %0, r9" : "=r"(v));
	return v;
}

__STATIC_FORCEINLINE uint32_t fiber_port_initial_xpsr(void)
{
	return 0x01000000u;
}

__STATIC_FORCEINLINE uint32_t fiber_port_stacked_pc(uintptr_t entry)
{
	return (uint32_t)(entry & ~(uintptr_t)1u);
}

FIBER_NORETURN
void fiber_internal_task_return(void);

void fiber_port_init_context_frame(FiberContext *ctx);

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

#if FIBER_START_USE_SVC
FIBER_NORETURN
void fiber_port_start_first_context(uintptr_t msp_top);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_FIBER_PORT_H_ */
