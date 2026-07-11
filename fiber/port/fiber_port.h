/*
 * fiber_port.h
 *
 * Internal Cortex-M port boundary used by the common fiber runtime.
 */

#ifndef FIBER_PORT_FIBER_PORT_H_
#define FIBER_PORT_FIBER_PORT_H_

#include "fiber_port_types.h"
#include "../target/fiber_target.h"
#include "fiber_port_boot_record.h"
#include "fiber_port_selected.h"
#include "fiber_port_state.h"
#include "common/fiber_port_primask.h"

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

__STATIC_FORCEINLINE uint32_t fiber_port_scheduler_critical_enter(void)
{
#if FIBER_HAS_BASEPRI
	const uint32_t scheduler_basepri = (uint32_t)FIBER_SCHEDULER_BASEPRI;
	const uint32_t old_basepri = fiber_basepri_read();
	fiber_basepri_write(scheduler_basepri);
	return old_basepri;
#else
	return fiber_port_primask_save_disable();
#endif
}

__STATIC_FORCEINLINE void fiber_port_scheduler_critical_exit(uint32_t state)
{
#if FIBER_HAS_BASEPRI
	fiber_basepri_write(state);
#else
	fiber_port_primask_restore(state);
#endif
}

__STATIC_FORCEINLINE void fiber_port_pend_switch(void)
{
	SCB->ICSR = SCB_ICSR_PENDSVSET_Msk;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_FIBER_PORT_H_ */
