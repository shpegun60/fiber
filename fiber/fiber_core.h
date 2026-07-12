/*
 * fiber_core.h
 *
 * Public cooperative fiber runtime API.
 */

#ifndef MCU_FIBER_FIBER_CORE_H_
#define MCU_FIBER_FIBER_CORE_H_

#include "port/fiber_port_selected.h"
#include "fiber_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void fiber_init(FiberContext* const ctx,
			void* const stack_begin,
			void* const stack_end,
			const entry_t entry,
			void* const arg);

FiberContext* fiber_current(void);

FIBER_NORETURN
void fiber_start(void);

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next, void *user);

void fiber_schedule(void);

#ifdef __cplusplus
} /* extern "C" */
#endif



#endif /* MCU_FIBER_FIBER_CORE_H_ */
