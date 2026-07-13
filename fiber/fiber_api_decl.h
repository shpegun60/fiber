/*
 * fiber_api_decl.h
 *
 * Public callable declarations using only opaque API types.
 */

#ifndef FIBER_FIBER_API_DECL_H_
#define FIBER_FIBER_API_DECL_H_

#include "fiber_api_attributes.h"
#include "fiber_api_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void fiber_init(FiberContext *ctx,
		void *stack_begin,
		void *stack_end,
		entry_t entry,
		void *arg);

FiberContext *fiber_current(void);

FIBER_API_NORETURN
void fiber_start(void);

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
		void *user);

void fiber_schedule(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_API_DECL_H_ */
