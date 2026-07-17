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

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
FiberContext *fiber_current(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_start(void);

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
		void *user);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void fiber_schedule(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_FIBER_API_DECL_H_ */
