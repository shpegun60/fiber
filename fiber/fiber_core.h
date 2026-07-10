/*
 * fiber_pendsv.h
 *
 *  Created on: Oct 13, 2025
 *      Author: admin
 */

#ifndef MCU_FIBER_FIBER_CORE_H_
#define MCU_FIBER_FIBER_CORE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "fiber_boot.h"

/* -------- Context --------
 * sp points to the last saved software frame. While this context is running,
 * the live stack pointer is PSP in the CPU. Ports update sp when saving the
 * context as the switch source, not when restoring it as the target.
 */
typedef struct FiberContext {
    uint32_t *sp;
    FiberBoot  boot;
} FiberContext;

#ifndef FIBER_SCHEDULER_PICK_NEXT_FN_DEFINED
#define FIBER_SCHEDULER_PICK_NEXT_FN_DEFINED
typedef FiberContext *(*FiberSchedulerPickNextFn)(FiberContext *current, void *user);
#endif

void fiber_init(FiberContext* const ctx,
			void* const stack_begin,
			void* const stack_end,
			const entry_t entry,
			void* const arg);

FiberContext* fiber_current(void);

FIBER_NORETURN
void fiber_start(FiberContext* const ctx);

void fiber_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next, void *user);

void fiber_schedule(void);

FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void);

#ifdef __cplusplus
} /* extern "C" */
#endif



#endif /* MCU_FIBER_FIBER_CORE_H_ */
