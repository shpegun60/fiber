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

/* -------- Context -------- */
typedef struct FiberContext {
    uint32_t *sp;
    FiberBoot  boot;
} FiberContext;

void fiber_init(FiberContext* const ctx,
			void* const stack_begin,
			void* const stack_end,
			const entry_t entry,
			void* const arg);

void fiber_switch(FiberContext* const from, FiberContext* const to);

FIBER_ATTR_NAKED_ASM
void fiber_pendsv(void);

#ifdef __cplusplus
} /* extern "C" */
#endif



#endif /* MCU_FIBER_FIBER_CORE_H_ */
