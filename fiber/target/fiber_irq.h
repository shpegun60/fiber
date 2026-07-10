/*
 * fiber_irq_init.h
 *
 *  Created on: Oct 14, 2025
 *      Author: admin
 */

#ifndef MCU_FIBER_TARGET_FIBER_IRQ_INIT_H_
#define MCU_FIBER_TARGET_FIBER_IRQ_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

void fiber_exception_runtime_check(void);

void fiber_pendsv_init_lowest_priority(void);

#ifdef __cplusplus
} /* extern "C" */
#endif


#endif /* MCU_FIBER_TARGET_FIBER_IRQ_INIT_H_ */
