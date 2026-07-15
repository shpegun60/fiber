/* ARM_CM0 declarations shared only by the selected port implementation. */
#ifndef FIBER_PORT_ARM_CM0_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM0_FIBER_PORT_PRIVATE_H_

#include "../fiber_port_select.h"
#include "fiber_portmacro.h"
#include "../fiber_port_context_cohort.h"
#include "../fiber_port_runtime_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

void fiber_port_init_context_frame(FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_restore(FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_save_current(const FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_port_context_prepare_first_start(FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_require_start_environment(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_require_start_interrupt_state(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_prepare(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_first_from_start(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_exception_runtime_check(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_pendsv_init_lowest_priority(void);

FIBER_NORETURN FIBER_ATTR_NAKED_ASM
void fiber_port_start_first_context(uintptr_t msp_top);
FIBER_ATTR_NAKED_ASM void SVC_Handler(void);
FIBER_ATTR_NAKED_ASM void PendSV_Handler(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM0_FIBER_PORT_PRIVATE_H_ */
