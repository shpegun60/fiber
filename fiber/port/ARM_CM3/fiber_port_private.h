/* ARM_CM3 declarations shared only by the selected port implementation. */
#ifndef FIBER_PORT_ARM_CM3_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM3_FIBER_PORT_PRIVATE_H_

#include "fiber_portmacro.h"
#include "../fiber_port_runtime_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

FIBER_NORETURN void fiber_internal_task_return(void);

void fiber_port_init_context_frame(FiberContext *ctx);
FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_restore(FiberContext *ctx);
FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_save_current(const FiberContext *ctx);
uintptr_t fiber_port_context_prepare_first_start(FiberContext *ctx);
void fiber_port_require_start_environment(void);
void fiber_port_require_start_interrupt_state(void);
void fiber_port_runtime_prepare(void);

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_first_from_start(void);
FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current);

void fiber_exception_runtime_check(void);
void fiber_pendsv_init_lowest_priority(void);

FIBER_NORETURN FIBER_ATTR_NAKED_ASM
void fiber_port_start_first_context(uintptr_t msp_top);
FIBER_ATTR_NAKED_ASM void fiber_svc(void);
FIBER_ATTR_NAKED_ASM void fiber_pendsv(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM3_FIBER_PORT_PRIVATE_H_ */
