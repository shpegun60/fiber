/* ARM_CM33_NTZ declarations shared only by construction/start objects. */
#ifndef FIBER_PORT_ARM_CM33_NTZ_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM33_NTZ_FIBER_PORT_PRIVATE_H_

#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "../../fiber_port_runtime_abi.h"
#include "../../../fiber_runtime_port_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

void fiber_port_init_context_frame(FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_context_validate_restore(FiberContext *ctx);
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

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
void fiber_port_start_first_context(uintptr_t msp_top);
FIBER_ATTR_NAKED_ASM void SVC_Handler(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_NTZ_FIBER_PORT_PRIVATE_H_ */
