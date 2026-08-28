/* ARM_CM33 TrustZone Non-secure implementation-private declarations. */
#ifndef FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_PRIVATE_H_

#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "../../fiber_port_runtime_abi.h"
#include "../../../fiber_runtime_port_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_init_context_frame(FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_prepare_first_start(FiberContext *ctx);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_secure_context_save_current_from_pendsv(
		FiberContext *current);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_secure_context_prepare_next_from_pendsv(
		FiberContext *next);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_load_next_from_pendsv(
		FiberContext *next,
		uint32_t handle);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_first_from_start(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current);

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
void fiber_port_start_first_context(uintptr_t msp_top);
FIBER_ATTR_NAKED_ASM void SVC_Handler(void);
FIBER_ATTR_NAKED_ASM void PendSV_Handler(void);

extern const unsigned char
fiber_port_arm_cm33_secure_context_handler_bundle_v1_anchor;
extern const unsigned char
fiber_port_arm_cm33_secure_context_attachment_bundle_v1_anchor;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_NON_SECURE_FIBER_PORT_PRIVATE_H_ */
