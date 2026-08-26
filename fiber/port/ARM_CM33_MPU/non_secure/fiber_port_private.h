/* ARM_CM33_MPU/non_secure declarations private to its protected runtime. */
#ifndef FIBER_PORT_ARM_CM33_MPU_NON_SECURE_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM33_MPU_NON_SECURE_FIBER_PORT_PRIVATE_H_

#include "fiber_port_boot.h"
#include "../../fiber_port_context_cohort.h"
#include "../../../fiber_runtime_port_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This staged profile owns protected SVC/PendSV mechanics but deliberately
 * exposes neither the forward runtime ABI nor a public MPU-management API. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_prepare_first_start(FiberContext *first);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_svc_dispatch(uint32_t *hardware_frame,
		uint32_t exc_return,
		FiberContext *current);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_context_validate_restore(FiberContext *ctx);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_pendsv_validate_save_current(FiberContext *current,
		uint32_t *hardware_frame,
		uint32_t exc_return);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(
		FiberContext *current);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_mpu_switch_to_context(FiberContext *next);

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_start_first_context(FiberContext *first);

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portPRIVILEGED_FUNCTION
void fiber_port_restore_first_context_from_svc(FiberContext *first,
		uint32_t svc_exc_return);

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM
fiber_portSYSCALL_FUNCTION
void fiber_port_unprivileged_task_return(void);

/* Private staging veneer only. It is intentionally not part of the public
 * forward ABI until this complete protected runtime becomes selectable. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FIBER_ATTR_NAKED_ASM fiber_portSYSCALL_FUNCTION
void fiber_port_unprivileged_yield(void);

FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void SVC_Handler(void);

FIBER_ATTR_NAKED_ASM fiber_portPRIVILEGED_FUNCTION
void PendSV_Handler(void);

/* Exact post-SVC continuation markers are provenance data, never API. */
extern const unsigned char fiber_port_svc_start_return_site[];
extern const unsigned char fiber_port_svc_yield_return_site[];
extern const unsigned char fiber_port_svc_return_return_site[];

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_MPU_NON_SECURE_FIBER_PORT_PRIVATE_H_ */
