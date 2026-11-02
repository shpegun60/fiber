/* ARM_CM33F_MPU/non_secure selected-runtime private SVC/PendSV bridges. */
#ifndef FIBER_PORT_ARM_CM33F_MPU_NON_SECURE_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM33F_MPU_NON_SECURE_FIBER_PORT_PRIVATE_H_

#include "fiber_port_boot.h"
#include "../../fiber_port_runtime_abi.h"
#include "../../../fiber_api_decl.h"
#include "../../../fiber_runtime_port_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Common publishes `first` before the selected port reaches this private start
 * bridge. Entry is privileged Thread/MSP with all masks clear, MPU disabled,
 * and an integration-owned MSP stack disjoint from contexts. The mandatory
 * SVC/runtime object also retains the separate PendSV component. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_prepare_first_start(FiberContext *first);

/* Assembly passes raw MSP/B8 for first start, or PSP/BC/AC for a running
 * context. Only #71 returns; #70 restores and #72 invokes terminal policy. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_svc_dispatch(uint32_t *hardware_frame,
		uint32_t exc_return,
		FiberContext *current);

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_start_first_context(FiberContext *first);

/* Called only after dispatcher validation and global-image installation, with
 * PRIMASK=1 and MPU_CTRL=0. It installs the per-context image and performs the
 * basic first restore; it is not a general context-load operation. */
FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_restore_first_context_from_svc(FiberContext *first,
		uint32_t svc_exc_return);

FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void SVC_Handler(void);

/* Private CPU veneer, not a generic runtime adapter or portable operation. */
FIBER_API_ATTR_SENSITIVE FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
fiber_portSYSCALL_FUNCTION
void fiber_port_yield_from_thread(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_context_validate_restore(FiberContext *ctx);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_pendsv_validate_save_current(FiberContext *current,
		uint32_t *hardware_frame, uint32_t exc_return);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
FiberContext *fiber_port_scheduler_pick_first_from_start(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
uint32_t fiber_port_primask_save_disable(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_primask_restore(uint32_t primask);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_mpu_switch_to_context(FiberContext *next);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_mpu_validate_active_context(const FiberContext *ctx);

/* Mandatory SVC/runtime -> unique PendSV archive member, independently of
 * startup weak aliases. Both components retain their exact ABI dependencies. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_handler_bundle_v1_anchor(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor(void);

FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void PendSV_Handler(void);

extern const unsigned char fiber_port_svc_start_return_site[];
extern const unsigned char fiber_port_svc_yield_return_site[];
extern const unsigned char fiber_port_svc_return_return_site[];

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33F_MPU_NON_SECURE_FIBER_PORT_PRIVATE_H_ */
