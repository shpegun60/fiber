/* ARM_CM55 scalar SecureContext private transfer/runtime contract. */
#ifndef FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_PRIVATE_H_
#define FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_PRIVATE_H_

#include "fiber_port_boot.h"
#include "../../../fiber_runtime_port_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The integration publishes first before entry. Entry is privileged Thread/MSP,
 * all masks clear, with a trusted, reserved exception/C stack. This does not
 * promise containment of arbitrary physical MSP corruption. The component
 * entry remains private; application code uses the common five-operation API. */
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_first_start(FiberContext *first);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uintptr_t fiber_port_prepare_first_start(FiberContext *first);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_prepare_start_environment(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_validate_first_candidate(FiberContext *first);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_arm_cm55_secure_context_first_start_component_v1_anchor(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_arm_cm55_secure_context_pendsv_component_v1_anchor(void);

FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
void fiber_port_start_first_context(uintptr_t msp_top);

FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
void SVC_Handler(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_svc_dispatch(uint32_t *hardware_frame, uint32_t exc_return,
		FiberContext *current);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_prepare_first_start(FiberContext *ctx);

/* After validated frame and Secure state, restore special registers and only
 * then r4-r11. No C call is reachable after that final GPR load. */
FIBER_API_NORETURN FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
void fiber_port_restore_first_context_from_svc(FiberContext *ctx);

/* Private serialized running slice. Integration owns trusted reserved MSP,
 * immutable vectors/code, lowest-priority NS PendSV, and IRQ hook discipline.
 * Only BC (NS origin) and FC (Secure origin) are admitted: DCRS=1, basic
 * Thread/NS-PSP, ES=0. Secure origin uses only a three-word NS header; its
 * hardware and callee-saved frame is Secure and must not be decoded here.
 * All failures after Secure save/load or allocation are terminal, not retryable.
 * Common retains scheduler storage and publication ownership. */
typedef struct FiberPortRunningCpuState {
	uint32_t ipsr, control, primask, basepri, faultmask, psplim, psp;
} FiberPortRunningCpuState;

#define FIBER_PORT_CM55_SECURE_ORIGIN_EXC_RETURN UINT32_C(0xFFFFFFFC)
#define FIBER_PORT_CM55_SECURE_HEADER_BYTES 12u

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_running_cpu_capture(FiberPortRunningCpuState *state);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_running_cpu_check(const FiberPortRunningCpuState *before);
FIBER_ATTR_NAKED_ASM FIBER_GENERAL_REGS_ONLY
void PendSV_Handler(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_pendsv_prepare_save(FiberContext *current,
		uintptr_t psp, uint32_t exc_return);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_scheduler_pick_next_from_pendsv(FiberContext *current);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_pendsv_prepare_next(FiberContext *next);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_pendsv_load_next(FiberContext *next, uint32_t handle);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_secure_context_save_current_from_pendsv(
		FiberContext *current, uintptr_t psp, uint32_t exc_return);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_secure_context_prepare_next_from_pendsv(FiberContext *next);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_secure_context_load_next_from_pendsv(FiberContext *next,
		uint32_t handle);

extern const unsigned char __fiber_c55s_ns_vector_start__[];
extern const unsigned char __fiber_c55s_ns_vector_end__[];
extern const unsigned char __fiber_c55s_ns_start_code_start__[];
extern const unsigned char __fiber_c55s_ns_start_code_end__[];
extern const unsigned char __fiber_c55s_ns_msp_stack_start__[];
extern const unsigned char __fiber_c55s_ns_msp_stack_end__[];
/* Even architectural stacked PC, not a callable Thumb function pointer. */
extern const unsigned char fiber_port_c55s_first_start_svc_return[];

#define FIBER_PORT_CM55_FIRST_START_MSP_RESERVE 2048u

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* FIBER_PORT_ARM_CM55_NON_SECURE_FIBER_PORT_PRIVATE_H_ */
