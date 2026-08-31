#include <stdint.h>

#include "fiber_port_private.h"

fiber_portPRIVILEGED_DATA
static FiberContext fiber_arm_cm55f_mpu_svc_context;

const unsigned char fiber_internal_runtime_port_abi_v1_anchor =
		(unsigned char)FIBER_RUNTIME_PORT_ABI_VERSION;

__attribute__((section(".fiber_test_unprivileged_ram"), aligned(32)))
static unsigned char fiber_arm_cm55f_mpu_svc_stack[2048];

fiber_portUNPRIVILEGED_FUNCTION
static void fiber_arm_cm55f_mpu_svc_entry(void *arg)
{
	(void)arg;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_panic(char code)
{
	(void)code;
	for (;;) {
		__asm volatile("nop");
	}
}

/* This fixture is the only C owner of the common slot. The port reaches it
 * from SVC assembly through the frozen assembly-visible symbol only. */
__attribute__((section(".bss.fiber_runtime_current_context_slot")))
FiberContext *volatile fiber_internal_runtime_current_context_slot;

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_runtime_require_current_context(void)
{
	FIBER_REQUIRE(fiber_internal_runtime_current_context_slot != NULL, 'G');
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_task_return(void)
{
	fiber_panic('R');
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
FiberContext *fiber_current(void)
{
	return fiber_internal_runtime_current_context_slot;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void fiber_schedule(void)
{
	fiber_port_runtime_schedule();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
FiberContext *fiber_internal_runtime_select_scheduler_candidate(
		FiberContext *current)
{
	return current != NULL ? current : &fiber_arm_cm55f_mpu_svc_context;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_runtime_publish_current_context(FiberContext *next)
{
	FIBER_REQUIRE(next != NULL, 'N');
	fiber_internal_runtime_current_context_slot = next;
}

__attribute__((used, section(".fiber_test_vectors"), aligned(128)))
const uintptr_t fiber_arm_cm55f_mpu_svc_vectors[16] = {
	[0] = (uintptr_t)UINT32_C(0x30010000),
	[11] = (uintptr_t)&SVC_Handler,
	[14] = (uintptr_t)&PendSV_Handler
};

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
int fiber_arm_cm55f_mpu_svc_probe(void)
{
	fiber_port_context_init(&fiber_arm_cm55f_mpu_svc_context,
			fiber_arm_cm55f_mpu_svc_stack,
			fiber_arm_cm55f_mpu_svc_stack +
				sizeof(fiber_arm_cm55f_mpu_svc_stack),
			fiber_arm_cm55f_mpu_svc_entry, (void *)0);
	fiber_internal_runtime_current_context_slot =
			&fiber_arm_cm55f_mpu_svc_context;
	fiber_port_prepare_first_start(&fiber_arm_cm55f_mpu_svc_context);
	return (int)(fiber_arm_cm55f_mpu_svc_context.mair0 |
			(uint32_t)(uintptr_t)fiber_internal_runtime_current_context_slot);
}
