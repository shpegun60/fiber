#include <stddef.h>
#include <stdint.h>

#include "fiber_port_private.h"

fiber_portPRIVILEGED_DATA
static FiberContext fiber_arm_cm55_mpu_first_start_context;

const unsigned char fiber_internal_runtime_port_abi_v1_anchor =
		(unsigned char)FIBER_RUNTIME_PORT_ABI_VERSION;

__attribute__((section(".fiber_test_unprivileged_ram"), aligned(32)))
static unsigned char fiber_arm_cm55_mpu_first_start_stack[2048];

fiber_portUNPRIVILEGED_FUNCTION
static void fiber_arm_cm55_mpu_first_start_entry(void *arg)
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

/* This fixture mirrors the common-owned input section. The selected port
 * reaches it only from SVC assembly, never through a C declaration. */
__attribute__((section(".bss.fiber_runtime_current_context_slot")))
FiberContext *volatile fiber_internal_runtime_current_context_slot;

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_runtime_select_scheduler_candidate(
		FiberContext *current)
{
	return current;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_publish_current_context(FiberContext *next)
{
	fiber_internal_runtime_current_context_slot = next;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_runtime_require_current_context(void)
{
	FIBER_REQUIRE(fiber_internal_runtime_current_context_slot != NULL, 'G');
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_task_return(void)
{
	for (;;) {
		__asm volatile("nop");
	}
}

__attribute__((used, section(".fiber_test_vectors"), aligned(128)))
const uintptr_t fiber_arm_cm55_mpu_first_start_vectors[16] = {
	[0] = (uintptr_t)UINT32_C(0x30010000),
	[11] = (uintptr_t)&SVC_Handler,
	[14] = (uintptr_t)&PendSV_Handler
};

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
int fiber_arm_cm55_mpu_first_start_probe(void)
{
	fiber_port_context_init(&fiber_arm_cm55_mpu_first_start_context,
			fiber_arm_cm55_mpu_first_start_stack,
			fiber_arm_cm55_mpu_first_start_stack +
				sizeof(fiber_arm_cm55_mpu_first_start_stack),
			fiber_arm_cm55_mpu_first_start_entry, (void *)0);
	fiber_internal_runtime_current_context_slot =
			&fiber_arm_cm55_mpu_first_start_context;
	fiber_port_prepare_first_start(&fiber_arm_cm55_mpu_first_start_context);
	return (int)(fiber_arm_cm55_mpu_first_start_context.mair0 |
			(uint32_t)(uintptr_t)fiber_internal_runtime_current_context_slot);
}
