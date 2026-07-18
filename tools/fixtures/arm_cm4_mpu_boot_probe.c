#include "fiber_port_private.h"

fiber_portPRIVILEGED_DATA
static FiberContext fiber_arm_cm4_mpu_probe_context;

const unsigned char fiber_internal_runtime_port_abi_v1_anchor =
		(unsigned char)FIBER_RUNTIME_PORT_ABI_VERSION;

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
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_runtime_require_current_context(void)
{
	FIBER_REQUIRE(fiber_internal_runtime_current_context_slot != NULL, 'G');
}

__attribute__((section(".fiber_test_unprivileged_ram"), aligned(2048)))
static unsigned char fiber_arm_cm4_mpu_probe_stack[2048];

fiber_portUNPRIVILEGED_FUNCTION
static void fiber_arm_cm4_mpu_probe_entry(void *arg)
{
	(void)arg;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
int fiber_arm_cm4_mpu_boot_probe(void);

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_task_return(void)
{
	for (;;) {
		__asm volatile("nop");
	}
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

__attribute__((used, section(".isr_vector")))
const uintptr_t fiber_arm_cm4_mpu_probe_vectors[16] = {
	[0] = UINT32_C(0x2001FFF8),
	[1] = (uintptr_t)fiber_arm_cm4_mpu_boot_probe,
	[11] = (uintptr_t)SVC_Handler,
	[14] = (uintptr_t)PendSV_Handler
};

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
int fiber_arm_cm4_mpu_boot_probe(void)
{
	FiberPortMpuGlobalRegionImage global_regions;
	fiber_port_mpu_build_global_regions(&global_regions);
	fiber_port_context_init(&fiber_arm_cm4_mpu_probe_context,
			fiber_arm_cm4_mpu_probe_stack,
			fiber_arm_cm4_mpu_probe_stack +
				sizeof(fiber_arm_cm4_mpu_probe_stack),
			fiber_arm_cm4_mpu_probe_entry,
			(void *)0);
	fiber_internal_runtime_current_context_slot =
			&fiber_arm_cm4_mpu_probe_context;
	return (int)(global_regions.regions[0].rasr |
			fiber_arm_cm4_mpu_probe_context.boot.hash |
			(uint32_t)(uintptr_t)
			fiber_internal_runtime_current_context_slot);
}
