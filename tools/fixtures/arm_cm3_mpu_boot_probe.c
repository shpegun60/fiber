#include "fiber_port_private.h"
#include "../../fiber/fiber_panic.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

fiber_portPRIVILEGED_DATA
static FiberContext fiber_arm_cm3_mpu_probe_context;

FiberContext *volatile fiber_internal_runtime_current_context_slot
		__attribute__((section(".bss.fiber_runtime_current_context_slot"))) = 0;

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
FiberContext *fiber_internal_runtime_select_scheduler_candidate(
		FiberContext *current)
{
	return current;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_runtime_publish_current_context(FiberContext *next)
{
	fiber_internal_runtime_current_context_slot = next;
}

__attribute__((section(".fiber_test_unprivileged_ram"), aligned(2048)))
static unsigned char fiber_arm_cm3_mpu_probe_stack[2048];

fiber_portUNPRIVILEGED_FUNCTION
static void fiber_arm_cm3_mpu_probe_entry(void *arg)
{
	(void)arg;
}

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

FIBER_USED __attribute__((section(".isr_vector")))
const uintptr_t fiber_arm_cm3_mpu_probe_vectors[16] = {
	[0] = (uintptr_t)0x20020000u,
	[11] = (uintptr_t)&SVC_Handler,
	[14] = (uintptr_t)&PendSV_Handler
};

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
int fiber_arm_cm3_mpu_boot_probe(void)
{
	FiberPortMpuGlobalRegionImage global_regions;
	fiber_port_mpu_build_global_regions(&global_regions);
	fiber_port_context_init(&fiber_arm_cm3_mpu_probe_context,
			fiber_arm_cm3_mpu_probe_stack,
			fiber_arm_cm3_mpu_probe_stack +
				sizeof(fiber_arm_cm3_mpu_probe_stack),
			fiber_arm_cm3_mpu_probe_entry,
			(void *)0);
	const uintptr_t retained_svc_slice =
			(uintptr_t)&fiber_port_start_first_context ^
			(uintptr_t)&fiber_port_runtime_schedule ^
			(uintptr_t)&fiber_port_unprivileged_task_return ^
			(uintptr_t)&SVC_Handler ^
			(uintptr_t)&PendSV_Handler;
	return (int)(global_regions.regions[0].rasr |
			fiber_arm_cm3_mpu_probe_context.boot.hash |
			(uint32_t)retained_svc_slice);
}
