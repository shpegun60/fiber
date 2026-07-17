#include "fiber_port_boot.h"
#include "../fiber_port_context_cohort.h"
#include "../../fiber/fiber_panic.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

fiber_portPRIVILEGED_DATA
static FiberContext fiber_arm_cm4_mpu_probe_context;

__attribute__((section(".bss.fiber_runtime_current_context_slot")))
static volatile FiberContext *fiber_arm_cm4_mpu_probe_current;

__attribute__((section(".fiber_test_unprivileged_ram"), aligned(2048)))
static unsigned char fiber_arm_cm4_mpu_probe_stack[2048];

fiber_portUNPRIVILEGED_FUNCTION
static void fiber_arm_cm4_mpu_probe_entry(void *arg)
{
	(void)arg;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portUNPRIVILEGED_FUNCTION
void fiber_port_unprivileged_task_return(void)
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
	fiber_arm_cm4_mpu_probe_current = &fiber_arm_cm4_mpu_probe_context;
	return (int)(global_regions.regions[0].rasr |
			fiber_arm_cm4_mpu_probe_context.boot.hash |
			(uint32_t)(uintptr_t)fiber_arm_cm4_mpu_probe_current);
}
