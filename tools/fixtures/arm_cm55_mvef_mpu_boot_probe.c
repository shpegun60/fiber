#include "fiber_port_boot.h"

FIBER_STATIC_ASSERT(fiber_portMPU_CONTEXT_STACK_INDEX == 0u,
		"ARM_CM55_MVEF_MPU stack pair must remain context index zero");
FIBER_STATIC_ASSERT(fiber_portMPU_STACK_REGION_NUMBER == 4u,
		"ARM_CM55_MVEF_MPU stack must program hardware region four");
FIBER_STATIC_ASSERT(fiber_portMPU_CURRENT_CONTEXT_REGION_NUMBER == 5u &&
		fiber_portMPU_CONTEXT_CURRENT_CONTEXT_INDEX == 1u,
		"ARM_CM55_MVEF_MPU current-slot aperture must occupy the second context pair");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_CONTEXT_WORDS == 54u &&
		fiber_portPROTECTED_BASIC_RESTORE_WORDS == 20u &&
		fiber_portPROTECTED_EXTENDED_RESTORE_WORDS == 53u,
		"ARM_CM55_MVEF_MPU protected MVE-FP context geometry changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedContext) == 216u,
		"ARM_CM55_MVEF_MPU protected MVE-FP image size changed");

fiber_portPRIVILEGED_DATA
static FiberContext fiber_arm_cm55_mvef_mpu_probe_context;

__attribute__((section(".fiber_test_unprivileged_ram"), aligned(32)))
static unsigned char fiber_arm_cm55_mvef_mpu_probe_stack[2048];

fiber_portUNPRIVILEGED_FUNCTION
static void fiber_arm_cm55_mvef_mpu_probe_entry(void *arg)
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

/* Mirror the common runtime object's dedicated input section. The linker proof
 * reserves its complete 32-byte aperture inside privileged SRAM. */
__attribute__((section(".bss.fiber_runtime_current_context_slot")))
FiberContext *volatile fiber_internal_runtime_current_context_slot;

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
int fiber_arm_cm55_mvef_mpu_boot_probe(void)
{
	FiberPortMpuGlobalRegionImage global_regions;
	FiberPortMpuRegionRegisters pxn_region;
	fiber_port_mpu_build_global_regions(&global_regions);
	if (fiber_port_mpu_try_encode_exact_region(0x08010000u, 0x08010020u,
			fiber_portMPU_FIRST_CONFIGURABLE_REGION_NUMBER,
			fiber_portMPU_REGION_READ_ONLY,
			fiber_portMPU_RLAR_ATTR_INDEX0 |
				fiber_portMPU_RLAR_PRIVILEGED_EXECUTE_NEVER,
			&pxn_region) == 0) {
		return -1;
	}
	fiber_port_context_init(&fiber_arm_cm55_mvef_mpu_probe_context,
			fiber_arm_cm55_mvef_mpu_probe_stack,
			fiber_arm_cm55_mvef_mpu_probe_stack +
				sizeof(fiber_arm_cm55_mvef_mpu_probe_stack),
			fiber_arm_cm55_mvef_mpu_probe_entry, (void *)0);
	fiber_port_context_validate_initial_restore(
			&fiber_arm_cm55_mvef_mpu_probe_context);
	fiber_internal_runtime_current_context_slot =
			&fiber_arm_cm55_mvef_mpu_probe_context;
	return (int)(global_regions.regions[
			fiber_portMPU_PRIVILEGED_DATA_REGION_NUMBER].rlar |
			pxn_region.rlar |
			fiber_arm_cm55_mvef_mpu_probe_context.boot.hash |
			(uint32_t)(uintptr_t)
			fiber_internal_runtime_current_context_slot);
}
