/* Compile/link/ELF-only ARM_CM0_MPU protected switch fixture. */

#include "fiber_port_private.h"
#include "../../fiber/fiber_panic.h"

static fiber_portPRIVILEGED_DATA
FiberContext fiber_arm_cm0_mpu_probe_context;

static fiber_portPRIVILEGED_DATA
FiberPortMpuGlobalRegionImage fiber_arm_cm0_mpu_probe_global_regions;

__attribute__((aligned(256), section(".fiber_test_unprivileged_ram")))
static unsigned char fiber_arm_cm0_mpu_probe_stack[256];

static fiber_portUNPRIVILEGED_FUNCTION
void fiber_arm_cm0_mpu_probe_entry(void *arg)
{
	(void)arg;
}

/* The fixture never executes this table. It gives the synthetic ELF concrete
 * direct SVC/PendSV routes so both selected handler slots can be audited before
 * board integration. */
typedef union FiberArmCm0MpuProbeVector {
	uintptr_t raw;
	void (*handler)(void);
} FiberArmCm0MpuProbeVector;

__attribute__((used, aligned(fiber_portVECTOR_ALIGNMENT),
		section(".fiber_test_vector_table")))
const FiberArmCm0MpuProbeVector fiber_arm_cm0_mpu_probe_vectors[16] = {
	[0] = { .raw = UINT32_C(0x2001FF00) },
	[fiber_portVECTOR_INDEX_SVC] = { .handler = SVC_Handler },
	[fiber_portVECTOR_INDEX_PENDSV] = { .handler = PendSV_Handler }
};

/* The non-selectable staged port invokes the frozen reverse ABI from PendSV.
 * Common runtime owns those functions; this fixture-only barrier resolves its
 * dependency without defining any forward operation in ARM_CM0_MPU itself. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_port_runtime_memory_barrier(void)
{
	__asm volatile("" ::: "memory");
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
	(void)code;
	for (;;) {
		__asm volatile("nop");
	}
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
fiber_portPRIVILEGED_FUNCTION
void fiber_internal_task_return(void)
{
	for (;;) {
		__asm volatile("nop");
	}
}

int fiber_arm_cm0_mpu_boot_probe(void)
{
	FiberPortMpuRegionRegisters encoded;
	if (fiber_port_mpu_try_encode_exact_region(
			(uintptr_t)fiber_arm_cm0_mpu_probe_stack,
			(uintptr_t)(fiber_arm_cm0_mpu_probe_stack +
				sizeof(fiber_arm_cm0_mpu_probe_stack)),
			fiber_portMPU_STACK_REGION,
			fiber_portMPU_DEFAULT_STACK_ATTRIBUTES, &encoded) == 0) {
		return -1;
	}

	fiber_port_context_init(&fiber_arm_cm0_mpu_probe_context,
			fiber_arm_cm0_mpu_probe_stack,
			fiber_arm_cm0_mpu_probe_stack +
				sizeof(fiber_arm_cm0_mpu_probe_stack),
			fiber_arm_cm0_mpu_probe_entry, (void *)0);
	fiber_port_context_seal_check(&fiber_arm_cm0_mpu_probe_context);
	fiber_port_mpu_build_global_regions(
			&fiber_arm_cm0_mpu_probe_global_regions);
	const uintptr_t retained_runtime_slice =
			(uintptr_t)&fiber_port_unprivileged_yield ^
			(uintptr_t)&PendSV_Handler;
	return (int)(encoded.rasr |
			fiber_arm_cm0_mpu_probe_context.boot.hash |
			fiber_arm_cm0_mpu_probe_context.protected_context.xpsr |
			fiber_arm_cm0_mpu_probe_global_regions.regions[0].rasr |
			(uint32_t)retained_runtime_slice);
}
