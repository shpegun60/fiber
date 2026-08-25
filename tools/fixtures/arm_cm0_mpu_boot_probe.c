/* Compile/link-only ARM_CM0_MPU slice-2 construction fixture. */

#include "fiber_port_boot.h"
#include "../../fiber/fiber_panic.h"

FIBER_PORT_CONTEXT_COHORT_DEFINE();

static FiberContext fiber_arm_cm0_mpu_probe_context;

__attribute__((aligned(256)))
static unsigned char fiber_arm_cm0_mpu_probe_stack[256];

static void fiber_arm_cm0_mpu_probe_entry(void *arg)
{
	(void)arg;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
	(void)code;
	for (;;) {
		__asm volatile("nop");
	}
}

/* This is a fixture-only definition for the slice-2 unresolved-surface link.
 * The real port-owned SVC veneer is intentionally deferred to slice 3. */
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_unprivileged_task_return(void)
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
	return (int)(encoded.rasr |
			fiber_arm_cm0_mpu_probe_context.boot.hash |
			fiber_arm_cm0_mpu_probe_context.protected_context.xpsr);
}
