#include <stdint.h>

#include "fiber_port_private.h"
#include "fiber_port_secure_context_abi.h"

static FiberContext fiber_arm_cm33_secure_context_probe_context;
static uint8_t fiber_arm_cm33_secure_context_probe_stack[256]
		__attribute__((aligned(8)));

static void fiber_arm_cm33_secure_context_probe_entry(void *arg)
{
	(void)arg;
}

void fiber_arm_cm33_secure_context_attach_probe(void)
{
	fiber_port_context_init(&fiber_arm_cm33_secure_context_probe_context,
			fiber_arm_cm33_secure_context_probe_stack,
			fiber_arm_cm33_secure_context_probe_stack +
				sizeof(fiber_arm_cm33_secure_context_probe_stack),
			fiber_arm_cm33_secure_context_probe_entry,
			(void *)(uintptr_t)0x1234u);
	fiber_port_secure_context_attach(
			&fiber_arm_cm33_secure_context_probe_context, 64u);
	fiber_port_boot_check(&fiber_arm_cm33_secure_context_probe_context.boot);
	fiber_port_context_initial_frame_check(
			&fiber_arm_cm33_secure_context_probe_context);
}
