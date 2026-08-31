#include <stddef.h>

#include "fiber_portmacro.h"

FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM55 Slice 1 must remain non-runtime");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_SECURITY_EXT == 1,
		"[fiber]: ARM_CM55 requires the Security Extension");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNS_NONSECURE == 1,
		"[fiber]: ARM_CM55 must remain a Non-secure profile");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_SECURE_CONTEXT_SLOT == 1,
		"[fiber]: ARM_CM55 must reserve the SecureContext frame slot");
FIBER_STATIC_ASSERT(FIBER_PORT_SOFTWARE_FRAME_WORDS == 11u,
		"[fiber]: ARM_CM55 software frame word count changed");
FIBER_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX == 2u,
		"[fiber]: ARM_CM55 EXC_RETURN frame index changed");
FIBER_STATIC_ASSERT(FIBER_PORT_INITIAL_CONTEXT_BYTES == 76u,
		"[fiber]: ARM_CM55 initial context geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 80u,
		"[fiber]: ARM_CM55 maximum context geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_SAVED_SP_MOD8 == 4u,
		"[fiber]: ARM_CM55 saved SP alignment changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x8Au,
		"[fiber]: ARM_CM55 context feature identity changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) == 76u,
		"[fiber]: ARM_CM55 boot record size changed");
FIBER_STATIC_ASSERT(sizeof(FiberContext) == 80u,
		"[fiber]: ARM_CM55 context size changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, secure_stack_bytes) == 28u,
		"[fiber]: ARM_CM55 secure-stack request offset changed");

int fiber_arm_cm55_secure_context_layout_probe(void)
{
	return (int)(sizeof(FiberContext) + sizeof(FiberPortBoot));
}
