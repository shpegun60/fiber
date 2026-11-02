#include "fiber_port_private.h"

const uint32_t m33_closed_geometry[] = {
    FIBER_PORT_CONTEXT_ABI_PORT_ID,
    FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION,
    FIBER_PORT_CONTEXT_ABI_FEATURE_MASK,
    sizeof(FiberContext), sizeof(FiberPortBoot),
    offsetof(FiberContext, boot),
    offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_base),
    offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_top),
    FIBER_PORT_SOFTWARE_FRAME_WORDS, FIBER_PORT_INITIAL_CONTEXT_BYTES,
    FIBER_PORT_SAVED_SP_MOD8, FIBER_PORT_INITIAL_EXC_RETURN
};
