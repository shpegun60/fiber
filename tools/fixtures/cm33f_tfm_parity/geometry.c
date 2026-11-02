/* Numeric view of actual selected headers; not a runtime provider. */
#include "fiber_port_private.h"
const uint32_t c3ft_parity_geometry[] = {
    sizeof(FiberContext), sizeof(FiberPortBoot),
    offsetof(FiberContext, sp), offsetof(FiberContext, boot),
    offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_base),
    offsetof(FiberContext, boot) + offsetof(FiberPortBoot, stack_top),
    offsetof(FiberContext, boot) + offsetof(FiberPortBoot, entry),
    offsetof(FiberContext, boot) + offsetof(FiberPortBoot, arg),
    FIBER_PORT_CONTEXT_ABI_PORT_ID, FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION,
    FIBER_PORT_CONTEXT_ABI_FEATURE_MASK, FIBER_PORT_INITIAL_CONTEXT_BYTES,
    FIBER_PORT_SOFTWARE_FRAME_BYTES, fiber_portINITIAL_EXC_RETURN,
    fiber_portEXTENDED_EXC_RETURN, FIBER_PORT_MAX_SAVED_CONTEXT_BYTES,
    FIBER_PORT_EXC_BASE_BYTES, FIBER_PORT_EXC_FP_EXT_BYTES,
    FIBER_PORT_HIGH_FP_SOFTWARE_BYTES, FIBER_PORT_RUNTIME_SELECTABLE, FIBER_FPU_LAZY
};
