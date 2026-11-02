#include "fiber_portmacro.h"
#include "fiber_port_boot.h"
#include "fiber_port_secure_context_abi.h"
#include "../secure/fiber_secure_gateway_contract.h"
#ifdef __cplusplus
# define ASSERT static_assert
#else
# define ASSERT _Static_assert
#endif
ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0, "staged only");
ASSERT(FIBER_PORT_CONTEXT_ABI_PORT_ID == 0x43334653u, "C3FS");
ASSERT(FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION == 0x00010001u, "new generation1");
ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x8Bu, "scalar FP TZ features");
ASSERT(FIBER_PORT_CONTEXT_ABI_PORT_ID == FIBER_ARM_CM33F_SECURE_GATEWAY_CONTEXT_PORT_ID,
        "paired ID");
ASSERT(FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION == FIBER_ARM_CM33F_SECURE_GATEWAY_CONTEXT_LAYOUT_VERSION,
        "paired generation");
ASSERT(FIBER_PORT_INITIAL_CONTEXT_BYTES == 76u &&
        FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 216u &&
        FIBER_PORT_SOFTWARE_FRAME_WORDS == 11u &&
        FIBER_PORT_HIGH_FP_SOFTWARE_BYTES == 64u &&
        FIBER_PORT_EXC_PER_LEVEL_BYTES == 104u, "independent numeric geometry");
#ifdef fiber_portSECURE_ORIGIN_EXC_RETURN
# error "staged FP cohort must not admit guessed running Secure-origin literals"
#endif
void (*const c3fs_constructor_c_linkage)(FiberContext*,void*,void*,entry_t,void*) =
        fiber_port_context_init;
void (*const c3fs_attachment_c_linkage)(FiberContext*,size_t) = fiber_port_secure_context_attach;
