#include "fiber/fiber_core.h"
#include "fiber_port_secure_context_abi.h"
#ifdef __CORTEX_M
# error "public storage must not include CMSIS"
#endif
#ifdef __cplusplus
static_assert(sizeof(FiberContext) == 80 && alignof(FiberContext) == 4, "public C++ layout");
#else
_Static_assert(sizeof(FiberContext) == 80 && _Alignof(FiberContext) == 4, "public C layout");
#endif
FiberContext c3fs_consumer_storage;
