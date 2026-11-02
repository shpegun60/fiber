#include "fiber/fiber_core.h"
FiberContext c3so_public_context;
const size_t c3so_public_size = sizeof(FiberContext);
FiberContext *c3so_public_current(void)
{
    return fiber_current();
}
