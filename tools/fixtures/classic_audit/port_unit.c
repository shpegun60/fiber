#include "fiber_port.c"

#if AUDIT_MPU
/* The same validated layout reaches this static check during real startup. */
void audit_vectors(void)
{
    FiberPortMpuMemoryLayout layout;
    fiber_port_mpu_load_linker_layout(&layout);
    fiber_port_mpu_linker_layout_check(&layout);
    fiber_port_validate_exception_vectors(&layout);
}
#endif
