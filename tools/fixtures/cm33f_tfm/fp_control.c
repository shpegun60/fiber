/* Valid explicit FP instruction, forbidden outside the actual context engine. */
#include "fiber_port_private.h"
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void forbidden_fp_control(void)
{
    fiber_portASM volatile("vmov.f32 s0, s0" ::: "memory");
}
