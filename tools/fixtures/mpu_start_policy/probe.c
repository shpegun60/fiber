#include "mcu_core.h"
#include "fiber_portmacro.h"

unsigned int mpu_start_policy_probe(void)
{
    return FIBER_REWIND_MSP;
}
