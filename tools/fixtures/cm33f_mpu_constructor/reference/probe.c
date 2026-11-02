#include <stddef.h>
#include "FreeRTOS.h"
#include "task.h"

_Static_assert(configENABLE_MPU == 1 && configENABLE_FPU == 1 &&
        configENABLE_MVE == 0 && configENABLE_TRUSTZONE == 0 &&
        configENABLE_PAC == 0 && configENABLE_BTI == 0,
        "pinned M33 MPU/SP-FP manifest");
_Static_assert(MAX_CONTEXT_SIZE == 54, "actual pinned backing");
_Static_assert(portARMV8M_MINOR_VERSION == 0, "actual M33 architecture");

__attribute__((used, section(".reference_geometry")))
const uint32_t constructor_reference_geometry[] = {
    MAX_CONTEXT_SIZE, sizeof(((xMPU_SETTINGS *)0)->ulContext),
    offsetof(xMPU_SETTINGS, ulContext),
    offsetof(xMPU_SETTINGS, ulTaskFlags), sizeof(xMPU_SETTINGS),
    offsetof(xMPU_SETTINGS, xSystemCallStackInfo),
    offsetof(xMPU_SETTINGS, xSystemCallStackInfo.pulSystemCallStack),
    offsetof(xMPU_SETTINGS, xSystemCallStackInfo.pulSystemCallStackLimit),
    offsetof(xMPU_SETTINGS, xSystemCallStackInfo.pulTaskStack)
};

__attribute__((used, section(".reference_data"), aligned(8)))
xMPU_SETTINGS constructor_reference_settings;

__attribute__((used, noinline))
void constructor_reference_return(void)
{
    for (;;) { __asm volatile ("udf #2"); }
}
