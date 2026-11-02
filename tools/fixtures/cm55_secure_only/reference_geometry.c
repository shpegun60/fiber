#include "FreeRTOS.h"
#include "task.h"
const uint32_t c5so_reference_geometry[] = {
    portBYTE_ALIGNMENT, configRUN_FREERTOS_SECURE_ONLY,
    configENABLE_TRUSTZONE, configENABLE_MPU, configENABLE_FPU,
    configENABLE_MVE, configENABLE_PAC, configENABLE_BTI
};
