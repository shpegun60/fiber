#include <stddef.h>
#include "FreeRTOS.h"
#include "task.h"

_Static_assert(configENABLE_MPU == 1 && configENABLE_FPU == 1 &&
        configENABLE_MVE == 0 && configENABLE_TRUSTZONE == 0 &&
        configRUN_FREERTOS_SECURE_ONLY == 0 && configENABLE_PAC == 0 &&
        configENABLE_BTI == 0 && configNUMBER_OF_CORES == 1, "reference manifest");
_Static_assert(portARMV8M_MINOR_VERSION == 0, "actual M33 dictionary");
_Static_assert(MAX_CONTEXT_SIZE == 54, "pinned 54-word backing");
_Static_assert(sizeof(((xMPU_SETTINGS *)0)->ulContext) == 216u, "pinned backing size");
_Static_assert(sizeof(MPURegionSettings_t) == 8u, "pinned region pair");
_Static_assert(portTOTAL_NUM_REGIONS == configTOTAL_MPU_REGIONS - 4u, "pinned context pairs");
_Static_assert(offsetof(xMPU_SETTINGS, ulMAIR0) == 0u, "pinned MAIR0");
_Static_assert(offsetof(xMPU_SETTINGS, xRegionsSettings) == 4u, "pinned regions");
_Static_assert(offsetof(xMPU_SETTINGS, ulContext) ==
        4u + (configTOTAL_MPU_REGIONS - 4u) * 8u, "pinned ulContext offset");

const uint32_t cm33f_reference_geometry[] __attribute__((used)) = {
    MAX_CONTEXT_SIZE, sizeof(((xMPU_SETTINGS *)0)->ulContext),
    offsetof(xMPU_SETTINGS, ulContext), portTOTAL_NUM_REGIONS,
    configTOTAL_MPU_REGIONS, portARMV8M_MINOR_VERSION
};
