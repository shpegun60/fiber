#include "FreeRTOS.h"
_Static_assert(configENABLE_FPU == 1, "actual reference FPU must be enabled");
_Static_assert(configENABLE_MVE == 0 && configENABLE_MPU == 0, "actual reference scalar FP/non-MPU branch");
_Static_assert(configENABLE_TRUSTZONE == 0 && configRUN_FREERTOS_SECURE_ONLY == 0, "actual TF-M NTZ branch");
const unsigned char reference_configuration = 1;
