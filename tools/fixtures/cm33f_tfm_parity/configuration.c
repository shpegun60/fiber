#include "FreeRTOS.h"
_Static_assert(configENABLE_FPU == 1, "actual reference FP branch required");
_Static_assert(configENABLE_MVE == 0 && configENABLE_MPU == 0, "non-MPU scalar FP reference required");
_Static_assert(configENABLE_TRUSTZONE == 0 && configRUN_FREERTOS_SECURE_ONLY == 0, "Non-secure NTZ reference required");
_Static_assert(__ARM_FP == 4, "single precision FP compiler manifest required");
const unsigned char c3ft_reference_configuration = 1;
