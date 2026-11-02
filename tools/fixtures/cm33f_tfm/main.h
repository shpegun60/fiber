#ifndef C3FT_TEST_DEVICE_H
#define C3FT_TEST_DEVICE_H
#ifndef __MPU_PRESENT
#define __MPU_PRESENT 0U
#endif
#ifndef __VTOR_PRESENT
#define __VTOR_PRESENT 1U
#endif
#ifndef __NVIC_PRIO_BITS
#define __NVIC_PRIO_BITS 3U
#endif
#ifndef __FPU_PRESENT
#define __FPU_PRESENT 1U
#endif
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
#define __Vendor_SysTickConfig 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SecureFault_IRQn = -9,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, Device_IRQn = 0
} IRQn_Type;
#include "core_cm33.h"
#endif
