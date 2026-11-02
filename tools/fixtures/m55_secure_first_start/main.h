#ifndef C55S_FIRST_START_MAIN_H
#define C55S_FIRST_START_MAIN_H
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 3U
#define __FPU_PRESENT 0U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
#define __Vendor_SysTickConfig 0U
typedef enum IRQn {
    NonMaskableInt_IRQn=-14, HardFault_IRQn=-13,
    MemoryManagement_IRQn=-12, BusFault_IRQn=-11,
    UsageFault_IRQn=-10, SecureFault_IRQn=-9,
    SVCall_IRQn=-5, DebugMonitor_IRQn=-4,
    PendSV_IRQn=-2, SysTick_IRQn=-1, Device_IRQn=0
} IRQn_Type;
#include "core_cm55.h"
#endif
