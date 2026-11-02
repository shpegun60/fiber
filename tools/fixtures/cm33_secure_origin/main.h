#ifndef FIBER_CM33_SECURE_ORIGIN_MAIN_H
#define FIBER_CM33_SECURE_ORIGIN_MAIN_H
#define __MPU_PRESENT 0U
#define __FPU_PRESENT 0U
#define __VTOR_PRESENT 1U
/* AN505 QEMU exposes all eight implemented priority bits. */
#define __NVIC_PRIO_BITS 8U
#define __SAUREGION_PRESENT 1U
#define __DSP_PRESENT 1U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
#define __Vendor_SysTickConfig 0U
typedef enum IRQn {
    NonMaskableInt_IRQn=-14, HardFault_IRQn=-13, MemoryManagement_IRQn=-12,
    BusFault_IRQn=-11, UsageFault_IRQn=-10, SecureFault_IRQn=-9,
    SVCall_IRQn=-5, DebugMonitor_IRQn=-4, PendSV_IRQn=-2, SysTick_IRQn=-1,
    Device_IRQn=0
} IRQn_Type;
#include "core_cm33.h"
#endif
