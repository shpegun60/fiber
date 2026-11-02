#ifndef C5SO_RUNTIME_MAIN_H
#define C5SO_RUNTIME_MAIN_H
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#ifndef EXEC_NVIC_PRIO_BITS
#define EXEC_NVIC_PRIO_BITS 3U
#endif
#define __NVIC_PRIO_BITS EXEC_NVIC_PRIO_BITS
#define __FPU_PRESENT 1U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
#define __PMU_PRESENT 0U
#define __Vendor_SysTickConfig 0U
typedef enum IRQn {
    NonMaskableInt_IRQn=-14,HardFault_IRQn=-13,MemoryManagement_IRQn=-12,
    BusFault_IRQn=-11,UsageFault_IRQn=-10,SecureFault_IRQn=-9,SVCall_IRQn=-5,
    DebugMonitor_IRQn=-4,PendSV_IRQn=-2,SysTick_IRQn=-1,Device_IRQn=0
} IRQn_Type;
#include "core_cm55.h"
#endif
