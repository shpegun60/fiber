#ifndef FIBER_REVERSE_ABI_CONSTRUCTOR_MAIN_H_
#define FIBER_REVERSE_ABI_CONSTRUCTOR_MAIN_H_

#define __MPU_PRESENT 0U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 2U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 0U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U

typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5,
    DebugMonitor_IRQn = -4, PendSV_IRQn = -2, SysTick_IRQn = -1,
    DummyDevice_IRQn = 0
} IRQn_Type;

#include "core_cm7.h"
#endif
