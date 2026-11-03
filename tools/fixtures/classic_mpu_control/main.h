#ifndef CLASSIC_MPU_CONTROL_MAIN_H
#define CLASSIC_MPU_CONTROL_MAIN_H
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT CONTROL_VTOR
#define __NVIC_PRIO_BITS 4U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT CONTROL_FP
#define __DSP_PRESENT CONTROL_FP
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, Device_IRQn = 0
} IRQn_Type;
#if CONTROL_CORE == 0
#include "core_cm0plus.h"
#elif CONTROL_CORE == 3
#include "core_cm3.h"
#elif CONTROL_CORE == 4
#include "core_cm4.h"
#elif CONTROL_CORE == 7
#include "core_cm7.h"
#else
#error unsupported CONTROL regression target
#endif
#endif
