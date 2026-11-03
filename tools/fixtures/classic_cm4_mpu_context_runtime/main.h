#ifndef CLASSIC_CM4_MPU_PILOT_MAIN_H_
#define CLASSIC_CM4_MPU_PILOT_MAIN_H_
#if !defined(__ARM_ARCH_7EM__) || !defined(__ARM_FP) || __ARM_FP != 4 || !defined(__ARM_PCS_VFP)
#error "pilot requires Cortex-M4 fpv4-sp-d16 hard-float"
#endif
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 8U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 1U
#define __FPU_USED 1U
#define __DSP_PRESENT 1U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11, UsageFault_IRQn = -10,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4, PendSV_IRQn = -2, SysTick_IRQn = -1,
    Device_IRQn = 0
} IRQn_Type;
#include "core_cm4.h"
#endif
