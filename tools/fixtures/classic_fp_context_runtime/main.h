#ifndef CLASSIC_FP_CONTEXT_RUNTIME_MAIN_H_
#define CLASSIC_FP_CONTEXT_RUNTIME_MAIN_H_

/* This manifest is for QEMU mps2-an386/Cortex-M4, not an STM32 board. */
#if !defined(__ARM_ARCH_7EM__) || !defined(__ARM_FP) || (__ARM_FP != 4) || \
        !defined(__ARM_PCS_VFP) || defined(__SOFTFP__)
#error "CM4F fixture requires Cortex-M4 hard-float fpv4-sp-d16"
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
#ifndef FIBER_SCHEDULER_BASEPRI
#define FIBER_SCHEDULER_BASEPRI 0x80u
#endif

typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5,
    DebugMonitor_IRQn = -4, PendSV_IRQn = -2, SysTick_IRQn = -1,
    Device_IRQn = 0
} IRQn_Type;
#include "core_cm4.h"
#endif
