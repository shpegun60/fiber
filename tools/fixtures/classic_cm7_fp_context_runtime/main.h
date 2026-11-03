#ifndef CLASSIC_CM7_FP_CONTEXT_RUNTIME_MAIN_H_
#define CLASSIC_CM7_FP_CONTEXT_RUNTIME_MAIN_H_

/* QEMU mps2-an500/Cortex-M7 r1p2, not an STM32 board. NVIC8 is model-specific.
 * Executing the r0p1 backend here is not erratum 837070 silicon validation;
 * this fixture makes no hardware, cache, TCM or STM32 peripheral claim. */
#if !defined(__ARM_ARCH_7EM__) || !defined(__ARM_FP) || (__ARM_FP != 14) || \
        !defined(__ARM_PCS_VFP) || defined(__SOFTFP__)
#error "CM7F fixture requires Cortex-M7 hard-float fpv5-d16"
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
#define __ITCM_PRESENT 0U
#define __DTCM_PRESENT 0U
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
#include "core_cm7.h"
#endif
