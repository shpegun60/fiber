#ifndef CLASSIC_CONTEXT_RUNTIME_MAIN_H_
#define CLASSIC_CONTEXT_RUNTIME_MAIN_H_

/* QEMU microbit is Cortex-M0 (not Cortex-M0+) with no VTOR or FPU. */
#if !defined(__ARM_ARCH_6M__)
#error "classic Context runtime fixture requires Cortex-M0 ARMv6-M"
#endif
#define __MPU_PRESENT 0U
#define __VTOR_PRESENT 0U
#define __NVIC_PRIO_BITS 2U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 0U

typedef enum IRQn {
    NonMaskableInt_IRQn = -14,
    HardFault_IRQn = -13,
    SVCall_IRQn = -5,
    PendSV_IRQn = -2,
    SysTick_IRQn = -1,
    Device_IRQn = 0
} IRQn_Type;

#include "core_cm0.h"
#endif
