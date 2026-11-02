#ifndef LIFECYCLE_MCU_CORE_H_
#define LIFECYCLE_MCU_CORE_H_
#define __NVIC_PRIO_BITS 2U
#define __Vendor_SysTickConfig 0U
#define __MPU_PRESENT 0U
#define __FPU_PRESENT LIFECYCLE_FPU
#define __DSP_PRESENT 0U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
#define __VTOR_PRESENT LIFECYCLE_VTOR
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11, UsageFault_IRQn = -10,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4, PendSV_IRQn = -2,
    SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#if LIFECYCLE_CORE == 0
#include "core_cm0.h"
#elif LIFECYCLE_CORE == 1
#include "core_cm0plus.h"
#elif LIFECYCLE_CORE == 4
#include "core_cm4.h"
#elif LIFECYCLE_CORE == 7
#include "core_cm7.h"
#else
#error Unsupported fixture core
#endif
#endif
