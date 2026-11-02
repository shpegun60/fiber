#ifndef FIBER_MPU_START_POLICY_MAIN_H
#define FIBER_MPU_START_POLICY_MAIN_H
#define __MPU_PRESENT 1U
#define __VTOR_PRESENT REWIND_VTOR
#define __NVIC_PRIO_BITS 3U
#define __Vendor_SysTickConfig 0U
#if REWIND_FP
#define __FPU_PRESENT 1U
#define __FPU_USED 1U
#else
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#endif
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
#define __SAUREGION_PRESENT 1U
#if REWIND_CORE >= 4
#define __DSP_PRESENT 1U
#else
#define __DSP_PRESENT 0U
#endif
typedef enum IRQn {
    NonMaskableInt_IRQn=-14, HardFault_IRQn=-13,
    MemoryManagement_IRQn=-12, BusFault_IRQn=-11,
    UsageFault_IRQn=-10, SecureFault_IRQn=-9, SVCall_IRQn=-5,
    DebugMonitor_IRQn=-4, PendSV_IRQn=-2, SysTick_IRQn=-1,
    DummyDevice_IRQn=0
} IRQn_Type;
#if REWIND_CORE == 0
#include "core_cm0plus.h"
#elif REWIND_CORE == 3
#include "core_cm3.h"
#elif REWIND_CORE == 4
#include "core_cm4.h"
#elif REWIND_CORE == 7
#include "core_cm7.h"
#elif REWIND_CORE == 33
#include "core_cm33.h"
#elif REWIND_CORE == 55
#include "core_cm55.h"
#else
#error "Select a supported MPU start-policy device"
#endif
#endif
