#ifndef FIBER_CONSTRUCTOR_R9_MAIN_H
#define FIBER_CONSTRUCTOR_R9_MAIN_H

#ifndef R9_CORE
#error "Constructor fixture needs its exact CMSIS core dialect"
#endif
#ifndef R9_FPU
#error "Constructor fixture needs its physical FPU manifest"
#endif
#define __MPU_PRESENT 0U
#if R9_CORE == 0
#define __VTOR_PRESENT 0U
#else
#define __VTOR_PRESENT 1U
#endif
#define __NVIC_PRIO_BITS 3U
#define __FPU_PRESENT R9_FPU
#if R9_CORE == 4 || R9_CORE == 7 || R9_CORE == 33 || R9_CORE == 55
#define __DSP_PRESENT 1U
#else
#define __DSP_PRESENT 0U
#endif
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
#define __ITCM_PRESENT 0U
#define __DTCM_PRESENT 0U
#define __SAUREGION_PRESENT 1U
#define __Vendor_SysTickConfig 0U
#if R9_CORE == 55
#define __MVE_PRESENT 1U
#endif
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SecureFault_IRQn = -9,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, Device_IRQn = 0
} IRQn_Type;
#if R9_CORE == 0
#include "core_cm0.h"
#elif R9_CORE == 3
#include "core_cm3.h"
#elif R9_CORE == 4
#include "core_cm4.h"
#elif R9_CORE == 7
#include "core_cm7.h"
#elif R9_CORE == 23
#include "core_cm23.h"
#elif R9_CORE == 33
#include "core_cm33.h"
#elif R9_CORE == 55
#include "core_cm55.h"
#else
#error "Unsupported constructor fixture core"
#endif
#endif
