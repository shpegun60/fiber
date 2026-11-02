#ifndef FIBER_SENSITIVE_CLOSURE_MAIN_H
#define FIBER_SENSITIVE_CLOSURE_MAIN_H
#ifndef CLOSURE_CORE
#error "Exact CMSIS core required"
#endif
#define __MPU_PRESENT CLOSURE_MPU
#define __VTOR_PRESENT CLOSURE_VTOR
#define __FPU_PRESENT CLOSURE_FPU
#define __NVIC_PRIO_BITS 3U
#if CLOSURE_CORE == 0 || CLOSURE_CORE == 3 || CLOSURE_CORE == 23
#define __DSP_PRESENT 0U
#else
#define __DSP_PRESENT 1U
#endif
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
#define __ITCM_PRESENT 0U
#define __DTCM_PRESENT 0U
#define __SAUREGION_PRESENT 1U
#define __Vendor_SysTickConfig 0U
#if CLOSURE_CORE == 55
#define __MVE_PRESENT 1U
#endif
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SecureFault_IRQn = -9,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, Device_IRQn = 0
} IRQn_Type;
#if CLOSURE_CORE == 0
#if CLOSURE_MPU || CLOSURE_VTOR
#include "core_cm0plus.h"
#else
#include "core_cm0.h"
#endif
#elif CLOSURE_CORE == 3
#include "core_cm3.h"
#elif CLOSURE_CORE == 4
#include "core_cm4.h"
#elif CLOSURE_CORE == 7
#include "core_cm7.h"
#elif CLOSURE_CORE == 23
#include "core_cm23.h"
#elif CLOSURE_CORE == 33
#include "core_cm33.h"
#elif CLOSURE_CORE == 55
#include "core_cm55.h"
#else
#error "Unknown CMSIS role"
#endif
#endif
