#ifndef CONTEXT_FACADE_MCU_CORE_H
#define CONTEXT_FACADE_MCU_CORE_H
#ifndef FACADE_NVIC_BITS
#define FACADE_NVIC_BITS 2
#endif
#define __NVIC_PRIO_BITS FACADE_NVIC_BITS
#define __Vendor_SysTickConfig 0U
#define __MPU_PRESENT 0U
#define __FPU_PRESENT FACADE_FPU
#define __DSP_PRESENT 0U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U
#define __VTOR_PRESENT FACADE_VTOR
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5,
    DebugMonitor_IRQn = -4, PendSV_IRQn = -2, SysTick_IRQn = -1,
    DummyDevice_IRQn = 0
} IRQn_Type;
#if FACADE_CORE == 0
#include "core_cm0.h"
#elif FACADE_CORE == 1
#include "core_cm0plus.h"
#elif FACADE_CORE == 4
#include "core_cm4.h"
#elif FACADE_CORE == 7
#include "core_cm7.h"
#else
#error "unsupported facade fixture core"
#endif
#endif
