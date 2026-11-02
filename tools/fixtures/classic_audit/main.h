#ifndef FIBER_CLASSIC_AUDIT_MAIN_H
#define FIBER_CLASSIC_AUDIT_MAIN_H

#define __MPU_PRESENT AUDIT_MPU
#define __VTOR_PRESENT AUDIT_VTOR
#define __NVIC_PRIO_BITS 2U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 0U
#define __ICACHE_PRESENT 0U
#define __DCACHE_PRESENT 0U

typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SVCall_IRQn = -5,
    DebugMonitor_IRQn = -4, PendSV_IRQn = -2, SysTick_IRQn = -1,
    DummyDevice_IRQn = 0
} IRQn_Type;

#if AUDIT_CORE == 0
#include "core_cm0.h"
#elif AUDIT_CORE == 1
#include "core_cm0plus.h"
#elif AUDIT_CORE == 3
#include "core_cm3.h"
#elif AUDIT_CORE == 4
#include "core_cm4.h"
#elif AUDIT_CORE == 7
#include "core_cm7.h"
#else
#error "unsupported classic audit core"
#endif
#endif
