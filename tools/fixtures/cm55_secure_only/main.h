#ifndef FIBER_CM55_SECURE_ONLY_TEST_MAIN_H_
#define FIBER_CM55_SECURE_ONLY_TEST_MAIN_H_
#define __MPU_PRESENT 1U
#ifndef __VTOR_PRESENT
#define __VTOR_PRESENT 1U
#endif
#ifndef __NVIC_PRIO_BITS
#define __NVIC_PRIO_BITS 3U
#endif
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 1U
#define __FPU_USED 0U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SecureFault_IRQn = -9,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, DummyDevice_IRQn = 0
} IRQn_Type;
#if defined(FIBER_TEST_CM33_DEVICE)
#include "core_cm33.h"
#else
#include "core_cm55.h"
#endif
#endif
