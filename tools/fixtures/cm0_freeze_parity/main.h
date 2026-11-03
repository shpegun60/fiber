#ifndef CM0_FREEZE_PARITY_MAIN_H_
#define CM0_FREEZE_PARITY_MAIN_H_
#if !defined(FREEZE_CM0PLUS) || ((FREEZE_CM0PLUS != 0) && (FREEZE_CM0PLUS != 1))
#error "select exactly the CM0 or CM0+ freeze fixture"
#endif
#define __MPU_PRESENT 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
#define __DSP_PRESENT 0U
#define __NVIC_PRIO_BITS 2U
#define __Vendor_SysTickConfig 0U
#define __VTOR_PRESENT FREEZE_CM0PLUS
typedef enum IRQn { NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    SVCall_IRQn = -5, PendSV_IRQn = -2, SysTick_IRQn = -1, Fixture_IRQn = 0 } IRQn_Type;
#if FREEZE_CM0PLUS
#include "core_cm0plus.h"
#else
#include "core_cm0.h"
#endif
#endif
