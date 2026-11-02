#ifndef FIBER_THUMB1_VECTOR_CONSTRAINTS_MAIN_H
#define FIBER_THUMB1_VECTOR_CONSTRAINTS_MAIN_H
#define __MPU_PRESENT THUMB1_MPU
#define __VTOR_PRESENT THUMB1_VTOR
#define __NVIC_PRIO_BITS 2U
#define __Vendor_SysTickConfig 0U
#define __FPU_PRESENT 0U
#define __FPU_USED 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    SVCall_IRQn = -5, PendSV_IRQn = -2, SysTick_IRQn = -1,
    Device_IRQn = 0
} IRQn_Type;
#if THUMB1_MPU || THUMB1_VTOR
#include "core_cm0plus.h"
#else
#include "core_cm0.h"
#endif
#endif
