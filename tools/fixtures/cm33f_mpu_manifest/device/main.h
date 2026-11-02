#ifndef CM33F_MPU_MANIFEST_DEVICE_H
#define CM33F_MPU_MANIFEST_DEVICE_H

#define __MPU_PRESENT 1U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 3U
#define __FPU_PRESENT 1U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
#define __Vendor_SysTickConfig 0U
typedef enum IRQn {
    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,
    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,
    UsageFault_IRQn = -10, SecureFault_IRQn = -9,
    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,
    PendSV_IRQn = -2, SysTick_IRQn = -1, Device_IRQn = 0
} IRQn_Type;

/* Positive facts, including __FPU_USED, come from the actual CMSIS header. */
#include "core_cm33.h"

/* Negative-only contradictions are introduced after real CMSIS inclusion. */
#if defined(PROOF_OMIT_CORE) || defined(PROOF_CORE)
# undef __CORTEX_M
# ifdef PROOF_CORE
#  define __CORTEX_M PROOF_CORE
# endif
#endif
#if defined(PROOF_OMIT_MPU) || defined(PROOF_MPU)
# undef __MPU_PRESENT
# ifdef PROOF_MPU
#  define __MPU_PRESENT PROOF_MPU
# endif
#endif
#if defined(PROOF_OMIT_VTOR) || defined(PROOF_VTOR)
# undef __VTOR_PRESENT
# ifdef PROOF_VTOR
#  define __VTOR_PRESENT PROOF_VTOR
# endif
#endif
#if defined(PROOF_OMIT_NVIC) || defined(PROOF_NVIC)
# undef __NVIC_PRIO_BITS
# ifdef PROOF_NVIC
#  define __NVIC_PRIO_BITS PROOF_NVIC
# endif
#endif
#if defined(PROOF_OMIT_FPU_PRESENT) || defined(PROOF_FPU_PRESENT)
# undef __FPU_PRESENT
# ifdef PROOF_FPU_PRESENT
#  define __FPU_PRESENT PROOF_FPU_PRESENT
# endif
#endif
#if defined(PROOF_OMIT_FPU_USED) || defined(PROOF_FPU_USED)
# undef __FPU_USED
# ifdef PROOF_FPU_USED
#  define __FPU_USED PROOF_FPU_USED
# endif
#endif
#if defined(PROOF_OMIT_ARM_FP) || defined(PROOF_ARM_FP)
# undef __ARM_FP
# ifdef PROOF_ARM_FP
#  define __ARM_FP PROOF_ARM_FP
# endif
#endif
#ifdef PROOF_MVE
# define __ARM_FEATURE_MVE PROOF_MVE
#endif

#endif
