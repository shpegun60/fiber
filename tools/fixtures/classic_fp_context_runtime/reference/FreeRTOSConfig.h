/* Link-only configuration for the unmodified pinned GCC/ARM_CM4F port. */
#ifndef CLASSIC_FP_REFERENCE_FREERTOS_CONFIG_H
#define CLASSIC_FP_REFERENCE_FREERTOS_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#if !defined(__ARM_ARCH_7EM__) || !defined(__thumb__)
# error "CM4F reference requires the Cortex-M4 Thumb target"
#endif
#if !defined(__ARM_FP) || ((__ARM_FP & 4) == 0)
# error "CM4F reference requires single-precision hardware FP"
#endif
#if !defined(__ARM_PCS_VFP) || defined(__SOFTFP__)
# error "CM4F reference requires the hard-float procedure-call ABI"
#endif

#define configCPU_CLOCK_HZ                         25000000UL
#define configTICK_RATE_HZ                         1000U
#define configUSE_PREEMPTION                       1
#define configUSE_TIME_SLICING                     1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION    0
#define configUSE_TICKLESS_IDLE                    0
#define configMAX_PRIORITIES                       5U
#define configMINIMAL_STACK_SIZE                   128U
#define configMAX_TASK_NAME_LEN                    16U
#define configTICK_TYPE_WIDTH_IN_BITS              TICK_TYPE_WIDTH_32_BITS
#define configIDLE_SHOULD_YIELD                    1
#define configTASK_NOTIFICATION_ARRAY_ENTRIES      1U
#define configQUEUE_REGISTRY_SIZE                  0U
#define configENABLE_BACKWARD_COMPATIBILITY        1
#define configNUM_THREAD_LOCAL_STORAGE_POINTERS    0
#define configSTACK_DEPTH_TYPE                     size_t
#define configMESSAGE_BUFFER_LENGTH_TYPE           size_t
#define configUSE_NEWLIB_REENTRANT                 0
#define configUSE_MINI_LIST_ITEM                   0

#define configUSE_TIMERS                           0
#define configSUPPORT_STATIC_ALLOCATION            1
#define configSUPPORT_DYNAMIC_ALLOCATION           0
#define configSTACK_ALLOCATION_FROM_SEPARATE_HEAP  0
#define configAPPLICATION_ALLOCATED_HEAP           0
#define configTOTAL_HEAP_SIZE                      4096U
#define configKERNEL_PROVIDED_STATIC_MEMORY        0

#define configKERNEL_INTERRUPT_PRIORITY            0xFFU
#define configMAX_SYSCALL_INTERRUPT_PRIORITY       0x80U
#define configMAX_API_CALL_INTERRUPT_PRIORITY      0x80U
#define configCHECK_HANDLER_INSTALLATION           1

#define configUSE_IDLE_HOOK                        0
#define configUSE_TICK_HOOK                        0
#define configUSE_MALLOC_FAILED_HOOK               0
#define configCHECK_FOR_STACK_OVERFLOW             0
#define configGENERATE_RUN_TIME_STATS              0
#define configUSE_TRACE_FACILITY                   0
#define configUSE_STATS_FORMATTING_FUNCTIONS       0
#define configUSE_TASK_NOTIFICATIONS               0
#define configUSE_MUTEXES                          0
#define configUSE_RECURSIVE_MUTEXES                0
#define configUSE_COUNTING_SEMAPHORES              0
#define configUSE_QUEUE_SETS                       0
#define configUSE_APPLICATION_TASK_TAG             0

void reference_assert_failed(uint32_t line);
#define configASSERT(condition) do { \
    if (!(condition)) { reference_assert_failed((uint32_t)__LINE__); } \
} while (0)

#endif
