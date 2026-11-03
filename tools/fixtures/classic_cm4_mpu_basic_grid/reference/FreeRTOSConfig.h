/*
 * Compile-only configuration for generated-assembly comparison with the
 * pinned local FreeRTOS ports. It does not describe an application runtime.
 */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define configCPU_CLOCK_HZ                         100000000UL
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
#define configTOTAL_HEAP_SIZE                      4096U
#define configAPPLICATION_ALLOCATED_HEAP           0
#define configSTACK_ALLOCATION_FROM_SEPARATE_HEAP  0

#define configKERNEL_INTERRUPT_PRIORITY            0xFFU
#define configMAX_SYSCALL_INTERRUPT_PRIORITY       0x80U
#define configMAX_API_CALL_INTERRUPT_PRIORITY      0x80U

#define configUSE_IDLE_HOOK                        0
#define configUSE_TICK_HOOK                        0
#define configUSE_MALLOC_FAILED_HOOK               0
#define configUSE_DAEMON_TASK_STARTUP_HOOK         0
#define configCHECK_FOR_STACK_OVERFLOW             0
#define configGENERATE_RUN_TIME_STATS              0
#define configUSE_TRACE_FACILITY                   0
#define configUSE_STATS_FORMATTING_FUNCTIONS       0
#define configKERNEL_PROVIDED_STATIC_MEMORY        1

#define configUSE_TASK_NOTIFICATIONS               1
#define configUSE_MUTEXES                          1
#define configUSE_RECURSIVE_MUTEXES                1
#define configUSE_COUNTING_SEMAPHORES              1
#define configUSE_QUEUE_SETS                       0
#define configUSE_APPLICATION_TASK_TAG             0

#define INCLUDE_vTaskPrioritySet                   1
#define INCLUDE_uxTaskPriorityGet                  1
#define INCLUDE_vTaskDelete                        1
#define INCLUDE_vTaskSuspend                       1
#define INCLUDE_vTaskDelayUntil                    1
#define INCLUDE_vTaskDelay                         1
#define INCLUDE_xTaskGetSchedulerState             1
#define INCLUDE_xTaskGetCurrentTaskHandle          1
#define INCLUDE_uxTaskGetStackHighWaterMark        1
#define INCLUDE_xTaskGetIdleTaskHandle             1
#define INCLUDE_eTaskGetState                      1
#define INCLUDE_xTimerPendFunctionCall             0
#define INCLUDE_xTaskAbortDelay                    1
#define INCLUDE_xTaskGetHandle                     1
#define INCLUDE_xTaskResumeFromISR                 1

#ifndef FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE
#define FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE     0
#endif
#ifndef FIBER_FREERTOS_PARITY_SECURE_ONLY
#define FIBER_FREERTOS_PARITY_SECURE_ONLY          0
#endif
#ifndef FIBER_FREERTOS_PARITY_ENABLE_FPU
#define FIBER_FREERTOS_PARITY_ENABLE_FPU           0
#endif
#ifndef FIBER_FREERTOS_PARITY_ENABLE_MVE
#define FIBER_FREERTOS_PARITY_ENABLE_MVE           0
#endif
#ifndef FIBER_FREERTOS_PARITY_MPU_REGIONS
#define FIBER_FREERTOS_PARITY_MPU_REGIONS          8
#endif
#ifndef FIBER_FREERTOS_PARITY_ENABLE_MPU
#define FIBER_FREERTOS_PARITY_ENABLE_MPU           0
#endif

#define configENABLE_TRUSTZONE \
    FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE
#define configRUN_FREERTOS_SECURE_ONLY \
    FIBER_FREERTOS_PARITY_SECURE_ONLY
#define configENABLE_FPU \
    FIBER_FREERTOS_PARITY_ENABLE_FPU
#define configENABLE_MVE \
    FIBER_FREERTOS_PARITY_ENABLE_MVE
#define configTOTAL_MPU_REGIONS \
    FIBER_FREERTOS_PARITY_MPU_REGIONS
#define configENABLE_MPU \
    FIBER_FREERTOS_PARITY_ENABLE_MPU

#define configUSE_MPU_WRAPPERS_V1                  0
#define configSYSTEM_CALL_STACK_SIZE               128U
#define configENABLE_ACCESS_CONTROL_LIST           0
#define configPROTECTED_KERNEL_OBJECT_POOL_SIZE    10U
#define configENFORCE_SYSTEM_CALLS_FROM_KERNEL_ONLY 1

#define configASSERT(x) do { if (!(x)) { for (;;) { } } } while (0)

#endif /* FREERTOS_CONFIG_H */
