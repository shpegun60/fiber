/* Link-only configuration for actual pinned CM0 port.c plus portasm.c. */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H
#include <stddef.h>
#include <stdint.h>
#define configCPU_CLOCK_HZ 16000000UL
#define configTICK_RATE_HZ 1000U
#define configUSE_PREEMPTION 1
#define configUSE_TIME_SLICING 1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION 0
#define configUSE_TICKLESS_IDLE 0
#define configMAX_PRIORITIES 5U
#define configMINIMAL_STACK_SIZE 128U
#define configMAX_TASK_NAME_LEN 16U
#define configTICK_TYPE_WIDTH_IN_BITS TICK_TYPE_WIDTH_32_BITS
#define configIDLE_SHOULD_YIELD 1
#define configTASK_NOTIFICATION_ARRAY_ENTRIES 1U
#define configQUEUE_REGISTRY_SIZE 0U
#define configENABLE_BACKWARD_COMPATIBILITY 1
#define configNUM_THREAD_LOCAL_STORAGE_POINTERS 0
#define configSTACK_DEPTH_TYPE size_t
#define configMESSAGE_BUFFER_LENGTH_TYPE size_t
#define configUSE_NEWLIB_REENTRANT 0
#define configUSE_MINI_LIST_ITEM 0
#define configUSE_TIMERS 0
#define configSUPPORT_STATIC_ALLOCATION 1
#define configSUPPORT_DYNAMIC_ALLOCATION 0
#define configTOTAL_HEAP_SIZE 4096U
#define configKERNEL_INTERRUPT_PRIORITY 0xFFU
#define configUSE_IDLE_HOOK 0
#define configUSE_TICK_HOOK 0
#define configUSE_MALLOC_FAILED_HOOK 0
#define configCHECK_FOR_STACK_OVERFLOW 0
#define configGENERATE_RUN_TIME_STATS 0
#define configUSE_TRACE_FACILITY 0
#define configUSE_STATS_FORMATTING_FUNCTIONS 0
#define configKERNEL_PROVIDED_STATIC_MEMORY 1
#define configUSE_TASK_NOTIFICATIONS 1
#define configUSE_MUTEXES 1
#define configUSE_RECURSIVE_MUTEXES 1
#define configUSE_COUNTING_SEMAPHORES 1
#define configENABLE_MPU 0
#define configUSE_MPU_WRAPPERS_V1 0
#define configCHECK_HANDLER_INSTALLATION 1
void reference_assert_failed(const char *file, int line) __attribute__((noreturn));
#define configASSERT(value) do { if (!(value)) { reference_assert_failed(__FILE__, __LINE__); } } while (0)
#endif
