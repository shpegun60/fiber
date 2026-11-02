/* Compile/link-only tuple for the unmodified pinned CM33 TrustZone port. */
#ifndef CM33F_SECURE_REFERENCE_FREERTOS_CONFIG_H
#define CM33F_SECURE_REFERENCE_FREERTOS_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#ifndef REFERENCE_ENABLE_FPU
# define REFERENCE_ENABLE_FPU 1
#endif
#define configENABLE_MPU 0
#define configENABLE_FPU REFERENCE_ENABLE_FPU
#define configENABLE_TRUSTZONE 1
#define configRUN_FREERTOS_SECURE_ONLY 0
#define configENABLE_MVE 0
#define configENABLE_PAC 0
#define configENABLE_BTI 0
#define configNUMBER_OF_CORES 1
#define configCPU_CLOCK_HZ 100000000UL
#define configTICK_RATE_HZ 1000U
#define configUSE_PREEMPTION 1
#define configUSE_TIME_SLICING 1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION 0
#define configUSE_TICKLESS_IDLE 0
#define configMAX_PRIORITIES 5U
#define configMINIMAL_STACK_SIZE 128U
#define configMAX_TASK_NAME_LEN 16U
#define configTICK_TYPE_WIDTH_IN_BITS TICK_TYPE_WIDTH_32_BITS
#define configSTACK_DEPTH_TYPE size_t
#define configSUPPORT_STATIC_ALLOCATION 1
#define configSUPPORT_DYNAMIC_ALLOCATION 0
#define configUSE_TIMERS 0
#define configUSE_IDLE_HOOK 0
#define configUSE_TICK_HOOK 0
#define configUSE_MALLOC_FAILED_HOOK 0
#define configCHECK_FOR_STACK_OVERFLOW 0
#define configUSE_TRACE_FACILITY 0
#define configUSE_STATS_FORMATTING_FUNCTIONS 0
#define configKERNEL_INTERRUPT_PRIORITY 0xffU
#define configMAX_SYSCALL_INTERRUPT_PRIORITY 0x80U
#define configMAX_API_CALL_INTERRUPT_PRIORITY 0x80U
#define configAPPLICATION_ALLOCATED_HEAP 0
#define secureconfigMAX_SECURE_CONTEXTS 3U
#define secureconfigTOTAL_HEAP_SIZE 4096U
#define secureconfigUSE_MALLOC_FAILED_HOOK 0
#define configASSERT(value) do { if (!(value)) { for (;;) {} } } while (0)

#endif
