#ifndef C55S_ATTACHMENT_REFERENCE_CONFIG_H
#define C55S_ATTACHMENT_REFERENCE_CONFIG_H
/* Actual kernel/port headers, only scheduler build configuration supplied here. */
#include <stddef.h>
#include <stdint.h>
#define configCPU_CLOCK_HZ 100000000UL
#define configTICK_RATE_HZ 1000U
#define configUSE_PREEMPTION 1
#define configMAX_PRIORITIES 5U
#define configMINIMAL_STACK_SIZE 128U
#define configMAX_TASK_NAME_LEN 16U
#define configTICK_TYPE_WIDTH_IN_BITS TICK_TYPE_WIDTH_32_BITS
#define configUSE_TIMERS 0
#define configSUPPORT_STATIC_ALLOCATION 1
#define configSUPPORT_DYNAMIC_ALLOCATION 0
#define configUSE_IDLE_HOOK 0
#define configUSE_TICK_HOOK 0
#define configMAX_SYSCALL_INTERRUPT_PRIORITY 128U
#define configKERNEL_INTERRUPT_PRIORITY 255U
#define configENABLE_TRUSTZONE 1
#define configRUN_FREERTOS_SECURE_ONLY 0
#define configENABLE_FPU 0
#define configENABLE_MVE 0
#define configENABLE_MPU 0
#define configENABLE_PAC 0
#define configENABLE_BTI 0
#define configUSE_MPU_WRAPPERS_V1 0
#define configASSERT(x) do { if (!(x)) { for (;;) {} } } while (0)
void fiber_internal_task_return(void);
#define configTASK_RETURN_ADDRESS fiber_internal_task_return
#endif
