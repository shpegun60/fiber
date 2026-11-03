#include "reference.h"
/* Link-only kernel boundaries. No TCB, task stack, or scheduler is emulated. */
TaskHandle_t volatile pxCurrentTCB;
volatile uint32_t reference_failure_code;
UBaseType_t uxSystemCallImplementations[NUM_SYSTEM_CALLS];
void reference_fail_stop(uint32_t code)
{
    reference_failure_code = code;
    __asm volatile("udf #90");
    for (;;) { __asm volatile("nop"); }
}
void vTaskSwitchContext(void) BOUNDARY;
void vTaskSwitchContext(void) { reference_fail_stop(0x501U); }
BaseType_t xTaskIncrementTick(void) BOUNDARY;
BaseType_t xTaskIncrementTick(void) { reference_fail_stop(0x502U); }
xMPU_SETTINGS *xTaskGetMPUSettings(TaskHandle_t task) BOUNDARY;
xMPU_SETTINGS *xTaskGetMPUSettings(TaskHandle_t task)
{
    (void) task;
    reference_fail_stop(0x503U);
}
