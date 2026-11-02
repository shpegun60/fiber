/* Unexecuted kernel linkage only. No fixture supplies a port/CMSE operation. */
#include "FreeRTOS.h"
#include "task.h"

TaskHandle_t pxCurrentTCB;

__attribute__((noreturn, noinline, used))
void vTaskSwitchContext(void)
{
    for (;;) { __asm volatile ("udf #81"); }
}

__attribute__((noreturn, noinline, used))
BaseType_t xTaskIncrementTick(void)
{
    for (;;) { __asm volatile ("udf #82"); }
}
