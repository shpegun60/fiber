/* Missing-kernel boundaries are fail-stop, never scheduler/tick models. */
#include "reference.h"
__attribute__((used, externally_visible)) TaskHandle_t volatile pxCurrentTCB = NULL;
volatile uint32_t reference_failure;
REFERENCE_STOP void reference_fail_stop(uint32_t reason)
{
    reference_failure = reason;
    for (;;) { __asm volatile("udf #90" ::: "memory"); }
}
REFERENCE_STOP void vTaskSwitchContext(void) { reference_fail_stop(0x53574348u); }
REFERENCE_STOP BaseType_t xTaskIncrementTick(void) { reference_fail_stop(0x5449434Bu); }
REFERENCE_STOP void reference_assert_failed(const char *file, int line)
{
    (void)file;
    (void)line;
    reference_fail_stop(0x41535354u);
}
