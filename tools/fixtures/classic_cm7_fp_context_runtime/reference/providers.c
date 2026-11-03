/* Explicit unavailable-kernel boundaries, never a simulated scheduler. */
#include "reference.h"

/* No real TCB or task stack exists in this link-only image. */
__attribute__((used, externally_visible))
TaskHandle_t volatile pxCurrentTCB = NULL;

volatile uint32_t reference_failure_code;

REFERENCE_STOP void reference_fail_stop(uint32_t code)
{
    reference_failure_code = code;
    for (;;) {
        __asm volatile("udf #90" ::: "memory");
    }
}

REFERENCE_BOUNDARY void reference_assert_failed(uint32_t line)
{
    reference_fail_stop(0xA5000000u | (line & 0x00FFFFFFu));
}

REFERENCE_BOUNDARY void vTaskSwitchContext(void)
{
    reference_fail_stop(0x53574348u);
}

REFERENCE_BOUNDARY BaseType_t xTaskIncrementTick(void)
{
    reference_fail_stop(0x5449434Bu);
}
