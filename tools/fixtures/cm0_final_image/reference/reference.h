#ifndef CM0_FINAL_REFERENCE_H
#define CM0_FINAL_REFERENCE_H

#include "FreeRTOS.h"
#include "task.h"
#include "portasm.h"

#define REFERENCE_BOUNDARY \
    __attribute__((noipa, used, externally_visible, target("general-regs-only")))
#define REFERENCE_STOP __attribute__((noreturn)) REFERENCE_BOUNDARY

REFERENCE_STOP void reference_fail_stop(uint32_t code);
REFERENCE_STOP void reference_reset_forbidden(void);
REFERENCE_STOP void reference_fault_forbidden(void);
extern volatile uint32_t reference_failure_code;
extern TaskHandle_t volatile pxCurrentTCB;
void vPortSVCHandler_C(uint32_t *caller_stack);
void SysTick_Handler(void);

#endif
