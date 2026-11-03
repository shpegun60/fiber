#ifndef CM0_FREEZE_PARITY_REFERENCE_H_
#define CM0_FREEZE_PARITY_REFERENCE_H_
#include "FreeRTOS.h"
#include "task.h"
#define REFERENCE_STOP __attribute__((noreturn, noinline, noipa, target("general-regs-only")))
REFERENCE_STOP void reference_fail_stop(uint32_t reason);
REFERENCE_STOP void reference_reset_forbidden(void);
REFERENCE_STOP void reference_fault_forbidden(void);
#endif
