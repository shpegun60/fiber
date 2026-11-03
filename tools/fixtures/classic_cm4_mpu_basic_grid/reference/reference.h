#ifndef CM4_MPU_BASIC_REFERENCE_H
#define CM4_MPU_BASIC_REFERENCE_H
#define MPU_WRAPPERS_INCLUDED_FROM_API_FILE
#include "FreeRTOS.h"
#include "task.h"
#include "mpu_syscall_numbers.h"
#undef MPU_WRAPPERS_INCLUDED_FROM_API_FILE
#define BOUNDARY __attribute__((noipa,used,externally_visible,target("general-regs-only")))
#define STOP __attribute__((noreturn)) BOUNDARY
void reference_fail_stop(uint32_t code) STOP;
void reference_reset_forbidden(void) STOP;
void reference_fault_forbidden(void) STOP;
#endif
