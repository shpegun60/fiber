/* Link-only providers. No kernel task, scheduler, syscall, or handler is run. */
#include "FreeRTOS.h"
#include "task.h"
#include "portasm.h"
#include "mpu_syscall_numbers.h"

void vPortSVCHandler_C(uint32_t *frame);
void vSystemCallEnter(uint32_t *frame, uint32_t lr, uint8_t service);
void vSystemCallExit(uint32_t *frame, uint32_t lr);

_Static_assert(MAX_CONTEXT_SIZE == 54, "actual pinned FP backing");
_Static_assert(portARMV8M_MINOR_VERSION == 0, "M33, not M55");
_Static_assert(configENABLE_MPU == 1 && configENABLE_FPU == 1 &&
        configENABLE_TRUSTZONE == 0 && configENABLE_MVE == 0 &&
        configENABLE_PAC == 0 && configENABLE_BTI == 0, "exact comparator");

/* Satisfy the unmodified port's shared privileged sections, not a fake kernel. */
__attribute__((used)) TaskHandle_t pxCurrentTCB;
UBaseType_t uxSystemCallImplementations[NUM_SYSTEM_CALLS] = {0};

__attribute__((noinline, used)) void vTaskSwitchContext(void)
{ for (;;) { __asm volatile ("udf #5"); } }
__attribute__((noinline, used)) BaseType_t xTaskIncrementTick(void)
{ for (;;) { __asm volatile ("udf #6"); } }
__attribute__((noinline, used)) xMPU_SETTINGS *xTaskGetMPUSettings(TaskHandle_t task)
{ (void)task; for (;;) { __asm volatile ("udf #7"); } }

__attribute__((noreturn, noinline, used))
void codegen_reference_task_return(void)
{ for (;;) { __asm volatile ("udf #4"); } }

__attribute__((used, section(".proof_geometry")))
const uint32_t codegen_reference_geometry[] = {
    MAX_CONTEXT_SIZE, sizeof(((xMPU_SETTINGS *)0)->ulContext) / 4u,
    offsetof(xMPU_SETTINGS, ulContext) + 4u,
    configTOTAL_MPU_REGIONS, portARMV8M_MINOR_VERSION
};

__attribute__((used, section(".proof_roots")))
const void *const codegen_reference_roots[] = {
    (const void *)&vRestoreContextOfFirstTask,
    (const void *)&vStartFirstTask,
    (const void *)&SVC_Handler,
    (const void *)&vPortSVCHandler_C,
    /* Real upstream definitions referenced only by inline assembly need C
     * roots before LTO. These are not replacement syscall implementations. */
    (const void *)&vSystemCallEnter, (const void *)&vSystemCallExit,
    (const void *)&pxPortInitialiseStack,
    (const void *)&codegen_reference_geometry
};
