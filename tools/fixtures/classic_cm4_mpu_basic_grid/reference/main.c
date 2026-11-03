#include "reference.h"
/* Typed roots refer to the real upstream functions, including the MPU fifth argument. */
StackType_t *pxPortInitialiseStack(StackType_t *, TaskFunction_t, void *, BaseType_t, xMPU_SETTINGS *);
extern BaseType_t xPortStartScheduler(void);
extern void vSVCHandler_C(uint32_t *);
extern void vSystemCallEnter(uint32_t *, uint32_t, uint8_t);
extern void vSystemCallExit(uint32_t *, uint32_t);
typedef struct {
    StackType_t *(*initialise)(StackType_t *, TaskFunction_t, void *, BaseType_t, xMPU_SETTINGS *);
    BaseType_t (*start)(void);
    void (*svc_dispatch)(uint32_t *);
    void (*system_enter)(uint32_t *, uint32_t, uint8_t);
    void (*system_exit)(uint32_t *, uint32_t);
} roots_t;
const roots_t reference_roots __attribute__((used,section(".reference_roots"))) = {
    pxPortInitialiseStack, xPortStartScheduler,
    vSVCHandler_C, vSystemCallEnter, vSystemCallExit
};
const uint32_t reference_contract[] __attribute__((used,section(".reference_contract"))) = {
    1, sizeof(StackType_t), sizeof(BaseType_t), sizeof(TickType_t), portBYTE_ALIGNMENT,
    __ARM_FP, __ARM_PCS_VFP, configMAX_SYSCALL_INTERRUPT_PRIORITY,
    configTOTAL_MPU_REGIONS, configUSE_MPU_WRAPPERS_V1,
    configENABLE_ERRATA_837070_WORKAROUND, sizeof(xMPU_SETTINGS)
};
void reference_reset_forbidden(void) { reference_fail_stop(0x504U); }
void reference_fault_forbidden(void) { reference_fail_stop(0x505U); }
