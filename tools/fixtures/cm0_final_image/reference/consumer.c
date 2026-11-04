/* Retained typed references; reset cannot enter the unavailable kernel. */
#include "reference.h"

_Static_assert(sizeof(StackType_t) == 4, "CM0 stack word");
_Static_assert(sizeof(BaseType_t) == 4, "CM0 base type");
_Static_assert(sizeof(UBaseType_t) == 4, "CM0 unsigned base type");
_Static_assert(sizeof(TickType_t) == 4, "CM0 tick width");
_Static_assert(sizeof(TaskHandle_t) == 4, "CM0 opaque TCB pointer");
_Static_assert(sizeof(TaskFunction_t) == 4, "CM0 task function pointer");
_Static_assert(portBYTE_ALIGNMENT == 8, "CM0 stack alignment");
_Static_assert(portSTACK_GROWTH == -1, "CM0 stack direction");
_Static_assert(configNUMBER_OF_CORES == 1, "CM0 single-core reference");
_Static_assert(configENABLE_MPU == 0, "CM0 no MPU reference");
_Static_assert(configENABLE_FPU == 0, "CM0 no FPU reference");
_Static_assert(configENABLE_TRUSTZONE == 0, "CM0 no TrustZone reference");
_Static_assert(configTICK_TYPE_WIDTH_IN_BITS == TICK_TYPE_WIDTH_32_BITS, "CM0 32-bit ticks");
_Static_assert(configMAX_SYSCALL_INTERRUPT_PRIORITY == 0, "CM0 BASEPRI not applicable");
_Static_assert(configMAX_API_CALL_INTERRUPT_PRIORITY == 0, "CM0 BASEPRI not applicable");

#if defined(__ARM_FP)
#define REFERENCE_ARM_FP __ARM_FP
#else
#define REFERENCE_ARM_FP 0u
#endif
#if defined(__ARM_PCS_VFP)
#define REFERENCE_PCS_VFP __ARM_PCS_VFP
#else
#define REFERENCE_PCS_VFP 0u
#endif
_Static_assert(REFERENCE_ARM_FP == 0 && REFERENCE_PCS_VFP == 0, "CM0 soft no-FP target");

struct ReferenceCodeRoots {
    StackType_t *(*initialise_stack)(StackType_t *, TaskFunction_t, void *);
    BaseType_t (*start_scheduler)(void);
    void (*start_first)(void);
    void (*svc)(void);
    void (*svc_dispatch)(uint32_t *);
    void (*restore_first)(void);
    void (*pendsv)(void);
};

__attribute__((used, externally_visible, section(".reference_roots")))
const struct ReferenceCodeRoots reference_code_roots = {
    pxPortInitialiseStack, xPortStartScheduler,
    vStartFirstTask, SVC_Handler, vPortSVCHandler_C,
    vRestoreContextOfFirstTask, PendSV_Handler
};

__attribute__((used, externally_visible, section(".reference_contract")))
const uint32_t reference_header_facts[] = {
    1u, sizeof(StackType_t), sizeof(BaseType_t), sizeof(TickType_t),
    portBYTE_ALIGNMENT, REFERENCE_ARM_FP, REFERENCE_PCS_VFP,
    configMAX_SYSCALL_INTERRUPT_PRIORITY, configMAX_API_CALL_INTERRUPT_PRIORITY,
    2u /* Declared fixture NVIC width, not hardware readback. */
};

REFERENCE_STOP void reference_reset_forbidden(void)
{
    reference_fail_stop(0x52535400u);
}

REFERENCE_STOP void reference_fault_forbidden(void)
{
    reference_fail_stop(0x4641554Cu);
}
