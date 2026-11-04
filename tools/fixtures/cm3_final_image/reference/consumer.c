/* Retained type/config facts only; this image cannot start the unavailable kernel. */
#include "reference.h"

_Static_assert(sizeof(StackType_t) == 4, "CM3 stack word");
_Static_assert(sizeof(BaseType_t) == 4, "CM3 base type");
_Static_assert(sizeof(UBaseType_t) == 4, "CM3 unsigned base type");
_Static_assert(sizeof(TickType_t) == 4, "CM3 tick width");
_Static_assert(sizeof(TaskHandle_t) == 4, "CM3 opaque task handle");
_Static_assert(sizeof(TaskFunction_t) == 4, "CM3 task entry");
_Static_assert(portBYTE_ALIGNMENT == 8, "CM3 stack alignment");
_Static_assert(portSTACK_GROWTH == -1, "CM3 stack direction");
_Static_assert(configENABLE_MPU == 0, "CM3 non-MPU");
_Static_assert(configENABLE_FPU == 0, "CM3 no FPU");
_Static_assert(configENABLE_TRUSTZONE == 0, "CM3 classic security");
_Static_assert(configMAX_SYSCALL_INTERRUPT_PRIORITY == 16, "raw p4/b16 syscall threshold");
_Static_assert(configMAX_API_CALL_INTERRUPT_PRIORITY == 16, "raw p4/b16 API threshold");
_Static_assert(configPRIO_BITS == 4 && __NVIC_PRIO_BITS == 4, "declared fixture priority bits");
_Static_assert(configCHECK_HANDLER_INSTALLATION == 1, "upstream handler check retained");
_Static_assert(configASSERT_DEFINED == 1, "upstream assertions enabled");

struct ReferenceCodeRoots {
    StackType_t *(*initialise_stack)(StackType_t *, TaskFunction_t, void *);
    BaseType_t (*start_scheduler)(void);
};

__attribute__((used, externally_visible, section(".reference_roots")))
const struct ReferenceCodeRoots reference_code_roots = {
    pxPortInitialiseStack,
    xPortStartScheduler
};

__attribute__((used, externally_visible, section(".reference_contract")))
const uint32_t reference_header_facts[] = {
    1u, sizeof(StackType_t), sizeof(BaseType_t), sizeof(TickType_t),
    portBYTE_ALIGNMENT, configENABLE_MPU, configENABLE_FPU,
    configMAX_SYSCALL_INTERRUPT_PRIORITY, configMAX_API_CALL_INTERRUPT_PRIORITY,
    __NVIC_PRIO_BITS
};

REFERENCE_STOP void reference_reset_forbidden(void)
{
    reference_fail_stop(0x52535400u);
}

REFERENCE_STOP void reference_fault_forbidden(void)
{
    reference_fail_stop(0x4641554Cu);
}
