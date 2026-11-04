/* Typed retained references only. Reset cannot enter the unavailable kernel. */
#include "reference.h"

_Static_assert(sizeof(StackType_t) == 4, "CM4 stack word");
_Static_assert(sizeof(BaseType_t) == 4, "CM4 base type");
_Static_assert(sizeof(TickType_t) == 4, "CM4 tick width");
_Static_assert(portBYTE_ALIGNMENT == 8, "CM4 stack alignment");
_Static_assert(portSTACK_GROWTH == -1, "CM4 stack direction");
_Static_assert(configMAX_SYSCALL_INTERRUPT_PRIORITY == 16, "raw p4/b16 syscall threshold");
_Static_assert(configMAX_API_CALL_INTERRUPT_PRIORITY == 16, "raw p4/b16 API threshold");

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
    portBYTE_ALIGNMENT, __ARM_FP, __ARM_PCS_VFP,
    configMAX_SYSCALL_INTERRUPT_PRIORITY, configMAX_API_CALL_INTERRUPT_PRIORITY,
    4u /* Declared fixture NVIC bits, not a hardware readback. */
};

REFERENCE_STOP void reference_reset_forbidden(void)
{
    reference_fail_stop(0x52535400u);
}

REFERENCE_STOP void reference_fault_forbidden(void)
{
    reference_fail_stop(0x4641554Cu);
}
