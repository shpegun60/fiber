/* This image retains upstream code; reset deliberately cannot start it. */
#include "reference.h"

_Static_assert(sizeof(StackType_t) == 4, "CM4F reference stack word");
_Static_assert(sizeof(BaseType_t) == 4, "CM4F reference base type");
_Static_assert(sizeof(TickType_t) == 4, "CM4F reference tick width");
_Static_assert(portBYTE_ALIGNMENT == 8, "CM4F reference stack alignment");
_Static_assert(portSTACK_GROWTH == -1, "CM4F reference stack direction");

struct ReferenceCodeRoots {
    StackType_t *(*initialise_stack)(StackType_t *, TaskFunction_t, void *);
    BaseType_t (*start_scheduler)(void);
};

/* Ordinary C references extract the real port object from its archive. */
__attribute__((used, externally_visible, section(".reference_roots")))
const struct ReferenceCodeRoots reference_code_roots = {
    pxPortInitialiseStack,
    xPortStartScheduler
};

__attribute__((used, externally_visible, section(".reference_contract")))
const uint32_t reference_header_facts[] = {
    1u, /* Link-only fixture contract version; not a Fiber identity. */
    sizeof(StackType_t),
    sizeof(BaseType_t),
    sizeof(TickType_t),
    portBYTE_ALIGNMENT,
    __ARM_FP,
    __ARM_PCS_VFP,
    configMAX_SYSCALL_INTERRUPT_PRIORITY
};

REFERENCE_STOP void reference_reset_forbidden(void)
{
    reference_fail_stop(0x52535400u);
}

REFERENCE_STOP void reference_fault_forbidden(void)
{
    reference_fail_stop(0x4641554Cu);
}
