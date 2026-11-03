#include "reference.h"
_Static_assert(sizeof(StackType_t) == 4, "reference stack word");
_Static_assert(sizeof(BaseType_t) == 4, "reference base word");
_Static_assert(sizeof(TickType_t) == 4, "reference tick word");
_Static_assert(portBYTE_ALIGNMENT == 8, "reference stack alignment");
_Static_assert(portSTACK_GROWTH == -1, "reference stack direction");
struct ReferenceRoots {
    StackType_t *(*init)(StackType_t *, TaskFunction_t, void *);
    BaseType_t (*start)(void);
};
__attribute__((used, externally_visible, section(".freeze_roots")))
const struct ReferenceRoots reference_code_roots = {pxPortInitialiseStack, xPortStartScheduler};
__attribute__((used, externally_visible, section(".reference_contract")))
const uint32_t reference_header_facts[] = {
    1u, sizeof(StackType_t), sizeof(BaseType_t), sizeof(TickType_t), portBYTE_ALIGNMENT, configENABLE_MPU
};
REFERENCE_STOP void reference_reset_forbidden(void) { reference_fail_stop(0x52535400u); }
REFERENCE_STOP void reference_fault_forbidden(void) { reference_fail_stop(0x4641554Cu); }
