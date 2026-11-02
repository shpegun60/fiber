#include <stdint.h>
#include "fiber_api_attributes.h"

/* Deliberately ordinary: every raw compiler family must be observable here. */
__attribute__((noinline, used, externally_visible))
int closure_unannotated_control(volatile int *const input, const int divisor)
{
    volatile char scratch[32];
    scratch[(unsigned)*input & 31u] = (char)*input;
    return (*input + divisor) / divisor + scratch[0];
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int closure_sensitive_control(volatile int *const input, const int divisor)
{
    return closure_unannotated_control(input, divisor);
}

static int (*volatile closure_local_callback)(volatile int *, int) = closure_unannotated_control;

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int closure_indirect_control(volatile int *const input, const int divisor)
{
    return closure_local_callback(input, divisor);
}

extern FIBER_GENERAL_REGS_ONLY int closure_external_boundary(void);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int closure_isolated_control(void)
{
    return closure_external_boundary();
}
