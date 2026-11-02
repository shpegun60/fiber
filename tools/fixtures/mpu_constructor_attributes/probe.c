#include "fiber_port_boot.h"

#define ATTRIBUTES_STRINGIFY_I(value) #value
#define ATTRIBUTES_STRINGIFY(value) ATTRIBUTES_STRINGIFY_I(value)

const char fiber_attributes_expected_cohort[] =
    ATTRIBUTES_STRINGIFY(FIBER_PORT_CONTEXT_COHORT_SYMBOL);

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_attributes_read_r9(void)
{
    return fiber_port_read_r9();
}

/* The same forced inline must remain callable from an ordinary FP-enabled TU,
 * not only from a general-registers-only constructor. Neither wrapper executes
 * in the test: its exact Thumb bytes prove the unchanged leaf ABI. */
FIBER_API_ATTR_SENSITIVE
uint32_t fiber_attributes_read_r9_ordinary(void)
{
    return fiber_port_read_r9();
}
