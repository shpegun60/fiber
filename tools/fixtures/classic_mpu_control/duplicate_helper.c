#include "fiber_portmacro.h"

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
static void control_duplicate_helper(void)
{
#ifdef CONTROL_DUP_POISON
    __asm volatile("vmov s0, s0" ::: "memory");
#else
    __asm volatile("nop\nnop" ::: "memory");
#endif
}

#ifdef CONTROL_DUP_A
#define CONTROL_DUP_ENTRY control_duplicate_entry_a
#else
#define CONTROL_DUP_ENTRY control_duplicate_entry_b
#endif

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void CONTROL_DUP_ENTRY(void)
{
    control_duplicate_helper();
}
