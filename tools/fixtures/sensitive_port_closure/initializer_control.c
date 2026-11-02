#include "fiber_api_attributes.h"

/* This is not gcov registration and must not inherit the cold-export allowance. */
__attribute__((constructor)) FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
#ifdef CLOSURE_COUNTERFEIT_REGISTRATION
void _sub_I_closure_counterfeit(void)
#else
void closure_illegal_initializer(void)
#endif
{
    __asm volatile("" ::: "memory");
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int closure_initializer_root(void)
{
    return 0;
}
