#include "fiber_portmacro.h"

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void control_new_pre_mrs_helper(void)
{
#if defined(CONTROL_HELPER_DATA_POISON)
    __asm volatile("nop\n.hword 0xeeb0, 0x0a40\nnop" ::: "memory");
#elif defined(CONTROL_HELPER_CONDITIONAL_RETURN_DATA)
    __asm volatile("cmp r0, #0\nit eq\nbxeq lr\n.hword 0xeeb0, 0x0a40\nnop" ::: "memory");
#elif defined(CONTROL_HELPER_CONDITIONAL_BRANCH_DATA)
    __asm volatile("cmp r0, #0\nbeq 1f\n.hword 0xeeb0, 0x0a40\n1:\nnop" ::: "memory");
#elif defined(CONTROL_HELPER_LITERAL_POOL)
    __asm volatile("b 1f\n.balign 4\n.word 0x0a40eeb0\n1:\nnop" ::: "memory");
#elif defined(CONTROL_HELPER_POISON)
    __asm volatile("vmov s0, s0" ::: "memory");
#else
    __asm volatile("nop\nnop" ::: "memory");
#endif
}
