#if !THUMB1_MPU
#include "fiber/port/fiber_port_select.h"
#endif
#include "fiber_portmacro.h"

/* Force a legal caller register allocation that the inlined instruction must
 * accommodate by moving through an encodable low register. */
__attribute__((used, externally_visible))
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t thumb1_vector_probe(uintptr_t address, uint32_t index)
{
    register uintptr_t base __asm("r10") = address;
    __asm volatile("" : "+r"(base));
    register uint32_t value __asm("r8") =
#if THUMB1_MPU
            fiber_port_read_vector_slot_at(base, index);
#else
            fiber_port_read_initial_msp();
#endif
    __asm volatile("" : "+r"(value));
    (void)base;
    (void)index;
    return value;
}
