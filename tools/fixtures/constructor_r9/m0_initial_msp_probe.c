#include "fiber/port/fiber_port_select.h"
#include "fiber_portmacro.h"

#define R9_REGISTER_STRINGIFY_INNER(value) #value
#define R9_REGISTER_STRINGIFY(value) R9_REGISTER_STRINGIFY_INNER(value)

/* R8 is callee-saved but not the reserved R9 static base. This ordinary C
 * caller remains ABI-conforming in both register contracts. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t r9_m0_initial_msp_probe(void)
{
    register uint32_t value __asm("r" R9_REGISTER_STRINGIFY(R9_PROBE_REGISTER)) =
            fiber_port_read_initial_msp();
    __asm volatile("" : "+r"(value));
    return value;
}
