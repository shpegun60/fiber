#include "fiber/fiber_runtime_port_abi.h"

#ifndef FIBER_RUNTIME_PORT_ABI_RETAIN_V1
#error "reverse ABI constructor guard must be a visible macro"
#endif

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_reverse_constructor_direct_macro_probe(void)
{
    FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
}
