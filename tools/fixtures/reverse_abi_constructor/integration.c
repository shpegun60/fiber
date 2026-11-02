#include <stddef.h>
#include <stdint.h>
#include "fiber/port/ARM_CM7/r0p1/fiber_port_boot.h"

/* Only application hooks and freestanding memory primitives are fixtures.
 * Public init, port construction and reverse services remain production code. */
int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end)
{
    return end > start;
}

int fiber_addr_plausible_code(uintptr_t address)
{
    return address != 0u;
}

/* Native LTO may introduce memory calls after its initial reachability pass. */
__attribute__((used, externally_visible))
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memset(void *destination, int value, size_t count)
{
    unsigned char *p = destination;
    while (count--) { *p++ = (unsigned char)value; }
    return destination;
}

__attribute__((used, externally_visible))
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void *memcpy(void *destination, const void *source, size_t count)
{
    unsigned char *d = destination;
    const unsigned char *s = source;
    while (count--) { *d++ = *s++; }
    return destination;
}
