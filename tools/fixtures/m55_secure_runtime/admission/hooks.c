#include <stdint.h>
#include <stddef.h>
#include "fiber/fiber_api_attributes.h"
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{ return begin >= 0x20010000u && begin < end && end <= 0x20020000u; }
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t address)
{ return (address & ~(uintptr_t)1u) >= 0x10000u && address < 0x20000u; }
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY __attribute__((externally_visible))
void *memset(void *destination, int value, size_t length)
{
    unsigned char *p = destination;
    for (size_t n = 0; n < length; ++n) p[n] = (unsigned char)value;
    return destination;
}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY __attribute__((externally_visible))
void *memcpy(void *destination, const void *source, size_t length)
{
    unsigned char *p = destination;
    const unsigned char *q = source;
    for (size_t n = 0; n < length; ++n) p[n] = q[n];
    return destination;
}
