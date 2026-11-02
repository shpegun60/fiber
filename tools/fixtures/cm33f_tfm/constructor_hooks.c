#include <stdint.h>
#include "fiber_api_attributes.h"
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{ return begin >= 0x20000000u && begin < end && end <= 0x20010000u; }
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t address)
{ return (address & ~(uintptr_t)1u) >= 0x08000000u && address < 0x08100000u; }
