#include <stdint.h>
#include <stddef.h>

#include "fiber_port_private.h"

FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end)
{
	return (start != 0u) && (end > start);
}

FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t addr)
{
	return addr != 0u;
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
	(void)code;
	for (;;) {
		__asm volatile ("wfe");
	}
}

FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_task_return(void)
{
	for (;;) {
		__asm volatile ("wfe");
	}
}

void *memcpy(void *destination, const void *source, size_t count)
{
	uint8_t *const out = (uint8_t *)destination;
	const uint8_t *const in = (const uint8_t *)source;
	for (size_t index = 0u; index < count; ++index) {
		out[index] = in[index];
	}
	return destination;
}

void *memset(void *destination, int value, size_t count)
{
	uint8_t *const out = (uint8_t *)destination;
	for (size_t index = 0u; index < count; ++index) {
		out[index] = (uint8_t)value;
	}
	return destination;
}
