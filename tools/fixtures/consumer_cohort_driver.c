/* The fresh caller knows only the opaque API, not the allocator's geometry. */
#include <stddef.h>
#include <stdint.h>
#include "fiber/fiber_api_decl.h"

extern FiberContext *fiber_consumer_get(void);

static _Alignas(32) unsigned char consumer_stack[2048];

static void consumer_entry(void *arg)
{
	(void)arg;
	for (;;) {
		fiber_schedule();
	}
}

void Reset_Handler(void)
{
	fiber_init(fiber_consumer_get(), consumer_stack,
			consumer_stack + sizeof(consumer_stack), consumer_entry, (void *)0);
	for (;;) {
		__asm volatile ("wfe");
	}
}

void Default_Handler(void)
{
	for (;;) {
		__asm volatile ("wfe");
	}
}

void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));

__attribute__((used, section(".isr_vector"), aligned(128)))
const uintptr_t consumer_vectors[16] = {
	[0] = UINT32_C(0x3000ff00),
	[1] = (uintptr_t)&Reset_Handler,
	[11] = (uintptr_t)&SVC_Handler,
	[14] = (uintptr_t)&PendSV_Handler
};

FIBER_SCHEDULER_HOOK_ATTR
int fiber_addr_plausible_ram(uintptr_t begin, uintptr_t end)
{
	return (begin >= UINT32_C(0x20000000)) &&
			(end <= UINT32_C(0x40000000)) && (end > begin);
}

FIBER_SCHEDULER_HOOK_ATTR
int fiber_addr_plausible_code(uintptr_t address)
{
	return (address >= UINT32_C(0x08000000)) &&
			(address < UINT32_C(0x08021000));
}

FIBER_SCHEDULER_HOOK_ATTR __attribute__((externally_visible))
void *memcpy(void *destination, const void *source, size_t count)
{
	unsigned char *out = destination;
	const unsigned char *in = source;
	while (count-- != 0u) {
		*out++ = *in++;
	}
	return destination;
}

FIBER_SCHEDULER_HOOK_ATTR __attribute__((externally_visible))
void *memset(void *destination, int value, size_t count)
{
	unsigned char *out = destination;
	while (count-- != 0u) {
		*out++ = (unsigned char)value;
	}
	return destination;
}
