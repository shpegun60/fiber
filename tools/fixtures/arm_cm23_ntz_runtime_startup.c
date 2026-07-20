/* Synthetic startup used only by the ARM_CM23_NTZ archive/link proof. */

#include <stddef.h>
#include <stdint.h>

extern void fiber_portable_application_fixture(void)
		__attribute__((noreturn));

void Default_Handler(void)
{
	for (;;) {
		__asm volatile("wfe");
	}
}

/* The selected port must replace these weak startup aliases with its strong
 * SVC/PendSV implementations after archive extraction. */
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));

void Reset_Handler(void)
{
	fiber_portable_application_fixture();
}

__attribute__((used, section(".isr_vector"), aligned(128)))
const uintptr_t fiber_arm_cm23_ntz_runtime_vectors[16] = {
	[0] = (uintptr_t)UINT32_C(0x20020000),
	[1] = (uintptr_t)&Reset_Handler,
	[11] = (uintptr_t)&SVC_Handler,
	[14] = (uintptr_t)&PendSV_Handler
};

/* Production integrations supply their own board memory map. These synthetic
 * bounds keep the archive proof freestanding while exercising real hook
 * references from the selected M23 port. */
int fiber_addr_plausible_ram(uintptr_t start, uintptr_t end)
{
	return (start >= UINT32_C(0x20000000)) && (end > start) &&
			(end <= UINT32_C(0x20020000));
}

int fiber_addr_plausible_code(uintptr_t address)
{
	return (address >= UINT32_C(0x08000000)) &&
			(address < UINT32_C(0x08020000));
}

/* Freestanding implementations keep the fixture independent of a C library
 * if GCC lowers a structure operation to a call. */
void *memcpy(void *destination, const void *source, size_t count)
{
	unsigned char *dst = (unsigned char *)destination;
	const unsigned char *src = (const unsigned char *)source;
	while (count-- != 0u) {
		*dst++ = *src++;
	}
	return destination;
}

void *memset(void *destination, int value, size_t count)
{
	unsigned char *dst = (unsigned char *)destination;
	while (count-- != 0u) {
		*dst++ = (unsigned char)value;
	}
	return destination;
}
