/* Synthetic startup used only by the ARM_CM33_MPU archive/link proof. */

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

void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));

void Reset_Handler(void)
{
	fiber_portable_application_fixture();
}

__attribute__((used, section(".isr_vector"), aligned(128)))
const uintptr_t fiber_arm_cm33_mpu_runtime_vectors[16] = {
	[0] = (uintptr_t)UINT32_C(0x3000FF00),
	[1] = (uintptr_t)&Reset_Handler,
	[11] = (uintptr_t)&SVC_Handler,
	[14] = (uintptr_t)&PendSV_Handler
};

/* Keep the proof freestanding when GCC lowers a structure operation to a
 * library call. */
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
