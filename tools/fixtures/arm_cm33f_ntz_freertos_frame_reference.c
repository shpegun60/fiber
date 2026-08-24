/*
 * Minimal generated-code fixture for the pinned FreeRTOS
 * ARM_CM33_NTZ/non_secure pxPortInitialiseStack() non-MPU branch.
 */
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
# define FIBER_TEST_REFERENCE_ATTR \
	__attribute__((noinline, noclone, noipa, target("general-regs-only")))
#else
# define FIBER_TEST_REFERENCE_ATTR
#endif

FIBER_TEST_REFERENCE_ATTR
uint32_t *fiber_test_freertos_cm33f_initialise_stack(uint32_t *top,
		uint32_t *end,
		uintptr_t entry,
		uintptr_t task_return,
		void *arg)
{
	top--;
	*top = 0x01000000u;
	top--;
	*top = (uint32_t)entry;
	top--;
	*top = (uint32_t)task_return;
	top -= 5;
	*top = (uint32_t)(uintptr_t)arg;
	top -= 9;
	*top = 0xFFFFFFBCu;
	top--;
	*top = (uint32_t)(uintptr_t)end;
	return top;
}
