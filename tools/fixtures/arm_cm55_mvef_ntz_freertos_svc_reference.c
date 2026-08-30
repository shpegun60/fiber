/*
 * Minimal generated-code fixture for the pinned FreeRTOS
 * ARM_CM55_NTZ/non_secure non-MPU MVE-FP first-start transfer.
 *
 * It intentionally carries only the reference transfer backbone. Fiber adds
 * provenance, FPU-policy, vector, and metadata validation around it.
 */
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
# define FIBER_TEST_REFERENCE_ATTR \
	__attribute__((naked, noinline, noclone, noipa, target("general-regs-only")))
#else
# define FIBER_TEST_REFERENCE_ATTR
#endif

uint32_t *fiber_test_freertos_cm55_mvef_current;

FIBER_TEST_REFERENCE_ATTR
void fiber_test_freertos_cm55_mvef_vstart_first(void)
{
	__asm volatile(
			".syntax unified                 \n"
			"ldr   r0, =0xE000ED08          \n"
			"ldr   r0, [r0]                 \n"
			"ldr   r0, [r0]                 \n"
			"msr   msp, r0                  \n"
			"cpsie i                        \n"
			"cpsie f                        \n"
			"dsb                            \n"
			"isb                            \n"
			"svc   #70                      \n"
			"nop                            \n"
			::: "memory");
}

FIBER_TEST_REFERENCE_ATTR
void fiber_test_freertos_cm55_mvef_restore_first(void)
{
	__asm volatile(
			".syntax unified                 \n"
			"ldr   r2, =fiber_test_freertos_cm55_mvef_current \n"
			"ldr   r1, [r2]                 \n"
			"ldr   r0, [r1]                 \n"
			"ldmia r0!, {r1-r2}             \n"
			"msr   psplim, r1               \n"
			"mrs   r1, control              \n"
			"orr   r1, r1, #2               \n"
			"msr   control, r1              \n"
			"adds  r0, #32                  \n"
			"msr   psp, r0                  \n"
			"isb                            \n"
			"movs  r0, #0                   \n"
			"msr   basepri, r0              \n"
			"bx    r2                       \n"
			::: "memory");
}
