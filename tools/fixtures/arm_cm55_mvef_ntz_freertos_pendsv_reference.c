/*
 * Minimal generated-code fixture for the pinned FreeRTOS
 * ARM_CM55_NTZ/non_secure non-MPU MVE-FP PendSV backbone.
 *
 * This intentionally contains only the reference save/switch/restore order.
 * Fiber adds provenance, bounds, context-integrity, FPU-policy and scheduler
 * CPU-state validation around this sequence.
 */
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
# define FIBER_TEST_REFERENCE_ATTR \
	__attribute__((naked, noinline, noclone, noipa))
#else
# define FIBER_TEST_REFERENCE_ATTR
#endif

uint32_t *fiber_test_freertos_cm55_mvef_current;

void fiber_test_freertos_cm55_mvef_switch(void);

FIBER_TEST_REFERENCE_ATTR
void fiber_test_freertos_cm55_mvef_pendsv(void)
{
	__asm volatile(
			".syntax unified                         \n"
			"mrs   r0, psp                          \n"
			"tst   lr, #0x10                        \n"
			"it    eq                               \n"
			"vstmdbeq r0!, {s16-s31}                \n"
			"mrs   r2, psplim                       \n"
			"mov   r3, lr                           \n"
			"stmdb r0!, {r2-r11}                    \n"
			"ldr   r2, =fiber_test_freertos_cm55_mvef_current \n"
			"ldr   r1, [r2]                         \n"
			"str   r0, [r1]                         \n"
			"movs  r0, #0                           \n"
			"msr   basepri, r0                      \n"
			"dsb                                    \n"
			"isb                                    \n"
			"bl    fiber_test_freertos_cm55_mvef_switch \n"
			"movs  r0, #0                           \n"
			"msr   basepri, r0                      \n"
			"ldr   r2, =fiber_test_freertos_cm55_mvef_current \n"
			"ldr   r1, [r2]                         \n"
			"ldr   r0, [r1]                         \n"
			"ldmia r0!, {r2-r11}                    \n"
			"tst   r3, #0x10                        \n"
			"it    eq                               \n"
			"vldmiaeq r0!, {s16-s31}                \n"
			"msr   psplim, r2                       \n"
			"msr   psp, r0                          \n"
			"bx    r3                               \n"
			:::
			"memory");
}
