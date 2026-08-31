/* Negative-link fixture: selected ARM_CM55F_MPU owns SVC strongly. */

void SVC_Handler(void)
{
	for (;;) {
		__asm volatile("nop");
	}
}
