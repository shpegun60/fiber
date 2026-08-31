/* Negative-link fixture: selected ARM_CM55_MVEF_MPU owns SVC strongly. */

void SVC_Handler(void)
{
	for (;;) {
		__asm volatile("nop");
	}
}
