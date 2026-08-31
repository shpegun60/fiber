/* Negative-link fixture: selected ARM_CM55_MVEF_MPU owns PendSV strongly. */

void PendSV_Handler(void)
{
	for (;;) {
		__asm volatile("nop");
	}
}
