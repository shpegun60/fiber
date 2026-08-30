/* Negative-link fixture: selected ARM_CM55_MPU owns PendSV strongly. */

void PendSV_Handler(void)
{
	for (;;) {
		__asm volatile("nop");
	}
}
