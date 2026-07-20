ENTRY(Reset_Handler)

MEMORY
{
	FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 128K
	RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

SECTIONS
{
	.isr_vector ORIGIN(FLASH) :
	{
		KEEP(*(.isr_vector))
	} > FLASH

	/* The build-owned relocation makes a complete archive from another exact
	 * context cohort fail to link. KEEP protects it from section GC and LTO. */
	.fiber_port_context_cohort_expectation : ALIGN(4)
	{
		KEEP(*(.fiber_port_context_cohort_expectation))
	} > FLASH

	.text : ALIGN(4)
	{
		*(.text*)
		*(.rodata*)
	} > FLASH

	.ARM.extab : ALIGN(4)
	{
		*(.ARM.extab*)
	} > FLASH

	.ARM.exidx : ALIGN(4)
	{
		__exidx_start = .;
		*(.ARM.exidx*)
		__exidx_end = .;
	} > FLASH

	.data : ALIGN(4)
	{
		*(.data*)
	} > RAM AT > FLASH

	.bss (NOLOAD) : ALIGN(4)
	{
		*(.bss*)
		*(COMMON)
	} > RAM
}
