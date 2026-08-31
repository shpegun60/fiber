/* Synthetic CMSE proof only; a board manifest owns real Secure/NSC placement. */
ENTRY(Reset_Handler)

MEMORY
{
	FLASH (rx) : ORIGIN = 0x0C000000, LENGTH = 64K
	FLASH_NSC (rx) : ORIGIN = 0x0C010000, LENGTH = 4K
	RAM (rwx) : ORIGIN = 0x30000000, LENGTH = 64K
}

SECTIONS
{
	.text :
	{
		*(.text*)
		*(.rodata*)
	} > FLASH
	.data :
	{
		*(.data*)
	} > RAM AT > FLASH
	.gnu.sgstubs :
	{
		. = ALIGN(32);
		KEEP(*(.gnu.sgstubs*))
		. = ALIGN(32);
	} > FLASH_NSC
	.fiber_secure_context_pool (NOLOAD) :
	{
		. = ALIGN(8);
		KEEP(*(.fiber_secure_context_pool))
		. = ALIGN(8);
	} > RAM
	.bss (NOLOAD) :
	{
		*(.bss*)
		*(COMMON)
	} > RAM
}
