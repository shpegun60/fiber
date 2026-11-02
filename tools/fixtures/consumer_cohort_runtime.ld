/* Link-only A16 regression, not a board startup or execution fixture. */
ENTRY(Reset_Handler)

__fiber_mpu_privileged_flash_start__ = 0x08000000;
__fiber_mpu_privileged_flash_end__ = 0x08010000;
__fiber_mpu_unprivileged_flash_start__ = 0x08010000;
__fiber_mpu_unprivileged_flash_end__ = 0x08020000;
__fiber_mpu_unprivileged_syscalls_start__ = 0x08020000;
__fiber_mpu_unprivileged_syscalls_end__ = 0x08021000;
__fiber_mpu_current_context_slot_start__ = 0x30000000;
__fiber_mpu_current_context_slot_end__ = 0x30000020;
__fiber_mpu_privileged_sram_start__ = 0x30000020;
__fiber_mpu_privileged_sram_end__ = 0x30010000;
__fiber_mpu_unprivileged_ram_start__ = 0x24000000;
__fiber_mpu_unprivileged_ram_end__ = 0x24010000;

SECTIONS
{
	.isr_vector 0x08000000 : { KEEP(*(.isr_vector)) }
	.fiber_port_privileged_code 0x08000080 :
	{
		KEEP(*(.fiber_port_privileged_functions))
		*(.text*) *(.rodata*)
	}
	.fiber_port_context_cohort_expectation : ALIGN(4)
	{
		KEEP(*(.fiber_port_context_cohort_expectation))
	}
	.fiber_port_unprivileged_code 0x08010000 :
	{
		KEEP(*(.fiber_port_unprivileged_functions))
	}
	.fiber_port_syscalls 0x08020000 : { KEEP(*(.fiber_port_syscalls)) }
	.fiber_current_context_slot 0x30000000 (NOLOAD) :
	{
		KEEP(*(.bss.fiber_runtime_current_context_slot))
		. = 0x20;
	}
	.fiber_port_privileged_data 0x30000020 (NOLOAD) :
	{
		KEEP(*(.fiber_port_privileged_data))
		*(.data*) *(.bss*) *(COMMON)
	}
	.ARM.extab : { *(.ARM.extab*) }
	.ARM.exidx :
	{
		__exidx_start = .;
		*(.ARM.exidx*)
		__exidx_end = .;
	}
	/DISCARD/ : { *(.comment*) *(.note*) }
}
