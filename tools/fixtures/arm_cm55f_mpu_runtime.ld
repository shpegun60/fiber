ENTRY(Reset_Handler)

__fiber_mpu_privileged_flash_start__ = 0x08000000;
__fiber_mpu_privileged_flash_end__ = 0x08010000;
__fiber_mpu_unprivileged_flash_start__ = 0x08010000;
__fiber_mpu_unprivileged_flash_end__ = 0x08020000;
__fiber_mpu_unprivileged_syscalls_start__ = 0x08020000;
__fiber_mpu_unprivileged_syscalls_end__ = 0x08021000;
__fiber_mpu_privileged_sram_start__ = 0x30000000;
__fiber_mpu_privileged_sram_end__ = 0x30010000;
__fiber_mpu_current_context_slot_start__ = 0x30000000;
__fiber_mpu_current_context_slot_end__ = 0x30000020;
__fiber_mpu_unprivileged_ram_start__ = 0x24000000;
__fiber_mpu_unprivileged_ram_end__ = 0x24010000;

SECTIONS
{
	.isr_vector 0x08000000 :
	{
		KEEP(*(.isr_vector))
	}

	/* This is the complete direct unprivileged Thread-mode call chain. The
	 * selected port reaches protected PendSV only through the SVC 71 veneer. */
	.fiber_port_unprivileged_code 0x08010000 :
	{
		KEEP(*(.fiber_port_unprivileged_functions))
		KEEP(*(.text.fiber_runtime_thread_functions))
		KEEP(*(.text.portable_fixture_entry*))
	}
	ASSERT((ADDR(.fiber_port_unprivileged_code) +
		SIZEOF(.fiber_port_unprivileged_code)) <= 0x08020000,
		"ARM_CM55F_MPU unprivileged code exceeds its exact MPU range")

	.fiber_port_privileged_code 0x08000080 :
	{
		KEEP(*(.fiber_port_privileged_functions))
		KEEP(*(.fiber_port_context_cohort_expectation))
		*(.text*)
		*(.rodata*)
	}
	ASSERT((ADDR(.fiber_port_privileged_code) +
		SIZEOF(.fiber_port_privileged_code)) <= 0x08010000,
		"ARM_CM55F_MPU privileged code exceeds its exact MPU range")

	.fiber_port_syscalls 0x08020000 :
	{
		KEEP(*(.fiber_port_syscalls))
	}
	ASSERT((ADDR(.fiber_port_syscalls) + SIZEOF(.fiber_port_syscalls)) <=
		0x08021000, "ARM_CM55F_MPU syscall code exceeds its exact MPU range")

	.fiber_current_context_slot 0x30000000 (NOLOAD) :
	{
		KEEP(*(.bss.fiber_runtime_current_context_slot))
		. = 0x20;
	}
	ASSERT(SIZEOF(.fiber_current_context_slot) == 0x20,
		"ARM_CM55F_MPU current slot aperture must be exactly 32 bytes")

	.fiber_port_unprivileged_ram 0x24000000 (NOLOAD) :
	{
		. = ALIGN(32);
		KEEP(*(.bss.portable_fixture_stack_1*))
		. = ALIGN(32);
		KEEP(*(.bss.portable_fixture_stack_2*))
	}
	ASSERT((ADDR(.fiber_port_unprivileged_ram) +
		SIZEOF(.fiber_port_unprivileged_ram)) <= 0x24010000,
		"ARM_CM55F_MPU unprivileged RAM exceeds its integration range")

	.fiber_port_privileged_data 0x30000020 (NOLOAD) :
	{
		KEEP(*(.fiber_port_privileged_data))
		*(.data*)
		*(.bss*)
		*(COMMON)
	}
	ASSERT((ADDR(.fiber_port_privileged_data) +
		SIZEOF(.fiber_port_privileged_data)) <= 0x30010000,
		"ARM_CM55F_MPU privileged data exceeds its exact MPU range")

	.ARM.extab : { *(.ARM.extab*) }
	.ARM.exidx :
	{
		__exidx_start = .;
		*(.ARM.exidx*)
		__exidx_end = .;
	}

	/DISCARD/ : { *(.comment*) *(.note*) }
}
