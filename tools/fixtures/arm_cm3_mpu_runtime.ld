ENTRY(Reset_Handler)

__fiber_mpu_privileged_code_start__ = 0x08000000;
__fiber_mpu_privileged_code_end__ = 0x08010000;
__fiber_mpu_unprivileged_code_start__ = 0x08010000;
__fiber_mpu_unprivileged_code_end__ = 0x08020000;
__fiber_mpu_current_context_slot_start__ = 0x20000000;
__fiber_mpu_current_context_slot_end__ = 0x20000020;
__fiber_mpu_privileged_data_start__ = 0x20010000;
__fiber_mpu_privileged_data_end__ = 0x20020000;
__fiber_mpu_unprivileged_ram_start__ = 0x20020000;
__fiber_mpu_unprivileged_ram_end__ = 0x20030000;

SECTIONS
{
	.isr_vector 0x08000000 :
	{
		KEEP(*(.isr_vector))
	}

	/* These functions are reachable from unprivileged Thread mode. Place
	 * their complete direct call chain before the privileged catch-all. */
	.fiber_unprivileged_code 0x08010000 :
	{
		KEEP(*(.fiber_port_unprivileged_functions))
		KEEP(*(.text.fiber_runtime_thread_functions))
		KEEP(*(.text.portable_fixture_entry*))
	}
	ASSERT(SIZEOF(.fiber_unprivileged_code) <= 0x10000,
		"ARM_CM3_MPU unprivileged code exceeds its exact MPU region")

	/* Explicit VMA permits this catch-all to follow the earlier extraction of
	 * unprivileged input sections while still occupying the lower flash bank. */
	.fiber_privileged_code 0x08000040 :
	{
		KEEP(*(.fiber_port_privileged_functions))
		KEEP(*(.fiber_port_context_cohort_expectation))
		*(.text*)
		*(.rodata*)
	}
	ASSERT((ADDR(.fiber_privileged_code) + SIZEOF(.fiber_privileged_code)) <=
		0x08010000, "ARM_CM3_MPU privileged code exceeds its exact MPU region")

	.fiber_current_context_slot 0x20000000 (NOLOAD) :
	{
		KEEP(*(.bss.fiber_runtime_current_context_slot))
		. = 0x20;
	}
	ASSERT(SIZEOF(.fiber_current_context_slot) == 0x20,
		"ARM_CM3_MPU current slot aperture must be exactly 32 bytes")

	/* Portable fixture stacks are the only application-writable objects in
	 * this proof. Each is one exact 2 KiB MPU region. */
	.fiber_unprivileged_ram 0x20020000 (NOLOAD) :
	{
		. = ALIGN(2048);
		KEEP(*(.bss.portable_fixture_stack_1*))
		. = ALIGN(2048);
		KEEP(*(.bss.portable_fixture_stack_2*))
	}
	ASSERT(SIZEOF(.fiber_unprivileged_ram) <= 0x10000,
		"ARM_CM3_MPU unprivileged RAM exceeds its integration range")

	.fiber_privileged_data 0x20010000 (NOLOAD) :
	{
		KEEP(*(.fiber_port_privileged_data))
		*(.data*)
		*(.bss*)
		*(COMMON)
	}
	ASSERT((ADDR(.fiber_privileged_data) + SIZEOF(.fiber_privileged_data)) <=
		0x20020000, "ARM_CM3_MPU privileged data exceeds its exact MPU region")

	.ARM.extab : { *(.ARM.extab*) }
	.ARM.exidx :
	{
		__exidx_start = .;
		*(.ARM.exidx*)
		__exidx_end = .;
	}

	/DISCARD/ : { *(.comment*) *(.note*) }
}
