ENTRY(fiber_arm_cm4_mpu_boot_probe)

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
	.fiber_unprivileged_code 0x08010000 :
	{
		KEEP(*(.fiber_port_unprivileged_functions))
	}
	ASSERT(SIZEOF(.fiber_unprivileged_code) <= 0x10000,
		"ARM_CM4_MPU unprivileged code exceeds its exact MPU region")

	.fiber_privileged_code 0x08000000 :
	{
		KEEP(*(.fiber_port_privileged_functions))
		*(.text*)
		*(.rodata*)
	}
	ASSERT((ADDR(.fiber_privileged_code) + SIZEOF(.fiber_privileged_code)) <=
		0x08010000, "ARM_CM4_MPU privileged code exceeds its exact MPU region")

	.fiber_current_context_slot 0x20000000 (NOLOAD) :
	{
		KEEP(*(.bss.fiber_runtime_current_context_slot))
		. = 0x20;
	}
	ASSERT(SIZEOF(.fiber_current_context_slot) == 0x20,
		"ARM_CM4_MPU current slot aperture must be exactly 32 bytes")

	.fiber_unprivileged_ram 0x20020000 (NOLOAD) :
	{
		. = ALIGN(2048);
		KEEP(*(.fiber_test_unprivileged_ram))
	}
	ASSERT(SIZEOF(.fiber_unprivileged_ram) <= 0x10000,
		"ARM_CM4_MPU unprivileged RAM exceeds its integration range")

	.fiber_privileged_data 0x20010000 (NOLOAD) :
	{
		KEEP(*(.fiber_port_privileged_data))
		*(.data*)
		*(.bss*)
		*(COMMON)
	}
	ASSERT((ADDR(.fiber_privileged_data) + SIZEOF(.fiber_privileged_data)) <=
		0x20020000, "ARM_CM4_MPU privileged data exceeds its exact MPU region")

	.ARM.extab : { *(.ARM.extab*) }
	.ARM.exidx :
	{
		__exidx_start = .;
		*(.ARM.exidx*)
		__exidx_end = .;
	}

	/DISCARD/ : { *(.comment*) *(.note*) }
}
