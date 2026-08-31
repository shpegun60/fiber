ENTRY(fiber_arm_cm55_mvef_mpu_svc_probe)

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
	.fiber_test_vectors 0x08000000 :
	{
		KEEP(*(.fiber_test_vectors))
	}

	.fiber_port_unprivileged_code 0x08010000 :
	{
		KEEP(*(.fiber_port_unprivileged_functions))
		KEEP(*(.text.fiber_runtime_thread_functions))
	}
	ASSERT((ADDR(.fiber_port_unprivileged_code) +
		SIZEOF(.fiber_port_unprivileged_code)) <= 0x08020000,
		"ARM_CM55_MVEF_MPU SVC unprivileged code exceeds its linker range")

	.fiber_port_privileged_code 0x08000080 :
	{
		KEEP(*(.fiber_port_privileged_functions))
		*(.text*)
		*(.rodata*)
	}
	ASSERT((ADDR(.fiber_port_privileged_code) +
		SIZEOF(.fiber_port_privileged_code)) <= 0x08010000,
		"ARM_CM55_MVEF_MPU SVC privileged code exceeds its linker range")

	.ARM.extab : { *(.ARM.extab*) }
	.ARM.exidx :
	{
		__exidx_start = .;
		*(.ARM.exidx*)
		__exidx_end = .;
	}

	.fiber_port_syscalls 0x08020000 :
	{
		KEEP(*(.fiber_port_syscalls))
	}
	ASSERT((ADDR(.fiber_port_syscalls) + SIZEOF(.fiber_port_syscalls)) <=
		0x08021000,
		"ARM_CM55_MVEF_MPU SVC syscall code exceeds its linker range")

	.fiber_current_context_slot 0x30000000 (NOLOAD) :
	{
		KEEP(*(.bss.fiber_runtime_current_context_slot))
		. = 0x20;
	}
	ASSERT(SIZEOF(.fiber_current_context_slot) == 0x20,
		"ARM_CM55_MVEF_MPU SVC current slot aperture must be exactly 32 bytes")

	.fiber_port_privileged_data 0x30000020 (NOLOAD) :
	{
		KEEP(*(.fiber_port_privileged_data))
		*(.data*)
		*(.bss*)
		*(COMMON)
	}
	ASSERT((ADDR(.fiber_port_privileged_data) +
		SIZEOF(.fiber_port_privileged_data)) <= 0x30010000,
		"ARM_CM55_MVEF_MPU SVC privileged data exceeds its linker range")

	.fiber_port_unprivileged_ram 0x24000000 (NOLOAD) :
	{
		. = ALIGN(32);
		KEEP(*(.fiber_test_unprivileged_ram))
	}
	ASSERT((ADDR(.fiber_port_unprivileged_ram) +
		SIZEOF(.fiber_port_unprivileged_ram)) <= 0x24010000,
		"ARM_CM55_MVEF_MPU SVC unprivileged RAM exceeds its linker range")

	/DISCARD/ : { *(.comment*) *(.note*) }
}
