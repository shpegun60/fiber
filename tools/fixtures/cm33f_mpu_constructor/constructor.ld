ENTRY(fiber_port_context_init)

__fiber_mpu_privileged_flash_start__ = 0x08000000;
__fiber_mpu_privileged_flash_end__ = 0x08010000;
__fiber_mpu_unprivileged_flash_start__ = 0x08010000;
__fiber_mpu_unprivileged_flash_end__ = 0x08020000;
__fiber_mpu_unprivileged_syscalls_start__ = 0x08020000;
__fiber_mpu_unprivileged_syscalls_end__ = 0x08021000;
__fiber_mpu_privileged_sram_start__ = 0x30000020;
__fiber_mpu_privileged_sram_end__ = 0x30010000;
__fiber_mpu_current_context_slot_start__ = 0x30000000;
__fiber_mpu_current_context_slot_end__ = 0x30000020;
__fiber_mpu_unprivileged_ram_start__ = 0x24000000;
__fiber_mpu_unprivileged_ram_end__ = 0x24010000;

SECTIONS
{
    .fiber_port_privileged_code 0x08000000 :
    {
        KEEP(*(.fiber_port_privileged_functions))
        *(.text*)
        *(.rodata*)
        KEEP(*(.fixture_boot_linkage))
        KEEP(*(.fiber_port_context_cohort_expectation))
    }
    .ARM.extab : { *(.ARM.extab*) }
    .ARM.exidx : { *(.ARM.exidx*) }
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
        *(.data*)
        *(.bss*)
        *(COMMON)
    }
    .fiber_port_unprivileged_ram 0x24000000 (NOLOAD) :
    {
        KEEP(*(.fixture_user_stack))
    }
    /DISCARD/ : { *(.comment*) *(.note*) }
}
