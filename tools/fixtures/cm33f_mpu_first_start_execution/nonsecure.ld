ENTRY(NS_Reset_Handler)
__fiber_mpu_privileged_flash_start__ = 0x00010000;
__fiber_mpu_privileged_flash_end__ = 0x00020000;
__fiber_mpu_unprivileged_flash_start__ = 0x00020000;
__fiber_mpu_unprivileged_flash_end__ = 0x00028000;
__fiber_mpu_unprivileged_syscalls_start__ = 0x00028000;
__fiber_mpu_unprivileged_syscalls_end__ = 0x00029000;
__fiber_mpu_current_context_slot_start__ = 0x20004000;
__fiber_mpu_current_context_slot_end__ = 0x20004020;
__fiber_mpu_privileged_sram_start__ = 0x20004020;
__fiber_mpu_privileged_sram_end__ = 0x20006000;
__fiber_mpu_unprivileged_ram_start__ = 0x20006000;
__fiber_mpu_unprivileged_ram_end__ = 0x20008000;
SECTIONS
{
    .vectors 0x00010000 : { KEEP(*(.vectors)) }
    /* Collect the public declaration's section before the general text glob. */
    .fiber_port_unprivileged_code 0x00020000 :
    { KEEP(*(.fiber_port_unprivileged_functions)) KEEP(*(.text.fiber_runtime_thread_functions)) }
    .fiber_port_privileged_code 0x00010800 :
    {
        *(.fiber_port_privileged_functions) *(.text*) *(.rodata*)
        KEEP(*(.fiber_port_context_cohort_expectation))
    }
    .fiber_port_syscalls 0x00028000 : { KEEP(*(.fiber_port_syscalls)) }
    .fiber_current_context_slot 0x20004000 (NOLOAD) :
    {
        __slot_zero_start = .;
        KEEP(*(.bss.fiber_runtime_current_context_slot))
        . = 32;
        __slot_zero_end = .;
    }
    .fiber_port_privileged_data 0x20004020 (NOLOAD) :
    {
        __bss_start = .;
        *(.fiber_port_privileged_data) *(.bss*) *(COMMON)
        __bss_end = .;
    }
    .fiber_port_unprivileged_ram 0x20006000 (NOLOAD) :
    { KEEP(*(.fixture_user_stack)) }
    /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(SIZEOF(.vectors) == 2048, "Full architectural NS vector span required")
ASSERT(__bss_end <= 0x20005000, "NS fixture data overlaps its MSP reserve")
ASSERT(SIZEOF(.fiber_port_unprivileged_ram) == 4096, "Exact task stack required")
