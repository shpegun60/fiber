ENTRY(audit_init)
AUDIT_FLASH = audit_flash_base;
SECTIONS
{
    .privileged_code AUDIT_FLASH :
    {
        __fiber_mpu_privileged_code_start__ = .;
        KEEP(*(.isr_vector))
        *(.fiber_port_privileged_functions*)
        *(.text*) *(.rodata*)
        __fiber_mpu_privileged_code_end__ = ABSOLUTE(AUDIT_FLASH + 0x10000);
    }
    ASSERT(SIZEOF(.privileged_code) <= 0x10000, "audit privileged code overflow")
    .unprivileged_code (AUDIT_FLASH + 0x10000) :
    {
        __fiber_mpu_unprivileged_code_start__ = .;
        *(.fiber_port_unprivileged_functions*)
        __fiber_mpu_unprivileged_code_end__ = ABSOLUTE(AUDIT_FLASH + 0x20000);
    }
    .privileged_data 0x20000000 :
    {
        __fiber_mpu_privileged_data_start__ = .;
        *(.fiber_port_privileged_data*) *(.data*) *(.bss*) *(COMMON)
        __fiber_mpu_privileged_data_end__ = ABSOLUTE(0x20001000);
    }
    ASSERT(SIZEOF(.privileged_data) <= 0x1000, "audit privileged data overflow")
    .current_slot 0x20001000 :
    {
        __fiber_mpu_current_context_slot_start__ = .;
        *(.fiber_port_current_context_slot)
        __fiber_mpu_current_context_slot_end__ = ABSOLUTE(0x20001100);
    }
    __fiber_mpu_unprivileged_ram_start__ = 0x20010000;
    __fiber_mpu_unprivileged_ram_end__ = 0x20020000;
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) }
}
