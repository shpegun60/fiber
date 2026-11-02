ENTRY(r9_call_init)
MEMORY {
    PRIV (rx) : ORIGIN = 0x08000000, LENGTH = 128K
    USER (rx) : ORIGIN = 0x08020000, LENGTH = 128K
    RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 32K
    SLOT (rw) : ORIGIN = 0x20030000, LENGTH = 256
}
__fiber_mpu_privileged_code_start__ = 0x08000000;
__fiber_mpu_privileged_code_end__ = 0x08020000;
__fiber_mpu_unprivileged_code_start__ = 0x08020000;
__fiber_mpu_unprivileged_code_end__ = 0x08040000;
__fiber_mpu_privileged_data_start__ = 0x20000000;
__fiber_mpu_privileged_data_end__ = 0x20010000;
__fiber_mpu_unprivileged_ram_start__ = 0x20010000;
__fiber_mpu_unprivileged_ram_end__ = 0x20030000;
__fiber_mpu_current_context_slot_start__ = 0x20030000;
__fiber_mpu_current_context_slot_end__ = 0x20030100;
SECTIONS {
    .unprivileged : {
        KEEP(*(.fiber_port_unprivileged_functions))
        KEEP(*(.text.fiber_runtime_thread_functions))
    } > USER
    .text : {
        KEEP(*(.fiber_port_privileged_functions))
        *(.text*) *(.rodata*)
        KEEP(*(.fiber_port_context_cohort_expectation))
    } > PRIV
    .data : { *(.fiber_port_privileged_data) *(.data*) } > RAM
    .current_slot (NOLOAD) : {
        KEEP(*(.bss.fiber_runtime_current_context_slot))
        . = 256;
    } > SLOT
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    ASSERT(ADDR(.bss) + SIZEOF(.bss) <= 0x20008000,
           "ELF data overlaps fixture-owned context")
    ASSERT(SIZEOF(.current_slot) == 256, "Exact current slot aperture required")
    /DISCARD/ : { *(.init_array*) *(.fini_array*) *(.ARM.exidx*) *(.ARM.extab*) }
}
