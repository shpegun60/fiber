ENTRY(fiber_init)
MEMORY {
    FLASH(rx) : ORIGIN = 0x08000000, LENGTH = 256K
    RAM(rw) : ORIGIN = 0x20000000, LENGTH = 256K
}
SECTIONS {
    .text : { *(.text*) *(.fiber_api_thread_functions*) *(.rodata*) } > FLASH
    .data : { *(.data*) KEEP(*(.fiber_port_context_cohort_expectation)) } > RAM
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) }
}
