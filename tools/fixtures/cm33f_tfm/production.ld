ENTRY(Reset_Handler)
MEMORY {
    FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 1M
    RAM (rw) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS {
    .vectors : { KEEP(*(.vectors)) } > FLASH
    .text : { *(.text*) *(.rodata*) } > FLASH
    .fiber_port_context_cohort_expectation : {
        KEEP(*(.fiber_port_context_cohort_expectation))
    } > FLASH
    .proof_roots : { KEEP(*(.proof_roots)) } > FLASH
    .data : { *(.data*) } > RAM AT> FLASH
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    /DISCARD/ : { *(.comment) *(.note*) }
}
