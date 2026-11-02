ENTRY(r9_secure_reset)
MEMORY {
    SECURE (rx) : ORIGIN = 0x00000000, LENGTH = 64K
    FLASH (rx) : ORIGIN = 0x00010000, LENGTH = 64K
    RAM (rw) : ORIGIN = 0x20010000, LENGTH = 64K
}
SECTIONS {
    .secure_vectors : { KEEP(*(.secure_vectors)) } > SECURE
    .secure_text : { *(.text.r9_secure*) *(.rodata.r9_secure*) } > SECURE
    .vectors : { KEEP(*(.vectors)) } > FLASH
    .text : { *(.text*) *(.rodata*) } > FLASH
    .fiber_port_context_cohort_expectation : { KEEP(*(.fiber_port_context_cohort_expectation)) } > FLASH
    .proof_roots : { KEEP(*(.proof_roots)) } > FLASH
    .data : {
        __data_begin = .; *(.data*)
        . = ALIGN(4); __init_begin = .; KEEP(*(.init_array*)) __init_end = .;
        __data_end = .;
    } > RAM AT> FLASH
    __data_load = LOADADDR(.data);
    .bss (NOLOAD) : { __bss_begin = .; *(.bss*) *(COMMON) __bss_end = .; } > RAM
    ASSERT(__bss_end <= 0x2001c000, "R9 fixture overlaps MSP")
    /DISCARD/ : { *(.comment) *(.note*) *(.fini_array*) }
}
