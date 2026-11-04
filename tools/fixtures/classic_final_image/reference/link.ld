ENTRY(reference_reset_handler)
MEMORY {
    FLASH (rx) : ORIGIN = 0, LENGTH = 256K
    RAM (rw) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS {
    .isr_vector : ALIGN(1024) { KEEP(*(.isr_vector)) } > FLASH
    .reference_roots (READONLY) : ALIGN(4) { KEEP(*(.reference_roots)) } > FLASH
    .reference_contract (READONLY) : ALIGN(4) { KEEP(*(.reference_contract)) } > FLASH
    .text : ALIGN(4) {
        KEEP(*(.text.reference_origin_padding))
        *(.text .text.*)
    } > FLASH
    .rodata : ALIGN(4) { *(.rodata .rodata.*) } > FLASH
    .ARM.extab : ALIGN(4) { *(.ARM.extab*) } > FLASH
    .ARM.exidx : ALIGN(4) { *(.ARM.exidx*) } > FLASH
    .data : ALIGN(8) { *(.data .data.*) } > RAM AT> FLASH
    .bss (NOLOAD) : ALIGN(8) {
        *(.bss .bss.* COMMON)
        __reference_bss_end = .;
    } > RAM
    .reference_stack ORIGIN(RAM) + LENGTH(RAM) - 4096 (NOLOAD) : {
        __reference_stack_bottom = .;
        . += 4096;
        __reference_stack_top = .;
    } > RAM
    .ARM.attributes 0 : { *(.ARM.attributes) }
    /DISCARD/ : { *(.comment) *(.note*) }
}
ASSERT(SIZEOF(.isr_vector) == 1024, "reference vector span")
ASSERT(SIZEOF(.reference_roots) == 8, "typed reference roots")
ASSERT(SIZEOF(.reference_contract) == 40, "reference header facts")
ASSERT(__reference_bss_end <= __reference_stack_bottom, "reference BSS/stack overlap")
