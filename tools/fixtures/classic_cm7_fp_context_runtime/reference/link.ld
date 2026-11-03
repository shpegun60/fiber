ENTRY(reference_reset_handler)

MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
    RAM (rw) : ORIGIN = 0x20000000, LENGTH = 64K
}

SECTIONS
{
    .isr_vector ORIGIN(FLASH) :
    {
        KEEP(*(.isr_vector))
    } > FLASH

    .reference_roots : ALIGN(4)
    {
        KEEP(*(.reference_roots))
    } > FLASH

    .reference_contract : ALIGN(4)
    {
        KEEP(*(.reference_contract))
    } > FLASH

    .text : ALIGN(4)
    {
        *(.text*)
        *(.rodata*)
    } > FLASH

    .ARM.extab : ALIGN(4) { *(.ARM.extab*) } > FLASH
    .ARM.exidx : ALIGN(4) { *(.ARM.exidx*) } > FLASH

    .data : ALIGN(8)
    {
        *(.data*)
    } > RAM AT > FLASH

    .bss (NOLOAD) : ALIGN(8)
    {
        *(.bss*)
        *(COMMON)
        __reference_bss_end = .;
    } > RAM

    .reference_stack ORIGIN(RAM) + LENGTH(RAM) - 4096 (NOLOAD) :
    {
        __reference_stack_bottom = .;
        . += 4096;
        __reference_stack_top = .;
    } > RAM

    .ARM.attributes 0 : { *(.ARM.attributes) }
    /DISCARD/ : { *(.comment) *(.note*) }
}

ASSERT(SIZEOF(.isr_vector) == 1024, "CM7 reference vector span")
ASSERT(SIZEOF(.reference_roots) == 8, "CM7 reference real-code roots")
ASSERT(SIZEOF(.reference_contract) == 32, "CM7 reference header facts")
ASSERT(__reference_bss_end <= __reference_stack_bottom,
       "CM7 reference data overlaps its reserved stack")
