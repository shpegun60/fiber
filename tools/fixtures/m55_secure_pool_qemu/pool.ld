ENTRY(Reset_Handler)
MEMORY
{
    FLASH (rx) : ORIGIN = 0, LENGTH = 512K
    RAM (rw) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS
{
    .vectors : { KEEP(*(.vectors)) } > FLASH
    .text : { *(.text*) *(.rodata*) } > FLASH
    .fiber_secure_context_pool (NOLOAD) : ALIGN(8)
    {
        __pool_start = .;
        KEEP(*(.fiber_secure_context_pool))
        __pool_end = .;
    } > RAM
    .bss (NOLOAD) : ALIGN(8)
    {
        __bss_start = .;
        *(.bss*) *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    } > RAM
    .data : { *(.data*) } > RAM AT > FLASH
    __msp_top = ORIGIN(RAM) + LENGTH(RAM);
    ASSERT(SIZEOF(.vectors) == 64, "fixture requires sixteen core vectors")
    ASSERT(ADDR(.vectors) == 0, "fixture vector table must start at zero")
    ASSERT(SIZEOF(.data) == 0, "fixture needs no initialized RAM")
    ASSERT(__bss_end <= __msp_top - 0x4000, "fixture data overlaps reserved MSP stack")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
