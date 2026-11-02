SECTIONS
{
    .text 0x10000100 : { *(.text*) *(.rodata*) }
    .gnu.sgstubs 0x10008000 : ALIGN(32) { KEEP(*(.gnu.sgstubs*)) }
    .bss 0x30000000 (NOLOAD) : { *(.bss*) *(COMMON) }
    .fiber_secure_context_pool (NOLOAD) : ALIGN(8) { KEEP(*(.fiber_secure_context_pool)) }
    .data : { *(.data*) }
    ASSERT(SIZEOF(.data) == 0, "foreign CM33 no RAM load image")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
