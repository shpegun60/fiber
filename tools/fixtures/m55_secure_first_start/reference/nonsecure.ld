ENTRY(NS_Reset_Handler)
SECTIONS
{
    . = 0x10000;
    .vectors : { KEEP(*(.vectors)) }
    .fixture_case : { KEEP(*(.fixture_case)) }
    .text : { *(.text*) *(.rodata*) }
    . = 0x20010000;
    .bss (NOLOAD) : ALIGN(8) { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    .data : { *(.data*) }
    ASSERT(SIZEOF(.vectors) == 64, "reference NS vectors")
    ASSERT(SIZEOF(.fixture_case) == 4, "reference case word")
    ASSERT(SIZEOF(.text) < 0xff00, "reference NS text")
    ASSERT(__bss_end < 0x20018000, "reference NS BSS")
    ASSERT(SIZEOF(.data) == 0, "no reference initialized RAM")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
