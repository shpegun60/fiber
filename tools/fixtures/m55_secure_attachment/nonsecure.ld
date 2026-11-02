ENTRY(NS_Reset_Handler)
SECTIONS
{
    . = 0x00010000;
    .vectors : { KEEP(*(.vectors)) }
    .fixture_case : { KEEP(*(.fixture_case)) }
    .text : { *(.text*) *(.rodata*) }
    . = 0x20010000;
    .bss (NOLOAD) : ALIGN(8) { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    .data : { *(.data*) }
    ASSERT(SIZEOF(.vectors) == 64, "NS core vectors")
    ASSERT(SIZEOF(.fixture_case) == 4, "one externally patched test-case word")
    ASSERT(SIZEOF(.text) < 0xff00, "NS text extent")
    ASSERT(__bss_end < 0x20018000, "NS BSS overlaps MSP")
    ASSERT(SIZEOF(.data) == 0, "no RAM load image")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
