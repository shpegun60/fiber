ENTRY(NS_Reset_Handler)
SECTIONS {
    . = 0x10000;
    .vectors : { KEEP(*(.vectors)) }
    .fixture_case : { KEEP(*(.fixture_case)) }
    .text : { *(.text*) *(.rodata*) }
    . = 0x20004000;
    .bss (NOLOAD) : ALIGN(8) { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    .data : { *(.data*) }
    ASSERT(SIZEOF(.vectors) == 64, "NS vectors")
    ASSERT(SIZEOF(.fixture_case) == 4, "One case word")
    ASSERT(SIZEOF(.text) < 0xff00, "NS code extent")
    ASSERT(__bss_end <= 0x20007000, "NS BSS overlaps MSP")
    ASSERT(SIZEOF(.data) == 0, "No initialized RAM image")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
