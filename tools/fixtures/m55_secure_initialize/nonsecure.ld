ENTRY(NS_Reset_Handler)
SECTIONS
{
    . = 0x00010000;
    .vectors : { KEEP(*(.vectors)) }
    .text : { *(.text*) *(.rodata*) }
    . = 0x20010000;
    .bss (NOLOAD) : ALIGN(8) { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    .data : { *(.data*) }
    ASSERT(SIZEOF(.text) < 0xff00, "NS code extent")
    ASSERT(__bss_end < 0x20018000, "NS data overlaps MSP")
    ASSERT(SIZEOF(.data) == 0, "no RAM load image")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
