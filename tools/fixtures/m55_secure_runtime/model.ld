ENTRY(Reset_Handler)
SECTIONS
{
    .vectors 0 : { KEEP(*(.vectors)) }
    .text 0x10000100 : { *(.text*) *(.rodata*) }
    .bss 0x30000000 (NOLOAD) : ALIGN(8) { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    .data : { *(.data*) }
    ASSERT(SIZEOF(.vectors) == 64, "model vectors")
    ASSERT(SIZEOF(.data) == 0, "no model RAM load image")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
