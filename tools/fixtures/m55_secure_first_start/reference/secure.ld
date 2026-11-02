ENTRY(Reset_Handler)
SECTIONS
{
    . = 0;
    .vectors : { KEEP(*(.vectors)) }
    . = 0x10000100;
    .text : { *(.text*) *(.rodata*) }
    .gnu.sgstubs 0x10008000 : ALIGN(32) { KEEP(*(.gnu.sgstubs*)) }
    . = 0x30000000;
    .bss (NOLOAD) : ALIGN(8) { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    .data : { *(.data*) }
    ASSERT(SIZEOF(.vectors) == 64, "reference Secure vectors")
    ASSERT(SIZEOF(.text) < 0x7e00, "reference Secure text")
    ASSERT(SIZEOF(.gnu.sgstubs) <= 0x1000, "reference NSC range")
    ASSERT(__bss_end < 0x30002000, "reference Secure BSS")
    ASSERT(SIZEOF(.data) == 0, "no reference initialized RAM")
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
