ENTRY(Reset_Handler)
SECTIONS
{
    .vectors 0x10000000 : { KEEP(*(.vectors)) }
    .text : { *(.text*) *(.rodata*) }
    .bss 0x30000000 (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; }
    /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(ADDR(.text) + SIZEOF(.text) < 0x10010000, "Secure fixture overlaps NS code alias")
ASSERT(__bss_end < 0x30002000, "Secure fixture overlaps its MSP")
