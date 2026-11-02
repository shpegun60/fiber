ENTRY(Reset_Handler)
SECTIONS
{
    . = ROM_BASE;
    .vectors : { KEEP(*(.vectors)) }
    .text : { *(.text*) *(.rodata*) }
    . = RAM_BASE;
    .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; }
    __psp_top = RAM_BASE + 0x4000;
    __msp_top = RAM_BASE + 0x7000;
    /DISCARD/ : { *(.comment) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(__bss_end < __psp_top - 0x1000, "CONTROL fixture RAM overflow")
