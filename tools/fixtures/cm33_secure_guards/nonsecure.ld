ENTRY(NS_Reset_Handler)
SECTIONS
{
    . = 0x00010000;
    .vectors : { KEEP(*(.vectors)) }
    .text : { *(.text*) *(.rodata*) }
    . = 0x20004000;
    .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; }
    /DISCARD/ : { *(.comment) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(SIZEOF(.text) < 0xff00, "NS fixture code overflows SAU region")
ASSERT(__bss_end < 0x20005000, "NS data overlaps stacks")
