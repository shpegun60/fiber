ENTRY(Reset_Handler)
SECTIONS
{
    . = 0x10000000;
    .vectors : { KEEP(*(.vectors)) }
    .text : { *(.text*) *(.rodata*) }
    . = 0x10008000;
    .nsc : { KEEP(*(.nsc)) }
    . = 0x00010000;
    .ns_vectors : { KEEP(*(.ns.vectors)) }
    .ns_text : { *(.ns.text) *(.ns.rodata) }
    . = 0x30000000;
    .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; }
    . = 0x20004000;
    .ns_bss (NOLOAD) : { *(.ns.bss) }
    /DISCARD/ : { *(.comment) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(SIZEOF(.nsc) <= 32, "NSC probe is one 32-byte SAU region")
ASSERT(__bss_end < 0x30001000, "Secure data overlaps stacks")
ASSERT(SIZEOF(.ns_bss) < 0x1000, "Non-secure data overlaps stacks")
