ENTRY(NS_Reset_Handler)
SECTIONS {
    . = 0x10000;
    .vectors : { KEEP(*(.vectors)) }
    .text : { *(.text*) *(.rodata*) }
    . = 0x20004000;
    .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(4); __bss_end = .; }
    .data : { *(.data*) }
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) }
}
ASSERT(SIZEOF(.vectors)==64,"NS vectors")
ASSERT(SIZEOF(.text)<0xff00,"NS synthetic flash")
ASSERT(__bss_end<0x20005000,"NS exception stack reservation")
ASSERT(SIZEOF(.data)==0,"no hidden NS RAM copy")
