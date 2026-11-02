SECTIONS
{
    . = 0x10000100;
    .text : { *(.text*) *(.rodata*) }
    .gnu.sgstubs 0x10008000 : ALIGN(32) { KEEP(*(.gnu.sgstubs*)) }
    . = 0x30000000;
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    .data : { *(.data*) }
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
