ENTRY(vStartFirstTask)
MEMORY
{
    FLASH (rx) : ORIGIN = 0x00010000, LENGTH = 64K
    RAM (rw) : ORIGIN = 0x20000000, LENGTH = 16K
}
SECTIONS
{
    .text : { *(.text*) *(.rodata*) KEEP(*(.reference_geometry)) } > FLASH
    .ARM.extab : { *(.ARM.extab*) } > FLASH
    .ARM.exidx : { *(.ARM.exidx*) } > FLASH
    .data : { *(.data*) } > RAM
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    /DISCARD/ : { *(.comment*) *(.note*) }
}
ASSERT(SIZEOF(.text) < 0x10000, "Reference Non-secure text escaped fixture flash")
