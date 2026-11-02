ENTRY(pxPortInitialiseStack)
SECTIONS
{
    .text 0x08000000 : { *(.text*) *(.privileged_functions*) *(.rodata*) }
    .reference_geometry : { KEEP(*(.reference_geometry)) }
    .ARM.extab : { *(.ARM.extab*) }
    .ARM.exidx : { *(.ARM.exidx*) }
    .data 0x30001000 (NOLOAD) :
    {
        KEEP(*(.reference_data))
        *(.data*) *(.bss*) *(COMMON)
    }
    /DISCARD/ : { *(.comment*) *(.note*) }
}
