ENTRY(cohort_consumer)
MEMORY
{
    FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 256K
    RAM (rw) : ORIGIN = 0x30000000, LENGTH = 256K
}
SECTIONS
{
    .text : { *(.text*) } > FLASH
    .rodata : { *(.rodata*) } > FLASH
    .gnu.sgstubs 0x10008000 : ALIGN(32)
    {
        KEEP(*(.gnu.sgstubs*))
    } > FLASH
    .data : { *(.data*) } > RAM
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    .fiber_secure_context_pool (NOLOAD) : ALIGN(8)
    {
        KEEP(*(.fiber_secure_context_pool*))
    } > RAM
    /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.extab*) *(.note*) }
}
