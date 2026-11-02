ENTRY(SecureContext_Init)
MEMORY
{
    FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 128K
    NSC (rx) : ORIGIN = 0x10020000, LENGTH = 1K
    RAM (rw) : ORIGIN = 0x30000000, LENGTH = 16K
}
SECTIONS
{
    .text : { *(.text*) *(.rodata*) KEEP(*(.reference_geometry)) } > FLASH
    .gnu.sgstubs 0x10020000 : { *(.gnu.sgstubs*) } > NSC
    .ARM.extab : { *(.ARM.extab*) } > FLASH
    .ARM.exidx : { *(.ARM.exidx*) } > FLASH
    .data : { *(.data*) } > RAM
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    /DISCARD/ : { *(.comment*) *(.note*) }
}
ASSERT(SIZEOF(.text) < 0x20000, "Reference Secure text overlaps NSC")
ASSERT(SIZEOF(.gnu.sgstubs) >= 7 * 8 && SIZEOF(.gnu.sgstubs) <= 64,
       "Seven real reference NSC veneers plus bounded linker alignment required")
